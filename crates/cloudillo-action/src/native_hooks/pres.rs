// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! PRES (presence) native hooks. PRES is ephemeral: `before_create` gates a local hint and
//! `before_receive` an inbound one, before the WebSocket forward, so a refused hint reaches
//! nobody.
//!
//! A PRES on a CONV is admitted from the CONV issuer or an active member at Member+ only; any
//! other PRES (DM presence) must be addressed to us. The CONV owner relays a group
//! `PRES:TYPING` to the other members ([`relay_typing`]).

use std::num::NonZeroUsize;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use lru::LruCache;
use parking_lot::Mutex;

use crate::helpers::{self, SubscriptionRole, conv_role};
use crate::hooks::{BeforeCreate, BeforeReceive, HookContext, HookResult};
use crate::native_hooks::ownership::{conv_owner, owns_subject};
use crate::prelude::*;
use cloudillo_types::action_types::CreateAction;
use cloudillo_types::meta_adapter::{self, ActionView};

/// Minimum gap between two hints of one issuer in one scope.
const PRES_INTERVAL: Duration = Duration::from_secs(3);

/// `(tn_id, scope, iss)` of a hint: the scope is a CONV id (`a1~…`) for a typing relay, the
/// PRES type for a DM hint, so the two never collide.
type PresKey = (TnId, Box<str>, Box<str>);

/// Last hint per [`PresKey`]: per process and in memory, enough for presence hints. Shared
/// state if a hint ever needs throttling across nodes.
static PRES_SEEN: LazyLock<Mutex<LruCache<PresKey, Instant>>> = LazyLock::new(|| {
	let cap = NonZeroUsize::new(4096).unwrap_or(NonZeroUsize::MIN);
	Mutex::new(LruCache::new(cap))
});

/// `iss` had a hint in `scope` within [`PRES_INTERVAL`]; otherwise stamps this one.
fn throttled(tn_id: TnId, scope: &str, iss: &str) -> bool {
	let now = Instant::now();
	let mut seen = PRES_SEEN.lock();
	let key = (tn_id, Box::from(scope), Box::from(iss));
	if seen.get(&key).is_some_and(|t| now.duration_since(*t) < PRES_INTERVAL) {
		return true;
	}
	seen.put(key, now);
	false
}

/// PRES `before_create`: a PRES on a CONV needs a member+ actor and is addressed to the CONV
/// owner, parented to the CONV (delivery needs the audience, the owner's relay the parent); any
/// other PRES (DM presence) is addressed to someone and signed by the tenant itself.
pub(crate) async fn before_create(app: App, ctx: BeforeCreate) -> ClResult<CreateAction> {
	let mut action = ctx.action;
	if let Some(conv_id) = action.subject.as_deref().filter(|s| s.starts_with("a1~")) {
		let Some(conv) = helpers::get_group(app.meta_adapter.as_ref(), ctx.tn_id, conv_id).await?
		else {
			return Err(Error::PermissionDenied);
		};
		if !may_signal(&app, ctx.tn_id, &conv, &ctx.actor).await {
			debug!(conv = %conv_id, actor = %ctx.actor, "PRES refused: actor is not a member");
			return Err(Error::PermissionDenied);
		}
		let owner: Box<str> = conv_owner(&conv).into();
		if action.audience_tag.as_ref().is_some_and(|a| *a != owner)
			|| action.parent_id.as_deref().is_some_and(|p| p != conv_id)
		{
			return Err(Error::PermissionDenied);
		}
		action.parent_id = Some(conv.action_id.clone());
		action.audience_tag = Some(owner);
	} else if action.audience_tag.is_none() || ctx.actor != ctx.tenant_tag {
		return Err(Error::PermissionDenied);
	}
	Ok(action)
}

/// PRES `before_receive`: refuse a PRES on a CONV from a non-member, or any other PRES not
/// addressed to us; relay an admitted group `PRES:TYPING`.
pub(crate) async fn before_receive(app: App, ctx: BeforeReceive) -> ClResult<()> {
	let a = &ctx.action;
	if let Some(conv_id) = a.sub.as_deref().filter(|s| s.starts_with("a1~")) {
		let Some(conv) = helpers::get_group(app.meta_adapter.as_ref(), ctx.tn_id, conv_id).await?
		else {
			debug!(sub = %conv_id, iss = %a.iss, "PRES refused: subject is not a CONV here");
			return Err(Error::PermissionDenied);
		};
		if !may_signal(&app, ctx.tn_id, &conv, &a.iss).await {
			debug!(conv = %conv_id, iss = %a.iss, "PRES refused: issuer is not a member");
			return Err(Error::PermissionDenied);
		}
		// A dropped hint is harmless; a flood would reach every member.
		if throttled(ctx.tn_id, conv_id, &a.iss) {
			return Err(Error::PermissionDenied);
		}
		if a.t.as_ref() == "PRES:TYPING" {
			relay_typing(&app, ctx.tn_id, &ctx.token, &conv, &a.iss).await;
		}
	} else {
		let us = app.auth_adapter.read_id_tag(ctx.tn_id).await?;
		if a.aud.as_deref() != Some(us.as_ref()) {
			debug!(iss = %a.iss, aud = ?a.aud, "PRES refused: not addressed to us");
			return Err(Error::PermissionDenied);
		}
		// As MSG's `allow_unknown: false`: a stranger's DM presence is refused.
		let known = app
			.meta_adapter
			.read_profile(ctx.tn_id, &a.iss)
			.await
			.is_ok_and(|(_, p)| p.connected.is_connected() || p.following);
		if !known {
			debug!(iss = %a.iss, "PRES refused: issuer is neither connected nor followed");
			return Err(Error::PermissionDenied);
		}
		// A dropped hint is harmless; a flood would reach every websocket.
		if throttled(ctx.tn_id, &a.t, &a.iss) {
			return Err(Error::PermissionDenied);
		}
	}
	Ok(())
}

/// PRES `on_create` (run after the ephemeral forward, `vars.token` the signed token): the CONV
/// owner's own `PRES:TYPING` reaches its members through [`relay_typing`], as a member's does.
pub(crate) async fn on_create(app: App, ctx: HookContext) -> ClResult<HookResult> {
	let done = Ok(HookResult::default());
	let Some(conv_id) = ctx.subject.as_deref().filter(|s| s.starts_with("a1~")) else {
		return done;
	};
	let Some(token) = ctx.vars.get("token").and_then(|t| t.as_str()) else {
		return done;
	};
	if ctx.subtype.as_deref() != Some("TYPING") {
		return done;
	}
	let Some(conv) = helpers::get_group(app.meta_adapter.as_ref(), ctx.tn_id, conv_id).await?
	else {
		return done;
	};
	if !throttled(ctx.tn_id, conv_id, &ctx.issuer) {
		relay_typing(&app, ctx.tn_id, token, &conv, &ctx.issuer).await;
	}
	done
}

/// The CONV owner re-posts a `PRES:TYPING` token to every active member's inbox except the
/// issuer's: a member's hint reaches the owner only (its `audience`), and the owner's own hint
/// reaches nobody else. A no-op unless we own `conv`; the caller has checked that `iss` is a
/// member. PRES is never stored, so `ActionDeliveryTask` (which loads the token from the DB)
/// cannot carry it. The token is parented to the CONV, so members' nodes admit the relay as a
/// child of the CONV they hold (`refuse_foreign_audience`).
/// Fire-and-forget: a typing hint is worthless by the time a retry would land.
pub(crate) async fn relay_typing(
	app: &App,
	tn_id: TnId,
	token: &str,
	conv: &ActionView,
	iss: &str,
) {
	let conv_id = &*conv.action_id;
	let Ok(us) = app.auth_adapter.read_id_tag(tn_id).await else {
		return;
	};
	if !owns_subject(conv, &us) {
		return;
	}
	let subs = match app.meta_adapter.list_actions(tn_id, &helpers::active_subs_opts(conv_id)).await
	{
		Ok(subs) => subs,
		Err(e) => {
			warn!(conv = %conv_id, error = %e, "typing relay: listing members failed");
			return;
		}
	};
	let members: Vec<_> = subs
		.into_iter()
		.map(|sub| sub.issuer.id_tag)
		.filter(|m| m.as_ref() != us.as_ref() && m.as_ref() != iss)
		.collect();
	helpers::spawn_inbox_posts(app, tn_id, members, token);
}

/// The CONV issuer, or an active member (live SUBS, profile not suspended/blocked/banned) at
/// Member+. One rule for a local hint and an inbound one.
async fn may_signal(app: &App, tn_id: TnId, conv: &ActionView, who: &str) -> bool {
	conv.issuer.id_tag.as_ref() == who
		|| (is_active_member(app, tn_id, &conv.action_id, who).await
			&& conv_role(app.meta_adapter.as_ref(), tn_id, conv, who).await
				>= SubscriptionRole::Member)
}

/// `member` holds an active (status `A`, not `DEL`) SUBS on `conv_id` and is not suspended,
/// blocked or banned. Read errors deny.
async fn is_active_member(app: &App, tn_id: TnId, conv_id: &str, member: &str) -> bool {
	app.meta_adapter
		.list_actions(
			tn_id,
			&meta_adapter::ListActionOptions {
				issuer: Some(member.to_string()),
				limit: Some(1),
				..helpers::active_subs_opts(conv_id)
			},
		)
		.await
		.is_ok_and(|subs| !subs.is_empty())
}

// vim: ts=4
