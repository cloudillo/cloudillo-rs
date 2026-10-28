// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! PIN (pinned message) authority and hooks
//!
//! - [`check_authority`] runs pre-store (`before_create` / `before_receive`), since a
//!   post-store hook cannot roll a stored row back. The subject must be a MSG held here; a
//!   group pin needs CONV moderator+ (`helpers::conv_role`), a DM pin a participant of the
//!   message. Tombstoned (`x.deletedBy`) messages stay pinnable, like they stay listed.
//! - [`on_store`] (`on_create` and `on_receive`) keeps at most [`MAX_PINS`] per conversation.
//!   Only the conversation's authority enforces it — the CONV owner for a group, the pinner's
//!   own node for a DM — by minting a `PIN:DEL` for the oldest pin, which federates like any pin.
//!
//! PIN never notifies (`forward.rs` allowlists) and is not full-text indexed.

use crate::helpers::{SubscriptionRole, conv_role};
use crate::hooks::{BeforeCreate, BeforeReceive, HookContext, HookResult};
use crate::native_hooks::ownership::owns_subject;
use crate::prelude::*;
use cloudillo_types::action_types::CreateAction;
use cloudillo_types::meta_adapter::ListActionOptions;

/// Pins per conversation; pinning one more retires the oldest.
const MAX_PINS: usize = 10;

/// Where an authorised pin lives.
pub(crate) enum PinScope {
	/// A group pin: the message's CONV id.
	Group(Box<str>),
	/// A DM pin: the message participant who is not the actor.
	Dm(Box<str>),
}

/// Pre-store authority for `PIN` / `PIN:DEL`. A subject or CONV that cannot be loaded is
/// refused as `PermissionDenied`, so a probe learns nothing about ids. A `parent` that is not
/// the message's CONV is refused, as is a DM message with no peer to address the pin to.
pub(crate) async fn check_authority(
	app: &App,
	tn_id: TnId,
	subject: Option<&str>,
	parent: Option<&str>,
	actor: &str,
) -> ClResult<PinScope> {
	let Some(subject) = subject else {
		return Err(Error::ValidationError("PIN needs the pinned MSG as subject".into()));
	};
	let target = super::msg::load_plain_msg(app, tn_id, subject, "PIN")
		.await
		.map_err(|_| Error::PermissionDenied)?;
	if let Some(conv_id) = target.parent_id.as_deref() {
		let conv = crate::helpers::get_group(app.meta_adapter.as_ref(), tn_id, conv_id)
			.await?
			.ok_or(Error::PermissionDenied)?;
		if conv_role(app.meta_adapter.as_ref(), tn_id, &conv, actor).await
			>= SubscriptionRole::required_for_action("PIN", None)
		{
			if parent.is_some_and(|p| p != conv_id) {
				return Err(Error::ValidationError("PIN parent is not the message's CONV".into()));
			}
			return Ok(PinScope::Group(conv_id.into()));
		}
	} else {
		if parent.is_some() {
			return Err(Error::ValidationError("a DM PIN has no parent".into()));
		}
		let aud = target.audience.as_ref().map(|a| a.id_tag.as_ref());
		let peer = if target.issuer.id_tag.as_ref() == actor {
			aud
		} else if aud == Some(actor) {
			Some(target.issuer.id_tag.as_ref())
		} else {
			None
		};
		if let Some(peer) = peer {
			return Ok(PinScope::Dm(peer.into()));
		}
	}
	tracing::debug!("PIN by {} of {} denied: not a moderator or participant", actor, subject);
	Err(Error::PermissionDenied)
}

/// PIN on_create / on_receive hook — enforce the pin cap (a local pin, or a member's pin on
/// the CONV owner).
pub async fn on_store(app: App, context: HookContext) -> ClResult<HookResult> {
	if context.subtype.as_deref() != Some("DEL")
		&& let Err(e) = retire_oldest(&app, &context).await
	{
		tracing::warn!("PIN {}: retiring the oldest pin failed: {}", context.action_id, e);
	}
	Ok(HookResult::default())
}

async fn retire_oldest(app: &App, context: &HookContext) -> ClResult<()> {
	let tn_id = context.tn_id;
	let mut opts = ListActionOptions {
		typ: Some(vec!["PIN".into()]),
		limit: Some(100),
		sort: Some("created".into()),
		sort_dir: Some("desc".into()),
		exclude_sub_typ: Some(Box::from([Box::from("DEL")])),
		..Default::default()
	};
	// (parent of the PIN:DEL, its audience)
	let (parent, audience) = if let Some(conv_id) = context.parent.as_deref() {
		let Some(conv) = app.meta_adapter.get_action(tn_id, conv_id).await? else {
			return Ok(());
		};
		if !owns_subject(&conv, &context.tenant_tag) {
			return Ok(());
		}
		opts.parent_id = Some(conv_id.to_string());
		(Some(conv_id), None)
	} else {
		let Some(peer) = context.audience.as_deref().filter(|_| !context.is_inbound) else {
			return Ok(());
		};
		opts.involved = Some(peer.to_string());
		opts.viewer_id_tag = Some(context.tenant_tag.clone());
		(None, Some(peer))
	};

	let mut pins = app.meta_adapter.list_actions(tn_id, &opts).await?;
	// `involved` also matches group pins addressed to a peer who owns the CONV.
	pins.retain(|p| parent.is_some() || p.parent_id.is_none());
	if pins.len() <= MAX_PINS {
		return Ok(());
	}
	// Newest first (`list_actions` orders `created DESC, a_id DESC`), so a backlog past the
	// page drains over the next pins. A second `PIN:DEL` of an already-retired subject is
	// harmless: it replaces the first under the same key.
	for old in &pins[MAX_PINS..] {
		tracing::info!("PIN cap: retiring {:?} (pin {})", old.subject, old.action_id);
		// A deleted MSG refuses a PIN:DEL (`check_authority`): drop such a pin locally.
		let target = match old.subject.as_deref() {
			Some(id) => app.meta_adapter.get_action(tn_id, id).await?,
			None => None,
		};
		if target.is_none() {
			if let Err(e) = app.meta_adapter.delete_action(tn_id, &old.action_id).await {
				tracing::warn!("PIN cap: dropping stale pin {} failed: {}", old.action_id, e);
			}
			continue;
		}
		if let Err(e) = crate::task::create_action(
			app,
			tn_id,
			&context.tenant_tag,
			CreateAction {
				typ: "PIN".into(),
				sub_typ: Some("DEL".into()),
				subject: old.subject.clone(),
				parent_id: parent.map(Into::into),
				audience_tag: audience.map(Into::into),
				..Default::default()
			},
		)
		.await
		{
			tracing::warn!("PIN cap: retiring pin {} failed: {}", old.action_id, e);
		}
	}
	Ok(())
}

/// PIN `before_create`: pin authority. A group pin is parented to its CONV, so
/// `GET /api/actions?type=PIN&parentId=<conv>` lists it and the fan-out walk finds the CONV.
pub(crate) async fn before_create(app: App, ctx: BeforeCreate) -> ClResult<CreateAction> {
	let mut action = ctx.action;
	match check_authority(
		&app,
		ctx.tn_id,
		action.subject.as_deref(),
		action.parent_id.as_deref(),
		&ctx.actor,
	)
	.await?
	{
		PinScope::Group(conv_id) => action.parent_id = Some(conv_id),
		PinScope::Dm(peer) => match action.audience_tag.as_deref() {
			None => action.audience_tag = Some(peer),
			Some(aud) if aud == peer.as_ref() => {}
			Some(_) => {
				return Err(Error::ValidationError("PIN audience is not the DM peer".into()));
			}
		},
	}
	Ok(action)
}

/// PIN `before_receive`: a CONV moderator+ for a group message, a participant for a DM one.
/// PIN needs no subscription (a DM has none), so this is its only gate; a vouched copy is
/// bound to the target room as for MSG edits. A group pin is listed by its CONV parent and its
/// token cannot be rewritten: no `p`, no pin. A hat relay skips the permission gates too, so a
/// relayed PIN whose target is held here is judged like a direct one.
pub(crate) async fn before_receive(app: App, ctx: BeforeReceive) -> ClResult<()> {
	let a = &ctx.action;
	if ctx.pre_approved {
		let primary = ctx.primary.as_ref().map(|(t, i)| (&**t, &**i));
		return super::msg::check_target_room(
			&app,
			ctx.tn_id,
			a.sub.as_deref(),
			a.p.as_deref(),
			primary,
		)
		.await;
	}
	let held = ctx.relayed
		&& match a.sub.as_deref() {
			Some(s) => app.meta_adapter.get_action(ctx.tn_id, s).await?.is_some(),
			None => false,
		};
	if (!ctx.relayed || held)
		&& matches!(
			check_authority(&app, ctx.tn_id, a.sub.as_deref(), a.p.as_deref(), &a.iss).await?,
			PinScope::Group(_)
		) && a.p.is_none()
	{
		return Err(Error::ValidationError("a group PIN needs its CONV as parent".into()));
	}
	Ok(())
}

// vim: ts=4
