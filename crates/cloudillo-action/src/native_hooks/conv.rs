// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! CONV (Conversation) action native hooks
//!
//! Handles conversation lifecycle:
//! - on_create: Auto-creates SUBS with admin role for the creator of a personal group. A
//!   community group (issued by the community, `x.createdBy` = the member) gets none: the
//!   creator's admin SUBS comes from their home node and is stamped in `subs::on_receive`.
//! - on_receive: Lists a group in the inbox when it arrives after our own SUBS
//! - Subtypes:
//!   - UPD: Update conversation settings (its own definition and hooks, `upd_*` below)
//!   - DEL: Archive/delete conversation (requires admin role)

use crate::helpers;
use crate::hooks::{BeforeCreate, BeforeReceive, HookContext, HookResult};
use crate::native_hooks::ownership::owns_subject;
use crate::prelude::*;
use crate::task::{CreateAction, create_action};
use cloudillo_core::roles;
use cloudillo_types::meta_adapter::{
	ActionView, PatchReaderState, ProfileType, UpdateActionDataOptions,
};

/// CONV on_create hook - Auto-subscribe the creator of a personal group as admin
///
/// Logic:
/// - Creator creates their own SUBS with subject=action_id, audience=self
/// - Role is stored in x.role (extensible metadata), not in content JWT
/// - On a community tenant there is no self-SUBS: the community is the owner (fan-out skips
///   it, `fanout::schedule_subscriber_fanout`), and the member who created it subscribes
///   from their home node.
pub async fn on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	let tn_id = context.tn_id;

	tracing::info!("CONV: Creating conversation {} by {}", context.action_id, context.issuer);

	if app.meta_adapter.read_tenant(tn_id).await?.typ == ProfileType::Community {
		return Ok(HookResult::default());
	}

	let subs_action = CreateAction {
		typ: "SUBS".into(),
		audience_tag: Some(context.issuer.clone().into_boxed_str()),
		subject: Some(context.action_id.clone().into()),
		// x.role stores the subscription role (server-side, not in JWT)
		x: Some(serde_json::json!({ "role": "admin" })),
		..Default::default()
	};

	match create_action(&app, tn_id, &context.issuer, subs_action).await {
		Ok(subs_id) => {
			tracing::info!(
				"CONV: Auto-created admin SUBS {} for conversation {}",
				subs_id,
				context.action_id
			);
		}
		Err(e) => {
			tracing::error!(
				"CONV: Failed to create admin SUBS for conversation {}: {}",
				context.action_id,
				e
			);
			// Don't fail the CONV creation - log and continue
		}
	}

	Ok(HookResult::default())
}

/// CONV on_receive hook - Handle receiving shared conversation
///
/// Logic:
/// - SUBS handles membership; the CONV is stored for reference
/// - A community group reaches a joiner's home node after their own SUBS (roster backfill,
///   `fanout::backfill_roster_to_joiner`), so `subs::on_create` found no local CONV and wrote
///   no `A:CONV` reader-state row. Write it here when our own SUBS on it is active.
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("CONV: Received conversation {} from {}", context.action_id, context.issuer);

	if context.subtype.is_some() {
		return Ok(HookResult::default());
	}
	let tn_id = context.tn_id;
	let key = format!("SUBS:{}:{}", context.action_id, context.tenant_tag);
	let Some(subs) = app.meta_adapter.get_action_by_key(tn_id, &key).await.ok().flatten() else {
		return Ok(HookResult::default());
	};
	let active = app
		.meta_adapter
		.get_action(tn_id, subs.action_id.as_ref())
		.await
		.ok()
		.flatten()
		.is_some_and(|v| v.sub_typ.is_none() && v.status.as_deref() == Some("A"));
	// Only the first arrival marks the history read: a re-delivered CONV must not.
	let first = matches!(
		app.meta_adapter.get_reader_state(tn_id, "A:CONV", &context.action_id).await,
		Ok(None)
	);
	if active
		&& first
		&& let Err(e) = app
			.meta_adapter
			.patch_reader_state(
				tn_id,
				"A:CONV",
				&context.action_id,
				&PatchReaderState { read_at: Some(Timestamp::now()), ..Default::default() },
				true,
			)
			.await
	{
		tracing::warn!("CONV on_receive: reader state of {} failed: {}", context.action_id, e);
	}

	Ok(HookResult::default())
}

/// Group-admin ops posted by someone other than the tenant (a member on a community node) are
/// issued as the tenant, the CONV's owner, so every creator compare downstream would pass.
/// Judge the actor's effective role on the named CONV instead.
pub(crate) async fn check_admin_actor(app: &App, ctx: &BeforeCreate) -> ClResult<()> {
	if ctx.actor == ctx.tenant_tag {
		return Ok(());
	}
	let conv = match ctx.action.subject.as_deref() {
		Some(subject) => app.meta_adapter.get_action(ctx.tn_id, subject).await?,
		None => None,
	};
	let need = helpers::SubscriptionRole::required_for_action(&ctx.typ, ctx.sub_typ.as_deref());
	let allowed = match &conv {
		Some(conv) if &*conv.typ == "CONV" => {
			helpers::conv_role(app.meta_adapter.as_ref(), ctx.tn_id, conv, &ctx.actor).await >= need
		}
		Some(_) => true,
		None => ctx.typ != "CONV",
	};
	if !allowed {
		tracing::warn!(
			"Rejecting {} by {}: below the group role it needs",
			ctx.action.typ,
			ctx.actor
		);
		return Err(Error::PermissionDenied);
	}
	Ok(())
}

/// CONV `before_create`: for a community-owned group (already issued as the community) the
/// creation gate and the creator stamp. `x` is replaced, never merged, so a client can forge
/// neither `createdBy` nor a role; SUBS `on_receive` reads it to make the creator admin.
pub(crate) async fn before_create(app: App, ctx: BeforeCreate) -> ClResult<CreateAction> {
	match ctx.sub_typ.as_deref() {
		None if app.meta_adapter.read_tenant(ctx.tn_id).await?.typ == ProfileType::Community => {
			// The community owns it outright: an audience would make someone else its owner
			// (`owns_subject`) and fan-out hub.
			if ctx.action.audience_tag.is_some() {
				return Err(Error::ValidationError("a community group takes no audience".into()));
			}
			let need = app
				.settings
				.get_string(ctx.tn_id, "conv.create_min_role")
				.await
				.ok()
				.and_then(|r| roles::role_level(&r))
				.filter(|&l| l > roles::FOLLOWER_LEVEL)
				.unwrap_or(roles::CONTRIBUTOR_LEVEL);
			if roles::highest_role_level(&ctx.actor_roles) < need {
				tracing::warn!(
					"Rejecting group creation by {}: below conv.create_min_role",
					ctx.actor
				);
				return Err(Error::PermissionDenied);
			}
			let mut action = ctx.action;
			action.x = Some(serde_json::json!({ "createdBy": ctx.actor.as_ref() }));
			return Ok(action);
		}
		_ => {}
	}
	Ok(ctx.action)
}

/// The plain CONV a CONV:UPD names as `subject`, held here.
async fn load_upd_target(app: &App, tn_id: TnId, subject: Option<&str>) -> ClResult<ActionView> {
	let Some(id) = subject else {
		return Err(Error::ValidationError("CONV:UPD needs the CONV as subject".into()));
	};
	helpers::get_group(app.meta_adapter.as_ref(), tn_id, id)
		.await?
		.ok_or_else(|| Error::ValidationError("CONV:UPD subject is not a held group".into()))
}

/// CONV:UPD `before_create`: only the tenant itself issues one (a member posting onto a
/// community node has no path). On the CONV's host it carries no audience and is applied
/// right away; anywhere else it is a request addressed to the host, which checks the role.
pub(crate) async fn upd_before_create(app: App, ctx: BeforeCreate) -> ClResult<CreateAction> {
	let conv = load_upd_target(&app, ctx.tn_id, ctx.action.subject.as_deref()).await?;
	if ctx.actor != ctx.tenant_tag {
		tracing::warn!("Rejecting CONV:UPD by {}: not the tenant", ctx.actor);
		return Err(Error::PermissionDenied);
	}
	if !addressed_to_host(&conv, &ctx.tenant_tag, ctx.action.audience_tag.as_deref()) {
		return Err(Error::ValidationError(
			"CONV:UPD is addressed to the group's host, or to no one on the host".into(),
		));
	}
	Ok(ctx.action)
}

/// A host-side group change (CONV:UPD, SUBS:ROLE) carries no audience on the CONV's host, and
/// is addressed to the host anywhere else.
pub(crate) fn addressed_to_host(
	conv: &ActionView,
	tenant_tag: &str,
	audience: Option<&str>,
) -> bool {
	let hosted = owns_subject(conv, tenant_tag);
	match audience {
		None => hosted,
		Some(aud) => !hosted && owns_subject(conv, aud),
	}
}

/// Whether an inbound host-side group change on `conv` is admitted: a copy the host vouched
/// for (APRV by the CONV's owner), the host's own change, or — on the host — a request from a
/// group admin addressed to us.
pub(crate) async fn host_change_admitted(
	app: &App,
	ctx: &BeforeReceive,
	conv: &ActionView,
) -> ClResult<bool> {
	let a = &ctx.action;
	if ctx.pre_approved {
		return Ok(
			matches!(&ctx.primary, Some((t, by)) if &**t == "APRV" && owns_subject(conv, by)),
		);
	}
	if owns_subject(conv, &a.iss) {
		return Ok(true);
	}
	let us = app.auth_adapter.read_id_tag(ctx.tn_id).await?;
	Ok(owns_subject(conv, &us)
		&& a.aud.as_deref() == Some(&*us)
		&& helpers::conv_role(app.meta_adapter.as_ref(), ctx.tn_id, conv, &a.iss).await
			>= helpers::SubscriptionRole::Admin)
}

/// The object `x` cloned (or `{}`), to stamp a change made `at`; `None` when the change already
/// applied (`x[stamp_key]`) is newer, so out-of-order delivery converges.
pub(crate) fn x_if_newer(
	x: Option<&serde_json::Value>,
	stamp_key: &str,
	at: i64,
) -> Option<serde_json::Value> {
	if x.and_then(|x| x.get(stamp_key))
		.and_then(serde_json::Value::as_i64)
		.is_some_and(|prev| prev > at)
	{
		return None;
	}
	Some(x.filter(|x| x.is_object()).cloned().unwrap_or_else(|| serde_json::json!({})))
}

/// CONV:UPD `before_receive`: a copy the host vouched for (APRV by the CONV's owner), the
/// host's own edit, or — on the host — a request from a group admin addressed to us.
pub(crate) async fn upd_before_receive(app: App, ctx: BeforeReceive) -> ClResult<()> {
	let a = &ctx.action;
	let conv = load_upd_target(&app, ctx.tn_id, a.sub.as_deref()).await?;
	if !host_change_admitted(&app, &ctx, &conv).await? {
		tracing::warn!("Rejecting CONV:UPD of {:?} by {}: not a group admin", a.sub, a.iss);
		return Err(Error::PermissionDenied);
	}
	Ok(())
}

/// CONV:UPD `on_create`: the host's own edit (no audience, `upd_before_create`) applies here.
/// An admin's request applies once the host approves it (`aprv::on_receive`).
pub async fn upd_on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	if context.audience.is_none() {
		apply_upd(&app, context.tn_id, &context.action_id).await;
	}
	Ok(HookResult::default())
}

/// CONV:UPD `on_receive`: `upd_before_receive` admitted it (request on the host, vouched copy
/// or the host's own edit on a member).
pub async fn upd_on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	apply_upd(&app, context.tn_id, &context.action_id).await;
	Ok(HookResult::default())
}

/// `flags` with its open letter set to `O` / `o`, every other letter (`r`, `c`) kept.
fn with_open(flags: &str, open: bool) -> String {
	let letter = if open { 'O' } else { 'o' };
	if flags.contains(['O', 'o']) {
		flags.chars().map(|c| if c == 'O' || c == 'o' { letter } else { c }).collect()
	} else {
		format!("{flags}{letter}")
	}
}

/// Rewrite the CONV a stored, already authorized CONV:UPD names: its content, `x.editedAt` /
/// `x.editedBy` merged into the existing `x` (community CONVs carry `x.createdBy`), and the
/// open letter when the UPD carries one. An update older than the applied one is skipped, so
/// out-of-order delivery converges. Best-effort, like `msg::apply_edit`.
// unlike `msg::apply_edit` the CONV token is kept (joiners need it), so joiners get
// the original settings until the next UPD; backfill the latest CONV:UPD if that matters.
pub(crate) async fn apply_upd(app: &App, tn_id: TnId, upd_id: &str) {
	let upd = match app.meta_adapter.get_action(tn_id, upd_id).await {
		Ok(Some(u)) => u,
		Ok(None) => return,
		Err(e) => {
			tracing::warn!("CONV:UPD {}: reading it failed: {}", upd_id, e);
			return;
		}
	};
	let (Some(target_id), Some(content)) = (upd.subject.as_deref(), upd.content.as_ref()) else {
		return;
	};
	let target = match load_upd_target(app, tn_id, Some(target_id)).await {
		Ok(t) => t,
		Err(e) => {
			tracing::warn!("CONV:UPD {}: target {}: {}", upd_id, target_id, e);
			return;
		}
	};
	let at = upd.created_at.0;
	let Some(mut x) = x_if_newer(target.x.as_ref(), "editedAt", at) else {
		return;
	};
	x["editedAt"] = at.into();
	x["editedBy"] = upd.issuer.id_tag.as_ref().into();
	let flags = match upd.flags.as_deref() {
		Some(f) if f.contains(['O', 'o']) => {
			Patch::Value(with_open(target.flags.as_deref().unwrap_or(""), f.contains('O')))
		}
		_ => Patch::Undefined,
	};
	let opts = UpdateActionDataOptions {
		// Stored content is JSON text, the same encoding the create path writes.
		content: Patch::Value(content.to_string()),
		x: Patch::Value(x),
		flags,
		..Default::default()
	};
	if let Err(e) = app.meta_adapter.update_action_data(tn_id, target_id, &opts).await {
		tracing::warn!("CONV:UPD {}: rewriting {} failed: {}", upd_id, target_id, e);
		return;
	}
	cloudillo_core::search_index_action(app, tn_id, target_id);
}

#[cfg(test)]
mod tests {
	use super::with_open;

	#[test]
	fn with_open_toggles_only_the_open_letter() {
		assert_eq!(with_open("rco", true), "rcO");
		assert_eq!(with_open("rcO", false), "rco");
		assert_eq!(with_open("rc", true), "rcO");
		assert_eq!(with_open("", false), "o");
	}
}

// vim: ts=4
