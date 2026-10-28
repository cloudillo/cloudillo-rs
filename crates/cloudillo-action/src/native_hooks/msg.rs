// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! MSG (Message) action native hooks
//!
//! A group `CONV` with `MSG` children is structurally a post with comments, so
//! the unread/badge machinery reuses the generic `comments`/`comments_ts`
//! counters rather than a parallel message-count column. These hooks keep the
//! parent CONV's counters current when a flat group message is added, via the
//! same SQL CMNT uses (`cmnt::recompute_comment_stats` with `&["MSG"]`).
//!
//! Scope: only MSGs whose `parent_id` is a **CONV** (the flat group messages the
//! frontend queries as `{type:'MSG', parentId:convId}`). A MSG replying to
//! another MSG (nested) is out of scope, so the counter reflects only top-level
//! group messages.
//!
//! Ownership mirrors CMNT (`ownership::owns_subject`): the CONV's authoritative
//! node maintains the count; mirrors pick it up via the STAT path. After
//! persisting we emit a coalesced STAT so subscribers learn the new
//! `commentCount`/`lastCommentAt` (the group-unread badge) in real time.
//!
//! Notifications are NOT minted here. A stored inbound MSG is broadcast live over WS
//! by `post_store::forward_to_websocket`; when the recipient is offline, that same
//! branch sends push (`process::send_push_notification`) and email
//! (`process::deliver_notification_email`), both behind the conversation
//! mute/mention gate `process::msg_notify_gate`. Each member's node gets the MSG
//! through the DM audience or the CONV fan-out, and re-parses mentions itself.

use crate::helpers::{self, SubscriptionRole, conv_role};
use crate::hooks::{BeforeCreate, BeforeReceive, HookContext, HookResult};
use crate::native_hooks::cmnt::recompute_comment_stats;
use crate::native_hooks::ownership::owns_subject;
use crate::native_hooks::stat_emit::emit_stat_for_subject;
use crate::prelude::*;
use cloudillo_types::action_types::CreateAction;
use cloudillo_types::meta_adapter::{ActionView, PatchReaderState, UpdateActionDataOptions};

/// MSG on_create hook — maintain the parent CONV's message counters for a local
/// outgoing group message. See the module doc for the scoping/ownership rules.
pub async fn on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: MSG on_create for action {}", context.action_id);
	apply_edit(&app, &context).await;
	update_conv_counters(&app, &context, "on_create").await
}

/// MSG on_receive hook — maintain the parent CONV's message counters for an
/// inbound federated group message. See the module doc for the rules.
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!("Native hook: MSG on_receive for action {}", context.action_id);
	apply_edit(&app, &context).await;
	update_conv_counters(&app, &context, "on_receive").await
}

/// The plain MSG (`sub_typ` empty) `id`: `NotFound` when absent, a `ValidationError` naming
/// `what` when it is anything else.
pub(crate) async fn load_plain_msg(
	app: &App,
	tn_id: TnId,
	id: &str,
	what: &str,
) -> ClResult<ActionView> {
	let Some(target) = app.meta_adapter.get_action(tn_id, id).await? else {
		return Err(Error::NotFound);
	};
	if target.typ.as_ref() != "MSG" || target.sub_typ.as_deref().is_some_and(|s| !s.is_empty()) {
		return Err(Error::ValidationError(format!("{what} subject is not a message")));
	}
	Ok(target)
}

/// Pre-store authority for `MSG:UPD` / `MSG:DEL`: `subject` must name a plain MSG
/// held here, and `actor` must be its issuer — or, for `DEL` in a group, a moderator+ of the
/// parent CONV (`helpers::conv_role`). It runs before the row exists (`before_create` /
/// `before_receive`) because a post-store hook cannot roll a stored row back
/// (`HookResult::continue_processing`). Any other type passes untouched.
pub(crate) async fn check_edit_authority(
	app: &App,
	tn_id: TnId,
	(typ, sub_typ): (&str, Option<&str>),
	subject: Option<&str>,
	actor: &str,
) -> ClResult<()> {
	// Both forms reach here: `("MSG", Some("UPD"))` and the token's combined `"MSG:UPD"`.
	let (base, sub) = match typ.split_once(':') {
		Some((b, s)) => (b, Some(s)),
		None => (typ, sub_typ),
	};
	if base != "MSG" || !matches!(sub, Some("UPD" | "DEL")) {
		return Ok(());
	}
	let Some(subject) = subject else {
		return Err(Error::ValidationError(
			"MSG:UPD/MSG:DEL needs the target MSG as subject".into(),
		));
	};
	let target = load_plain_msg(app, tn_id, subject, "MSG:UPD/MSG:DEL").await?;
	if target.issuer.id_tag.as_ref() == actor {
		return Ok(());
	}
	if sub == Some("DEL")
		&& let Some(parent_id) = target.parent_id.as_deref()
		&& let Some(conv) = helpers::get_group(app.meta_adapter.as_ref(), tn_id, parent_id).await?
		&& conv_role(app.meta_adapter.as_ref(), tn_id, &conv, actor).await
			>= SubscriptionRole::Moderator
	{
		return Ok(());
	}
	tracing::warn!(
		"MSG:{:?} by {} of {} denied: not the author or a moderator",
		sub,
		actor,
		subject
	);
	Err(Error::PermissionDenied)
}

/// Pre-approved `MSG:UPD` / `MSG:DEL` / `PIN` / `PIN:DEL`, which skip the
/// author/moderator check: the vouch must be an `APRV` by the owner of the target message's
/// CONV, and a `p` the token carries must be that CONV. A DM target is refused — pre-approval
/// is a room concept, and a DM edit takes the checked path. `MSG:UPD` carries no `p`
/// (`fanout::group_msg_variant_root`), so the room is read from the target, not the token.
pub(crate) async fn check_target_room(
	app: &App,
	tn_id: TnId,
	subject: Option<&str>,
	p: Option<&str>,
	vouched_by: Option<(&str, &str)>,
) -> ClResult<()> {
	let Some(subject) = subject else {
		return Err(Error::ValidationError("edit or pin needs the target MSG as subject".into()));
	};
	let target = app.meta_adapter.get_action(tn_id, subject).await?.ok_or(Error::NotFound)?;
	let Some(conv_id) = target.parent_id.as_deref() else {
		tracing::warn!("pre-approved edit/pin of DM {} refused", subject);
		return Err(Error::PermissionDenied);
	};
	let Some(("APRV", aprv_issuer)) = vouched_by else {
		return Err(Error::PermissionDenied);
	};
	if p.is_some_and(|p| p != conv_id) {
		tracing::warn!("pre-approved edit/pin of {}: p is not its CONV {}", subject, conv_id);
		return Err(Error::PermissionDenied);
	}
	let owned = helpers::get_group(app.meta_adapter.as_ref(), tn_id, conv_id)
		.await?
		.is_some_and(|c| owns_subject(&c, aprv_issuer));
	if !owned {
		tracing::warn!(
			"pre-approved edit/pin of {}: {} does not own its CONV",
			subject,
			aprv_issuer
		);
		return Err(Error::PermissionDenied);
	}
	Ok(())
}

/// Rewrite the target of an (already authorized) `MSG:UPD` / `MSG:DEL` in place.
/// `UPD` sets the new content and `x = {"editedAt": <epoch>}`; `DEL` blanks content and
/// attachments and sets `x = {"deletedBy": <idTag>}`. The row stays listed as a tombstone —
/// never status `D`, which lists hide. A tombstone is final and an edit older than the
/// current one is skipped, so out-of-order delivery converges. The target's conversation
/// (`A:CONV` = its parent, else `P:MSG` with the peer) then recomputes `unread`.
/// Best-effort, like `stamp_reader`.
async fn apply_edit(app: &App, context: &HookContext) {
	let is_del = match context.subtype.as_deref() {
		Some("DEL") => true,
		Some("UPD") => false,
		_ => return,
	};
	let Some(target_id) = context.subject.as_deref() else {
		return;
	};
	let tn_id = context.tn_id;
	let target = match app.meta_adapter.get_action(tn_id, target_id).await {
		Ok(Some(t)) if t.typ.as_ref() == "MSG" => t,
		Ok(_) => {
			tracing::debug!("MSG edit {}: target {} not a held MSG", context.action_id, target_id);
			return;
		}
		Err(e) => {
			tracing::warn!(
				"MSG edit {}: reading target {} failed: {}",
				context.action_id,
				target_id,
				e
			);
			return;
		}
	};
	// The pre-store checks already bind the target's room; a `p` naming another one is refused.
	if context
		.parent
		.as_deref()
		.is_some_and(|p| target.parent_id.as_deref() != Some(p))
	{
		tracing::warn!(
			"MSG edit {}: parent is not the room of target {}",
			context.action_id,
			target_id
		);
		return;
	}
	let at = context.created_at.parse::<i64>().unwrap_or(0).min(Timestamp::now().0);
	let x = target.x.as_ref();
	if x.and_then(|x| x.get("deletedBy")).is_some() {
		return;
	}
	if !is_del
		&& x.and_then(|x| x.get("editedAt"))
			.and_then(serde_json::Value::as_i64)
			.is_some_and(|prev| prev > at)
	{
		return;
	}
	let opts = if is_del {
		UpdateActionDataOptions {
			content: Patch::Null,
			attachments: Patch::Null,
			x: Patch::Value(serde_json::json!({ "deletedBy": context.issuer })),
			..Default::default()
		}
	} else {
		let Some(content) = context.content.as_ref() else {
			return;
		};
		// Stored content is JSON text, the same encoding the create path writes.
		UpdateActionDataOptions {
			content: Patch::Value(content.to_string()),
			x: Patch::Value(serde_json::json!({ "editedAt": at })),
			..Default::default()
		}
	};
	if let Err(e) = app.meta_adapter.update_action_data(tn_id, target_id, &opts).await {
		tracing::warn!("MSG edit {}: rewriting {} failed: {}", context.action_id, target_id, e);
		return;
	}
	// A deleted MSG drops its original token: stop serving / re-delivering it. An edited one
	// keeps it, so an undelivered original still reaches the peer ahead of the UPD.
	if is_del && let Err(e) = app.meta_adapter.delete_action_token(tn_id, target_id).await {
		tracing::warn!(
			"MSG edit {}: dropping token of {} failed: {}",
			context.action_id,
			target_id,
			e
		);
	}
	cloudillo_core::search_index_action(app, tn_id, target_id);

	let (kind, conv_ref) = match target.parent_id.as_deref() {
		Some(parent) => ("A:CONV", parent),
		None if target.issuer.id_tag.as_ref() == context.tenant_tag => {
			let Some(peer) = target.audience.as_ref() else {
				return;
			};
			("P:MSG", peer.id_tag.as_ref())
		}
		None => ("P:MSG", target.issuer.id_tag.as_ref()),
	};
	crate::helpers::recompute_reader_row(app, tn_id, &context.action_id, kind, conv_ref).await;
}

/// Shared body for both MSG hooks: when this MSG is a flat child of a CONV we own,
/// recompute the CONV's `comments`/`comments_ts` from its live MSG children,
/// persist them, and schedule a coalesced STAT broadcast. No-op if the MSG has no
/// parent, a non-CONV parent, or a CONV we aren't authoritative for.
async fn update_conv_counters(
	app: &App,
	context: &HookContext,
	phase: &str,
) -> ClResult<HookResult> {
	let tn_id = context.tn_id;
	// Edit/delete variants are not new messages: they neither stamp nor unarchive.
	let is_new = !matches!(context.subtype.as_deref(), Some("DEL" | "UPD"));
	// Our own message coming back (e.g. relayed by a CONV owner) is not incoming.
	let incoming = is_new && context.issuer != context.tenant_tag;
	let Some(parent_id) = &context.parent else {
		// A bare MSG (no parent) is a 1:1 direct message — no CONV counter to keep,
		// but it stamps the `P:MSG` reader-state row of the peer (audience for our own
		// DM, issuer for one addressed to us), creating it on the first DM either way.
		// Our own without an audience is no DM (it fans out via `subject`), and an incoming
		// one addressed elsewhere (a hat relay through this node) is not our conversation.
		let peer = if context.issuer == context.tenant_tag {
			context.audience.as_deref()
		} else if context.audience.as_deref() == Some(context.tenant_tag.as_str()) {
			Some(context.issuer.as_str())
		} else {
			None
		};
		if is_new && let Some(peer) = peer {
			stamp_reader(app, context, "P:MSG", peer, true, incoming, None).await;
		}
		tracing::debug!("MSG {}: no parent — skipping CONV counter update", phase);
		return Ok(HookResult::default());
	};

	let Some(parent_action) = app.meta_adapter.get_action(tn_id, parent_id).await? else {
		tracing::debug!("MSG {}: parent action {} not found locally", phase, parent_id);
		return Ok(HookResult::default());
	};

	// Scope: only group messages (parent is a CONV). Replies to another MSG (nested)
	// are out of scope and must not touch the CONV counter.
	if parent_action.typ.as_ref() != "CONV" {
		tracing::debug!(
			"MSG {}: parent {} is a {} (not a CONV) — out of scope, skipping",
			phase,
			parent_id,
			parent_action.typ
		);
		return Ok(HookResult::default());
	}

	// The reader's own `A:CONV` row (owned or mirror, update-only: the row comes from
	// joining, `subs::on_create`), so before the ownership gate below.
	if is_new {
		stamp_reader(app, context, "A:CONV", parent_id, false, incoming, Some(&parent_action))
			.await;
	}

	if !owns_subject(&parent_action, &context.tenant_tag) {
		tracing::debug!(
			"MSG {}: CONV {} not owned by us ({}) — skipping count update (STAT mirror path handles counters)",
			phase,
			parent_id,
			context.tenant_tag
		);
		return Ok(HookResult::default());
	}

	// Recompute the CONV's message stats from its live MSG children — reuses the
	// same recompute SQL CMNT uses, parameterized to MSG children.
	let (count, comments_ts) = recompute_comment_stats(app, tn_id, parent_id, &["MSG"]).await?;
	tracing::info!(
		"MSG{} {}: {} in CONV {} → STAT broadcast (count={}, ts={})",
		if context.subtype.as_deref() == Some("DEL") { ":DEL" } else { "" },
		phase,
		context.issuer,
		parent_id,
		count,
		comments_ts
	);

	let update_opts = UpdateActionDataOptions {
		comments: Patch::Value(count),
		comments_ts: if comments_ts > 0 {
			Patch::Value(Timestamp(comments_ts))
		} else {
			Patch::Null
		},
		..Default::default()
	};

	if let Err(e) = app.meta_adapter.update_action_data(tn_id, parent_id, &update_opts).await {
		tracing::warn!("MSG {}: failed to update CONV {} message stats: {}", phase, parent_id, e);
		return Ok(HookResult::default());
	}

	emit_stat_for_subject(app, tn_id, &context.tenant_tag, parent_id).await;

	Ok(HookResult::default())
}

/// Stamp the reader's conversation row with this new MSG — `P:MSG` (ref = the peer,
/// `insert` creates it when missing) or `A:CONV` (update-only). An `incoming` one also
/// clears `archived` (update-only, never creates a row), recomputes `unread` and, when it
/// mentions the reader ([`crate::helpers::is_mention`]; `conv` is the group, `None` for a
/// DM), stamps `mentionedAt`. Best-effort: a failure is logged and never fails the hook.
async fn stamp_reader(
	app: &App,
	context: &HookContext,
	kind: &str,
	ref_: &str,
	insert: bool,
	incoming: bool,
	conv: Option<&ActionView>,
) {
	let tn_id = context.tn_id;
	let at = crate::helpers::stamp_reader_row(app, context, kind, ref_, insert).await;
	if !incoming {
		return;
	}
	let meta = &app.meta_adapter;
	let unarchive = PatchReaderState { archived: Patch::Null, ..Default::default() };
	if let Err(e) = meta.patch_reader_state(tn_id, kind, ref_, &unarchive, false).await {
		tracing::warn!("MSG: failed to unarchive {} {}: {}", kind, ref_, e);
	}
	crate::helpers::recompute_reader_row(app, tn_id, &context.action_id, kind, ref_).await;
	let content = context.content.as_ref();
	if crate::helpers::is_mention(app, tn_id, &context.tenant_tag, &context.issuer, content, conv)
		.await && let Err(e) = meta.stamp_reader_mention(tn_id, kind, ref_, at).await
	{
		tracing::warn!(
			"MSG {}: mention stamp on {} {} failed: {}",
			context.action_id,
			kind,
			ref_,
			e
		);
	}
}

/// MSG `before_create`: edit/delete authority. The actor is the poster: on a
/// community every member posts as the CONV-creating tenant.
pub(crate) async fn before_create(app: App, ctx: BeforeCreate) -> ClResult<CreateAction> {
	check_edit_authority(
		&app,
		ctx.tn_id,
		(ctx.action.typ.as_ref(), ctx.action.sub_typ.as_deref()),
		ctx.action.subject.as_deref(),
		&ctx.actor,
	)
	.await?;
	Ok(ctx.action)
}

/// MSG `before_receive`: only the target's author, or a CONV moderator+ for a group DEL.
/// `check_subscription_permissions` lets any member through, and the post-store hook could not
/// undo the row. A copy the CONV owner vouched for was judged on the owner's node, the only one
/// holding authoritative roles (`helpers::conv_role`), so a pre-approved one only proves the
/// vouch came from that owner, not any APRV or REPOST ([`check_target_room`]). A hat relay
/// skips the permission gates too, so a relayed UPD/DEL whose target is held here is judged
/// like a direct one; one whose target is not local edits nothing (`apply_edit`).
pub(crate) async fn before_receive(app: App, ctx: BeforeReceive) -> ClResult<()> {
	let a = &ctx.action;
	let edit = matches!(a.t.as_ref(), "MSG:UPD" | "MSG:DEL");
	let held = ctx.relayed
		&& edit
		&& match a.sub.as_deref() {
			Some(s) => app.meta_adapter.get_action(ctx.tn_id, s).await?.is_some(),
			None => false,
		};
	if !ctx.pre_approved && (!ctx.relayed || held) {
		check_edit_authority(&app, ctx.tn_id, (&a.t, None), a.sub.as_deref(), &a.iss).await
	} else if ctx.pre_approved && edit {
		let primary = ctx.primary.as_ref().map(|(t, i)| (&**t, &**i));
		check_target_room(&app, ctx.tn_id, a.sub.as_deref(), a.p.as_deref(), primary).await
	} else {
		Ok(())
	}
}

// vim: ts=4
