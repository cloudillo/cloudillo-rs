// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Shared helper functions for action processing

use std::collections::HashSet;
use std::convert::Infallible;
use std::str::FromStr;

use crate::prelude::*;
use crate::subject_ref::{SubjectRef, parse_subject_ref};
use cloudillo_types::meta_adapter::{
	ActionView, Channel, ListActionOptions, MetaAdapter, ProfileStatus,
};

/// Profiles whose SUBS no longer count as membership.
pub(crate) const INACTIVE_MEMBER_STATUSES: [ProfileStatus; 3] =
	[ProfileStatus::Suspended, ProfileStatus::Blocked, ProfileStatus::Banned];

// ponytail: one unpaged query, page if groups outgrow this
const MAX_MEMBER_LIST: u32 = 10_000;

/// Active members of `subject`: SUBS at status `A`, not `DEL`, issuer not suspended, blocked or
/// banned (enforced in SQL, so an adapter error fails the list rather than failing open).
pub(crate) fn active_subs_opts(subject: &str) -> ListActionOptions {
	ListActionOptions {
		typ: Some(vec!["SUBS".into()]),
		subject: Some(vec![subject.to_string()]),
		status: Some(vec!["A".into()]),
		exclude_sub_typ: Some(Box::from([Box::from("DEL")])),
		exclude_issuer_profile_status: Some(Box::from(INACTIVE_MEMBER_STATUSES)),
		limit: Some(MAX_MEMBER_LIST),
		..Default::default()
	}
}

/// Gate an identity-valued action field (`iss`, `aud`) on being a **canonical**
/// id_tag — a UTS #46 U-label, per [`cloudillo_types::validation::validate_id_tag`].
///
/// The action format constrains its identities rather than normalising them: a
/// mixed-case, punycoded or otherwise non-canonical identity would be signed into the
/// token, federate under a name that does not match the peer's stored identity, and key
/// local rows off a third form. Enforced at both boundaries — the inbound verifier
/// (`process::verify_action_token`) and the local creator (`task::create_action`).
///
/// `field` names the offending claim in the error.
pub fn check_identity_field(field: &str, id_tag: &str) -> ClResult<()> {
	if cloudillo_types::validation::validate_id_tag(id_tag) {
		Ok(())
	} else {
		Err(Error::ValidationError(format!("invalid {field} id_tag: {id_tag}")))
	}
}

/// Gate an action `subject` that carries an identity (`@<id_tag>`) on the same canonical
/// form [`check_identity_field`] demands of `iss` and `aud`.
///
/// A [`SubjectRef::Channel`] (`@tenant~name`) has its tenant checked the same way.
/// [`SubjectRef::Action`] (`a1~…`) and [`SubjectRef::Placeholder`] (`@42`) are not
/// identities and pass untouched. An unparsable subject also passes here.
///
/// The community-INVT lookups build their filter as `format!("@{}", community_tag)` from a
/// canonical tag (`native_hooks/invt.rs`, `native_hooks/conn.rs`) while the adapter does an
/// exact `a.subject IN (…)`, so an INVT federated with `sub = "@Club.Example.COM"` stored that
/// spelling and matched nothing — a since-demoted inviter could not withdraw their own
/// invitation. Normalising at the comparison sites would have been the wrong fix; the storage
/// invariant is enforced on write, here.
pub fn check_subject_field(subject: &str) -> ClResult<()> {
	match parse_subject_ref(subject) {
		Some(SubjectRef::Identity(id_tag) | SubjectRef::Channel { tenant: id_tag, .. }) => {
			check_identity_field("subject", id_tag)
		}
		Some(SubjectRef::Action(_) | SubjectRef::Placeholder(_)) | None => Ok(()),
	}
}

/// Cap on how many files one action may attach.
///
/// Each entry costs a full `file_access` ladder walk in `handler::post_action`
/// (read_file, share entry, parent-chain walk, FSHR lookup, sometimes a relationship
/// read) plus a `resolve_attachments` lookup in `task.rs`, all sequential on the read
/// pool — so an unbounded list turns one authenticated POST into ~10^5 queries.
/// Generous for a media post; raise it only alongside a producer that needs more.
pub const MAX_ATTACHMENTS: usize = 32;

/// Reject an over-long attachment list before anything walks it.
pub fn check_attachment_count(attachments: Option<&[Box<str>]>) -> ClResult<()> {
	let count = attachments.map_or(0, <[_]>::len);
	if count > MAX_ATTACHMENTS {
		return Err(Error::ValidationError(format!(
			"too many attachments ({count}, max {MAX_ATTACHMENTS})"
		)));
	}
	Ok(())
}

/// Extract type and optional subtype from type string (e.g., "POST:TEXT" -> ("POST", Some("TEXT")))
pub fn extract_type_and_subtype(type_str: &str) -> (String, Option<String>) {
	if let Some(colon_pos) = type_str.find(':') {
		let (t, st) = type_str.split_at(colon_pos);
		(t.to_string(), Some(st[1..].to_string()))
	} else {
		(type_str.to_string(), None)
	}
}

/// Apply key pattern with action field substitutions for deduplication
///
/// Besides the action fields, `{content.<field>}` resolves a top-level field of the
/// action content — IDP:REG and APKG key their dedup on an identity/package name that
/// only exists in the content. A field that is absent, null or non-scalar substitutes
/// empty, matching how the optional action fields degrade.
pub fn apply_key_pattern(
	pattern: &str,
	action_type: &str,
	issuer: &str,
	audience: Option<&str>,
	parent: Option<&str>,
	subject: Option<&str>,
	content: Option<&serde_json::Value>,
) -> String {
	let mut result = pattern
		.replace("{type}", action_type)
		.replace("{issuer}", issuer)
		.replace("{audience}", audience.unwrap_or(""))
		.replace("{parent}", parent.unwrap_or(""))
		.replace("{subject}", subject.unwrap_or(""));

	while let Some(start) = result.find("{content.") {
		// A pattern missing its closing brace would otherwise loop forever
		let Some(len) = result[start..].find('}') else { break };
		let end = start + len;
		let field = &result[start + "{content.".len()..end];
		let value = match content.and_then(|c| c.as_object()).and_then(|o| o.get(field)) {
			Some(serde_json::Value::String(s)) => s.clone(),
			Some(v) if v.is_number() || v.is_boolean() => v.to_string(),
			_ => String::new(),
		};
		result.replace_range(start..=end, &value);
	}
	result
}

/// Serialize content Value to JSON string
pub fn serialize_content(content: Option<&serde_json::Value>) -> Option<String> {
	content.map(|v| serde_json::to_string(v).unwrap_or_default())
}

/// Derive a short rendering snippet from an action's content value.
///
/// Handles the common content shapes: a bare `String`, an object with a `text`,
/// `content` or `title` field (POST:LDOC carries only the document `title` when the
/// author adds no commentary), or any other value (rendered via `to_string`). Caps
/// the result at 200 characters. Used by the offline email notification path
/// (`process::deliver_notification_email`).
pub(crate) fn content_snippet(content: Option<&serde_json::Value>) -> String {
	content_text(content).chars().take(200).collect()
}

/// The full text behind [`content_snippet`], uncapped.
fn content_text(content: Option<&serde_json::Value>) -> String {
	match content {
		Some(serde_json::Value::String(s)) => s.clone(),
		Some(serde_json::Value::Object(o)) => o
			.get("text")
			.or_else(|| o.get("content"))
			.or_else(|| o.get("title"))
			.and_then(|v| v.as_str())
			.map(str::to_string)
			.unwrap_or_default(),
		Some(other) => other.to_string(),
		None => String::new(),
	}
}

/// Scan MSG content for `@idTag` mention tokens: returns `(mentions_me, mentions_all)`.
///
/// A token is `@` not preceded by an alphanumeric (so `bob@x.org` is no mention),
/// followed by id_tag characters; a trailing `.` (sentence end) is dropped. `@all` is
/// reported raw — whether it counts depends on the issuer's role ([`conv_role`]).
pub fn parse_mentions(content: Option<&serde_json::Value>, me: &str) -> (bool, bool) {
	let text = content_text(content);
	let (mut mine, mut all) = (false, false);
	let mut parts = text.split('@');
	let mut prev = parts.next().unwrap_or_default();
	for part in parts {
		if !prev.chars().next_back().is_some_and(char::is_alphanumeric) {
			let end = part
				.find(|c: char| !(c.is_alphanumeric() || matches!(c, '.' | '-' | '_')))
				.unwrap_or(part.len());
			let tag = part[..end].trim_end_matches('.');
			if tag == "all" {
				all = true;
			} else if !tag.is_empty() && tag.eq_ignore_ascii_case(me) {
				mine = true;
			}
		}
		prev = part;
	}
	(mine, all)
}

/// Read-receipt reciprocity: a tenant with `msg.send_read_receipts` off is shown no RCPT but
/// its own. True when the action (`typ`, `issuer`) must be hidden from the tenant.
pub(crate) async fn rcpt_hidden(
	app: &App,
	tn_id: TnId,
	typ: &str,
	issuer: &str,
	tenant_tag: &str,
) -> bool {
	typ == "RCPT"
		&& issuer != tenant_tag
		&& !app.settings.get_bool(tn_id, "msg.send_read_receipts").await.unwrap_or(true)
}

/// Effective role of `issuer` in the conversation `conv`, from **this node's own rows**:
/// the CONV issuer is `Admin`, anyone else gets the `x.role` of the local
/// `SUBS:{conv}:{issuer}` row ([`get_subscription_role`]), `Observer` without one — raised on a
/// community group by the mapped community role ([`effective_role`]).
///
/// Only the CONV owner's node has authoritative roles: inbound SUBS rows carry no `x`, so
/// on a member node every non-creator reads as `Member`. A delegated moderator therefore
/// counts as moderator on the owner node only; the creator counts everywhere.
pub async fn conv_role<M: MetaAdapter + ?Sized>(
	meta: &M,
	tn_id: TnId,
	conv: &ActionView,
	issuer: &str,
) -> SubscriptionRole {
	if conv.issuer.id_tag.as_ref() == issuer {
		return SubscriptionRole::Admin;
	}
	let key = format!("SUBS:{}:{}", conv.action_id, issuer);
	let subs = match meta.get_action_by_key(tn_id, &key).await {
		Ok(Some(sub)) => get_subscription_role(sub.x.as_ref()),
		_ => SubscriptionRole::Observer,
	};
	effective_role(meta, tn_id, conv, issuer, subs).await
}

/// The group role `subs` of `member` in `conv`, combined with their community role:
/// on a community group (`x.createdBy` set, which only the owning community's row has) it is
/// max(`subs`, mapped role), leader → `Admin`, moderator → `Moderator`, anyone else keeps
/// `subs`. A personal group returns `subs` unchanged. Read at every check: there is no
/// role-change hook, so a lost community role takes effect lazily, at the next one.
pub async fn effective_role<M: MetaAdapter + ?Sized>(
	meta: &M,
	tn_id: TnId,
	conv: &ActionView,
	member: &str,
	subs: SubscriptionRole,
) -> SubscriptionRole {
	if conv_created_by(conv.x.as_ref()).is_none() {
		return subs;
	}
	let mapped = match community_level(meta, tn_id, member).await {
		l if l >= cloudillo_core::roles::LEADER_LEVEL => SubscriptionRole::Admin,
		l if l >= cloudillo_core::roles::MODERATOR_LEVEL => SubscriptionRole::Moderator,
		_ => SubscriptionRole::Observer,
	};
	subs.max(mapped)
}

/// `member`'s highest community-ladder level on this tenant (`ROLE_HIERARCHY` index): 0 without
/// a profile or for an access-restricted one (`read_profile_roles` drops those), 1
/// (`FOLLOWER_LEVEL`) for a mere follower. A real member is above `FOLLOWER_LEVEL`.
pub async fn community_level<M: MetaAdapter + ?Sized>(
	meta: &M,
	tn_id: TnId,
	member: &str,
) -> usize {
	match meta.read_profile_roles(tn_id, member).await {
		Ok(Some(roles)) => cloudillo_core::roles::highest_role_level(&roles),
		_ => 0,
	}
}

/// Whether a MSG mentions the reader `me`: a personal `@me` ([`parse_mentions`]), or `@all`
/// from a moderator+ `issuer` of the group `conv` ([`conv_role`]) unless the reader ignores
/// `@all` — per conversation (`conv`'s `A:CONV` reader-state `ignoreAll`) or globally (the
/// `msg.ignore_all` setting). A DM (`conv` None) has no `@all`. Shared by the notify gate
/// (`process::msg_notify_gate`) and the MSG hook's mention stamp (`native_hooks::msg`).
pub async fn is_mention(
	app: &App,
	tn_id: TnId,
	me: &str,
	issuer: &str,
	content: Option<&serde_json::Value>,
	conv: Option<&ActionView>,
) -> bool {
	let (mine, all) = parse_mentions(content, me);
	if mine {
		return true;
	}
	let Some(conv) = conv.filter(|_| all) else {
		return false;
	};
	!conv.reader_state.as_ref().is_some_and(|r| r.ignore_all)
		&& !app.settings.get_bool(tn_id, "msg.ignore_all").await.unwrap_or(false)
		&& conv_role(app.meta_adapter.as_ref(), tn_id, conv, issuer).await
			>= SubscriptionRole::Moderator
}

/// Stamp the reader-state row `kind`/`ref_` with the hook's action (`last_id`/`last_at`;
/// `insert` creates a missing row). The time is the action's `created_at` capped at now (hooks
/// run after the insert), the unread timeline's clock: clients mark read by creation time.
/// Returns the stamped time, even when the write failed. Best-effort: a failure is logged.
pub(crate) async fn stamp_reader_row(
	app: &App,
	ctx: &crate::hooks::HookContext,
	kind: &str,
	ref_: &str,
	insert: bool,
) -> Timestamp {
	let now = Timestamp::now().0;
	let at = Timestamp(ctx.created_at.parse::<i64>().unwrap_or(now).min(now));
	if let Err(e) = app
		.meta_adapter
		.stamp_reader_activity(ctx.tn_id, kind, ref_, &ctx.action_id, at, insert)
		.await
	{
		tracing::warn!("{}: stamping {} {} failed: {}", ctx.action_id, kind, ref_, e);
	}
	at
}

/// The plain group CONV `id` held here (not a CONV:UPD row), `None` otherwise.
pub(crate) async fn get_group<M: MetaAdapter + ?Sized>(
	meta: &M,
	tn_id: TnId,
	id: &str,
) -> ClResult<Option<ActionView>> {
	Ok(meta
		.get_action(tn_id, id)
		.await?
		.filter(|c| &*c.typ == "CONV" && c.sub_typ.as_deref().is_none_or(str::is_empty)))
}

/// POST `token` to each recipient's inbox, ≤ 8 at a time. Fire-and-forget, for never-stored
/// hints (a retry would land too late to matter).
// ponytail: 8 concurrent posts per call; a shared outbound limiter if these pile up
pub(crate) fn spawn_inbox_posts(app: &App, tn_id: TnId, recipients: Vec<Box<str>>, token: &str) {
	if recipients.is_empty() {
		return;
	}
	let payload = serde_json::json!({ "token": token });
	let app = app.clone();
	tokio::spawn(async move {
		let mut set = tokio::task::JoinSet::new();
		for recipient in recipients {
			if set.len() >= 8 {
				set.join_next().await;
			}
			let app = app.clone();
			let payload = payload.clone();
			set.spawn(async move {
				if let Err(e) = app
					.request
					.post::<serde_json::Value>(tn_id, &recipient, "/inbox", &payload)
					.await
				{
					debug!(recipient = %recipient, error = %e, "inbox post failed");
				}
			});
		}
		while set.join_next().await.is_some() {}
	});
}

/// Recompute the stored `unread` of the reader-state row `kind`/`ref_`. Best-effort: a
/// failure is logged against `action_id`.
pub(crate) async fn recompute_reader_row(
	app: &App,
	tn_id: TnId,
	action_id: &str,
	kind: &str,
	ref_: &str,
) {
	if let Err(e) = app.meta_adapter.recompute_reader_unread(tn_id, kind, ref_).await {
		tracing::warn!("{}: unread of {} {} failed: {}", action_id, kind, ref_, e);
	}
}

/// Inherit visibility and channel from the parent action, else from an action `subject`.
///
/// MSG inherits from `parent_id`; SUBS/INVT (which forbid a parent and reference
/// their container CONV via `subject`) inherit from that subject action. Only
/// **action** subjects count — identity (`@community`) and channel
/// (`@tenant~name`) subjects have no action to inherit from and fall through to
/// the type/user default.
///
/// Visibility: explicit > inherited. Channel: inherited > explicit, and the explicit one
/// is honoured only on a root (no `parent_id`, no action subject), so a reply can never
/// leave its thread's room.
pub async fn inherit_context<M: MetaAdapter + ?Sized>(
	meta_adapter: &M,
	tn_id: TnId,
	visibility: Option<char>,
	channel: Option<Box<str>>,
	parent_id: Option<&str>,
	subject: Option<&str>,
) -> (Option<char>, Option<Box<str>>) {
	let subject = subject.filter(|s| matches!(parse_subject_ref(s), Some(SubjectRef::Action(_))));
	if parent_id.is_none() && subject.is_none() {
		return (visibility, channel);
	}
	for id in [parent_id, subject].into_iter().flatten() {
		if let Ok(Some(ctx)) = meta_adapter.get_action(tn_id, id).await {
			return (visibility.or(ctx.visibility), ctx.channel);
		}
	}
	// Not a root, but the context is unknown here: never fall back to the explicit channel.
	(visibility, None)
}

/// The member who created a community group: `x.createdBy` on its CONV, stamped pre-store by
/// `post_action` (which replaces any client `x`). `None` on a personal group.
pub fn conv_created_by(x: Option<&serde_json::Value>) -> Option<&str> {
	x?.get("createdBy")?.as_str()
}

/// Whether a community group is listed for discovery: CONV content `join` is
/// `role` or `request`. Absent reads as `private`, unlisted.
pub fn conv_listed(content: Option<&serde_json::Value>) -> bool {
	matches!(content.and_then(|c| c.get("join")).and_then(|j| j.as_str()), Some("role" | "request"))
}

/// Resolve audience tag from parent action for federation.
///
/// When an action has a parent (e.g., MSG in a CONV), it should inherit
/// the audience from the parent so it can federate to the parent's home instance.
///
/// Returns:
/// - parent.audience_tag if present
/// - parent.issuer_tag as fallback
/// - None if parent_id is None or parent action doesn't exist
pub async fn resolve_parent_audience<M: MetaAdapter + ?Sized>(
	meta_adapter: &M,
	tn_id: TnId,
	parent_id: Option<&str>,
) -> Option<Box<str>> {
	let parent_id = parent_id?;
	let parent = meta_adapter.get_action(tn_id, parent_id).await.ok()??;

	// Prefer parent's audience, fall back to parent's issuer
	parent.audience.map(|a| a.id_tag).or(Some(parent.issuer.id_tag))
}

/// Resolve root_id from parent action chain.
///
/// The root_id tracks the original action in a thread hierarchy.
/// This enables subscription inheritance - a subscription to the root
/// grants permission to interact with all nested replies.
///
/// Resolution logic:
/// - If parent has a root_id, use it (propagate the chain)
/// - If parent has no root_id, the parent itself is the root
/// - If no parent, return None
///
/// Returns:
/// - parent.root_id if present
/// - parent_id if parent has no root_id (parent is the root)
/// - None if parent_id is None or parent action doesn't exist
pub async fn resolve_root_id<M: MetaAdapter + ?Sized>(
	meta_adapter: &M,
	tn_id: TnId,
	parent_id: Option<&str>,
) -> Option<Box<str>> {
	let parent_id = parent_id?;
	let parent = meta_adapter.get_action(tn_id, parent_id).await.ok()??;

	// If parent has a root_id, use it; otherwise parent is the root
	parent.root_id.or(Some(parent_id.into()))
}

// =============================================================================
// Action Flags
// =============================================================================
// Flags use lowercase to disable capabilities:
// - r: Reactions disabled (absence = enabled)
// - c: Comments disabled (absence = enabled)
// - O/o: Open (anyone can subscribe) / Closed (invite-only) — opt-in semantics

/// Check if a capability flag is enabled (not disabled by lowercase).
/// Capabilities are enabled by default; a lowercase flag character disables them.
pub fn is_capability_enabled(flags: Option<&str>, capability: char) -> bool {
	let disabled_char = capability.to_ascii_lowercase();
	!flags.is_some_and(|f| f.contains(disabled_char))
}

/// Check if the action is open (anyone can subscribe without invitation)
/// Returns true if 'O' is present in flags, false otherwise
pub fn is_open(flags: Option<&str>) -> bool {
	flags.is_some_and(|f| f.contains('O'))
}

/// Apply the open ('O') flag visibility promotion for new actions.
///
/// Open actions get Connected ('C') visibility, but a resolved 'S' (Subscribed)
/// is NEVER promoted: visibility cascades via `inherit_context`, so promoting
/// an open CONV to 'C' would expose its MSG children and SUBS roster rows to mere
/// connections. Open-group discovery happens at the community-profile layer, so
/// keeping 'S' costs no discoverability.
pub fn apply_open_flag_visibility(flags: Option<&str>, visibility: Option<char>) -> Option<char> {
	if is_open(flags) && visibility != Some('S') {
		Some('C') // Connected visibility for open groups
	} else {
		visibility
	}
}

// =============================================================================
// Role-Based Permission Checking
// =============================================================================
// Roles: observer, member, moderator, admin
// Permissions are hierarchical: admin > moderator > member > observer

/// Subscription role levels (higher number = more permissions)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SubscriptionRole {
	Observer = 0,
	Member = 1,
	Moderator = 2,
	Admin = 3,
}

impl FromStr for SubscriptionRole {
	type Err = Infallible;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(match s.to_lowercase().as_str() {
			"admin" => Self::Admin,
			"moderator" => Self::Moderator,
			"member" => Self::Member,
			_ => Self::Observer,
		})
	}
}

impl SubscriptionRole {
	/// Get the minimum role required for an action type
	pub fn required_for_action(action_type: &str, subtype: Option<&str>) -> Self {
		match (action_type, subtype) {
			// Admin-level actions
			("SUBS" | "CONV", Some("UPD")) => Self::Admin,

			// Moderator-level actions
			// PIN: also enforced by `native_hooks::pin::check_authority` (PIN does not
			// require a subscription, so this table alone would not stop it).
			("SUBS", Some("DEL")) | ("INVT" | "PIN", _) => Self::Moderator,

			// Observer can only view (SUBS without subtype is creating subscription);
			// a read receipt is part of viewing.
			("SUBS", None) | ("RCPT", _) => Self::Observer,

			// Member-level actions (participation) and default for unknown action types
			_ => Self::Member,
		}
	}
}

/// Get subscription role from a stored subscription's server-side metadata (`x.role`).
///
/// **Only `x`.** `content` is the action token's `c` claim — signed by the *issuer*, i.e.
/// by the very party whose role is being decided, and the SUBS content schema whitelists
/// `"admin"`. Inbound processing strips `x` (`process.rs`, `x: None`), so a `content.role`
/// fallback would let a remote subscriber name its own role and pick up `CONV:UPD`,
/// `SUBS:DEL` (kick members) and `INVT`.
///
/// `x` is not server-side-only, though: `CreateAction.x` and `PatchActionRequest.x` are
/// deserialized from the client body and stored verbatim, so a client *can* put a `role` there.
/// What makes it safe is the **key**, not the field. A locally-created action is issued as the
/// tenant, so a forged `x.role` keys as `SUBS:{subject}:{tenant}` and never matches the
/// `SUBS:{target}:{action.iss}` lookup in `check_subscription_role_permission`. `content` has no
/// such protection — it is the issuer's signed `c` claim — which is why the fallback is gone.
/// The roles that do count are written by the CONV and INVT native hooks, or default to
/// `Member`, which is what an ordinary federated subscriber gets.
///
/// The two "unknown" defaults differ on purpose. **Absent `x`** is the ordinary inbound row —
/// `process.rs` strips `x` on receipt — so it must resolve to `Member`, the participation
/// baseline a federated subscriber is entitled to. **A present but unrecognised `x.role`** is
/// corruption in a value only this server writes (the CONV and INVT native hooks), so it falls
/// to `Observer`, the least authority. Reversing either one is a privilege change: `Member` for
/// a bad `x.role` would let a typo confer participation, and `Observer` for an absent `x` would
/// mute every federated subscriber.
pub fn get_subscription_role(x: Option<&serde_json::Value>) -> SubscriptionRole {
	x.and_then(|x| x.get("role"))
		.and_then(|r| r.as_str())
		.map_or(SubscriptionRole::Member, |s| s.parse().unwrap_or(SubscriptionRole::Observer))
}

/// Broadcast/Announce recipient set for `tn_id`: every profile with the
/// directional `follower` flag set (maintained by the FLLW/CONN native hooks),
/// excluding `exclude_id_tag` (the author/self). `list_follower_tags` already
/// drops Suspended/Blocked/Banned issuers. Callers append any extra direct
/// recipients (e.g. the action author) themselves.
///
/// With a `channel` (absolute `@tenant~name`), only followers who can enter the room
/// remain. A channel of another tenant, or one that no longer exists, yields no
/// recipients (fails closed). `exclude_id_tag` is the tenant itself, so it is also the
/// only tenant whose rooms this node can resolve.
pub(crate) async fn broadcast_recipient_tags(
	app: &App,
	tn_id: TnId,
	exclude_id_tag: &str,
	channel: Option<&str>,
) -> ClResult<HashSet<Box<str>>> {
	let Some(channel) = channel else {
		return Ok(app
			.meta_adapter
			.list_follower_tags(tn_id)
			.await?
			.into_iter()
			.filter(|tag| tag.as_ref() != exclude_id_tag)
			.collect());
	};
	let Some(SubjectRef::Channel { tenant, name }) = parse_subject_ref(channel) else {
		return Ok(HashSet::new());
	};
	if tenant != exclude_id_tag {
		return Ok(HashSet::new());
	}
	let room = match app.meta_adapter.read_channel(tn_id, name).await {
		Ok(room) => room,
		Err(Error::NotFound) => return Ok(HashSet::new()),
		Err(e) => return Err(e),
	};
	let roster = if room.closed {
		app.meta_adapter.list_channel_members(tn_id, name).await?
	} else {
		Vec::new()
	};
	let followers = app.meta_adapter.list_follower_roles(tn_id).await?;
	Ok(room_recipients(&room, &roster, followers, exclude_id_tag))
}

/// A follower's id tag and its roles on this tenant.
type FollowerRoles = (Box<str>, Box<[Box<str>]>);

/// The followers who can enter `room`, minus `exclude_id_tag`. Federated followers are never
/// hatted here: a hat is worn on an action, not on a follow.
fn room_recipients(
	room: &Channel,
	roster: &[Box<str>],
	followers: Vec<FollowerRoles>,
	exclude_id_tag: &str,
) -> HashSet<Box<str>> {
	followers
		.into_iter()
		.filter(|(tag, roles)| {
			tag.as_ref() != exclude_id_tag
				&& cloudillo_core::channels::can_enter(
					room.min_role.as_deref(),
					room.closed,
					roles,
					roster.contains(tag),
					false,
				)
		})
		.map(|(tag, _)| tag)
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parse_mentions_tokens() {
		let c = |s: &str| serde_json::Value::String(s.into());
		assert_eq!(parse_mentions(Some(&c("hi @bob.org.")), "bob.org"), (true, false));
		assert_eq!(parse_mentions(Some(&c("mail me@bob.org")), "bob.org"), (false, false));
		assert_eq!(parse_mentions(Some(&c("@all, @bob.org.uk")), "bob.org"), (false, true));
		let obj = serde_json::json!({ "text": "(@Bob.org) see" });
		assert_eq!(parse_mentions(Some(&obj), "bob.org"), (true, false));
		assert_eq!(parse_mentions(None, "bob.org"), (false, false));
	}

	fn room(min_role: Option<&str>, closed: bool) -> Channel {
		Channel {
			name: "organising".into(),
			title: None,
			descr: None,
			visibility: Some('F'),
			min_role: min_role.map(Into::into),
			closed,
			created_at: Timestamp::now(),
			updated_at: Timestamp::now(),
		}
	}

	fn followers() -> Vec<FollowerRoles> {
		let f = |tag: &str, roles: &[&str]| -> FollowerRoles {
			(tag.into(), roles.iter().map(|&r| r.into()).collect())
		};
		vec![
			f("club.example.com", &["leader"]),
			f("fan.example.com", &["follower"]),
			f("mod.example.com", &["moderator"]),
			f("lead.example.com", &["leader"]),
		]
	}

	fn sorted(tags: HashSet<Box<str>>) -> Vec<Box<str>> {
		let mut v: Vec<_> = tags.into_iter().collect();
		v.sort_unstable();
		v
	}

	/// Fanout does not over-deliver: a post in a `moderator` room reaches
	/// only moderator+ followers; an open-floor room reaches every follower but the author.
	#[test]
	fn fanout_does_not_over_deliver() {
		let floored =
			room_recipients(&room(Some("moderator"), false), &[], followers(), "club.example.com");
		assert_eq!(sorted(floored), [Box::from("lead.example.com"), Box::from("mod.example.com")]);

		let open = room_recipients(&room(None, false), &[], followers(), "club.example.com");
		assert_eq!(
			sorted(open),
			[
				Box::from("fan.example.com"),
				Box::from("lead.example.com"),
				Box::from("mod.example.com")
			]
		);

		// A closed room narrows the floor to its roster.
		let roster: [Box<str>; 1] = [Box::from("mod.example.com")];
		let closed = room_recipients(
			&room(Some("moderator"), true),
			&roster,
			followers(),
			"club.example.com",
		);
		assert_eq!(sorted(closed), [Box::from("mod.example.com")]);
	}

	/// The subscription role comes from server-side metadata only. `content` is the
	/// action token's `c` claim, signed by the party whose role is being decided —
	/// inbound processing strips `x`, so honouring `content.role` let a remote SUBS
	/// declare itself `admin` and pick up CONV:UPD / SUBS:DEL / INVT.
	#[test]
	fn subscription_role_comes_from_server_metadata_only() {
		let x = serde_json::json!({ "role": "admin" });
		assert_eq!(get_subscription_role(Some(&x)), SubscriptionRole::Admin);

		// No `x` — an inbound row — is an ordinary member, whatever it claimed.
		assert_eq!(get_subscription_role(None), SubscriptionRole::Member);

		// An unrecognised server-side role falls to the least authority, not the most.
		let bogus = serde_json::json!({ "role": "wizard" });
		assert_eq!(get_subscription_role(Some(&bogus)), SubscriptionRole::Observer);
	}

	/// Only the field name in the error is this wrapper's own; which identities pass is
	/// `cloudillo_types::validation::validate_id_tag`'s contract, tested there.
	#[test]
	fn test_check_identity_field() {
		assert!(check_identity_field("issuer", "alice.example.com").is_ok());

		// Non-canonical identities are rejected, not normalised — and the error
		// names the offending claim.
		let Err(Error::ValidationError(msg)) = check_identity_field("issuer", "Alice.Example.com")
		else {
			panic!("expected a validation error");
		};
		assert!(msg.contains("issuer"), "error should name the field: {msg}");
	}

	/// `invt.rs` and `conn.rs` build their lookup as `format!("@{}", tag)` from a canonical
	/// tag against an exact `a.subject IN (…)`, so a subject stored in a different spelling
	/// matches nothing — a since-demoted inviter could not withdraw their own invitation.
	/// Closed here, on write, not by normalising at every compare.
	#[test]
	fn an_identity_subject_must_be_canonical() {
		assert!(check_subject_field("@club.example.com").is_ok());

		let Err(Error::ValidationError(msg)) = check_subject_field("@Club.Example.COM") else {
			panic!("a non-canonical identity subject must be rejected");
		};
		assert!(msg.contains("subject"), "error should name the field: {msg}");

		// The two non-identity forms are untouched: a content-addressed action id and an
		// in-batch placeholder.
		assert!(check_subject_field("a1~abc").is_ok());
		assert!(check_subject_field("@42").is_ok());

		// `@a1~abc` parses as a *channel* of tenant `a1` (see `subject_ref`), which is
		// not a valid id_tag.
		assert!(check_subject_field("@a1~abc").is_err());

		// A channel subject's tenant must be canonical too.
		assert!(check_subject_field("@club.example.com~campaign").is_ok());
		assert!(check_subject_field("@Club.Example.COM~campaign").is_err());
	}

	#[test]
	fn an_over_long_attachment_list_is_refused() {
		let at_cap: Vec<Box<str>> =
			(0..MAX_ATTACHMENTS).map(|i| format!("f1~{i}").into()).collect();
		assert!(check_attachment_count(Some(&at_cap)).is_ok(), "the cap itself is allowed");
		assert!(check_attachment_count(None).is_ok());

		let over: Vec<Box<str>> = (0..=MAX_ATTACHMENTS).map(|i| format!("f1~{i}").into()).collect();
		assert!(matches!(check_attachment_count(Some(&over)), Err(Error::ValidationError(_))));
	}

	#[test]
	fn test_extract_type_and_subtype_simple() {
		let (t, st) = extract_type_and_subtype("POST");
		assert_eq!(t, "POST");
		assert_eq!(st, None);
	}

	#[test]
	fn test_extract_type_and_subtype_with_subtype() {
		let (t, st) = extract_type_and_subtype("POST:TEXT");
		assert_eq!(t, "POST");
		assert_eq!(st, Some("TEXT".to_string()));
	}

	#[test]
	fn test_extract_type_and_subtype_multiple_colons() {
		let (t, st) = extract_type_and_subtype("POST:TEXT:EXTRA");
		assert_eq!(t, "POST");
		assert_eq!(st, Some("TEXT:EXTRA".to_string()));
	}

	#[test]
	fn test_apply_key_pattern_full() {
		let pattern = "{type}:{parent}:{issuer}";
		let key = apply_key_pattern(pattern, "REACT", "user1", None, Some("action123"), None, None);
		assert_eq!(key, "REACT:action123:user1");
	}

	#[test]
	fn test_apply_key_pattern_empty_optionals() {
		let pattern = "{type}:{parent}:{issuer}:{audience}:{subject}";
		let key = apply_key_pattern(pattern, "POST", "user1", None, None, None, None);
		assert_eq!(key, "POST::user1::");
	}

	#[test]
	fn test_apply_key_pattern_all_fields() {
		let pattern = "{type}:{parent}:{issuer}:{audience}:{subject}";
		let key = apply_key_pattern(
			pattern,
			"MSG",
			"user1",
			Some("user2"),
			Some("parent123"),
			Some("hello"),
			None,
		);
		assert_eq!(key, "MSG:parent123:user1:user2:hello");
	}

	/// Without content substitution every IDP:REG from one server to one IdP shares
	/// a single key, and the meta adapter tombstones the previous row on store.
	#[test]
	fn test_apply_key_pattern_content_field() {
		let pattern = "{type}:{issuer}:{audience}:{content.idTag}";
		let content = serde_json::json!({ "idTag": "test5.home.w9.hu", "lang": "hu" });
		let key = apply_key_pattern(
			pattern,
			"IDP",
			"home.w9.hu",
			Some("home.w9.hu"),
			None,
			None,
			Some(&content),
		);
		assert_eq!(key, "IDP:home.w9.hu:home.w9.hu:test5.home.w9.hu");
	}

	#[test]
	fn test_apply_key_pattern_content_field_missing() {
		let pattern = "{type}:{content.name}:{content.missing}";
		let content = serde_json::json!({ "name": "quillo" });
		// A missing field substitutes empty, like the absent action optionals…
		let key = apply_key_pattern(pattern, "APKG", "user1", None, None, None, Some(&content));
		assert_eq!(key, "APKG:quillo:");
		// …as does content that is absent entirely.
		let key = apply_key_pattern(pattern, "APKG", "user1", None, None, None, None);
		assert_eq!(key, "APKG::");
	}

	#[test]
	fn test_serialize_content_none() {
		let result = serialize_content(None);
		assert_eq!(result, None);
	}

	#[test]
	fn test_serialize_content_string() {
		let value = serde_json::Value::String("hello".to_string());
		let result = serialize_content(Some(&value));
		assert_eq!(result, Some("\"hello\"".to_string()));
	}

	#[test]
	fn test_serialize_content_object() {
		let value = serde_json::json!({"key": "value"});
		let result = serialize_content(Some(&value));
		assert_eq!(result, Some("{\"key\":\"value\"}".to_string()));
	}

	// Flag tests
	#[test]
	fn test_is_capability_enabled() {
		// Generic helper tests
		assert!(is_capability_enabled(None, 'R'));
		assert!(is_capability_enabled(Some(""), 'R'));
		assert!(!is_capability_enabled(Some("r"), 'R'));
		assert!(is_capability_enabled(Some("c"), 'R')); // 'c' doesn't affect 'R'
	}

	#[test]
	fn test_is_open_uppercase() {
		assert!(is_open(Some("rcO")));
		assert!(is_open(Some("O")));
	}

	#[test]
	fn test_is_open_lowercase() {
		assert!(!is_open(Some("RCo")));
		assert!(!is_open(Some("rc")));
	}

	// Regression: an open ('O') group's 'S' must never be promoted to 'C' — it
	// would cascade into MSG/SUBS children and leak group content + roster.
	#[test]
	fn test_open_flag_never_promotes_subscribed() {
		// An open CONV's 'S' survives the open flag…
		assert_eq!(apply_open_flag_visibility(Some("rcO"), Some('S')), Some('S'));
		assert_eq!(apply_open_flag_visibility(Some("O"), Some('S')), Some('S'));
		// …other resolved visibilities are promoted for discoverability…
		assert_eq!(apply_open_flag_visibility(Some("rcO"), Some('F')), Some('C'));
		assert_eq!(apply_open_flag_visibility(Some("O"), None), Some('C'));
		// …and closed (no 'O') actions are untouched.
		assert_eq!(apply_open_flag_visibility(Some("rco"), Some('S')), Some('S'));
		assert_eq!(apply_open_flag_visibility(None, Some('F')), Some('F'));
	}

	// Role-based permission tests
	#[test]
	fn test_subscription_role_from_str() {
		assert_eq!("admin".parse::<SubscriptionRole>().unwrap(), SubscriptionRole::Admin);
		assert_eq!("ADMIN".parse::<SubscriptionRole>().unwrap(), SubscriptionRole::Admin);
		assert_eq!("moderator".parse::<SubscriptionRole>().unwrap(), SubscriptionRole::Moderator);
		assert_eq!("member".parse::<SubscriptionRole>().unwrap(), SubscriptionRole::Member);
		assert_eq!("observer".parse::<SubscriptionRole>().unwrap(), SubscriptionRole::Observer);
		assert_eq!("unknown".parse::<SubscriptionRole>().unwrap(), SubscriptionRole::Observer);
	}

	#[test]
	fn test_subscription_role_ordering() {
		assert!(SubscriptionRole::Admin > SubscriptionRole::Moderator);
		assert!(SubscriptionRole::Moderator > SubscriptionRole::Member);
		assert!(SubscriptionRole::Member > SubscriptionRole::Observer);
	}

	#[test]
	fn test_content_snippet_object_text() {
		let value = serde_json::json!({ "text": "hello" });
		assert_eq!(content_snippet(Some(&value)), "hello");
	}

	#[test]
	fn test_content_snippet_object_content() {
		let value = serde_json::json!({ "content": "world" });
		assert_eq!(content_snippet(Some(&value)), "world");
	}

	/// A POST:LDOC body has no `text` when the author adds no commentary — the
	/// document `title` is the only prose there is, so the notification uses it.
	#[test]
	fn test_content_snippet_object_title() {
		let value = serde_json::json!({
			"doc": "a.org:f1~x",
			"contentType": "cloudillo/quillo",
			"title": "Q3 terv"
		});
		assert_eq!(content_snippet(Some(&value)), "Q3 terv");
	}

	#[test]
	fn test_content_snippet_string() {
		let value = serde_json::Value::String("hi there".to_string());
		assert_eq!(content_snippet(Some(&value)), "hi there");
	}

	#[test]
	fn test_content_snippet_none() {
		assert_eq!(content_snippet(None), "");
	}

	#[test]
	fn test_content_snippet_caps_at_200() {
		let long = "x".repeat(500);
		let value = serde_json::Value::String(long);
		assert_eq!(content_snippet(Some(&value)).chars().count(), 200);
	}
}

// vim: ts=4
