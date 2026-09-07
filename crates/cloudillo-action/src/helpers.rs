// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Shared helper functions for action processing

use std::collections::HashSet;
use std::convert::Infallible;
use std::str::FromStr;

use crate::prelude::*;
use crate::subject_ref::{SubjectRef, parse_subject_ref};
use cloudillo_types::meta_adapter::MetaAdapter;

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
/// [`SubjectRef::Action`] (`a1~…`) and [`SubjectRef::Placeholder`] (`@42`) are not
/// identities and pass untouched.
///
/// The community-INVT lookups build their filter as `format!("@{}", community_tag)` from a
/// canonical tag (`native_hooks/invt.rs`, `native_hooks/conn.rs`) while the adapter does an
/// exact `a.subject IN (…)`, so an INVT federated with `sub = "@Club.Example.COM"` stored that
/// spelling and matched nothing — a since-demoted inviter could not withdraw their own
/// invitation. Normalising at the comparison sites would have been the wrong fix; the storage
/// invariant is enforced on write, here.
pub fn check_subject_field(subject: &str) -> ClResult<()> {
	match parse_subject_ref(subject) {
		Some(SubjectRef::Identity(id_tag)) => check_identity_field("subject", id_tag),
		_ => Ok(()),
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
	let raw = match content {
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
	};
	raw.chars().take(200).collect()
}

/// Inherit visibility from the parent action, else from an action `subject`.
///
/// MSG inherits from `parent_id`; SUBS/INVT (which forbid a parent and reference
/// their container CONV via `subject`) inherit from that subject action. Only
/// **action** subjects count — identity subjects (`@community`) have no action
/// to inherit from and fall through to the type/user default.
pub async fn inherit_visibility<M: MetaAdapter + ?Sized>(
	meta_adapter: &M,
	tn_id: TnId,
	visibility: Option<char>,
	parent_id: Option<&str>,
	subject: Option<&str>,
) -> Option<char> {
	if visibility.is_some() {
		return visibility;
	}
	if let Some(parent_id) = parent_id
		&& let Ok(Some(parent)) = meta_adapter.get_action(tn_id, parent_id).await
	{
		return parent.visibility;
	}
	if let Some(subject) = subject
		&& matches!(parse_subject_ref(subject), Some(SubjectRef::Action(_)))
		&& let Ok(Some(subj)) = meta_adapter.get_action(tn_id, subject).await
	{
		return subj.visibility;
	}
	None
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
/// is NEVER promoted: visibility cascades via `inherit_visibility`, so promoting
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
			("SUBS", Some("DEL")) | ("INVT", _) => Self::Moderator,

			// Observer can only view (SUBS without subtype is creating subscription)
			("SUBS", None) => Self::Observer,

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
pub(crate) async fn broadcast_recipient_tags(
	app: &App,
	tn_id: TnId,
	exclude_id_tag: &str,
) -> ClResult<HashSet<Box<str>>> {
	Ok(app
		.meta_adapter
		.list_follower_tags(tn_id)
		.await?
		.into_iter()
		.filter(|tag| tag.as_ref() != exclude_id_tag)
		.collect())
}

#[cfg(test)]
mod tests {
	use super::*;

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

		// `@a1~abc` parses as an *identity* (see `subject_ref`), and is not a valid one.
		assert!(check_subject_field("@a1~abc").is_err());
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
