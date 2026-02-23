//! Shared helper functions for action processing

use std::convert::Infallible;
use std::str::FromStr;

use crate::prelude::*;
use cloudillo_types::meta_adapter::MetaAdapter;

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
pub fn apply_key_pattern(
	pattern: &str,
	action_type: &str,
	issuer: &str,
	audience: Option<&str>,
	parent: Option<&str>,
	subject: Option<&str>,
) -> String {
	pattern
		.replace("{type}", action_type)
		.replace("{issuer}", issuer)
		.replace("{audience}", audience.unwrap_or(""))
		.replace("{parent}", parent.unwrap_or(""))
		.replace("{subject}", subject.unwrap_or(""))
}

/// Serialize content Value to JSON string
pub fn serialize_content(content: Option<&serde_json::Value>) -> Option<String> {
	content.map(|v| serde_json::to_string(v).unwrap_or_default())
}

/// Inherit visibility from parent action if not explicitly set
pub async fn inherit_visibility<M: MetaAdapter + ?Sized>(
	meta_adapter: &M,
	tn_id: TnId,
	visibility: Option<char>,
	parent_id: Option<&str>,
) -> Option<char> {
	if visibility.is_some() {
		return visibility;
	}
	if let Some(parent_id) = parent_id {
		if let Ok(Some(parent)) = meta_adapter.get_action(tn_id, parent_id).await {
			return parent.visibility;
		}
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
	!flags.map(|f| f.contains(disabled_char)).unwrap_or(false)
}

/// Reactions enabled unless explicitly disabled with lowercase 'r'
pub fn can_react(flags: Option<&str>) -> bool {
	is_capability_enabled(flags, 'R')
}

/// Comments enabled unless explicitly disabled with lowercase 'c'
pub fn can_comment(flags: Option<&str>) -> bool {
	is_capability_enabled(flags, 'C')
}

/// Check if the action is open (anyone can subscribe without invitation)
/// Returns true if 'O' is present in flags, false otherwise
pub fn is_open(flags: Option<&str>) -> bool {
	flags.map(|f| f.contains('O')).unwrap_or(false)
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
			// Moderator-level actions
			("SUBS", Some("DEL")) => Self::Moderator, // Kick users

			// Admin-level actions
			("SUBS", Some("UPD")) => Self::Admin, // Role changes
			("CONV", Some("UPD")) => Self::Admin, // Update conversation
			("INVT", _) => Self::Moderator,       // Invite users

			// Member-level actions (participation)
			("MSG", _) => Self::Member,
			("REACT", _) => Self::Member,
			("PRES", _) => Self::Member,
			("CMNT", _) => Self::Member,

			// Observer can only view (SUBS without subtype is creating subscription)
			("SUBS", None) => Self::Observer,

			// Default to member for unknown action types
			_ => Self::Member,
		}
	}
}

/// Check if a user's role permits the given action
/// Returns true if allowed, false otherwise
///
/// Note: This does NOT check issuer permission - that should be checked separately
pub fn check_role_permission(user_role: &str, action_type: &str, subtype: Option<&str>) -> bool {
	let role: SubscriptionRole = user_role.parse().unwrap_or(SubscriptionRole::Observer);
	let required = SubscriptionRole::required_for_action(action_type, subtype);
	role >= required
}

/// Get subscription role from action's metadata
///
/// Reads from x.role (new location), falling back to content.role for migration.
/// This supports both Action (content as JSON string) and ActionView (content as Value).
///
/// Parameters:
/// - x: The extensible metadata (x field from Action/ActionView)
/// - content: The action content (as parsed JSON Value)
///
/// For Action<S> with content as string, caller should parse it first:
/// ```ignore
/// let content_json = action.content.as_ref()
///     .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
/// get_subscription_role(action.x.as_ref(), content_json.as_ref())
/// ```
pub fn get_subscription_role(
	x: Option<&serde_json::Value>,
	content: Option<&serde_json::Value>,
) -> SubscriptionRole {
	// First try x.role (new location for server-side metadata)
	if let Some(role_str) = x.and_then(|x| x.get("role")).and_then(|r| r.as_str()) {
		return role_str.parse().unwrap_or(SubscriptionRole::Observer);
	}

	// Fallback to content.role for migration compatibility
	// Default to Member (not Observer) - subscribers should participate by default
	content
		.and_then(|c| c.get("role"))
		.and_then(|r| r.as_str())
		.map(|s| s.parse().unwrap_or(SubscriptionRole::Member))
		.unwrap_or(SubscriptionRole::Member)
}

/// Check if the user is the issuer (creator) of an action
/// Issuers always have full permission on their own actions
pub fn is_action_issuer(action_issuer: &str, user_id: &str) -> bool {
	action_issuer == user_id
}

/// Get the effective audience, defaulting to issuer if audience is None
///
/// In Cloudillo's action model:
/// - Actions with no audience are "self-directed" (e.g., personal posts)
/// - These should be treated as if audience == issuer for delivery/processing
///
/// This helper normalizes the audience field for consistent handling.
pub fn effective_audience<'a>(audience: Option<&'a str>, issuer: &'a str) -> &'a str {
	audience.unwrap_or(issuer)
}

#[cfg(test)]
mod tests {
	use super::*;

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
		let key = apply_key_pattern(pattern, "REACT", "user1", None, Some("action123"), None);
		assert_eq!(key, "REACT:action123:user1");
	}

	#[test]
	fn test_apply_key_pattern_empty_optionals() {
		let pattern = "{type}:{parent}:{issuer}:{audience}:{subject}";
		let key = apply_key_pattern(pattern, "POST", "user1", None, None, None);
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
		);
		assert_eq!(key, "MSG:parent123:user1:user2:hello");
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
	fn test_can_react_none() {
		// None = enabled (no flags means all capabilities on)
		assert!(can_react(None));
	}

	#[test]
	fn test_can_react_enabled() {
		// No lowercase 'r' = reactions enabled
		assert!(can_react(Some("RCo")));
		assert!(can_react(Some("co")));
		assert!(can_react(Some("")));
	}

	#[test]
	fn test_can_react_disabled() {
		// Lowercase 'r' = reactions disabled
		assert!(!can_react(Some("rCo")));
		assert!(!can_react(Some("rco")));
		assert!(!can_react(Some("r")));
	}

	#[test]
	fn test_can_comment_none() {
		// None = enabled
		assert!(can_comment(None));
	}

	#[test]
	fn test_can_comment_enabled() {
		// No lowercase 'c' = comments enabled
		assert!(can_comment(Some("RCo")));
		assert!(can_comment(Some("ro")));
		assert!(can_comment(Some("")));
	}

	#[test]
	fn test_can_comment_disabled() {
		// Lowercase 'c' = comments disabled
		assert!(!can_comment(Some("Rco")));
		assert!(!can_comment(Some("rco")));
		assert!(!can_comment(Some("c")));
	}

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
	fn test_check_role_permission_member() {
		// Members can send messages
		assert!(check_role_permission("member", "MSG", None));
		// Members can react
		assert!(check_role_permission("member", "REACT", None));
		// Members cannot kick
		assert!(!check_role_permission("member", "SUBS", Some("DEL")));
		// Members cannot change roles
		assert!(!check_role_permission("member", "SUBS", Some("UPD")));
	}

	#[test]
	fn test_check_role_permission_moderator() {
		// Moderators can do everything members can
		assert!(check_role_permission("moderator", "MSG", None));
		assert!(check_role_permission("moderator", "REACT", None));
		// Moderators can kick
		assert!(check_role_permission("moderator", "SUBS", Some("DEL")));
		// Moderators cannot change roles
		assert!(!check_role_permission("moderator", "SUBS", Some("UPD")));
	}

	#[test]
	fn test_check_role_permission_admin() {
		// Admins can do everything
		assert!(check_role_permission("admin", "MSG", None));
		assert!(check_role_permission("admin", "SUBS", Some("DEL")));
		assert!(check_role_permission("admin", "SUBS", Some("UPD")));
		assert!(check_role_permission("admin", "CONV", Some("UPD")));
	}

	#[test]
	fn test_check_role_permission_observer() {
		// Observers can only view
		assert!(!check_role_permission("observer", "MSG", None));
		assert!(!check_role_permission("observer", "REACT", None));
		// Observers can create subscriptions (join)
		assert!(check_role_permission("observer", "SUBS", None));
	}

	#[test]
	fn test_is_action_issuer() {
		assert!(is_action_issuer("alice@example.com", "alice@example.com"));
		assert!(!is_action_issuer("alice@example.com", "bob@example.com"));
	}

	#[test]
	fn test_effective_audience_with_audience() {
		// When audience is provided, use it
		assert_eq!(
			effective_audience(Some("bob@example.com"), "alice@example.com"),
			"bob@example.com"
		);
	}

	#[test]
	fn test_effective_audience_without_audience() {
		// When audience is None, fall back to issuer
		assert_eq!(effective_audience(None, "alice@example.com"), "alice@example.com");
	}
}

// vim: ts=4
