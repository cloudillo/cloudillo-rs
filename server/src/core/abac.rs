//! Attribute-Based Access Control (ABAC) system for Cloudillo
//!
//! Implements classic ABAC with 4-object model:
//! - Subject: Authenticated user (AuthCtx)
//! - Action: Operation being performed (string like "file:read")
//! - Object: Resource being accessed (implements AttrSet trait)
//! - Environment: Context (time, etc.)

use crate::auth_adapter::AuthCtx;
use crate::prelude::*;
use std::collections::HashMap;

/// Visibility levels for resources (files, actions, profile fields)
///
/// Stored as single char in database:
/// - None/NULL = Direct (most restrictive, owner + explicit audience only)
/// - 'P' = Public (anyone, including unauthenticated)
/// - 'V' = Verified (any authenticated user from any federated instance)
/// - '2' = 2nd degree (friend of friend, reserved for future voucher token system)
/// - 'F' = Follower (authenticated user who follows the owner)
/// - 'C' = Connected (authenticated user who is connected/mutual with owner)
///
/// Hierarchy (from most permissive to most restrictive):
/// Public > Verified > 2nd Degree > Follower > Connected > Direct
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum VisibilityLevel {
	/// Anyone can access, including unauthenticated users
	Public,
	/// Any authenticated user from any federated instance
	Verified,
	/// Friend of friend (2nd degree connection) - reserved for voucher token system
	SecondDegree,
	/// Authenticated user who follows the owner
	Follower,
	/// Authenticated user who is connected (mutual) with owner
	Connected,
	/// Most restrictive - only owner and explicit audience
	#[default]
	Direct,
}

impl VisibilityLevel {
	/// Parse from database char value
	pub fn from_char(c: Option<char>) -> Self {
		match c {
			Some('P') => Self::Public,
			Some('V') => Self::Verified,
			Some('2') => Self::SecondDegree,
			Some('F') => Self::Follower,
			Some('C') => Self::Connected,
			None => Self::Direct, // NULL = Direct (most restrictive)
			_ => Self::Direct,    // Unknown = Direct (secure by default)
		}
	}

	/// Convert to string for attribute lookup
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::Public => "public",
			Self::Verified => "verified",
			Self::SecondDegree => "second_degree",
			Self::Follower => "follower",
			Self::Connected => "connected",
			Self::Direct => "direct",
		}
	}
}

/// Subject's access level to a resource based on their relationship with the owner
///
/// Used to determine if a subject meets the visibility requirements.
/// Higher levels grant access to more restrictive visibility settings.
///
/// Hierarchy: Owner > Connected > Follower > SecondDegree > Verified > Public > None
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum SubjectAccessLevel {
	/// No authentication or relationship
	#[default]
	None,
	/// Unauthenticated but public access requested
	Public,
	/// Authenticated user (has valid JWT from any federated instance)
	Verified,
	/// Has voucher token proving 2nd degree connection (future)
	SecondDegree,
	/// Follows the resource owner
	Follower,
	/// Connected (mutual) with resource owner
	Connected,
	/// Is the resource owner
	Owner,
}

impl SubjectAccessLevel {
	/// Check if this access level can view content with given visibility
	pub fn can_access(self, visibility: VisibilityLevel) -> bool {
		match visibility {
			VisibilityLevel::Public => true, // Everyone can access public
			VisibilityLevel::Verified => self >= Self::Verified,
			VisibilityLevel::SecondDegree => self >= Self::SecondDegree,
			VisibilityLevel::Follower => self >= Self::Follower,
			VisibilityLevel::Connected => self >= Self::Connected,
			VisibilityLevel::Direct => self >= Self::Owner, // Only owner for direct
		}
	}
}

/// Check if subject can view an item based on visibility and relationship
///
/// This is a standalone function for use in list filtering where we don't
/// have full ABAC context. It evaluates visibility rules directly.
///
/// # Arguments
/// * `subject_id_tag` - The viewer's id_tag (empty string for anonymous)
/// * `is_authenticated` - Whether the subject is authenticated
/// * `item_owner_id_tag` - The item owner/issuer's id_tag
/// * `tenant_id_tag` - The tenant's id_tag (owner of the node where item is stored)
/// * `visibility` - The item's visibility level (None = Direct)
/// * `subject_following_owner` - Whether the subject follows the owner
/// * `subject_connected_to_owner` - Whether the subject is connected to owner
/// * `audience_tags` - Optional list of audience id_tags (for Direct visibility)
#[allow(clippy::too_many_arguments)]
pub fn can_view_item(
	subject_id_tag: &str,
	is_authenticated: bool,
	item_owner_id_tag: &str,
	tenant_id_tag: &str,
	visibility: Option<char>,
	subject_following_owner: bool,
	subject_connected_to_owner: bool,
	audience_tags: Option<&[&str]>,
) -> bool {
	let visibility = VisibilityLevel::from_char(visibility);

	// Determine subject's access level
	// Note: "guest" id_tag is used for unauthenticated users - treat as Public
	let is_real_auth = is_authenticated && !subject_id_tag.is_empty() && subject_id_tag != "guest";
	let is_tenant = subject_id_tag == tenant_id_tag;
	let access_level = if subject_id_tag == item_owner_id_tag || is_tenant {
		SubjectAccessLevel::Owner // Tenant has same access as owner
	} else if subject_connected_to_owner {
		SubjectAccessLevel::Connected
	} else if subject_following_owner {
		SubjectAccessLevel::Follower
	} else if is_real_auth {
		SubjectAccessLevel::Verified
	} else {
		SubjectAccessLevel::Public
	};

	// Check basic access
	if access_level.can_access(visibility) {
		return true;
	}

	// For Direct visibility, also check explicit audience
	if visibility == VisibilityLevel::Direct {
		if let Some(tags) = audience_tags {
			return tags.contains(&subject_id_tag);
		}
	}

	false
}

/// Attribute set trait - all objects implement this
pub trait AttrSet: Send + Sync {
	/// Get a single string attribute
	fn get(&self, key: &str) -> Option<&str>;

	/// Get a list attribute
	fn get_list(&self, key: &str) -> Option<Vec<&str>>;

	/// Check if attribute equals value
	fn has(&self, key: &str, value: &str) -> bool {
		self.get(key) == Some(value)
	}

	/// Check if list attribute contains value
	fn contains(&self, key: &str, value: &str) -> bool {
		self.get_list(key).map(|list| list.contains(&value)).unwrap_or(false)
	}
}

/// Environment attributes (environmental context)
#[derive(Debug, Clone)]
pub struct Environment {
	pub time: Timestamp,
	// Future: ip_address, user_agent, etc.
}

impl Environment {
	pub fn new() -> Self {
		Self { time: Timestamp::now() }
	}
}

impl Default for Environment {
	fn default() -> Self {
		Self::new()
	}
}

/// Policy rule condition
#[derive(Debug, Clone)]
pub struct Condition {
	pub attribute: String,
	pub operator: Operator,
	pub value: serde_json::Value,
}

#[derive(Debug, Clone, Copy)]
pub enum Operator {
	Equals,
	NotEquals,
	Contains,
	NotContains,
	GreaterThan,
	LessThan,
	In,      // Subject attr in object list
	HasRole, // Subject has specific role
}

impl Condition {
	/// Evaluate condition against subject, action, object, environment
	pub fn evaluate(
		&self,
		subject: &AuthCtx,
		action: &str,
		object: &dyn AttrSet,
		_environment: &Environment,
	) -> bool {
		// First, try to get value from object
		if let Some(obj_val) = object.get(&self.attribute) {
			return self.compare_value(obj_val);
		}

		// Then try subject attributes
		match self.attribute.as_str() {
			"subject.id_tag" => self.compare_value(&subject.id_tag),
			"subject.tn_id" => self.compare_value(&subject.tn_id.0.to_string()),
			"subject.roles" | "role.admin" | "role.moderator" | "role.member" => {
				// Special handling for role checks
				if let Operator::HasRole = self.operator {
					if let Some(role) = self.value.as_str() {
						return subject.roles.iter().any(|r| r.as_ref() == role);
					}
				}
				// For dotted notation like "role.admin"
				if self.attribute.starts_with("role.") {
					let role_name = &self.attribute[5..];
					return subject.roles.iter().any(|r| r.as_ref() == role_name);
				}
				false
			}
			"action" => self.compare_value(action),
			_ => false,
		}
	}

	fn compare_value(&self, actual: &str) -> bool {
		match self.operator {
			Operator::Equals => self.value.as_str() == Some(actual),
			Operator::NotEquals => self.value.as_str() != Some(actual),
			Operator::Contains => {
				if let Some(needle) = self.value.as_str() {
					actual.contains(needle)
				} else {
					false
				}
			}
			Operator::NotContains => {
				if let Some(needle) = self.value.as_str() {
					!actual.contains(needle)
				} else {
					true
				}
			}
			Operator::GreaterThan => {
				if let (Some(threshold), Ok(val)) = (self.value.as_f64(), actual.parse::<f64>()) {
					val > threshold
				} else {
					false
				}
			}
			Operator::LessThan => {
				if let (Some(threshold), Ok(val)) = (self.value.as_f64(), actual.parse::<f64>()) {
					val < threshold
				} else {
					false
				}
			}
			_ => false,
		}
	}
}

/// Policy rule
#[derive(Debug, Clone)]
pub struct PolicyRule {
	pub name: String,
	pub conditions: Vec<Condition>,
	pub effect: Effect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
	Allow,
	Deny,
}

impl PolicyRule {
	/// Evaluate rule against subject, action, object, environment
	pub fn evaluate(
		&self,
		subject: &AuthCtx,
		action: &str,
		object: &dyn AttrSet,
		environment: &Environment,
	) -> Option<Effect> {
		// All conditions must match for rule to apply
		let all_match = self
			.conditions
			.iter()
			.all(|cond| cond.evaluate(subject, action, object, environment));

		if all_match {
			Some(self.effect)
		} else {
			None
		}
	}
}

/// ABAC Policy (collection of rules)
#[derive(Debug, Clone)]
pub struct Policy {
	pub name: String,
	pub rules: Vec<PolicyRule>,
}

impl Policy {
	/// Evaluate policy - returns Effect if any rule matches
	pub fn evaluate(
		&self,
		subject: &AuthCtx,
		action: &str,
		object: &dyn AttrSet,
		environment: &Environment,
	) -> Option<Effect> {
		for rule in &self.rules {
			if let Some(effect) = rule.evaluate(subject, action, object, environment) {
				return Some(effect);
			}
		}
		None
	}
}

/// Profile-level policy configuration (TOP + BOTTOM)
#[derive(Debug, Clone)]
pub struct ProfilePolicy {
	pub tn_id: TnId,
	pub top_policy: Policy,    // Maximum permissions (constraints)
	pub bottom_policy: Policy, // Minimum permissions (guarantees)
}

/// Collection-level policy configuration
///
/// Used for CREATE operations where no specific object exists yet.
/// Evaluates permissions based on subject attributes only.
///
/// Example: User wants to upload a file
///   - Can evaluate "can user create files?" without the file existing
///   - Checks: quota_remaining > 0, role == "creator", !banned, email_verified
#[derive(Debug, Clone)]
pub struct CollectionPolicy {
	pub resource_type: String, // "files", "actions", "profiles"
	pub action: String,        // "create", "list"
	pub top_policy: Policy,    // Denials/constraints
	pub bottom_policy: Policy, // Guarantees
}

/// Main permission checker
pub struct PermissionChecker {
	profile_policies: HashMap<TnId, ProfilePolicy>,
	collection_policies: HashMap<String, CollectionPolicy>, // key: "resource:action"
}

impl PermissionChecker {
	pub fn new() -> Self {
		Self { profile_policies: HashMap::new(), collection_policies: HashMap::new() }
	}

	/// Load profile policy for tenant (called during bootstrap)
	pub fn load_policy(&mut self, policy: ProfilePolicy) {
		self.profile_policies.insert(policy.tn_id, policy);
	}

	/// Load collection policy for resource type + action
	pub fn load_collection_policy(&mut self, policy: CollectionPolicy) {
		let key = format!("{}:{}", policy.resource_type, policy.action);
		self.collection_policies.insert(key, policy);
	}

	/// Get collection policy for resource type and action
	pub fn get_collection_policy(
		&self,
		resource_type: &str,
		action: &str,
	) -> Option<&CollectionPolicy> {
		let key = format!("{}:{}", resource_type, action);
		self.collection_policies.get(&key)
	}

	/// Core permission check function
	pub fn has_permission(
		&self,
		subject: &AuthCtx,
		action: &str,
		object: &dyn AttrSet,
		environment: &Environment,
	) -> bool {
		// Step 1: Check TOP policy (constraints)
		if let Some(profile_policy) = self.profile_policies.get(&subject.tn_id) {
			if let Some(Effect::Deny) =
				profile_policy.top_policy.evaluate(subject, action, object, environment)
			{
				info!("TOP policy denied: tn_id={}, action={}", subject.tn_id.0, action);
				return false;
			}

			// Step 2: Check BOTTOM policy (guarantees)
			if let Some(Effect::Allow) =
				profile_policy.bottom_policy.evaluate(subject, action, object, environment)
			{
				info!("BOTTOM policy allowed: tn_id={}, action={}", subject.tn_id.0, action);
				return true;
			}
		}

		// Step 3: Default permission rules (ownership, visibility, etc.)
		self.check_default_rules(subject, action, object, environment)
	}

	/// Default permission rules (when policies don't match)
	fn check_default_rules(
		&self,
		subject: &AuthCtx,
		action: &str,
		object: &dyn AttrSet,
		_environment: &Environment,
	) -> bool {
		use tracing::debug;

		// Admin override - admins can do everything
		if subject.roles.iter().any(|r| r.as_ref() == "admin") {
			debug!(subject = %subject.id_tag, action = action, "Admin role allows access");
			return true;
		}

		// Parse action into resource:operation
		let parts: Vec<&str> = action.split(':').collect();
		if parts.len() != 2 {
			debug!(subject = %subject.id_tag, action = action, "Invalid action format (expected resource:operation)");
			return false;
		}
		let operation = parts[1];

		// Ownership check for modify operations
		if matches!(operation, "update" | "delete" | "write") {
			if let Some(owner) = object.get("owner_id_tag") {
				if owner == subject.id_tag.as_ref() {
					debug!(subject = %subject.id_tag, action = action, owner = owner, "Owner access allowed for modify operation");
					return true;
				}
				debug!(subject = %subject.id_tag, action = action, owner = owner, "Non-owner denied for modify operation");
			} else {
				debug!(subject = %subject.id_tag, action = action, "No owner_id_tag found for modify operation");
			}
			// Non-owners cannot modify
			return false;
		}

		// Visibility check for read operations
		if matches!(operation, "read") {
			return self.check_visibility(subject, object);
		}

		// Create operations - check quota/limits in future
		if operation == "create" {
			debug!(subject = %subject.id_tag, action = action, "Create operation allowed");
			return true; // Allow for now
		}

		// Default deny
		debug!(subject = %subject.id_tag, action = action, "Default deny: no matching rules");
		false
	}

	/// Check visibility-based access using the new VisibilityLevel enum
	///
	/// Determines subject's access level and checks against resource visibility.
	/// Supports both char-based visibility (from DB) and string-based (legacy).
	fn check_visibility(&self, subject: &AuthCtx, object: &dyn AttrSet) -> bool {
		use tracing::debug;

		// Parse visibility from object attributes
		// Try char-based first (from "visibility_char"), then fall back to string
		let visibility = if let Some(vis_char) = object.get("visibility_char") {
			VisibilityLevel::from_char(vis_char.chars().next())
		} else if let Some(vis_str) = object.get("visibility") {
			match vis_str {
				"public" | "P" => VisibilityLevel::Public,
				"verified" | "V" => VisibilityLevel::Verified,
				"second_degree" | "2" => VisibilityLevel::SecondDegree,
				"follower" | "F" => VisibilityLevel::Follower,
				"connected" | "C" => VisibilityLevel::Connected,
				"direct" => VisibilityLevel::Direct,
				_ => VisibilityLevel::Direct, // Unknown = Direct (secure by default)
			}
		} else {
			VisibilityLevel::Direct // No visibility = Direct (most restrictive)
		};

		// Determine subject's access level based on relationship with resource
		let is_owner = object.get("owner_id_tag") == Some(subject.id_tag.as_ref());
		let is_issuer = object.get("issuer_id_tag") == Some(subject.id_tag.as_ref());
		let is_connected = object.get("connected") == Some("true");
		let is_follower = object.get("following") == Some("true");
		let in_audience = object.contains("audience_tag", subject.id_tag.as_ref());

		// Calculate subject's effective access level
		// Note: "guest" id_tag is used for unauthenticated users - treat as Public
		let is_authenticated = !subject.id_tag.is_empty() && subject.id_tag.as_ref() != "guest";
		let access_level = if is_owner || is_issuer {
			SubjectAccessLevel::Owner
		} else if is_connected {
			SubjectAccessLevel::Connected
		} else if is_follower {
			SubjectAccessLevel::Follower
		} else if is_authenticated {
			// Authenticated user without specific relationship
			SubjectAccessLevel::Verified
		} else {
			SubjectAccessLevel::Public
		};

		// Check if access level meets visibility requirement
		let allowed = access_level.can_access(visibility);

		// For Direct visibility, also check explicit audience
		let allowed =
			if visibility == VisibilityLevel::Direct { allowed || in_audience } else { allowed };

		debug!(
			subject = %subject.id_tag,
			visibility = ?visibility,
			access_level = ?access_level,
			is_owner = is_owner,
			is_issuer = is_issuer,
			is_connected = is_connected,
			is_follower = is_follower,
			in_audience = in_audience,
			allowed = allowed,
			"Visibility check"
		);

		allowed
	}

	/// Evaluate collection policy (for CREATE operations)
	///
	/// Collection policies check subject attributes without an object existing.
	/// Used for operations like "can user upload files?" or "can user create posts?"
	pub fn has_collection_permission(
		&self,
		subject: &AuthCtx,
		subject_attrs: &dyn AttrSet,
		resource_type: &str,
		action: &str,
		environment: &Environment,
	) -> bool {
		use tracing::debug;

		// Get collection policy
		let policy = match self.get_collection_policy(resource_type, action) {
			Some(p) => p,
			None => {
				// No policy defined → allow by default
				debug!(
					subject = %subject.id_tag,
					resource_type = resource_type,
					action = action,
					"No collection policy found - allowing by default"
				);
				return true;
			}
		};

		// Step 1: Check TOP policy (denials/constraints)
		if let Some(Effect::Deny) =
			policy.top_policy.evaluate(subject, action, subject_attrs, environment)
		{
			debug!(
				subject = %subject.id_tag,
				resource_type = resource_type,
				action = action,
				"Collection TOP policy denied"
			);
			return false;
		}

		// Step 2: Check BOTTOM policy (guarantees)
		if let Some(Effect::Allow) =
			policy.bottom_policy.evaluate(subject, action, subject_attrs, environment)
		{
			debug!(
				subject = %subject.id_tag,
				resource_type = resource_type,
				action = action,
				"Collection BOTTOM policy allowed"
			);
			return true;
		}

		// Step 3: Default deny (no policies matched)
		debug!(
			subject = %subject.id_tag,
			resource_type = resource_type,
			action = action,
			"No matching collection policies - default deny"
		);
		false
	}
}

impl Default for PermissionChecker {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_environment_creation() {
		let env = Environment::new();
		assert!(env.time.0 > 0);
	}

	#[test]
	fn test_permission_checker_creation() {
		let checker = PermissionChecker::new();
		assert_eq!(checker.profile_policies.len(), 0);
	}
}
