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

	/// Check visibility-based access
	fn check_visibility(&self, subject: &AuthCtx, object: &dyn AttrSet) -> bool {
		use tracing::debug;

		let visibility = object.get("visibility").unwrap_or("private");

		match visibility {
			"public" => {
				debug!(subject = %subject.id_tag, visibility = "public", "Public visibility allows access");
				true
			}
			"private" => {
				// Only owner can access
				let is_owner = object.get("owner_id_tag") == Some(subject.id_tag.as_ref());
				if is_owner {
					debug!(subject = %subject.id_tag, visibility = "private", owner = object.get("owner_id_tag").unwrap_or("unknown"), "Owner can access private content");
				} else {
					debug!(subject = %subject.id_tag, visibility = "private", owner = object.get("owner_id_tag").unwrap_or("unknown"), "Non-owner cannot access private content");
				}
				is_owner
			}
			"followers" => {
				// Check if subject follows owner
				let is_owner = object.get("owner_id_tag") == Some(subject.id_tag.as_ref());
				let is_follower = object.get("following") == Some("true");
				let allowed = is_follower || is_owner;
				if allowed {
					debug!(subject = %subject.id_tag, visibility = "followers", is_owner = is_owner, is_follower = is_follower, "Follower visibility allows access");
				} else {
					debug!(subject = %subject.id_tag, visibility = "followers", is_owner = is_owner, is_follower = is_follower, "Not a follower and not owner - denied");
				}
				allowed
			}
			"connected" => {
				// Check if subject is connected to owner
				let is_owner = object.get("owner_id_tag") == Some(subject.id_tag.as_ref());
				let is_connected = object.get("connected") == Some("true");
				let allowed = is_connected || is_owner;
				if allowed {
					debug!(subject = %subject.id_tag, visibility = "connected", is_owner = is_owner, is_connected = is_connected, "Connected visibility allows access");
				} else {
					debug!(subject = %subject.id_tag, visibility = "connected", is_owner = is_owner, is_connected = is_connected, "Not connected and not owner - denied");
				}
				allowed
			}
			"direct" => {
				// Check audience list
				let is_owner = object.get("owner_id_tag") == Some(subject.id_tag.as_ref());
				let is_issuer = object.get("issuer_id_tag") == Some(subject.id_tag.as_ref());
				let in_audience = object.contains("audience_tag", subject.id_tag.as_ref());
				let allowed = in_audience || is_owner || is_issuer;
				if allowed {
					debug!(subject = %subject.id_tag, visibility = "direct", in_audience = in_audience, is_owner = is_owner, is_issuer = is_issuer, "Direct audience check allows access");
				} else {
					debug!(subject = %subject.id_tag, visibility = "direct", in_audience = in_audience, is_owner = is_owner, is_issuer = is_issuer, "Not in audience - denied");
				}
				allowed
			}
			_ => {
				debug!(subject = %subject.id_tag, visibility = visibility, "Unknown visibility level - denied");
				false
			}
		}
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
