//! Collection-level permission middleware for ABAC (CREATE operations)
//!
//! Validates CREATE permissions for resources that don't yet exist,
//! based on subject attributes like quota, tier, and role.

use axum::{
	extract::{Request, State},
	middleware::Next,
	response::Response,
};

use crate::{abac::Environment, extract::Auth, middleware::PermissionCheckOutput, prelude::*};
use cloudillo_types::types::SubjectAttrs;

/// Middleware factory for collection permission checks
///
/// Returns a middleware function that validates CREATE permissions via ABAC.
/// Evaluates collection-level policies based on subject attributes.
///
/// # Arguments
/// * `resource_type` - The resource being created (e.g., "file", "action")
/// * `action` - The permission action to check (e.g., "create")
///
/// # Returns
/// A cloneable middleware function with return type `PermissionCheckOutput`
pub fn check_perm_create(
	resource_type: &'static str,
	action: &'static str,
) -> impl Fn(State<App>, Auth, Request, Next) -> PermissionCheckOutput + Clone {
	move |state, auth, req, next| {
		Box::pin(check_create_permission(state, auth, req, next, resource_type, action))
	}
}

async fn check_create_permission(
	State(app): State<App>,
	Auth(auth_ctx): Auth,
	req: Request,
	next: Next,
	resource_type: &str,
	action: &str,
) -> Result<Response, Error> {
	use tracing::warn;

	// Check if user has a role that allows content creation
	// Minimum role for creating content: "contributor"
	if !auth_ctx.roles.iter().any(|r| r.as_ref() == "contributor") {
		warn!(
			subject = %auth_ctx.id_tag,
			resource_type = resource_type,
			action = action,
			roles = ?auth_ctx.roles,
			"CREATE permission denied: requires at least 'contributor' role"
		);
		return Err(Error::PermissionDenied);
	}

	// Load subject attributes
	let subject_attrs = load_subject_attrs(&app, &auth_ctx).await?;

	// Create environment context
	let environment = Environment::new();
	let checker = app.permission_checker.read().await;

	// Evaluate collection policy
	if !checker.has_collection_permission(
		&auth_ctx,
		&subject_attrs,
		resource_type,
		action,
		&environment,
	) {
		warn!(
			subject = %auth_ctx.id_tag,
			resource_type = resource_type,
			action = action,
			tier = %subject_attrs.tier,
			quota_remaining_bytes = %subject_attrs.quota_remaining_bytes,
			roles = ?subject_attrs.roles,
			banned = subject_attrs.banned,
			email_verified = subject_attrs.email_verified,
			"CREATE permission denied"
		);
		return Err(Error::PermissionDenied);
	}

	Ok(next.run(req).await)
}

/// Load subject attributes for collection-level permission evaluation
///
/// Loads user's tier, quota, roles, and status from authentication/metadata.
/// These attributes are used to evaluate CREATE operation permissions.
async fn load_subject_attrs(
	app: &App,
	auth_ctx: &cloudillo_types::auth_adapter::AuthCtx,
) -> ClResult<SubjectAttrs> {
	// Check if user is banned by querying profile ban status
	// Note: We use get_profile_info which returns ProfileData with status information
	let banned = match app.meta_adapter.get_profile_info(auth_ctx.tn_id, &auth_ctx.id_tag).await {
		Ok(_profile_data) => {
			// Check if profile status indicates banned
			// ProfileData.status is not available in current implementation,
			// so we need to query more directly. For now, default to false.
			// TODO: Extend ProfileData or add get_profile_ban_status method to adapter
			false
		}
		Err(_) => {
			// If profile doesn't exist locally, assume not banned
			// (user might be from remote instance)
			false
		}
	};

	// Check if email is verified by checking tenant status
	// If we can successfully read the tenant, they have been created and verified
	let email_verified = match app.auth_adapter.read_tenant(&auth_ctx.id_tag).await {
		Ok(_) => {
			// If tenant exists and we can read it, assume verified
			// In the current schema, tenant status 'A' means Active/verified
			// TODO: Add explicit email_verified field to tenants table for better tracking
			true
		}
		Err(_) => {
			// If we can't read tenant, they may not be local or not verified
			false
		}
	};

	// Determine user tier based on roles
	let tier: Box<str> = if auth_ctx.roles.iter().any(|r| r.as_ref() == "leader") {
		"premium".into()
	} else if auth_ctx.roles.iter().any(|r| r.as_ref() == "creator") {
		"standard".into()
	} else {
		"free".into()
	};

	// Calculate quota remaining (in bytes)
	// TODO: Query from meta_adapter to get user's actual used quota
	let quota_bytes = match tier.as_ref() {
		"premium" => 1024 * 1024 * 1024, // 1GB
		"standard" => 100 * 1024 * 1024, // 100MB
		_ => 10 * 1024 * 1024,           // 10MB (free tier)
	};

	// Get rate limit remaining (per hour)
	// TODO: Query from meta_adapter or time-based tracker for actual rate limit tracking
	let rate_limit_remaining_val = 100u32; // per hour

	Ok(SubjectAttrs {
		id_tag: auth_ctx.id_tag.clone(),
		roles: auth_ctx.roles.to_vec(),
		tier,
		quota_remaining_bytes: quota_bytes.to_string().into(),
		rate_limit_remaining: rate_limit_remaining_val.to_string().into(),
		banned,
		email_verified,
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_subject_attrs_creation() {
		let attrs = SubjectAttrs {
			id_tag: "alice".into(),
			roles: vec!["creator".into()],
			tier: "standard".into(),
			quota_remaining_bytes: "100000000".into(),
			rate_limit_remaining: "50".into(),
			banned: false,
			email_verified: true,
		};

		assert_eq!(attrs.id_tag.as_ref(), "alice");
		assert_eq!(attrs.tier.as_ref(), "standard");
		assert!(!attrs.banned);
		assert!(attrs.email_verified);
	}

	#[test]
	fn test_subject_attrs_implements_attr_set() {
		use crate::abac::AttrSet;

		let attrs = SubjectAttrs {
			id_tag: "bob".into(),
			roles: vec!["member".into(), "creator".into()],
			tier: "premium".into(),
			quota_remaining_bytes: "500000000".into(),
			rate_limit_remaining: "95".into(),
			banned: false,
			email_verified: true,
		};

		// Test get()
		assert_eq!(attrs.get("id_tag"), Some("bob"));
		assert_eq!(attrs.get("tier"), Some("premium"));
		assert_eq!(attrs.get("banned"), Some("false"));

		// Test get_list()
		let roles = attrs.get_list("roles");
		assert!(roles.is_some());
		assert_eq!(roles.unwrap().len(), 2);

		// Test has()
		assert!(attrs.has("tier", "premium"));
		assert!(!attrs.has("tier", "free"));

		// Test contains()
		assert!(attrs.contains("roles", "creator"));
		assert!(!attrs.contains("roles", "admin"));
	}
}

// vim: ts=4
