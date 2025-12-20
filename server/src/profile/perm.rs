//! Profile permission middleware for ABAC

use axum::{
	extract::{Path, Request, State},
	middleware::Next,
	response::Response,
};

use crate::{
	core::{abac::Environment, extract::Auth, middleware::PermissionCheckOutput},
	prelude::*,
	types::ProfileAttrs,
};

/// Middleware factory for profile permission checks
///
/// Returns a middleware function that validates profile permissions via ABAC
///
/// # Arguments
/// * `action` - The permission action to check (e.g., "read", "write")
///
/// # Returns
/// A cloneable middleware function with return type `PermissionCheckOutput`
pub fn check_perm_profile(
	action: &'static str,
) -> impl Fn(State<App>, Auth, Path<String>, Request, Next) -> PermissionCheckOutput + Clone {
	move |state, auth, path, req, next| {
		Box::pin(check_profile_permission(state, auth, path, req, next, action))
	}
}

async fn check_profile_permission(
	State(app): State<App>,
	Auth(auth_ctx): Auth,
	Path(id_tag): Path<String>,
	req: Request,
	next: Next,
	action: &str,
) -> Result<Response, Error> {
	use tracing::warn;

	// Load profile attributes (STUB - Phase 3 will implement)
	let attrs = load_profile_attrs(&app, auth_ctx.tn_id, &id_tag, &auth_ctx.id_tag).await?;

	// Check permission
	let environment = Environment::new();
	let checker = app.permission_checker.read().await;

	// Format action as "profile:operation" for ABAC checker
	let full_action = format!("profile:{}", action);

	if !checker.has_permission(&auth_ctx, &full_action, &attrs, &environment) {
		warn!(
			subject = %auth_ctx.id_tag,
			action = action,
			target_id_tag = %id_tag,
			owner_id_tag = %attrs.tenant_tag,
			profile_type = attrs.profile_type,
			roles = ?attrs.roles,
			status = attrs.status,
			"Profile permission denied"
		);
		return Err(Error::PermissionDenied);
	}

	Ok(next.run(req).await)
}

// Load profile attributes from MetaAdapter
async fn load_profile_attrs(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	_subject_id_tag: &str,
) -> ClResult<ProfileAttrs> {
	// Get profile data from MetaAdapter - if not found, return default attrs
	match app.meta_adapter.get_profile_info(tn_id, id_tag).await {
		Ok(profile_data) => {
			// Determine if subject is following or connected to target
			// For now, default to false - in Phase 4 this will query relationship metadata
			let following = false;
			let connected = false;

			Ok(ProfileAttrs {
				id_tag: profile_data.id_tag,
				profile_type: profile_data.r#type,
				tenant_tag: id_tag.into(), // tenant_tag refers to the profile owner
				roles: vec![],             // TODO: Query actual roles from relationship metadata in Phase 4
				status: "active".into(),   // TODO: Query actual profile status from MetaAdapter
				following,
				connected,
				visibility: "public".into(), // Profiles are publicly readable
			})
		}
		Err(Error::NotFound) => {
			// Profile doesn't exist locally - return default attrs
			// This allows read operations to proceed (handler will return empty object)
			Ok(ProfileAttrs {
				id_tag: id_tag.into(),
				profile_type: "person".into(),
				tenant_tag: id_tag.into(),
				roles: vec![],
				status: "unknown".into(),
				following: false,
				connected: false,
				visibility: "public".into(), // Profiles are publicly readable
			})
		}
		Err(e) => Err(e),
	}
}

// vim: ts=4
