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

	if !checker.has_permission(&auth_ctx, action, &attrs, &environment) {
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

// STUB IMPLEMENTATION - Phase 3 will replace with real adapter calls
async fn load_profile_attrs(
	_app: &App,
	_tn_id: TnId,
	_id_tag: &str,
	_subject_id_tag: &str,
) -> ClResult<ProfileAttrs> {
	// TODO: Call app.meta_adapter.get_profile_attrs(tn_id, id_tag, subject_id_tag).await
	Ok(ProfileAttrs {
		id_tag: "stub".into(),
		profile_type: "person".into(),
		tenant_tag: "tenant1".into(),
		roles: vec!["member".into()],
		status: "active".into(),
		following: false,
		connected: false,
	})
}
