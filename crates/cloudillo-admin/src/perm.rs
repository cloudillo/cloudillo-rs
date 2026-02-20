//! Admin permission middleware

use axum::{
	extract::{Request, State},
	middleware::Next,
	response::Response,
};

use cloudillo_core::extract::Auth;

use crate::prelude::*;

/// Middleware that checks if the current user has admin role (SADM)
///
/// This middleware is simpler than `check_perm_profile` as it doesn't require
/// a path parameter - it just checks if the authenticated user has admin privileges.
pub async fn require_admin(
	State(_app): State<App>,
	Auth(auth_ctx): Auth,
	req: Request,
	next: Next,
) -> Result<Response, Error> {
	// Check if user has SADM (site admin) role
	if !auth_ctx.roles.iter().any(|r| r.as_ref() == "SADM") {
		tracing::warn!(
			subject = %auth_ctx.id_tag,
			roles = ?auth_ctx.roles,
			"Admin permission denied - SADM role required"
		);
		return Err(Error::PermissionDenied);
	}

	Ok(next.run(req).await)
}

// vim: ts=4
