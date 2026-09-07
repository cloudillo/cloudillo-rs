// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Profile permission middleware for ABAC

use axum::{
	extract::{Path, Request, State, rejection::PathRejection},
	middleware::Next,
	response::Response,
};
use serde::Deserialize;

use crate::prelude::*;
use cloudillo_core::abac::Environment;
use cloudillo_core::extract::{Auth, IdTag};
use cloudillo_core::middleware::PermissionCheckOutput;
use cloudillo_types::types::ProfileAttrs;

/// The one path parameter this guard authorizes on.
///
/// Extracted by name, so trailing captures are simply ignored — `Path<T>` over a
/// struct goes through serde's map deserializer, which does not arity-check the
/// way a single-field `Path<String>` (a *sequence*) does. Reading positionally
/// would be worse than inelegant here: a route whose first capture is not the
/// id_tag would authorize against a different subject.
#[derive(Deserialize)]
pub struct IdTagParam {
	id_tag: String,
}

/// The guard's path extraction, kept fallible: a route with no `{id_tag}` capture
/// gets a logged `PermissionDenied` rather than axum's bare 400 with the serde
/// message in it.
type IdTagPath = Result<Path<IdTagParam>, PathRejection>;

/// Middleware factory for profile permission checks
///
/// Returns a middleware function that validates profile permissions via ABAC
///
/// # Arguments
/// * `action` - The permission action to check (e.g., "read", "write")
///
/// # Returns
/// A cloneable middleware function with return type `PermissionCheckOutput`
///
/// The route must capture the subject as `{id_tag}` — the guard reads it by name,
/// not by position. Other captures are ignored.
pub fn check_perm_profile(
	action: &'static str,
) -> impl Fn(State<App>, IdTag, Auth, IdTagPath, Request, Next) -> PermissionCheckOutput + Clone {
	move |state, tenant, auth, params, req, next| {
		Box::pin(check_profile_permission(state, tenant, auth, params, req, next, action))
	}
}

async fn check_profile_permission(
	State(app): State<App>,
	IdTag(tenant_id_tag): IdTag,
	Auth(auth_ctx): Auth,
	params: IdTagPath,
	req: Request,
	next: Next,
	action: &str,
) -> Result<Response, Error> {
	use tracing::warn;

	let Ok(Path(IdTagParam { id_tag })) = params else {
		warn!("Profile permission guard on a route with no {{id_tag}} capture");
		return Err(Error::PermissionDenied);
	};

	let attrs =
		load_profile_attrs(&app, auth_ctx.tn_id, &tenant_id_tag, &id_tag, &auth_ctx.id_tag).await?;

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
			tenant_id_tag = %attrs.tenant_id_tag,
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
	tenant_id_tag: &str,
	id_tag: &str,
	subject_id_tag: &str,
) -> ClResult<ProfileAttrs> {
	// Query subject's roles in this tenant
	let subject_roles = app
		.meta_adapter
		.read_profile_roles(tn_id, subject_id_tag)
		.await
		.ok()
		.flatten()
		.map(Vec::from)
		.unwrap_or_default();

	// Get profile data from MetaAdapter - if not found, return default attrs
	match app.meta_adapter.get_profile_info(tn_id, id_tag).await {
		Ok(profile_data) => {
			// Determine if subject is following or connected to target
			// For now, default to false - in Phase 4 this will query relationship metadata
			let is_follower = false;
			let connected = false;

			Ok(ProfileAttrs {
				id_tag: profile_data.id_tag,
				profile_type: profile_data.r#type,
				// Owner authority over a profile row is the hosting tenant's, never the
				// row's subject: a member must not edit the tenant's record about them.
				tenant_id_tag: tenant_id_tag.into(),
				roles: subject_roles,
				status: "active".into(), // TODO: Query actual profile status from MetaAdapter
				is_follower,
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
				tenant_id_tag: tenant_id_tag.into(),
				roles: subject_roles,
				status: "unknown".into(),
				is_follower: false,
				connected: false,
				visibility: "public".into(), // Profiles are publicly readable
			})
		}
		Err(e) => Err(e),
	}
}

#[cfg(test)]
mod tests {
	use cloudillo_core::abac::{Environment, PermissionChecker};
	use cloudillo_types::auth_adapter::AuthCtx;
	use cloudillo_types::types::{ProfileAttrs, TnId};

	fn attrs(tenant_id_tag: &str) -> ProfileAttrs {
		ProfileAttrs {
			id_tag: "bob.example.com".into(),
			profile_type: "person".into(),
			tenant_id_tag: tenant_id_tag.into(),
			roles: vec![],
			status: "active".into(),
			is_follower: false,
			connected: false,
			visibility: "public".into(),
		}
	}

	fn subject(id_tag: &str) -> AuthCtx {
		AuthCtx {
			tn_id: TnId(1),
			id_tag: id_tag.into(),
			roles: Box::new([]),
			scope: None,
			anonymous: false,
		}
	}

	/// `tenant_id_tag` must be the hosting tenant, not the *target* profile: ABAC's ownership
	/// branch would otherwise hand `profile:write` to the row's own subject — letting a
	/// suspended community member lift their own status.
	#[test]
	fn member_has_no_write_authority_over_own_profile_row() {
		let checker = PermissionChecker::new();
		let env = Environment::new();
		let community = attrs("community.example.com");
		let bob = subject("bob.example.com");

		assert!(!checker.has_permission(&bob, "profile:write", &community, &env));
		assert!(!checker.has_permission(&bob, "profile:delete", &community, &env));

		// Reading stays open — visibility is hardcoded "public".
		assert!(checker.has_permission(&bob, "profile:read", &community, &env));

		// The tenant itself keeps owner authority over the rows it hosts.
		let tenant = subject("community.example.com");
		assert!(checker.has_permission(&tenant, "profile:write", &community, &env));
	}
}

// vim: ts=4
