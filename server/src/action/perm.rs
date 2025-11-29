//! Action permission middleware for ABAC

use axum::{
	extract::{Path, Request, State},
	middleware::Next,
	response::Response,
};

use crate::{
	auth_adapter::AuthCtx,
	core::{abac::Environment, extract::OptionalAuth, middleware::PermissionCheckOutput},
	prelude::*,
	types::ActionAttrs,
};

/// Middleware factory for action permission checks
///
/// Returns a middleware function that validates action permissions via ABAC
///
/// # Arguments
/// * `action` - The permission action to check (e.g., "read", "write")
///
/// # Returns
/// A cloneable middleware function with return type `PermissionCheckOutput`
pub fn check_perm_action(
	action: &'static str,
) -> impl Fn(State<App>, TnId, OptionalAuth, Path<String>, Request, Next) -> PermissionCheckOutput + Clone
{
	move |state, tn_id, auth, path, req, next| {
		Box::pin(check_action_permission(state, tn_id, auth, path, req, next, action))
	}
}

async fn check_action_permission(
	State(app): State<App>,
	tn_id: TnId,
	OptionalAuth(maybe_auth_ctx): OptionalAuth,
	Path(action_id): Path<String>,
	req: Request,
	next: Next,
	action: &str,
) -> Result<Response, Error> {
	use tracing::warn;

	// Create auth context or guest context if not authenticated
	let (auth_ctx, subject_id_tag) = if let Some(auth_ctx) = maybe_auth_ctx {
		let id_tag = auth_ctx.id_tag.clone();
		(auth_ctx, id_tag)
	} else {
		// For unauthenticated requests, create a guest context
		let guest_ctx =
			AuthCtx { tn_id, id_tag: "guest".into(), roles: vec![].into(), scope: None };
		(guest_ctx, "guest".into())
	};

	// Load action attributes
	let attrs = load_action_attrs(&app, tn_id, &action_id, &subject_id_tag).await?;

	// Check permission
	let environment = Environment::new();
	let checker = app.permission_checker.read().await;

	// Format action as "action:operation" for ABAC checker
	let full_action = format!("action:{}", action);

	if !checker.has_permission(&auth_ctx, &full_action, &attrs, &environment) {
		warn!(
			subject = %auth_ctx.id_tag,
			action = action,
			action_id = %action_id,
			visibility = attrs.visibility,
			issuer_id_tag = %attrs.issuer_id_tag,
			action_type = attrs.typ,
			"Action permission denied"
		);
		return Err(Error::PermissionDenied);
	}

	Ok(next.run(req).await)
}

// Load action attributes from MetaAdapter
async fn load_action_attrs(
	app: &App,
	tn_id: TnId,
	action_id: &str,
	subject_id_tag: &str,
) -> ClResult<ActionAttrs> {
	use crate::core::abac::VisibilityLevel;
	use tracing::debug;

	// Get action view from MetaAdapter
	let action_view = app.meta_adapter.get_action(tn_id, action_id).await?;

	let action_view = action_view.ok_or(Error::NotFound)?;

	// Extract audience as list of profile id_tags
	let audience_tag = action_view
		.audience
		.as_ref()
		.map(|p| vec![p.id_tag.clone()])
		.unwrap_or_default();

	// Get visibility from action metadata - convert char to string representation
	let visibility: Box<str> = VisibilityLevel::from_char(action_view.visibility).as_str().into();

	// Look up subject's relationship with the action issuer
	let (following, connected) = if subject_id_tag != "guest" && !subject_id_tag.is_empty() {
		// Get profile to check relationship status using list_profiles with id_tag filter
		let opts = crate::meta_adapter::ListProfileOptions {
			id_tag: Some(subject_id_tag.to_string()),
			..Default::default()
		};
		match app.meta_adapter.list_profiles(tn_id, &opts).await {
			Ok(profiles) => {
				if let Some(profile) = profiles.first() {
					let following = profile.following;
					let connected = profile.connected;
					debug!(
						subject = subject_id_tag,
						issuer = %action_view.issuer.id_tag,
						following = following,
						connected = connected,
						"Loaded relationship status for action permission check"
					);
					(following, connected)
				} else {
					debug!(subject = subject_id_tag, "Profile not found, assuming no relationship");
					(false, false)
				}
			}
			Err(e) => {
				debug!(
					subject = subject_id_tag,
					error = %e,
					"Failed to load profile, assuming no relationship"
				);
				(false, false)
			}
		}
	} else {
		(false, false)
	};

	Ok(ActionAttrs {
		typ: action_view.typ,
		sub_typ: action_view.sub_typ,
		issuer_id_tag: action_view.issuer.id_tag,
		parent_id: action_view.parent_id,
		root_id: action_view.root_id,
		audience_tag,
		tags: vec![], // TODO: Extract tags from action metadata when available
		visibility,
		following,
		connected,
	})
}
