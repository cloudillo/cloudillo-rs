//! Action permission middleware for ABAC

use axum::{
	extract::{Path, Request, State},
	middleware::Next,
	response::Response,
};

use crate::{
	core::{abac::Environment, extract::Auth, middleware::PermissionCheckOutput},
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
) -> impl Fn(State<App>, Auth, Path<String>, Request, Next) -> PermissionCheckOutput + Clone {
	move |state, auth, path, req, next| {
		Box::pin(check_action_permission(state, auth, path, req, next, action))
	}
}

async fn check_action_permission(
	State(app): State<App>,
	Auth(auth_ctx): Auth,
	Path(action_id): Path<String>,
	req: Request,
	next: Next,
	action: &str,
) -> Result<Response, Error> {
	use tracing::warn;

	// Load action attributes (STUB - Phase 3 will implement)
	let attrs = load_action_attrs(&app, auth_ctx.tn_id, &action_id, &auth_ctx.id_tag).await?;

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
	_subject_id_tag: &str,
) -> ClResult<ActionAttrs> {
	// Get action view from MetaAdapter
	let action_view = app.meta_adapter.get_action(tn_id, action_id).await?;

	let action_view = action_view.ok_or(Error::NotFound)?;

	// Extract audience as list of profile id_tags
	let audience_tag = action_view
		.audience
		.as_ref()
		.map(|p| vec![p.id_tag.clone()])
		.unwrap_or_default();

	// Determine visibility based on audience and action properties
	// TODO: Add explicit visibility field to ActionView for more fine-grained control
	let visibility = if audience_tag.is_empty() {
		"public".into()
	} else {
		"direct".into() // Has specific audience
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
	})
}
