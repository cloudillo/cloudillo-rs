// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Action permission middleware for ABAC

use axum::{
	extract::{Path, Request, State, rejection::PathRejection},
	middleware::Next,
	response::Response,
};
use serde::Deserialize;

use cloudillo_core::{
	abac::Environment,
	extract::{IdTag, OptionalAuth},
	middleware::PermissionCheckOutput,
};
use cloudillo_types::auth_adapter::AuthCtx;
use cloudillo_types::types::ActionAttrs;

use crate::prelude::*;

/// The one path parameter this guard authorizes on.
///
/// Extracted by name, so trailing captures are simply ignored — `Path<T>` over a
/// struct goes through serde's map deserializer, which does not arity-check the
/// way a single-field `Path<String>` (a *sequence*) does.
#[derive(Deserialize)]
pub struct ActionIdParam {
	action_id: String,
}

/// The guard's path extraction, kept fallible: a route with no `{action_id}`
/// capture gets a logged `PermissionDenied` rather than axum's bare 400 with the
/// serde message in it.
type ActionIdPath = Result<Path<ActionIdParam>, PathRejection>;

/// Middleware factory for action permission checks
///
/// Returns a middleware function that validates action permissions via ABAC
///
/// # Arguments
/// * `action` - The permission action to check (e.g., "read", "write")
///
/// # Returns
/// A cloneable middleware function with return type `PermissionCheckOutput`
///
/// The route must capture the action id as `{action_id}` — the guard reads it by
/// name, not by position. Other captures are ignored.
pub fn check_perm_action(
	action: &'static str,
) -> impl Fn(State<App>, TnId, IdTag, OptionalAuth, ActionIdPath, Request, Next) -> PermissionCheckOutput
+ Clone {
	move |state, tn_id, id_tag, auth, params, req, next| {
		Box::pin(check_action_permission(state, tn_id, id_tag, auth, params, req, next, action))
	}
}

#[expect(clippy::too_many_arguments, reason = "permission check requires all context fields")]
async fn check_action_permission(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	OptionalAuth(maybe_auth_ctx): OptionalAuth,
	params: ActionIdPath,
	req: Request,
	next: Next,
	action: &str,
) -> Result<Response, Error> {
	use tracing::warn;

	let Ok(Path(ActionIdParam { action_id })) = params else {
		warn!("Action permission guard on a route with no {{action_id}} capture");
		return Err(Error::PermissionDenied);
	};

	// Draft actions (@{a_id}): skip ABAC, verify authenticated user is the issuer
	if action_id.starts_with('@') {
		let auth_ctx = maybe_auth_ctx.ok_or(Error::PermissionDenied)?;
		let draft = app.meta_adapter.get_action(tn_id, &action_id).await?.ok_or(Error::NotFound)?;
		// Someone else's draft does not exist for this caller.
		if draft.issuer.id_tag.as_ref() != auth_ctx.id_tag.as_ref() {
			return Err(Error::NotFound);
		}
		return Ok(next.run(req).await);
	}

	// Create auth context or guest context if not authenticated
	let auth_ctx = maybe_auth_ctx.unwrap_or_else(|| AuthCtx {
		tn_id,
		id_tag: "guest".into(),
		roles: vec![].into(),
		scope: None,
		anonymous: true,
		hat: None,
		exp: None,
	});

	// Load action attributes
	let attrs = load_action_attrs(&app, tn_id, &action_id, &auth_ctx, &tenant_id_tag).await?;

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

/// Require read on `action_id` through the same path as `GET /api/actions/{id}`.
/// NotFound on denial, so a hidden (or deleted) parent is indistinguishable from a missing one.
pub(crate) async fn check_action_read(
	app: &App,
	tn_id: TnId,
	action_id: &str,
	auth_ctx: &AuthCtx,
	tenant_id_tag: &str,
) -> ClResult<()> {
	let attrs = load_action_attrs(app, tn_id, action_id, auth_ctx, tenant_id_tag)
		.await
		.map_err(|e| if matches!(e, Error::PermissionDenied) { Error::NotFound } else { e })?;
	let checker = app.permission_checker.read().await;
	if checker.has_permission(auth_ctx, "action:read", &attrs, &Environment::new()) {
		Ok(())
	} else {
		Err(Error::NotFound)
	}
}

// Load action attributes from MetaAdapter
async fn load_action_attrs(
	app: &App,
	tn_id: TnId,
	action_id: &str,
	auth: &AuthCtx,
	tenant_id_tag: &str,
) -> ClResult<ActionAttrs> {
	use cloudillo_core::abac::{self, VisibilityLevel};

	// A credential naming the tenant without being it (share link, via-embed) is a guest here:
	// handed to `enterable_channels` as the tenant's id_tag it would lift the channel gate.
	let is_tenant = abac::is_tenant_self(auth, tenant_id_tag);
	let impostor = abac::names_tenant_without_being_it(auth, tenant_id_tag);
	let subject_id_tag: &str = if impostor { "guest" } else { &auth.id_tag };
	let subject_roles: &[Box<str>] = if impostor { &[] } else { &auth.roles };

	// Get action view from MetaAdapter
	let action_view = app.meta_adapter.get_action(tn_id, action_id).await?;

	let action_view = action_view.ok_or(Error::NotFound)?;

	// A hatted action we relayed is readable here by the tenant only (see `list_actions`).
	if action_view.hat.as_ref().is_some_and(|h| &*h.id_tag == tenant_id_tag) && !is_tenant {
		return Err(Error::PermissionDenied);
	}

	// Channel gate, the same rule the list applies: a room the reader cannot enter hides its rows.
	if let Some(channel) = action_view.channel.as_deref() {
		let enterable = cloudillo_core::channels::enterable_channels(
			app,
			tn_id,
			tenant_id_tag,
			subject_id_tag,
			subject_roles,
			auth.hat.is_some(),
		)
		.await?;
		if enterable.is_some_and(|set| !set.iter().any(|c| c.as_ref() == channel)) {
			return Err(Error::PermissionDenied);
		}
	}

	// Extract audience as list of profile id_tags
	let mut audience_tag = action_view
		.audience
		.as_ref()
		.map(|p| vec![p.id_tag.clone()])
		.unwrap_or_default();

	// Subscriber bridge — the same container rule the list filter applies.
	if let Some(c) = crate::filter::subscriber_container(&action_view)
		&& crate::filter::load_subscribers(app, tn_id, &[c])
			.await
			.get(c)
			.is_some_and(|subs| subs.contains(subject_id_tag))
	{
		audience_tag.push(subject_id_tag.into());
	}

	// Get visibility from action metadata - convert char to string representation
	let visibility: Box<str> = VisibilityLevel::from_char(action_view.visibility).as_str().into();

	// The reader's relation to *this tenant*: `follower` is "they follow us", which is what the
	// visibility rules mean. Same value and same guard as `cloudillo_file::perm::load_file_attrs`
	// — only the SecondDegree/Follower/Connected rungs consult it. `filter::
	// filter_actions_by_visibility` reads the same pair, so the single-item and list views of one
	// action can never disagree.
	let rel = if abac::visibility_needs_relation(VisibilityLevel::from_char(action_view.visibility))
	{
		abac::subject_relation_to_tenant(app, tn_id, subject_id_tag).await?
	} else {
		cloudillo_types::meta_adapter::ProfileRelation::default()
	};

	Ok(ActionAttrs {
		typ: action_view.typ,
		sub_typ: action_view.sub_typ,
		tenant_id_tag: tenant_id_tag.into(),
		issuer_id_tag: action_view.issuer.id_tag,
		parent_id: action_view.parent_id,
		root_id: action_view.root_id,
		audience_tag,
		tags: vec![], // TODO: Extract tags from action metadata when available
		visibility,
		is_follower: rel.follower,
		connected: rel.connected,
	})
}
