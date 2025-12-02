//! File permission middleware for ABAC

use axum::{
	extract::{Path, Request, State},
	middleware::Next,
	response::Response,
};

use crate::{
	auth_adapter::AuthCtx,
	core::{
		abac::Environment,
		extract::{IdTag, OptionalAuth},
		file_access,
		middleware::PermissionCheckOutput,
	},
	prelude::*,
	types::FileAttrs,
};

/// Middleware factory for file permission checks
///
/// Returns a middleware function that validates file permissions via ABAC
///
/// # Arguments
/// * `action` - The permission action to check (e.g., "read", "write")
///
/// # Returns
/// A cloneable middleware function with return type `PermissionCheckOutput`
pub fn check_perm_file(
	action: &'static str,
) -> impl Fn(
	State<App>,
	IdTag,
	TnId,
	OptionalAuth,
	Path<String>,
	Request,
	Next,
) -> PermissionCheckOutput
       + Clone {
	move |state, id_tag, tn_id, auth, path, req, next| {
		Box::pin(check_file_permission(state, id_tag, tn_id, auth, path, req, next, action))
	}
}

#[allow(clippy::too_many_arguments)]
async fn check_file_permission(
	State(app): State<App>,
	IdTag(tenant_id_tag): IdTag,
	tn_id: TnId,
	OptionalAuth(maybe_auth_ctx): OptionalAuth,
	Path(file_id): Path<String>,
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

	// Load file attributes (pass scope from auth context for scoped token access)
	let attrs = load_file_attrs(
		&app,
		tn_id,
		&file_id,
		&subject_id_tag,
		&tenant_id_tag,
		auth_ctx.scope.as_deref(),
	)
	.await?;

	// Check permission
	let environment = Environment::new();
	let checker = app.permission_checker.read().await;

	// Format action as "file:operation" for ABAC checker
	let full_action = format!("file:{}", action);

	if !checker.has_permission(&auth_ctx, &full_action, &attrs, &environment) {
		warn!(
			subject = %auth_ctx.id_tag,
			action = %full_action,
			file_id = %file_id,
			visibility = attrs.visibility,
			owner_id_tag = %attrs.owner_id_tag,
			access_level = ?attrs.access_level,
			"File permission denied"
		);
		return Err(Error::PermissionDenied);
	}

	Ok(next.run(req).await)
}

// Load file attributes from MetaAdapter
async fn load_file_attrs(
	app: &App,
	tn_id: TnId,
	file_or_variant_id: &str,
	subject_id_tag: &str,
	tenant_id_tag: &str,
	scope: Option<&str>,
) -> ClResult<FileAttrs> {
	use crate::core::abac::VisibilityLevel;
	use std::borrow::Cow;
	use tracing::debug;

	// Detect if this is a variant_id (starts with 'b') and look up the file_id
	let file_id: Cow<str> = if file_or_variant_id.starts_with('b') {
		// This is a variant_id, look up the file_id
		debug!("Looking up file_id for variant_id: {}", file_or_variant_id);
		let fid = app.meta_adapter.read_file_id_by_variant(tn_id, file_or_variant_id).await?;
		debug!("Found file_id: {} for variant_id: {}", fid, file_or_variant_id);
		Cow::Owned(fid.to_string())
	} else {
		Cow::Borrowed(file_or_variant_id)
	};

	// Get file view from MetaAdapter
	let file_view = app.meta_adapter.read_file(tn_id, &file_id).await?;

	let file_view = file_view.ok_or(Error::NotFound)?;

	// Extract owner from nested ProfileInfo
	// If no owner or owner has empty id_tag, file is owned by the tenant itself
	let owner_id_tag = file_view
		.owner
		.as_ref()
		.and_then(|p| if p.id_tag.is_empty() { None } else { Some(p.id_tag.clone()) })
		.unwrap_or_else(|| {
			debug!("File has no owner, using tenant_id_tag: {}", tenant_id_tag);
			tenant_id_tag.into()
		});

	// Determine access level by looking up scoped tokens, FSHR action grants
	let access_level = file_access::get_access_level_with_scope(
		app,
		tn_id,
		&file_id,
		subject_id_tag,
		&owner_id_tag,
		scope,
	)
	.await;

	// Get visibility from file metadata - convert char to string representation
	let visibility: Box<str> = VisibilityLevel::from_char(file_view.visibility).as_str().into();

	// Look up subject's relationship with the file owner
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
						owner = %owner_id_tag,
						following = following,
						connected = connected,
						"Loaded relationship status for file permission check"
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

	Ok(FileAttrs {
		file_id: file_view.file_id,
		owner_id_tag,
		mime_type: file_view.content_type.unwrap_or_else(|| "application/octet-stream".into()),
		tags: file_view.tags.unwrap_or_default(),
		visibility,
		access_level,
		following,
		connected,
	})
}

// vim: ts=4
