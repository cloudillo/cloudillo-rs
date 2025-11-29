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

	// Load file attributes
	let attrs = load_file_attrs(&app, tn_id, &file_id, &subject_id_tag, &tenant_id_tag).await?;

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
	file_id: &str,
	_subject_id_tag: &str,
	tenant_id_tag: &str,
) -> ClResult<FileAttrs> {
	// Get file view from MetaAdapter
	let file_view = app.meta_adapter.read_file(tn_id, file_id).await?;

	let file_view = file_view.ok_or(Error::NotFound)?;

	// Extract owner from nested ProfileInfo
	// If no owner or owner has empty id_tag, file is owned by the tenant itself
	let owner_id_tag = file_view
		.owner
		.as_ref()
		.and_then(|p| if p.id_tag.is_empty() { None } else { Some(p.id_tag.clone()) })
		.unwrap_or_else(|| {
			use tracing::debug;
			debug!("File has no owner, using tenant_id_tag: {}", tenant_id_tag);
			tenant_id_tag.into()
		});

	// Determine access level based on file status and file content type
	// Default to Read for now - can be enhanced with granular permissions
	let access_level = crate::types::AccessLevel::Read;

	// Get visibility from file metadata
	// TODO: Add visibility field to FileView in meta_adapter
	let visibility = "public".into(); // Default to public for now

	Ok(FileAttrs {
		file_id: file_view.file_id,
		owner_id_tag,
		mime_type: file_view.content_type.unwrap_or_else(|| "application/octet-stream".into()),
		tags: file_view.tags.unwrap_or_default(),
		visibility,
		access_level,
	})
}

// vim: ts=4
