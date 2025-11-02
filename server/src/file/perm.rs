//! File permission middleware for ABAC

use axum::{
	extract::{Path, Request, State},
	middleware::Next,
	response::Response,
};
use std::future::Future;
use std::pin::Pin;

use crate::{
	core::{abac::Environment, extract::Auth},
	prelude::*,
	types::FileAttrs,
};

/// Middleware factory for file permission checks
pub fn check_perm_file(
	action: &'static str,
) -> impl Fn(
	State<App>,
	Auth,
	Path<String>,
	Request,
	Next,
) -> Pin<Box<dyn Future<Output = Result<Response, Error>> + Send>>
       + Clone {
	move |state, auth, path, req, next| {
		Box::pin(check_file_permission(state, auth, path, req, next, action))
	}
}

async fn check_file_permission(
	State(app): State<App>,
	Auth(auth_ctx): Auth,
	Path(file_id): Path<String>,
	req: Request,
	next: Next,
	action: &str,
) -> Result<Response, Error> {
	use tracing::warn;

	// Load file attributes (STUB - Phase 3 will implement)
	let attrs = load_file_attrs(&app, auth_ctx.tn_id, &file_id, &auth_ctx.id_tag).await?;

	// Check permission
	let environment = Environment::new();
	let checker = app.permission_checker.read().await;

	if !checker.has_permission(&auth_ctx, action, &attrs, &environment) {
		warn!(
			subject = %auth_ctx.id_tag,
			action = action,
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

// STUB IMPLEMENTATION - Phase 3 will replace with real adapter calls
async fn load_file_attrs(
	_app: &App,
	_tn_id: TnId,
	_file_id: &str,
	_subject_id_tag: &str,
) -> ClResult<FileAttrs> {
	// TODO: Call app.meta_adapter.get_file_attrs(tn_id, file_id, subject_id_tag).await
	Ok(FileAttrs {
		file_id: "stub".into(),
		owner_id_tag: "stub_user".into(),
		mime_type: "application/octet-stream".into(),
		tags: vec![],
		visibility: "public".into(),
		access_level: crate::types::AccessLevel::Read,
	})
}
