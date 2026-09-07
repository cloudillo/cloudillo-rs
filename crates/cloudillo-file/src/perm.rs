// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! File permission middleware for ABAC

use axum::{
	extract::{Path, Request, State, rejection::PathRejection},
	middleware::Next,
	response::Response,
};
use serde::Deserialize;

use crate::prelude::*;
use cloudillo_core::abac::Environment;
use cloudillo_core::extract::{IdTag, OptionalAuth};
use cloudillo_core::file_access;
use cloudillo_core::middleware::PermissionCheckOutput;
use cloudillo_types::auth_adapter::AuthCtx;
use cloudillo_types::types::FileAttrs;

/// The one path parameter this guard authorizes on.
///
/// Extracted by name, so trailing captures like the `{tag}` of
/// `/api/files/{file_id}/tag/{tag}` are simply ignored — `Path<T>` over a struct
/// goes through serde's map deserializer, which does not arity-check the way a
/// single-field `Path<String>` (a *sequence*) does.
#[derive(Deserialize)]
pub struct FileIdParam {
	/// `/api/files/variant/{variant_id}` captures under a different name;
	/// `load_file_attrs` below detects the `b` prefix and resolves the variant
	/// id to its file id.
	#[serde(alias = "variant_id")]
	file_id: String,
}

/// The guard's path extraction, kept fallible: a route with no accepted capture
/// gets a logged `PermissionDenied` rather than axum's bare 400 with the serde
/// message in it.
type FileIdPath = Result<Path<FileIdParam>, PathRejection>;

/// Middleware factory for file permission checks
///
/// Returns a middleware function that validates file permissions via ABAC
///
/// # Arguments
/// * `action` - The permission action to check (e.g., "read", "write")
///
/// # Returns
/// A cloneable middleware function with return type `PermissionCheckOutput`
///
/// The route must capture the file id as `{file_id}` (or `{variant_id}`) — the
/// guard reads it by name, not by position. Other captures are ignored.
pub fn check_perm_file(
	action: &'static str,
) -> impl Fn(State<App>, IdTag, TnId, OptionalAuth, FileIdPath, Request, Next) -> PermissionCheckOutput
+ Clone {
	move |state, id_tag, tn_id, auth, params, req, next| {
		Box::pin(check_file_permission(state, id_tag, tn_id, auth, params, req, next, action))
	}
}

#[expect(clippy::too_many_arguments, reason = "permission check requires all context fields")]
async fn check_file_permission(
	State(app): State<App>,
	IdTag(tenant_id_tag): IdTag,
	tn_id: TnId,
	OptionalAuth(maybe_auth_ctx): OptionalAuth,
	params: FileIdPath,
	req: Request,
	next: Next,
	action: &str,
) -> Result<Response, Error> {
	use tracing::warn;

	let Ok(Path(FileIdParam { file_id })) = params else {
		warn!("File permission guard on a route with no {{file_id}} capture");
		return Err(Error::PermissionDenied);
	};

	// Create auth context or guest context if not authenticated
	let (auth_ctx, subject_id_tag) = if let Some(auth_ctx) = maybe_auth_ctx {
		let id_tag = auth_ctx.id_tag.clone();
		(auth_ctx, id_tag)
	} else {
		// For unauthenticated requests, create a guest context
		let guest_ctx = AuthCtx {
			tn_id,
			id_tag: "guest".into(),
			roles: vec![].into(),
			scope: None,
			anonymous: true,
		};
		(guest_ctx, "guest".into())
	};

	// Load file attributes (pass scope from auth context for scoped token access)
	let attrs = load_file_attrs(
		&app,
		tn_id,
		&file_id,
		&subject_id_tag,
		&tenant_id_tag,
		&auth_ctx.roles,
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
	subject_roles: &[Box<str>],
	scope: Option<&str>,
) -> ClResult<FileAttrs> {
	use cloudillo_core::abac::{self, VisibilityLevel};
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

	// Resolves both ownership facts off the row: an absent owner means the tenant owns it, an
	// absent upstream means it originates here (which is what gates role access in `file_access`).
	let file_ref = file_access::FileRef::from_view(&file_view, tenant_id_tag);
	debug!("File access for {}: owner {}", file_id, file_ref.owner_id_tag);

	// Determine access level by looking up scoped tokens, FSHR action grants
	let ctx = file_access::FileAccessCtx {
		user_id_tag: subject_id_tag,
		tenant_id_tag,
		user_roles: subject_roles,
	};
	let access_level = file_access::get_access_level_with_scope(
		app,
		tn_id,
		file_ref,
		&ctx,
		scope,
		file_view.root_id.as_deref(),
	)
	.await;

	// Get visibility from file metadata - convert char to string representation
	let vis_level = VisibilityLevel::from_char(file_view.visibility);
	let visibility: Box<str> = vis_level.as_str().into();

	// Owned before the borrow of the row ends, so `FileAttrs` can take it.
	let owner_id_tag: Box<str> = file_ref.owner_id_tag.into();

	// The subject's relationship **to the tenant**: `follower` is "they follow us", which is
	// what the visibility rules mean. (`following` is the opposite direction.) Only the
	// SecondDegree/Follower/Connected rungs consult it, and ABAC's read branch returns on
	// `can_read()` first — same guard `apkg.rs` and `check_file_access_with_scope` apply.
	let rel = if !access_level.can_read() && abac::visibility_needs_relation(vis_level) {
		abac::subject_relation_to_tenant(app, tn_id, subject_id_tag).await?
	} else {
		cloudillo_types::meta_adapter::ProfileRelation::default()
	};

	Ok(FileAttrs {
		file_id: file_view.file_id,
		owner_id_tag,
		upstream_id_tag: file_view.upstream_tag,
		mime_type: file_view.content_type.unwrap_or_else(|| "application/octet-stream".into()),
		tags: file_view.tags.unwrap_or_default(),
		visibility,
		access_level,
		is_follower: rel.follower,
		connected: rel.connected,
	})
}

#[cfg(test)]
mod tests {
	use cloudillo_core::abac::{Environment, PermissionChecker};
	use cloudillo_types::auth_adapter::AuthCtx;
	use cloudillo_types::types::{AccessLevel, FileAttrs, TnId};

	/// The shape a *mirrored* row produces once `load_file_attrs` resolves it: `owner_id_tag` is
	/// the local placer (or, for an accepted FSHR share on a personal tenant, the tenant itself),
	/// while `access_level` stays at whatever `file_access` allowed — never `Admin`, because its
	/// owner shortcut is gated on `upstream_id_tag.is_none()`.
	fn mirrored_attrs() -> FileAttrs {
		FileAttrs {
			file_id: "f1~mirror".into(),
			owner_id_tag: "alice.example.com".into(),
			upstream_id_tag: Some("carol.example.com".into()),
			mime_type: "text/plain".into(),
			tags: vec![],
			visibility: "direct".into(),
			access_level: AccessLevel::Read,
			is_follower: false,
			connected: false,
		}
	}

	fn subject(id_tag: &str, scope: Option<&str>) -> AuthCtx {
		AuthCtx {
			tn_id: TnId(1),
			id_tag: id_tag.into(),
			roles: Box::new([]),
			scope: scope.map(Box::from),
			anonymous: scope.is_some(),
		}
	}

	/// Pins the split between ABAC and `file_access`: ABAC's ownership branch is not
	/// upstream-gated, so the owner of a mirrored row keeps *record* authority — rename, move,
	/// hide, soft-delete, tag — even at `AccessLevel::Read`. Content and share management are
	/// decided elsewhere (`file_access`, `share_access`) and stay denied there.
	///
	/// Deliberate, not incidental: changing it is what would strip a placer of the ability to
	/// remove their own pin.
	#[test]
	fn mirrored_row_owner_keeps_record_authority() {
		let checker = PermissionChecker::new();
		let env = Environment::new();
		let attrs = mirrored_attrs();
		let alice = subject("alice.example.com", None);

		assert!(checker.has_permission(&alice, "file:update", &attrs, &env));
		assert!(checker.has_permission(&alice, "file:delete", &attrs, &env));
		assert!(checker.has_permission(&alice, "file:write", &attrs, &env));

		// A delegated (share-link / API-key scoped) caller is judged on `access_level` alone —
		// a share-link token is minted `sub: None`, so its `id_tag` is the tenant's and would
		// otherwise walk straight through the ownership branch.
		let scoped = subject("alice.example.com", Some("file:f1~mirror:R"));
		assert!(!checker.has_permission(&scoped, "file:update", &attrs, &env));
		assert!(!checker.has_permission(&scoped, "file:delete", &attrs, &env));
		assert!(!checker.has_permission(&scoped, "file:write", &attrs, &env));

		// Someone else at the same Read level gets nothing.
		assert!(!checker.has_permission(
			&subject("bob.example.com", None),
			"file:update",
			&attrs,
			&env
		));
	}

	/// The other half of the split: record authority is *not* content authority. A revoked
	/// FSHR share drops `access_level` to `None` but deliberately leaves the recipient's
	/// mirrored row in place so they can still delete their own copy — so if ABAC's read path
	/// honoured `owner_id_tag` on a mirrored row, revocation would never take effect.
	#[test]
	fn mirrored_row_owner_gets_no_read_on_a_revoked_share() {
		let checker = PermissionChecker::new();
		let env = Environment::new();
		let alice = subject("alice.example.com", None);

		let mut revoked = mirrored_attrs();
		revoked.access_level = AccessLevel::None;
		assert!(!checker.has_permission(&alice, "file:read", &revoked, &env));

		// Record authority survives revocation — Alice can still remove her own copy.
		assert!(checker.has_permission(&alice, "file:update", &revoked, &env));
		assert!(checker.has_permission(&alice, "file:delete", &revoked, &env));

		// A locally-originating row (no upstream) still reads via ownership.
		let mut local = mirrored_attrs();
		local.access_level = AccessLevel::None;
		local.upstream_id_tag = None;
		assert!(checker.has_permission(&alice, "file:read", &local, &env));
	}
}

// vim: ts=4
