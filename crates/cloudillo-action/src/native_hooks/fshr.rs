// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! FSHR (File Share) action native hooks
//!
//! Handles file sharing lifecycle:
//! - on_receive: Sets status to 'C' (confirmation required) for incoming shares
//! - on_accept: Creates file entry when user accepts the share

use crate::hooks::{HookContext, HookResult};
use crate::prelude::*;
use cloudillo_core::share_access::{
	ShareStanding, ensure_grant_within, ensure_standing, share_standing_for_actor,
};
use cloudillo_types::meta_adapter::{CreateFile, CreateShareEntry, FileStatus};
use cloudillo_types::types::AccessLevel;

/// Map an FSHR sub-type to the `share_entries` / `file_user_data` permission char.
///
/// Both sides of the federation go through it — the sender's `on_create` share entry and the
/// recipient's `on_accept` cached badge — so a sub-type can never mean two different things.
/// `"DEL"` is handled by the callers before this point.
fn perm_char_for_sub_typ(sub_typ: Option<&str>) -> char {
	match sub_typ {
		Some("ADMIN") => 'A',
		Some("WRITE") => 'W',
		Some("COMMENT") => 'C',
		_ => 'R',
	}
}

/// A grantee dropping their own grant needs no standing over the file — revoking access one holds
/// is never an escalation.
fn is_self_revocation(issuer: &str, audience: &str) -> bool {
	issuer == audience
}

/// Gate an FSHR-driven `share_entries` write against the subject file, exactly as
/// `POST /api/files/{id}/shares` gates the direct write.
///
/// The hook is the *second* door to `share_entries`. `POST /api/actions` is gated only by
/// `check_perm_create("action", "create")`, which asks for the `contributor` role and nothing about
/// the file named in `subject`, so without this any member could emit an FSHR naming someone else's
/// file and — the adapter's upsert being create-or-overwrite — grant themselves `'A'` on it, or
/// drop another user's grant via `DEL`.
///
/// `permission` is `Some` only for granting sub-types; a revocation hands out nothing, so it needs
/// manager standing but no grant ceiling.
async fn authorize_share_change(
	app: &App,
	context: &HookContext,
	resource_id: &str,
	permission: Option<char>,
) -> ClResult<()> {
	let authority = share_standing_for_actor(
		app,
		context.tn_id,
		resource_id,
		&context.issuer,
		&context.tenant_tag,
	)
	.await?;
	ensure_standing(authority.standing, ShareStanding::Manager, &context.issuer, resource_id)?;
	if let Some(permission) = permission {
		ensure_grant_within(
			AccessLevel::from_perm_char(permission),
			authority.grant_ceiling,
			&context.issuer,
			resource_id,
		)?;
	}
	Ok(())
}

/// FSHR on_create hook - Create share_entry on the sender's side
///
/// When a user shares a file/directory via the action API, this hook ensures
/// the corresponding share_entry is created so that the recipient can access
/// the shared content. For DEL subtype, removes the share_entry instead.
///
/// Every write here passes [`authorize_share_change`] first — defence in depth for the legitimate
/// emitters (`cloudillo_file::share::create_share` / `delete_share`), which already cleared
/// `require_share_manager`. Hooks run post-store with no rollback, so a denial deletes the offending
/// action row explicitly: leaving it stored would keep it visible to listings, federation relay and
/// future hooks even though it grants nothing. `cloudillo_core::file_access::fshr_grant_level`
/// honouring an FSHR row solely when its issuer owns the file remains as defence in depth, covering
/// the window before the delete and any row that predates this check.
pub async fn on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	let tn_id = context.tn_id;

	let Some(ref resource_id) = context.subject else {
		tracing::warn!("FSHR on_create: Missing subject (file_id)");
		return Ok(HookResult::default());
	};

	let Some(ref audience) = context.audience else {
		tracing::warn!("FSHR on_create: Missing audience");
		return Ok(HookResult::default());
	};

	let is_del = context.subtype.as_deref() == Some("DEL");
	let permission = perm_char_for_sub_typ(context.subtype.as_deref());

	if !(is_del && is_self_revocation(&context.issuer, audience))
		&& let Err(e) =
			authorize_share_change(&app, &context, resource_id, (!is_del).then_some(permission))
				.await
	{
		tracing::warn!(
			issuer = %context.issuer,
			subject = %resource_id,
			sub_typ = ?context.subtype,
			audience = %audience,
			"FSHR on_create denied: issuer may not manage this file's share set"
		);
		// Best effort: a failed cleanup must never turn a denial into a success, so the original
		// error is returned either way.
		if let Err(del_err) = app.meta_adapter.delete_action(tn_id, &context.action_id).await {
			tracing::warn!(
				action_id = %context.action_id,
				error = %del_err,
				"FSHR on_create: failed to remove the denied action row; it grants nothing \
				 (file_access::fshr_grant_level requires the issuer to own the file) but will \
				 remain visible until the next cleanup"
			);
		} else {
			cloudillo_core::search_index_action(&app, tn_id, &context.action_id);
		}
		return Err(e);
	}

	if is_del {
		// Remove the share entry
		let entries = app.meta_adapter.list_share_entries(tn_id, 'F', resource_id).await?;
		for entry in entries {
			if entry.subject_type == 'U' && entry.subject_id.as_ref() == audience.as_str() {
				app.meta_adapter.delete_share_entry(tn_id, entry.id).await?;
				tracing::info!(
					"FSHR on_create: Deleted share entry for {} on {}",
					audience,
					resource_id
				);
			}
		}
		return Ok(HookResult::default());
	}

	// The action carries no `expiresAt`, and the adapter's upsert assigns `expires_at =
	// excluded.expires_at` — so read the existing row first, or a re-emitted FSHR quietly turns an
	// expiring grant into a permanent one.
	let existing = app
		.meta_adapter
		.list_share_entries(tn_id, 'F', resource_id)
		.await?
		.into_iter()
		.find(|e| e.subject_type == 'U' && e.subject_id.as_ref() == audience.as_str());

	if let Some(ref entry) = existing
		&& entry.permission == permission
	{
		// `create_share` already stored exactly this grant. Skipping the upsert also preserves
		// `created_by`, which the hook would otherwise rewrite to the issuer.
		return Ok(HookResult::default());
	}

	let entry = CreateShareEntry {
		subject_type: 'U',
		subject_id: audience.clone(),
		permission,
		expires_at: existing.and_then(|e| e.expires_at),
	};

	match app
		.meta_adapter
		.create_share_entry(tn_id, 'F', resource_id, &context.issuer, &entry)
		.await
	{
		Ok(_) => {
			tracing::info!(
				"FSHR on_create: Created share entry for {} on {} (perm={})",
				audience,
				resource_id,
				permission
			);
		}
		Err(e) => {
			tracing::warn!("FSHR on_create: Failed to create share entry: {}", e);
			return Err(e);
		}
	}

	Ok(HookResult::default())
}

/// FSHR on_receive hook - Handle incoming file share request
///
/// Logic:
/// - Refuse a share whose subject file we already hold under a different owner
/// - If we are the audience and subType is not DEL, set status to 'C' (confirmation required)
/// - DEL subtype doesn't require confirmation
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	tracing::debug!(
		"Native hook: FSHR on_receive for action {} from {} to {:?}",
		context.action_id,
		context.issuer,
		context.audience
	);

	// A missing row is the ordinary case — `on_accept` creates it. A row owned by someone other
	// than the issuer means the sender is claiming authority over content that is not theirs;
	// refuse outright rather than leaning on `file_access`'s issuer check, so no junk row lands.
	if let Some(file_id) = &context.subject
		&& let Ok(Some(file)) = app.meta_adapter.read_file(context.tn_id, file_id).await
	{
		// Same fallback `file_access::check_file_access_with_scope` uses — no explicit owner means
		// the tenant owns the row. The two must agree or one gate contradicts the other.
		let owner = file
			.owner
			.as_ref()
			.map(|p| p.id_tag.as_ref())
			.filter(|s| !s.is_empty())
			.unwrap_or(context.tenant_tag.as_str());
		if owner != context.issuer {
			tracing::warn!(
				issuer = %context.issuer,
				subject = %file_id,
				owner = %owner,
				"FSHR on_receive refused: issuer does not own the subject file"
			);
			return Err(Error::PermissionDenied);
		}
	}

	// Check if we are the audience
	let is_audience = context.audience.as_ref() == Some(&context.tenant_tag);

	// Only require confirmation for non-DEL subtypes when we are the audience.
	// The resting status is declared here and written once by the post-store
	// pipeline (process.rs); otherwise the action rests at 'A' (default).
	let status: Option<char> = if is_audience && context.subtype.as_deref() != Some("DEL") {
		tracing::info!(
			"FSHR: Received file share from {} - setting status to confirmation required",
			context.issuer
		);
		Some('C')
	} else {
		None
	};

	Ok(HookResult { status, ..Default::default() })
}

/// FSHR on_accept hook - Create file entry when user accepts the share
///
/// Logic:
/// - Parse content to get fileName and contentType
/// - Create file entry with status 'M' (mutable/shared) and owner_tag from issuer
pub async fn on_accept(app: App, context: HookContext) -> ClResult<HookResult> {
	let tn_id = context.tn_id;

	tracing::debug!(
		"Native hook: FSHR on_accept for action {} from {}",
		context.action_id,
		context.issuer
	);

	// Parse content
	let Some(content) = &context.content else {
		tracing::warn!("FSHR on_accept: Missing content");
		return Ok(HookResult::default());
	};

	let Some(content_type) = content.get("contentType").and_then(|v| v.as_str()) else {
		tracing::warn!("FSHR on_accept: Missing contentType in content");
		return Ok(HookResult::default());
	};

	let Some(file_name) = content.get("fileName").and_then(|v| v.as_str()) else {
		tracing::warn!("FSHR on_accept: Missing fileName in content");
		return Ok(HookResult::default());
	};

	let Some(file_tp) = content.get("fileTp").and_then(|v| v.as_str()) else {
		tracing::warn!("FSHR on_accept: Missing fileTp in content");
		return Ok(HookResult::default());
	};

	// Subject contains the file_id
	let Some(file_id) = &context.subject else {
		tracing::warn!("FSHR on_accept: Missing subject (file_id)");
		return Ok(HookResult::default());
	};

	tracing::info!(
		"FSHR: Accepting file share - creating file entry for {} from {} (type: {})",
		file_id,
		context.issuer,
		file_tp
	);

	// Create file entry with status 'A' (active) and visibility direct (most restricted - owner and tenant can see)
	let create_opts = CreateFile {
		file_id: Some(file_id.clone().into()),
		owner_tag: Some(context.issuer.clone().into()), // Shared files: owner is the sharer
		content_type: content_type.into(),
		file_name: file_name.into(),
		file_tp: Some(file_tp.into()),
		status: Some(FileStatus::Active),
		..Default::default()
	};

	match app.meta_adapter.create_file(tn_id, create_opts).await {
		Ok(file_result) => {
			tracing::info!("FSHR: Created shared file entry: {:?}", file_result);
			cloudillo_core::search_index_file(&app, tn_id, file_id);
		}
		Err(e) => {
			tracing::error!("FSHR: Failed to create file entry: {}", e);
			return Err(e);
		}
	}

	// Seed the recipient's cached access_level so the badge appears on first list without a refresh
	// round-trip; matches what `refresh_file` writes on subsequent reconciliations.
	let access_perm = perm_char_for_sub_typ(context.subtype.as_deref());
	if let Err(e) = app
		.meta_adapter
		.update_file_user_data(
			tn_id,
			&context.tenant_tag,
			file_id,
			Patch::Undefined,
			Patch::Undefined,
			Patch::Value(access_perm),
		)
		.await
	{
		tracing::warn!(
			"FSHR on_accept: failed to seed cached access_level on file_user_data: {}",
			e
		);
	}

	Ok(HookResult::default())
}

/// Only the pure decisions — everything else here needs a whole `App`. The resource-level half is
/// tested in `cloudillo_core::share_access`, and `on_receive`'s owner guard has its companion check
/// tested as `cloudillo_core::file_access::fshr_grant_level`.
#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn perm_char_agrees_with_the_access_level_vocabulary() {
		// `authorize_share_change` caps the grant by converting the char straight back, so a
		// sub-type disagreeing with `AccessLevel` would be capped as a different level than it
		// stores.
		for (sub_typ, level) in [
			("ADMIN", AccessLevel::Admin),
			("WRITE", AccessLevel::Write),
			("COMMENT", AccessLevel::Comment),
		] {
			let c = perm_char_for_sub_typ(Some(sub_typ));
			assert_eq!(Some(c), level.to_perm_char(), "{sub_typ} must map to {level:?}");
			assert_eq!(AccessLevel::from_perm_char(c), level);
		}

		// Unknown and absent sub-types fall back to read, so an unrecognized vocabulary word can
		// never over-grant.
		for sub_typ in [None, Some("READ"), Some("write"), Some("")] {
			assert_eq!(perm_char_for_sub_typ(sub_typ), 'R');
		}
		assert_eq!(AccessLevel::Read.to_perm_char(), Some('R'));
	}

	#[test]
	fn self_revocation_is_the_only_ungated_del() {
		// A grantee dropping their own grant needs no standing; dropping anyone else's is share
		// management and goes through `authorize_share_change`.
		assert!(is_self_revocation("bob.example.com", "bob.example.com"));
		assert!(!is_self_revocation("bob.example.com", "alice.example.com"));
		// Exact match only — no prefix/suffix relationship counts.
		assert!(!is_self_revocation("bob.example.com", "sub.bob.example.com"));
		assert!(!is_self_revocation("", "alice.example.com"));
	}
}

// vim: ts=4
