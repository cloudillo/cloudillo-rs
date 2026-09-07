// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Access level computation for files

use crate::prelude::*;
use cloudillo_core::file_access;
use cloudillo_types::meta_adapter::FileView;
use cloudillo_types::types::AccessLevel;

/// Compute access_level (Read/Write) for each file in the list.
///
/// Visibility filtering is already handled at the SQL level via
/// `ListFileOptions::visible_levels`, so this function only determines
/// the subject's read/write access for each file.
///
/// `floor_access` provides a minimum access level inherited from a parent
/// directory share. When set, each file's effective access is the maximum of
/// its individually computed level and this floor.
pub async fn compute_file_access_levels(
	app: &App,
	tn_id: TnId,
	ctx: &file_access::FileAccessCtx<'_>,
	floor_access: Option<AccessLevel>,
	files: Vec<FileView>,
) -> ClResult<Vec<FileView>> {
	if files.is_empty() {
		return Ok(files);
	}

	// For anonymous users, access_level is Read for all files
	if ctx.user_id_tag.is_empty() {
		return Ok(files
			.into_iter()
			.map(|mut file| {
				file.access_level = Some(AccessLevel::Read);
				file
			})
			.collect());
	}

	// For authenticated users, compute access level for each file
	let mut result = Vec::with_capacity(files.len());
	for mut file in files {
		let file_ref = file_access::FileRef::from_view(&file, ctx.tenant_id_tag);

		// Cross-context row: the owner lives on a different tenant. Source
		// authority is the origin server, not us; the FSHR-fallback path in
		// `get_access_level` would return stale data after a downgrade. Use
		// the value persisted in `file_user_data` by `refresh_file` (and by
		// FSHR on_accept) instead.
		//
		// Cache miss fallback: rows from before the v30 backfill, or rows
		// whose FSHR didn't match the migration's filter, leave the column
		// NULL. Returning `None` there would erase the eye badge until the
		// user manually triggered a refresh. Fall back to the legacy
		// `get_access_level` path (best-effort: stale after a downgrade,
		// but better than no badge). The fallback runs once per row until
		// `refresh_file` populates the cache; that's still cheaper than the
		// pre-cache behaviour in the common case.
		// Provenance, not authority: a row is cross-context when its canonical copy lives
		// elsewhere. The owner may well be a local member on a community tenant.
		let is_cross_context = file_ref.upstream_id_tag.is_some();
		let access_level = if is_cross_context {
			match file.user_data.as_ref().and_then(|u| u.access_level) {
				Some(lv) => lv,
				None => {
					file_access::get_access_level(app, tn_id, file_ref, ctx, floor_access).await
				}
			}
		} else {
			file_access::get_access_level(app, tn_id, file_ref, ctx, floor_access).await
		};

		let effective = match floor_access {
			Some(floor) => floor.max(access_level),
			None => access_level,
		};

		file.access_level = Some(effective);
		result.push(file);
	}

	Ok(result)
}

// vim: ts=4
