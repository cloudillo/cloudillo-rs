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
		let owner_tag = file
			.owner
			.as_ref()
			.and_then(|o| if o.id_tag.is_empty() { None } else { Some(o.id_tag.as_ref()) })
			.unwrap_or(ctx.tenant_id_tag);

		let access_level =
			file_access::get_access_level(app, tn_id, &file.file_id, owner_tag, ctx, floor_access)
				.await;

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
