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
pub async fn compute_file_access_levels(
	app: &App,
	tn_id: TnId,
	subject_id_tag: &str,
	is_authenticated: bool,
	tenant_id_tag: &str,
	subject_roles: &[Box<str>],
	files: Vec<FileView>,
) -> ClResult<Vec<FileView>> {
	if files.is_empty() {
		return Ok(files);
	}

	// For anonymous users, access_level is Read for all files
	if !is_authenticated || subject_id_tag.is_empty() {
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
		// Get owner id_tag, filtering out empty strings (from failed profile JOINs)
		let owner_tag = file
			.owner
			.as_ref()
			.and_then(|o| if o.id_tag.is_empty() { None } else { Some(o.id_tag.as_ref()) })
			.unwrap_or(tenant_id_tag);

		let ctx = file_access::FileAccessCtx {
			user_id_tag: subject_id_tag,
			tenant_id_tag,
			user_roles: subject_roles,
		};
		let access_level =
			file_access::get_access_level(app, tn_id, &file.file_id, owner_tag, &ctx).await;

		file.access_level = Some(access_level);
		result.push(file);
	}

	Ok(result)
}

// vim: ts=4
