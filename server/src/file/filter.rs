//! Visibility filtering for files

use crate::{
	core::abac::can_view_item, core::file_access, meta_adapter::FileView, prelude::*,
	types::AccessLevel,
};

/// Filter files by visibility and compute access_level for each file
///
/// This function filters a list of files to only include those the subject
/// is allowed to see based on:
/// - The file's visibility level
/// - The subject's relationship with the owner (following/connected)
///
/// For each visible file, it also computes the user's access level (Read/Write).
pub async fn filter_files_by_visibility(
	app: &App,
	tn_id: TnId,
	subject_id_tag: &str,
	is_authenticated: bool,
	tenant_id_tag: &str,
	subject_roles: &[Box<str>],
	files: Vec<FileView>,
) -> ClResult<Vec<FileView>> {
	// If no files, return early
	if files.is_empty() {
		return Ok(files);
	}

	// Look up subject's relationship with the tenant (the only relationship we can check)
	let rels = app.meta_adapter.get_relationships(tn_id, &[subject_id_tag]).await?;
	let (following, connected) = rels.get(subject_id_tag).copied().unwrap_or((false, false));

	// Filter files based on visibility
	let visible_files: Vec<FileView> = files
		.into_iter()
		.filter(|file| {
			// Get owner id_tag, filtering out empty strings (from failed profile JOINs)
			let owner_tag = file
				.owner
				.as_ref()
				.and_then(|o| if o.id_tag.is_empty() { None } else { Some(o.id_tag.as_ref()) })
				.unwrap_or(tenant_id_tag);

			// Files don't have audience, so pass None
			can_view_item(
				subject_id_tag,
				is_authenticated,
				owner_tag,
				tenant_id_tag,
				file.visibility,
				following,
				connected,
				None,
			)
		})
		.collect();

	// For anonymous users, access_level is Read for all visible files
	if !is_authenticated || subject_id_tag.is_empty() {
		return Ok(visible_files
			.into_iter()
			.map(|mut file| {
				file.access_level = Some(AccessLevel::Read);
				file
			})
			.collect());
	}

	// For authenticated users, compute access level for each file
	let mut result = Vec::with_capacity(visible_files.len());
	for mut file in visible_files {
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
