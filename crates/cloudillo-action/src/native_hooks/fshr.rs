// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! FSHR (File Share) action native hooks
//!
//! Handles file sharing lifecycle:
//! - on_receive: Sets status to 'C' (confirmation required) for incoming shares
//! - on_accept: Creates file entry when user accepts the share

use crate::hooks::{HookContext, HookResult};
use crate::prelude::*;
use cloudillo_types::meta_adapter::{
	CreateFile, CreateShareEntry, FileStatus, UpdateActionDataOptions,
};

/// FSHR on_create hook - Create share_entry on the sender's side
///
/// When a user shares a file/directory via the action API, this hook ensures
/// the corresponding share_entry is created so that the recipient can access
/// the shared content. For DEL subtype, removes the share_entry instead.
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

	if context.subtype.as_deref() == Some("DEL") {
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

	let permission = match context.subtype.as_deref() {
		Some("WRITE") => 'W',
		Some("COMMENT") => 'C',
		_ => 'R',
	};

	let entry = CreateShareEntry {
		subject_type: 'U',
		subject_id: audience.clone(),
		permission,
		expires_at: None,
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
/// - If we are the audience and subType is not DEL, set status to 'C' (confirmation required)
/// - DEL subtype doesn't require confirmation
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	let tn_id = context.tn_id;

	tracing::debug!(
		"Native hook: FSHR on_receive for action {} from {} to {:?}",
		context.action_id,
		context.issuer,
		context.audience
	);

	// Check if we are the audience
	let is_audience = context.audience.as_ref() == Some(&context.tenant_tag);

	// Only require confirmation for non-DEL subtypes when we are the audience
	if is_audience && context.subtype.as_deref() != Some("DEL") {
		tracing::info!(
			"FSHR: Received file share from {} - setting status to confirmation required",
			context.issuer
		);

		let update_opts =
			UpdateActionDataOptions { status: Patch::Value('C'), ..Default::default() };

		if let Err(e) = app
			.meta_adapter
			.update_action_data(tn_id, &context.action_id, &update_opts)
			.await
		{
			tracing::warn!("FSHR: Failed to update action status to 'C': {}", e);
		}
	}

	Ok(HookResult::default())
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
		}
		Err(e) => {
			tracing::error!("FSHR: Failed to create file entry: {}", e);
			return Err(e);
		}
	}

	Ok(HookResult::default())
}

// vim: ts=4
