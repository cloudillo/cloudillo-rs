//! FSHR (File Share) action native hooks
//!
//! Handles file sharing lifecycle:
//! - on_receive: Sets status to 'C' (confirmation required) for incoming shares
//! - on_accept: Creates file entry when user accepts the share

use crate::action::hooks::{HookContext, HookResult};
use crate::core::app::App;
use crate::meta_adapter::{CreateFile, FileStatus, UpdateActionDataOptions};
use crate::prelude::*;
use crate::types::Patch;

/// FSHR on_receive hook - Handle incoming file share request
///
/// Logic:
/// - If we are the audience and subType is not DEL, set status to 'C' (confirmation required)
/// - DEL subtype doesn't require confirmation
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	let tn_id = TnId(context.tenant_id as u32);

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
	let tn_id = TnId(context.tenant_id as u32);

	tracing::debug!(
		"Native hook: FSHR on_accept for action {} from {}",
		context.action_id,
		context.issuer
	);

	// Parse content
	let content = match &context.content {
		Some(c) => c,
		None => {
			tracing::warn!("FSHR on_accept: Missing content");
			return Ok(HookResult::default());
		}
	};

	let content_type = match content.get("contentType").and_then(|v| v.as_str()) {
		Some(ct) => ct,
		None => {
			tracing::warn!("FSHR on_accept: Missing contentType in content");
			return Ok(HookResult::default());
		}
	};

	let file_name = match content.get("fileName").and_then(|v| v.as_str()) {
		Some(fn_) => fn_,
		None => {
			tracing::warn!("FSHR on_accept: Missing fileName in content");
			return Ok(HookResult::default());
		}
	};

	let file_tp = match content.get("fileTp").and_then(|v| v.as_str()) {
		Some(ft) => ft,
		None => {
			tracing::warn!("FSHR on_accept: Missing fileTp in content");
			return Ok(HookResult::default());
		}
	};

	// Subject contains the file_id
	let file_id = match &context.subject {
		Some(s) => s,
		None => {
			tracing::warn!("FSHR on_accept: Missing subject (file_id)");
			return Ok(HookResult::default());
		}
	};

	tracing::info!(
		"FSHR: Accepting file share - creating file entry for {} from {} (type: {})",
		file_id,
		context.issuer,
		file_tp
	);

	// Create file entry with status 'A' (active) and visibility direct (most restricted - owner and tenant can see)
	let create_opts = CreateFile {
		orig_variant_id: None,
		file_id: Some(file_id.clone().into()),
		parent_id: None,
		owner_tag: Some(context.issuer.clone().into()), // Shared files: owner is the sharer
		creator_tag: None,
		preset: None,
		content_type: content_type.into(),
		file_name: file_name.into(),
		file_tp: Some(file_tp.into()),
		created_at: None,
		tags: None,
		x: None,
		visibility: None, // Direct - owner and tenant can see
		status: Some(FileStatus::Active),
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
