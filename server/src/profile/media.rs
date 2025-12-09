//! Profile image/media handlers

use async_trait::async_trait;
use axum::{body::Bytes, extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use crate::{
	core::{
		extract::Auth,
		scheduler::{Task, TaskId},
	},
	error::Error,
	file::{image, preset},
	meta_adapter,
	prelude::*,
	types::Patch,
	types::TnId,
};

/// Image type for tenant profile updates
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TenantImageType {
	ProfilePic,
	CoverPic,
}

/// Task to update tenant profile/cover image after file ID is generated
#[derive(Debug, Serialize, Deserialize)]
pub struct TenantImageUpdaterTask {
	tn_id: TnId,
	f_id: u64,
	image_type: TenantImageType,
}

impl TenantImageUpdaterTask {
	pub fn new(tn_id: TnId, f_id: u64, image_type: TenantImageType) -> Arc<Self> {
		Arc::new(Self { tn_id, f_id, image_type })
	}
}

#[async_trait]
impl Task<App> for TenantImageUpdaterTask {
	fn kind() -> &'static str {
		"tenant.image-update"
	}
	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		let task: TenantImageUpdaterTask = serde_json::from_str(ctx)
			.map_err(|_| Error::Internal("invalid TenantImageUpdaterTask context".into()))?;
		Ok(Arc::new(task))
	}

	fn serialize(&self) -> String {
		serde_json::to_string(self).unwrap_or_default()
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		// Get the generated file_id
		let file_id = app.meta_adapter.get_file_id(self.tn_id, self.f_id).await?;

		// Update tenant with the final file_id
		let update = match self.image_type {
			TenantImageType::ProfilePic => meta_adapter::UpdateTenantData {
				profile_pic: Patch::Value(file_id.to_string()),
				..Default::default()
			},
			TenantImageType::CoverPic => meta_adapter::UpdateTenantData {
				cover_pic: Patch::Value(file_id.to_string()),
				..Default::default()
			},
		};

		app.meta_adapter.update_tenant(self.tn_id, &update).await?;

		info!("Updated tenant {} {:?} to {}", self.tn_id, self.image_type, file_id);
		Ok(())
	}
}

/// PUT /me/image - Upload profile picture
pub async fn put_profile_image(
	State(app): State<App>,
	Auth(auth): Auth,
	body: Bytes,
) -> ClResult<(StatusCode, Json<serde_json::Value>)> {
	// Get image data directly from body
	let image_data = body.to_vec();

	if image_data.is_empty() {
		return Err(Error::ValidationError("No image data provided".into()));
	}

	// Detect content type from image data
	let content_type = image::detect_image_type(&image_data)
		.ok_or_else(|| Error::ValidationError("Invalid or unsupported image format".into()))?;

	// Get image dimensions
	let dim = image::get_image_dimensions(&image_data).await?;
	info!("Profile image dimensions: {}x{}", dim.0, dim.1);

	// Get preset for profile pictures
	let preset = preset::presets::profile_picture();

	// Create file metadata
	let f_id = app
		.meta_adapter
		.create_file(
			auth.tn_id,
			meta_adapter::CreateFile {
				preset: Some("profile-picture".into()),
				orig_variant_id: None, // Will be set by generate_image_variants
				file_id: None,
				parent_id: None,
				owner_tag: Some(auth.id_tag.as_ref().into()),
				content_type: content_type.into(),
				file_name: format!("{}-profile-pic.jpg", auth.id_tag).into(),
				file_tp: Some("BLOB".into()),
				created_at: None,
				tags: Some(vec!["profile".into()]),
				x: Some(json!({ "dim": dim })),
				visibility: Some('P'), // Profile pics are always public
				status: None,
			},
		)
		.await?;

	// Extract numeric f_id
	let f_id = match f_id {
		meta_adapter::FileId::FId(fid) => fid,
		meta_adapter::FileId::FileId(fid) => {
			// Already has a file_id (duplicate), use it directly
			app.meta_adapter
				.update_tenant(
					auth.tn_id,
					&meta_adapter::UpdateTenantData {
						profile_pic: Patch::Value(fid.to_string()),
						..Default::default()
					},
				)
				.await?;
			info!("User {} uploaded profile image (existing): {}", auth.id_tag, fid);
			return Ok((
				StatusCode::OK,
				Json(json!({
					"fileId": fid,
					"type": "profile-pic"
				})),
			));
		}
	};

	// Generate image variants using the helper function
	let result =
		image::generate_image_variants(&app, auth.tn_id, f_id, &image_data, &preset).await?;

	// Schedule TenantImageUpdaterTask to update tenant profile_pic after file_id is generated
	app.scheduler
		.task(TenantImageUpdaterTask::new(auth.tn_id, f_id, TenantImageType::ProfilePic))
		.depend_on(vec![result.file_id_task])
		.schedule()
		.await?;

	// Return pending file_id (prefixed with @)
	let pending_file_id = format!("@{}", f_id);

	info!("User {} uploaded profile image: {}", auth.id_tag, pending_file_id);

	Ok((
		StatusCode::OK,
		Json(json!({
			"fileId": pending_file_id,
			"type": "profile-pic"
		})),
	))
}

/// PUT /me/cover - Upload cover image
pub async fn put_cover_image(
	State(app): State<App>,
	Auth(auth): Auth,
	body: Bytes,
) -> ClResult<(StatusCode, Json<serde_json::Value>)> {
	// Get image data directly from body
	let image_data = body.to_vec();

	if image_data.is_empty() {
		return Err(Error::ValidationError("No image data provided".into()));
	}

	// Detect content type from image data
	let content_type = image::detect_image_type(&image_data)
		.ok_or_else(|| Error::ValidationError("Invalid or unsupported image format".into()))?;

	// Get image dimensions
	let dim = image::get_image_dimensions(&image_data).await?;
	info!("Cover image dimensions: {}x{}", dim.0, dim.1);

	// Get preset for cover images
	let preset = preset::presets::cover();

	// Create file metadata
	let f_id = app
		.meta_adapter
		.create_file(
			auth.tn_id,
			meta_adapter::CreateFile {
				preset: Some("cover".into()),
				orig_variant_id: None, // Will be set by generate_image_variants
				file_id: None,
				parent_id: None,
				owner_tag: Some(auth.id_tag.as_ref().into()),
				content_type: content_type.into(),
				file_name: format!("{}-cover.jpg", auth.id_tag).into(),
				file_tp: Some("BLOB".into()),
				created_at: None,
				tags: Some(vec!["cover".into()]),
				x: Some(json!({ "dim": dim })),
				visibility: Some('P'), // Cover images are always public
				status: None,
			},
		)
		.await?;

	// Extract numeric f_id
	let f_id = match f_id {
		meta_adapter::FileId::FId(fid) => fid,
		meta_adapter::FileId::FileId(fid) => {
			// Already has a file_id (duplicate), use it directly
			app.meta_adapter
				.update_tenant(
					auth.tn_id,
					&meta_adapter::UpdateTenantData {
						cover_pic: Patch::Value(fid.to_string()),
						..Default::default()
					},
				)
				.await?;
			info!("User {} uploaded cover image (existing): {}", auth.id_tag, fid);
			return Ok((
				StatusCode::OK,
				Json(json!({
					"fileId": fid,
					"type": "cover"
				})),
			));
		}
	};

	// Generate image variants using the helper function
	let result =
		image::generate_image_variants(&app, auth.tn_id, f_id, &image_data, &preset).await?;

	// Schedule TenantImageUpdaterTask to update tenant cover_pic after file_id is generated
	app.scheduler
		.task(TenantImageUpdaterTask::new(auth.tn_id, f_id, TenantImageType::CoverPic))
		.depend_on(vec![result.file_id_task])
		.schedule()
		.await?;

	// Return pending file_id (prefixed with @)
	let pending_file_id = format!("@{}", f_id);

	info!("User {} uploaded cover image: {}", auth.id_tag, pending_file_id);

	Ok((
		StatusCode::OK,
		Json(json!({
			"fileId": pending_file_id,
			"type": "cover"
		})),
	))
}

// vim: ts=4
