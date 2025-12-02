//! Profile image/media handlers

use async_trait::async_trait;
use axum::{body::Bytes, extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use crate::{
	blob_adapter,
	core::{
		extract::Auth,
		scheduler::{Task, TaskId},
	},
	error::Error,
	file::{descriptor, image, store},
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

	// Detect original format from content type (before content_type is moved)
	let orig_format = match content_type.as_str() {
		"image/jpeg" => "jpeg",
		"image/png" => "png",
		"image/webp" => "webp",
		"image/avif" => "avif",
		_ => "jpeg",
	};

	// Get image dimensions
	let dim = image::get_image_dimensions(&image_data).await?;
	info!("Profile image dimensions: {}x{}", dim.0, dim.1);

	// Store original blob
	let orig_variant_id = store::create_blob_buf(
		&app,
		auth.tn_id,
		&image_data,
		blob_adapter::CreateBlobOptions::default(),
	)
	.await?;

	// Create file metadata
	let f_id = app
		.meta_adapter
		.create_file(
			auth.tn_id,
			meta_adapter::CreateFile {
				preset: Some("profile-pic".into()),
				orig_variant_id: Some(orig_variant_id.clone()),
				file_id: None,
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

	// Create original variant record
	app.meta_adapter
		.create_file_variant(
			auth.tn_id,
			f_id,
			meta_adapter::FileVariant {
				variant_id: orig_variant_id.as_ref(),
				variant: "orig",
				format: orig_format,
				resolution: dim,
				size: image_data.len() as u64,
				available: true,
				duration: None,
				bitrate: None,
				page_count: None,
			},
		)
		.await?;

	// Generate and store profile variant (pf) - 80px for 2x retina at 40px display, always AVIF
	let pf_format = image::ImageFormat::Avif;
	let resized = image::resize_image(app.clone(), image_data, pf_format, (80, 80)).await?;
	let variant_id_pf = store::create_blob_buf(
		&app,
		auth.tn_id,
		&resized.bytes,
		blob_adapter::CreateBlobOptions::default(),
	)
	.await?;

	app.meta_adapter
		.create_file_variant(
			auth.tn_id,
			f_id,
			meta_adapter::FileVariant {
				variant_id: variant_id_pf.as_ref(),
				variant: "pf",
				format: pf_format.as_ref(),
				resolution: (resized.width, resized.height),
				size: resized.bytes.len() as u64,
				available: true,
				duration: None,
				bitrate: None,
				page_count: None,
			},
		)
		.await?;

	// Schedule FileIdGeneratorTask to compute file_id from variants
	let file_id_task = app
		.scheduler
		.task(descriptor::FileIdGeneratorTask::new(auth.tn_id, f_id))
		.key(format!("{},{}", auth.tn_id, f_id))
		.schedule()
		.await?;

	// Schedule TenantImageUpdaterTask to update tenant profile_pic after file_id is generated
	app.scheduler
		.task(TenantImageUpdaterTask::new(auth.tn_id, f_id, TenantImageType::ProfilePic))
		.depend_on(vec![file_id_task])
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

	// Store original blob
	let orig_variant_id = store::create_blob_buf(
		&app,
		auth.tn_id,
		&image_data,
		blob_adapter::CreateBlobOptions::default(),
	)
	.await?;

	// Create file metadata
	let f_id = app
		.meta_adapter
		.create_file(
			auth.tn_id,
			meta_adapter::CreateFile {
				preset: Some("cover".into()),
				orig_variant_id: Some(orig_variant_id.clone()),
				file_id: None,
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

	// Read format settings
	let thumbnail_format_str = app
		.settings
		.get_string(auth.tn_id, "file.thumbnail_format")
		.await
		.unwrap_or_else(|_| "webp".to_string());
	let thumbnail_format: image::ImageFormat =
		thumbnail_format_str.parse().unwrap_or(image::ImageFormat::Webp);

	let image_format_str = app
		.settings
		.get_string(auth.tn_id, "file.image_format")
		.await
		.unwrap_or_else(|_| "webp".to_string());
	let image_format: image::ImageFormat =
		image_format_str.parse().unwrap_or(image::ImageFormat::Webp);

	// Create original variant record
	app.meta_adapter
		.create_file_variant(
			auth.tn_id,
			f_id,
			meta_adapter::FileVariant {
				variant_id: orig_variant_id.as_ref(),
				variant: "orig",
				format: image_format.as_ref(),
				resolution: dim,
				size: image_data.len() as u64,
				available: true,
				duration: None,
				bitrate: None,
				page_count: None,
			},
		)
		.await?;

	// Save original to temp for variant generation tasks
	let orig_file = app.opts.tmp_dir.join::<&str>(&orig_variant_id);
	tokio::fs::write(&orig_file, &image_data).await?;

	// Generate and store thumbnail
	let resized_tn =
		image::resize_image(app.clone(), image_data, thumbnail_format, (128, 128)).await?;
	let variant_id_tn = store::create_blob_buf(
		&app,
		auth.tn_id,
		&resized_tn.bytes,
		blob_adapter::CreateBlobOptions::default(),
	)
	.await?;

	app.meta_adapter
		.create_file_variant(
			auth.tn_id,
			f_id,
			meta_adapter::FileVariant {
				variant_id: variant_id_tn.as_ref(),
				variant: "tn",
				format: thumbnail_format.as_ref(),
				resolution: (resized_tn.width, resized_tn.height),
				size: resized_tn.bytes.len() as u64,
				available: true,
				duration: None,
				bitrate: None,
				page_count: None,
			},
		)
		.await?;

	// Schedule variant generation tasks for larger sizes (hd for cover images)
	let mut variant_task_ids = Vec::new();
	let original_max = dim.0.max(dim.1) as f32;

	// Cover images need hd variant (1920px)
	if original_max > 256.0 {
		let task = image::ImageResizerTask::new(
			auth.tn_id,
			f_id,
			orig_file.clone(),
			"hd",
			image_format,
			(1920, 1920),
		);
		let task_id = app.scheduler.add(task).await?;
		variant_task_ids.push(task_id);
	}

	// Schedule FileIdGeneratorTask to compute file_id from variants
	let mut builder = app
		.scheduler
		.task(descriptor::FileIdGeneratorTask::new(auth.tn_id, f_id))
		.key(format!("{},{}", auth.tn_id, f_id));
	if !variant_task_ids.is_empty() {
		builder = builder.depend_on(variant_task_ids);
	}
	let file_id_task = builder.schedule().await?;

	// Schedule TenantImageUpdaterTask to update tenant cover_pic after file_id is generated
	app.scheduler
		.task(TenantImageUpdaterTask::new(auth.tn_id, f_id, TenantImageType::CoverPic))
		.depend_on(vec![file_id_task])
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
