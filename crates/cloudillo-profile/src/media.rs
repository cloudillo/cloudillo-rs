// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Profile image/media handlers

use async_trait::async_trait;
use axum::{Json, body::Bytes, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use crate::prelude::*;
use cloudillo_core::extract::Auth;
use cloudillo_core::scheduler::{Task, TaskId};
use cloudillo_file::{image, preset};
use cloudillo_types::{auth_adapter, meta_adapter};

/// Image type for tenant profile updates
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TenantImageType {
	ProfilePic,
	CoverPic,
}

impl TenantImageType {
	/// `files.preset` value
	fn preset_name(self) -> &'static str {
		match self {
			Self::ProfilePic => "profile-picture",
			Self::CoverPic => "cover",
		}
	}

	/// Variant set to generate for this image kind
	fn preset(self) -> preset::FilePreset {
		match self {
			Self::ProfilePic => preset::presets::profile_picture(),
			Self::CoverPic => preset::presets::cover(),
		}
	}

	fn file_name(self, id_tag: &str) -> String {
		match self {
			Self::ProfilePic => format!("{}-profile-pic.jpg", id_tag),
			Self::CoverPic => format!("{}-cover.jpg", id_tag),
		}
	}

	/// `files.tags` entry
	fn tag(self) -> &'static str {
		match self {
			Self::ProfilePic => "profile",
			Self::CoverPic => "cover",
		}
	}

	/// `type` field of the JSON response
	fn response_type(self) -> &'static str {
		match self {
			Self::ProfilePic => "profile-pic",
			Self::CoverPic => "cover",
		}
	}

	fn log_label(self) -> &'static str {
		match self {
			Self::ProfilePic => "profile image",
			Self::CoverPic => "cover image",
		}
	}

	/// Whether the dedup fast path must drop the cached /api/me: only `profile_pic`
	/// is part of `ProfileBase`. `TenantImageUpdaterTask::run` invalidates for both.
	fn invalidate_me(self) -> bool {
		match self {
			Self::ProfilePic => true,
			Self::CoverPic => false,
		}
	}

	fn update_data(self, file_id: &str) -> meta_adapter::UpdateTenantData {
		match self {
			Self::ProfilePic => meta_adapter::UpdateTenantData {
				profile_pic: Patch::Value(file_id.to_string()),
				..Default::default()
			},
			Self::CoverPic => meta_adapter::UpdateTenantData {
				cover_pic: Patch::Value(file_id.to_string()),
				..Default::default()
			},
		}
	}
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

		let update = self.image_type.update_data(file_id.as_ref());

		app.meta_adapter.update_tenant(self.tn_id, &update).await?;
		// `profile_pic`/`cover_pic` just changed → drop the cached /api/me. This
		// is the point where the data truly lands (the HTTP handler only schedules
		// this task), so invalidating here covers both image types correctly.
		app.profile_me.invalidate(self.tn_id);
		// A published site caches its owner's picture, so the same write goes
		// stale there too. Cover images are not part of that copy.
		if matches!(self.image_type, TenantImageType::ProfilePic) {
			crate::reload_site_cache_after_profile_change(app, self.tn_id).await;
		}

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
	put_tenant_image(app, auth, body, TenantImageType::ProfilePic).await
}

/// PUT /me/cover - Upload cover image
pub async fn put_cover_image(
	State(app): State<App>,
	Auth(auth): Auth,
	body: Bytes,
) -> ClResult<(StatusCode, Json<serde_json::Value>)> {
	put_tenant_image(app, auth, body, TenantImageType::CoverPic).await
}

/// Shared body of the profile-picture and cover-image upload handlers.
async fn put_tenant_image(
	app: App,
	auth: auth_adapter::AuthCtx,
	body: Bytes,
	kind: TenantImageType,
) -> ClResult<(StatusCode, Json<serde_json::Value>)> {
	let image_data = body.to_vec();

	if image_data.is_empty() {
		return Err(Error::ValidationError("No image data provided".into()));
	}

	let content_type = image::detect_image_type(&image_data)
		.ok_or_else(|| Error::ValidationError("Invalid or unsupported image format".into()))?;

	let dim = image::get_image_dimensions(&image_data).await?;
	info!("Uploaded {} dimensions: {}x{}", kind.log_label(), dim.0, dim.1);

	let preset = kind.preset();

	// Route into the managed folder so the file GC can reap the previous image once
	// `tenants.profile_pic` / `tenants.cover_pic` no longer references it.
	let f_id = app
		.meta_adapter
		.create_file(
			auth.tn_id,
			meta_adapter::CreateFile {
				preset: Some(kind.preset_name().into()),
				parent_id: Some(meta_adapter::MANAGED_PARENT_ID.into()),
				creator_tag: Some(auth.id_tag.as_ref().into()),
				content_type: content_type.into(),
				file_name: kind.file_name(&auth.id_tag).into(),
				file_tp: Some("BLOB".into()),
				tags: Some(vec![kind.tag().into()]),
				x: Some(json!({ "dim": dim })),
				// Always public: guest-mode views fetch avatars without a token
				visibility: Some('P'),
				..Default::default()
			},
		)
		.await?;

	let f_id = match f_id {
		meta_adapter::FileId::FId(fid) => fid,
		meta_adapter::FileId::FileId(fid) => {
			// Unreachable with the SQLite meta adapter: it returns `FileId::FileId` only
			// from its dedup branch, which requires `orig_variant_id` — not set here.
			// Kept because `FileId` is part of the adapter trait and another adapter may dedup.
			app.meta_adapter
				.update_tenant(auth.tn_id, &kind.update_data(fid.as_ref()))
				.await?;
			if kind.invalidate_me() {
				app.profile_me.invalidate(auth.tn_id);
			}
			if matches!(kind, TenantImageType::ProfilePic) {
				crate::reload_site_cache_after_profile_change(&app, auth.tn_id).await;
			}
			info!("User {} uploaded {} (existing): {}", auth.id_tag, kind.log_label(), fid);
			return Ok((
				StatusCode::OK,
				Json(json!({
					"fileId": fid,
					"type": kind.response_type()
				})),
			));
		}
	};

	let result =
		image::generate_image_variants(&app, auth.tn_id, f_id, &image_data, &preset).await?;

	// The tenant field is written by the task, once the file_id exists
	app.scheduler
		.task(TenantImageUpdaterTask::new(auth.tn_id, f_id, kind))
		.depend_on(vec![result.file_id_task])
		.schedule()
		.await?;

	// `@` marks a pending file_id the client must resolve later
	let pending_file_id = format!("@{}", f_id);

	info!("User {} uploaded {}: {}", auth.id_tag, kind.log_label(), pending_file_id);

	Ok((
		StatusCode::OK,
		Json(json!({
			"fileId": pending_file_id,
			"type": kind.response_type()
		})),
	))
}

// vim: ts=4
