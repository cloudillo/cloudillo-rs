//! Profile image/media handlers

use axum::{
	extract::{Multipart, State},
	http::StatusCode,
	Json,
};
use serde_json::json;

use crate::{
	core::{extract::Auth, hasher},
	error::Error,
	file::image,
	meta_adapter,
	prelude::*,
};

/// PUT /me/image - Upload profile picture
pub async fn put_profile_image(
	State(app): State<App>,
	Auth(auth): Auth,
	mut multipart: Multipart,
) -> ClResult<(StatusCode, Json<serde_json::Value>)> {
	// Extract image from multipart
	let mut image_data = Vec::new();
	let mut content_type = String::new();

	while let Some(field) = multipart
		.next_field()
		.await
		.map_err(|_| Error::NetworkError("multipart error".into()))?
	{
		if field.name() == Some("image") {
			content_type = field.content_type().unwrap_or("image/jpeg").to_string();
			image_data = field
				.bytes()
				.await
				.map_err(|_| Error::NetworkError("failed to read field bytes".into()))?
				.to_vec();
			break;
		}
	}

	if image_data.is_empty() {
		return Err(Error::ValidationError("No image data provided".into()));
	}

	// Validate content type
	if !matches!(content_type.as_str(), "image/jpeg" | "image/png" | "image/webp" | "image/avif") {
		return Err(Error::ValidationError("Invalid image content type".into()));
	}

	// Hash image to get blob ID
	let orig_variant_id = hasher::hash("b", &image_data);

	// Get image dimensions
	let dim = image::get_image_dimensions(&image_data).await?;
	info!("Profile image dimensions: {}x{}", dim.0, dim.1);

	// Create file metadata
	let f_id = app
		.meta_adapter
		.create_file(
			auth.tn_id,
			meta_adapter::CreateFile {
				preset: "profile-pic".into(),
				orig_variant_id,
				file_id: None,
				owner_tag: Some(auth.id_tag.as_ref().into()),
				content_type: content_type.into(),
				file_name: format!("{}-profile-pic.jpg", auth.id_tag).into(),
				file_tp: Some("BLOB".into()),
				created_at: None,
				tags: Some(vec!["profile".into()]),
				x: Some(json!({ "dim": dim })),
			},
		)
		.await?;

	// Extract file ID
	let file_id = match f_id {
		meta_adapter::FileId::FId(fid) => {
			// Image will be processed asynchronously via tasks
			app.meta_adapter.get_file_id(auth.tn_id, fid).await?
		}
		meta_adapter::FileId::FileId(fid) => fid,
	};

	// Update tenant with new profile picture
	app.meta_adapter
		.update_tenant(
			auth.tn_id,
			&meta_adapter::UpdateTenantData {
				profile_pic: Patch::Value(file_id.to_string()),
				..Default::default()
			},
		)
		.await?;

	info!("User {} uploaded profile image: {}", auth.id_tag, file_id);

	Ok((
		StatusCode::OK,
		Json(json!({
			"fileId": file_id,
			"type": "profile-pic"
		})),
	))
}

/// PUT /me/cover - Upload cover image
pub async fn put_cover_image(
	State(app): State<App>,
	Auth(auth): Auth,
	mut multipart: Multipart,
) -> ClResult<(StatusCode, Json<serde_json::Value>)> {
	// Extract image from multipart
	let mut image_data = Vec::new();
	let mut content_type = String::new();

	while let Some(field) = multipart
		.next_field()
		.await
		.map_err(|_| Error::NetworkError("multipart error".into()))?
	{
		if field.name() == Some("image") {
			content_type = field.content_type().unwrap_or("image/jpeg").to_string();
			image_data = field
				.bytes()
				.await
				.map_err(|_| Error::NetworkError("failed to read field bytes".into()))?
				.to_vec();
			break;
		}
	}

	if image_data.is_empty() {
		return Err(Error::ValidationError("No image data provided".into()));
	}

	// Validate content type
	if !matches!(content_type.as_str(), "image/jpeg" | "image/png" | "image/webp" | "image/avif") {
		return Err(Error::ValidationError("Invalid image content type".into()));
	}

	// Hash image to get blob ID
	let orig_variant_id = hasher::hash("b", &image_data);

	// Get image dimensions
	let dim = image::get_image_dimensions(&image_data).await?;
	info!("Cover image dimensions: {}x{}", dim.0, dim.1);

	// Create file metadata
	let f_id = app
		.meta_adapter
		.create_file(
			auth.tn_id,
			meta_adapter::CreateFile {
				preset: "cover".into(),
				orig_variant_id,
				file_id: None,
				owner_tag: Some(auth.id_tag.as_ref().into()),
				content_type: content_type.into(),
				file_name: format!("{}-cover.jpg", auth.id_tag).into(),
				file_tp: Some("BLOB".into()),
				created_at: None,
				tags: Some(vec!["cover".into()]),
				x: Some(json!({ "dim": dim })),
			},
		)
		.await?;

	// Extract file ID
	let file_id = match f_id {
		meta_adapter::FileId::FId(fid) => {
			// Image will be processed asynchronously via tasks
			app.meta_adapter.get_file_id(auth.tn_id, fid).await?
		}
		meta_adapter::FileId::FileId(fid) => fid,
	};

	// Update tenant with new cover picture
	app.meta_adapter
		.update_tenant(
			auth.tn_id,
			&meta_adapter::UpdateTenantData {
				cover_pic: Patch::Value(file_id.to_string()),
				..Default::default()
			},
		)
		.await?;

	info!("User {} uploaded cover image: {}", auth.id_tag, file_id);

	Ok((
		StatusCode::OK,
		Json(json!({
			"fileId": file_id,
			"type": "cover"
		})),
	))
}

// vim: ts=4
