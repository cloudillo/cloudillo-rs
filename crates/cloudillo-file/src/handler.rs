// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

use axum::{
	Json,
	body::{Body, to_bytes},
	extract::{self, Query, State},
	http::StatusCode,
	response,
};
use futures_core::Stream;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
	fmt::Debug,
	path::{Path, PathBuf},
	pin::Pin,
};
use tokio::io::AsyncWriteExt;

use crate::prelude::*;
use crate::{
	audio::AudioExtractorTask,
	descriptor::{self, FileIdGeneratorTask},
	dir_cache::{DirCache, DirEntry},
	ffmpeg, filter, image,
	image::ImageResizerTask,
	pdf,
	preset::{self, get_audio_tier, get_image_tier, get_video_tier, presets},
	store, svg,
	variant::{self, VariantClass},
	video::VideoTranscoderTask,
};
use cloudillo_core::abac::SubjectAccessLevel;
use cloudillo_core::extract::{Auth, IdTag, OptionalAuth, OptionalRequestId};
use cloudillo_core::file_access;
use cloudillo_types::blob_adapter;
use cloudillo_types::hasher;
use cloudillo_types::meta_adapter;
use cloudillo_types::meta_adapter::{MANAGED_PARENT_ID, ROOT_PARENT_ID, TRASH_PARENT_ID};
use cloudillo_types::types::{self, AccessLevel, ApiResponse, TokenScope};
use cloudillo_types::utils;

// Utility functions //
//*******************//
pub fn format_from_content_type(content_type: &str) -> Option<&str> {
	Some(match content_type {
		// Image
		"image/jpeg" => "jpeg",
		"image/png" => "png",
		"image/webp" => "webp",
		"image/avif" => "avif",
		"image/gif" => "gif",
		"image/svg+xml" => "svg",
		// Video
		"video/mp4" | "video/quicktime" => "mp4",
		"video/webm" => "webm",
		"video/x-matroska" => "mkv",
		"video/x-msvideo" => "avi",
		// Audio
		"audio/mpeg" => "mp3",
		"audio/wav" => "wav",
		"audio/ogg" => "ogg",
		"audio/flac" => "flac",
		"audio/aac" => "aac",
		"audio/webm" => "weba",
		// Document
		"application/pdf" => "pdf",
		_ => None?,
	})
}

/// Stream request body directly to a temp file (for large uploads).
/// Hashes bytes inline so callers receive both the size and the orig blob id
/// without re-reading the file from disk. Aborts and removes the partial file
/// when the streamed bytes exceed `max_size_bytes`.
async fn stream_body_to_file(
	body: Body,
	path: &PathBuf,
	max_size_bytes: u64,
) -> ClResult<(u64, Box<str>)> {
	use futures::StreamExt;

	let mut file = tokio::fs::File::create(path).await?;
	let mut body_stream = body.into_data_stream();
	let mut total_size: u64 = 0;
	let mut hasher = hasher::Hasher::new();

	while let Some(chunk) = body_stream.next().await {
		let chunk = chunk.map_err(|e| Error::Internal(format!("body read error: {}", e)))?;
		total_size += chunk.len() as u64;
		if total_size > max_size_bytes {
			drop(file);
			let _ = tokio::fs::remove_file(path).await;
			return Err(Error::ValidationError("upload exceeds maximum file size".into()));
		}
		hasher.update(&chunk);
		file.write_all(&chunk).await?;
	}
	file.flush().await?;

	Ok((total_size, hasher.finalize("b").into_boxed_str()))
}

/// Best-effort RAII cleanup for streaming-upload temp files.
/// On drop, spawns a remove_file task unless `keep()` was called.
struct TempFileGuard(Option<PathBuf>);

impl TempFileGuard {
	fn new(p: PathBuf) -> Self {
		Self(Some(p))
	}

	fn replace(&mut self, p: PathBuf) {
		self.0 = Some(p);
	}

	fn keep(mut self) {
		self.0 = None;
	}
}

impl Drop for TempFileGuard {
	fn drop(&mut self) {
		if let Some(p) = self.0.take() {
			tokio::spawn(async move {
				if let Err(e) = tokio::fs::remove_file(&p).await
					&& e.kind() != std::io::ErrorKind::NotFound
				{
					warn!("TempFileGuard cleanup failed for {:?}: {}", p, e);
				}
			});
		}
	}
}

pub fn content_type_from_format(format: &str) -> &str {
	match format {
		// Image
		"jpeg" => "image/jpeg",
		"png" => "image/png",
		"webp" => "image/webp",
		"avif" => "image/avif",
		"gif" => "image/gif",
		"svg" => "image/svg+xml",
		// Video
		"mp4" => "video/mp4",
		"webm" => "video/webm",
		"mkv" => "video/x-matroska",
		"avi" => "video/x-msvideo",
		// Audio
		"mp3" => "audio/mpeg",
		"wav" => "audio/wav",
		"ogg" => "audio/ogg",
		"flac" => "audio/flac",
		"aac" => "audio/aac",
		"weba" => "audio/webm",
		// Document
		"pdf" => "application/pdf",
		_ => "application/octet-stream",
	}
}

fn serve_file<S: AsRef<str> + Debug>(
	descriptor: Option<&str>,
	variant: &meta_adapter::FileVariant<S>,
	stream: Pin<Box<dyn Stream<Item = Result<axum::body::Bytes, std::io::Error>> + Send>>,
	disable_cache: bool,
) -> ClResult<response::Response<axum::body::Body>> {
	let content_type = content_type_from_format(variant.format.as_ref());

	let mut response = axum::response::Response::builder()
		.header(axum::http::header::CONTENT_TYPE, content_type)
		.header(axum::http::header::CONTENT_LENGTH, variant.size);

	// Add cache headers for content-addressed (immutable) files
	if disable_cache {
		response = response.header(axum::http::header::CACHE_CONTROL, "no-store, no-cache");
	} else {
		// Content-addressed files never change - use immutable caching
		response = response
			.header(axum::http::header::CACHE_CONTROL, "public, max-age=31536000, immutable");
	}

	response = response.header("X-Cloudillo-Variant", variant.variant_id.as_ref());
	if let Some(descriptor) = descriptor {
		response = response.header("X-Cloudillo-Variants", descriptor);
	}

	// Add CSP headers for SVG files to prevent script execution in federated content
	if content_type == "image/svg+xml" {
		response = response
			.header("Content-Security-Policy", "script-src 'none'; object-src 'none'")
			.header("X-Content-Type-Options", "nosniff");
	}

	Ok(response.body(axum::body::Body::from_stream(stream))?)
}

/// Sentinel parents that have no real folder row backing them. `ROOT_PARENT_ID`
/// is intentionally NOT listed here: root rows store `parent_id = NULL` in the
/// DB, so a `Some("__root__")` value never appears on a `FileView` from the
/// adapter.
fn is_terminal_parent(parent_id: &str) -> bool {
	parent_id == TRASH_PARENT_ID || parent_id == MANAGED_PARENT_ID
}

/// Resolve a single (tn, file_id) → DirEntry through the cache, falling back
/// to a single read_file call on cache miss.
async fn resolve_dir_entry(
	app: &App,
	cache: &DirCache,
	tn_id: TnId,
	file_id: &str,
) -> Option<DirEntry> {
	if let Some(entry) = cache.get(tn_id, file_id) {
		return Some(entry);
	}
	match app.meta_adapter.read_file(tn_id, file_id).await {
		Ok(Some(view)) => {
			let entry =
				DirEntry { parent_id: view.parent_id.clone(), name: view.file_name.clone() };
			cache.put(tn_id, file_id, entry.clone());
			Some(entry)
		}
		Ok(None) => None,
		Err(e) => {
			warn!("dir_cache resolve failed for tn_id={} file_id={}: {}", tn_id, file_id, e);
			None
		}
	}
}

/// Populate `parent_name` on each file in `files` when `with_parent` is true.
/// Resolves names via `DirCache`; misses fall back to one `read_file` per
/// distinct missing parent_id on the page.
async fn populate_parent_names(
	app: &App,
	cache: &DirCache,
	tn_id: TnId,
	files: &mut [meta_adapter::FileView],
) {
	use std::collections::HashMap;

	let mut missing: Vec<Box<str>> = Vec::new();
	for f in files.iter() {
		if let Some(pid) = f.parent_id.as_deref()
			&& !is_terminal_parent(pid)
			&& cache.get(tn_id, pid).is_none()
			&& !missing.iter().any(|m| m.as_ref() == pid)
		{
			missing.push(Box::from(pid));
		}
	}

	let mut resolved: HashMap<Box<str>, Box<str>> = HashMap::new();
	for pid in &missing {
		if let Some(entry) = resolve_dir_entry(app, cache, tn_id, pid).await {
			resolved.insert(pid.clone(), entry.name.clone());
		}
	}

	for f in files.iter_mut() {
		let Some(pid) = f.parent_id.as_deref() else { continue };
		if is_terminal_parent(pid) {
			continue;
		}
		if let Some(name) = resolved.get(pid) {
			f.parent_name = Some(name.clone());
		} else if let Some(entry) = cache.get(tn_id, pid) {
			f.parent_name = Some(entry.name);
		}
	}
}

/// Walk the parent chain iteratively (cap depth at 64) and produce a
/// root→parent ordered path. The file itself is not included.
async fn build_path(
	app: &App,
	cache: &DirCache,
	tn_id: TnId,
	start_parent_id: Option<&str>,
) -> Vec<meta_adapter::PathSegment> {
	const MAX_DEPTH: usize = 64;
	let mut acc: Vec<meta_adapter::PathSegment> = Vec::new();
	let mut current: Option<Box<str>> = start_parent_id.map(Box::from);

	for _ in 0..MAX_DEPTH {
		let Some(cur) = current.take() else { break };
		if is_terminal_parent(&cur) {
			break;
		}
		let Some(entry) = resolve_dir_entry(app, cache, tn_id, &cur).await else { break };
		acc.push(meta_adapter::PathSegment { id: cur.clone(), name: entry.name.clone() });
		current = entry.parent_id;
	}

	acc.reverse();
	acc
}

/// GET /api/files
pub async fn get_file_list(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	OptionalAuth(maybe_auth): OptionalAuth,
	Query(mut opts): Query<meta_adapter::ListFileOptions>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<meta_adapter::FileView>>>)> {
	// Guard: with_path is intended for single-file fetches. Reject misuse on
	// wide listings to keep iterative walks bounded.
	const MAX_BULK_WITHPATH_LIMIT: usize = 5;
	if opts.with_path
		&& opts.file_id.is_none()
		&& opts.limit.unwrap_or(30) as usize > MAX_BULK_WITHPATH_LIMIT
	{
		return Err(Error::ValidationError(format!(
			"withPath requires fileId or limit<={}",
			MAX_BULK_WITHPATH_LIMIT
		)));
	}

	// Set user_id_tag for user-specific data (pinned, starred, sorting by recent/modified)
	let (subject_id_tag, is_authenticated, subject_roles, scope) = match &maybe_auth {
		Some(auth) => {
			opts.user_id_tag = Some(auth.id_tag.to_string());
			(auth.id_tag.as_ref(), true, &auth.roles[..], auth.scope.as_deref())
		}
		None => ("", false, &[][..], None),
	};

	// For scoped tokens, push scope constraint into the DB query
	if let Some(scope_fid) = scope.and_then(TokenScope::parse).and_then(|ts| match ts {
		TokenScope::File { file_id, .. } => Some(file_id),
		TokenScope::ApkgPublish => None,
	}) {
		opts.scope_file_id = Some(scope_fid);
	}

	// Push visibility filtering into SQL for correct pagination
	let rels = app.meta_adapter.get_relationships(tn_id, &[subject_id_tag]).await?;
	let (following, connected) = rels.get(subject_id_tag).copied().unwrap_or((false, false));
	let is_real_auth = is_authenticated && !subject_id_tag.is_empty() && subject_id_tag != "guest";
	let is_tenant = subject_id_tag == tenant_id_tag.as_ref();

	let access_level = if is_tenant {
		SubjectAccessLevel::Owner
	} else if connected {
		SubjectAccessLevel::Connected
	} else if following {
		SubjectAccessLevel::Follower
	} else if is_real_auth {
		SubjectAccessLevel::Verified
	} else {
		SubjectAccessLevel::Public
	};
	opts.visible_levels = access_level.visible_levels().map(<[char]>::to_vec);

	if !is_tenant {
		opts.hidden = None;
	}

	// Share access: bypass visibility filter when the user has a share entry
	// on the queried folder (parentId). Per-file share checks are handled
	// individually by get_access_level in compute_file_access_levels.
	let mut inherited_share: Option<types::AccessLevel> = None;
	if !is_tenant
		&& is_real_auth
		&& let Some(ref parent_id) = opts.parent_id
		&& parent_id != ROOT_PARENT_ID
		&& parent_id != TRASH_PARENT_ID
		&& parent_id != MANAGED_PARENT_ID
	{
		inherited_share =
			file_access::check_share_for_file(&app, tn_id, parent_id, subject_id_tag).await;
	}
	if inherited_share.is_some() {
		opts.visible_levels = None;
	}

	let limit = opts.limit.unwrap_or(30) as usize;
	let sort_field = opts.sort.as_deref().unwrap_or("created");

	let files = app.meta_adapter.list_files(tn_id, &opts).await?;

	// Compute access_level (Read/Write) for each file
	// (visibility is already filtered at SQL level via visible_levels)
	let access_ctx = file_access::FileAccessCtx {
		user_id_tag: subject_id_tag,
		tenant_id_tag: &tenant_id_tag,
		user_roles: subject_roles,
	};
	let mut filtered =
		filter::compute_file_access_levels(&app, tn_id, &access_ctx, inherited_share, files)
			.await?;

	// Check if there are more results (we fetched limit+1)
	let has_more = filtered.len() > limit;
	if has_more {
		filtered.truncate(limit);
	}

	// Optional enrichment: parent folder name (one level) and full path chain.
	// Both are resolved via the shared DirCache extension.
	if opts.with_parent || opts.with_path {
		let dir_cache = app.ext::<DirCache>()?.clone();
		if opts.with_parent {
			populate_parent_names(&app, &dir_cache, tn_id, &mut filtered).await;
		}
		if opts.with_path {
			for f in &mut filtered {
				let segs = build_path(&app, &dir_cache, tn_id, f.parent_id.as_deref()).await;
				f.path = Some(segs);
			}
		}
	}

	// Build next cursor from last item
	let next_cursor = if has_more && !filtered.is_empty() {
		let last = filtered.last().ok_or(Error::Internal("no last item".into()))?;
		let sort_value = match sort_field {
			"recent" => {
				// Use user's accessed_at if available, otherwise created_at
				let ts = last
					.user_data
					.as_ref()
					.and_then(|ud| ud.accessed_at)
					.unwrap_or(last.created_at);
				serde_json::Value::Number(ts.0.into())
			}
			"modified" => {
				// Use user's modified_at if available, otherwise created_at
				let ts = last
					.user_data
					.as_ref()
					.and_then(|ud| ud.modified_at)
					.unwrap_or(last.created_at);
				serde_json::Value::Number(ts.0.into())
			}
			"name" => serde_json::Value::String(last.file_name.to_string()),
			_ => serde_json::Value::Number(last.created_at.0.into()),
		};
		let cursor = types::CursorData::new(sort_field, sort_value, &last.file_id);
		Some(cursor.encode())
	} else {
		None
	};

	let response = ApiResponse::with_cursor_pagination(filtered, next_cursor, has_more)
		.with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// GET /api/files/variant/{variant_id}
pub async fn get_file_variant(
	State(app): State<App>,
	tn_id: TnId,
	extract::Path(variant_id): extract::Path<String>,
) -> ClResult<impl response::IntoResponse> {
	let variant = app.meta_adapter.read_file_variant(tn_id, &variant_id).await?;
	info!("variant: {:?}", variant);
	let blob_tn = if variant.global { TnId(0) } else { tn_id };
	let stream = app.blob_adapter.read_blob_stream(blob_tn, &variant_id).await?;

	serve_file(None, &variant, stream, app.opts.disable_cache)
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetFileVariantSelector {
	pub variant: Option<String>,
	pub min_x: Option<u32>,
	pub min_y: Option<u32>,
	pub min_res: Option<u32>, // min resolution in kpx
}

pub async fn get_file_variant_file_id(
	State(app): State<App>,
	tn_id: TnId,
	extract::Path(file_id): extract::Path<String>,
	extract::Query(selector): extract::Query<GetFileVariantSelector>,
) -> ClResult<impl response::IntoResponse> {
	let mut variants = app
		.meta_adapter
		.list_file_variants(tn_id, meta_adapter::FileId::FileId(&file_id))
		.await?;
	variants.sort();
	debug!("variants: {:?}", variants);

	let variant = descriptor::get_best_file_variant(&variants, &selector)?;
	let blob_tn = if variant.global { TnId(0) } else { tn_id };
	let stream = app.blob_adapter.read_blob_stream(blob_tn, &variant.variant_id).await?;

	let root_id = app.meta_adapter.read_file(tn_id, &file_id).await?.and_then(|f| f.root_id);
	let descriptor = descriptor::get_file_descriptor(&variants, root_id.as_deref());

	serve_file(Some(&descriptor), variant, stream, app.opts.disable_cache)
}

pub async fn get_file_descriptor(
	State(app): State<App>,
	tn_id: TnId,
	extract::Path(file_id): extract::Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<String>>)> {
	let mut variants = app
		.meta_adapter
		.list_file_variants(tn_id, meta_adapter::FileId::FileId(&file_id))
		.await?;
	variants.sort();

	let root_id = app.meta_adapter.read_file(tn_id, &file_id).await?.and_then(|f| f.root_id);
	let descriptor = descriptor::get_file_descriptor(&variants, root_id.as_deref());

	let response = ApiResponse::new(descriptor).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

#[derive(Deserialize)]
pub struct PostFileQuery {
	#[serde(rename = "parentId")]
	parent_id: Option<String>,
	#[serde(rename = "rootId")]
	root_id: Option<String>,
	#[serde(rename = "createdAt")]
	created_at: Option<Timestamp>,
	tags: Option<String>,
	/// Visibility level: P=Public, V=Verified, F=Follower, C=Connected, NULL=Direct
	visibility: Option<char>,
	/// `as=managed` routes the new file into the hidden per-tenant managed folder
	/// (parent_id = `__managed__`). Used for system-managed uploads (action
	/// attachments, profile/cover images) so the file GC can reap unreferenced
	/// files without touching user-library files. Any client-supplied `parentId`
	/// is ignored when this is set.
	#[serde(rename = "as")]
	as_kind: Option<String>,
}

/// Resolve the effective parent_id from a request's `as` and `parentId` fields.
///
/// `as=managed` always wins and routes the file into the managed folder.
/// Otherwise, the explicit `parentId` is honored — except a client cannot plant
/// a file directly into `__managed__` or `__trash__` without the matching
/// `as=managed` hint, since those would be silently GC'd or hidden in trash.
fn resolve_managed_parent(
	as_kind: Option<&str>,
	parent_id: Option<&str>,
) -> ClResult<Option<String>> {
	if matches!(as_kind, Some("managed")) {
		return Ok(Some(MANAGED_PARENT_ID.to_string()));
	}
	if let Some(p) = parent_id
		&& (p == MANAGED_PARENT_ID || p == TRASH_PARENT_ID)
	{
		return Err(Error::ValidationError(format!(
			"parentId '{}' is reserved and requires as=managed",
			p
		)));
	}
	Ok(parent_id.map(str::to_owned))
}

impl PostFileQuery {
	fn effective_parent_id(&self) -> ClResult<Option<String>> {
		resolve_managed_parent(self.as_kind.as_deref(), self.parent_id.as_deref())
	}
}

#[derive(Deserialize)]
pub struct PostFileRequest {
	#[serde(rename = "fileTp")]
	file_tp: String, // Required parameter
	#[serde(rename = "contentType")]
	content_type: Option<String>, // Optional, defaults to application/json
	#[serde(rename = "fileName")]
	file_name: Option<String>,
	#[serde(rename = "parentId")]
	parent_id: Option<String>,
	/// Document tree root file_id (makes this a child in a document tree)
	#[serde(rename = "rootId")]
	root_id: Option<String>,
	#[serde(rename = "createdAt")]
	created_at: Option<Timestamp>,
	tags: Option<String>,
	/// Visibility level: P=Public, V=Verified, F=Follower, C=Connected, NULL=Direct
	visibility: Option<char>,
	/// `as: "managed"` routes the new file into the hidden per-tenant managed folder.
	/// Mirrors the `?as=managed` query param on the blob upload endpoint.
	#[serde(rename = "as")]
	as_kind: Option<String>,
	/// Hand cross-context creation: fileId from the source context to reference.
	/// When present, the new row in the destination tenant points to a file owned
	/// by another tenant; together with `source_id_tag`.
	#[serde(rename = "sourceFileId")]
	source_file_id: Option<String>,
	/// Hand cross-context creation: owner idTag of the source content.
	#[serde(rename = "sourceIdTag")]
	source_id_tag: Option<String>,
}

impl PostFileRequest {
	fn effective_parent_id(&self) -> ClResult<Option<String>> {
		resolve_managed_parent(self.as_kind.as_deref(), self.parent_id.as_deref())
	}
}

async fn handle_post_image(
	app: &App,
	tn_id: types::TnId,
	f_id: u64,
	_content_type: &str,
	bytes: &[u8],
	preset: &preset::FilePreset,
) -> ClResult<serde_json::Value> {
	let result = image::generate_image_variants(app, tn_id, f_id, bytes, preset).await?;

	let mut data = json!({
		"fileId": format!("@{}", f_id),
		"dim": [result.dim.0, result.dim.1]
	});
	if let Some(thumb_id) = result.thumbnail_variant_id {
		data["thumbnailVariantId"] = serde_json::Value::String(thumb_id);
	}
	Ok(data)
}

/// Handle SVG upload - sanitize, rasterize thumbnail, and store
async fn handle_post_svg(
	app: &App,
	tn_id: types::TnId,
	f_id: u64,
	bytes: &[u8],
	preset: &preset::FilePreset,
) -> ClResult<serde_json::Value> {
	// 1. Sanitize SVG
	let sanitized = svg::sanitize_svg(bytes)?;
	info!("SVG sanitized: {} -> {} bytes", bytes.len(), sanitized.len());

	// 2. Parse dimensions from sanitized SVG
	let (orig_width, orig_height) = svg::parse_svg_dimensions(&sanitized)?;
	info!("SVG dimensions: {}x{}", orig_width, orig_height);

	// 3. Read format settings for thumbnail
	let thumbnail_format_str = app
		.settings
		.get_string(tn_id, "file.thumbnail_format")
		.await
		.unwrap_or_else(|_| "webp".to_string());
	let thumbnail_format: image::ImageFormat =
		thumbnail_format_str.parse().unwrap_or(image::ImageFormat::Webp);

	// 4. Store sanitized SVG as vis.sd (SVG scales infinitely, no need for separate "orig")
	// Note: We use vis.sd because:
	// - Apps typically request vis.sd first, then fall back to vis.hd/orig
	// - SVG is vector-based, any variant serves as highest quality
	// - Database PRIMARY KEY (f_id, variant_id, tn_id) prevents two variants with same blob
	let sd_variant_id = if preset.store_original {
		store::create_blob_buf(app, tn_id, &sanitized, blob_adapter::CreateBlobOptions::default())
			.await?
	} else {
		hasher::hash("b", &sanitized)
	};

	// Create vis.sd variant with sanitized SVG
	app.meta_adapter
		.create_file_variant(
			tn_id,
			f_id,
			meta_adapter::FileVariant {
				variant_id: sd_variant_id.as_ref(),
				variant: "vis.sd",
				format: "svg",
				resolution: (orig_width, orig_height),
				size: sanitized.len() as u64,
				available: preset.store_original,
				global: false,
				duration: None,
				bitrate: None,
				page_count: None,
			},
		)
		.await?;

	// 6. Determine thumbnail variant
	let thumbnail_variant = preset.thumbnail_variant.as_deref().unwrap_or("vis.tn");
	let thumbnail_tier = preset::get_image_tier(thumbnail_variant);
	let tn_format = thumbnail_tier.and_then(|t| t.format).unwrap_or(thumbnail_format);
	let tn_max_dim = thumbnail_tier.map_or(256, |t| t.max_dim);

	// 7. Rasterize SVG for thumbnail (synchronous)
	let resized_tn = svg::rasterize_svg_sync(&sanitized, tn_format, (tn_max_dim, tn_max_dim))?;

	let thumbnail_variant_id = store::create_blob_buf(
		app,
		tn_id,
		&resized_tn.bytes,
		blob_adapter::CreateBlobOptions::default(),
	)
	.await?;

	app.meta_adapter
		.create_file_variant(
			tn_id,
			f_id,
			meta_adapter::FileVariant {
				variant_id: thumbnail_variant_id.as_ref(),
				variant: thumbnail_variant,
				format: tn_format.as_ref(),
				resolution: (resized_tn.width, resized_tn.height),
				size: resized_tn.bytes.len() as u64,
				available: true,
				global: false,
				duration: None,
				bitrate: None,
				page_count: None,
			},
		)
		.await?;

	info!(
		"SVG thumbnail created: {}x{} ({} bytes)",
		resized_tn.width,
		resized_tn.height,
		resized_tn.bytes.len()
	);

	// 8. Schedule FileIdGeneratorTask (no additional variant tasks needed)
	app.scheduler
		.task(FileIdGeneratorTask::new(tn_id, f_id))
		.key(format!("{},{}", tn_id, f_id))
		.schedule()
		.await?;

	Ok(json!({
		"fileId": format!("@{}", f_id),
		"thumbnailVariantId": thumbnail_variant_id,
		"dim": [orig_width, orig_height]
	}))
}

/// Handle video upload - assumes body has already been streamed to `temp_path`
/// and probed; always records the orig variant row so re-uploads dedup at
/// `create_file` next time around.
#[expect(clippy::too_many_arguments, reason = "video pipeline carries pre-computed inputs")]
async fn handle_post_video_stream(
	app: &App,
	tn_id: types::TnId,
	f_id: u64,
	content_type: &str,
	temp_path: &Path,
	resolution: (u32, u32),
	duration: f64,
	orig_blob_id: &str,
	blob_stored: bool,
	total_size: u64,
	preset: &preset::FilePreset,
) -> ClResult<serde_json::Value> {
	info!("Video info: duration={:.2}s, resolution={}x{}", duration, resolution.0, resolution.1);

	// Read max_generate_variant setting
	let max_quality_str = app
		.settings
		.get_string(tn_id, "file.max_generate_variant")
		.await
		.unwrap_or_else(|_| "hd".to_string());
	let max_quality =
		variant::parse_quality(&max_quality_str).unwrap_or(variant::VariantQuality::High);

	// Always record the orig variant row so future re-uploads of identical
	// content hit the dedup path in create_file. `available` reflects whether
	// the blob bytes exist on disk for this tenant.
	app.meta_adapter
		.create_file_variant(
			tn_id,
			f_id,
			meta_adapter::FileVariant {
				variant_id: orig_blob_id,
				variant: "orig",
				format: format_from_content_type(content_type).unwrap_or("mp4"),
				resolution,
				size: total_size,
				available: blob_stored,
				global: false,
				duration: Some(duration),
				bitrate: None,
				page_count: None,
			},
		)
		.await?;

	// 4. Extract thumbnail synchronously (like images)
	let frame_path = app.opts.tmp_dir.join(format!("frame_{}.jpg", f_id));

	// Calculate smart seek time (10% of duration, min 3s for long videos)
	let seek_time = if duration > 10.0 {
		(duration * 0.1).max(3.0).min(duration - 1.0)
	} else if duration > 1.0 {
		duration / 2.0
	} else {
		0.0
	};

	// Extract frame using FFmpeg
	ffmpeg::FFmpeg::extract_frame(temp_path, &frame_path, seek_time)
		.map_err(|e| Error::Internal(format!("thumbnail extraction failed: {}", e)))?;

	// Read frame and resize to thumbnail (keep frame file for other vis.* variants)
	let frame_bytes = tokio::fs::read(&frame_path).await?;

	let thumbnail_result =
		image::resize_image(app.clone(), frame_bytes, image::ImageFormat::Webp, (256, 256))
			.await
			.map_err(|e| Error::Internal(format!("thumbnail resize failed: {}", e)))?;

	// Store thumbnail blob
	let thumbnail_variant_id = store::create_blob_buf(
		app,
		tn_id,
		&thumbnail_result.bytes,
		blob_adapter::CreateBlobOptions::default(),
	)
	.await?;

	// Create thumbnail variant record
	app.meta_adapter
		.create_file_variant(
			tn_id,
			f_id,
			meta_adapter::FileVariant {
				variant_id: &thumbnail_variant_id,
				variant: "vis.tn",
				format: "webp",
				resolution: (thumbnail_result.width, thumbnail_result.height),
				size: thumbnail_result.bytes.len() as u64,
				available: true,
				global: false,
				duration: None,
				bitrate: None,
				page_count: None,
			},
		)
		.await?;

	info!(
		"Video thumbnail extracted: {}x{} ({} bytes)",
		thumbnail_result.width,
		thumbnail_result.height,
		thumbnail_result.bytes.len()
	);

	// 5. Create tasks based on preset (async)
	let mut task_ids = Vec::new();

	// 5a. Create visual variants from extracted frame (sized frames approach)
	for variant_name in &preset.image_variants {
		if variant_name == "vis.tn" {
			continue; // Already created thumbnail synchronously
		}
		// Skip variants exceeding max_generate_variant setting
		if let Some(parsed) = variant::Variant::parse(variant_name)
			&& parsed.quality > max_quality
		{
			continue;
		}
		if let Some(tier) = get_image_tier(variant_name) {
			let task = ImageResizerTask::new(
				tn_id,
				f_id,
				frame_path.clone(),
				variant_name.clone(),
				image::ImageFormat::Webp,
				(tier.max_dim, tier.max_dim),
			);
			task_ids.push(app.scheduler.add(task).await?);
		}
	}

	// 5b. Create video transcode tasks
	for variant_name in &preset.video_variants {
		// Skip variants exceeding max_generate_variant setting
		if let Some(parsed) = variant::Variant::parse(variant_name)
			&& parsed.quality > max_quality
		{
			continue;
		}
		if let Some(tier) = get_video_tier(variant_name) {
			let task = VideoTranscoderTask::new(
				tn_id,
				f_id,
				temp_path.to_owned(),
				variant_name.as_str(),
				tier.max_dim,
				tier.bitrate,
			);
			task_ids.push(app.scheduler.add(task).await?);
		}
	}

	// 6. Optionally extract audio
	if preset.extract_audio {
		for variant_name in &preset.audio_variants {
			// Skip variants exceeding max_generate_variant setting
			if let Some(parsed) = variant::Variant::parse(variant_name)
				&& parsed.quality > max_quality
			{
				continue;
			}
			if let Some(tier) = get_audio_tier(variant_name) {
				let task = AudioExtractorTask::new(
					tn_id,
					f_id,
					temp_path.to_owned(),
					variant_name.as_str(),
					tier.bitrate,
				);
				task_ids.push(app.scheduler.add(task).await?);
			}
		}
	}

	// 7. Create FileIdGeneratorTask depending on transcode tasks
	let mut builder = app
		.scheduler
		.task(FileIdGeneratorTask::new(tn_id, f_id))
		.key(format!("{},{}", tn_id, f_id));
	if !task_ids.is_empty() {
		builder = builder.depend_on(task_ids);
	}
	builder.schedule().await?;

	Ok(json!({
		"fileId": format!("@{}", f_id),
		"duration": duration,
		"resolution": [resolution.0, resolution.1],
		"thumbnailVariantId": thumbnail_variant_id
	}))
}

/// Handle audio upload - assumes body has already been streamed to `temp_path`
/// and probed; always records the orig variant row.
#[expect(clippy::too_many_arguments, reason = "audio pipeline carries pre-computed inputs")]
async fn handle_post_audio_stream(
	app: &App,
	tn_id: types::TnId,
	f_id: u64,
	content_type: &str,
	temp_path: &Path,
	duration: f64,
	orig_blob_id: &str,
	blob_stored: bool,
	total_size: u64,
	preset: &preset::FilePreset,
) -> ClResult<serde_json::Value> {
	info!("Audio info: duration={:.2}s", duration);

	// Read max_generate_variant setting
	let max_quality_str = app
		.settings
		.get_string(tn_id, "file.max_generate_variant")
		.await
		.unwrap_or_else(|_| "hd".to_string());
	let max_quality =
		variant::parse_quality(&max_quality_str).unwrap_or(variant::VariantQuality::High);

	// Always record the orig variant row.
	app.meta_adapter
		.create_file_variant(
			tn_id,
			f_id,
			meta_adapter::FileVariant {
				variant_id: orig_blob_id,
				variant: "orig",
				format: format_from_content_type(content_type).unwrap_or("mp3"),
				resolution: (0, 0),
				size: total_size,
				available: blob_stored,
				global: false,
				duration: Some(duration),
				bitrate: None,
				page_count: None,
			},
		)
		.await?;

	// 4. Create AudioExtractorTask for each variant
	let mut task_ids = Vec::new();
	for variant_name in &preset.audio_variants {
		// Skip variants exceeding max_generate_variant setting
		if let Some(parsed) = variant::Variant::parse(variant_name)
			&& parsed.quality > max_quality
		{
			continue;
		}
		if let Some(tier) = get_audio_tier(variant_name) {
			let task = AudioExtractorTask::new(
				tn_id,
				f_id,
				temp_path.to_owned(),
				variant_name.as_str(),
				tier.bitrate,
			);
			task_ids.push(app.scheduler.add(task).await?);
		}
	}

	// 5. Create FileIdGeneratorTask
	let mut builder = app
		.scheduler
		.task(FileIdGeneratorTask::new(tn_id, f_id))
		.key(format!("{},{}", tn_id, f_id));
	if !task_ids.is_empty() {
		builder = builder.depend_on(task_ids);
	}
	builder.schedule().await?;

	Ok(json!({
		"fileId": format!("@{}", f_id),
		"duration": duration
	}))
}

/// Handle PDF upload - in-memory processing (PDFs are typically smaller)
async fn handle_post_pdf(
	app: &App,
	tn_id: types::TnId,
	f_id: u64,
	bytes: &[u8],
) -> ClResult<serde_json::Value> {
	// 1. Store original blob
	let orig_blob_id =
		store::create_blob_buf(app, tn_id, bytes, blob_adapter::CreateBlobOptions::default())
			.await?;

	// 2. Write to temp file for thumbnail generation
	let temp_path = app.opts.tmp_dir.join(format!("pdf_{}_{}", tn_id.0, f_id));
	tokio::fs::write(&temp_path, bytes).await?;

	// 3. Generate thumbnail synchronously (so vis.tn is available immediately)
	let pdf_result = pdf::generate_pdf_thumbnail_variant(app, tn_id, f_id, &temp_path, 256).await?;

	// 4. Clean up temp file
	let _ = tokio::fs::remove_file(&temp_path).await;

	// 5. Create doc.orig variant with page count (now known from PDF info)
	app.meta_adapter
		.create_file_variant(
			tn_id,
			f_id,
			meta_adapter::FileVariant {
				variant_id: &orig_blob_id,
				variant: "orig",
				format: "pdf",
				resolution: (0, 0),
				size: bytes.len() as u64,
				available: true,
				global: false,
				duration: None,
				bitrate: None,
				page_count: Some(pdf_result.page_count),
			},
		)
		.await?;

	// 6. Create FileIdGeneratorTask (no dependencies needed)
	app.scheduler
		.task(FileIdGeneratorTask::new(tn_id, f_id))
		.key(format!("{},{}", tn_id, f_id))
		.schedule()
		.await?;

	Ok(json!({
		"fileId": format!("@{}", f_id),
		"thumbnailVariantId": pdf_result.variant_id
	}))
}

/// Handle raw file upload - assumes body has already been streamed to `temp_path`
/// with hash known; stores blob bytes (no re-hash) and records orig variant.
async fn handle_post_raw_stream(
	app: &App,
	tn_id: types::TnId,
	f_id: u64,
	content_type: &str,
	temp_path: &Path,
	orig_blob_id: &str,
	total_size: u64,
) -> ClResult<serde_json::Value> {
	// Persist blob bytes from the temp file (hash already in scope).
	app.blob_adapter
		.create_blob_from_path(
			tn_id,
			orig_blob_id,
			temp_path,
			&blob_adapter::CreateBlobOptions::default(),
		)
		.await?;

	// Determine format from content-type or use generic extension
	let format = format_from_content_type(content_type).unwrap_or("bin");

	app.meta_adapter
		.create_file_variant(
			tn_id,
			f_id,
			meta_adapter::FileVariant {
				variant_id: orig_blob_id,
				variant: "orig",
				format,
				resolution: (0, 0),
				size: total_size,
				available: true,
				global: false,
				duration: None,
				bitrate: None,
				page_count: None,
			},
		)
		.await?;

	// Clean up temp file
	let _ = tokio::fs::remove_file(temp_path).await;

	// Create FileIdGeneratorTask (no variants, just the original)
	app.scheduler
		.task(FileIdGeneratorTask::new(tn_id, f_id))
		.key(format!("{},{}", tn_id, f_id))
		.schedule()
		.await?;

	Ok(json!({"fileId": format!("@{}", f_id)}))
}

/// POST /api/files - File creation for non-blob types (CRDT, RTDB, etc.)
/// Accepts JSON body with metadata:
/// {
///   "fileTp": "CRDT" | "RTDB" | etc.,
///   "createdAt": optional timestamp,
///   "tags": optional comma-separated tags
/// }
pub async fn post_file(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	extract::Json(req): extract::Json<PostFileRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<serde_json::Value>>)> {
	info!("POST /api/files - Creating file with fileTp={}", req.file_tp);

	// Scope check first: cross-context placements have no `root_id`, so a
	// scoped token (share link, scope `file:<id>:W`) cannot create them — and a
	// scoped token creating a normal new file is bounded to the scoped root.
	file_access::check_scope_allows_create(auth.scope.as_deref(), req.root_id.as_deref())?;

	// Cross-context creation (Hand verbs: Pin / Place) routes through a dedicated
	// branch before the normal new-blob path. Triggered by the presence of
	// `sourceFileId` + `sourceIdTag`.
	if let (Some(source_file_id), Some(source_id_tag)) =
		(req.source_file_id.as_deref(), req.source_id_tag.as_deref())
	{
		return post_file_cross_context(
			app,
			tn_id,
			auth,
			req_id,
			&req,
			source_file_id,
			source_id_tag,
		)
		.await;
	}

	// Generate file_id
	let file_id = utils::random_id()?;

	// Validate root_id if provided - the root file must exist and be a top-level file
	if let Some(ref root_id) = req.root_id {
		let root_file =
			app.meta_adapter.read_file(tn_id, root_id).await?.ok_or_else(|| {
				Error::ValidationError(format!("root file '{}' not found", root_id))
			})?;
		if root_file.root_id.is_some() {
			return Err(Error::ValidationError(
				"root_id must reference a top-level file (not a file that itself has a root_id)"
					.into(),
			));
		}
	}

	// Default visibility to 'C' (Connected) for community tenants
	let tenant_meta = app.meta_adapter.read_tenant(tn_id).await?;
	let visibility = match req.visibility {
		Some(v) => Some(v),
		None if matches!(tenant_meta.typ, meta_adapter::ProfileType::Community) => Some('C'),
		None => None,
	};

	// Create file metadata with specified fileTp
	let content_type = req.content_type.clone().unwrap_or_else(|| "application/json".to_string());
	let _f_id = app
		.meta_adapter
		.create_file(
			tn_id,
			meta_adapter::CreateFile {
				preset: Some("default".into()),
				orig_variant_id: Some(file_id.clone().into()),
				file_id: Some(file_id.clone().into()),
				parent_id: req.effective_parent_id()?.map(Into::into),
				root_id: req.root_id.map(Into::into),
				creator_tag: Some(auth.id_tag.clone()),
				content_type: content_type.into(),
				file_name: req.file_name.clone().unwrap_or_else(|| "file".into()).into(),
				file_tp: Some(req.file_tp.clone().into()),
				created_at: req.created_at,
				tags: req.tags.as_ref().map(|s| s.split(',').map(Into::into).collect()),
				visibility,
				..Default::default()
			},
		)
		.await?;

	info!("Created file metadata for fileTp={} by {}", req.file_tp, auth.id_tag);

	let data = json!({"fileId": file_id});

	let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::CREATED, Json(response)))
}

/// Fetch a `FileView` for `source_file_id` from the peer that owns `source_id_tag`,
/// translating peer errors into the typed cross-context error codes. The proxy-token
/// exchange already gates access: 403 → caller has no share grant on the source,
/// 404/410 → source row gone or never existed, network/parse → source unreachable.
async fn fetch_source_file_view(
	app: &App,
	tn_id: types::TnId,
	source_id_tag: &str,
	source_file_id: &str,
) -> ClResult<meta_adapter::FileView> {
	let envelope: types::ApiResponse<meta_adapter::FileView> = app
		.request
		.get(tn_id, source_id_tag, &format!("/files/{}/metadata", source_file_id))
		.await
		.map_err(|e| match e {
			Error::NotFound | Error::Gone => Error::FileSourceNotFound,
			Error::PermissionDenied => Error::FileSourceForbidden,
			Error::NetworkError(_) => Error::FileSourceUnreachable,
			Error::Parse => Error::Internal("source returned malformed metadata".into()),
			other => other,
		})?;
	Ok(envelope.data)
}

/// Combine source-supplied tags with caller-supplied tags into the initial tag
/// set for a cross-context placement. Caller tags layer on top of source tags
/// (intent: "also tag it locally with these") and duplicates are skipped.
fn merge_cross_context_tags(
	source_tags: Option<&[Box<str>]>,
	req_tags: Option<&str>,
) -> Option<Vec<Box<str>>> {
	let source: Option<Vec<Box<str>>> = source_tags.map(|t| {
		t.iter()
			.map(|s| s.as_ref().trim())
			.filter(|s| !s.is_empty())
			.map(Box::<str>::from)
			.collect()
	});
	let extra: Option<Vec<Box<str>>> = req_tags.map(|s| {
		s.split(',')
			.map(str::trim)
			.filter(|s| !s.is_empty())
			.map(Box::<str>::from)
			.collect()
	});
	match (source, extra) {
		(None, None) => None,
		(Some(t), None) | (None, Some(t)) => (!t.is_empty()).then_some(t),
		(Some(mut a), Some(b)) => {
			for tag in b {
				if !a.iter().any(|existing| existing.as_ref() == tag.as_ref()) {
					a.push(tag);
				}
			}
			(!a.is_empty()).then_some(a)
		}
	}
}

/// Resolve the initial visibility for a cross-context placement. `override_`
/// (from the request body) wins; otherwise community tenants default to `'C'`
/// (Connected) and personal tenants to NULL (Direct, kept out of directory
/// listings).
async fn default_cross_context_visibility(
	app: &App,
	tn_id: types::TnId,
	override_: Option<char>,
) -> ClResult<Option<char>> {
	if let Some(v) = override_ {
		return Ok(Some(v));
	}
	let dest_tenant = app.meta_adapter.read_tenant(tn_id).await?;
	Ok(matches!(dest_tenant.typ, meta_adapter::ProfileType::Community).then_some('C'))
}

/// Cross-context file creation (Hand: Pin / Place verbs).
///
/// Step 2 of the Hand flow; FSHR creation on the source is a prior, separate
/// frontend call. Creates a new row in the destination tenant (`tn_id`) that
/// references content owned by another tenant (`source_id_tag`). The
/// destination row's `owner_tag` is the canonical source owner, never the
/// caller and never the destination.
///
/// Source file metadata is fetched via the inter-node HTTP API; this handler
/// never touches the source tenant's adapters.
async fn post_file_cross_context(
	app: App,
	tn_id: types::TnId,
	auth: cloudillo_types::auth_adapter::AuthCtx,
	req_id: Option<String>,
	req: &PostFileRequest,
	source_file_id: &str,
	source_id_tag: &str,
) -> ClResult<(StatusCode, Json<ApiResponse<serde_json::Value>>)> {
	info!(
		"POST /api/files cross-context: source={}@{} -> dest tn_id={}",
		source_file_id, source_id_tag, tn_id.0
	);

	// (Reminder: in Cloudillo each user is a separate tenant, so a tenant-
	// scoped proxy token authenticates the calling user.)
	let source_view = fetch_source_file_view(&app, tn_id, source_id_tag, source_file_id).await?;

	// Cycle reject: source must be owned by source_id_tag itself, not be a
	// cross-tenant placement of yet another tenant's file.
	let source_owner = source_view.owner.as_ref().map_or(source_id_tag, |o| o.id_tag.as_ref());
	if source_owner != source_id_tag {
		return Err(Error::FileCycleRejected);
	}

	// Idempotency check: if a row already exists for the same source file_id
	// AND the existing row's owner matches the requested source AND the parent
	// matches, return 200 with the existing FileView (safe retry).
	let parent_id_resolved = req.effective_parent_id()?;
	if let Some(existing) = app.meta_adapter.read_file(tn_id, source_file_id).await? {
		let existing_owner = existing.owner.as_ref().map(|o| o.id_tag.as_ref());
		let existing_parent = existing.parent_id.as_deref();
		let req_parent = parent_id_resolved.as_deref();

		if existing_owner == Some(source_id_tag) && existing_parent == req_parent {
			info!("Idempotent cross-context create: returning existing row");
			let view = app
				.meta_adapter
				.read_file_with_user_data(tn_id, source_file_id, &auth.id_tag)
				.await?
				.ok_or_else(|| Error::Internal("idempotent row vanished".into()))?;
			let data = serde_json::to_value(&view)?;
			let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());
			return Ok((StatusCode::OK, Json(response)));
		}

		// Same file_id but different owner: this row was created via a
		// different path (e.g. an inbound action attachment) and is not
		// the same logical placement. Semantically a generic conflict.
		if existing_owner != Some(source_id_tag) {
			return Err(Error::Conflict(format!(
				"file_id '{}' already exists in this tenant with a different owner",
				source_file_id
			)));
		}

		// Same owner, different parent: the file is already placed in this
		// tenant under a different parent. Frontend behavior matches the
		// different-owner case ("go to existing location"), so a generic 409
		// with the existing parent embedded is sufficient.
		return Err(Error::Conflict(format!(
			"file_id '{}' is already placed in this context (parent: {})",
			source_file_id,
			existing.parent_id.as_deref().unwrap_or("<root>")
		)));
	}

	let visibility = default_cross_context_visibility(&app, tn_id, req.visibility).await?;

	let content_type: Box<str> = source_view
		.content_type
		.clone()
		.unwrap_or_else(|| "application/octet-stream".into());

	// Initial row state must match what the first `refresh_file` would write,
	// so the visible state doesn't flip between Pin/Place and the very next
	// refresh. Copy `tags`, `preset`, `x` from the source view; request-
	// supplied tags layer on top of source tags rather than replacing them.
	let combined_tags = merge_cross_context_tags(source_view.tags.as_deref(), req.tags.as_deref());

	app.meta_adapter
		.create_file(
			tn_id,
			cloudillo_types::meta_adapter::CreateFile {
				file_id: Some(source_file_id.into()),
				owner_tag: Some(source_id_tag.into()),
				creator_tag: Some(auth.id_tag.clone()),
				content_type,
				file_name: source_view.file_name.clone(),
				file_tp: source_view.file_tp.clone(),
				parent_id: parent_id_resolved.map(Into::into),
				preset: source_view.preset.clone(),
				tags: combined_tags,
				x: source_view.x.clone(),
				status: Some(cloudillo_types::meta_adapter::FileStatus::Active),
				visibility,
				..Default::default()
			},
		)
		.await?;

	// Seed the caller's cached access_level so the response carries the eye
	// badge without a follow-up `/refresh` round-trip. Mirrors what FSHR
	// on_accept does on the recipient side and what `refresh_file` writes on
	// subsequent reconciliations.
	let access_patch: Patch<char> = match source_view.access_level {
		Some(lv) => match access_level_to_perm_char(lv) {
			Some(ch) => Patch::Value(ch),
			None => Patch::Null,
		},
		None => Patch::Undefined,
	};
	if !access_patch.is_undefined() {
		// Best-effort: a failure here just means the eye badge will appear
		// on the next list/refresh rather than this response.
		if let Err(e) = app
			.meta_adapter
			.update_file_user_data(
				tn_id,
				&auth.id_tag,
				source_file_id,
				Patch::Undefined,
				Patch::Undefined,
				access_patch,
			)
			.await
		{
			tracing::warn!("cross-context create: failed to seed cached access_level: {}", e);
		}
	}

	let view = app
		.meta_adapter
		.read_file_with_user_data(tn_id, source_file_id, &auth.id_tag)
		.await?
		.ok_or_else(|| Error::Internal("freshly created row missing".into()))?;
	let data = serde_json::to_value(&view)?;
	let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::CREATED, Json(response)))
}

/// Wrapper around `FileView` that adds a non-sticky `refreshStatus` hint for
/// transient outcomes (e.g. network failure). The hint lives only in the
/// response — it is never persisted — so it disappears on the next successful
/// refresh. `view` flattens onto the wire, so callers that ignore the hint
/// see exactly the same shape as `GET /files/{id}/metadata`.
#[derive(Debug, Serialize)]
pub struct RefreshResponse {
	#[serde(flatten)]
	view: meta_adapter::FileView,
	#[serde(rename = "refreshStatus", skip_serializing_if = "Option::is_none")]
	refresh_status: Option<&'static str>,
}

/// POST /api/files/{file_id}/refresh
///
/// Reconciles a cross-context file row with its source. Frontend calls this
/// when it detects an inconsistency (broken thumbnail, 404 on blob, stale
/// access). The response body wraps the destination `FileView` (same shape as
/// `GET /files/{id}/metadata`) plus an optional `refreshStatus` hint for
/// transient outcomes.
///
/// Outcomes:
/// - 200 + cleared tombstone → source responded; if caller is the row's
///   creator we sync `file_name` / `content_type` / `file_tp` / `tags` /
///   `preset` / `x` and clear any prior `broken_*`. Non-creators get a
///   per-user-only refresh (the cached `access_level` is updated for the
///   caller, shared row state is left untouched).
/// - 200 + `broken_reason = 'deleted'` → source returned 404/410. Creator-only.
/// - 200 + `broken_reason = 'revoked'` → source returned 403. Creator-only;
///   non-creators get their cached `access_level` cleared but the shared
///   tombstone is left alone.
/// - 200 + `refreshStatus = "unreachable"` → transient network/parse failure.
///   No row mutation: the response returns whatever was already on disk.
///   The hint is non-sticky, so a successful retry simply omits the field.
///
/// Atomicity: the handler issues up to three independent adapter writes
/// (`update_file_data`, `update_file_user_data`, then a read). Each write is
/// individually idempotent — replaying the same refresh is safe. A failure
/// between writes therefore leaves the row in a consistent point along the
/// (file_data updated? → user_data updated?) trajectory, which the next
/// refresh resolves. This is deliberate: avoiding a transaction here keeps
/// the adapter trait surface narrow.
pub async fn refresh_file(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	Auth(auth): Auth,
	extract::Path(file_id): extract::Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<RefreshResponse>>)> {
	// Cross-context placements always use content-addressed ids (`f1~…`); the
	// `@<f_id>` form addresses local-only rows and cannot have an upstream
	// source. Reject early so callers see a clear validation error rather
	// than a later "refresh is only valid for cross-context" message that
	// looks like a permission / state issue.
	if file_id.starts_with('@') {
		return Err(Error::ValidationError(
			"refresh requires a content-addressed file_id, not an @-prefixed id".into(),
		));
	}

	// Caller must have read access to the destination row. We don't have a
	// cheap-and-direct ABAC check at the handler layer, so reuse
	// `check_file_access_with_scope` (the same gate that
	// `GET /metadata` uses for authed callers).
	let ctx = file_access::FileAccessCtx {
		user_id_tag: &auth.id_tag,
		tenant_id_tag: &tenant_id_tag,
		user_roles: &auth.roles,
	};
	let existing = file_access::check_file_access_with_scope(
		&app,
		tn_id,
		&file_id,
		&ctx,
		auth.scope.as_deref(),
		None,
	)
	.await
	.map_err(|e| match e {
		file_access::FileAccessError::NotFound => Error::NotFound,
		file_access::FileAccessError::AccessDenied => Error::PermissionDenied,
		file_access::FileAccessError::InternalError(m) => Error::Internal(m),
	})?
	.file_view;

	// Refresh only makes sense for cross-context rows — local-owned rows have
	// no upstream source to fetch. Identify them by `owner_tag` differing
	// from the local tenant's id_tag.
	let owner_tag = match existing.owner.as_ref() {
		Some(o) if o.id_tag.as_ref() != tenant_id_tag.as_ref() => o.id_tag.as_ref(),
		_ => {
			return Err(Error::ValidationError(
				"refresh is only valid for cross-context (hand-pinned) files".into(),
			));
		}
	};

	// Only the row's creator may write shared row state (file_name,
	// content_type, tags, preset, x, broken_*). Non-creators with read access
	// can still keep their per-user cached `access_level` in sync, but they
	// cannot toggle the tombstone or overwrite shared fields for everyone.
	let is_creator =
		existing.creator.as_ref().map(|c| c.id_tag.as_ref()) == Some(auth.id_tag.as_ref());

	let fetch: Result<types::ApiResponse<meta_adapter::FileView>, Error> =
		app.request.get(tn_id, owner_tag, &format!("/files/{}/metadata", file_id)).await;

	let mut refresh_status: Option<&'static str> = None;

	let access_level_update: Patch<char> = match fetch {
		Ok(envelope) => {
			let source = envelope.data;
			let source_access_level = source.access_level;
			if is_creator {
				// Refresh is reconciliation, not authoritative replacement: a
				// source omitting a field means "no information, preserve
				// local" (Patch::Undefined). A source that wants to clear a
				// field must send explicit null (handled via Patch::Null
				// where serde maps to Option). For tags, an empty list is the
				// source's way to clear; that maps to Patch::Null.
				let opts = meta_adapter::UpdateFileOptions {
					file_name: Patch::Value(source.file_name.to_string()),
					content_type: match source.content_type.as_deref() {
						Some(c) => Patch::Value(c.to_string()),
						None => Patch::Undefined,
					},
					file_tp: match source.file_tp.as_deref() {
						Some(s) => Patch::Value(s.to_string()),
						None => Patch::Undefined,
					},
					tags: match source.tags.as_deref() {
						Some(t) => {
							let cleaned: Vec<String> = t
								.iter()
								.map(|s| s.as_ref().trim().to_string())
								.filter(|s| !s.is_empty())
								.collect();
							if cleaned.is_empty() { Patch::Null } else { Patch::Value(cleaned) }
						}
						None => Patch::Undefined,
					},
					preset: match source.preset.as_deref() {
						Some(p) => Patch::Value(p.to_string()),
						None => Patch::Undefined,
					},
					x: match &source.x {
						Some(v) => Patch::Value(v.clone()),
						None => Patch::Undefined,
					},
					broken: Patch::Null,
					..Default::default()
				};
				app.meta_adapter.update_file_data(tn_id, &file_id, &opts).await?;
			}
			// Source server populated access_level → cache it; otherwise preserve
			// whatever we already had (older peer servers may omit the field).
			match source_access_level {
				Some(lv) => match access_level_to_perm_char(lv) {
					Some(ch) => Patch::Value(ch),
					None => Patch::Null, // source says "no access" — clear cache
				},
				None => Patch::Undefined,
			}
		}
		Err(Error::NotFound | Error::Gone) => {
			if is_creator {
				let opts = meta_adapter::UpdateFileOptions {
					broken: Patch::Value(meta_adapter::BrokenReason::Deleted),
					..Default::default()
				};
				app.meta_adapter.update_file_data(tn_id, &file_id, &opts).await?;
			}
			Patch::Null // file gone — clear cached badge for this user
		}
		Err(Error::PermissionDenied) => {
			if is_creator {
				let opts = meta_adapter::UpdateFileOptions {
					broken: Patch::Value(meta_adapter::BrokenReason::Revoked),
					..Default::default()
				};
				app.meta_adapter.update_file_data(tn_id, &file_id, &opts).await?;
			}
			Patch::Null // caller's grant revoked — clear their cached badge
		}
		Err(Error::NetworkError(_) | Error::Timeout) => {
			// Transient: don't mutate the row at all. A single hiccup on the
			// source server must not flip the tombstone — that's a sticky
			// signal reserved for authoritative source responses. Surface the
			// failure to the UI via `refreshStatus` so it can show a
			// non-sticky banner that disappears on success.
			refresh_status = Some("unreachable");
			Patch::Undefined
		}
		Err(Error::Parse) => {
			// Malformed peer response is a permanent bug on the source side,
			// not a transient condition. Bubble it up as an internal error
			// rather than the tombstone-clear / unreachable banner UX.
			return Err(Error::Internal("source returned malformed metadata".into()));
		}
		Err(other) => return Err(other),
	};

	// Persist the source-reported access_level decision (skipped on transient
	// failure via Patch::Undefined). Subsequent list responses read this back
	// via the file_user_data JOIN, so the eye badge survives reloads instead
	// of being recomputed from stale FSHR actions.
	if !access_level_update.is_undefined() {
		app.meta_adapter
			.update_file_user_data(
				tn_id,
				&auth.id_tag,
				&file_id,
				Patch::Undefined, // pinned
				Patch::Undefined, // starred
				access_level_update,
			)
			.await?;
	}

	let mut view = app
		.meta_adapter
		.read_file_with_user_data(tn_id, &file_id, &auth.id_tag)
		.await?
		.ok_or(Error::NotFound)?;
	// Mirror the persisted user_data.access_level onto the top-level field so the
	// immediate response matches what subsequent list calls will return.
	view.access_level = view.user_data.as_ref().and_then(|u| u.access_level);
	let body = RefreshResponse { view, refresh_status };
	Ok((StatusCode::OK, Json(ApiResponse::new(body).with_req_id(req_id.unwrap_or_default()))))
}

/// Map an AccessLevel back to its single-char wire form for storage in
/// `file_user_data.access_level`. Mirrors [`AccessLevel::from_perm_char`].
/// `AccessLevel::None` returns `None` — the caller should clear the cache
/// rather than write a stale `'R'` badge.
fn access_level_to_perm_char(level: AccessLevel) -> Option<char> {
	match level {
		AccessLevel::None => None,
		AccessLevel::Read => Some('R'),
		AccessLevel::Comment => Some('C'),
		AccessLevel::Write | AccessLevel::Admin => Some('W'),
	}
}

async fn build_dedup_response(
	app: &App,
	tn_id: types::TnId,
	id_tag: &str,
	file_id: &str,
	req_id: Option<String>,
) -> ClResult<(StatusCode, Json<ApiResponse<serde_json::Value>>)> {
	info!("Dedup hit: file_id={}", file_id);
	app.meta_adapter.record_file_access(tn_id, id_tag, file_id).await?;

	let view = app.meta_adapter.read_file(tn_id, file_id).await?.ok_or(Error::NotFound)?;

	let mut data = serde_json::to_value(&view).unwrap_or_else(|_| json!({"fileId": file_id}));
	if let Some(obj) = data.as_object_mut() {
		obj.insert("existed".into(), serde_json::Value::Bool(true));
	}
	let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

#[expect(clippy::too_many_arguments, reason = "file processing requires multiple parameters")]
pub async fn post_file_blob(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	extract::Path((preset_name, file_name)): extract::Path<(String, String)>,
	query: Query<PostFileQuery>,
	header: axum::http::HeaderMap,
	OptionalRequestId(req_id): OptionalRequestId,
	body: Body,
) -> ClResult<(StatusCode, Json<ApiResponse<serde_json::Value>>)> {
	// Max file size constants (in MiB, using binary units)
	const BYTES_PER_MIB: usize = 1_048_576; // 1024 * 1024
	const DEFAULT_MAX_SIZE_MIB: i64 = 50;
	const DEFAULT_MAX_STREAMING_SIZE_MIB: i64 = 100;

	// Scope check: scoped tokens can only create children under the scoped root
	file_access::check_scope_allows_create(auth.scope.as_deref(), query.root_id.as_deref())?;

	let content_type = header
		.get(axum::http::header::CONTENT_TYPE)
		.and_then(|v| v.to_str().ok())
		.unwrap_or("application/octet-stream");
	info!(
		"post_file_blob: preset={}, content_type={}, root_id={:?}, parent_id={:?}",
		preset_name, content_type, query.root_id, query.parent_id
	);

	// Default visibility to 'C' (Connected) for community tenants
	let tenant_meta = app.meta_adapter.read_tenant(tn_id).await?;
	let visibility = match query.visibility {
		Some(v) => Some(v),
		None if matches!(tenant_meta.typ, meta_adapter::ProfileType::Community) => Some('C'),
		None => None,
	};

	// Validate root_id if provided - the root file must exist and be a top-level file
	if let Some(ref root_id) = query.root_id {
		let root_file =
			app.meta_adapter.read_file(tn_id, root_id).await?.ok_or_else(|| {
				Error::ValidationError(format!("root file '{}' not found", root_id))
			})?;
		if root_file.root_id.is_some() {
			return Err(Error::ValidationError(
				"root_id must reference a top-level file (not a file that itself has a root_id)"
					.into(),
			));
		}
	}

	// 1. Get preset (or default)
	let preset = presets::get(&preset_name).unwrap_or_else(presets::default);

	// 2. Map content-type to media class
	let media_class = VariantClass::from_content_type(content_type);

	// 3. Validate against preset's allowed classes
	let media_class = match media_class {
		Some(class) if preset.allowed_media_classes.contains(&class) => class,
		Some(class) => {
			return Err(Error::ValidationError(format!(
				"preset '{}' does not allow {:?} uploads",
				preset.name, class
			)));
		}
		None if preset.allowed_media_classes.contains(&VariantClass::Raw) => VariantClass::Raw,
		None => return Err(Error::ValidationError("unsupported media type".into())),
	};

	info!("Media class: {:?}", media_class);

	let max_size_mib = app
		.settings
		.get_int(tn_id, "file.max_file_size_mb")
		.await
		.unwrap_or(DEFAULT_MAX_SIZE_MIB)
		.max(1); // Ensure at least 1 MiB

	let max_size_bytes = usize::try_from(max_size_mib).unwrap_or(50) * BYTES_PER_MIB;

	let max_streaming_mib = app
		.settings
		.get_int(tn_id, "file.max_streaming_file_size_mb")
		.await
		.unwrap_or(DEFAULT_MAX_STREAMING_SIZE_MIB)
		.max(1);
	let max_streaming_bytes =
		u64::try_from(max_streaming_mib).unwrap_or(100) * BYTES_PER_MIB as u64;

	// 4. Route to handler - some need bytes (in-memory), some need streaming Body
	match media_class {
		// In-memory processing (small files)
		VariantClass::Visual => {
			let bytes = to_bytes(body, max_size_bytes).await?;
			let orig_variant_id = hasher::hash("b", &bytes);
			info!("Content id: {} ({} bytes)", orig_variant_id, bytes.len());

			// Detect if this is an SVG (check content-type or content itself)
			let is_svg = content_type == "image/svg+xml"
				|| (content_type == "application/octet-stream" && svg::is_svg(&bytes));

			// Get dimensions - SVG uses different parsing
			let dim = if is_svg {
				svg::parse_svg_dimensions(&bytes)?
			} else {
				image::get_image_dimensions(&bytes).await?
			};
			info!("Image dimensions: {}/{} (SVG: {})", dim.0, dim.1, is_svg);

			let f_id = app
				.meta_adapter
				.create_file(
					tn_id,
					meta_adapter::CreateFile {
						preset: Some(preset_name.clone().into()),
						orig_variant_id: Some(orig_variant_id),
						creator_tag: Some(auth.id_tag.clone()),
						content_type: if is_svg {
							"image/svg+xml".into()
						} else {
							content_type.into()
						},
						file_name: file_name.into(),
						file_tp: Some("BLOB".into()),
						created_at: query.created_at,
						tags: query.tags.as_ref().map(|s| s.split(',').map(Into::into).collect()),
						x: Some(json!({ "dim": dim })),
						root_id: query.root_id.clone().map(Into::into),
						parent_id: query.effective_parent_id()?.map(Into::into),
						visibility,
						..Default::default()
					},
				)
				.await?;

			match f_id {
				meta_adapter::FileId::FId(f_id) => {
					// Route to SVG or raster image handler
					let data = if is_svg {
						handle_post_svg(&app, tn_id, f_id, &bytes, &preset).await?
					} else {
						handle_post_image(&app, tn_id, f_id, content_type, &bytes, &preset).await?
					};
					let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());
					Ok((StatusCode::CREATED, Json(response)))
				}
				meta_adapter::FileId::FileId(file_id) => {
					return build_dedup_response(&app, tn_id, &auth.id_tag, &file_id, req_id).await;
				}
			}
		}

		VariantClass::Document => {
			let bytes = to_bytes(body, max_size_bytes).await?;
			let orig_variant_id = hasher::hash("b", &bytes);
			info!("Content id: {} ({} bytes)", orig_variant_id, bytes.len());

			let f_id = app
				.meta_adapter
				.create_file(
					tn_id,
					meta_adapter::CreateFile {
						preset: Some(preset_name.clone().into()),
						orig_variant_id: Some(orig_variant_id),
						creator_tag: Some(auth.id_tag.clone()),
						content_type: content_type.into(),
						file_name: file_name.into(),
						file_tp: Some("BLOB".into()),
						created_at: query.created_at,
						tags: query.tags.as_ref().map(|s| s.split(',').map(Into::into).collect()),
						root_id: query.root_id.clone().map(Into::into),
						parent_id: query.effective_parent_id()?.map(Into::into),
						visibility,
						..Default::default()
					},
				)
				.await?;

			match f_id {
				meta_adapter::FileId::FId(f_id) => {
					let data = handle_post_pdf(&app, tn_id, f_id, &bytes).await?;
					let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());
					Ok((StatusCode::CREATED, Json(response)))
				}
				meta_adapter::FileId::FileId(file_id) => {
					return build_dedup_response(&app, tn_id, &auth.id_tag, &file_id, req_id).await;
				}
			}
		}

		// Streaming to disk (large files) - stream first so we know the orig
		// blob hash, then call create_file with `orig_variant_id` set so the
		// existing dedup branch in the meta adapter catches re-uploads.
		VariantClass::Video => {
			let temp_token = utils::random_id()?;
			let temp_path =
				app.opts.tmp_dir.join(format!("upload_{}_pending_{}", tn_id.0, temp_token));
			let (total_size, orig_blob_id) =
				stream_body_to_file(body, &temp_path, max_streaming_bytes).await?;
			let mut temp_guard = TempFileGuard::new(temp_path.clone());
			info!(
				"Video upload streamed to {:?}, size: {} bytes, content id: {}",
				temp_path, total_size, orig_blob_id
			);

			let media_info = ffmpeg::FFmpeg::probe(&temp_path)
				.map_err(|e| Error::Internal(format!("ffprobe failed: {}", e)))?;
			let resolution = media_info.video_resolution().unwrap_or((0, 0));
			let duration = media_info.duration;

			let blob_stored =
				app.settings.get_bool(tn_id, "file.store_original_vid").await.unwrap_or(false);
			if blob_stored {
				app.blob_adapter
					.create_blob_from_path(
						tn_id,
						&orig_blob_id,
						&temp_path,
						&blob_adapter::CreateBlobOptions::default(),
					)
					.await?;
			}

			let f_id = app
				.meta_adapter
				.create_file(
					tn_id,
					meta_adapter::CreateFile {
						preset: Some(preset_name.clone().into()),
						orig_variant_id: Some(orig_blob_id.clone()),
						creator_tag: Some(auth.id_tag.clone()),
						content_type: content_type.into(),
						file_name: file_name.into(),
						file_tp: Some("BLOB".into()),
						created_at: query.created_at,
						tags: query.tags.as_ref().map(|s| s.split(',').map(Into::into).collect()),
						root_id: query.root_id.clone().map(Into::into),
						parent_id: query.effective_parent_id()?.map(Into::into),
						visibility,
						..Default::default()
					},
				)
				.await?;

			match f_id {
				meta_adapter::FileId::FId(f_id) => {
					let final_temp_path =
						app.opts.tmp_dir.join(format!("upload_{}_{}", tn_id.0, f_id));
					tokio::fs::rename(&temp_path, &final_temp_path).await?;
					temp_guard.replace(final_temp_path.clone());
					let data = handle_post_video_stream(
						&app,
						tn_id,
						f_id,
						content_type,
						&final_temp_path,
						resolution,
						duration,
						&orig_blob_id,
						blob_stored,
						total_size,
						&preset,
					)
					.await?;
					// Transcode tasks consume the temp file; keep it past this request.
					temp_guard.keep();
					let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());
					Ok((StatusCode::CREATED, Json(response)))
				}
				meta_adapter::FileId::FileId(file_id) => {
					// Dedup hit: keep relying on TempFileGuard's Drop to clean up.
					return build_dedup_response(&app, tn_id, &auth.id_tag, &file_id, req_id).await;
				}
			}
		}

		VariantClass::Audio => {
			let temp_token = utils::random_id()?;
			let temp_path =
				app.opts.tmp_dir.join(format!("upload_{}_pending_{}", tn_id.0, temp_token));
			let (total_size, orig_blob_id) =
				stream_body_to_file(body, &temp_path, max_streaming_bytes).await?;
			let mut temp_guard = TempFileGuard::new(temp_path.clone());
			info!(
				"Audio upload streamed to {:?}, size: {} bytes, content id: {}",
				temp_path, total_size, orig_blob_id
			);

			let media_info = ffmpeg::FFmpeg::probe(&temp_path)
				.map_err(|e| Error::Internal(format!("ffprobe failed: {}", e)))?;
			let duration = media_info.duration;

			let blob_stored =
				app.settings.get_bool(tn_id, "file.store_original_aud").await.unwrap_or(false);
			if blob_stored {
				app.blob_adapter
					.create_blob_from_path(
						tn_id,
						&orig_blob_id,
						&temp_path,
						&blob_adapter::CreateBlobOptions::default(),
					)
					.await?;
			}

			let f_id = app
				.meta_adapter
				.create_file(
					tn_id,
					meta_adapter::CreateFile {
						preset: Some(preset_name.clone().into()),
						orig_variant_id: Some(orig_blob_id.clone()),
						creator_tag: Some(auth.id_tag.clone()),
						content_type: content_type.into(),
						file_name: file_name.into(),
						file_tp: Some("BLOB".into()),
						created_at: query.created_at,
						tags: query.tags.as_ref().map(|s| s.split(',').map(Into::into).collect()),
						root_id: query.root_id.clone().map(Into::into),
						parent_id: query.effective_parent_id()?.map(Into::into),
						visibility,
						..Default::default()
					},
				)
				.await?;

			match f_id {
				meta_adapter::FileId::FId(f_id) => {
					let final_temp_path =
						app.opts.tmp_dir.join(format!("upload_{}_{}", tn_id.0, f_id));
					tokio::fs::rename(&temp_path, &final_temp_path).await?;
					temp_guard.replace(final_temp_path.clone());
					let data = handle_post_audio_stream(
						&app,
						tn_id,
						f_id,
						content_type,
						&final_temp_path,
						duration,
						&orig_blob_id,
						blob_stored,
						total_size,
						&preset,
					)
					.await?;
					// Audio extractor task consumes the temp file; keep it past this request.
					temp_guard.keep();
					let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());
					Ok((StatusCode::CREATED, Json(response)))
				}
				meta_adapter::FileId::FileId(file_id) => {
					// Dedup hit: keep relying on TempFileGuard's Drop to clean up.
					return build_dedup_response(&app, tn_id, &auth.id_tag, &file_id, req_id).await;
				}
			}
		}

		VariantClass::Raw => {
			let temp_token = utils::random_id()?;
			let temp_path =
				app.opts.tmp_dir.join(format!("upload_{}_pending_{}", tn_id.0, temp_token));
			let (total_size, orig_blob_id) =
				stream_body_to_file(body, &temp_path, max_streaming_bytes).await?;
			let mut temp_guard = TempFileGuard::new(temp_path.clone());
			info!(
				"Raw upload streamed to {:?}, size: {} bytes, content id: {}",
				temp_path, total_size, orig_blob_id
			);

			let f_id = app
				.meta_adapter
				.create_file(
					tn_id,
					meta_adapter::CreateFile {
						preset: Some(preset_name.clone().into()),
						orig_variant_id: Some(orig_blob_id.clone()),
						creator_tag: Some(auth.id_tag.clone()),
						content_type: content_type.into(),
						file_name: file_name.into(),
						file_tp: Some("BLOB".into()),
						created_at: query.created_at,
						tags: query.tags.as_ref().map(|s| s.split(',').map(Into::into).collect()),
						root_id: query.root_id.clone().map(Into::into),
						parent_id: query.effective_parent_id()?.map(Into::into),
						visibility,
						..Default::default()
					},
				)
				.await?;

			match f_id {
				meta_adapter::FileId::FId(f_id) => {
					let final_temp_path =
						app.opts.tmp_dir.join(format!("upload_{}_{}", tn_id.0, f_id));
					tokio::fs::rename(&temp_path, &final_temp_path).await?;
					temp_guard.replace(final_temp_path.clone());
					let data = handle_post_raw_stream(
						&app,
						tn_id,
						f_id,
						content_type,
						&final_temp_path,
						&orig_blob_id,
						total_size,
					)
					.await?;
					// handle_post_raw_stream removed the temp file on success.
					temp_guard.keep();
					let response = ApiResponse::new(data).with_req_id(req_id.unwrap_or_default());
					Ok((StatusCode::CREATED, Json(response)))
				}
				meta_adapter::FileId::FileId(file_id) => {
					let _ = tokio::fs::remove_file(&temp_path).await;
					temp_guard.keep();
					return build_dedup_response(&app, tn_id, &auth.id_tag, &file_id, req_id).await;
				}
			}
		}
	}
}

/// GET /api/files/{file_id}/metadata
pub async fn get_file_metadata(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	OptionalAuth(maybe_auth): OptionalAuth,
	extract::Path(file_id): extract::Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<meta_adapter::FileView>>)> {
	let mut file = app.meta_adapter.read_file(tn_id, &file_id).await?.ok_or(Error::NotFound)?;
	// Defence in depth for anonymous callers: never expose Direct-visibility
	// metadata (creator tag, tags, x-extras) without auth. Authed callers are
	// already gated by the route-level `check_perm_file("read")` ABAC middleware.
	if maybe_auth.is_none() && file.visibility.is_none() {
		return Err(Error::NotFound);
	}
	// Compute the caller's effective access level so cross-context callers
	// (e.g. `POST /files/{id}/refresh` on a peer) can cache it. Same-tenant
	// access is already fully described by the route-level ABAC role check —
	// running `get_access_level_with_scope` for every authed request to this
	// endpoint (hit by virtually every file view) would add a needless FSHR-
	// fallback query against the actions table to the hot path. Skip it
	// unless the file is genuinely cross-tenant.
	if let Some(auth) = maybe_auth.as_ref() {
		let owner_tag = file.owner.as_ref().map_or(tenant_id_tag.as_ref(), |o| o.id_tag.as_ref());
		let is_cross_tenant = owner_tag != tenant_id_tag.as_ref();
		if is_cross_tenant {
			let ctx = file_access::FileAccessCtx {
				user_id_tag: &auth.id_tag,
				tenant_id_tag: &tenant_id_tag,
				user_roles: &auth.roles,
			};
			let level = file_access::get_access_level_with_scope(
				&app,
				tn_id,
				&file_id,
				owner_tag,
				&ctx,
				auth.scope.as_deref(),
				file.root_id.as_deref(),
			)
			.await;
			// Map AccessLevel::None → None so we don't lie about a non-grant.
			file.access_level = match level {
				AccessLevel::None => None,
				other => Some(other),
			};
		}
	}
	Ok((StatusCode::OK, Json(ApiResponse::new(file).with_req_id(req_id.unwrap_or_default()))))
}

// vim: ts=4
