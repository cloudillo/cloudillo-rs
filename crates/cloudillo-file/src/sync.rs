// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! File synchronization from remote instances
//!
//! Provides unified file sync functionality for both action attachments
//! and profile picture synchronization.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use serde::Deserialize;

use crate::prelude::*;
use crate::variant::{Variant, VariantClass, VariantQuality};
use cloudillo_types::hasher;
use cloudillo_types::meta_adapter::{CreateFile, FileId, FileVariant};
use cloudillo_types::types::ApiResponse;

/// Lightweight struct for deserializing remote file metadata
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoteFileMetadata {
	content_type: Option<String>,
	file_name: String,
	created_at: Timestamp,
	x: Option<serde_json::Value>,
}

/// Result of a file sync operation
#[derive(Debug, Default)]
pub struct SyncResult {
	pub file_id: String,
	pub synced_variants: Vec<String>,
	pub skipped_variants: Vec<String>,
}

/// Variant size ordering for filtering by max_cache_variant setting
const VARIANT_ORDER: &[&str] = &["tn", "pf", "sd", "md", "hd", "xd"];

/// Check if a variant should be synced based on max variant setting
fn should_sync_variant(variant: &str, max_variant: &str) -> bool {
	let max_idx = VARIANT_ORDER.iter().position(|&v| v == max_variant).unwrap_or(usize::MAX);
	let var_idx = VARIANT_ORDER.iter().position(|&v| v == variant).unwrap_or(usize::MAX);
	var_idx <= max_idx
}

/// Get the sync setting key for a variant class (returns None for doc/raw - always sync)
pub fn get_sync_setting_key(class: VariantClass) -> Option<&'static str> {
	match class {
		VariantClass::Visual => Some("file.sync_max_vis"),
		VariantClass::Video => Some("file.sync_max_vid"),
		VariantClass::Audio => Some("file.sync_max_aud"),
		VariantClass::Document | VariantClass::Raw => None, // Always sync
	}
}

/// Get the default sync max for a variant class
pub fn get_default_sync_max(class: VariantClass) -> &'static str {
	match class {
		VariantClass::Video => "sd",
		VariantClass::Visual | VariantClass::Audio => "md",
		VariantClass::Document | VariantClass::Raw => "orig", // Always sync all
	}
}

/// Determine sync source based on action context
///
/// If audienceTag is set and we're not the audience, sync from audience.
/// Otherwise sync from issuer.
pub fn get_sync_source<'a>(
	tenant_tag: &str,
	audience_tag: Option<&'a str>,
	issuer_tag: &'a str,
) -> &'a str {
	match audience_tag {
		Some(aud) if aud != tenant_tag => aud,
		_ => issuer_tag,
	}
}

/// Check if we are the audience (must sync ALL variants)
pub fn is_audience(tenant_tag: &str, audience_tag: Option<&str>) -> bool {
	audience_tag.is_some_and(|aud| aud == tenant_tag)
}

/// Recover the file's primary variant class from a parsed descriptor.
///
/// The first parseable non-Original quality wins. A descriptor with only
/// `orig` (e.g., a binary archive uploaded as Raw) defaults to `Raw`.
fn primary_class(variants: &[cloudillo_types::meta_adapter::FileVariant<&str>]) -> VariantClass {
	for v in variants {
		if let Some(parsed) = Variant::parse(v.variant)
			&& parsed.quality != VariantQuality::Original
		{
			return parsed.class;
		}
	}
	VariantClass::Raw
}

/// Verify that content hash matches expected ID
///
/// IDs are formatted as `prefix~hash` (e.g., `b1~abc123`, `f1~xyz789`, `d1~...`)
/// Returns Ok(()) if hash matches, Err if mismatch
fn verify_content_hash(data: &[u8], expected_id: &str) -> ClResult<()> {
	// Extract prefix from expected ID (e.g., "b" from "b1~hash", "f" from "f1~hash")
	let prefix = expected_id
		.find('1')
		.map(|pos| &expected_id[..pos])
		.ok_or_else(|| Error::ValidationError(format!("Invalid ID format: {}", expected_id)))?;

	// Compute hash using the same hasher that generates IDs
	let computed_id = hasher::hash(prefix, data);

	if computed_id.as_ref() != expected_id {
		return Err(Error::ValidationError(format!(
			"Hash mismatch: expected {}, got {}",
			expected_id, computed_id
		)));
	}

	Ok(())
}

/// Sync file variants from a remote instance
///
/// # Arguments
/// * `app` - Application state
/// * `tn_id` - Tenant ID
/// * `remote_id_tag` - Remote instance id_tag to fetch from
/// * `file_id` - The file ID to sync
/// * `variants` - Optional list of specific variants to sync (None = all up to max setting)
/// * `auth` - Whether to use authenticated requests (true for direct-visibility files, false for public)
/// * `visibility` - Visibility character to assign to a newly created file row (None → 'D')
/// * `sync_all` - When true and `variants` is None, bypass the per-class
///   `file.sync_max_*` settings filter and sync every variant on the remote
///   descriptor. Used when the local tenant is the audience and acts as the
///   canonical mirror for downstream followers.
///
/// # Returns
/// Ok(SyncResult) with details of what was synced
#[allow(clippy::too_many_arguments)]
pub async fn sync_file_variants(
	app: &App,
	tn_id: TnId,
	remote_id_tag: &str,
	file_id: &str,
	variants: Option<&[&str]>,
	auth: bool,
	visibility: Option<char>,
	sync_all: bool,
) -> ClResult<SyncResult> {
	let mut result = SyncResult { file_id: file_id.to_string(), ..Default::default() };

	debug!("Syncing file {} from {}", file_id, remote_id_tag);

	let variant_timeout_secs = app
		.settings
		.get_int_opt(tn_id, "file.sync_variant_timeout_secs")
		.await
		.ok()
		.flatten()
		.and_then(|v| u64::try_from(v).ok())
		.unwrap_or(300);
	let variant_timeout = Duration::from_secs(variant_timeout_secs);

	// 1. Fetch file descriptor from remote
	let descriptor_path = format!("/files/{}/descriptor", file_id);
	let descriptor_response: ApiResponse<String> = if auth {
		app.request.get(tn_id, remote_id_tag, &descriptor_path).await?
	} else {
		app.request.get_noauth(tn_id, remote_id_tag, &descriptor_path).await?
	};
	let descriptor = &descriptor_response.data;

	debug!("  fetched descriptor: {}", descriptor);

	// 3. Parse descriptor to get variant info (parse first for debugging)
	let (root_id, mut parsed_variants) = super::descriptor::parse_file_descriptor(descriptor)?;

	// 2. Verify descriptor hash matches file_id
	if let Err(e) = verify_content_hash(descriptor.as_bytes(), file_id) {
		// Regenerate the descriptor from parsed pieces; if it differs from what we fetched,
		// the source's canonicalizer disagrees with ours. If it matches, the source's variants
		// table has drifted from what was hashed at finalize.
		parsed_variants.sort();
		let local_descriptor = super::descriptor::get_file_descriptor(&parsed_variants, root_id);
		let computed = hasher::hash("f", descriptor.as_bytes());
		if local_descriptor == *descriptor {
			warn!(
				"Descriptor hash mismatch for {} (computed {}, {} bytes, source produced canonical form):\n  \
				 fetched:   {}\n  error: {}",
				file_id,
				computed,
				descriptor.len(),
				descriptor,
				e
			);
		} else {
			warn!(
				"Descriptor hash mismatch for {} (computed {}, fetched {} bytes / regenerated {} bytes — formats differ):\n  \
				 fetched:    {}\n  regenerated: {}\n  error: {}",
				file_id,
				computed,
				descriptor.len(),
				local_descriptor.len(),
				descriptor,
				local_descriptor,
				e
			);
		}
		return Err(e);
	}

	if parsed_variants.is_empty() {
		warn!("No variants found in descriptor for {}", file_id);
		return Ok(result);
	}

	// Look up the file's class so the audience/non-audience filters can ask
	// `class.sync_orig()` whether the `orig` bytes should be fetched. The
	// class itself owns this policy (Visual/Video/Audio opt out; Document/Raw
	// keep the default).
	let file_class = primary_class(&parsed_variants);
	let fetch_orig_bytes = file_class.sync_orig();

	// 4. Filter variants to sync using per-class settings
	let variants_to_sync: Vec<_> = if let Some(explicit_variants) = variants {
		// Explicit variant list provided - only sync those
		parsed_variants
			.iter()
			.filter(|v| explicit_variants.contains(&v.variant))
			.collect()
	} else if sync_all {
		// Audience role: act as the canonical descriptor mirror. Fetch blob
		// bytes for every variant whose class is OK with it. Media classes
		// declare `sync_orig() = false` so we skip `orig` byte fetch — the
		// metadata row is still created below from the parsed descriptor.
		parsed_variants
			.iter()
			.filter(|v| {
				let q = Variant::parse(v.variant).map(|vp| vp.quality);
				if q == Some(VariantQuality::Original) { fetch_orig_bytes } else { true }
			})
			.collect()
	} else {
		// Use per-class sync settings
		let mut class_max_variants: HashMap<VariantClass, String> = HashMap::new();

		// Build map of class -> max_variant from settings
		for variant in &parsed_variants {
			let class = Variant::parse(variant.variant).map_or(VariantClass::Visual, |v| v.class);

			if let std::collections::hash_map::Entry::Vacant(e) = class_max_variants.entry(class)
				&& let Some(setting_key) = get_sync_setting_key(class)
			{
				let max_variant = app
					.settings
					.get_string_opt(tn_id, setting_key)
					.await
					.ok()
					.flatten()
					.unwrap_or_else(|| get_default_sync_max(class).to_string());
				e.insert(max_variant);
			}
			// For doc/raw, no entry = sync all
		}

		// Filter variants using per-class max settings
		parsed_variants
			.iter()
			.filter(|v| {
				let parsed = Variant::parse(v.variant);

				// `orig`: defer to the file's class policy.
				if parsed.map(|vp| vp.quality) == Some(VariantQuality::Original) {
					return fetch_orig_bytes;
				}

				// Non-orig variants: existing per-class max-quality logic.
				let class = parsed.map_or(VariantClass::Visual, |vp| vp.class);
				let Some(max_variant) = class_max_variants.get(&class).map(String::as_str) else {
					return true; // No setting key (Doc/Raw): sync all qualities.
				};
				let quality = parsed.map_or(v.variant, |vp| vp.quality.as_str());
				should_sync_variant(quality, max_variant)
			})
			.collect()
	};

	// Build a set of variant names that should have their content synced
	let variants_to_sync_set: HashSet<&str> = variants_to_sync.iter().map(|v| v.variant).collect();

	debug!(
		"Variants to sync content for: {:?}, total variants: {}",
		variants_to_sync_set,
		parsed_variants.len()
	);

	// 6. Check if file already exists by file_id and get its f_id
	let existing_f_id = app.meta_adapter.read_f_id_by_file_id(tn_id, file_id).await.ok();

	// Also get existing variant records to know which ones need to be created
	let existing_variants: Vec<String> = if existing_f_id.is_some() {
		app.meta_adapter
			.list_file_variants(tn_id, cloudillo_types::meta_adapter::FileId::FileId(file_id))
			.await
			.map(|v| v.iter().map(|fv| fv.variant.to_string()).collect())
			.unwrap_or_default()
	} else {
		vec![]
	};

	let (f_id, is_new_file): (Option<u64>, bool) = if let Some(f_id) = existing_f_id {
		// File already exists - use its f_id to add missing variants
		debug!("File {} already exists (f_id={}), syncing missing variants", file_id, f_id);
		(Some(f_id), false)
	} else {
		// Fetch file metadata from remote to get correct content_type and file_name
		let metadata_path = format!("/files/{}/metadata", file_id);
		let remote_meta: ApiResponse<RemoteFileMetadata> = if auth {
			app.request.get(tn_id, remote_id_tag, &metadata_path).await?
		} else {
			app.request.get_noauth(tn_id, remote_id_tag, &metadata_path).await?
		};
		let remote_file = remote_meta.data;

		// Create file entry with file_id and status='P' (pending)
		// Variants can be added to pending files, then finalize sets status='A'
		let first_variant = &parsed_variants[0];
		let create_opts = CreateFile {
			orig_variant_id: Some(first_variant.variant_id.into()),
			file_id: Some(file_id.into()),
			preset: Some("sync".into()),
			content_type: remote_file
				.content_type
				.unwrap_or_else(|| "application/octet-stream".into())
				.into(),
			file_name: remote_file.file_name.into(),
			created_at: Some(remote_file.created_at),
			visibility: Some(visibility.unwrap_or('D')),
			x: remote_file.x,
			..Default::default()
		};

		match app.meta_adapter.create_file(tn_id, create_opts).await {
			Ok(FileId::FId(f_id)) => (Some(f_id), true),
			Ok(FileId::FileId(_)) => {
				// Matched by orig_variant_id - shouldn't happen often but handle it
				debug!("File {} matched existing by orig_variant_id", file_id);
				(None, false)
			}
			Err(e) => {
				warn!("Failed to create file entry for {}: {}", file_id, e);
				return Err(e);
			}
		}
	};

	// 7. Process ALL variants from the descriptor
	// Create metadata records for all variants, but only sync content for selected ones
	for variant in &parsed_variants {
		let variant_id = variant.variant_id;
		let variant_name = variant.variant;
		let should_sync_content = variants_to_sync_set.contains(variant_name);

		// Check if this variant record already exists in the database
		let variant_record_exists = existing_variants.iter().any(|v| v == variant_name);

		if variant_record_exists {
			// Variant record already exists - skip
			debug!("  variant {} record already exists, skipping", variant_name);
			result.skipped_variants.push(variant_name.to_string());
			continue;
		}

		// Determine blob size and availability
		let (blob_size, available) = if should_sync_content {
			// This variant should have its content synced
			if let Some(size) = app.blob_adapter.stat_blob(tn_id, variant_id).await {
				// Blob already exists - use its size
				debug!("  variant {} blob already exists", variant_name);
				result.skipped_variants.push(variant_name.to_string());
				(size, true)
			} else {
				// Fetch variant data from remote
				match fetch_and_store_blob(
					app,
					tn_id,
					remote_id_tag,
					variant_id,
					variant_name,
					auth,
					variant_timeout,
				)
				.await
				{
					Ok(size) => {
						info!("  synced variant {} ({})", variant_name, variant_id);
						result.synced_variants.push(variant_name.to_string());
						(size, true)
					}
					Err(e) => {
						// Atomic sync: any fetch failure aborts. The file row
						// stays in status='P' and finalize_file is never reached.
						// The caller (ActionVerifierTask) retries with exponential
						// back-off; on the retry, variant_record_exists short-
						// circuits already-synced variants and stat_blob short-
						// circuits already-stored blobs.
						warn!("  failed to sync variant {}: {} — aborting sync", variant_name, e);
						return Err(e);
					}
				}
			}
		} else {
			// This variant is metadata-only (not syncing content)
			debug!("  variant {} metadata-only (not syncing content)", variant_name);
			result.skipped_variants.push(variant_name.to_string());
			(variant.size, false) // Use size from descriptor, mark as unavailable
		};

		// Create file variant record in MetaAdapter
		if let Some(f_id) = f_id {
			let file_variant = FileVariant {
				variant_id,
				variant: variant_name,
				format: variant.format,
				resolution: variant.resolution,
				size: blob_size,
				available,
				duration: variant.duration,
				bitrate: variant.bitrate,
				page_count: variant.page_count,
			};

			if let Err(e) = app.meta_adapter.create_file_variant(tn_id, f_id, file_variant).await {
				warn!("  failed to create variant record for {}: {}", variant_name, e);
			}
		}
	}

	// 8. Finalize the file by setting file_id (only if we created a new file entry)
	if is_new_file
		&& let Some(f_id) = f_id
		&& let Err(e) = app.meta_adapter.finalize_file(tn_id, f_id, file_id).await
	{
		warn!("Failed to finalize file {}: {}", file_id, e);
		// Variants are synced, just finalization failed
	}

	info!(
		"File sync complete for {}: {} synced, {} skipped",
		file_id,
		result.synced_variants.len(),
		result.skipped_variants.len(),
	);

	Ok(result)
}

/// Fetch a variant blob from remote and store it locally
///
/// Streams the response body straight to disk via `create_blob_stream`, so
/// large attachments (video etc.) do not have to be buffered in memory and the
/// 10s default body-collection timeout does not apply. The whole streaming
/// operation is bounded by `timeout` to guard against stalled connections.
///
/// Returns the blob size on success.
async fn fetch_and_store_blob(
	app: &App,
	tn_id: TnId,
	remote_id_tag: &str,
	variant_id: &str,
	variant_name: &str,
	auth: bool,
	timeout: Duration,
) -> ClResult<u64> {
	let variant_path = format!("/files/variant/{}", variant_id);
	let mut stream = app.request.get_stream(tn_id, remote_id_tag, &variant_path, auth).await?;

	let store_res = tokio::time::timeout(
		timeout,
		app.blob_adapter.create_blob_stream(tn_id, variant_id, &mut stream),
	)
	.await
	.map_err(|_| Error::Timeout)?;

	if let Err(e) = &store_res
		&& matches!(e, Error::ValidationError(_))
	{
		warn!("  variant {} hash mismatch or empty stream: {}", variant_name, e);
	}
	store_res?;

	let blob_size = app
		.blob_adapter
		.stat_blob(tn_id, variant_id)
		.await
		.ok_or_else(|| Error::Internal("blob disappeared after streaming write".into()))?;

	Ok(blob_size)
}

// vim: ts=4
