//! File synchronization from remote instances
//!
//! Provides unified file sync functionality for both action attachments
//! and profile picture synchronization.

use std::collections::{HashMap, HashSet};

use crate::blob_adapter::CreateBlobOptions;
use crate::core::hasher;
use crate::file::variant::{Variant, VariantClass};
use crate::meta_adapter::{CreateFile, FileId, FileVariant};
use crate::prelude::*;
use crate::types::ApiResponse;

/// Result of a file sync operation
#[derive(Debug, Default)]
pub struct SyncResult {
	pub file_id: String,
	pub synced_variants: Vec<String>,
	pub skipped_variants: Vec<String>,
	pub failed_variants: Vec<String>,
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
		VariantClass::Visual => "md",
		VariantClass::Video => "sd",
		VariantClass::Audio => "md",
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
	audience_tag.map(|aud| aud == tenant_tag).unwrap_or(false)
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
///
/// # Returns
/// Ok(SyncResult) with details of what was synced
pub async fn sync_file_variants(
	app: &App,
	tn_id: TnId,
	remote_id_tag: &str,
	file_id: &str,
	variants: Option<&[&str]>,
	auth: bool,
) -> ClResult<SyncResult> {
	let mut result = SyncResult { file_id: file_id.to_string(), ..Default::default() };

	debug!("Syncing file {} from {}", file_id, remote_id_tag);

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
	let mut parsed_variants = super::descriptor::parse_file_descriptor(descriptor)?;

	// 2. Verify descriptor hash matches file_id
	if let Err(e) = verify_content_hash(descriptor.as_bytes(), file_id) {
		// Generate local descriptor from parsed variants to compare
		parsed_variants.sort();
		let local_descriptor = super::descriptor::get_file_descriptor(&parsed_variants);
		warn!(
			"Descriptor hash mismatch for {}:\n  fetched:   {}\n  generated: {}\n  error: {}",
			file_id, descriptor, local_descriptor, e
		);
		return Err(e);
	}

	if parsed_variants.is_empty() {
		warn!("No variants found in descriptor for {}", file_id);
		return Ok(result);
	}

	// 4. Filter variants to sync using per-class settings
	let variants_to_sync: Vec<_> = if let Some(explicit_variants) = variants {
		// Explicit variant list provided - only sync those
		parsed_variants
			.iter()
			.filter(|v| explicit_variants.contains(&v.variant))
			.collect()
	} else {
		// Use per-class sync settings
		let mut class_max_variants: HashMap<VariantClass, String> = HashMap::new();

		// Build map of class -> max_variant from settings
		for variant in &parsed_variants {
			let class =
				Variant::parse(variant.variant).map(|v| v.class).unwrap_or(VariantClass::Visual);

			if let std::collections::hash_map::Entry::Vacant(e) = class_max_variants.entry(class) {
				if let Some(setting_key) = get_sync_setting_key(class) {
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
		}

		// Filter variants using per-class max settings
		parsed_variants
			.iter()
			.filter(|v| {
				let class =
					Variant::parse(v.variant).map(|vp| vp.class).unwrap_or(VariantClass::Visual);

				// Doc/Raw always sync (no setting key)
				let Some(max_variant) = class_max_variants.get(&class).map(|s| s.as_str()) else {
					return true; // No limit = sync all
				};

				let quality =
					Variant::parse(v.variant).map(|vp| vp.quality.as_str()).unwrap_or(v.variant);

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
			.list_file_variants(tn_id, crate::meta_adapter::FileId::FileId(file_id))
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
		// Create file entry with file_id and status='P' (pending)
		// Variants can be added to pending files, then finalize sets status='A'
		// Use first variant from parsed_variants (always available) for file creation
		let first_variant = &parsed_variants[0];
		let create_opts = CreateFile {
			orig_variant_id: Some(first_variant.variant_id.into()),
			file_id: Some(file_id.into()), // Set file_id (enables deduplication)
			parent_id: None,
			owner_tag: None, // Owned by tenant, not remote user
			preset: Some("sync".into()),
			content_type: format_to_content_type(first_variant.format).into(),
			file_name: format!("synced.{}", format_to_extension(first_variant.format)).into(),
			file_tp: None,
			created_at: Some(Timestamp::now()),
			tags: None,
			x: None,
			visibility: Some('D'), // Direct visibility for synced files
			status: None,          // Default to 'P' (pending)
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
			let blob_exists = app.blob_adapter.stat_blob(tn_id, variant_id).await.is_some();

			if blob_exists {
				// Blob already exists - use its size
				let size = app.blob_adapter.stat_blob(tn_id, variant_id).await.unwrap_or(0);
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
				)
				.await
				{
					Ok(size) => {
						info!("  synced variant {} ({})", variant_name, variant_id);
						result.synced_variants.push(variant_name.to_string());
						(size, true)
					}
					Err(e) => {
						warn!("  failed to sync variant {}: {}", variant_name, e);
						result.failed_variants.push(variant_name.to_string());
						continue; // Skip creating record for failed fetches
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
				duration: None,
				bitrate: None,
				page_count: None,
			};

			if let Err(e) = app.meta_adapter.create_file_variant(tn_id, f_id, file_variant).await {
				warn!("  failed to create variant record for {}: {}", variant_name, e);
			}
		}
	}

	// 8. Finalize the file by setting file_id (only if we created a new file entry)
	if is_new_file {
		if let Some(f_id) = f_id {
			if let Err(e) = app.meta_adapter.finalize_file(tn_id, f_id, file_id).await {
				warn!("Failed to finalize file {}: {}", file_id, e);
				// Variants are synced, just finalization failed
			}
		}
	}

	info!(
		"File sync complete for {}: {} synced, {} skipped, {} failed",
		file_id,
		result.synced_variants.len(),
		result.skipped_variants.len(),
		result.failed_variants.len()
	);

	Ok(result)
}

/// Fetch a variant blob from remote and store it locally
///
/// Returns the blob size on success
async fn fetch_and_store_blob(
	app: &App,
	tn_id: TnId,
	remote_id_tag: &str,
	variant_id: &str,
	variant_name: &str,
	auth: bool,
) -> ClResult<u64> {
	let variant_path = format!("/files/variant/{}", variant_id);
	let bytes = app.request.get_bin(tn_id, remote_id_tag, &variant_path, auth).await?;

	if bytes.is_empty() {
		warn!("  variant {} returned empty data", variant_name);
		return Err(Error::ValidationError("empty variant data".into()));
	}

	// Verify blob hash matches variant_id
	verify_content_hash(&bytes, variant_id).map_err(|e| {
		error!("  variant {} hash mismatch: {}", variant_name, e);
		e
	})?;

	let blob_size = bytes.len() as u64;

	// Store blob
	app.blob_adapter
		.create_blob_buf(tn_id, variant_id, &bytes, &CreateBlobOptions::default())
		.await
		.map_err(|e| {
			warn!("  failed to store blob for variant {}: {}", variant_name, e);
			e
		})?;

	Ok(blob_size)
}

/// Convert format string to content type
fn format_to_content_type(format: &str) -> &'static str {
	match format.to_lowercase().as_str() {
		"webp" => "image/webp",
		"avif" => "image/avif",
		"jpeg" | "jpg" => "image/jpeg",
		"png" => "image/png",
		"gif" => "image/gif",
		_ => "application/octet-stream",
	}
}

/// Convert format string to file extension
fn format_to_extension(format: &str) -> &'static str {
	match format.to_lowercase().as_str() {
		"webp" => "webp",
		"avif" => "avif",
		"jpeg" | "jpg" => "jpg",
		"png" => "png",
		"gif" => "gif",
		_ => "bin",
	}
}

// vim: ts=4
