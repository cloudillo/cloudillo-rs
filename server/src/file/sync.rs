//! File synchronization from remote instances
//!
//! Provides unified file sync functionality for both action attachments
//! and profile picture synchronization.

use crate::blob_adapter::CreateBlobOptions;
use crate::core::hasher;
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
///
/// # Returns
/// Ok(SyncResult) with details of what was synced
pub async fn sync_file_variants(
	app: &App,
	tn_id: TnId,
	remote_id_tag: &str,
	file_id: &str,
	variants: Option<&[&str]>,
) -> ClResult<SyncResult> {
	let mut result = SyncResult { file_id: file_id.to_string(), ..Default::default() };

	debug!("Syncing file {} from {}", file_id, remote_id_tag);

	// 1. Fetch file descriptor from remote
	let descriptor_path = format!("/file/{}/descriptor", file_id);
	let descriptor_response: ApiResponse<String> =
		app.request.get_noauth(tn_id, remote_id_tag, &descriptor_path).await?;
	let descriptor = &descriptor_response.data;

	debug!("  fetched descriptor: {}", descriptor);

	// 2. Verify descriptor hash matches file_id
	verify_content_hash(descriptor.as_bytes(), file_id).map_err(|e| {
		error!("Descriptor hash mismatch for {}: {}", file_id, e);
		e
	})?;

	// 3. Parse descriptor to get variant info
	let parsed_variants = super::descriptor::parse_file_descriptor(descriptor)?;

	if parsed_variants.is_empty() {
		warn!("No variants found in descriptor for {}", file_id);
		return Ok(result);
	}

	// 4. Determine max variant from settings (default: "md")
	let max_variant = app
		.settings
		.get_string_opt(tn_id, "file.max_cache_variant")
		.await
		.ok()
		.flatten()
		.unwrap_or_else(|| "md".to_string());

	// 5. Filter variants to sync
	let variants_to_sync: Vec<_> = parsed_variants
		.iter()
		.filter(|v| {
			if let Some(explicit_variants) = variants {
				// Explicit variant list provided - only sync those
				explicit_variants.contains(&v.variant)
			} else {
				// Use max_cache_variant setting
				should_sync_variant(v.variant, &max_variant)
			}
		})
		.collect();

	if variants_to_sync.is_empty() {
		debug!("No variants to sync for {} after filtering", file_id);
		return Ok(result);
	}

	// 6. Create file entry in MetaAdapter (if doesn't exist)
	// Use first variant as orig_variant_id
	let first_variant = &variants_to_sync[0];
	let create_opts = CreateFile {
		orig_variant_id: first_variant.variant_id.into(),
		file_id: Some(file_id.into()),
		owner_tag: Some(remote_id_tag.into()),
		preset: "sync".into(),
		content_type: format_to_content_type(first_variant.format).into(),
		file_name: format!("synced.{}", format_to_extension(first_variant.format)).into(),
		file_tp: None,
		created_at: Some(Timestamp::now()),
		tags: None,
		x: None,
		visibility: Some('P'), // Public for synced files
	};

	// f_id is Some if we created a new file entry, None if file already exists
	// We only create variant metadata for new files
	let f_id: Option<u64> = match app.meta_adapter.create_file(tn_id, create_opts).await {
		Ok(FileId::FId(f_id)) => Some(f_id),
		Ok(FileId::FileId(_)) => {
			// File already exists - that's fine, we'll still sync blobs
			// but skip variant metadata creation (it should already exist)
			debug!("File {} already exists, syncing missing blobs only", file_id);
			None
		}
		Err(e) => {
			warn!("Failed to create file entry for {}: {}", file_id, e);
			return Err(e);
		}
	};

	// 7. Sync each variant
	for variant in variants_to_sync {
		let variant_id = variant.variant_id;
		let variant_name = variant.variant;

		// Check if blob already exists
		if app.blob_adapter.stat_blob(tn_id, variant_id).await.is_some() {
			debug!("  variant {} already exists, skipping", variant_name);
			result.skipped_variants.push(variant_name.to_string());
			continue;
		}

		// Fetch variant data from remote
		let variant_path = format!("/file/variant/{}", variant_id);
		let bytes = match app.request.get_bin(tn_id, remote_id_tag, &variant_path, false).await {
			Ok(bytes) => bytes,
			Err(e) => {
				warn!("  failed to fetch variant {}: {}", variant_name, e);
				result.failed_variants.push(variant_name.to_string());
				continue;
			}
		};

		if bytes.is_empty() {
			warn!("  variant {} returned empty data", variant_name);
			result.failed_variants.push(variant_name.to_string());
			continue;
		}

		// Verify blob hash matches variant_id
		if let Err(e) = verify_content_hash(&bytes, variant_id) {
			error!("  variant {} hash mismatch: {}", variant_name, e);
			result.failed_variants.push(variant_name.to_string());
			continue;
		}

		// Store blob
		if let Err(e) = app
			.blob_adapter
			.create_blob_buf(tn_id, variant_id, &bytes, &CreateBlobOptions::default())
			.await
		{
			warn!("  failed to store blob for variant {}: {}", variant_name, e);
			result.failed_variants.push(variant_name.to_string());
			continue;
		}

		// Create file variant record in MetaAdapter (only if we created a new file entry)
		if let Some(f_id) = f_id {
			let file_variant = FileVariant {
				variant_id,
				variant: variant_name,
				format: variant.format,
				resolution: variant.resolution,
				size: bytes.len() as u64,
				available: true,
			};

			if let Err(e) = app.meta_adapter.create_file_variant(tn_id, f_id, file_variant).await {
				warn!("  failed to create variant record for {}: {}", variant_name, e);
				// Blob is stored, just metadata failed - don't count as failed
			}
		}

		info!("  synced variant {} ({})", variant_name, variant_id);
		result.synced_variants.push(variant_name.to_string());
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
