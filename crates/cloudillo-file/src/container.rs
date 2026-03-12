//! Container cache for zip-based app packages.
//!
//! Parses zip central directory on first access, caches entry metadata,
//! and serves individual files by wrapping raw deflate data in gzip envelope.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::prelude::*;

/// Metadata for a single entry within a zip container
#[derive(Debug, Clone)]
pub struct ZipEntryInfo {
	/// Byte offset to the start of compressed data within the blob
	pub data_offset: u64,
	/// Size of compressed data in bytes
	pub compressed_size: u64,
	/// Size of uncompressed data in bytes
	pub uncompressed_size: u64,
	/// CRC-32 checksum of uncompressed data
	pub crc32: u32,
	/// Whether the entry uses deflate compression (vs stored)
	pub is_deflated: bool,
	/// MIME type inferred from file extension
	pub content_type: Box<str>,
}

/// Parsed zip index for a container blob
#[derive(Debug)]
pub struct ZipIndex {
	/// Map from normalized file path to entry metadata
	pub entries: HashMap<Box<str>, ZipEntryInfo>,
}

/// Cache of parsed container indexes, keyed by blob_id
#[derive(Debug, Default)]
pub struct ContainerCache {
	entries: RwLock<HashMap<Box<str>, Arc<ZipIndex>>>,
}

impl ContainerCache {
	pub fn new() -> Self {
		Self { entries: RwLock::new(HashMap::new()) }
	}

	/// Get a cached zip index, or load the blob and parse it on cache miss
	///
	/// The `load_blob` closure is only called if the index is not cached,
	/// avoiding full-blob reads for subsequent requests.
	pub async fn get_or_parse_with<F, Fut>(
		&self,
		blob_id: &str,
		load_blob: F,
	) -> ClResult<Arc<ZipIndex>>
	where
		F: FnOnce() -> Fut,
		Fut: std::future::Future<Output = ClResult<Box<[u8]>>>,
	{
		// Fast path: check read lock
		{
			let cache = self.entries.read().await;
			if let Some(index) = cache.get(blob_id) {
				return Ok(Arc::clone(index));
			}
		}

		// Cache miss: load blob and parse
		let blob_data = load_blob().await?;
		let index = Arc::new(parse_zip_index(&blob_data)?);

		// Re-check under write lock to avoid duplicate inserts (TOCTOU)
		let mut cache = self.entries.write().await;
		if let Some(existing) = cache.get(blob_id) {
			return Ok(Arc::clone(existing));
		}
		cache.insert(blob_id.into(), Arc::clone(&index));
		Ok(index)
	}

	/// Invalidate a cached entry
	#[allow(dead_code)]
	pub async fn invalidate(&self, blob_id: &str) {
		let mut cache = self.entries.write().await;
		cache.remove(blob_id);
	}
}

/// Parse a zip file's central directory and build an index of entries
fn parse_zip_index(data: &[u8]) -> ClResult<ZipIndex> {
	let archive = rawzip::ZipArchive::from_slice(data).map_err(|e| {
		error!("Failed to parse zip archive: {}", e);
		Error::Internal(format!("Invalid zip archive: {e}"))
	})?;

	let mut entries = HashMap::new();

	for entry_result in archive.entries() {
		let entry = entry_result.map_err(|e| {
			error!("Failed to read zip entry: {}", e);
			Error::Internal(format!("Invalid zip entry: {e}"))
		})?;

		// Skip directory entries
		if entry.is_dir() {
			continue;
		}

		let normalized = entry.file_path().try_normalize().map_err(|e| {
			error!("Failed to normalize zip entry path: {}", e);
			Error::Internal(format!("Invalid zip entry path: {e}"))
		})?;
		let path: &str = normalized.as_ref();

		let is_deflated = matches!(entry.compression_method(), rawzip::CompressionMethod::Deflate);

		// Get the local entry to find data offset
		let wayfinder = entry.wayfinder();
		let local_entry = archive.get_entry(wayfinder).map_err(|e| {
			error!("Failed to read local zip entry: {}", e);
			Error::Internal(format!("Failed to read local zip entry: {e}"))
		})?;

		// Get byte range of compressed data within the blob
		let (range_start, range_end) = local_entry.compressed_data_range();

		let content_type = mime_from_path(path);

		entries.insert(
			Box::from(path),
			ZipEntryInfo {
				data_offset: range_start,
				compressed_size: range_end - range_start,
				uncompressed_size: entry.uncompressed_size_hint(),
				crc32: entry.crc32(),
				is_deflated,
				content_type,
			},
		);
	}

	Ok(ZipIndex { entries })
}

/// Wrap raw deflate data in a gzip envelope.
///
/// Gzip = 10-byte header + raw deflate data + 8-byte trailer (CRC32 + size).
/// Both CRC32 and uncompressed size are available from the zip central directory,
/// so this is a zero-computation wrapping operation.
pub fn wrap_in_gzip(deflate_data: &[u8], crc32: u32, uncompressed_size: u64) -> Vec<u8> {
	let size_mod = (uncompressed_size & 0xFFFF_FFFF) as u32;
	let mut output = Vec::with_capacity(10 + deflate_data.len() + 8);

	// Gzip header (10 bytes)
	output.extend_from_slice(&[
		0x1f, 0x8b, // Magic number
		0x08, // Compression method (deflate)
		0x00, // Flags (none)
		0x00, 0x00, 0x00, 0x00, // Modification time (zero)
		0x00, // Extra flags
		0xff, // OS (unknown)
	]);

	// Raw deflate data
	output.extend_from_slice(deflate_data);

	// Gzip trailer (8 bytes)
	output.extend_from_slice(&crc32.to_le_bytes());
	output.extend_from_slice(&size_mod.to_le_bytes());

	output
}

/// Decompress raw deflate data.
pub fn inflate(deflate_data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
	use flate2::read::DeflateDecoder;
	use std::io::Read;

	let mut decoder = DeflateDecoder::new(deflate_data);
	let mut output = Vec::new();
	decoder.read_to_end(&mut output)?;
	Ok(output)
}

/// Infer MIME type from file path extension
fn mime_from_path(path: &str) -> Box<str> {
	let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
	match ext.as_str() {
		"html" | "htm" => "text/html; charset=utf-8",
		"js" | "mjs" => "application/javascript; charset=utf-8",
		"css" => "text/css; charset=utf-8",
		"json" => "application/json; charset=utf-8",
		"svg" => "image/svg+xml",
		"png" => "image/png",
		"jpg" | "jpeg" => "image/jpeg",
		"gif" => "image/gif",
		"webp" => "image/webp",
		"avif" => "image/avif",
		"ico" => "image/x-icon",
		"woff" => "font/woff",
		"woff2" => "font/woff2",
		"ttf" => "font/ttf",
		"otf" => "font/otf",
		"wasm" => "application/wasm",
		"txt" => "text/plain; charset=utf-8",
		"xml" => "application/xml; charset=utf-8",
		"map" => "application/json",
		_ => "application/octet-stream",
	}
	.into()
}

/// Read the `cloudillo.json` manifest from zip data
pub fn read_manifest(data: &[u8]) -> ClResult<serde_json::Value> {
	let archive = rawzip::ZipArchive::from_slice(data)
		.map_err(|e| Error::Internal(format!("Invalid zip archive: {e}")))?;

	for entry_result in archive.entries() {
		let entry = entry_result.map_err(|e| Error::Internal(format!("Invalid zip entry: {e}")))?;

		let normalized = entry
			.file_path()
			.try_normalize()
			.map_err(|e| Error::Internal(format!("Invalid zip entry path: {e}")))?;
		let path: &str = normalized.as_ref();

		if path == "cloudillo.json" {
			let wayfinder = entry.wayfinder();
			let local_entry = archive
				.get_entry(wayfinder)
				.map_err(|e| Error::Internal(format!("Failed to read manifest entry: {e}")))?;

			let raw_data = local_entry.data();

			let manifest_bytes = match entry.compression_method() {
				rawzip::CompressionMethod::Store => raw_data.to_vec(),
				rawzip::CompressionMethod::Deflate => inflate(raw_data)
					.map_err(|e| Error::Internal(format!("Failed to inflate manifest: {e}")))?,
				_ => {
					return Err(Error::Internal(
						"Unsupported compression method in manifest".into(),
					));
				}
			};

			return serde_json::from_slice(&manifest_bytes)
				.map_err(|e| Error::Internal(format!("Invalid cloudillo.json: {e}")));
		}
	}

	Err(Error::Internal("cloudillo.json not found in package".into()))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_mime_from_path() {
		assert_eq!(&*mime_from_path("index.html"), "text/html; charset=utf-8");
		assert_eq!(&*mime_from_path("app.js"), "application/javascript; charset=utf-8");
		assert_eq!(&*mime_from_path("style.css"), "text/css; charset=utf-8");
		assert_eq!(&*mime_from_path("icon.svg"), "image/svg+xml");
		assert_eq!(&*mime_from_path("unknown.xyz"), "application/octet-stream");
	}

	#[test]
	fn test_gzip_wrapping() {
		let data = b"hello";
		let crc = 0x3610_a686_u32;
		let result = wrap_in_gzip(data, crc, 5);

		// Check header
		assert_eq!(&result[..2], &[0x1f, 0x8b]);
		assert_eq!(result[2], 0x08);

		// Check trailer
		let len = result.len();
		let trailer_crc = u32::from_le_bytes([
			result[len - 8],
			result[len - 7],
			result[len - 6],
			result[len - 5],
		]);
		let trailer_size = u32::from_le_bytes([
			result[len - 4],
			result[len - 3],
			result[len - 2],
			result[len - 1],
		]);
		assert_eq!(trailer_crc, crc);
		assert_eq!(trailer_size, 5);
	}
}

// vim: ts=4
