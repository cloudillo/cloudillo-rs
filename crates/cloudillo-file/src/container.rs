// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Container cache for zip-based app packages.
//!
//! Parses zip central directory on first access, caches entry metadata,
//! and serves individual files by wrapping raw deflate data in gzip envelope.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;

use lru::LruCache;

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
	/// MIME type inferred from file extension. Every value `mime_from_path`
	/// can return is a literal, so this costs no allocation per entry.
	pub content_type: &'static str,
}

impl ZipEntryInfo {
	/// Is this entry within the size this server will read at all?
	///
	/// The compressed size, because that is the one bound holding for **every** entry:
	/// deflate does not meaningfully expand, so a compressed size past the cap means an
	/// inflated size past it too, and a stored entry's two sizes are the same number.
	/// Checking the declared *uncompressed* size would let a stored entry through.
	///
	/// Applied in `Container::read_raw`, which every reader of an entry's bytes goes
	/// through.
	pub fn within_read_limit(&self) -> bool {
		self.compressed_size <= MAX_ENTRY_BYTES
	}

	/// May this entry go out as a gzip envelope around its stored deflate stream?
	///
	/// A stored entry has no deflate stream to wrap. A deflated one declaring more
	/// than [`crate::MAX_ENTRY_BYTES`] is refused because nothing inflates on that path:
	/// the declared size goes straight into the gzip trailer, so a 1 MiB stream
	/// claiming 8 GiB would ship to any client that sent `Accept-Encoding: gzip`.
	pub fn can_pass_through_gzip(&self) -> bool {
		self.is_deflated && self.uncompressed_size <= MAX_ENTRY_BYTES
	}
}

/// Parsed zip index for a container blob
#[derive(Debug)]
pub struct ZipIndex {
	/// Map from normalized file path to entry metadata
	pub entries: HashMap<Box<str>, ZipEntryInfo>,
	/// The `orig` variant id this index was parsed from — the blob its entries
	/// live in. Cached alongside the index so a warm request never has to ask
	/// the database how a fileId resolves to a variant.
	pub variant_id: Box<str>,
}

/// Default LRU capacity. An index holds parsed offsets only, never entry bytes: a few
/// hundred entries × ~100 bytes ≈ 30 KB per container, so 128 indexes ≈ 4 MB. The `None`
/// fallback is unreachable (128 is non-zero) but coded as `NonZeroUsize::MIN`.
const DEFAULT_CAPACITY: NonZeroUsize = match NonZeroUsize::new(128) {
	Some(n) => n,
	None => NonZeroUsize::MIN,
};

/// Concurrent **cold** container loads allowed across the whole process.
///
/// A cold load holds a whole blob in memory — up to [`MAX_CONTAINER_BYTES`] — on an
/// unauthenticated path, so without a cap the peak is a client's to choose.
/// `loading_gate` collapses a burst on *one* container; this bounds how many distinct
/// ones are in flight. Warm opens never touch it.
const MAX_CONCURRENT_LOADS: usize = 4;

/// Cache of parsed container indexes, keyed by the container's **fileId**.
///
/// A fileId is a hash of the file descriptor, so it names one immutable `orig` blob for
/// all time and a key is never reused. Keying here rather than by variant id lets a warm
/// request skip the `files JOIN file_variants` lookup entirely: the variant id rides
/// inside the cached [`ZipIndex`].
///
/// A file that has not been finalised is addressed as `@<f_id>`, and that id is
/// **mutable** — `open_container` bypasses the cache for those.
///
/// LRU-bounded: every publish that changes bytes mints a new fileId, so an unbounded map
/// would grow by one index per publish and never shed one. Eviction needs no
/// invalidation — a miss just re-reads and re-parses the blob.
///
/// Uses `parking_lot::Mutex` (no poisoning) because `LruCache::get` mutates recency
/// state. The guard is never held across an await.
#[derive(Debug)]
pub struct ContainerCache {
	entries: parking_lot::Mutex<LruCache<Box<str>, Arc<ZipIndex>>>,
	/// One gate per container being loaded, so N concurrent cold requests for one
	/// container cost one blob read and one parse instead of N. See
	/// [`ContainerCache::loading_gate`].
	loading: parking_lot::Mutex<HashMap<Box<str>, Arc<tokio::sync::Mutex<()>>>>,
	/// Permits for a cold load. See [`MAX_CONCURRENT_LOADS`].
	loads: tokio::sync::Semaphore,
}

impl Default for ContainerCache {
	fn default() -> Self {
		Self::new()
	}
}

impl ContainerCache {
	pub fn new() -> Self {
		Self::with_capacity(DEFAULT_CAPACITY)
	}

	pub fn with_capacity(capacity: NonZeroUsize) -> Self {
		Self {
			entries: parking_lot::Mutex::new(LruCache::new(capacity)),
			loading: parking_lot::Mutex::new(HashMap::new()),
			loads: tokio::sync::Semaphore::new(MAX_CONCURRENT_LOADS),
		}
	}

	/// The gate a cold open holds while it reads the blob and parses the index.
	///
	/// Everyone asking for the same container waits on the same gate and finds the index
	/// in the cache when it opens, so a burst of concurrent first requests costs one blob
	/// read and one parse. That matters because the path reaching here is
	/// **unauthenticated**, so N is whatever a client chooses.
	///
	/// A `tokio::sync::Mutex` because the guard is held across an await; the map around it
	/// is the sync one, and is never held across one.
	///
	/// Gates nothing waits on any more are swept here rather than released by the winner,
	/// which would have to release on every error path out of the load.
	pub fn loading_gate(&self, file_id: &str) -> Arc<tokio::sync::Mutex<()>> {
		let mut map = self.loading.lock();
		map.retain(|_, gate| Arc::strong_count(gate) > 1);
		Arc::clone(
			map.entry(file_id.into())
				.or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
		)
	}

	/// A permit for one cold load, awaited before the blob read. See
	/// [`MAX_CONCURRENT_LOADS`].
	pub async fn load_permit(&self) -> ClResult<tokio::sync::SemaphorePermit<'_>> {
		self.loads
			.acquire()
			.await
			.map_err(|_| Error::Internal("Container load semaphore closed".into()))
	}

	/// Get a cached index by fileId. A hit also promotes it to most-recently-used.
	pub fn get(&self, file_id: &str) -> Option<Arc<ZipIndex>> {
		self.entries.lock().get(file_id).map(Arc::clone)
	}

	/// Store a parsed index under its container's fileId.
	///
	/// Two requests racing the same cold container would both parse and insert an equal
	/// index — correct but wasteful on an unauthenticated path. [`Self::loading_gate`]
	/// collapses the race to one read and one parse.
	pub fn put(&self, file_id: &str, index: Arc<ZipIndex>) {
		self.entries.lock().put(file_id.into(), index);
	}

	/// Invalidate a cached entry
	#[allow(dead_code)]
	pub fn invalidate(&self, file_id: &str) {
		self.entries.lock().pop(file_id);
	}
}

/// Parse a zip file's central directory and build an index of entries
pub fn parse_zip_index(data: &[u8], variant_id: &str) -> ClResult<ZipIndex> {
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

		// Only the two methods this reader can honour. Anything else — bzip2, zstd,
		// lzma — would be indistinguishable from a stored entry downstream and get
		// served byte for byte under its inferred `Content-Type`: garbage, silently.
		let method = entry.compression_method();
		let is_deflated = if method == rawzip::CompressionMethod::DEFLATE {
			true
		} else if method == rawzip::CompressionMethod::STORE {
			false
		} else {
			// Left out of the index rather than failing the container: such an entry must
			// never be served, but it must not take every other page of the site with it.
			// A missing index entry is a 404 for that path alone.
			warn!(%path, %method, "Skipping container entry with unsupported compression");
			continue;
		};

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

	Ok(ZipIndex { entries, variant_id: variant_id.into() })
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

/// Largest entry this server will inflate out of a container.
///
/// A container entry is a page fragment, a manifest or a feed; nothing legitimate
/// approaches this. Without a cap, `inflate` is an unauthenticated memory-exhaustion
/// vector — the zip header's declared size is attacker-controlled.
pub const MAX_ENTRY_BYTES: u64 = 32 * 1024 * 1024;

/// Largest container blob this server will open.
///
/// `open_container` reads the whole blob to parse its central directory, and uploads
/// carry `DefaultBodyLimit::disable()`, so without this an unbounded upload becomes an
/// unbounded allocation on an unauthenticated request. Well clear of any real container —
/// a published document is fragments and media references, not the media itself.
pub const MAX_CONTAINER_BYTES: u64 = 256 * 1024 * 1024;

/// Largest `_site/manifest.json` this server will parse.
///
/// Deliberately far below [`MAX_ENTRY_BYTES`]: the manifest is a page index, and
/// deserializing it builds a `HashMap` plus a sorted `Vec` of everything in it.
/// At 32 MB that is ~400k entries built on a worker thread for one page view.
pub const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;

/// Below this, an entry inflates inline rather than on the worker pool.
///
/// A page fragment is a few kilobytes and the serve path is latency-critical, so a
/// channel round trip per fragment would cost more than the inflate. Above it the work
/// is worth a hop: [`MAX_ENTRY_BYTES`] of deflate is real CPU time.
pub const INFLATE_INLINE_BYTES: u64 = 64 * 1024;

/// Decompress raw deflate data, refusing anything past `max_output` bytes.
pub fn inflate_bounded(deflate_data: &[u8], max_output: u64) -> Result<Vec<u8>, std::io::Error> {
	use flate2::read::DeflateDecoder;
	use std::io::Read;

	// One byte past the cap is read on purpose: it is what tells an entry that
	// exactly fills the budget from one that overruns it.
	let mut decoder = DeflateDecoder::new(deflate_data).take(max_output.saturating_add(1));
	let mut output = Vec::new();
	decoder.read_to_end(&mut output)?;
	if output.len() as u64 > max_output {
		return Err(std::io::Error::new(
			std::io::ErrorKind::InvalidData,
			"container entry exceeds the maximum inflated size",
		));
	}
	Ok(output)
}

/// Infer MIME type from file path extension
fn mime_from_path(path: &str) -> &'static str {
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
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_mime_from_path() {
		assert_eq!(mime_from_path("index.html"), "text/html; charset=utf-8");
		assert_eq!(mime_from_path("app.js"), "application/javascript; charset=utf-8");
		assert_eq!(mime_from_path("style.css"), "text/css; charset=utf-8");
		assert_eq!(mime_from_path("icon.svg"), "image/svg+xml");
		assert_eq!(mime_from_path("unknown.xyz"), "application/octet-stream");
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

	fn deflate(data: &[u8]) -> Vec<u8> {
		use flate2::{Compression, write::DeflateEncoder};
		use std::io::Write;

		let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
		encoder.write_all(data).expect("deflate");
		encoder.finish().expect("deflate finish")
	}

	fn info(compressed: u64, uncompressed: u64, is_deflated: bool) -> ZipEntryInfo {
		ZipEntryInfo {
			data_offset: 0,
			compressed_size: compressed,
			uncompressed_size: uncompressed,
			crc32: 0,
			is_deflated,
			content_type: "text/plain",
		}
	}

	/// The cap has to sit on the compressed size — the one number that bounds every
	/// entry. On the inflate call it would miss a **stored** entry entirely.
	#[test]
	fn an_oversized_entry_is_refused_whether_or_not_it_is_deflated() {
		let cap = MAX_ENTRY_BYTES;
		assert!(info(cap, cap, false).within_read_limit());
		assert!(info(cap, cap, true).within_read_limit());
		assert!(!info(cap + 1, cap + 1, false).within_read_limit());
		assert!(!info(cap + 1, cap * 100, true).within_read_limit());
		// A header lying *downward* about the inflated size cannot buy a bigger
		// read: the compressed size is what is checked.
		assert!(!info(cap + 1, 10, true).within_read_limit());
	}

	/// Nothing inflates on the gzip pass-through — the declared size is copied straight
	/// into the trailer — so an oversized entry is declined here, not bounded downstream.
	#[test]
	fn the_gzip_pass_through_declines_a_declared_size_past_the_cap() {
		let cap = MAX_ENTRY_BYTES;
		assert!(info(1024, cap, true).can_pass_through_gzip());
		assert!(!info(1024, cap + 1, true).can_pass_through_gzip());
		// A stored entry has no deflate stream to wrap, whatever its size.
		assert!(!info(1024, 1024, false).can_pass_through_gzip());
	}

	/// A minimal one-entry zip, so the compression method in both headers is ours to
	/// choose. `data` is stored verbatim: the method field is a claim, and what is under
	/// test is whether the parser believes it.
	fn one_entry_zip(method: u16, name: &str, data: &[u8]) -> Vec<u8> {
		let name = name.as_bytes();
		let size = u32::try_from(data.len()).expect("small");
		let mut out = Vec::new();

		// Local file header.
		out.extend_from_slice(&0x0403_4b50_u32.to_le_bytes());
		out.extend_from_slice(&20_u16.to_le_bytes()); // version needed
		out.extend_from_slice(&0_u16.to_le_bytes()); // flags
		out.extend_from_slice(&method.to_le_bytes());
		out.extend_from_slice(&0_u32.to_le_bytes()); // mod time + date
		out.extend_from_slice(&0_u32.to_le_bytes()); // crc32
		out.extend_from_slice(&size.to_le_bytes()); // compressed
		out.extend_from_slice(&size.to_le_bytes()); // uncompressed
		out.extend_from_slice(&u16::try_from(name.len()).expect("short").to_le_bytes());
		out.extend_from_slice(&0_u16.to_le_bytes()); // extra len
		out.extend_from_slice(name);
		out.extend_from_slice(data);

		// Central directory.
		let cd_offset = u32::try_from(out.len()).expect("small");
		out.extend_from_slice(&0x0201_4b50_u32.to_le_bytes());
		out.extend_from_slice(&20_u16.to_le_bytes()); // version made by
		out.extend_from_slice(&20_u16.to_le_bytes()); // version needed
		out.extend_from_slice(&0_u16.to_le_bytes()); // flags
		out.extend_from_slice(&method.to_le_bytes());
		out.extend_from_slice(&0_u32.to_le_bytes()); // mod time + date
		out.extend_from_slice(&0_u32.to_le_bytes()); // crc32
		out.extend_from_slice(&size.to_le_bytes()); // compressed
		out.extend_from_slice(&size.to_le_bytes()); // uncompressed
		out.extend_from_slice(&u16::try_from(name.len()).expect("short").to_le_bytes());
		out.extend_from_slice(&0_u16.to_le_bytes()); // extra len
		out.extend_from_slice(&0_u16.to_le_bytes()); // comment len
		out.extend_from_slice(&0_u16.to_le_bytes()); // disk number
		out.extend_from_slice(&0_u16.to_le_bytes()); // internal attrs
		out.extend_from_slice(&0_u32.to_le_bytes()); // external attrs
		out.extend_from_slice(&0_u32.to_le_bytes()); // local header offset
		out.extend_from_slice(name);

		// End of central directory.
		let cd_size = u32::try_from(out.len()).expect("small") - cd_offset;
		out.extend_from_slice(&0x0605_4b50_u32.to_le_bytes());
		out.extend_from_slice(&0_u32.to_le_bytes()); // disk numbers
		out.extend_from_slice(&1_u16.to_le_bytes()); // entries on this disk
		out.extend_from_slice(&1_u16.to_le_bytes()); // entries total
		out.extend_from_slice(&cd_size.to_le_bytes());
		out.extend_from_slice(&cd_offset.to_le_bytes());
		out.extend_from_slice(&0_u16.to_le_bytes()); // comment len
		out
	}

	/// A method this reader cannot decode must not parse as *stored*, or its bytes go out
	/// compressed under the `Content-Type` inferred from the name.
	#[test]
	fn a_compression_method_this_reader_cannot_honour_is_left_out_of_the_index() {
		let stored = one_entry_zip(0, "index.html", b"<p>hi</p>");
		let index = parse_zip_index(&stored, "v1").expect("stored parses");
		let entry = index.entries.get("index.html").expect("entry");
		assert!(!entry.is_deflated);

		// 93 is zstd; 12 is bzip2. Neither has a decoder here.
		for method in [93_u16, 12] {
			let blob = one_entry_zip(method, "index.html", b"<p>hi</p>");
			let index = parse_zip_index(&blob, "v1").expect("container still parses");
			assert!(index.entries.is_empty(), "method {method}");
		}
	}

	/// The declared uncompressed size comes off the zip header, so this cap is all that
	/// stands between a crafted entry and the heap — and one that exactly fills the budget
	/// is still legitimate.
	#[test]
	fn an_entry_that_inflates_past_the_cap_is_refused() {
		let compressed = deflate(&vec![b'a'; 1024]);

		let exact = inflate_bounded(&compressed, 1024).expect("at the cap");
		assert_eq!(exact.len(), 1024);
		assert!(inflate_bounded(&compressed, 2048).is_ok());
		assert!(inflate_bounded(&compressed, 1023).is_err());
		assert!(inflate_bounded(&compressed, 0).is_err());
	}
}

// vim: ts=4
