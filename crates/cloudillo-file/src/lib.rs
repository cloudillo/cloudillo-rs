// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! File subsystem. File storage, metadata, documents, etc.

#![allow(dead_code)]

pub mod apkg;
pub(crate) mod audio;
pub(crate) mod container;
pub mod descriptor;
pub(crate) mod duplicate;
pub(crate) mod ffmpeg;
pub mod filter;
pub mod gc;
pub mod handler;
pub mod image;
pub mod management;
pub(crate) mod pdf;
pub mod perm;
pub mod preset;
pub mod settings;
pub mod share;
pub mod site_html;
pub(crate) mod store;
pub(crate) mod svg;
pub mod sync;
pub mod tag;
pub(crate) mod variant;
pub(crate) mod video;

mod prelude;

use std::sync::Arc;

use futures::TryStreamExt;

use cloudillo_types::worker::Priority;
use container::ContainerCache;
use prelude::*;

/// What the container index knows about one entry, without reading its bytes.
///
/// Re-exported by name rather than by widening `container` to `pub`: callers
/// outside the crate need the type, not the module.
pub use container::ZipEntryInfo;

/// The size ceilings a container read is bounded by. Re-exported like [`ZipEntryInfo`]:
/// `cloudillo-site` and `cloudillo-search` reason about them in their own limits.
pub use container::{MAX_CONTAINER_BYTES, MAX_ENTRY_BYTES, MAX_MANIFEST_BYTES};

/// Create a new container cache for registration in extensions
pub fn new_container_cache() -> Arc<ContainerCache> {
	Arc::new(ContainerCache::new())
}

/// A container resolved once, and everything read out of it afterwards.
///
/// Resolution — fileId → `orig` variant id → parsed index — happens in
/// [`open_container`] and nowhere else, so serving a page cannot pay for it twice. The
/// index cache is keyed by fileId, so a warm open costs no database query.
///
/// Does **no** permission or preset check: the caller has already established that this
/// file is a container it may read. `apkg::get_container_content` runs the ABAC path;
/// `cloudillo-site` reaches its containers through the site cache.
#[derive(Debug, Clone)]
pub struct Container {
	tn_id: TnId,
	index: Arc<container::ZipIndex>,
}

/// Open a container by fileId and hand back a handle to its parsed index.
///
/// Returns [`Error::NotFound`] when the file has no `orig` variant, which is
/// what [`Container`]'s predecessors raised for the same case. A missing
/// *entry* is not an error — see [`Container::entry`].
///
/// Cold, this costs one **whole-blob** read plus one parse, both bounded: the blob by
/// [`MAX_CONTAINER_BYTES`] and the burst by the cache's single-flight gate, so
/// concurrent cold requests for one container pay for one of each between them — which
/// matters because `cloudillo-site` reaches here unauthenticated. The parse runs on
/// `priority`'s queue, like [`Container::read_bytes`] and [`Container::read_manifest`].
///
/// TODO: the whole blob is read to parse its central directory, so the ceiling is
/// [`MAX_CONTAINER_BYTES`] rather than a few KB. Range-reading the EOCD record plus the
/// central directory instead needs zip64 EOCD locator handling; `read_blob_range_stream`
/// already exists and [`Container::read_raw`] already uses it.
pub async fn open_container(
	app: &App,
	tn_id: TnId,
	file_id: &str,
	priority: Priority,
) -> ClResult<Container> {
	// A file that has not been finalised is addressed as `@<f_id>` (see
	// `descriptor.rs`), and its variant set is still being written — so the id is
	// mutable and caching an index under it would serve stale bytes later.
	let cacheable = !file_id.starts_with('@');
	let cache = app.ext::<Arc<ContainerCache>>()?;

	if cacheable && let Some(index) = cache.get(file_id) {
		return Ok(Container { tn_id, index });
	}

	// Held across the read and the parse below, so a burst of cold requests for one
	// container costs one of each. An uncacheable id has no gate: nothing would be
	// shared through the cache afterwards anyway.
	let gate = if cacheable { Some(cache.loading_gate(file_id)) } else { None };
	let _hold = match gate.as_ref() {
		Some(gate) => Some(gate.lock().await),
		None => None,
	};
	// Whoever held the gate before us filled the cache.
	if cacheable && let Some(index) = cache.get(file_id) {
		return Ok(Container { tn_id, index });
	}

	// Held across the blob read and the parse below. The gate above collapses a
	// burst on this one container; this bounds how many distinct containers may be
	// held in memory at once, which the unauthenticated serve path otherwise leaves
	// to the caller.
	let _permit = cache.load_permit().await?;

	let variants = app
		.meta_adapter
		.list_file_variants(tn_id, cloudillo_types::meta_adapter::FileId::FileId(file_id))
		.await?;
	let orig = variants.iter().find(|v| v.variant.as_ref() == "orig").ok_or(Error::NotFound)?;
	// Refused off the variant row, before the read: an upload has no size bound
	// (`DefaultBodyLimit::disable()`), so this would otherwise be an unbounded
	// allocation on an unauthenticated request.
	if orig.size > container::MAX_CONTAINER_BYTES {
		return Err(Error::ValidationError("container exceeds the maximum readable size".into()));
	}
	let variant_id: Box<str> = orig.variant_id.as_ref().into();

	let blob_data = app.blob_adapter.read_blob_buf(tn_id, &variant_id).await?;
	// CPU-bound over up to `MAX_CONTAINER_BYTES`, on the **caller's** queue — the
	// same rule `Container::read_bytes` and `Container::read_manifest` follow. A
	// page view takes `Priority::High`; the reindex sweep takes `Priority::Medium`, or
	// a sweep over a tenant's containers would queue ahead of every live render.
	let index = Arc::new(
		app.worker
			.spawn(priority, move || container::parse_zip_index(&blob_data, &variant_id))
			.await??,
	);

	if cacheable {
		cache.put(file_id, Arc::clone(&index));
	}

	Ok(Container { tn_id, index })
}

impl Container {
	/// The container's `orig` variant id — the blob its entries live in.
	pub fn variant_id(&self) -> &str {
		&self.index.variant_id
	}

	/// Look one path up in the index, without reading any bytes.
	///
	/// `None` means the container has no such entry — a 404, not an error. The
	/// result borrows out of the cached index, so nothing is cloned.
	pub fn entry(&self, path: &str) -> Option<&ZipEntryInfo> {
		self.index.entries.get(path)
	}

	/// One entry's bytes exactly as they sit in the zip.
	///
	/// Only the entry's own byte range is fetched from the blob, so reading a
	/// single fragment out of a large container costs one range read.
	pub async fn read_raw(&self, app: &App, info: &ZipEntryInfo) -> ClResult<Vec<u8>> {
		// The one place every reader of an entry's bytes goes through, so the size bound
		// lives here. Sound as a single guard: deflate does not meaningfully expand, so a
		// compressed size past the cap means an inflated size past it too, and a stored
		// entry's two sizes are the same number. `ValidationError` because it is a
		// permanent property of the entry — the search walk skips it and keeps going.
		if !info.within_read_limit() {
			return Err(Error::ValidationError(
				"container entry exceeds the maximum readable size".into(),
			));
		}

		let chunks: Vec<axum::body::Bytes> = app
			.blob_adapter
			.read_blob_range_stream(
				self.tn_id,
				self.variant_id(),
				info.data_offset,
				info.compressed_size,
			)
			.await?
			.try_collect()
			.await
			.map_err(|e| Error::Internal(format!("range read failed: {e}")))?;

		// The compressed size is known up front, so the buffer is allocated once rather
		// than grown through a concat — clamped to `MAX_ENTRY_BYTES` because that size is
		// whatever the uploader wrote into the zip header. The buffer still grows to hold
		// what the range read returns; the clamp only bounds the up-front reservation.
		let capacity =
			usize::try_from(info.compressed_size.min(container::MAX_ENTRY_BYTES)).unwrap_or(0);
		let mut raw_data = Vec::with_capacity(capacity);
		for chunk in &chunks {
			raw_data.extend_from_slice(chunk);
		}
		Ok(raw_data)
	}

	/// One entry's uncompressed bytes, up to [`MAX_ENTRY_BYTES`].
	///
	/// The bound is [`Container::read_raw`]'s, which every path into an entry's bytes
	/// shares — put there rather than here so a stored entry cannot slip past it. On top
	/// of that a deflated entry inflates under its own declared size, so a header that
	/// lies upward cannot widen the budget and an honest one narrows it. Unauthenticated
	/// callers reach this, so an entry past the cap fails one request, not the process.
	///
	/// An entry the cap refuses, and a corrupt deflate stream, come back as
	/// [`Error::ValidationError`]: both are permanent properties of the entry, so a caller
	/// walking a container can skip it and keep going. Every other failure is a transport
	/// failure and stays [`Error::Internal`], which such a caller must **not** treat as
	/// "this entry has no content".
	///
	/// `priority` is the **caller's**, like [`Container::read_manifest`]: a page view takes
	/// [`Priority::High`], the reindex sweep [`Priority::Medium`]. Never [`Priority::Low`]
	/// — that queue is for work nothing waits on, and an inflate always has a caller
	/// blocked on its result.
	pub async fn read_bytes(
		&self,
		app: &App,
		info: &ZipEntryInfo,
		priority: Priority,
	) -> ClResult<Vec<u8>> {
		let raw_data = self.read_raw(app, info).await?;
		if !info.is_deflated {
			return Ok(raw_data);
		}
		let cap = info.uncompressed_size.min(container::MAX_ENTRY_BYTES);
		// Small entries inline: a page fragment is a few kilobytes and the serve path is
		// latency-critical, so the channel round trip would cost more than the inflate.
		let inflated = if info.uncompressed_size <= container::INFLATE_INLINE_BYTES {
			container::inflate_bounded(&raw_data, cap)
		} else {
			app.worker
				.spawn(priority, move || container::inflate_bounded(&raw_data, cap))
				.await?
		};
		inflated.map_err(|e| {
			let message = format!("Failed to decompress zip entry: {e}");
			match e.kind() {
				std::io::ErrorKind::InvalidData => Error::ValidationError(message),
				_ => Error::Internal(message),
			}
		})
	}

	/// The container's `_site/manifest.json`, parsed into any projection of it, or
	/// `None` when the container has no manifest.
	///
	/// The three readers — the site handler, the site cache and the search indexer's
	/// container walk — each want a different projection of the same file. Here so the
	/// "absent", "unparseable" and "absurd" answers cannot drift apart; what a missing
	/// manifest *means* is still the caller's to decide, hence `None` rather than an error.
	///
	/// Bounded by [`MAX_MANIFEST_BYTES`] rather than the generic entry cap: this parse
	/// builds a map of every page in the site, so 32 MB of manifest is ~400k entries. Past
	/// the bound it is an [`Error::ValidationError`], which is what makes the search
	/// indexer skip an absurd manifest the way it skips an unreadable fragment.
	///
	/// `priority` is the **caller's**: a page view takes [`Priority::High`], the reindex
	/// sweep [`Priority::Medium`] — a sweep flooding the high queue would stall a live
	/// render, and [`Priority::Low`] is for work nothing waits on.
	pub async fn read_manifest<T>(&self, app: &App, priority: Priority) -> ClResult<Option<T>>
	where
		T: serde::de::DeserializeOwned + Send + 'static,
	{
		let path = cloudillo_types::site::MANIFEST_ENTRY;
		let Some(info) = self.entry(path) else { return Ok(None) };
		// The declared size first, so an absurd manifest is refused before it is
		// read; the real one after, because a header may understate.
		let too_big = |size: u64| {
			(size > container::MAX_MANIFEST_BYTES)
				.then(|| Error::ValidationError(format!("{path} is too large to parse")))
		};
		if let Some(err) = too_big(info.uncompressed_size) {
			return Err(err);
		}
		let bytes = self.read_bytes(app, info, priority).await?;
		if let Some(err) = too_big(bytes.len() as u64) {
			return Err(err);
		}

		app.worker
			.spawn(priority, move || {
				serde_json::from_slice(&bytes)
					.map(Some)
					.map_err(|e| Error::ValidationError(format!("invalid {path}: {e}")))
			})
			.await?
	}

	/// One entry as a gzip stream, or `None` when there is nothing to pass through
	/// — the caller's signal to fall back to [`Container::read_bytes`].
	///
	/// Re-wrapping the stored deflate stream in a gzip envelope is nearly free;
	/// inflating only for the client to compress again is not.
	///
	/// `None` for two cases. A **stored** entry has no deflate stream to wrap. And an entry
	/// declaring more than [`MAX_ENTRY_BYTES`] is declined here, because nothing inflates
	/// on this path and the declared size goes straight into the gzip trailer: a 1 MiB
	/// stream claiming 8 GiB would otherwise ship to any gzip client. The fallback then
	/// fails it cleanly through [`Container::read_raw`]'s bound.
	pub async fn read_gzip(&self, app: &App, info: &ZipEntryInfo) -> ClResult<Option<Vec<u8>>> {
		if !info.can_pass_through_gzip() {
			return Ok(None);
		}
		let raw_data = self.read_raw(app, info).await?;
		Ok(Some(container::wrap_in_gzip(&raw_data, info.crc32, info.uncompressed_size)))
	}
}

/// Did the client actually offer gzip?
///
/// A substring test over the raw header would read `gzip;q=0` — an explicit
/// *refusal* — as support, and would also fire on `x-gzip` and on any other token
/// that happens to contain the word. So the header is split into its entries, each
/// entry's token taken before the `;`, and an entry carrying a `q=0` parameter
/// dropped. Only an exact `gzip` token with a non-zero q counts.
///
/// Lives beside [`Container::read_gzip`] because it is the decision that gates
/// that call, and both container readers — `apkg::get_container_content` and
/// `cloudillo_site::serve` — have to make it the same way.
pub fn accepts_gzip(headers: &axum::http::HeaderMap) -> bool {
	let Some(value) =
		headers.get(axum::http::header::ACCEPT_ENCODING).and_then(|v| v.to_str().ok())
	else {
		return false;
	};
	value.split(',').any(|entry| {
		let mut parts = entry.split(';');
		let token = parts.next().unwrap_or("").trim();
		if !token.eq_ignore_ascii_case("gzip") {
			return false;
		}
		// `q=0`, `q=0.0`, `q=0.000` all mean "not acceptable"; anything else,
		// including a missing or unparseable q, leaves the entry acceptable.
		!parts.any(|param| {
			let Some((name, weight)) = param.split_once('=') else {
				return false;
			};
			name.trim().eq_ignore_ascii_case("q")
				&& weight.trim().parse::<f32>().is_ok_and(|q| q <= 0.0)
		})
	})
}

pub fn register_settings(
	registry: &mut cloudillo_core::settings::SettingsRegistry,
) -> ClResult<()> {
	settings::register_settings(registry)
}

pub fn init(app: &App) -> ClResult<()> {
	app.scheduler.register::<image::ImageResizerTask>()?;
	app.scheduler.register::<descriptor::FileIdGeneratorTask>()?;
	app.scheduler.register::<video::VideoTranscoderTask>()?;
	app.scheduler.register::<audio::AudioExtractorTask>()?;
	app.scheduler.register::<pdf::PdfProcessorTask>()?;
	app.scheduler.register::<gc::GcTask>()?;
	Ok(())
}

/// Schedule recurring file-subsystem maintenance jobs (currently the file+blob GC).
/// Call after settings have been initialized so defaults are readable.
pub async fn schedule_recurring(app: &App) -> ClResult<()> {
	gc::schedule(app).await?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use axum::http::{HeaderMap, header};

	use super::accepts_gzip;

	/// The gzip pass-through hands the client a body it has to be able to decode:
	/// a substring test would have read the explicit refusal `gzip;q=0` as support
	/// and served an undecodable envelope to a client that asked for zstd.
	#[test]
	fn gzip_is_offered_only_by_an_exact_token_with_a_non_zero_weight() {
		let accepts = |value: &str| {
			let mut headers = HeaderMap::new();
			headers.insert(header::ACCEPT_ENCODING, value.parse().expect("header"));
			accepts_gzip(&headers)
		};
		assert!(accepts("gzip"));
		assert!(accepts("gzip, deflate, br, zstd"));
		assert!(accepts("gzip;q=0.5"));
		assert!(accepts(" GZIP ;q=1.0"));
		assert!(!accepts("gzip;q=0"));
		assert!(!accepts("gzip;q=0.0"));
		assert!(!accepts("br, zstd"));
		// The word appears, but never as a token of its own.
		assert!(!accepts("x-gzip"));
		assert!(!accepts(""));
		assert!(!accepts_gzip(&HeaderMap::new()));
	}
}

// vim: ts=4
