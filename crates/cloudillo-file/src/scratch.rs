// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Scratch files under `opts.tmp_dir`: where they are named, and who removes them.
//!
//! One implementation, because a hand-rolled `tmp_dir.join(format!(…))` per call site
//! is how two of them end up sharing a name — a PID or an object id is not unique
//! across a restart, and nothing sweeps `tmp_dir` at startup.
//!
//! `tmp_dir` must be a dedicated directory (default `./data/tmp`): the GC sweep removes
//! every regular file in it older than its window, whatever wrote it.

use std::path::{Path, PathBuf};

use futures::{Stream, StreamExt};
use tokio::io::AsyncWriteExt;

use crate::prelude::*;

/// A fresh scratch path under `tmp_dir`: `{tmp_dir}/{prefix}_{random_id()}{ext}`.
///
/// Random, not derived from the object being processed: nothing sweeps `tmp_dir` at
/// startup, so a leaked file must not collide with the next boot's first use of the
/// same id. `prefix` is for the operator reading `ls`; `ext` carries the leading dot
/// and is what the tools that infer a format from it (ffmpeg, `pdftoppm`) need — `""`
/// otherwise.
pub fn scratch_path(tmp_dir: &Path, prefix: &str, ext: &str) -> ClResult<PathBuf> {
	Ok(tmp_dir.join(format!("{prefix}_{}{ext}", cloudillo_types::utils::random_id()?)))
}

/// Stream `stream` into `path`, calling `on_chunk` per chunk. `Ok(None)` when more than
/// `max` bytes arrive (the partial file is removed); `Ok(Some(written))` otherwise.
pub async fn write_capped<S, B, E>(
	path: &Path,
	mut stream: S,
	max: u64,
	mut on_chunk: impl FnMut(&[u8]),
) -> ClResult<Option<u64>>
where
	S: Stream<Item = Result<B, E>> + Unpin,
	B: AsRef<[u8]>,
	Error: From<E>,
{
	let mut file = tokio::fs::File::create(path).await?;
	let mut written: u64 = 0;
	while let Some(chunk) = stream.next().await {
		let chunk = chunk?;
		let chunk = chunk.as_ref();
		written += chunk.len() as u64;
		if written > max {
			drop(file);
			let _ = tokio::fs::remove_file(path).await;
			return Ok(None);
		}
		on_chunk(chunk);
		file.write_all(chunk).await?;
	}
	file.flush().await?;
	Ok(Some(written))
}

/// Best-effort RAII cleanup for scratch files.
/// On drop, removes the file unless `keep()` was called.
pub struct TempFileGuard {
	path: PathBuf,
	keep: bool,
}

impl TempFileGuard {
	pub(crate) fn new(path: PathBuf) -> Self {
		Self { path, keep: false }
	}

	/// A fresh [`scratch_path`], guarded for removal.
	pub fn scratch(tmp_dir: &Path, prefix: &str, ext: &str) -> ClResult<Self> {
		Ok(Self::new(scratch_path(tmp_dir, prefix, ext)?))
	}

	pub fn path(&self) -> &Path {
		&self.path
	}

	pub(crate) fn replace(&mut self, path: PathBuf) {
		self.path = path;
	}

	pub fn keep(mut self) {
		self.keep = true;
	}
}

impl Drop for TempFileGuard {
	fn drop(&mut self) {
		if self.keep {
			return;
		}
		let path = std::mem::take(&mut self.path);
		let report = |path: &Path, e: std::io::Error| {
			if e.kind() != std::io::ErrorKind::NotFound {
				warn!("TempFileGuard cleanup failed for {:?}: {}", path, e);
			}
		};
		// Off a runtime (a worker thread, a runtime shutting down) `tokio::spawn` panics.
		match tokio::runtime::Handle::try_current() {
			Ok(handle) => {
				handle.spawn(async move {
					if let Err(e) = tokio::fs::remove_file(&path).await {
						report(&path, e);
					}
				});
			}
			Err(_) => {
				if let Err(e) = std::fs::remove_file(&path) {
					report(&path, e);
				}
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Two scratch paths for the same job never collide — the whole point of the
	/// random half, since a leaked file outlives the process that made it.
	#[test]
	fn a_scratch_path_is_unique_per_call() {
		let dir = Path::new("/tmp/cloudillo-test");
		let a = scratch_path(dir, "upload", "").expect("path");
		let b = scratch_path(dir, "upload", "").expect("path");
		assert_ne!(a, b);
		assert!(a.starts_with(dir));
		assert!(a.file_name().is_some_and(|n| n.to_string_lossy().starts_with("upload_")));
		// The extension is the caller's, because ffmpeg and `pdftoppm` read it.
		let png = scratch_path(dir, "pdf_thumb", ".png").expect("path");
		assert_eq!(png.extension().and_then(|e| e.to_str()), Some("png"));
	}
}

// vim: ts=4
