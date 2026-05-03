// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

use std::path::Path;

use crate::prelude::*;
use cloudillo_types::blob_adapter;
use cloudillo_types::hasher;

pub async fn create_blob_buf(
	app: &App,
	tn_id: TnId,
	data: &[u8],
	opts: blob_adapter::CreateBlobOptions,
) -> ClResult<Box<str>> {
	let tm = std::time::SystemTime::now();
	let data_vec = data.to_vec();
	let file_id = app
		.worker
		.run(move || {
			let mut hasher = hasher::Hasher::new();
			hasher.update(&data_vec);
			hasher.finalize("b")
		})
		.await?;
	if let Ok(elapsed) = tm.elapsed() {
		info!("SHA256 elapsed: {}ms", elapsed.as_millis());
	}
	app.blob_adapter.create_blob_buf(tn_id, &file_id, data, &opts).await?;

	Ok(file_id.into_boxed_str())
}

/// Create blob from a file path by streaming it (for large files)
/// This reads the file in chunks, computes hash, and stores in blob adapter
pub async fn create_blob_from_file(
	app: &App,
	tn_id: TnId,
	file_path: &Path,
	opts: blob_adapter::CreateBlobOptions,
) -> ClResult<Box<str>> {
	let tm = std::time::SystemTime::now();

	let path = file_path.to_path_buf();
	let blob_id = app
		.worker
		.try_run(move || -> ClResult<String> {
			use std::io::Read;
			let mut file = std::fs::File::open(&path)?;
			let mut hasher = hasher::Hasher::new();
			let mut buffer = vec![0u8; 64 * 1024];
			loop {
				let n = file.read(&mut buffer)?;
				if n == 0 {
					break;
				}
				hasher.update(&buffer[..n]);
			}
			Ok(hasher.finalize("b"))
		})
		.await?;

	if let Ok(elapsed) = tm.elapsed() {
		info!("SHA256 streaming hash elapsed: {}ms", elapsed.as_millis());
	}

	app.blob_adapter
		.create_blob_from_path(tn_id, &blob_id, file_path, &opts)
		.await?;

	Ok(blob_id.into_boxed_str())
}

// vim: ts=4
