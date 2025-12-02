use std::path::Path;

use tokio::io::AsyncReadExt;

use crate::blob_adapter;
use crate::core::hasher;
use crate::prelude::*;
use crate::types::TnId;

pub async fn create_blob_buf(
	app: &App,
	tn_id: TnId,
	data: &[u8],
	opts: blob_adapter::CreateBlobOptions,
) -> ClResult<Box<str>> {
	let tm = std::time::SystemTime::now();
	let mut hasher = hasher::Hasher::new();
	hasher.update(data);
	let file_id = hasher.finalize("b");
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

	// Open file and compute hash
	let mut file = tokio::fs::File::open(file_path).await?;
	let mut hasher = hasher::Hasher::new();
	let mut buffer = vec![0u8; 64 * 1024]; // 64KB chunks

	loop {
		let n = file.read(&mut buffer).await?;
		if n == 0 {
			break;
		}
		hasher.update(&buffer[..n]);
	}

	let blob_id = hasher.finalize("b");

	if let Ok(elapsed) = tm.elapsed() {
		info!("SHA256 streaming hash elapsed: {}ms", elapsed.as_millis());
	}

	// Read file again and store via blob adapter
	// (Could optimize with blob_adapter streaming support in future)
	let bytes = tokio::fs::read(file_path).await?;
	app.blob_adapter.create_blob_buf(tn_id, &blob_id, &bytes, &opts).await?;

	Ok(blob_id.into_boxed_str())
}

// vim: ts=4
