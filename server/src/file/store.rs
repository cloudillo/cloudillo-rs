use base64::Engine;
use sha2::{Sha256, Digest};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::prelude::*;
use crate::App;
use crate::blob_adapter;
use crate::types::TnId;

pub async fn create_blob_buf(app: &App, tn_id: TnId, data: &[u8], opts: blob_adapter::CreateBlobOptions) -> ClResult<Box<str>> {
	let tm = std::time::SystemTime::now();
	let mut hasher = Sha256::new();
	hasher.update(data);
	let file_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());
	info!("SHA256 elapsed: {}ms", tm.elapsed().unwrap().as_millis());
	app.blob_adapter.create_blob_buf(tn_id, &file_id, data, &opts).await?;

	Ok(file_id.into_boxed_str())
}

pub async fn create_blob_stream(app: App, tn_id: TnId, data: &mut dyn AsyncRead, opts: blob_adapter::CreateBlobOptions) -> ClResult<Box<str>> {
	todo!()
}

// vim: ts=4
