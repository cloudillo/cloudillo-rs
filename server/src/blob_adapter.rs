use async_trait::async_trait;
use axum::body::Bytes;
use std::{fmt::Debug, collections::HashMap, pin::Pin};
use tokio::io::AsyncRead;
use futures_core::Stream;

use crate::{
	prelude::*,
};

#[derive(Clone, Default)]
pub struct CreateBlobOptions {
	force: bool,
	public: bool,
}

#[async_trait]
pub trait BlobAdapter: Debug + Send + Sync {
	/// Creates a new blob from a buffer
	async fn create_blob_buf(&self, tn_id: u32, file_id: &str, data: &[u8], opts: &CreateBlobOptions) -> ClResult<()>;

	/// Creates a new blob using a stream
	async fn create_blob_stream(&self, tn_id: u32, file_id: &str, stream: &mut (dyn AsyncRead + Send + Unpin)) -> ClResult<()>;

	/// Reads a blob
	async fn read_blob_buf(&self, tn_id: u32, blob_id: &str) -> ClResult<Box<[u8]>>;

	/// Reads a blob
	async fn read_blob_stream(&self, tn_id: u32, blob_id: &str) -> ClResult<Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>>;
}

// vim: ts=4
