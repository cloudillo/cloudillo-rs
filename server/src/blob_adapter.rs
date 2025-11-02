//! Adapter that manages and stores blobs (immutable file data)
use async_trait::async_trait;
use axum::body::Bytes;
use futures_core::Stream;
use std::{fmt::Debug, pin::Pin};
use tokio::io::AsyncRead;

use crate::prelude::*;

#[derive(Clone, Default)]
pub struct CreateBlobOptions {
	force: bool,
	public: bool,
}

pub struct BlobStat {
	pub size: u64,
}

#[async_trait]
pub trait BlobAdapter: Debug + Send + Sync {
	/// Creates a new blob from a buffer
	async fn create_blob_buf(
		&self,
		tn_id: TnId,
		file_id: &str,
		data: &[u8],
		opts: &CreateBlobOptions,
	) -> ClResult<()>;

	/// Creates a new blob using a stream
	async fn create_blob_stream(
		&self,
		tn_id: TnId,
		file_id: &str,
		stream: &mut (dyn AsyncRead + Send + Unpin),
	) -> ClResult<()>;

	/// Stats a blob
	async fn stat_blob(&self, tn_id: TnId, blob_id: &str) -> Option<u64>;

	/// Reads a blob
	async fn read_blob_buf(&self, tn_id: TnId, blob_id: &str) -> ClResult<Box<[u8]>>;

	/// Reads a blob
	async fn read_blob_stream(
		&self,
		tn_id: TnId,
		blob_id: &str,
	) -> ClResult<Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>>;
}

// vim: ts=4
