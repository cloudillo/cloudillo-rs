use std::{
	fmt::Debug,
	path::{Path, PathBuf},
	pin::Pin,
};

use async_trait::async_trait;
use futures_core::Stream;
use tokio::{
	fs::{create_dir_all, metadata, remove_file, rename, File},
	io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
};
use tokio_util::{bytes::Bytes, io::ReaderStream};

use cloudillo::{blob_adapter, core::hasher, prelude::*, types::TnId};

/// Calculates the path of the directory for a blob
fn obj_dir(base_dir: &Path, tn_id: TnId, file_id: &str) -> ClResult<PathBuf> {
	let hash_start = file_id.find('~').ok_or(Error::Parse)? + 1;
	if file_id.len() < hash_start + 4 {
		Err(Error::Parse)?
	};

	Ok(PathBuf::from(base_dir)
		.join(tn_id.to_string())
		.join(&file_id[hash_start..hash_start + 2])
		.join(&file_id[hash_start + 2..hash_start + 4]))
}

fn obj_file_path(base_dir: &Path, tn_id: TnId, file_id: &str) -> ClResult<PathBuf> {
	let hash_start = file_id.find('~').ok_or(Error::Parse)? + 1;
	if file_id.len() < hash_start + 5 {
		Err(Error::Parse)?
	};

	Ok(PathBuf::from(base_dir)
		.join(tn_id.to_string())
		.join(&file_id[hash_start..hash_start + 2])
		.join(&file_id[hash_start + 2..hash_start + 4])
		.join(file_id))
}

fn obj_tmp_file_path(base_dir: &Path, tn_id: TnId, file_id: &str) -> ClResult<PathBuf> {
	let tmp_id = format!("tmp-{}", cloudillo::core::utils::random_id()?);
	let hash_start = file_id.find('~').ok_or(Error::Parse)? + 1;
	if file_id.len() < hash_start + 5 {
		Err(Error::Parse)?
	};

	Ok(PathBuf::from(base_dir).join(tn_id.to_string()).join(&tmp_id))
}

#[derive(Debug)]
pub struct BlobAdapterFs {
	base_dir: Box<Path>,
}

impl BlobAdapterFs {
	pub async fn new(base_dir: Box<Path>) -> Result<Self, Error> {
		create_dir_all(&base_dir).await?;
		Ok(Self { base_dir })
	}
}

#[async_trait]
impl blob_adapter::BlobAdapter for BlobAdapterFs {
	/// Creates a new blob from a buffer
	async fn create_blob_buf(
		&self,
		tn_id: TnId,
		file_id: &str,
		data: &[u8],
		_opts: &blob_adapter::CreateBlobOptions,
	) -> ClResult<()> {
		info!("create_blob_buf: {:?}", obj_file_path(&self.base_dir, tn_id, file_id)?);
		create_dir_all(obj_dir(&self.base_dir, tn_id, file_id)?).await?;

		let mut file = File::create(obj_file_path(&self.base_dir, tn_id, file_id)?).await?;
		file.write_all(data).await?;
		file.sync_all().await?;

		Ok(())
	}

	/// Creates a new blob using a stream
	async fn create_blob_stream(
		&self,
		tn_id: TnId,
		file_id: &str,
		stream: &mut (dyn AsyncRead + Send + Unpin),
	) -> ClResult<()> {
		create_dir_all(obj_dir(&self.base_dir, tn_id, file_id)?).await?;

		let tmp_path = obj_tmp_file_path(&self.base_dir, tn_id, file_id)?;
		info!("  attachment tmpfile: {:?}", &tmp_path);
		let mut file = File::create(&tmp_path).await?;
		let mut hasher = hasher::Hasher::new();
		let mut buf = [0u8; 8192];

		let res = async {
			loop {
				let n = stream.read(&mut buf).await?;
				if n == 0 {
					break;
				}
				file.write_all(&buf[0..n]).await?;
				hasher.update(&buf[0..n]);
			}
			let id = hasher.finalize("b");

			rename(&tmp_path, obj_file_path(&self.base_dir, tn_id, &id)?).await?;
			info!("  attachment downloaded, check: {} ?= {}", &id, &file_id);
			Ok::<(), Error>(())
		}
		.await;
		if res.is_err() {
			info!("  attachment download failed, removing tmpfile: {:?}", &tmp_path);
			remove_file(&tmp_path).await?;
		}

		Ok(())
	}

	/// Checks if a blob exists, returns its size
	async fn stat_blob(&self, tn_id: TnId, blob_id: &str) -> Option<u64> {
		let path = obj_file_path(&self.base_dir, tn_id, blob_id).ok()?;
		let file_metadata = metadata(&path).await.ok()?;
		Some(file_metadata.len())
	}

	/// Reads a blob
	async fn read_blob_buf(&self, tn_id: TnId, blob_id: &str) -> ClResult<Box<[u8]>> {
		let mut file = File::open(obj_file_path(&self.base_dir, tn_id, blob_id)?).await?;
		let mut buf: Vec<u8> = Vec::new();
		file.read_to_end(&mut buf).await?;

		Ok(buf.into_boxed_slice())
	}

	/// Reads a blob
	async fn read_blob_stream(
		&self,
		tn_id: TnId,
		blob_id: &str,
	) -> ClResult<Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>> {
		info!("path: {:?}", obj_file_path(&self.base_dir, tn_id, blob_id)?);
		let file = File::open(obj_file_path(&self.base_dir, tn_id, blob_id)?)
			.await
			.map_err(|_| Error::NotFound)?;
		let stream = ReaderStream::new(file);

		Ok(Box::pin(stream))
	}
}

#[cfg(test)]
mod test {
	use std::path::{Path, PathBuf};

	use crate::obj_dir;
	use cloudillo::types::TnId;

	#[test]
	fn test_obj_dir() {
		let file_id = "f1~1234567890";
		let dir = obj_dir(Path::new("some_dir"), TnId(42), file_id).unwrap_or_default();
		assert_eq!(dir, PathBuf::from("some_dir/42/12/34"));
	}
}

// vim: ts=4
