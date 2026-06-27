// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

use std::{
	fmt::Debug,
	path::{Path, PathBuf},
	pin::Pin,
};

use async_trait::async_trait;
use futures_core::Stream;
use tokio::{
	fs::{File, create_dir_all, metadata, read_dir, remove_dir_all, remove_file, rename},
	io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
};
use tokio_util::{bytes::Bytes, io::ReaderStream};

use cloudillo_types::{blob_adapter, hasher, prelude::*};

/// Validates that a file_id hash portion contains only safe characters (base64url alphabet)
fn validate_hash(hash: &str) -> ClResult<()> {
	if !hash.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
		return Err(Error::ValidationError("invalid characters in file_id hash".into()));
	}
	Ok(())
}

/// Calculates the path of the directory for a blob
fn obj_dir(base_dir: &Path, tn_id: TnId, file_id: &str) -> ClResult<PathBuf> {
	let hash_start = file_id.find('~').ok_or(Error::Parse)? + 1;
	if file_id.len() < hash_start + 4 {
		Err(Error::Parse)?;
	}
	validate_hash(&file_id[hash_start..])?;

	Ok(PathBuf::from(base_dir)
		.join(tn_id.to_string())
		.join(&file_id[hash_start..hash_start + 2])
		.join(&file_id[hash_start + 2..hash_start + 4]))
}

fn obj_file_path(base_dir: &Path, tn_id: TnId, file_id: &str) -> ClResult<PathBuf> {
	let hash_start = file_id.find('~').ok_or(Error::Parse)? + 1;
	if file_id.len() < hash_start + 5 {
		Err(Error::Parse)?;
	}
	validate_hash(&file_id[hash_start..])?;

	Ok(PathBuf::from(base_dir)
		.join(tn_id.to_string())
		.join(&file_id[hash_start..hash_start + 2])
		.join(&file_id[hash_start + 2..hash_start + 4])
		.join(file_id))
}

fn obj_tmp_file_path(base_dir: &Path, tn_id: TnId, file_id: &str) -> ClResult<PathBuf> {
	let tmp_id = format!("tmp-{}", cloudillo_types::utils::random_id()?);
	let hash_start = file_id.find('~').ok_or(Error::Parse)? + 1;
	if file_id.len() < hash_start + 5 {
		Err(Error::Parse)?;
	}
	validate_hash(&file_id[hash_start..])?;

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

			if id != file_id {
				return Err(Error::ValidationError(format!(
					"blob hash mismatch: expected {}, got {}",
					file_id, id
				)));
			}
			rename(&tmp_path, obj_file_path(&self.base_dir, tn_id, &id)?).await?;
			info!("  attachment downloaded: {}", &id);
			Ok::<(), Error>(())
		}
		.await;
		if let Err(e) = res {
			info!("  attachment download failed, removing tmpfile: {:?}", &tmp_path);
			let _ = remove_file(&tmp_path).await;
			return Err(e);
		}

		Ok(())
	}

	/// Checks if a blob exists, returns its size and mtime
	async fn stat_blob(&self, tn_id: TnId, blob_id: &str) -> Option<blob_adapter::BlobStat> {
		let path = obj_file_path(&self.base_dir, tn_id, blob_id).ok()?;
		let file_metadata = metadata(&path).await.ok()?;
		let modified_at = file_metadata
			.modified()
			.ok()
			.and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
			.and_then(|d| i64::try_from(d.as_secs()).ok())
			.unwrap_or(0);
		Some(blob_adapter::BlobStat { size: file_metadata.len(), modified_at })
	}

	/// Reads a blob
	async fn read_blob_buf(&self, tn_id: TnId, blob_id: &str) -> ClResult<Box<[u8]>> {
		let mut file = File::open(obj_file_path(&self.base_dir, tn_id, blob_id)?).await?;
		let mut buf: Vec<u8> = Vec::new();
		file.read_to_end(&mut buf).await?;

		Ok(buf.into_boxed_slice())
	}

	/// Reads a byte range from a blob as a stream (no full buffering).
	async fn read_blob_range_stream(
		&self,
		tn_id: TnId,
		blob_id: &str,
		offset: u64,
		length: u64,
	) -> ClResult<Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>> {
		use tokio::io::AsyncSeekExt;

		let mut file = File::open(obj_file_path(&self.base_dir, tn_id, blob_id)?)
			.await
			.map_err(|_| Error::NotFound)?;
		file.seek(std::io::SeekFrom::Start(offset))
			.await
			.map_err(|e| Error::Internal(format!("blob range seek failed: {e}")))?;
		let stream = ReaderStream::new(file.take(length));
		Ok(Box::pin(stream))
	}

	/// Reads a blob
	async fn read_blob_stream(
		&self,
		tn_id: TnId,
		blob_id: &str,
	) -> ClResult<Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>> {
		debug!("path: {:?}", obj_file_path(&self.base_dir, tn_id, blob_id)?);
		let file = File::open(obj_file_path(&self.base_dir, tn_id, blob_id)?)
			.await
			.map_err(|_| Error::NotFound)?;
		let stream = ReaderStream::new(file);

		Ok(Box::pin(stream))
	}

	async fn create_blob_from_path(
		&self,
		tn_id: TnId,
		file_id: &str,
		source: &Path,
		_opts: &blob_adapter::CreateBlobOptions,
	) -> ClResult<()> {
		create_dir_all(obj_dir(&self.base_dir, tn_id, file_id)?).await?;
		tokio::fs::copy(source, obj_file_path(&self.base_dir, tn_id, file_id)?).await?;
		Ok(())
	}

	async fn delete_tenant_blobs(&self, tn_id: TnId) -> ClResult<()> {
		let tenant_dir = PathBuf::from(self.base_dir.as_ref()).join(tn_id.to_string());

		match remove_dir_all(&tenant_dir).await {
			Ok(()) => Ok(()),
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
			Err(e) => Err(Error::from(e)),
		}
	}

	async fn delete_blob(&self, tn_id: TnId, blob_id: &str) -> ClResult<()> {
		let path = obj_file_path(&self.base_dir, tn_id, blob_id)?;
		match remove_file(&path).await {
			Ok(()) => {
				// Best-effort prune of now-empty shard dirs. `remove_dir` fails
				// with `DirectoryNotEmpty` (or, on some platforms, `Other` /
				// `ENOTEMPTY`) when siblings still exist; we ignore every
				// error here — leaving an empty dir is harmless, and racing
				// with a concurrent `create_dir_all` is fine because the
				// next blob write will recreate the path.
				if let (Some(leaf), Some(mid)) =
					(path.parent(), path.parent().and_then(|p| p.parent()))
				{
					let _ = tokio::fs::remove_dir(leaf).await;
					let _ = tokio::fs::remove_dir(mid).await;
				}
				Ok(())
			}
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
			Err(e) => Err(Error::from(e)),
		}
	}

	async fn cleanup_tmp_files(&self, tn_id: TnId, cutoff_secs: i64) -> ClResult<u64> {
		let tenant_dir = PathBuf::from(self.base_dir.as_ref()).join(tn_id.to_string());
		let mut rd = match read_dir(&tenant_dir).await {
			Ok(rd) => rd,
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
			Err(e) => return Err(Error::from(e)),
		};
		let mut removed: u64 = 0;
		while let Some(entry) = rd.next_entry().await.map_err(Error::from)? {
			let name = entry.file_name();
			let Some(name) = name.to_str() else {
				continue;
			};
			if !name.starts_with("tmp-") {
				continue;
			}
			let ft = entry.file_type().await.map_err(Error::from)?;
			if !ft.is_file() {
				continue;
			}
			let Ok(md) = entry.metadata().await else {
				continue;
			};
			let mtime = md
				.modified()
				.ok()
				.and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
				.and_then(|d| i64::try_from(d.as_secs()).ok())
				.unwrap_or(0);
			if mtime > cutoff_secs {
				continue;
			}
			match remove_file(entry.path()).await {
				Ok(()) => removed += 1,
				Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
				Err(e) => warn!("blob-gc: tmp cleanup failed for {:?}: {}", entry.path(), e),
			}
		}
		Ok(removed)
	}

	async fn list_blobs(
		&self,
		tn_id: TnId,
	) -> ClResult<Pin<Box<dyn Stream<Item = ClResult<String>> + Send>>> {
		let tenant_dir = PathBuf::from(self.base_dir.as_ref()).join(tn_id.to_string());
		let stream = async_stream::try_stream! {
			let mut outer = match read_dir(&tenant_dir).await {
				Ok(rd) => rd,
				Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
				Err(e) => Err(Error::from(e))?,
			};
			while let Some(lvl1) = outer.next_entry().await.map_err(Error::from)? {
				if !lvl1.file_type().await.map_err(Error::from)?.is_dir() {
					continue;
				}
				let mut inner = read_dir(lvl1.path()).await.map_err(Error::from)?;
				while let Some(lvl2) = inner.next_entry().await.map_err(Error::from)? {
					if !lvl2.file_type().await.map_err(Error::from)?.is_dir() {
						continue;
					}
					let mut leaf = read_dir(lvl2.path()).await.map_err(Error::from)?;
					while let Some(entry) = leaf.next_entry().await.map_err(Error::from)? {
						if !entry.file_type().await.map_err(Error::from)?.is_file() {
							continue;
						}
						if let Some(name) = entry.file_name().to_str() {
							// `tmp-*` artifacts live above the shard dirs
							// (see `create_blob_stream`), not at the leaf, so
							// they cannot reach this loop — the previous skip
							// here was dead code. `cleanup_tmp_files` handles
							// those separately.
							yield name.to_string();
						}
					}
				}
			}
		};
		Ok(Box::pin(stream))
	}
}

#[cfg(test)]
mod test {
	use std::path::{Path, PathBuf};

	use crate::obj_dir;
	use cloudillo_types::types::TnId;

	#[test]
	fn test_obj_dir() {
		let file_id = "f1~1234567890";
		let dir = obj_dir(Path::new("some_dir"), TnId(42), file_id).unwrap_or_default();
		assert_eq!(dir, PathBuf::from("some_dir/42/12/34"));
	}

	#[test]
	fn test_path_traversal_rejected() {
		let malicious_id = "f1~../../etc/passwd";
		assert!(obj_dir(Path::new("some_dir"), TnId(42), malicious_id).is_err());
	}

	#[test]
	fn test_slash_in_hash_rejected() {
		let malicious_id = "f1~ab/cd/evil";
		assert!(obj_dir(Path::new("some_dir"), TnId(42), malicious_id).is_err());
	}

	#[tokio::test]
	async fn test_read_blob_range_stream() {
		use crate::BlobAdapterFs;
		use cloudillo_types::blob_adapter::{BlobAdapter, CreateBlobOptions};
		use futures::TryStreamExt;

		let dir = tempfile::tempdir().unwrap();
		let adapter = BlobAdapterFs::new(dir.path().into()).await.unwrap();

		let blob_id = "b1~abcdefghij";
		let data: Vec<u8> = (0u8..32).collect();
		adapter
			.create_blob_buf(TnId(7), blob_id, &data, &CreateBlobOptions::default())
			.await
			.unwrap();

		// Read bytes [4, 12) — offset 4, length 8.
		let chunks: Vec<_> = adapter
			.read_blob_range_stream(TnId(7), blob_id, 4, 8)
			.await
			.unwrap()
			.try_collect()
			.await
			.unwrap();
		let read: Vec<u8> = chunks.concat();
		assert_eq!(read, data[4..12]);
	}
}

// vim: ts=4
