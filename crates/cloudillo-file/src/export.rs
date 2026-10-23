// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Per-tenant bulk export (`/api/export`, `/api/admin/tenants/{id_tag}/export`).
//!
//! A request queues [`ExportTask`], which writes one ZIP to `opts.tmp_dir`:
//!
//! - `files/<folder>/…/<name>` — the original blob of every live local file (no trash, no
//!   system-managed files, no mirrored copies of remote files)
//! - `documents/<file_id>.json` — every CRDT and RTDB document as JSON
//! - `actions.json` — the tenant's own actions, with their signed tokens
//! - `profile.json` — the tenant profile
//! - `FORMATS.md` — this layout, for the person opening the archive
//!
//! State lives next to the ZIP in a status sidecar, both under fixed names (see
//! [`zip_path`]). One export per tenant at a time; the ZIP is deleted on its first download,
//! and is unavailable 24 h after it was requested.

use std::collections::{HashMap, HashSet};
use std::io::{BufWriter, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use axum::{
	Json,
	body::Body,
	extract::{ConnectInfo, Path as AxPath, State},
	http::{HeaderValue, StatusCode, header},
	response::Response,
};
use futures::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::runtime::Handle;

use crate::prelude::*;
use cloudillo_core::{
	Auth, audit,
	extract::{IdTag, OptionalRequestId},
	scheduler::{Task, TaskId},
};
use cloudillo_types::{
	auth_adapter::AuditCategory,
	blob_adapter::BlobRef,
	meta_adapter::{FileId, ListActionOptions, ListFileOptions, MAX_PARENT_DEPTH},
	types::{ApiResponse, CursorData, serialize_timestamp_iso},
};

/// How long an export stays available after it was requested.
const EXPORT_TTL_SECS: i64 = 86_400;

/// Page size for the cursor-paged file and action listings.
const PAGE: u32 = 500;

const FORMATS_MD: &str = "\
# Cloudillo export

- `files/` — the original of every file in your drive, under its folder path. Trash, \
system-managed files (post attachments, profile pictures) and copies of files shared with you \
from other servers are not included. Two files with the same path in the same folder: the \
second is prefixed with its entry id.
- `documents/<fileId>.json` — every collaborative document (CRDT) and database (RTDB) as JSON:
  `{fileId, fileName, fileTp, contentType, path, data}`. `data` maps `<collection>/<docId>` to
  the stored value. For a CRDT document a root map is a collection keyed by its keys, a root
  array is keyed by position, and a text root is one entry `_` with `{t: text, h: first line}`.
  The meaning of each collection is defined by the app that owns the `contentType`.
- `actions.json` — the actions (posts, comments, reactions, …) you issued, newest first, in
  the API's action format; `token` is the signed original.
- `profile.json` — your profile (`idTag`, `name`, `type`, pictures, extra fields).
";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportState {
	Pending,
	Ready,
	Failed,
}

/// `GET /api/export` body; also the on-disk status sidecar.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportStatus {
	pub status: ExportState,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub size: Option<u64>,
}

/// See [`AppState::export_path`](cloudillo_core::app::AppState::export_path).
///
/// `tmp_dir` is swept by the GC scratch sweep (`file.gc_scratch_window_secs`, a day
/// by default), which is also what removes an export nobody downloads. A window set below a
/// day shortens the export's life with it; a dedicated sweep if that matters.
fn zip_path(app: &App, tn_id: TnId) -> PathBuf {
	app.export_path(tn_id, "zip")
}

fn status_path(app: &App, tn_id: TnId) -> PathBuf {
	app.export_path(tn_id, "json")
}

async fn remove_quiet(path: &Path) {
	if let Err(e) = tokio::fs::remove_file(path).await
		&& e.kind() != std::io::ErrorKind::NotFound
	{
		warn!("export: removing {:?} failed: {}", path, e);
	}
}

/// The tenant's export, or `None` if there is none or it has expired (and is removed here).
async fn read_status(app: &App, tn_id: TnId) -> ClResult<Option<ExportStatus>> {
	let raw = match tokio::fs::read(status_path(app, tn_id)).await {
		Ok(raw) => raw,
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
		Err(e) => return Err(e.into()),
	};
	let status: ExportStatus = serde_json::from_slice(&raw)?;
	if Timestamp::now().0.saturating_sub(status.created_at.0) > EXPORT_TTL_SECS {
		app.remove_export(tn_id).await;
		return Ok(None);
	}
	Ok(Some(status))
}

async fn write_status(app: &App, tn_id: TnId, status: &ExportStatus) -> ClResult<()> {
	tokio::fs::write(status_path(app, tn_id), serde_json::to_vec(status)?).await?;
	Ok(())
}

/// Queue an export. `Conflict` while one is still pending; a ready or failed one is replaced.
async fn request_export(app: &App, tn_id: TnId) -> ClResult<ExportStatus> {
	if read_status(app, tn_id).await?.is_some_and(|s| s.status == ExportState::Pending) {
		return Err(Error::Conflict("an export is already in progress".into()));
	}
	remove_quiet(&zip_path(app, tn_id)).await;
	let status =
		ExportStatus { status: ExportState::Pending, created_at: Timestamp::now(), size: None };
	write_status(app, tn_id, &status).await?;
	let scheduled = app
		.scheduler
		.task(Arc::new(ExportTask { tn_id, created_at: status.created_at }))
		.key(format!("file.export:{}", tn_id.0))
		.now()
		.await;
	if let Err(e) = scheduled {
		app.remove_export(tn_id).await;
		return Err(e);
	}
	Ok(status)
}

/// POST /api/export - Queue an export of the tenant's data
pub async fn post_export(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Auth(auth): Auth,
	IdTag(id_tag): IdTag,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<ExportStatus>>)> {
	cloudillo_core::abac::require_tenant_account(&auth, &id_tag)?;
	let status = request_export(&app, auth.tn_id).await?;
	audit::record_event(
		&app,
		AuditCategory::Admin,
		"export.request",
		"success",
		Some(auth.tn_id),
		Some(&auth.id_tag),
		&addr,
		None,
	)
	.await;
	info!(tn_id = ?auth.tn_id, "Export requested");
	Ok((
		StatusCode::ACCEPTED,
		Json(ApiResponse::new(status).with_req_id(req_id.unwrap_or_default())),
	))
}

/// POST /api/admin/tenants/{id_tag}/export - Queue an export for a tenant (SADM). The tenant's
/// owner downloads it.
pub async fn post_admin_export(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Auth(auth): Auth,
	AxPath(id_tag): AxPath<String>,
) -> ClResult<(StatusCode, Json<ApiResponse<ExportStatus>>)> {
	let tn_id = app.auth_adapter.read_tn_id(&id_tag).await?;
	let status = request_export(&app, tn_id).await?;
	audit::record_event(
		&app,
		AuditCategory::Admin,
		"export.request",
		"success",
		Some(tn_id),
		Some(&auth.id_tag),
		&addr,
		Some(serde_json::json!({ "idTag": id_tag })),
	)
	.await;
	info!(tn_id = ?tn_id, id_tag = %id_tag, "Export requested by admin");
	Ok((StatusCode::ACCEPTED, Json(ApiResponse::new(status))))
}

/// GET /api/export - Status of the tenant's export (404 when there is none)
pub async fn get_export(
	State(app): State<App>,
	Auth(auth): Auth,
	IdTag(id_tag): IdTag,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<ExportStatus>>)> {
	cloudillo_core::abac::require_tenant_account(&auth, &id_tag)?;
	let status = read_status(&app, auth.tn_id).await?.ok_or(Error::NotFound)?;
	Ok((StatusCode::OK, Json(ApiResponse::new(status).with_req_id(req_id.unwrap_or_default()))))
}

/// GET /api/export/download - Stream the ready ZIP, once (404 unless ready)
pub async fn get_export_download(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Auth(auth): Auth,
	IdTag(id_tag): IdTag,
) -> ClResult<Response> {
	cloudillo_core::abac::require_tenant_account(&auth, &id_tag)?;
	let tn_id = auth.tn_id;
	if !read_status(&app, tn_id).await?.is_some_and(|s| s.status == ExportState::Ready) {
		return Err(Error::NotFound);
	}
	let file = tokio::fs::File::open(zip_path(&app, tn_id))
		.await
		.map_err(|_| Error::NotFound)?;
	let size = file.metadata().await?.len();
	// One download: unlinked now, the open handle keeps streaming it.
	// An interrupted download loses the export and the owner requests a new one.
	// Delete at end of stream if that bites.
	app.remove_export(tn_id).await;
	audit::record_event(
		&app,
		AuditCategory::Admin,
		"export.download",
		"success",
		Some(tn_id),
		Some(&auth.id_tag),
		&addr,
		Some(serde_json::json!({ "size": size })),
	)
	.await;

	let body = Body::from_stream(tokio_util::io::ReaderStream::with_capacity(file, 64 * 1024));
	let mut res = Response::new(body);
	let headers = res.headers_mut();
	headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/zip"));
	headers.insert(
		header::CONTENT_DISPOSITION,
		HeaderValue::from_static("attachment; filename=\"cloudillo-export.zip\""),
	);
	headers.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
	headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
	Ok(res)
}

/// Builds one tenant's export ZIP. Queued by [`request_export`], keyed per tenant.
/// `created_at` names the request it serves: a task left over from an earlier request
/// must not finish a later one.
#[derive(Debug)]
pub struct ExportTask {
	tn_id: TnId,
	created_at: Timestamp,
}

#[async_trait]
impl Task<App> for ExportTask {
	fn kind() -> &'static str {
		"file.export"
	}
	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		let (tn_id, ts) = ctx
			.split_once(':')
			.ok_or_else(|| Error::ValidationError("invalid export task context".into()))?;
		Ok(Arc::new(ExportTask { tn_id: TnId(tn_id.parse()?), created_at: Timestamp(ts.parse()?) }))
	}

	fn serialize(&self) -> String {
		format!("{}:{}", self.tn_id.0, self.created_at.0)
	}

	/// Failure is reported through the status, not a scheduler retry: the owner sees `failed`
	/// and asks again.
	async fn run(&self, app: &App) -> ClResult<()> {
		let tn_id = self.tn_id;
		let is_mine =
			|s: &ExportStatus| s.status == ExportState::Pending && s.created_at == self.created_at;
		if !read_status(app, tn_id).await?.is_some_and(|s| is_mine(&s)) {
			return Ok(());
		}
		let part = app.export_path(tn_id, &format!("{}.part", self.created_at.0));
		let built = build_zip(app, tn_id, part.clone()).await;
		let Some(mut status) = read_status(app, tn_id).await?.filter(is_mine) else {
			// Removed or replaced while building (tenant purge, expiry, a new request).
			remove_quiet(&part).await;
			return Ok(());
		};
		let built = match built {
			Ok(size) => tokio::fs::rename(&part, zip_path(app, tn_id))
				.await
				.map(|()| size)
				.map_err(Into::into),
			Err(e) => Err(e),
		};
		match built {
			Ok(size) => {
				info!(tn_id = ?tn_id, size, "Export ready");
				status.status = ExportState::Ready;
				status.size = Some(size);
			}
			Err(e) => {
				warn!(tn_id = ?tn_id, error = %e, "Export failed");
				remove_quiet(&part).await;
				status.status = ExportState::Failed;
			}
		}
		write_status(app, tn_id, &status).await
	}
}

/// rawzip writes to a sync `Write`, and the build waits on blob reads for its whole length, so
/// it runs on tokio's blocking pool and drives the async adapter calls with `block_on` — a
/// worker-pool slot would sit idle on I/O while CPU jobs queue behind it. The CRDT replay
/// inside still goes to `run_slow`.
async fn build_zip(app: &App, tn_id: TnId, path: PathBuf) -> ClResult<u64> {
	let id_tag = app.auth_adapter.read_id_tag(tn_id).await?;
	let (app, rt) = (app.clone(), Handle::current());
	tokio::task::spawn_blocking(move || write_zip(&rt, &app, tn_id, &id_tag, &path)).await?
}

type Zip = rawzip::ZipArchiveWriter<BufWriter<std::fs::File>>;

fn zip_err(e: &rawzip::Error) -> Error {
	Error::Internal(format!("export zip: {e}"))
}

fn write_zip(rt: &Handle, app: &App, tn_id: TnId, id_tag: &str, path: &Path) -> ClResult<u64> {
	let mut zip = rawzip::ZipArchiveWriter::new(BufWriter::new(std::fs::File::create(path)?));
	deflated(&mut zip, "FORMATS.md".into(), |w| Ok(w.write_all(FORMATS_MD.as_bytes())?))?;
	let tenant = rt.block_on(app.meta_adapter.read_tenant(tn_id))?;
	deflated(&mut zip, "profile.json".into(), |w| Ok(serde_json::to_writer_pretty(w, &tenant)?))?;
	deflated(&mut zip, "actions.json".into(), |w| write_actions(rt, app, tn_id, id_tag, w))?;
	write_files(rt, app, tn_id, &mut zip)?;
	let file = zip
		.finish()
		.map_err(|e| zip_err(&e))?
		.into_inner()
		.map_err(|e| Error::from(e.into_error()))?;
	file.sync_all()?;
	Ok(file.metadata()?.len())
}

/// A deflated entry; `body` writes its uncompressed bytes.
fn deflated(
	zip: &mut Zip,
	path: String,
	body: impl FnOnce(&mut dyn Write) -> ClResult<()>,
) -> ClResult<()> {
	let (mut entry, config) = zip
		.new_file(path)
		.compression_method(rawzip::CompressionMethod::DEFLATE)
		.start()
		.map_err(|e| zip_err(&e))?;
	let mut writer =
		config.wrap(flate2::write::DeflateEncoder::new(&mut entry, flate2::Compression::default()));
	body(&mut writer)?;
	let (encoder, descriptor) = writer.finish().map_err(|e| zip_err(&e))?;
	encoder.finish()?;
	entry.finish(descriptor).map_err(|e| zip_err(&e))?;
	Ok(())
}

/// A stored (uncompressed) entry streamed from `stream` — blobs are mostly compressed already.
fn stored<S, B>(zip: &mut Zip, path: String, rt: &Handle, mut stream: S) -> ClResult<()>
where
	S: Stream<Item = Result<B, std::io::Error>> + Unpin,
	B: AsRef<[u8]>,
{
	let (mut entry, config) = zip.new_file(path).start().map_err(|e| zip_err(&e))?;
	let mut writer = config.wrap(&mut entry);
	while let Some(chunk) = rt.block_on(stream.next()) {
		writer.write_all(chunk?.as_ref())?;
	}
	let (_, descriptor) = writer.finish().map_err(|e| zip_err(&e))?;
	entry.finish(descriptor).map_err(|e| zip_err(&e))?;
	Ok(())
}

/// The tenant's own actions as one JSON array, page by page.
fn write_actions(
	rt: &Handle,
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	w: &mut dyn Write,
) -> ClResult<()> {
	let mut opts = ListActionOptions {
		limit: Some(PAGE),
		issuer: Some(id_tag.into()),
		// Drafts and scheduled actions are visible to their issuer only — the tenant.
		viewer_id_tag: Some(id_tag.into()),
		include_tokens: Some(true),
		..Default::default()
	};
	w.write_all(b"[")?;
	let mut first = true;
	loop {
		let mut page = rt.block_on(app.meta_adapter.list_actions(tn_id, &opts))?;
		// The adapter returns one row past the limit when there is more.
		let more = page.len() > PAGE as usize;
		page.truncate(PAGE as usize);
		for action in &page {
			if !first {
				w.write_all(b",\n")?;
			}
			first = false;
			serde_json::to_writer(&mut *w, action)?;
		}
		match page.last() {
			Some(last) if more => {
				let ts = Value::from(last.created_at.0);
				opts.cursor = Some(CursorData::new("created", ts, &last.action_id).encode());
			}
			_ => break,
		}
	}
	w.write_all(b"]")?;
	Ok(())
}

/// Folder entry_id → (parent entry_id, name).
type Folders<'a> = HashMap<&'a str, (Option<&'a str>, &'a str)>;

/// A name safe as one ZIP path segment: no separators, no `.`/`..`.
fn clean(name: &str) -> String {
	let name = name.replace(['/', '\\'], "_");
	if name.is_empty() || name == "." || name == ".." { "_".into() } else { name }
}

/// `<folder>/…/<name>` from the folder chain; stops at the root, at a folder not exported, or
/// at `MAX_PARENT_DEPTH` (a cycle).
fn entry_path(folders: &Folders, parent: Option<&str>, name: &str) -> String {
	let mut parts = vec![clean(name)];
	let mut cur = parent;
	while let Some(id) = cur {
		let Some((up, folder)) = folders.get(id).filter(|_| parts.len() <= MAX_PARENT_DEPTH) else {
			break;
		};
		parts.push(clean(folder));
		cur = *up;
	}
	parts.reverse();
	parts.join("/")
}

fn write_files(rt: &Handle, app: &App, tn_id: TnId, zip: &mut Zip) -> ClResult<()> {
	// No `parent_id`: `list_files`' default browse filter already drops the trash (and
	// everything below a trashed folder), system-managed files, pending uploads and deleted
	// rows. `local_only` drops mirrored copies of remote files, whose content is not ours.
	let mut opts = ListFileOptions { limit: Some(PAGE), local_only: true, ..Default::default() };
	let mut entries = Vec::new();
	loop {
		let mut page = rt.block_on(app.meta_adapter.list_files(tn_id, &opts))?;
		let more = page.len() > PAGE as usize;
		page.truncate(PAGE as usize);
		let cursor = page.last().filter(|_| more).map(|last| {
			let ts = Value::from(last.created_at.0);
			CursorData::new("created", ts, &last.entry_id).encode()
		});
		entries.append(&mut page);
		match cursor {
			Some(cursor) => opts.cursor = Some(cursor),
			None => break,
		}
	}

	let folders: Folders = entries
		.iter()
		.filter(|f| f.file_tp.as_deref() == Some("FLDR") || f.file_id.is_none())
		.map(|f| (&*f.entry_id, (f.parent_id.as_deref(), &*f.file_name)))
		.collect();
	let mut used = HashSet::new();
	for f in &entries {
		let (Some(file_id), Some(tp)) = (f.file_id.as_deref(), f.file_tp.as_deref()) else {
			continue;
		};
		let parent = f.parent_id.as_deref();
		let path = entry_path(&folders, parent, &f.file_name);
		match tp {
			"BLOB" => {
				let path = if used.insert(path.clone()) {
					path
				} else {
					let name = format!("{}_{}", f.entry_id, f.file_name);
					let path = entry_path(&folders, parent, &name);
					used.insert(path.clone());
					path
				};
				let stream = rt.block_on(async {
					let variants =
						app.meta_adapter.list_file_variants(tn_id, FileId::FileId(file_id)).await?;
					let orig = variants
						.iter()
						.find(|v| v.variant.as_ref() == "orig")
						.ok_or(Error::NotFound)?;
					app.blob_adapter.read_ref_stream(BlobRef::variant(tn_id, orig)).await
				});
				match stream {
					Ok(stream) => stored(zip, format!("files/{path}"), rt, stream)?,
					Err(e) => warn!(tn_id = ?tn_id, file_id, error = %e, "Export: blob skipped"),
				}
			}
			"CRDT" | "RTDB" => {
				let docs = rt.block_on(async {
					if tp == "CRDT" {
						crate::crdt_export::export_all(app, tn_id, file_id).await
					} else {
						app.rtdb_adapter.export_all(tn_id, file_id).await
					}
				});
				let docs = match docs {
					Ok(docs) => docs,
					Err(e) => {
						warn!(tn_id = ?tn_id, file_id, error = %e, "Export: document skipped");
						continue;
					}
				};
				let data: serde_json::Map<String, Value> =
					docs.into_iter().map(|(k, v)| (k.into_string(), v)).collect();
				let doc = serde_json::json!({
					"fileId": file_id,
					"fileName": f.file_name,
					"fileTp": tp,
					"contentType": f.content_type,
					"path": path,
					"data": data,
				});
				deflated(zip, format!("documents/{file_id}.json"), |w| {
					Ok(serde_json::to_writer_pretty(w, &doc)?)
				})?;
			}
			_ => {}
		}
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn entry_paths_follow_folders_and_stay_inside_the_archive() {
		let folders: Folders = HashMap::from([
			("a", (None, "Docs")),
			("b", (Some("a"), "../x")),
			("c", (Some("c"), "loop")),
		]);
		assert_eq!(entry_path(&folders, Some("b"), "r/1.txt"), "Docs/.._x/r_1.txt");
		assert_eq!(entry_path(&folders, None, ".."), "_");
		// A parent that was not exported (trash, remote) puts the file at the top.
		assert_eq!(entry_path(&folders, Some("gone"), "f"), "f");
		// A cycle ends at the depth bound instead of spinning.
		let looped = entry_path(&folders, Some("c"), "f");
		assert_eq!(looped.split('/').count(), MAX_PARENT_DEPTH + 1);
	}
}

// vim: ts=4
