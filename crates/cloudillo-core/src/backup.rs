// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Online backups: a snapshot of every store under `BACKUP_DIR`.
//!
//! Each store's snapshot is consistent on its own, but they are taken one after another, not at
//! one point in time: a tenant created or purged during the run may be half-present in a restore.
//!
//! A run writes `<BACKUP_DIR>/<yyyymmddThhmmssZ>.partial/{auth,meta,crdt,rtdb,blob}/` through
//! the adapters' `snapshot` methods, adds `manifest.json` (size and sha256 of every file), and
//! renames the directory once complete. Files, directories and the rename are fsynced, so a
//! directory without the suffix is always whole, even after a crash. Then it prunes to
//! `backup.keep` snapshots. Every run is audited as `admin.backup`.
//!
//! Runs daily at `backup.time` (UTC, read at startup) and on demand from
//! `POST /api/admin/backup`. Only one run at a time: [`BackupState`] holds the flag.
//!
//! Restore is offline only — `cloudillo restore <dir>` in the server binary, which checks the
//! manifest with [`verify_snapshot`] before touching anything.

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::prelude::*;
use crate::scheduler::{Task, TaskId};
use crate::settings::{
	PermissionLevel, SettingDefinition, SettingScope, SettingValue, SettingsRegistry,
};
use cloudillo_types::auth_adapter::{AuditCategory, AuditEvent};
use cloudillo_types::types::SHARED_TN;

const MANIFEST: &str = "manifest.json";
const PARTIAL_SUFFIX: &str = ".partial";
const DEFAULT_KEEP: i64 = 7;

/// Store subdirectories of a snapshot. `blob` maps to `DATA_DIR/blob`, the rest to `DB_DIR/*`.
pub const PARTS: [&str; 5] = ["auth", "meta", "crdt", "rtdb", "blob"];
/// Files every complete snapshot holds; one without them would restore an empty server.
const REQUIRED_FILES: [&str; 2] = ["auth/auth.db", "meta/meta.db"];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestFile {
	/// Relative to the snapshot directory, `/`-separated, first component one of [`PARTS`].
	pub path: String,
	pub size: u64,
	pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
	/// Server version that wrote the snapshot; it fixes every store's schema version.
	pub version: String,
	/// Unix seconds.
	pub created_at: i64,
	pub files: Vec<ManifestFile>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupResult {
	pub name: String,
	pub bytes: u64,
	pub files: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LastRun {
	/// Unix seconds the run started.
	pub at: i64,
	pub ok: bool,
	pub bytes: u64,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotInfo {
	pub name: String,
	pub created_at: i64,
	pub bytes: u64,
}

/// Backup directory, running flag and last outcome. Registered as an app extension.
pub struct BackupState {
	dir: PathBuf,
	running: AtomicBool,
	last: Mutex<Option<LastRun>>,
}

impl BackupState {
	pub fn new(dir: impl Into<PathBuf>) -> Self {
		Self { dir: dir.into(), running: AtomicBool::new(false), last: Mutex::new(None) }
	}
	pub fn is_running(&self) -> bool {
		self.running.load(Ordering::Acquire)
	}
	/// Outcome of the last run since process start (not persisted).
	pub fn last(&self) -> Option<LastRun> {
		self.last.lock().clone()
	}
}

/// Clears the running flag when the run ends, panics included.
struct RunGuard(App);

impl Drop for RunGuard {
	fn drop(&mut self) {
		if let Ok(state) = self.0.ext::<BackupState>() {
			state.running.store(false, Ordering::Release);
		}
	}
}

fn acquire(app: &App) -> ClResult<RunGuard> {
	let state = app.ext::<BackupState>()?;
	if state
		.running
		.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
		.is_err()
	{
		return Err(Error::Conflict("A backup is already running".into()));
	}
	Ok(RunGuard(app.clone()))
}

/// Run a backup now and wait for it. `Conflict` if one is already running.
pub async fn run_backup(
	app: &App,
	actor: Option<&str>,
	ip: Option<&str>,
) -> ClResult<BackupResult> {
	let guard = acquire(app)?;
	run_acquired(app, guard, actor, ip).await
}

/// Start a backup in the background (`POST /api/admin/backup`). `Conflict` if one is running.
pub fn start_backup(app: &App, actor: &str, ip: &str) -> ClResult<()> {
	let guard = acquire(app)?;
	let (app, actor, ip) = (app.clone(), actor.to_string(), ip.to_string());
	tokio::spawn(async move {
		// The outcome is logged, audited and kept in `BackupState::last`.
		let _ = run_acquired(&app, guard, Some(&actor), Some(&ip)).await;
	});
	Ok(())
}

async fn run_acquired(
	app: &App,
	_guard: RunGuard,
	actor: Option<&str>,
	ip: Option<&str>,
) -> ClResult<BackupResult> {
	let state = app.ext::<BackupState>()?;
	let at = Timestamp::now().0;
	let res = snapshot_all(app, &state.dir).await;

	let (last, details) = match &res {
		Ok(r) => {
			info!(name = %r.name, bytes = r.bytes, files = r.files, "backup: snapshot complete");
			(
				LastRun { at, ok: true, bytes: r.bytes, error: None },
				serde_json::json!({ "name": r.name, "bytes": r.bytes, "files": r.files }),
			)
		}
		Err(e) => {
			warn!(error = %e, "backup: failed");
			(
				LastRun { at, ok: false, bytes: 0, error: Some(e.to_string()) },
				serde_json::json!({ "error": e.to_string() }),
			)
		}
	};
	*state.last.lock() = Some(last);

	let mut ev = AuditEvent::new(
		AuditCategory::Admin,
		"admin.backup",
		if res.is_ok() { "success" } else { "fail" },
	);
	ev.actor = actor.map(Into::into);
	ev.ip = ip.map(Into::into);
	ev.details = Some(details);
	crate::audit::record(app, ev).await;
	res
}

async fn snapshot_all(app: &App, dir: &Path) -> ClResult<BackupResult> {
	tokio::fs::create_dir_all(dir).await?;
	// Snapshots hold every tenant's keys and data; the parent dir gates them all.
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		tokio::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).await?;
	}
	// Leftovers of a run that crashed; we hold the running flag, so none is live.
	for name in read_names(dir).await? {
		if name.ends_with(PARTIAL_SUFFIX) {
			let _ = tokio::fs::remove_dir_all(dir.join(&name)).await;
		}
	}
	let prev = complete_snapshots(dir).await?.pop().map(|n| dir.join(n));

	let name = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
	// Second-resolution names: the final rename would fail after all the work.
	if tokio::fs::try_exists(dir.join(&name)).await? {
		return Err(Error::Conflict("A snapshot was taken this second, retry".into()));
	}
	let partial = dir.join(format!("{name}{PARTIAL_SUFFIX}"));
	let manifest = match write_snapshot(app, &partial, prev.as_deref()).await {
		Ok(m) => m,
		Err(e) => {
			let _ = tokio::fs::remove_dir_all(&partial).await;
			return Err(e);
		}
	};
	tokio::fs::rename(&partial, dir.join(&name)).await?;
	let d = dir.to_path_buf();
	blocking(move || sync_dir(&d)).await?;

	let keep = app
		.settings
		.get_int_opt(SHARED_TN, "backup.keep")
		.await
		.ok()
		.flatten()
		.unwrap_or(DEFAULT_KEEP)
		.max(1);
	let all = complete_snapshots(dir).await?;
	let excess = all.len().saturating_sub(usize::try_from(keep).unwrap_or(usize::MAX));
	for old in &all[..excess] {
		if let Err(e) = tokio::fs::remove_dir_all(dir.join(old)).await {
			warn!(snapshot = %old, error = %e, "backup: prune failed");
		}
	}

	Ok(BackupResult {
		name,
		bytes: manifest.files.iter().map(|f| f.size).sum(),
		files: manifest.files.len(),
	})
}

// No cross-store point in time; upgrade path: an app-wide write gate held across all five.
async fn write_snapshot(app: &App, partial: &Path, prev: Option<&Path>) -> ClResult<Manifest> {
	tokio::fs::create_dir(partial).await?;
	for p in PARTS {
		tokio::fs::create_dir(partial.join(p)).await?;
	}
	let prev_blob = prev.map(|p| p.join("blob"));
	let parts = vec![
		("auth", app.auth_adapter.snapshot(&partial.join("auth")).await?),
		("meta", app.meta_adapter.snapshot(&partial.join("meta")).await?),
		("crdt", app.crdt_adapter.snapshot(&partial.join("crdt")).await?),
		("rtdb", app.rtdb_adapter.snapshot(&partial.join("rtdb")).await?),
		("blob", app.blob_adapter.snapshot(&partial.join("blob"), prev_blob.as_deref()).await?),
	];

	// Blob files are only ever replaced via tmp+rename, never modified in place, so a file
	// that is the same inode as the previous snapshot's copy (and the same size) still has
	// that snapshot's hash — rehashing the whole store nightly is wasted IO. Anything else,
	// a rewritten blob or a cross-device copy, is rehashed.
	let mut known: HashMap<String, (u64, String)> = HashMap::new();
	if let Some(prev) = prev
		&& let Ok(m) = read_manifest(prev).await
	{
		known = m
			.files
			.into_iter()
			.filter(|f| f.path.starts_with("blob/"))
			.map(|f| (f.path, (f.size, f.sha256)))
			.collect();
	}

	let root = partial.to_path_buf();
	let prev = prev.map(Path::to_path_buf);
	let (files, dirs) = blocking(move || {
		let mut out = Vec::new();
		// Every directory that got a new entry, for the fsync after the manifest.
		let mut dirs = BTreeSet::from([root.clone()]);
		for (part, sp) in parts {
			dirs.insert(root.join(part));
			for rel in sp.files {
				let path = format!("{part}/{}", rel.to_string_lossy());
				let full = root.join(&path);
				if let Some(d) = full.parent() {
					dirs.insert(d.to_path_buf());
				}
				let size = std::fs::metadata(&full)?.len();
				let sha256 = match (known.remove(&path), &prev) {
					(Some((s, h)), Some(prev))
						if s == size && same_file(&full, &prev.join(&path)) =>
					{
						h
					}
					// New data; a reused hash is a link to an inode the previous run synced.
					_ => {
						std::fs::File::open(&full)?.sync_all()?;
						sha256_file(&full)?
					}
				};
				out.push(ManifestFile { path, size, sha256 });
			}
		}
		Ok((out, dirs))
	})
	.await?;

	let manifest =
		Manifest { version: crate::app::VERSION.into(), created_at: Timestamp::now().0, files };
	let manifest_path = partial.join(MANIFEST);
	tokio::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?).await?;
	blocking(move || {
		std::fs::File::open(&manifest_path)?.sync_all()?;
		dirs.iter().try_for_each(|d| sync_dir(d))
	})
	.await?;
	Ok(manifest)
}

async fn blocking<T: Send + 'static>(
	f: impl FnOnce() -> std::io::Result<T> + Send + 'static,
) -> ClResult<T> {
	Ok(tokio::task::spawn_blocking(f)
		.await
		.map_err(|e| Error::Internal(format!("backup blocking task failed: {e}")))??)
}

/// fsync a directory, making its entries (new files, renames) durable. No-op off unix.
fn sync_dir(path: &Path) -> std::io::Result<()> {
	#[cfg(unix)]
	std::fs::File::open(path)?.sync_all()?;
	#[cfg(not(unix))]
	let _ = path;
	Ok(())
}

/// Both paths name one inode. `false` when unknown, which forces a rehash.
fn same_file(a: &Path, b: &Path) -> bool {
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		match (std::fs::metadata(a), std::fs::metadata(b)) {
			(Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
			_ => false,
		}
	}
	#[cfg(not(unix))]
	{
		let _ = (a, b);
		false
	}
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
	Ok(hash_copy(std::fs::File::open(path)?, std::io::sink())?.1)
}

/// Stream `src` into `dest`, returning its size and hex sha256.
fn hash_copy(mut src: impl Read, mut dest: impl Write) -> std::io::Result<(u64, String)> {
	let mut hasher = Sha256::new();
	let mut buf = vec![0u8; 64 * 1024];
	let mut size = 0u64;
	loop {
		let n = src.read(&mut buf)?;
		if n == 0 {
			break;
		}
		hasher.update(&buf[..n]);
		dest.write_all(&buf[..n])?;
		size += n as u64;
	}
	let mut out = String::with_capacity(64);
	for b in hasher.finalize() {
		let _ = write!(out, "{b:02x}");
	}
	Ok((size, out))
}

async fn read_names(dir: &Path) -> ClResult<Vec<String>> {
	let mut names = Vec::new();
	let mut rd = match tokio::fs::read_dir(dir).await {
		Ok(rd) => rd,
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(names),
		Err(e) => return Err(e.into()),
	};
	while let Some(entry) = rd.next_entry().await? {
		if let Ok(name) = entry.file_name().into_string() {
			names.push(name);
		}
	}
	Ok(names)
}

/// `yyyymmddThhmmssZ`
fn is_snapshot_name(name: &str) -> bool {
	let b = name.as_bytes();
	b.len() == 16
		&& b[8] == b'T'
		&& b[15] == b'Z'
		&& b.iter().enumerate().all(|(i, c)| i == 8 || i == 15 || c.is_ascii_digit())
}

/// Completed snapshot names, oldest first.
async fn complete_snapshots(dir: &Path) -> ClResult<Vec<String>> {
	let mut names = Vec::new();
	for name in read_names(dir).await? {
		if is_snapshot_name(&name) && tokio::fs::try_exists(dir.join(&name).join(MANIFEST)).await? {
			names.push(name);
		}
	}
	names.sort_unstable();
	Ok(names)
}

async fn read_manifest(snapshot: &Path) -> ClResult<Manifest> {
	Ok(serde_json::from_slice(&tokio::fs::read(snapshot.join(MANIFEST)).await?)?)
}

/// Completed snapshots, newest first (`GET /api/admin/backup`).
pub async fn list_snapshots(app: &App) -> ClResult<Vec<SnapshotInfo>> {
	let dir = &app.ext::<BackupState>()?.dir;
	let mut out = Vec::new();
	for name in complete_snapshots(dir).await?.into_iter().rev() {
		match read_manifest(&dir.join(&name)).await {
			Ok(m) => out.push(SnapshotInfo {
				created_at: m.created_at,
				bytes: m.files.iter().map(|f| f.size).sum(),
				name,
			}),
			Err(e) => warn!(snapshot = %name, error = %e, "backup: unreadable manifest"),
		}
	}
	Ok(out)
}

/// Check every file listed in `<snapshot>/manifest.json` for size and sha256. Blocking; used by
/// the offline `cloudillo restore` before it moves anything.
pub fn verify_snapshot(snapshot: &Path) -> ClResult<Manifest> {
	let manifest: Manifest = serde_json::from_slice(&std::fs::read(snapshot.join(MANIFEST))?)?;
	// crdt/rtdb/blob may legitimately be empty; the two databases never are
	for required in REQUIRED_FILES {
		if !manifest.files.iter().any(|f| f.path == required) {
			return Err(Error::ValidationError(format!("{required}: missing from manifest")));
		}
	}
	for f in &manifest.files {
		let rel = Path::new(&f.path);
		let safe = rel.components().all(|c| matches!(c, Component::Normal(_)))
			&& f.path.split('/').next().is_some_and(|p| PARTS.contains(&p))
			&& f.path.contains('/');
		if !safe {
			return Err(Error::ValidationError(format!("{}: invalid path in manifest", f.path)));
		}
		let full = snapshot.join(rel);
		// A symlinked parent dir escapes the snapshot even with a clean relative path
		if !full.canonicalize()?.starts_with(snapshot.canonicalize()?) {
			return Err(Error::ValidationError(format!("{}: outside the snapshot", f.path)));
		}
		let (size, sha256) = hash_copy(open_regular(&full)?, std::io::sink())?;
		if size != f.size || sha256 != f.sha256 {
			return Err(Error::ValidationError(format!("{}: size or sha256 mismatch", f.path)));
		}
	}
	Ok(manifest)
}

/// Open `path` only if it is a regular file, not a symlink.
fn open_regular(path: &Path) -> ClResult<std::fs::File> {
	if !std::fs::symlink_metadata(path)?.file_type().is_file() {
		return Err(Error::ValidationError(format!("{}: not a regular file", path.display())));
	}
	Ok(std::fs::File::open(path)?)
}

/// Copy `src` to `dest`, hashing the bytes actually copied, so a file swapped after
/// [`verify_snapshot`] cannot slip in. On mismatch `dest` is removed. `dest` must not exist
/// (a planted file or symlink is refused); it is created owner-only and synced. Blocking.
pub fn copy_verified(src: &Path, dest: &Path, size: u64, sha256: &str) -> ClResult<()> {
	let file = open_regular(src)?;
	let mut opts = std::fs::File::options();
	opts.write(true).create_new(true);
	#[cfg(unix)]
	std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
	let mut out = opts.open(dest)?;
	let got = hash_copy(file, &mut out)?;
	if got.0 != size || got.1 != sha256 {
		let _ = std::fs::remove_file(dest);
		return Err(Error::ValidationError(format!("{}: size or sha256 mismatch", src.display())));
	}
	out.sync_all()?;
	Ok(())
}

/// `HH:MM` → `(hour, minute)`.
fn parse_time(s: &str) -> Option<(u8, u8)> {
	let (h, m) = s.trim().split_once(':')?;
	let (h, m) = (h.parse::<u8>().ok()?, m.parse::<u8>().ok()?);
	(h <= 23 && m <= 59).then_some((h, m))
}

/// Daily backup at `backup.time`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BackupTask;

#[async_trait]
impl Task<App> for BackupTask {
	fn kind() -> &'static str {
		"core.backup"
	}
	fn kind_of(&self) -> &'static str {
		Self::kind()
	}
	fn build(_id: TaskId, _ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		Ok(Arc::new(Self))
	}
	fn serialize(&self) -> String {
		String::new()
	}

	// No retry policy: a failure is audited and shown by `GET /api/admin/backup`, and the next
	// run is a day away; retries would stack snapshot IO on a node that is already in trouble.
	async fn run(&self, app: &App) -> ClResult<()> {
		// The persisted cron row outlives `backup.time` being cleared; honour the setting.
		let time = app.settings.get_string_opt(SHARED_TN, "backup.time").await.ok().flatten();
		if time.as_deref().and_then(parse_time).is_none() {
			info!("backup: disabled (backup.time empty), skipping");
			return Ok(());
		}
		// Other errors are logged and audited by `run_acquired`.
		if let Err(Error::Conflict(_)) = run_backup(app, None, None).await {
			info!("backup: a run is already in progress, skipping");
		}
		Ok(())
	}
}

pub fn init(app: &App) -> ClResult<()> {
	app.scheduler.register::<BackupTask>()?;
	Ok(())
}

/// Schedule the daily run from `backup.time`; nothing when it is empty. Read once at startup.
pub async fn schedule(app: &App) -> ClResult<()> {
	let time = app
		.settings
		.get_string_opt(SHARED_TN, "backup.time")
		.await
		.ok()
		.flatten()
		.unwrap_or_default();
	let Some((hour, minute)) = parse_time(&time) else {
		if !time.trim().is_empty() {
			warn!(time = %time, "backup: invalid backup.time, scheduled backup disabled");
		}
		return Ok(());
	};
	app.scheduler
		.task(Arc::new(BackupTask))
		.key("core.backup")
		.daily_at(hour, minute)
		.schedule()
		.await?;
	Ok(())
}

pub fn register_settings(registry: &mut SettingsRegistry) -> ClResult<()> {
	registry.register(
		SettingDefinition::builder("backup.time")
			.description(
				"Daily backup time, UTC 'HH:MM'; empty disables the scheduled backup. Read at \
				 startup: a change takes effect after a restart",
			)
			.default(SettingValue::String(String::new()))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.validator(|v| match v {
				SettingValue::String(s) if s.trim().is_empty() || parse_time(s).is_some() => Ok(()),
				_ => Err(Error::ValidationError(
					"Backup time must be empty or 'HH:MM' (00:00-23:59)".into(),
				)),
			})
			.build()?,
	)?;
	registry.register(
		SettingDefinition::builder("backup.keep")
			.description("Number of backup snapshots to keep; older ones are deleted after a run")
			.default(SettingValue::Int(DEFAULT_KEEP))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.validator(|v| match v {
				SettingValue::Int(n) if *n >= 1 => Ok(()),
				_ => Err(Error::ValidationError("Backups to keep must be at least 1".into())),
			})
			.build()?,
	)?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn names_and_times() {
		assert!(is_snapshot_name("20261020T040000Z"));
		assert!(!is_snapshot_name("20261020T040000Z.partial"));
		assert!(!is_snapshot_name("2026102xT040000Z"));
		assert_eq!(parse_time("04:30"), Some((4, 30)));
		assert_eq!(parse_time("24:00"), None);
		assert_eq!(parse_time(""), None);
	}

	#[cfg(unix)]
	#[test]
	fn same_file_tells_a_rewrite_apart() {
		let dir = tempfile::tempdir().unwrap();
		let (live, snap) = (dir.path().join("live"), dir.path().join("snap"));
		std::fs::write(&live, b"one").unwrap();
		std::fs::hard_link(&live, &snap).unwrap();
		assert!(same_file(&live, &snap));
		// tmp+rename at the same size: the previous hash must not be reused.
		let tmp = dir.path().join("tmp");
		std::fs::write(&tmp, b"two").unwrap();
		std::fs::rename(&tmp, &live).unwrap();
		assert!(!same_file(&live, &snap));
		assert!(!same_file(&live, &dir.path().join("missing")));
	}

	const BODY: &[u8] = b"hello";
	const BODY_SHA: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

	/// Snapshot dir with `meta/db` and the [`REQUIRED_FILES`] = BODY, and a manifest listing
	/// the required files plus `entries` (path, size, sha).
	fn snapshot_with(entries: &[(&str, u64, &str)]) -> tempfile::TempDir {
		let dir = tempfile::tempdir().unwrap();
		std::fs::create_dir(dir.path().join("meta")).unwrap();
		std::fs::create_dir(dir.path().join("auth")).unwrap();
		for f in ["meta/db", "meta/meta.db", "auth/auth.db"] {
			std::fs::write(dir.path().join(f), BODY).unwrap();
		}
		let required = REQUIRED_FILES.map(|p| (p, 5, BODY_SHA));
		write_manifest(&dir, required.iter().chain(entries));
		dir
	}

	fn write_manifest<'a>(
		dir: &tempfile::TempDir,
		entries: impl Iterator<Item = &'a (&'a str, u64, &'a str)>,
	) {
		let files = entries
			.map(|(p, s, h)| ManifestFile { path: (*p).into(), size: *s, sha256: (*h).into() })
			.collect();
		let m = Manifest { version: "t".into(), created_at: 0, files };
		std::fs::write(dir.path().join(MANIFEST), serde_json::to_vec(&m).unwrap()).unwrap();
	}

	fn rejected(dir: &tempfile::TempDir) -> bool {
		matches!(verify_snapshot(dir.path()), Err(Error::ValidationError(_)))
	}

	#[test]
	fn verify_accepts_valid() {
		assert!(verify_snapshot(snapshot_with(&[("meta/db", 5, BODY_SHA)]).path()).is_ok());
	}

	#[test]
	fn verify_rejects_bad_paths_and_content() {
		for path in ["meta/../meta/db", "/meta/db", "etc/x", "meta"] {
			assert!(rejected(&snapshot_with(&[(path, 5, BODY_SHA)])), "{path}");
		}
		assert!(rejected(&snapshot_with(&[("meta/db", 4, BODY_SHA)])));
		assert!(rejected(&snapshot_with(&[("meta/db", 5, &"0".repeat(64))])));
	}

	#[test]
	fn verify_rejects_incomplete_manifest() {
		let dir = snapshot_with(&[]);
		write_manifest(&dir, [("meta/meta.db", 5, BODY_SHA)].iter());
		assert!(rejected(&dir));
		write_manifest(&dir, std::iter::empty());
		assert!(rejected(&dir));
	}

	#[cfg(unix)]
	#[test]
	fn verify_rejects_symlinks() {
		let outside = tempfile::tempdir().unwrap();
		for f in ["db", "meta.db"] {
			std::fs::write(outside.path().join(f), BODY).unwrap();
		}

		let dir = snapshot_with(&[("meta/db", 5, BODY_SHA)]);
		std::fs::remove_file(dir.path().join("meta/db")).unwrap();
		std::os::unix::fs::symlink(outside.path().join("db"), dir.path().join("meta/db")).unwrap();
		assert!(rejected(&dir));

		let dir = snapshot_with(&[("meta/db", 5, BODY_SHA)]);
		std::fs::remove_dir_all(dir.path().join("meta")).unwrap();
		std::os::unix::fs::symlink(outside.path(), dir.path().join("meta")).unwrap();
		assert!(rejected(&dir));
	}

	#[test]
	fn copy_verified_checks_copied_bytes() {
		let dir = snapshot_with(&[]);
		let (src, dest) = (dir.path().join("meta/db"), dir.path().join("out"));
		copy_verified(&src, &dest, 5, BODY_SHA).unwrap();
		assert_eq!(std::fs::read(&dest).unwrap(), BODY);

		std::fs::remove_file(&dest).unwrap();
		assert!(copy_verified(&src, &dest, 5, &"0".repeat(64)).is_err());
		assert!(!dest.exists());
	}
}

// vim: ts=4
