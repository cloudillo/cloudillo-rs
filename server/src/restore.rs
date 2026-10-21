// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! `cloudillo restore <snapshot-dir> [--force]` — offline restore of a backup snapshot.
//!
//! Verifies every file of the snapshot's manifest and copies it into `*.restore-<unix-ts>`
//! staging dirs. Only then moves the current `DB_DIR/{auth,meta,crdt,rtdb}` and `DATA_DIR/blob`
//! aside to `*.pre-restore-<unix-ts>` and renames the staging dirs into place. Nothing else
//! under `DATA_DIR`/`DB_DIR` (tmp, certs, …) is touched. Refuses while the server holds
//! `DB_DIR/cloudillo.lock`.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, io};

use cloudillo::app::{BACKUP_PARTS, Manifest, copy_verified, verify_snapshot};

const USAGE: &str = "usage: cloudillo restore <snapshot-dir> [--force]";

/// Take the exclusive lock the server holds for its whole life. Held by `restore` too, so a
/// server cannot start mid-restore.
pub fn lock(db_dir: &Path) -> Result<File, Box<dyn std::error::Error>> {
	let path = db_dir.join("cloudillo.lock");
	let file = File::options().create(true).truncate(false).write(true).open(&path)?;
	file.try_lock()
		.map_err(|e| format!("{}: {e} (is another cloudillo running?)", path.display()))?;
	Ok(file)
}

fn env_dir(var: &str) -> PathBuf {
	env::var(var).map_or_else(|_| PathBuf::from("./data"), PathBuf::from)
}

pub fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
	let (snapshot, force) = match args {
		[dir] => (Path::new(dir), false),
		[dir, flag] if flag == "--force" => (Path::new(dir), true),
		_ => return Err(USAGE.into()),
	};
	let db_dir = env_dir("DB_DIR");
	let data_dir = env_dir("DATA_DIR");
	fs::create_dir_all(&db_dir)?;
	// `--force` overrides only the version check: a running server always blocks the restore
	let _lock = lock(&db_dir)?;

	restore(snapshot, &db_dir, &data_dir, force)
}

/// `major.minor.patch`, ignoring a `-pre` suffix.
fn parse_ver(v: &str) -> Option<(u64, u64, u64)> {
	let v = v.split_once('-').map_or(v, |(v, _)| v);
	let mut it = v.split('.').map(str::parse);
	match (it.next()?, it.next()?, it.next()?, it.next()) {
		(Ok(a), Ok(b), Ok(c), None) => Some((a, b, c)),
		_ => None,
	}
}

/// `path` with `.{suffix}` appended to its last component.
fn sibling(path: &Path, suffix: &str) -> PathBuf {
	PathBuf::from(format!("{}.{suffix}", path.display()))
}

/// Verify `snapshot`, stage it next to the live dirs, then swap each staged part in.
///
/// Live data is untouched until every file is staged and re-verified, so a bad copy leaves the
/// server as it was. Only the final per-part renames can fail half way; that prints the undo.
fn restore(
	snapshot: &Path,
	db_dir: &Path,
	data_dir: &Path,
	force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
	println!("Verifying {} ...", snapshot.display());
	let manifest = verify_snapshot(snapshot).map_err(|e| format!("verification failed: {e}"))?;
	println!(
		"Verified {} files (written by cloudillo {}, created at unix {})",
		manifest.files.len(),
		manifest.version,
		manifest.created_at
	);
	let cur = env!("CARGO_PKG_VERSION");
	match (parse_ver(&manifest.version), parse_ver(cur)) {
		(Some(v), Some(c)) if v > c && !force => {
			return Err(format!(
				"snapshot written by cloudillo {}, newer than this binary {cur}; \
				 upgrade first or pass --force",
				manifest.version
			)
			.into());
		}
		(Some(_), Some(_)) => {}
		_ => {
			eprintln!("warning: cannot compare snapshot version {:?} with {cur}", manifest.version);
		}
	}

	let ts = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
	// Staging is a sibling of the live dir, so the swap is a same-filesystem rename
	let target = |part: &str| {
		if part == "blob" { data_dir.join(part) } else { db_dir.join(part) }
	};
	let staging = |part: &str| sibling(&target(part), &format!("restore-{ts}"));

	if let Err(e) = stage(snapshot, &manifest, &staging) {
		for part in BACKUP_PARTS {
			let _ = fs::remove_dir_all(staging(part));
		}
		return Err(format!("restore failed, live data untouched: {e}").into());
	}

	let mut swapped: Vec<(PathBuf, PathBuf)> = Vec::new();
	for part in BACKUP_PARTS {
		let live = target(part);
		let aside = sibling(&live, &format!("pre-restore-{ts}"));
		if let Err(e) = swap(&live, &aside, &staging(part)) {
			eprintln!("Swapping in {part} failed: {e}. To undo:");
			for (live, aside) in &swapped {
				let (l, a) = (live.display(), aside.display());
				if aside.exists() {
					eprintln!("  rm -rf '{l}' && mv '{a}' '{l}'");
				} else {
					eprintln!("  rm -rf '{l}'");
				}
			}
			if aside.exists() {
				eprintln!("  mv '{}' '{}'", aside.display(), live.display());
			}
			eprintln!("Staged copies are left in *.restore-{ts}.");
			return Err(e.into());
		}
		swapped.push((live, aside));
	}
	println!(
		"Restored {} files into DB_DIR={} and DATA_DIR={}/blob. Start the server to finish.",
		manifest.files.len(),
		db_dir.display(),
		data_dir.display()
	);
	Ok(())
}

/// Move `live` (if any) to `aside`, then `staged` to `live`.
fn swap(live: &Path, aside: &Path, staged: &Path) -> io::Result<()> {
	match fs::symlink_metadata(live) {
		Ok(_) => {
			fs::rename(live, aside)?;
			println!("Moved {} -> {}", live.display(), aside.display());
		}
		Err(e) if e.kind() == io::ErrorKind::NotFound => {}
		Err(e) => return Err(e),
	}
	fs::rename(staged, live)?;
	// Make the renames durable
	#[cfg(unix)]
	if let Some(parent) = live.parent() {
		File::open(parent)?.sync_all()?;
	}
	Ok(())
}

/// `create_dir_all`, owner-only on unix.
fn create_private_dir(path: &Path) -> io::Result<()> {
	let mut b = fs::DirBuilder::new();
	b.recursive(true);
	#[cfg(unix)]
	std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
	b.create(path)
}

/// Copy every manifest file into its part's staging dir; every part gets a dir, even if empty.
fn stage(
	snapshot: &Path,
	manifest: &Manifest,
	staging: &impl Fn(&str) -> PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
	for part in BACKUP_PARTS {
		create_private_dir(&staging(part))?;
	}
	for f in &manifest.files {
		// `verify_snapshot` checked the path: relative, no `..`, first component a part.
		let (part, rest) = f.path.split_once('/').ok_or("invalid manifest path")?;
		let dest = staging(part).join(rest);
		if let Some(parent) = dest.parent() {
			create_private_dir(parent)?;
		}
		// Re-hashes what it copies: a file swapped since `verify_snapshot` is refused.
		copy_verified(&snapshot.join(&f.path), &dest, f.size, &f.sha256)?;
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	const BODY_SHA: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
	const FILES: [&str; 3] = ["auth/auth.db", "meta/meta.db", "blob/ab/f1~x"];

	/// Snapshot holding FILES = "hello", and a root with `db/` and `data/` holding "old" data.
	fn setup() -> (tempfile::TempDir, tempfile::TempDir) {
		let snap = tempfile::tempdir().unwrap();
		for f in FILES {
			let p = snap.path().join(f);
			fs::create_dir_all(p.parent().unwrap()).unwrap();
			fs::write(p, "hello").unwrap();
		}
		let files: Vec<String> = FILES
			.iter()
			.map(|f| format!(r#"{{"path":"{f}","size":5,"sha256":"{BODY_SHA}"}}"#))
			.collect();
		let manifest = format!(r#"{{"version":"t","createdAt":0,"files":[{}]}}"#, files.join(","));
		fs::write(snap.path().join("manifest.json"), manifest).unwrap();

		let root = tempfile::tempdir().unwrap();
		for f in ["db/auth/auth.db", "data/blob/old"] {
			let p = root.path().join(f);
			fs::create_dir_all(p.parent().unwrap()).unwrap();
			fs::write(p, "old").unwrap();
		}
		(snap, root)
	}

	fn names(dir: &Path) -> Vec<String> {
		let mut v: Vec<String> = fs::read_dir(dir)
			.unwrap()
			.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
			.collect();
		v.sort();
		v
	}

	#[test]
	fn parses_and_orders_versions() {
		assert_eq!(parse_ver("0.8.21"), Some((0, 8, 21)));
		assert_eq!(parse_ver("1.2.3-rc1"), Some((1, 2, 3)));
		assert_eq!(parse_ver("t"), None);
		assert_eq!(parse_ver("1.2"), None);
		assert_eq!(parse_ver("1.2.3.4"), None);
		assert!(parse_ver("0.10.0") > parse_ver("0.9.9"));
		assert!(parse_ver("0.8.20") < parse_ver("0.8.21"));
	}

	#[test]
	fn refuses_newer_snapshot_unless_forced() {
		let (snap, root) = setup();
		let m = fs::read_to_string(snap.path().join("manifest.json")).unwrap();
		let m = m.replace(r#""version":"t""#, r#""version":"999.0.0""#);
		fs::write(snap.path().join("manifest.json"), m).unwrap();
		let (db, data) = (root.path().join("db"), root.path().join("data"));
		let err = restore(snap.path(), &db, &data, false).unwrap_err().to_string();
		assert!(err.contains("newer than this binary"), "{err}");
		assert_eq!(fs::read_to_string(db.join("auth/auth.db")).unwrap(), "old");
		restore(snap.path(), &db, &data, true).unwrap();
	}

	#[test]
	fn restores_and_keeps_old_data_aside() {
		let (snap, root) = setup();
		let (db, data) = (root.path().join("db"), root.path().join("data"));
		restore(snap.path(), &db, &data, false).unwrap();

		for f in FILES {
			let (part, rest) = f.split_once('/').unwrap();
			let dir = if part == "blob" { &data } else { &db };
			assert_eq!(fs::read_to_string(dir.join(part).join(rest)).unwrap(), "hello");
		}
		assert!(!data.join("blob/old").exists());
		assert!(names(&db).iter().all(|n| !n.contains(".restore-")));
		let aside = names(&db).into_iter().find(|n| n.starts_with("auth.pre-restore-")).unwrap();
		assert_eq!(fs::read_to_string(db.join(aside).join("auth.db")).unwrap(), "old");
		let aside = names(&data).into_iter().find(|n| n.starts_with("blob.pre-restore-")).unwrap();
		assert_eq!(fs::read_to_string(data.join(aside).join("old")).unwrap(), "old");
	}

	#[test]
	fn failure_leaves_live_data_untouched() {
		// Corrupt snapshot: refused by verification
		let (snap, root) = setup();
		fs::write(snap.path().join("blob/ab/f1~x"), "HELLO").unwrap();
		let (db, data) = (root.path().join("db"), root.path().join("data"));
		assert!(restore(snap.path(), &db, &data, false).is_err());
		assert_eq!(names(&db), ["auth"]);
		assert_eq!(names(&data), ["blob"]);

		// Staging fails after the DB_DIR parts are staged: DATA_DIR is a file
		let (snap, root) = setup();
		let db = root.path().join("db");
		let data = root.path().join("not-a-dir");
		fs::write(&data, "").unwrap();
		assert!(restore(snap.path(), &db, &data, false).is_err());
		assert_eq!(names(&db), ["auth"]);
		assert_eq!(fs::read_to_string(db.join("auth/auth.db")).unwrap(), "old");
	}
}

// vim: ts=4
