// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! The document formats this *build* ships, read once out of the frontend bundle.
//!
//! # Why a global tier exists
//!
//! `doc_formats` says which app owns a content type, where its documents live and
//! how to index them. Written at runtime by the shell — an app starts, says "I
//! handle `cloudillo/notillo`", the shell PUTs its bundled copy of that app's
//! manifest — that copies the same constant into one row per tenant per node, and
//! only for a tenant whose user actually opened the app. A tenant nobody logged
//! into, a guest arriving on a share link, a manifest changed by an upgrade
//! nobody has opened yet — all end up with documents stored but not indexed.
//!
//! The data is a property of the bundle, so it is loaded from the bundle: the
//! frontend build serialises each bundled app's manifest into `dist`, and this
//! registry reads them at startup. Conceptually the `tn_id = 0` tier, but held in
//! memory and **never written to `doc_formats`** — nothing is duplicated into the
//! database, and there is nothing to migrate when the bundle changes.
//!
//! # Precedence
//!
//! A tenant row always wins, whatever its `formatVersion`. A row means the tenant
//! deliberately installed something — usually a packaged app whose code lives in a
//! blob — and a backend upgrade must never silently repoint it at a bundled app.
//! `DELETE /api/doc-formats/{content_type}` drops the row and reverts to the
//! bundled entry. There is no way to *suppress* a bundled format, only to override
//! it; see `cloudillo_core::doc_format` for the resolution itself.
//!
//! # Failure is not fatal
//!
//! `DIST_DIR` is externally supplied data that a deployment can point anywhere,
//! and dev checkouts frequently have no `dist` at all. A missing directory, an
//! unreadable file, malformed JSON or an invalid `search` block therefore degrade
//! — to an empty registry, or to one format fewer — rather than failing startup.
//! An empty registry leaves resolution entirely to the tenant's own rows.

use std::{collections::HashMap, fmt::Write as _, path::Path};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use cloudillo_types::meta_adapter::DocFormat;

use crate::prelude::*;

/// Publisher recorded for a bundled manifest that names none. The bundle is the
/// platform's own build, so its apps are the platform's own publications.
const DEFAULT_PUBLISHER_TAG: &str = "cloudillo.org";

/// The aggregate file holding the shell's internal apps, which have no
/// `dist/apps/<id>` directory of their own. A JSON array of manifests.
const SHELL_MANIFESTS_FILE: &str = "shell-apps.json";

/// Per-app manifest file, `dist/apps/<id>/cloudillo.json`. A single manifest
/// object, and the same name (and format) an APKG package carries — which is what
/// will let a packaged app's install feed this same loader later.
const APP_MANIFEST_FILE: &str = "cloudillo.json";

/// The doc formats the bundle declares, keyed by content type.
#[derive(Debug, Default)]
pub struct BundledAppRegistry {
	formats: HashMap<Box<str>, DocFormat>,
	/// Stable hash over the `(content_type, search)` pairs only — the staleness
	/// stamp `cloudillo_search::reindex` folds into `search.index_rev` so a bundle
	/// whose index rules changed triggers exactly one reindex per tenant. See
	/// [`rules_hash`].
	pub rules_hash: Box<str>,
	/// Manifests that contributed at least one format. Logged at startup.
	pub app_count: usize,
}

impl BundledAppRegistry {
	/// Read every manifest under `dist_dir`. Never fails: see the module docs.
	///
	/// `validate_search` checks one `search` block and returns why it is bad. It
	/// is a callback rather than a direct call because the rules DSL lives in
	/// `cloudillo-search`, which depends on this crate — validating here would be
	/// a dependency cycle. A block it rejects costs that one content type its
	/// entry, nothing else.
	pub fn load<F>(dist_dir: &Path, validate_search: F) -> Self
	where
		F: Fn(&serde_json::Value) -> Result<(), String>,
	{
		let mut manifests = read_manifests(dist_dir);
		if manifests.is_empty() {
			info!(dist_dir = %dist_dir.display(), "No bundled app manifests found");
			return Self::default();
		}
		// Deterministic order, so a content type two apps both claim without a
		// `primary` marker resolves the same way on every node and every boot.
		manifests.sort_by(|a, b| a.manifest.id.cmp(&b.manifest.id));

		// The `bool` is "this entry claimed `primary`", which is what lets a later
		// app take a content type an earlier one already holds.
		let mut formats: HashMap<Box<str>, (DocFormat, bool)> = HashMap::new();
		let mut app_count = 0usize;
		for LoadedManifest { manifest, updated_at } in &manifests {
			let publisher = manifest.publisher.as_deref().unwrap_or(DEFAULT_PUBLISHER_TAG);
			let mut contributed = false;
			for ct in &manifest.content_types {
				if let Some(search) = &ct.search
					&& let Err(e) = validate_search(search)
				{
					error!(app = %manifest.id, content_type = %ct.mime_type, error = %e,
						"Bundled manifest has an invalid search block; skipping this format");
					continue;
				}
				let primary = ct.priority.as_deref() == Some("primary");
				if let Some((held, held_primary)) = formats.get(ct.mime_type.as_str())
					&& (*held_primary || !primary)
				{
					warn!(content_type = %ct.mime_type, held_by = %held.app_name,
						challenger = %manifest.id,
						"Two bundled apps declare the same content type; keeping the first");
					continue;
				}
				let format = DocFormat {
					content_type: ct.mime_type.as_str().into(),
					publisher_tag: publisher.into(),
					app_name: manifest.id.as_str().into(),
					format_version: ct.format_version.as_deref().and_then(|v| {
						let encoded = encode_format_version(v);
						if encoded.is_none() {
							warn!(app = %manifest.id, content_type = %ct.mime_type,
								format_version = %v, "Unparseable formatVersion; ignoring it");
						}
						encoded
					}),
					store_tp: ct.store_tp.as_deref().map(Into::into),
					nav_param: ct.nav_param.as_deref().map(Into::into),
					search: ct.search.clone(),
					x: None,
					updated_at: *updated_at,
				};
				formats.insert(ct.mime_type.as_str().into(), (format, primary));
				contributed = true;
			}
			app_count += usize::from(contributed);
		}

		let formats: HashMap<Box<str>, DocFormat> =
			formats.into_iter().map(|(ct, (fmt, _))| (ct, fmt)).collect();
		let rules_hash = rules_hash(&formats);
		info!(apps = app_count, formats = formats.len(), rules_hash = %rules_hash,
			"Bundled app manifests loaded");
		Self { formats, rules_hash, app_count }
	}

	pub fn get(&self, content_type: &str) -> Option<&DocFormat> {
		self.formats.get(content_type)
	}

	pub fn iter(&self) -> impl Iterator<Item = &DocFormat> {
		self.formats.values()
	}

	pub fn is_empty(&self) -> bool {
		self.formats.is_empty()
	}

	pub fn len(&self) -> usize {
		self.formats.len()
	}
}

/// One manifest, plus the mtime of the file it came from — the closest thing a
/// bundled entry has to the `updated_at` a tenant row gets from its write.
struct LoadedManifest {
	manifest: BundledManifest,
	updated_at: Timestamp,
}

/// The slice of an app manifest the backend cares about.
///
/// Deliberately no `deny_unknown_fields`: the same file carries everything the
/// frontend needs (icons, launch modes, translations, …) and those must stay
/// free to change without turning into a startup warning here.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundledManifest {
	id: String,
	/// Publisher `id_tag`. Absent on every manifest today; see
	/// [`DEFAULT_PUBLISHER_TAG`].
	publisher: Option<String>,
	#[serde(default)]
	content_types: Vec<BundledContentType>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundledContentType {
	mime_type: String,
	/// `"primary"` wins a content type two bundled apps both declare. Mirrors the
	/// shell's own `buildMimeMap`.
	priority: Option<String>,
	store_tp: Option<String>,
	nav_param: Option<String>,
	/// `major.minor.patch`, encoded by [`encode_format_version`].
	format_version: Option<String>,
	search: Option<serde_json::Value>,
}

/// Read `shell-apps.json` and every `apps/*/cloudillo.json` under `dist_dir`.
fn read_manifests(dist_dir: &Path) -> Vec<LoadedManifest> {
	let mut out = Vec::new();
	read_manifest_file(&dist_dir.join(SHELL_MANIFESTS_FILE), &mut out);

	let apps_dir = dist_dir.join("apps");
	let entries = match std::fs::read_dir(&apps_dir) {
		Ok(entries) => entries,
		Err(e) => {
			info!(dir = %apps_dir.display(), error = %e, "No bundled app directory");
			return out;
		}
	};
	for entry in entries.flatten() {
		read_manifest_file(&entry.path().join(APP_MANIFEST_FILE), &mut out);
	}
	out
}

/// Append the manifest(s) in one file. A file that is absent is normal; a file
/// that is present and broken is worth a warning, but never fatal.
fn read_manifest_file(path: &Path, out: &mut Vec<LoadedManifest>) {
	let text = match std::fs::read_to_string(path) {
		Ok(text) => text,
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
		Err(e) => {
			warn!(path = %path.display(), error = %e, "Cannot read bundled app manifest");
			return;
		}
	};
	let updated_at = file_mtime(path);
	match parse_manifests(&text) {
		Ok(manifests) => out
			.extend(manifests.into_iter().map(|manifest| LoadedManifest { manifest, updated_at })),
		Err(e) => warn!(path = %path.display(), error = %e, "Invalid bundled app manifest"),
	}
}

/// A per-app file holds one manifest object, the shell's aggregate an array of
/// them. Both go through here so either shape works in either file.
fn parse_manifests(text: &str) -> ClResult<Vec<BundledManifest>> {
	let value: serde_json::Value = serde_json::from_str(text)?;
	match value {
		serde_json::Value::Array(items) => items
			.into_iter()
			.map(|item| serde_json::from_value(item).map_err(Error::from))
			.collect(),
		other => Ok(vec![serde_json::from_value(other)?]),
	}
}

fn file_mtime(path: &Path) -> Timestamp {
	std::fs::metadata(path)
		.and_then(|meta| meta.modified())
		.ok()
		.and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
		.map_or(Timestamp(0), |d| Timestamp(d.as_secs().cast_signed()))
}

/// Hash of everything in this bundle that changes what gets indexed.
///
/// Folded into the per-tenant index staleness stamp, so it must cover the
/// `search` rules and **nothing else**: including `nav_param`, `store_tp`, app
/// names or versions would make a cosmetic manifest edit re-index every document
/// of every tenant on the node.
///
/// `serde_json::Map` is a `BTreeMap` here, so `to_string` already emits object
/// keys in a fixed order; sorting the pairs covers the map iteration order.
fn rules_hash(formats: &HashMap<Box<str>, DocFormat>) -> Box<str> {
	let mut entries: Vec<(&str, String)> = formats
		.iter()
		.filter_map(|(ct, fmt)| fmt.search.as_ref().map(|s| (&**ct, s.to_string())))
		.collect();
	entries.sort_unstable();

	let mut hasher = Sha256::new();
	for (content_type, search) in entries {
		// Length-prefixed, so no pair of (content type, rules) can be re-split
		// into a different pair with the same concatenation. `u64` rather than
		// `usize`: the stamp should not change because the node is 32-bit.
		hasher.update((content_type.len() as u64).to_le_bytes());
		hasher.update(content_type.as_bytes());
		hasher.update((search.len() as u64).to_le_bytes());
		hasher.update(search.as_bytes());
	}
	let digest = hasher.finalize();
	let mut out = String::with_capacity(16);
	for b in &digest[..8] {
		let _ = write!(&mut out, "{b:02x}");
	}
	out.into()
}

/// `"1.0.0"` → `1_000_000`. The inverse of the frontend's `decodeFormatVersion`
/// and the exact encoding `encodeFormatVersion` produces: three decimal digits
/// per component, `major * 1_000_000 + minor * 1_000 + patch`, each component
/// `0..=999`.
///
/// `None` for anything else — a two-component version, a component out of range,
/// anything non-numeric. The caller treats that as "no version stated", which the
/// registration gate already handles.
pub fn encode_format_version(s: &str) -> Option<i64> {
	let mut parts = s.split('.');
	let mut component = || -> Option<i64> {
		let part = parts.next()?;
		// `str::parse` accepts a leading `+`, which is not a version.
		if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
			return None;
		}
		part.parse::<i64>().ok().filter(|v| *v <= 999)
	};
	let major = component()?;
	let minor = component()?;
	let patch = component()?;
	if parts.next().is_some() {
		return None;
	}
	Some(major * 1_000_000 + minor * 1_000 + patch)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
	use super::*;

	/// Stands in for the server's `IndexRules::parse`: a `search` block is good
	/// unless it says `{"bad": ...}`.
	fn validate(v: &serde_json::Value) -> Result<(), String> {
		if v.get("bad").is_some() { Err("bad rules".to_owned()) } else { Ok(()) }
	}

	#[test]
	fn a_version_encodes_the_way_the_frontend_encodes_it() {
		assert_eq!(encode_format_version("0.0.0"), Some(0));
		assert_eq!(encode_format_version("1.0.0"), Some(1_000_000));
		assert_eq!(encode_format_version("2.1.42"), Some(2_001_042));
		// The upper bound `cloudillo_search::format::FORMAT_VERSION_MAX` accepts.
		assert_eq!(encode_format_version("999.999.999"), Some(999_999_999));
	}

	#[test]
	fn anything_the_encoding_cannot_represent_is_no_version_at_all() {
		// A component over 999 would carry into the next one, so `1000.0.0` and
		// `1.0.0` would encode identically — worse than having no ordering.
		assert_eq!(encode_format_version("1000.0.0"), None);
		assert_eq!(encode_format_version("1.1000.0"), None);
		assert_eq!(encode_format_version("1.0"), None);
		assert_eq!(encode_format_version("1.0.0.0"), None);
		assert_eq!(encode_format_version("x"), None);
		assert_eq!(encode_format_version(""), None);
		assert_eq!(encode_format_version("1.0.+0"), None);
		assert_eq!(encode_format_version("-1.0.0"), None);
		assert_eq!(encode_format_version("1.0.0-beta"), None);
	}

	fn rules(title: &str) -> serde_json::Value {
		serde_json::json!({ "v": 1, "parts": [{ "kind": "p", "title": [title] }] })
	}

	fn write_app(dist: &Path, id: &str, manifest: &serde_json::Value) {
		let dir = dist.join("apps").join(id);
		std::fs::create_dir_all(&dir).expect("create app dir");
		std::fs::write(dir.join(APP_MANIFEST_FILE), manifest.to_string()).expect("write manifest");
	}

	fn app_manifest(id: &str, mime: &str, search: Option<&serde_json::Value>) -> serde_json::Value {
		serde_json::json!({
			"id": id,
			"name": id,
			"version": "1.2.3",
			"kind": "bundled",
			"icon": "file",
			"contentTypes": [{
				"mimeType": mime,
				"storeTp": "RTDB",
				"navParam": "nav",
				"formatVersion": "1.0.0",
				"search": search
			}]
		})
	}

	#[test]
	fn a_missing_dist_tree_is_an_empty_registry_not_a_failure() {
		// The dev default: `DIST_DIR` pointing at a path that does not exist. Every
		// doc-format path then resolves from the tenant's own rows alone.
		let reg = BundledAppRegistry::load(Path::new("/nonexistent/dist"), validate);
		assert!(reg.is_empty());
		assert_eq!(reg.app_count, 0);
	}

	#[test]
	fn both_the_per_app_files_and_the_shell_aggregate_are_read() {
		let dir = tempfile::tempdir().expect("tempdir");
		let dist = dir.path();
		write_app(
			dist,
			"notillo",
			&app_manifest("notillo", "cloudillo/notillo", Some(&rules("ti"))),
		);
		// The shell's internal apps have no `dist/apps/<id>` of their own, so they
		// arrive as one array.
		std::fs::write(
			dist.join(SHELL_MANIFESTS_FILE),
			serde_json::json!([
				app_manifest("files", "cloudillo/files", None),
				app_manifest("feed", "cloudillo/feed", Some(&rules("fe"))),
			])
			.to_string(),
		)
		.expect("write shell manifests");

		let reg = BundledAppRegistry::load(dist, validate);

		assert_eq!(reg.len(), 3);
		assert_eq!(reg.app_count, 3);
		let notillo = reg.get("cloudillo/notillo").expect("notillo missing");
		assert_eq!(&*notillo.app_name, "notillo");
		assert_eq!(&*notillo.publisher_tag, DEFAULT_PUBLISHER_TAG);
		assert_eq!(notillo.format_version, Some(1_000_000));
		assert_eq!(notillo.nav_param.as_deref(), Some("nav"));
		assert_eq!(notillo.store_tp.as_deref(), Some("RTDB"));
		// A content type with no `search` still resolves — `storeTp` and `navParam`
		// matter to the file and search handlers even when nothing is indexed.
		assert!(reg.get("cloudillo/files").is_some());
	}

	#[test]
	fn a_manifest_may_name_its_own_publisher() {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut manifest = app_manifest("thirdillo", "x/thirdillo", None);
		manifest["publisher"] = serde_json::json!("other.example");
		write_app(dir.path(), "thirdillo", &manifest);

		let reg = BundledAppRegistry::load(dir.path(), validate);

		let fmt = reg.get("x/thirdillo").expect("thirdillo missing");
		assert_eq!(&*fmt.publisher_tag, "other.example");
	}

	#[test]
	fn a_primary_declaration_wins_a_contested_content_type() {
		let dir = tempfile::tempdir().expect("tempdir");
		let dist = dir.path();
		// `aaa` sorts first and would win on order alone.
		write_app(dist, "aaa", &app_manifest("aaa", "cloudillo/shared", Some(&rules("a"))));
		let mut zzz = app_manifest("zzz", "cloudillo/shared", Some(&rules("z")));
		zzz["contentTypes"][0]["priority"] = serde_json::json!("primary");
		write_app(dist, "zzz", &zzz);

		let reg = BundledAppRegistry::load(dist, validate);

		assert_eq!(reg.len(), 1);
		let fmt = reg.get("cloudillo/shared").expect("shared missing");
		assert_eq!(&*fmt.app_name, "zzz");
	}

	#[test]
	fn without_a_primary_the_first_app_in_sorted_order_keeps_it() {
		// Deterministic across nodes and boots, which `read_dir` order is not.
		let dir = tempfile::tempdir().expect("tempdir");
		let dist = dir.path();
		write_app(dist, "aaa", &app_manifest("aaa", "cloudillo/shared", Some(&rules("a"))));
		write_app(dist, "zzz", &app_manifest("zzz", "cloudillo/shared", Some(&rules("z"))));

		let reg = BundledAppRegistry::load(dist, validate);

		let fmt = reg.get("cloudillo/shared").expect("shared missing");
		assert_eq!(&*fmt.app_name, "aaa");
	}

	#[test]
	fn an_invalid_search_block_costs_only_its_own_format() {
		// A stale or hand-edited dist must not brick the node.
		let dir = tempfile::tempdir().expect("tempdir");
		let dist = dir.path();
		write_app(
			dist,
			"broken",
			&app_manifest("broken", "cloudillo/broken", Some(&serde_json::json!({ "bad": true }))),
		);
		write_app(
			dist,
			"notillo",
			&app_manifest("notillo", "cloudillo/notillo", Some(&rules("ti"))),
		);

		let reg = BundledAppRegistry::load(dist, validate);

		assert!(reg.get("cloudillo/broken").is_none());
		assert!(reg.get("cloudillo/notillo").is_some());
	}

	#[test]
	fn unparseable_json_costs_only_its_own_file() {
		let dir = tempfile::tempdir().expect("tempdir");
		let dist = dir.path();
		std::fs::create_dir_all(dist.join("apps").join("junk")).expect("create junk dir");
		std::fs::write(dist.join("apps").join("junk").join(APP_MANIFEST_FILE), "{ not json")
			.expect("write junk");
		write_app(
			dist,
			"notillo",
			&app_manifest("notillo", "cloudillo/notillo", Some(&rules("ti"))),
		);

		let reg = BundledAppRegistry::load(dist, validate);

		assert_eq!(reg.len(), 1);
		assert!(reg.get("cloudillo/notillo").is_some());
	}

	#[test]
	fn the_rules_hash_tracks_the_search_blocks_and_nothing_else() {
		let mut a: HashMap<Box<str>, DocFormat> = HashMap::new();
		let fmt = |ct: &str, nav: &str, search: serde_json::Value| DocFormat {
			content_type: ct.into(),
			publisher_tag: "cloudillo.org".into(),
			app_name: "notillo".into(),
			format_version: Some(1_000_000),
			store_tp: Some("RTDB".into()),
			nav_param: Some(nav.into()),
			search: Some(search),
			x: None,
			updated_at: Timestamp(0),
		};
		a.insert("x/one".into(), fmt("x/one", "nav", rules("ti")));
		a.insert("x/two".into(), fmt("x/two", "nav", rules("tj")));

		// Same content, built in the other order: a `HashMap` iterates differently
		// but the stamp must not, or every boot would re-index every tenant.
		let mut b: HashMap<Box<str>, DocFormat> = HashMap::new();
		b.insert("x/two".into(), fmt("x/two", "nav", rules("tj")));
		b.insert("x/one".into(), fmt("x/one", "nav", rules("ti")));
		assert_eq!(rules_hash(&a), rules_hash(&b));

		// A cosmetic edit must not cost a reindex.
		let mut nav_changed = a.clone();
		nav_changed.insert("x/one".into(), fmt("x/one", "page", rules("ti")));
		assert_eq!(rules_hash(&a), rules_hash(&nav_changed));

		// A rules edit must.
		let mut rules_changed = a.clone();
		rules_changed.insert("x/one".into(), fmt("x/one", "nav", rules("changed")));
		assert_ne!(rules_hash(&a), rules_hash(&rules_changed));
	}
}

// vim: ts=4
