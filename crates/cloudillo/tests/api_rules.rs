// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Source-scanning enforcement of the API rules. Each test reads the workspace sources as text
//! (non-test code only, whole-line comments dropped) and fails with every offending
//! `path:line`. An allowlist entry names the exact item and why it is exempt.
//!
//! "No side effects on GET" is a review-checklist item, not a test.

#![allow(
	clippy::unwrap_used,
	clippy::expect_used,
	clippy::panic,
	clippy::many_single_char_names,
	clippy::cast_possible_truncation,
	clippy::cast_possible_wrap
)]

use std::fs;
use std::path::{Path, PathBuf};

fn workspace() -> PathBuf {
	Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
	let Ok(entries) = fs::read_dir(dir) else { return };
	for entry in entries.flatten() {
		let path = entry.path();
		if path.is_dir() {
			walk(&path, out);
		} else if path.extension().is_some_and(|e| e == "rs") {
			out.push(path);
		}
	}
}

/// `(workspace-relative path, non-test code lines)` for every `.rs` under `crates/*/src` and
/// `adapters/*/src`. Whole-line comments and every `#[cfg(test)]` item (the attribute through
/// the item's closing brace, or a one-line item ending in `;`) become empty lines, so line
/// numbers stay true.
fn sources() -> Vec<(String, Vec<String>)> {
	let root = workspace();
	let mut files = Vec::new();
	for group in ["crates", "adapters"] {
		let Ok(entries) = fs::read_dir(root.join(group)) else { continue };
		for entry in entries.flatten() {
			walk(&entry.path().join("src"), &mut files);
		}
	}
	files.sort();
	let mut out = Vec::new();
	for path in files {
		let src = fs::read_to_string(&path).unwrap();
		let rel = path.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
		let mut lines = Vec::new();
		// `Some(depth)` while skipping a test item; depth 0 = its body has not opened yet.
		let mut skip: Option<i32> = None;
		for line in src.lines() {
			let t = line.trim_start();
			if let Some(depth) = skip.as_mut() {
				lines.push(String::new());
				let opens = line.matches('{').count() as i32;
				if *depth == 0 && opens == 0 {
					if t.trim_end().ends_with(';') {
						skip = None;
					}
					continue;
				}
				*depth += opens - line.matches('}').count() as i32;
				if *depth <= 0 {
					skip = None;
				}
				continue;
			}
			if t.trim_end() == "#[cfg(test)]" {
				skip = Some(0);
				lines.push(String::new());
				continue;
			}
			lines.push(if t.starts_with("//") { String::new() } else { line.to_owned() });
		}
		out.push((rel, lines));
	}
	out
}

fn fail(rule: &str, hits: &[String]) {
	assert!(hits.is_empty(), "{rule}:\n  {}", hits.join("\n  "));
}

/// Files whose serde items may reach the REST wire, outside `cloudillo-types` (whose wire types
/// carry their own tests): a file with an axum `Json`/`Query` extractor or response, or any
/// `src/types.rs` (view/request types kept apart from their handlers). Not every `crates/*/src`
/// file: that pulled in 30+ scheduler payloads, DSL config and ffmpeg probe structs, none REST.
fn in_rest_scope(rel: &str, lines: &[String]) -> bool {
	rel.starts_with("crates/")
		&& !rel.starts_with("crates/cloudillo-types/")
		&& (rel.ends_with("/src/types.rs")
			|| lines.iter().any(|l| l.contains("Json<") || l.contains("Query<")))
}

/// Fail on an ALLOW entry that names no `async fn` / `struct` / `enum` in its file, or several.
fn check_allow(rule: &str, keyword: &[&str], allow: &[(&str, &str)]) {
	let src = sources();
	let mut stale = Vec::new();
	for (file, name) in allow {
		let n = src
			.iter()
			.filter(|(rel, _)| rel == file)
			.flat_map(|(_, lines)| lines)
			.filter(|l| {
				keyword.iter().any(|k| {
					l.match_indices(&format!("{k} {name}")).any(|(at, m)| {
						!l[at + m.len()..].starts_with(|c: char| c.is_alphanumeric() || c == '_')
					})
				})
			})
			.count();
		if n != 1 {
			stale.push(format!("{file} {name}: {n} matches"));
		}
	}
	fail(&format!("{rule}: stale or ambiguous ALLOW entry"), &stale);
}

/// Index just past the item body that opens on `lines[from]`: where brace depth returns to 0.
fn body_end(lines: &[String], from: usize) -> usize {
	let mut depth = 0i32;
	for (j, l) in lines.iter().enumerate().skip(from) {
		depth += l.matches('{').count() as i32 - l.matches('}').count() as i32;
		if depth <= 0 && j > from {
			return j + 1;
		}
	}
	lines.len()
}

/// Rule 1: a JSON handler returns `ApiResponse<T>` — every `Json<…>` in an `async fn` return
/// type wraps `ApiResponse`, and a handler returning `Response` / `impl IntoResponse` builds no
/// `Json(` on a line without `ApiResponse`. Binary, CSV, DAV, ACME, `.well-known`,
/// export-download and apkg handlers return no `Json` at all, so they need no entry here.
#[test]
fn json_handlers_return_api_response() {
	/// `(file, fn)` — why it may return a bare `Json`.
	const ALLOW: &[(&str, &str)] = &[
		// `/.well-known/cloudillo/id-tag`: a federation discovery document, not REST.
		("crates/cloudillo-auth/src/handler.rs", "get_id_tag"),
		// Helper, not a handler: every caller unpacks it and re-wraps it in `ApiResponse`.
		("crates/cloudillo-auth/src/handler.rs", "return_login"),
		// Builds `ApiResponse` itself, then returns it as a `Value` (two response shapes).
		("crates/cloudillo-ref/src/handler.rs", "get_ref"),
	];
	check_allow("json_handlers_return_api_response", &["async fn"], ALLOW);
	let mut hits = Vec::new();
	for (rel, lines) in sources() {
		for (i, line) in lines.iter().enumerate() {
			let Some((_, rest)) = line.split_once("async fn ") else { continue };
			let name: String =
				rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
			if ALLOW.contains(&(rel.as_str(), name.as_str())) {
				continue;
			}
			// The signature runs to the first line that opens the body at paren depth 0.
			let mut sig = String::new();
			let mut depth = 0i32;
			let mut open = i;
			for (j, l) in lines.iter().enumerate().skip(i) {
				sig.push_str(l);
				sig.push(' ');
				depth += l.matches('(').count() as i32 - l.matches(')').count() as i32;
				if depth <= 0 && (l.trim_end().ends_with('{') || l.trim_end().ends_with(';')) {
					open = j;
					break;
				}
			}
			let Some((_, ret)) = sig.rsplit_once(") -> ") else { continue };
			let bare = ret
				.match_indices("Json<")
				.any(|(at, m)| !ret[at + m.len()..].trim_start().starts_with("ApiResponse"));
			if bare {
				hits.push(format!("{rel}:{} {name}", i + 1));
				continue;
			}
			let ret = ret.trim_end().trim_end_matches('{').trim_end();
			let opaque = ["impl IntoResponse", "Response"]
				.iter()
				.any(|r| ret == *r || ret == format!("ClResult<{r}>"));
			if opaque && sig.trim_end().ends_with('{') {
				let end = body_end(&lines, open);
				if let Some(j) = (open..end)
					.find(|&j| lines[j].contains("Json(") && !lines[j].contains("ApiResponse"))
				{
					hits.push(format!("{rel}:{} {name}", j + 1));
				}
			}
		}
	}
	fail("JSON handler returning a bare Json<…> instead of Json<ApiResponse<…>>", &hits);
}

/// One `#[derive(..Serialize|Deserialize..)]` item in a handler file.
struct SerdeItem {
	line: usize,
	name: String,
	is_enum: bool,
	/// Every attribute line of the item, joined.
	attrs: String,
	/// `(line, field or variant line, preceding attribute lines)`.
	members: Vec<(usize, String, String)>,
}

fn serde_items(lines: &[String]) -> Vec<SerdeItem> {
	let mut items = Vec::new();
	let mut i = 0;
	while i < lines.len() {
		let t = lines[i].trim();
		if !(t.starts_with("#[derive(") && (t.contains("Serialize") || t.contains("Deserialize"))) {
			i += 1;
			continue;
		}
		// Attributes stacked above the derive, then everything down to the declaration.
		let mut attrs = String::new();
		let mut k = i;
		while k > 0 && lines[k - 1].trim().starts_with("#[") {
			k -= 1;
			attrs.push_str(&lines[k]);
		}
		let mut j = i;
		let decl = loop {
			let Some(l) = lines.get(j) else { break None };
			let d = l.trim().trim_start_matches("pub(crate) ").trim_start_matches("pub ");
			if d.starts_with("struct ") || d.starts_with("enum ") {
				break Some(d.to_owned());
			}
			attrs.push_str(l);
			j += 1;
		};
		let Some(decl) = decl else { break };
		let is_enum = decl.starts_with("enum ");
		let name: String = decl
			.split_whitespace()
			.nth(1)
			.unwrap_or_default()
			.chars()
			.take_while(|c| c.is_alphanumeric() || *c == '_')
			.collect();
		let mut members = Vec::new();
		let mut depth = decl.matches('{').count() as i32 - decl.matches('}').count() as i32;
		let mut pending = String::new();
		j += 1;
		while depth > 0 && j < lines.len() {
			let l = &lines[j];
			// Only direct members (depth 1), not fields of a struct-like enum variant.
			if depth == 1 {
				let t = l.trim();
				let in_attr = pending.matches('[').count() > pending.matches(']').count();
				if t.starts_with("#[") || in_attr {
					pending.push_str(t);
				} else if !t.is_empty() {
					members.push((j + 1, t.to_owned(), std::mem::take(&mut pending)));
				}
			}
			depth += l.matches('{').count() as i32 - l.matches('}').count() as i32;
			j += 1;
		}
		items.push(SerdeItem { line: i + 1, name, is_enum, attrs, members });
		i = j.max(i + 1);
	}
	items
}

/// `(name, type)` of a struct field line; `None` for anything else.
fn field(line: &str) -> Option<(&str, &str)> {
	let t = line.trim_start_matches("pub(crate) ").trim_start_matches("pub ");
	let (name, ty) = t.split_once(':')?;
	(!name.is_empty()
		&& name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
	.then_some((name, ty))
}

/// Rule 2: wire keys are camelCase. A serde struct in a handler file whose multi-word field is
/// neither under `rename_all = "camelCase"` nor individually `rename`d fails, and so does an enum
/// with a multi-word variant and no `rename_all`/`untagged`. Single-word items are exempt: the
/// attribute would be a no-op there, and the test catches the item once it gains a second word.
#[test]
fn handler_serde_items_are_camel_case() {
	/// `(file, item)` — not a REST view: scheduler payloads and JWT claims, never on the API.
	/// (vCard types live outside handler files.)
	const ALLOW: &[(&str, &str)] = &[
		("crates/cloudillo-profile/src/media.rs", "TenantImageType"),
		("crates/cloudillo-profile/src/media.rs", "TenantImageUpdaterTask"),
		("crates/cloudillo-profile/src/register.rs", "PendingWelcomeEmail"),
		("crates/cloudillo-profile/src/partners.rs", "PartnerSyncTask"),
		("crates/cloudillo-auth/src/webauthn.rs", "RegChallengeToken"),
		("crates/cloudillo-auth/src/webauthn.rs", "LoginChallengeToken"),
	];
	check_allow("handler_serde_items_are_camel_case", &["struct", "enum"], ALLOW);
	let squash = |s: &str| s.replace(' ', "");
	// An explicit per-member `rename = "…"` (not `rename_all`).
	let renamed = |pre: &str| squash(pre).contains("rename=\"");
	let mut hits = Vec::new();
	for (rel, lines) in sources() {
		if !in_rest_scope(&rel, &lines) {
			continue;
		}
		for item in serde_items(&lines) {
			if ALLOW.contains(&(rel.as_str(), item.name.as_str())) {
				continue;
			}
			let attrs = squash(&item.attrs);
			let bad = if item.is_enum {
				// `lowercase` yields one-word wire words; anything else but camelCase does not.
				!attrs.contains("rename_all=\"camelCase\"")
					&& !attrs.contains("rename_all=\"lowercase\"")
					&& !attrs.contains("untagged")
					&& item.members.iter().any(|(_, m, pre)| {
						let v: String = m.chars().take_while(char::is_ascii_alphanumeric).collect();
						v.chars().filter(char::is_ascii_uppercase).count() > 1 && !renamed(pre)
					})
			} else {
				!attrs.contains("rename_all=\"camelCase\"")
					&& item.members.iter().any(|(_, m, pre)| {
						field(m).is_some_and(|(n, _)| n.trim_matches('_').contains('_'))
							&& !renamed(pre)
					})
			};
			if bad {
				hits.push(format!("{rel}:{} {}", item.line, item.name));
			}
		}
	}
	fail("serde item with snake_case/PascalCase wire keys (add rename_all = \"camelCase\")", &hits);
}

/// Rule 3: no bare `Timestamp` field in a REST view or request struct — the wire carries
/// `ApiTime` (RFC 3339). `Timestamp` stays the type for storage, scheduler payloads and JWTs.
#[test]
fn rest_structs_use_api_time() {
	/// `(file, item)` — not on the REST wire: scheduler payloads, JWT claims, DB rows.
	const ALLOW: &[(&str, &str)] = &[];
	check_allow("rest_structs_use_api_time", &["struct"], ALLOW);
	let mut hits = Vec::new();
	for (rel, lines) in sources() {
		if !in_rest_scope(&rel, &lines) {
			continue;
		}
		for item in serde_items(&lines) {
			if item.is_enum || ALLOW.contains(&(rel.as_str(), item.name.as_str())) {
				continue;
			}
			for (line, m, _) in &item.members {
				let Some((name, ty)) = field(m) else { continue };
				let bare = ty
					.match_indices("Timestamp")
					.any(|(at, _)| !ty[..at].ends_with(|c: char| c.is_alphanumeric() || c == '_'));
				if bare {
					hits.push(format!("{rel}:{line} {}.{name}", item.name));
				}
			}
		}
	}
	fail("bare Timestamp in a REST struct (use ApiTime)", &hits);
}

/// Rule 4: `cloudillo-types/src/error.rs` is the only source of error codes — no `"E-` string
/// literal anywhere else in non-test code.
#[test]
fn error_codes_only_in_registry() {
	/// `(file, literal prefix)` — strings that start with `"E-` but are not codes.
	const ALLOW: &[(&str, &str)] = &[("crates/cloudillo-core/src/audit.rs", "\"E-mail")];
	let mut hits = Vec::new();
	for (rel, lines) in sources() {
		if rel == "crates/cloudillo-types/src/error.rs" {
			continue;
		}
		for (i, line) in lines.iter().enumerate() {
			let bad = line.match_indices("\"E-").any(|(at, _)| {
				!ALLOW.iter().any(|(f, lit)| *f == rel && line[at..].starts_with(lit))
			});
			if bad {
				hits.push(format!("{rel}:{} {}", i + 1, line.trim()));
			}
		}
	}
	fail("\"E-… literal outside error.rs (use cloudillo_types::error::codes)", &hits);
}

/// Rule 5: no route puts a literal segment where a sibling route of the same length has a
/// capture under the same prefix (`/api/x/rotations` next to `/api/x/{id}`). Any segment
/// containing `{` (incl. `@{publisher}`) is a capture. No allowlist.
#[test]
fn no_literal_segment_beside_a_capture() {
	let mut files = Vec::new();
	walk(&workspace().join("crates/cloudillo/src/routes"), &mut files);
	let mut paths = Vec::new();
	for file in files {
		let src = fs::read_to_string(&file).unwrap();
		let code: String = src
			.lines()
			.filter(|l| !l.trim_start().starts_with("//"))
			.collect::<Vec<_>>()
			.join("\n");
		for (at, m) in code.match_indices(".route(") {
			let rest = code[at + m.len()..].trim_start();
			let Some(rest) = rest.strip_prefix('"') else { continue };
			let Some((path, _)) = rest.split_once('"') else { continue };
			paths.push(path.to_owned());
		}
	}
	paths.sort();
	paths.dedup();
	assert!(paths.len() > 50, "route scan found only {} paths", paths.len());
	let capture = |s: &str| s.contains('{');
	let split: Vec<Vec<&str>> =
		paths.iter().map(|p| p.trim_matches('/').split('/').collect()).collect();
	let mut hits = Vec::new();
	for a in &split {
		for b in &split {
			if a.len() != b.len() {
				continue;
			}
			for i in 0..a.len() {
				let same_prefix = (0..i).all(|j| a[j] == b[j] || (capture(a[j]) && capture(b[j])));
				if same_prefix && !capture(a[i]) && capture(b[i]) {
					hits.push(format!("/{} beside /{}", a.join("/"), b.join("/")));
				}
			}
		}
	}
	fail("literal route segment where a sibling route has a capture", &hits);
}

// vim: ts=4
