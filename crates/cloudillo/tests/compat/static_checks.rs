// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Static checks over the workspace sources (text scan, no parsing).

use std::path::{Path, PathBuf};

/// `file:struct` pairs allowed to carry `deny_unknown_fields`. Only structs that never see a
/// request body or stored data from another release belong here.
const DENY_UNKNOWN_FIELDS_ALLOWLIST: &[&str] = &[
	// Search rules shipped inside the server's own action definitions, kept strict.
	"crates/cloudillo-search/src/rules.rs:RawActionRules",
	"crates/cloudillo-search/src/rules.rs:RawRules",
	"crates/cloudillo-search/src/rules.rs:RawPart",
	"crates/cloudillo-search/src/rules.rs:RawAttachTo",
	"crates/cloudillo-search/src/rules.rs:RawFullField",
	"crates/cloudillo-search/src/rules.rs:RawLimits",
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
	let Ok(entries) = std::fs::read_dir(dir) else { return };
	for entry in entries.flatten() {
		let path = entry.path();
		if path.is_dir() {
			if path.file_name().is_some_and(|n| n == "target") {
				continue;
			}
			rust_files(&path, out);
		} else if path.extension().is_some_and(|e| e == "rs") {
			out.push(path);
		}
	}
}

/// Name of the first `struct`/`enum` declared at or after `lines[from]`.
fn next_type_name(lines: &[&str], from: usize) -> Option<String> {
	lines.iter().skip(from).find_map(|line| {
		let mut words = line.split(|c: char| !(c.is_alphanumeric() || c == '_'));
		words.by_ref().find(|w| *w == "struct" || *w == "enum")?;
		words.find(|w| !w.is_empty()).map(str::to_string)
	})
}

/// Every `file:Type` under `<root>/{crates,adapters,server}/**/src/` carrying
/// `deny_unknown_fields` outside a comment.
fn deny_unknown_fields_sites(root: &Path) -> Vec<String> {
	let mut files = Vec::new();
	for top in ["crates", "adapters", "server"] {
		rust_files(&root.join(top), &mut files);
	}
	let mut sites = Vec::new();
	for file in files {
		let rel = file.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
		if !rel.contains("/src/") {
			continue;
		}
		let text = std::fs::read_to_string(&file).unwrap();
		let lines: Vec<&str> = text.lines().collect();
		for (i, line) in lines.iter().enumerate() {
			let code = line.split("//").next().unwrap_or("");
			if code.contains("deny_unknown_fields") {
				let name = next_type_name(&lines, i).unwrap_or_else(|| format!("line {}", i + 1));
				sites.push(format!("{rel}:{name}"));
			}
		}
	}
	sites.sort();
	sites
}

/// A request or stored struct with `deny_unknown_fields` refuses whatever a newer release adds
/// (compat rules W1/A1). New strict structs need an allowlist entry and a reason.
#[test]
fn no_deny_unknown_fields_outside_allowlist() {
	let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
	let sites = deny_unknown_fields_sites(&root);
	let unexpected: Vec<&String> = sites
		.iter()
		.filter(|s| !DENY_UNKNOWN_FIELDS_ALLOWLIST.contains(&s.as_str()))
		.collect();
	assert!(unexpected.is_empty(), "deny_unknown_fields outside the allowlist: {unexpected:#?}");
	// A stale entry would silently re-allow a struct of the same name later.
	let stale: Vec<&&str> = DENY_UNKNOWN_FIELDS_ALLOWLIST
		.iter()
		.filter(|a| !sites.iter().any(|s| s == *a))
		.collect();
	assert!(stale.is_empty(), "allowlist entries no longer present: {stale:#?}");
}
