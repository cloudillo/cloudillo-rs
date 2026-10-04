// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Mismatch collection, grouping and the report file.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use cloudillo::types::AccessLevel;

use crate::ops::Actual;
use crate::oracle::Expect;

/// Report file of one layer: `$CARGO_TARGET_TMPDIR/access-matrix-{layer}.md`.
pub fn report_path(layer: &str) -> String {
	format!("{}/access-matrix-{layer}.md", env!("CARGO_TARGET_TMPDIR"))
}

const SAMPLES: usize = 5;

pub struct Mismatch {
	pub op: String,
	pub rule: &'static str,
	pub expected: String,
	pub actual: String,
	pub subject: String,
	pub object: String,
}

type Key = (String, &'static str, String, String);
type Group = (usize, Vec<(String, String)>);

pub struct Report {
	layer: &'static str,
	cells: usize,
	groups: BTreeMap<Key, Group>,
	/// Harness errors `(op, detail)`; always fail.
	errors: BTreeMap<(String, String), Group>,
}

fn push(g: &mut Group, subject: String, object: String) {
	g.0 += 1;
	if g.1.len() < SAMPLES {
		g.1.push((subject, object));
	}
}

/// `Allow` / `Present@Write`: the level is appended only where the oracle expects one.
fn fmt_level(s: String, want_level: bool, level: Option<AccessLevel>) -> String {
	if want_level { format!("{s}@{level:?}") } else { s }
}

impl Report {
	pub fn new(layer: &'static str) -> Self {
		Self { layer, cells: 0, groups: BTreeMap::new(), errors: BTreeMap::new() }
	}

	/// Count one cell whose outcome the caller judges itself.
	pub fn cell(&mut self) {
		self.cells += 1;
	}

	pub fn add(&mut self, m: Mismatch) {
		let g = self.groups.entry((m.op, m.rule, m.expected, m.actual)).or_default();
		push(g, m.subject, m.object);
	}

	pub fn error(&mut self, op: String, detail: String, subject: String, object: String) {
		push(self.errors.entry((op, detail)).or_default(), subject, object);
	}

	/// Compare one cell with its expectation; `level` is the reported level (if any).
	pub fn check(
		&mut self,
		op: String,
		exp: Expect,
		act: Actual,
		level: Option<AccessLevel>,
		subject: String,
		object: String,
	) {
		self.cells += 1;
		if let Actual::HarnessError(d) = act {
			return self.error(op, d, subject, object);
		}
		// `Outcome` and `Actual` share variant names.
		let expected = fmt_level(format!("{:?}", exp.outcome), exp.level.is_some(), exp.level);
		let actual = fmt_level(format!("{act:?}"), exp.level.is_some(), level);
		if expected != actual {
			self.add(Mismatch { op, rule: exp.rule, expected, actual, subject, object });
		}
	}

	/// Write the report and fail on any harness error or mismatch group.
	pub fn finish(self) {
		let layer = self.layer;
		let path = report_path(layer);
		let n_err: usize = self.errors.values().map(|g| g.0).sum();
		let n_mis: usize = self.groups.values().map(|g| g.0).sum();

		let mut out = format!(
			"# Access matrix report — {layer}\n\n{} cells, {} mismatches in {} groups, {} harness \
			 errors\n",
			self.cells,
			n_mis,
			self.groups.len(),
			n_err,
		);
		let samples = |g: &Group| {
			g.1.iter().map(|(s, o)| format!("`{s}` → `{o}`")).collect::<Vec<_>>().join(", ")
		};
		if !self.errors.is_empty() {
			out.push_str(
				"\n## Harness errors\n\n| op | detail | count | samples |\n|---|---|---|---|\n",
			);
			for ((op, d), g) in &self.errors {
				let _ = writeln!(out, "| {op} | {d} | {} | {} |", g.0, samples(g));
			}
		}
		out.push_str(
			"\n## Mismatches\n\n| op | rule | expected | actual | count | samples |\n\
			 |---|---|---|---|---|---|\n",
		);
		for ((op, rule, e, a), g) in &self.groups {
			let _ = writeln!(out, "| {op} | {rule} | {e} | {a} | {} | {} |", g.0, samples(g));
		}
		std::fs::write(&path, &out).expect("write access-matrix report");
		tracing::info!(
			"access matrix [{layer}]: {} cells, {n_mis} mismatches, {n_err} harness errors — {path}",
			self.cells
		);
		assert!(
			n_err == 0 && self.groups.is_empty(),
			"access matrix [{layer}]: {n_err} harness errors, {} mismatch groups — see {path}",
			self.groups.len()
		);
	}
}

// vim: ts=4
