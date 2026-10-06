// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Level layers: each layer
//! varies one dimension from a baseline instead of crossing every subject with every object.
//! Baselines: `owner@X`, `stranger@X`; file `tenant-blob-d-active`, action
//! `post-d-tenant-active`.
//! - **subject**: every [`LEVEL_SUBJECTS`](crate::subjects::LEVEL_SUBJECTS) × the baseline
//!   objects at vis `d` and `p` (+ `?fileId=` on the trashed row).
//! - **shape**: every level shape at vis `d` × owner, stranger, a grantee / audience, subscriber.
//! - **vis**: every vis on `TenantOwned` / `Post` × anon, follower, connected, stranger.
//! - **life**: Active / Trashed / Pending / Tombstoned rows × owner, moderator, grantee,
//!   stranger, a scoped owner × metadata, `?fileId=`, `?parentId=` (+ `?status=` listings).
//!
//! Every cell is judged by the oracle. The per-subject list / search / count requests stay
//! full: one request each, joined locally against every level object.

use std::collections::HashMap;

use cloudillo::types::AccessLevel;
use futures::stream::{self, StreamExt};

use crate::fixture::{ALICE, CLUB, Fixture, call};
use crate::objects::{ActionShape, FileKind, FileLife, FileShape, Obj, is_level};
use crate::ops::{
	ActionOp, Actual, FileOp, Op, classify_obj, count_actions, list_paged, list_presence, obj_host,
	obj_key,
};
use crate::oracle::{Outcome, expected, listing};
use crate::report::{Mismatch, Report};
use crate::subjects::{Subject, level_subjects};

const CONC: usize = 16;
const FILE_LISTS: [Op; 2] = [Op::File(FileOp::List), Op::Search];
const ACTION_LISTS: [Op; 2] = [Op::Action(ActionOp::List), Op::Search];
const LIFE_LISTS: [Op; 2] = [Op::File(FileOp::ByStatus('P')), Op::File(FileOp::ByStatus('D'))];

pub(crate) type Cell<'a> = (Op, &'a Subject, &'a Obj);
type Rows = Result<HashMap<String, Option<AccessLevel>>, Actual>;

/// Per-host subjects of the shape layer (files, actions) and the vis / life layers.
const SHAPE_FILE_SUBJECTS: [(&str, [&str; 3]); 2] = [
	(ALICE, ["owner@alice", "stranger@alice.test", "g-read@alice.test"]),
	(CLUB, ["owner@club", "stranger@club.test", "g-read@club.test"]),
];
const SHAPE_ACTION_SUBJECTS: [(&str, [&str; 4]); 2] = [
	(
		ALICE,
		[
			"owner@alice",
			"stranger@alice.test",
			"direct@alice.test",
			"subscriber@alice.test",
		],
	),
	(CLUB, ["owner@club", "stranger@club.test", "direct@club.test", "subscriber@club.test"]),
];
const VIS_SUBJECTS: [&str; 4] = [
	"anon@alice.test",
	"follower@alice.test",
	"connected@alice.test",
	"stranger@alice.test",
];
const LIFE_SUBJECTS: [&str; 9] = [
	"owner@alice",
	"g-write@alice.test",
	"stranger@alice.test",
	"owner-scoped-r@alice",
	"owner@club",
	"m-moderator@club.test",
	"m-contributor@club.test",
	"g-write@club.test",
	"stranger@club.test",
];

/// Level objects on `host`: files (`file`) or actions.
pub fn level_objs<'a>(fx: &'a Fixture, host: &str, file: bool) -> Vec<&'a Obj> {
	fx.objs
		.iter()
		.filter(|o| is_level(o) && obj_host(o) == host && matches!(o, Obj::File(_)) == file)
		.collect()
}

fn named<'a>(fx: &'a Fixture, host: &str, name: &str) -> &'a Obj {
	fx.objs
		.iter()
		.find(|o| {
			obj_host(o) == host
				&& match o {
					Obj::File(f) => f.spec.name == name,
					Obj::Action(a) => a.spec.name == name,
				}
		})
		.unwrap_or_else(|| panic!("layer object {name}@{host}"))
}

/// Life-layer rows on `host`: every non-active Blob file, plus the active baseline.
fn life_objs<'a>(fx: &'a Fixture, host: &str) -> Vec<&'a Obj> {
	fx.objs
		.iter()
		.filter(|o| match o {
			Obj::File(f) => {
				f.spec.tn == host
					&& f.spec.kind == FileKind::Blob
					&& !f.spec.name.starts_with("cur-")
					&& (f.spec.life != FileLife::Active
						|| (f.spec.shape == FileShape::TenantOwned && f.spec.vis == Some('P')))
			}
			Obj::Action(_) => false,
		})
		.collect()
}

/// Metadata per file; `PATCH {}` on vis `P` / Direct only (the write guard ignores vis).
fn push_file<'a>(cells: &mut Vec<Cell<'a>>, s: &'a Subject, o: &'a Obj) {
	cells.push((Op::File(FileOp::Metadata), s, o));
	if matches!(o, Obj::File(f) if matches!(f.spec.vis, Some('P') | None)) {
		cells.push((Op::File(FileOp::Patch), s, o));
	}
}

/// File cells per layer `(name, cells)`.
pub fn file_layers(fx: &Fixture) -> Vec<(&'static str, Vec<Cell<'_>>)> {
	let mut subject_l = Vec::new();
	for s in level_subjects(&fx.subjects) {
		for n in ["tenant-blob-d-active", "tenant-blob-p-active"] {
			push_file(&mut subject_l, s, named(fx, &s.host, n));
		}
		// A trashed row reached by id exists only for those who may manage it.
		subject_l.push((Op::File(FileOp::ById), s, named(fx, &s.host, "tenant-blob-p-trashed")));
	}
	let mut shape_l = Vec::new();
	for (host, names) in SHAPE_FILE_SUBJECTS {
		for n in names {
			let s = fx.subject(n);
			for o in level_objs(fx, host, true) {
				if matches!(o, Obj::File(f) if f.spec.vis.is_none()) {
					push_file(&mut shape_l, s, o);
				}
			}
		}
	}
	let mut vis_l = Vec::new();
	for n in VIS_SUBJECTS {
		let s = fx.subject(n);
		for o in level_objs(fx, &s.host, true) {
			if matches!(o, Obj::File(f) if f.spec.shape == FileShape::TenantOwned) {
				push_file(&mut vis_l, s, o);
			}
		}
	}
	let mut life_l = Vec::new();
	for n in LIFE_SUBJECTS {
		let s = fx.subject(n);
		for o in life_objs(fx, &s.host) {
			for op in [FileOp::Metadata, FileOp::ById, FileOp::ByParent] {
				life_l.push((Op::File(op), s, o));
			}
		}
	}
	vec![("subject", subject_l), ("shape", shape_l), ("vis", vis_l), ("life", life_l)]
}

/// Action `GET` cells per layer `(name, cells)`.
pub fn action_layers(fx: &Fixture) -> Vec<(&'static str, Vec<Cell<'_>>)> {
	let get = Op::Action(ActionOp::Get);
	let mut subject_l = Vec::new();
	for s in level_subjects(&fx.subjects) {
		for n in ["post-d-tenant-active", "post-p-tenant-active"] {
			subject_l.push((get, s, named(fx, &s.host, n)));
		}
	}
	let mut shape_l = Vec::new();
	for (host, names) in SHAPE_ACTION_SUBJECTS {
		for n in names {
			let s = fx.subject(n);
			for o in level_objs(fx, host, false) {
				if matches!(o, Obj::Action(a) if a.spec.vis.is_none()) {
					shape_l.push((get, s, o));
				}
			}
		}
	}
	let mut vis_l = Vec::new();
	for n in VIS_SUBJECTS {
		let s = fx.subject(n);
		for o in level_objs(fx, &s.host, false) {
			if matches!(o, Obj::Action(a) if a.spec.typ == ActionShape::Post) {
				vis_l.push((get, s, o));
			}
		}
	}
	vec![("subject", subject_l), ("shape", shape_l), ("vis", vis_l)]
}

fn life_subjects(fx: &Fixture) -> Vec<&Subject> {
	LIFE_SUBJECTS.iter().map(|n| fx.subject(n)).collect()
}

pub(crate) async fn run_cells(fx: &Fixture, rep: &mut Report, cells: Vec<Cell<'_>>) {
	let got: Vec<_> = stream::iter(cells)
		.map(|(op, s, o)| async move {
			let (status, body) = call(op.router(fx), op.request(s, o)).await;
			(op, s, o, classify_obj(op, o, status, &body))
		})
		.buffer_unordered(CONC)
		.collect()
		.await;
	for (op, s, o, (act, level)) in got {
		rep.check(op.name(), expected(&s.facts, o, &op), act, level, s.name.clone(), obj_key(o));
	}
}

/// Every `(subject, op)` listing, fetched concurrently.
async fn run_lists<'a>(
	fx: &Fixture,
	subs: &[&'a Subject],
	ops: [Op; 2],
) -> Vec<(&'a Subject, Op, Rows)> {
	stream::iter(subs.iter().flat_map(|&s| ops.map(|op| (s, op))))
		.map(|(s, op)| async move { (s, op, list_presence(fx, s, op).await) })
		.buffer_unordered(CONC)
		.collect()
		.await
}

/// Join one listing with the subject's same-host level objects of that kind.
fn join_listing(rep: &mut Report, op: Op, s: &Subject, rows: Rows, objs: &[&Obj]) {
	let gate = listing(&s.facts, &op);
	let rows = match rows {
		Ok(rows) if gate.outcome == Outcome::Allow => rows,
		other => {
			let act = other.err().unwrap_or(Actual::Allow);
			return rep.check(op.name(), gate, act, None, s.name.clone(), "(listing)".into());
		}
	};
	for &o in objs {
		let (act, level) = match rows.get(&obj_key(o)) {
			Some(l) => (Actual::Present, *l),
			None => (Actual::Absent, None),
		};
		rep.check(op.name(), expected(&s.facts, o, &op), act, level, s.name.clone(), obj_key(o));
	}
}

pub async fn file_levels(fx: &Fixture) -> Report {
	let mut rep = Report::new("file_levels");
	let subs = level_subjects(&fx.subjects);
	let cells = file_layers(fx).into_iter().flat_map(|(_, c)| c).collect();
	run_cells(fx, &mut rep, cells).await;
	for (s, op, rows) in run_lists(fx, &subs, FILE_LISTS).await {
		if op == Op::File(FileOp::List) {
			check_narrows(fx, &mut rep, s, &rows, op, &FILE_NARROWS).await;
		}
		join_listing(&mut rep, op, s, rows, &level_objs(fx, &s.host, true));
	}
	for (s, op, rows) in run_lists(fx, &life_subjects(fx), LIFE_LISTS).await {
		join_listing(&mut rep, op, s, rows, &life_objs(fx, &s.host));
	}
	rep
}

pub async fn action_levels(fx: &Fixture) -> Report {
	let mut rep = Report::new("action_levels");
	let subs = level_subjects(&fx.subjects);
	let cells = action_layers(fx).into_iter().flat_map(|(_, c)| c).collect();
	run_cells(fx, &mut rep, cells).await;

	let counts: HashMap<&str, Result<u64, Actual>> = stream::iter(&subs)
		.map(|&s| async move { (s.name.as_str(), count_actions(fx, s).await) })
		.buffer_unordered(CONC)
		.collect()
		.await;

	for (s, op, rows) in run_lists(fx, &subs, ACTION_LISTS).await {
		if op == Op::Action(ActionOp::List) {
			check_count(&mut rep, s, &rows, &counts[s.name.as_str()]);
			check_narrows(fx, &mut rep, s, &rows, op, &ACTION_NARROWS).await;
		}
		join_listing(&mut rep, op, s, rows, &level_objs(fx, &s.host, false));
	}
	rep
}

/// `/api/actions` parameters; `status=` names every status, hidden ones included.
const ACTION_NARROWS: [&str; 6] = [
	"status=A,C,D,N,V,F",
	"includeTokens=true",
	"includeSubject=true",
	"visibility=P",
	"visibility=D",
	"subscribed=true",
];
/// `/api/files` parameters; `{host}` is the subject's host.
const FILE_NARROWS: [&str; 3] = ["ownerIdTag={host}", "pinned=true", "starred=true"];

/// A filter narrows a list, never widens it: no query lists a row the plain list hides. A
/// refused query lists nothing.
async fn check_narrows(
	fx: &Fixture,
	rep: &mut Report,
	s: &Subject,
	plain: &Rows,
	op: Op,
	queries: &[&str],
) {
	let Ok(plain) = plain else { return };
	let (base, id_key) = if op == Op::File(FileOp::List) {
		("/api/files", "fileId")
	} else {
		("/api/actions", "actionId")
	};
	for q in queries {
		let q = q.replace("{host}", &s.host);
		let Ok(wide) = list_paged(fx, s, &format!("{base}?{q}&"), id_key).await else { continue };
		for key in wide.keys().filter(|k| !plain.contains_key(*k)) {
			rep.add(Mismatch {
				op: op.name(),
				rule: "list.narrows",
				expected: "Absent".into(),
				actual: "Present".into(),
				subject: s.name.clone(),
				object: format!("{key} ({q})"),
			});
		}
	}
}

/// `count=true` must equal the default list's length, and be refused exactly when it is.
fn check_count(rep: &mut Report, s: &Subject, list: &Rows, count: &Result<u64, Actual>) {
	let op = Op::Action(ActionOp::Count).name();
	match (list, count) {
		(_, Err(Actual::HarnessError(d))) => {
			rep.error(op, d.clone(), s.name.clone(), "(count)".into());
		}
		(Ok(rows), Ok(c)) if rows.len() as u64 == *c => {}
		(Err(a), Err(b)) if a == b => {}
		(l, c) => rep.add(Mismatch {
			op,
			rule: "count.eq-list",
			expected: "Count=List".into(),
			actual: "Count!=List".into(),
			subject: s.name.clone(),
			object: format!("list {:?} vs count {c:?}", l.as_ref().map(HashMap::len)),
		}),
	}
}

// vim: ts=4
