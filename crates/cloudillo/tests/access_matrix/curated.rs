// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Curated layers: literal hand-picked rows, each with a stable case id, and their runner.
//! Names are short case names; [`subject`] and [`target`] map them to fixture names. The
//! report's `rule` is the row id.

use axum::body::Body;
use axum::http::{Method, Request};
use cloudillo::types::AccessLevel;
use cloudillo::websocket::WsKind;
use serde_json::{Value, json};

use crate::fixture::{Fixture, call, req};
use crate::levels::{Cell as OracleCell, run_cells};
use crate::objects::Obj;
use crate::ops::{
	ActionOp, Actual, FileOp, Op, bearer, classify, count_actions, list_presence, obj_key,
	status_class,
};
use crate::oracle::{Outcome, expected};
use crate::report::{Mismatch, Report};
use crate::subjects::Subject;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
	FileMeta,
	/// `PATCH {}`.
	FilePatch,
	/// `POST /api/files` (CRDT) under the object as parent.
	FileCreate,
	/// `PATCH …/user {}`.
	FileUser,
	FileRefresh,
	FileList,
	FileContent,
	FileDelete,
	FileRestore,
	FileTag,
	FileDuplicate,
	ActGet,
	ActPatch,
	/// `POST /api/actions` (MSG) under the object as parent.
	ActCreate,
	ActAccept,
	ActReject,
	ActDismiss,
	ActPublish,
	ActCancel,
	ActDelete,
	ActList,
	/// `GET /api/actions?count=true`: Present = the object is counted.
	ActCount,
	Search,
	Outbox,
	ReadMarker,
	Subscribe,
	/// `?access=` value (`None` = omitted).
	WsCrdt(Option<&'static str>),
	WsRtdb(Option<&'static str>),
}
use Route::*;

/// `(id, subject, object, route, expected)` — `object` is `""` for none. `expected` is
/// `Allow|Deny|Present|Absent`, optionally `@Level`, or `400`; `Allow*` = any status but
/// 401/403/404 (FC-37, unreachable upstream).
pub type Row = (&'static str, &'static str, &'static str, Route, &'static str);

/// One executed cell; G2 rows expand to six.
pub struct Cell {
	id: &'static str,
	op: String,
	subject: &'static str,
	object: &'static str,
	route: Route,
	want: &'static str,
}

impl Route {
	fn op(self) -> Option<Op> {
		use ActionOp as A;
		use FileOp as F;
		Some(match self {
			FileMeta => Op::File(F::Metadata),
			FilePatch => Op::File(F::Patch),
			FileCreate => Op::File(F::CreateCrdt),
			FileRefresh => Op::File(F::Refresh),
			FileList => Op::File(F::List),
			FileContent => Op::File(F::Content),
			FileDelete => Op::File(F::Delete),
			FileRestore => Op::File(F::Restore),
			FileTag => Op::File(F::Tag),
			FileDuplicate => Op::File(F::Duplicate),
			ActGet => Op::Action(A::Get),
			ActPatch => Op::Action(A::Patch),
			ActCreate => Op::Action(A::Create),
			ActAccept => Op::Action(A::Accept),
			ActReject => Op::Action(A::Reject),
			ActDismiss => Op::Action(A::Dismiss),
			ActPublish => Op::Action(A::Publish),
			ActCancel => Op::Action(A::Cancel),
			ActDelete => Op::Action(A::Delete),
			ActList | ActCount => Op::Action(A::List),
			Search => Op::Search,
			Outbox => Op::Outbox,
			WsCrdt(a) => Op::Ws(WsKind::Crdt, a),
			WsRtdb(a) => Op::Ws(WsKind::Rtdb, a),
			FileUser | ReadMarker | Subscribe => return None,
		})
	}

	fn is_listing(self) -> bool {
		matches!(self, FileList | ActList | ActCount | Search | Outbox)
	}
}

const WHO: [&str; 2] = ["anon@alice", "tampered@alice"];

/// G1 — wiring: tier representatives and self-enforcers × {anon, tampered}.
pub const G1: &[Row] = &[
	("G1-01", WHO[0], "tenant-blob-d-active@alice", FileMeta, "Deny"),
	("G1-02", WHO[1], "tenant-blob-d-active@alice", FileMeta, "Deny"),
	("G1-03", WHO[0], "tenant-blob-d-active@alice", FilePatch, "Deny"),
	("G1-04", WHO[1], "tenant-blob-d-active@alice", FilePatch, "Deny"),
	("G1-05", WHO[0], "folder@alice", FileCreate, "Deny"),
	("G1-06", WHO[1], "folder@alice", FileCreate, "Deny"),
	("G1-07", WHO[0], "post-d-tenant-active@alice", ActGet, "Deny"),
	("G1-08", WHO[1], "post-d-tenant-active@alice", ActGet, "Deny"),
	("G1-09", WHO[0], "post-d-tenant-draft@alice", ActPatch, "Deny"),
	("G1-10", WHO[1], "post-d-tenant-draft@alice", ActPatch, "Deny"),
	("G1-11", WHO[0], "container-d-tenant-active@alice", ActCreate, "Deny"),
	("G1-12", WHO[1], "container-d-tenant-active@alice", ActCreate, "Deny"),
	("G1-13", WHO[0], "tenant-blob-d-active@alice", FileUser, "Deny"),
	("G1-14", WHO[1], "tenant-blob-d-active@alice", FileUser, "Deny"),
	("G1-15", WHO[0], "mirroredplacer-blob-d-active@alice", FileRefresh, "Deny"),
	("G1-16", WHO[1], "mirroredplacer-blob-d-active@alice", FileRefresh, "Deny"),
	("G1-17", WHO[0], "tenant-blob-d-active@alice", FileList, "Absent"),
	("G1-18", WHO[1], "tenant-blob-d-active@alice", FileList, "Absent"),
	("G1-19", WHO[0], "apkg-blob-d-active@alice", FileContent, "Deny"),
	("G1-20", WHO[1], "apkg-blob-d-active@alice", FileContent, "Deny"),
	("G1-21", WHO[0], "post-d-tenant-active@alice", ActList, "Absent"),
	("G1-22", WHO[1], "post-d-tenant-active@alice", ActList, "Absent"),
	("G1-23", WHO[0], "post-d-tenant-active@alice", Search, "Absent"),
	("G1-24", WHO[1], "post-d-tenant-active@alice", Search, "Absent"),
	("G1-25", WHO[0], "post-p-tenant-active@alice", ActAccept, "Deny"),
	("G1-26", WHO[1], "post-p-tenant-active@alice", ActAccept, "Deny"),
	("G1-27", WHO[0], "", Outbox, "Deny"),
	("G1-28", WHO[1], "", Outbox, "Deny"),
	("G1-29", WHO[0], "", ReadMarker, "Deny"),
	("G1-30", WHO[1], "", ReadMarker, "Deny"),
	("G1-31", WHO[0], "container-d-tenant-active@alice", Subscribe, "Deny"),
	("G1-32", WHO[1], "container-d-tenant-active@alice", Subscribe, "Deny"),
	("G1-33", WHO[0], "tenant-crdt-d-active@alice", WsCrdt(None), "Deny"),
	("G1-34", WHO[1], "tenant-crdt-d-active@alice", WsCrdt(None), "Deny"),
	("G1-35", WHO[0], "tenant-rtdb-d-active@alice", WsRtdb(None), "Deny"),
	("G1-36", WHO[1], "tenant-rtdb-d-active@alice", WsRtdb(None), "Deny"),
];

/// G2 columns: `(column, route, object)`; P = Public CRDT, D = `root@alice`.
const G2_COLS: [(&str, Route, &str); 6] = [
	("OP", FileMeta, "tenant-crdt-p-active@alice"),
	("OD", FileMeta, "root@alice"),
	("UP", FileUser, "tenant-crdt-p-active@alice"),
	("UD", FileUser, "root@alice"),
	("WP", FilePatch, "tenant-crdt-p-active@alice"),
	("WD", FilePatch, "root@alice"),
];

const DENY6: [&str; 6] = ["Deny"; 6];
/// A valid scoped token outside its scope is a guest: the Public object only.
const GUEST6: [&str; 6] = ["Allow", "Deny", "Deny", "Deny", "Deny", "Deny"];

/// G2 — credential grid, columns in [`G2_COLS`] order.
pub const G2: &[(&str, &str, [&str; 6])] = &[
	("G2-01", "anon@alice", ["Allow", "Deny", "Deny", "Deny", "Deny", "Deny"]),
	("G2-02", "owner@alice", ["Allow@Admin", "Allow@Admin", "Allow", "Allow", "Allow", "Allow"]),
	(
		"G2-03",
		"apikey-unscoped@alice",
		["Allow@Admin", "Allow@Admin", "Allow", "Allow", "Allow", "Allow"],
	),
	("G2-04", "connected@alice", ["Allow@Read", "Deny", "Allow", "Deny", "Deny", "Deny"]),
	("G2-05", "sharelink-r@alice", ["Allow", "Allow@Read", "Deny", "Deny", "Deny", "Deny"]),
	("G2-06", "sharelink-w@alice", ["Allow", "Allow@Write", "Deny", "Deny", "Deny", "Allow"]),
	("G2-07", "sharelink-a@alice", ["Allow", "Allow@Write", "Deny", "Deny", "Deny", "Allow"]),
	("G2-08", "owner-scoped-r@alice", ["Allow", "Allow@Read", "Deny", "Allow", "Deny", "Deny"]),
	("G2-09", "apikey-file@alice", ["Allow", "Allow@Read", "Deny", "Allow", "Deny", "Deny"]),
	("G2-10", "via-embed@alice", ["Allow", "Deny", "Deny", "Deny", "Deny", "Deny"]),
	("G2-11", "apikey-dav@alice", GUEST6),
	("G2-12", "apkg-publish@alice", GUEST6),
	("G2-13", "idp-key@alice", DENY6),
	("G2-14", "xtenant-replay@alice", DENY6),
	("G2-15", "expired@alice", DENY6),
	("G2-16", "wrong-iss@alice", DENY6),
	("G2-17", "tampered@alice", DENY6),
	("G2-18", "scope-admin@alice", GUEST6),
	("G2-19", "scope-foreign@alice", GUEST6),
];

/// File curated rows.
pub const FC: &[Row] = &[
	("FC-01", "owner@alice", "cur-del-owner@alice", FileDelete, "Allow"),
	("FC-02", "g_write@alice", "tenant-blob-d-active@alice", FileDelete, "Deny"),
	("FC-03", "g_admin@alice", "cur-del-gadmin@alice", FileDelete, "Allow"),
	("FC-04", "m_leader@club", "cur-del-leader@club", FileDelete, "Allow"),
	("FC-05", "m_moderator@club", "cur-del-moderator@club", FileDelete, "Allow"),
	("FC-06", "m_contributor@club", "cur-del-member@club", FileDelete, "Allow"),
	("FC-07", "owner@alice", "cur-restore-owner@alice", FileRestore, "Allow"),
	("FC-08", "g_write@alice", "tenant-blob-p-trashed@alice", FileRestore, "Deny"),
	("FC-09", "g_write@alice", "cur-tag-gwrite@alice", FileTag, "Allow"),
	("FC-10", "g_comment@alice", "tenant-blob-d-active@alice", FileTag, "Deny"),
	("FC-11", "m_contributor@club", "tenant-crdt-p-active@club", FileDuplicate, "Allow"),
	("FC-12", "m_supporter@club", "tenant-blob-p-active@club", FileDuplicate, "Deny"),
	("FC-13", "sharelink-w@alice", "root@alice", FileDuplicate, "Deny"),
	("FC-14", "m_contributor@club", "tenant-crdt-d-active@club", FileDuplicate, "Allow"),
	("FC-15", "m_contributor@club", "folder@club", FileCreate, "Allow"),
	("FC-16", "m_supporter@club", "folder@club", FileCreate, "Deny"),
	("FC-17", "owner-scoped-w@alice", "folder@alice", FileCreate, "Deny"),
	("FC-18", "owner@alice", "folder-blob-p-trashed@alice", FileCreate, "Deny"),
	("FC-19", "owner@alice", "tenant-blob-p-trashed@alice", FileMeta, "Allow@Admin"),
	("FC-20", "anon@alice", "tenant-blob-p-trashed@alice", FileMeta, "Deny"),
	// Strict lifecycle: Write on a trashed row is not the right to see it.
	("FC-21", "g_write@alice", "tenant-blob-p-trashed@alice", FileMeta, "Deny"),
	("FC-22", "g_read@alice", "tenant-blob-p-trashed@alice", FileMeta, "Deny"),
	("FC-23", "m_leader@club", "tenant-blob-p-trashed@club", FileMeta, "Allow@Admin"),
	("FC-24", "owner@alice", "tenant-blob-p-pending@alice", FileMeta, "Allow@Admin"),
	("FC-25", "anon@alice", "tenant-blob-p-pending@alice", FileMeta, "Deny"),
	("FC-26", "owner@alice", "tenant-blob-p-trashed@alice", FileList, "Absent"),
	("FC-27", "owner@alice", "tenant-blob-p-pending@alice", FileList, "Absent"),
	("FC-28", "anon@alice", "tenant-crdt-p-active@alice", FileMeta, "Allow@Read"),
	("FC-29", "anon@alice", "tenant-rtdb-d-active@alice", FileMeta, "Deny"),
	("FC-30", "g_write@alice", "tenant-rtdb-d-active@alice", FilePatch, "Allow"),
	("FC-31", "anon@alice", "apkg-blob-p-active@alice", FileContent, "Allow"),
	("FC-32", "stranger@alice", "apkg-blob-d-active@alice", FileContent, "Deny"),
	("FC-33", "owner@alice", "apkg-blob-p-trashed@alice", FileContent, "Allow"),
	("FC-34", "g_read@alice", "tenant-blob-d-active@alice", FileUser, "Allow"),
	("FC-35", "stranger@alice", "tenant-blob-d-active@alice", FileUser, "Deny"),
	("FC-36", "sharelink-w@alice", "root@alice", FileUser, "Deny"),
	("FC-37", "owner@alice", "mirroredplacer-blob-p-active@alice", FileRefresh, "Allow*"),
	("FC-38", "connected@alice", "mirroredplacer-blob-p-active@alice", FileRefresh, "Allow*"),
	("FC-39", "m_leader@club", "mirroredplacer-blob-p-active@club", FileRefresh, "Allow*"),
	("FC-40", "owner@alice", "tenant-blob-p-active@alice", FileRefresh, "400"),
	("FC-41", "sharelink-r@alice", "root@alice", FileList, "Present@Read"),
	("FC-42", "sharelink-r@alice", "tenant-blob-p-active@alice", FileList, "Absent"),
	("FC-43", "sharelink-r@alice", "tenant-crdt-p-active@alice", Search, "Absent"),
	("FC-44", "sharelink-r@alice", "post-p-tenant-active@alice", Search, "Absent"),
	("FC-45", "owner@alice", "cur-mirror-del-placer@alice", FileDelete, "Allow"),
	("FC-46", "connected@alice", "cur-mirror-del-remote@alice", FileDelete, "Deny"),
	("FC-47", "m_leader@club", "cur-mirror-del-leader@club", FileDelete, "Deny"),
	// Share-link guest reads the public row, yet refresh is gated for anonymous callers.
	("FC-48", "sharelink-r@alice", "mirroredplacer-blob-p-active@alice", FileRefresh, "Deny"),
];

/// Action curated rows.
pub const AC: &[Row] = &[
	("AC-01", "owner@alice", "post-p-tenant-draft@alice", ActGet, "Allow"),
	("AC-02", "connected@alice", "post-p-tenant-draft@alice", ActGet, "Deny"),
	("AC-03", "owner@alice", "post-p-tenant-draft@alice", ActList, "Present"),
	("AC-04", "follower@alice", "post-p-tenant-draft@alice", ActList, "Absent"),
	("AC-05", "anon@alice", "post-p-tenant-scheduled@alice", ActList, "Absent"),
	("AC-06", "owner@alice", "post-p-tenant-deleted@alice", ActGet, "Deny"),
	("AC-07", "owner@alice", "post-p-tenant-deleted@alice", ActList, "Absent"),
	("AC-08", "owner@alice", "post-p-remote-pending@alice", ActList, "Present"),
	("AC-09", "owner@alice", "cur-dismiss-owner@alice", ActDismiss, "Allow"),
	("AC-10", "m_moderator@club", "post-p-tenant-dismissed@club", ActDismiss, "Deny"),
	("AC-11", "m_leader@club", "cur-dismiss-leader@club", ActDismiss, "Allow"),
	// Dismissing an already-active action is an idempotent no-op.
	("AC-12", "owner@alice", "post-p-tenant-active@alice", ActDismiss, "Allow"),
	("AC-13", "owner@alice", "cur-draft-patch@alice", ActPatch, "Allow"),
	("AC-14", "m_leader@club", "post-p-tenant-draft@club", ActPatch, "Deny"),
	("AC-15", "owner@alice", "cur-draft-publish@alice", ActPublish, "Allow"),
	("AC-16", "connected@alice", "post-p-tenant-draft@alice", ActPublish, "Deny"),
	("AC-17", "owner@alice", "cur-sched-cancel@alice", ActCancel, "Allow"),
	("AC-18", "m_contributor@club", "post-p-tenant-scheduled@club", ActCancel, "Deny"),
	("AC-19", "owner@alice", "cur-draft-delete@alice", ActDelete, "Allow"),
	("AC-20", "owner@alice", "post-p-tenant-active@alice", ActPatch, "400"),
	("AC-21", "owner@alice", "cur-del-action-owner@alice", ActDelete, "Allow"),
	("AC-22", "connected@alice", "post-p-remote-active@alice", ActDelete, "Deny"),
	("AC-23", "m_leader@club", "cur-del-action-leader@club", ActDelete, "Allow"),
	("AC-24", "m_moderator@club", "post-p-remote-active@club", ActDelete, "Deny"),
	("AC-25", "m_moderator@club", "cur-accept-mod@club", ActAccept, "Allow"),
	("AC-26", "m_contributor@club", "cur-accept-mod@club", ActAccept, "Deny"),
	("AC-27", "hatted@club", "cur-accept-mod@club", ActAccept, "Deny"),
	("AC-28", "owner@club", "cur-reject-owner@club", ActReject, "Allow"),
	("AC-29", "m_moderator@club", "post-p-remote-active@club", ActAccept, "400"),
	("AC-30", "m_moderator@club", "cur-reject-mod@club", ActReject, "Allow"),
	("AC-31", "m_contributor@club", "container-p-tenant-active@club", ActCreate, "Allow"),
	("AC-32", "m_supporter@club", "container-p-tenant-active@club", ActCreate, "Deny"),
	("AC-33", "m_contributor@club", "container-d-tenant-active@club", ActCreate, "Deny"),
	("AC-34", "hatted@club", "container-p-tenant-active@club", ActCreate, "Allow"),
	("AC-35", "owner@alice", "container-p-tenant-deleted@alice", ActCreate, "Deny"),
	("AC-36", "subscriber@alice", "container-s-tenant-active@alice", ActGet, "Allow"),
	("AC-37", "subscriber@alice", "container-s-tenant-active@alice", ActList, "Present"),
	("AC-38", "stranger@alice", "container-s-tenant-active@alice", ActGet, "Deny"),
	("AC-39", "subscriber@alice", "post-s-tenant-active@alice", ActGet, "Deny"),
	("AC-40", "stranger@alice", "post-f-remote-active@alice", Search, "Absent"),
	("AC-41", "stranger@alice", "post-f-remote-active@alice", ActCount, "Absent"),
	("AC-42", "follower@alice", "post-f-tenant-active@alice", Search, "Present"),
];

/// WebSocket rows.
pub const WS: &[Row] = &[
	("WS-01", "owner@alice", "root@alice", WsCrdt(None), "Allow@Admin"),
	("WS-02", "g_read@alice", "tenant-crdt-d-active@alice", WsCrdt(Some("write")), "Deny"),
	("WS-03", "g_read@alice", "tenant-crdt-d-active@alice", WsCrdt(Some("read")), "Allow@Read"),
	("WS-04", "g_read@alice", "tenant-crdt-d-active@alice", WsCrdt(None), "Allow@Read"),
	("WS-05", "g_write@alice", "tenant-crdt-d-active@alice", WsCrdt(None), "Allow@Write"),
	("WS-06", "g_comment@alice", "tenant-crdt-d-active@alice", WsCrdt(Some("write")), "Deny"),
	("WS-07", "g_comment@alice", "tenant-crdt-d-active@alice", WsCrdt(None), "Allow@Comment"),
	("WS-08", "anon@alice", "tenant-crdt-p-active@alice", WsCrdt(None), "Allow@Read"),
	("WS-09", "sharelink-r@alice", "root@alice", WsCrdt(Some("write")), "Deny"),
	("WS-10", "sharelink-w@alice", "root@alice", WsCrdt(Some("write")), "Allow@Write"),
	("WS-11", "sharelink-r@alice", "tenant-crdt-p-active@alice", WsCrdt(None), "Allow@Read"),
	("WS-12", "sharelink-r@alice", "docchild-crdt-d-active@alice", WsCrdt(None), "Allow@Read"),
	("WS-13", "owner@alice", "tenant-rtdb-d-active@alice", WsRtdb(Some("write")), "Allow@Write"),
	("WS-14", "stranger@alice", "tenant-rtdb-d-active@alice", WsRtdb(None), "Deny"),
	(
		"WS-15",
		"m_contributor@club",
		"tenant-crdt-d-active@club",
		WsCrdt(Some("write")),
		"Allow@Write",
	),
	("WS-16", "m_follower@club", "tenant-crdt-d-active@club", WsCrdt(Some("write")), "Deny"),
	("WS-17", "m_follower@club", "tenant-crdt-d-active@club", WsCrdt(None), "Deny"),
	("WS-18", "stranger@alice", "f1~zqm-alice-nonexistent", WsCrdt(None), "Deny"),
	("WS-19", "owner-scoped-r@alice", "root@alice", WsCrdt(Some("write")), "Deny"),
	(
		"WS-20",
		"g_comment@alice",
		"f1~zqm-alice-tenant-rtdb-d-active~meta",
		WsRtdb(None),
		"Allow@Comment",
	),
	("WS-21", "g_comment@alice", "tenant-rtdb-d-active@alice", WsRtdb(None), "Allow@Read"),
	("WS-22", "g_read@alice", "tenant-rtdb-d-active@alice", WsRtdb(Some("write")), "Deny"),
];

/// Self-enforcing routes.
pub const SE: &[Row] = &[
	("SE-01", "anon@alice", "tenant-blob-p-active@alice", FileList, "Present@Read"),
	("SE-02", "anon@alice", "tenant-blob-f-active@alice", FileList, "Absent"),
	("SE-03", "anon@alice", "post-p-tenant-active@alice", ActList, "Present"),
	("SE-04", "anon@alice", "post-c-tenant-active@alice", ActList, "Absent"),
	("SE-05", "anon@alice", "tenant-blob-p-active@alice", Search, "Present"),
	("SE-06", "anon@alice", "tenant-blob-v-active@alice", Search, "Absent"),
	("SE-07", "connected@alice", "post-p-tenant-active@alice", Outbox, "Present"),
	("SE-08", "stranger@alice", "post-p-tenant-active@alice", Outbox, "Absent"),
	("SE-09", "connected@alice", "post-p-remote-active@alice", Outbox, "Absent"),
	("SE-10", "connected@alice", "post-p-tenant-draft@alice", Outbox, "Absent"),
	("SE-11", "owner@alice", "post-p-tenant-active@alice", ReadMarker, "Allow"),
	("SE-12", "sharelink-w@alice", "post-p-tenant-active@alice", ReadMarker, "Deny"),
	// `sub_level` is the tenant owner's row; a subscriber cannot move it.
	("SE-13", "subscriber@alice", "container-s-tenant-active@alice", Subscribe, "Deny"),
	("SE-14", "stranger@alice", "container-d-tenant-active@alice", Subscribe, "Deny"),
	("SE-15", "owner-scoped-w@alice", "container-p-tenant-active@alice", Subscribe, "Deny"),
];

/// Oracle-judged curated cells: `(id, subject, object, op)`, no literal expectation — the
/// oracle decides. Boundary cells of rules the level layers cannot reach.
pub type OracleRow = (&'static str, &'static str, &'static str, Op);

/// Files: a scoped owner's own pending upload; `DELETE /api/trash` authority (allow cells on
/// the disposable `trash` community, each with its own trashed row).
pub const FO: &[OracleRow] = &[
	("FO-01", "owner-scoped-r@alice", "docchild-blob-d-pending@alice", Op::File(FileOp::Metadata)),
	("FO-02", "owner-scoped-r@alice", "docchild-blob-d-pending@alice", Op::File(FileOp::ById)),
	// A share link's id_tag is the tenant's; it never owns a pending row.
	("FO-03", "sharelink-r@alice", "docchild-blob-d-pending@alice", Op::File(FileOp::Metadata)),
	("FO-04", "sharelink-r@alice", "docchild-blob-d-pending@alice", Op::File(FileOp::ById)),
	("FO-05", "owner@trash", "cur-emptytrash-owner@trash", Op::File(FileOp::EmptyTrash)),
	("FO-06", "m_moderator@trash", "cur-emptytrash-mod@trash", Op::File(FileOp::EmptyTrash)),
	("FO-07", "m_contributor@trash", "cur-emptytrash-mod@trash", Op::File(FileOp::EmptyTrash)),
	("FO-08", "owner-scoped-w@alice", "tenant-blob-p-trashed@alice", Op::File(FileOp::EmptyTrash)),
];

/// Actions: creating and scheduling a draft.
pub const AO: &[OracleRow] = &[
	("AO-01", "owner@alice", "post-p-tenant-active@alice", Op::Action(ActionOp::CreateDraft)),
	("AO-02", "stranger@alice", "post-p-tenant-active@alice", Op::Action(ActionOp::CreateDraft)),
	(
		"AO-03",
		"owner-scoped-w@alice",
		"post-p-tenant-active@alice",
		Op::Action(ActionOp::CreateDraft),
	),
	("AO-04", "owner@alice", "cur-draft-publish-at@alice", Op::Action(ActionOp::PublishAt)),
	("AO-05", "connected@alice", "cur-draft-publish-at@alice", Op::Action(ActionOp::PublishAt)),
	(
		"AO-06",
		"owner-scoped-w@alice",
		"cur-draft-publish-at@alice",
		Op::Action(ActionOp::PublishAt),
	),
];

/// Runs oracle-judged rows into `rep`: refusals first, so an allowed mutation (purge,
/// schedule) never precedes a refusal on the same object.
pub async fn run_oracle(fx: &Fixture, rep: &mut Report, rows: &[OracleRow]) {
	let mut cells: Vec<OracleCell> = Vec::new();
	for &(id, subject_name, object, op) in rows {
		match (subject(fx, subject_name), target(fx, object)) {
			(Some(s), Some(Tgt::Obj(o))) => cells.push((op, s, o)),
			_ => rep.error(
				op.name(),
				format!("{id}: unresolved"),
				subject_name.into(),
				object.into(),
			),
		}
	}
	let (allow, refuse): (Vec<_>, Vec<_>) = cells
		.into_iter()
		.partition(|(op, s, o)| expected(&s.facts, o, op).outcome == Outcome::Allow);
	run_cells(fx, rep, refuse).await;
	run_cells(fx, rep, allow).await;
}

/// Every route of the guarded file and action tiers (`routes/tables/{file,action}.rs`
/// `read()` / `write()` / `create()`), the single source of the tier probe. A route added to
/// a tier needs a row here; review catches a missing one (`routes/tables/mod.rs`).
pub const TIERS: &[(&str, &[&str])] = &[
	(
		"file.read",
		&[
			"GET /api/files/variant/{variant_id}",
			"GET /api/files/{file_id}/descriptor",
			"GET /api/files/{file_id}/metadata",
			"GET /api/files/{file_id}",
		],
	),
	(
		"file.write",
		&[
			"PATCH /api/files/{file_id}",
			"DELETE /api/files/{file_id}",
			"POST /api/files/{file_id}/restore",
			"PUT /api/files/{file_id}/tag/{tag}",
			"DELETE /api/files/{file_id}/tag/{tag}",
		],
	),
	(
		"file.create",
		&[
			"POST /api/files",
			"POST /api/files/{preset}/{file_name}",
			"POST /api/files/{file_id}/duplicate",
		],
	),
	("action.read", &["GET /api/actions/{action_id}"]),
	(
		"action.write",
		&[
			"DELETE /api/actions/{action_id}",
			"PATCH /api/actions/{action_id}",
			"POST /api/actions/{action_id}/publish",
			"POST /api/actions/{action_id}/cancel",
			"POST /api/actions/{action_id}/dismiss",
		],
	),
	("action.create", &["POST /api/actions"]),
];

/// Tier probe: every [`TIERS`] route × {anon, tampered}, on Direct objects; oracle-judged.
pub fn probe_cells(fx: &Fixture) -> Vec<OracleCell<'_>> {
	let obj = |n| match target(fx, n) {
		Some(Tgt::Obj(o)) => o,
		_ => panic!("probe object {n}"),
	};
	let (file, action) = (obj("tenant-blob-d-active@alice"), obj("post-d-tenant-active@alice"));
	let mut out = Vec::new();
	for (_, routes) in TIERS {
		for r in *routes {
			let (m, p) = r.split_once(' ').expect("METHOD path");
			let o = if p.starts_with("/api/actions") { action } else { file };
			for who in WHO {
				let s = subject(fx, who).unwrap_or_else(|| panic!("probe subject {who}"));
				out.push((Op::Probe(m, p), s, o));
			}
		}
	}
	out
}

pub fn cells(rows: &[Row]) -> Vec<Cell> {
	rows.iter()
		.map(|&(id, subject, object, route, want)| Cell {
			id,
			op: format!("{route:?}"),
			subject,
			object,
			route,
			want,
		})
		.collect()
}

/// G1 rows plus every G2 cell; a G2 cell's op carries its column (`FileMeta·OD`).
pub fn gate_cells() -> Vec<Cell> {
	let mut out = cells(G1);
	for &(id, subject, wants) in G2 {
		for ((col, route, object), want) in G2_COLS.into_iter().zip(wants) {
			out.push(Cell { id, op: format!("{route:?}·{col}"), subject, object, route, want });
		}
	}
	out
}

/// Catalogue subject name → fixture subject: exact, else `_`→`-` plus `.test` on the host
/// (remote-derived and `anon` subjects).
fn subject<'a>(fx: &'a Fixture, name: &str) -> Option<&'a Subject> {
	let alt = format!("{}.test", name.replace('_', "-"));
	let find = |n: &str| fx.subjects.iter().find(|s| s.name == n);
	find(name).or_else(|| find(&alt))
}

enum Tgt<'a> {
	None,
	Obj(&'a Obj),
	/// A file id with no row (WS-18).
	Raw(&'static str),
}

/// Catalogue object name (`{spec}@{host}`, `root@X`, `folder@X`, raw `f1~…`) → fixture object.
fn target<'a>(fx: &'a Fixture, name: &'static str) -> Option<Tgt<'a>> {
	if name.is_empty() {
		return Some(Tgt::None);
	}
	if name.starts_with("f1~") {
		return Some(Tgt::Raw(name));
	}
	let (n, host) = name.split_once('@')?;
	let n = match n {
		"root" => "tenant-crdt-d-active",
		"folder" => "folder-blob-d-active",
		n => n,
	};
	let host = format!("{host}.test");
	fx.objs
		.iter()
		.find(|o| match o {
			Obj::File(f) => f.spec.name == n && f.spec.tn == host,
			Obj::Action(a) => a.spec.name == n && a.spec.tn == host,
		})
		.map(Tgt::Obj)
}

/// Forward-only read watermark far in the future (epoch seconds).
const MARKER_POS: i64 = 4_000_000_000;

fn request(s: &Subject, route: Route, tgt: &Tgt) -> Request<Body> {
	let key = match tgt {
		Tgt::Obj(o) => obj_key(o),
		Tgt::Raw(r) => (*r).to_owned(),
		Tgt::None => "zqm".into(),
	};
	let raw = |m: Method, uri: &str, body: Body| req(&s.host, m, uri, bearer(s), body);
	let j = |v: Value| Body::from(v.to_string());
	match (route, tgt) {
		(FileUser, _) => raw(Method::PATCH, &format!("/api/files/{key}/user"), j(json!({}))),
		(ReadMarker, _) => {
			let body = json!({ "scope": "thread", "key": key, "position": MARKER_POS });
			raw(Method::PUT, "/api/read-marker", j(body))
		}
		(Subscribe, _) => {
			raw(Method::PUT, &format!("/api/actions/{key}/subscribe"), j(json!({ "level": "W" })))
		}
		(_, Tgt::Obj(o)) => route.op().expect("route has an op").request(s, o),
		(WsCrdt(None), Tgt::Raw(_)) => raw(Method::GET, &format!("/ws/crdt/{key}"), Body::empty()),
		(WsRtdb(None), Tgt::Raw(_)) => raw(Method::GET, &format!("/ws/rtdb/{key}"), Body::empty()),
		_ => panic!("{route:?} needs a seeded object"),
	}
}

/// `(outcome, level, status)`; status is 0 for listings.
type Observed = (Actual, Option<AccessLevel>, u16);

async fn observe(fx: &Fixture, s: &Subject, route: Route, tgt: &Tgt<'_>) -> Observed {
	if !route.is_listing() {
		let router = if matches!(route, WsCrdt(_) | WsRtdb(_)) { &fx.ws } else { &fx.api };
		let (status, body) = call(router, request(s, route, tgt)).await;
		let (a, l) = match route.op() {
			Some(op) => classify(op, status, &body),
			None => (status_class(status), None),
		};
		return (a, l, status.as_u16());
	}
	let op = route.op().expect("listing route has an op");
	let rows = list_presence(fx, s, op).await;
	let Tgt::Obj(o) = tgt else {
		// No object: the listing itself is the cell.
		return (rows.err().unwrap_or(Actual::Allow), None, 0);
	};
	let rows = match rows {
		Ok(rows) => rows,
		// A refused listing shows nothing.
		Err(Actual::Deny) => return (Actual::Absent, None, 0),
		Err(a) => return (a, None, 0),
	};
	let key = obj_key(o);
	if route == ActCount {
		return match count_actions(fx, s).await {
			// Counted = listed, or the count exceeds what the list shows.
			Ok(c) => {
				let counted = rows.contains_key(&key) || c > rows.len() as u64;
				(if counted { Actual::Present } else { Actual::Absent }, None, 0)
			}
			Err(a) => (a, None, 0),
		};
	}
	match rows.get(&key) {
		Some(l) => (Actual::Present, *l, 0),
		None => (Actual::Absent, None, 0),
	}
}

/// Render the observed outcome in the `expected` vocabulary; `Err` = harness error.
fn render(want: &str, (a, level, status): Observed) -> Result<String, String> {
	let denied = matches!(status, 401 | 403 | 404);
	let s = match a {
		_ if want == "Allow*" && status != 0 && !denied => "Allow".to_owned(),
		Actual::HarnessError(_) if want == "400" && status == 400 => return Ok("400".into()),
		Actual::HarnessError(d) => return Err(d),
		a => format!("{a:?}"),
	};
	Ok(if want.contains('@') {
		format!("{s}@{}", level.map_or_else(|| "None".to_owned(), |l| format!("{l:?}")))
	} else {
		s
	})
}

/// Runs `cells` serially: refusals before allows, so an Allow row's mutation (accept,
/// delete) never precedes a Deny row on the same object.
pub async fn run(fx: &Fixture, layer: &'static str, mut cells: Vec<Cell>) -> Report {
	let mut rep = Report::new(layer);
	cells.sort_by_key(|c| c.want.starts_with("Allow"));
	for c in cells {
		let obj = c.object.to_owned();
		match (subject(fx, c.subject), target(fx, c.object)) {
			(Some(s), Some(tgt)) => {
				let want = c.want.trim_end_matches('*');
				match render(c.want, observe(fx, s, c.route, &tgt).await) {
					Ok(actual) if actual == want => {}
					Ok(actual) => rep.add(Mismatch {
						op: c.op,
						rule: c.id,
						expected: want.to_owned(),
						actual,
						subject: s.name.clone(),
						object: obj,
					}),
					Err(d) => rep.error(c.op, format!("{}: {d}", c.id), s.name.clone(), obj),
				}
			}
			(s, _) => {
				let what = if s.is_none() { "unknown subject" } else { "unseeded object" };
				rep.error(c.op, format!("{}: {what}", c.id), c.subject.into(), obj);
			}
		}
	}
	rep
}

// vim: ts=4
