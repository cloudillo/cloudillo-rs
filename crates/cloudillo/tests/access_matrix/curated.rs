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
	ActionOp, Actual, FileOp, MARK, Op, bearer, classify, count_actions, list_paged, list_presence,
	obj_key, status_class,
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
	/// `GET …/descriptor`: the variant list of the content held here.
	FileDescriptor,
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
	/// `GET /api/channels`: the room's porch `status`, or `Absent` when unlisted.
	ChanPorch(&'static str),
	/// `GET /api/channels`: which of `minRole` / `closed` / `memberCount` the room's porch
	/// entry carries (`+`-joined, `none`), or `Absent` when unlisted.
	ChanPorchKeys(&'static str),
	/// `POST /api/channels {name}`.
	ChanCreate(&'static str),
	/// `PATCH /api/channels/{name} {title}`.
	ChanPatch(&'static str),
	ChanDelete(&'static str),
	/// `GET /api/channels/{name}/members`.
	ChanMembers(&'static str),
	/// `GET /api/actions?channel=@{host}~{room}`: Present = the object is listed.
	ChanFeed(&'static str),
	/// `POST /api/files` (CRDT) with this raw `channel` value.
	ChanUpload(&'static str),
	/// `GET /api/profiles?{query}`, summarised by [`profiles`].
	Profiles(&'static str),
	/// `GET /api/partners`, summarised by [`partners`].
	Partners,
	/// `GET /api/partners/map`.
	PartnersMap,
	/// `POST /api/partners/sync`.
	PartnersSync,
	/// `POST /api/actions {type: PTNR, subject: @peer.test}`.
	PtnrCreate,
	/// `POST /api/actions {type: "PTNR:DEL", subject: @peer.test}`: the subtype in `type`.
	PtnrDelCreate,
	/// `GET /api/actions?{query}`: Present = the object is listed.
	ActListQ(&'static str),
	/// `GET /api/files?{query}`: Present = the object is listed.
	FileListQ(&'static str),
	/// `GET {uri}` of profile rows: `Empty` or `Listed`.
	Ids(&'static str),
	/// `GET {uri}` of profile rows: `Present` if the id_tag is listed, else `Absent`.
	IdIn(&'static str, &'static str),
	/// `PATCH /api/profiles/{id_tag} {hats: [...]}`.
	HatsPatch(&'static str),
	/// `GET {uri}` (one row or a list): `Clean`, or `Leak:{field}` for the first field set.
	Fields(&'static str, &'static [&'static str]),
	/// `GET {uri}`: Allow / Deny.
	Get(&'static str),
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
			FileList | FileListQ(_) => Op::File(F::List),
			FileContent => Op::File(F::Content),
			FileDescriptor => Op::File(F::Descriptor),
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
			ActList | ActCount | ChanFeed(_) | ActListQ(_) => Op::Action(A::List),
			Search => Op::Search,
			Outbox => Op::Outbox,
			WsCrdt(a) => Op::Ws(WsKind::Crdt, a),
			WsRtdb(a) => Op::Ws(WsKind::Rtdb, a),
			FileUser | ReadMarker | Subscribe | ChanPorch(_) | ChanPorchKeys(_) | ChanCreate(_)
			| ChanPatch(_) | ChanDelete(_) | ChanMembers(_) | ChanUpload(_) | Profiles(_)
			| Partners | PartnersMap | PartnersSync | PtnrCreate | PtnrDelCreate | Ids(_)
			| IdIn(..) | HatsPatch(_) | Fields(..) | Get(_) => return None,
		})
	}

	fn is_listing(self) -> bool {
		matches!(
			self,
			FileList
				| FileListQ(_)
				| ActList | ActCount
				| Search | Outbox
				| ChanFeed(_)
				| ActListQ(_)
		)
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
	// A user's share map: self or tenant only; neither credential naming alice is either.
	("FC-49", "sharelink-r@alice", "", Get(SHARES_ALICE), "Deny"),
	("FC-50", "idp-mgmt@alice", "", Get(SHARES_ALICE), "Deny"),
	("FC-51", "owner@alice", "", Get(SHARES_ALICE), "Allow"),
	// An `idp_` key gets no identity grants. No object is shared to alice's own id_tag, so this
	// cannot catch a leaked `share_subject`; it pins the guest level only.
	("FC-52", "idp-mgmt@alice", "tenant-crdt-d-active@alice", Search, "Absent"),
	// v58 entry split on a non-folder BLOB: the direct share (keyed by entry_id) still grants,
	// and nothing else reaches it. Links to a non-folder doc: G2-05..07 (root) and G2-10 (embed);
	// API-created shares and multi-entry links: `share_lifecycle` /
	// `share_link_sees_only_its_entry`.
	("FC-53", "g_read@alice", "tenant-blob-d-active@alice", FileMeta, "Allow@Read"),
	("FC-54", "stranger@alice", "tenant-blob-d-active@alice", FileMeta, "Deny"),
	("FC-55", "follower@alice", "tenant-blob-d-active@alice", FileMeta, "Deny"),
	("FC-56", "anon@alice", "tenant-blob-d-active@alice", FileMeta, "Deny"),
	("FC-57", "sharelink-a@alice", "tenant-blob-d-active@alice", FileMeta, "Deny"),
	("FC-58", "idp-key@alice", "tenant-blob-d-active@alice", FileMeta, "Deny"),
	// Restore and duplicate from outside the tenant's grants, or with a credential that carries
	// its id_tag without being the tenant. Same-drive moves: `same_drive_moves`.
	("FC-59", "stranger@alice", "tenant-blob-p-trashed@alice", FileRestore, "Deny"),
	("FC-60", "anon@alice", "tenant-blob-p-trashed@alice", FileRestore, "Deny"),
	("FC-61", "sharelink-w@alice", "tenant-blob-p-trashed@alice", FileRestore, "Deny"),
	("FC-62", "idp-key@alice", "tenant-blob-p-trashed@alice", FileRestore, "Deny"),
	("FC-63", "stranger@alice", "tenant-blob-d-active@alice", FileDuplicate, "Deny"),
	("FC-64", "anon@alice", "tenant-blob-d-active@alice", FileDuplicate, "Deny"),
	("FC-65", "sharelink-r@alice", "tenant-blob-d-active@alice", FileDuplicate, "Deny"),
	("FC-66", "idp-key@alice", "tenant-blob-p-active@alice", FileDuplicate, "Deny"),
	// A reference (Pin / Place / FSHR) holds no bytes here: no reader, its placer and the FSHR
	// audience included, gets content through it. Scenarios with local content under the same
	// id: `a_pin_holds_no_local_bytes`, `a_forged_fshr_exposes_no_local_bytes`, and for a
	// reference claiming to be a folder, `a_remote_folder_never_shadows_a_local_id`. Nor does it
	// lend an attach or duplicate right, or a name: `a_pin_cannot_launder_attach_rights`,
	// `duplicating_a_crdt_reference_does_not_copy_local_doc`,
	// `attachment_name_never_comes_from_a_sibling`; nor may one name local content:
	// `a_reference_cannot_name_local_content`.
	("FC-67", "owner@alice", "tenant-blob-d-active@alice", FileDescriptor, "Allow"),
	("FC-68", "owner@alice", "mirroredplacer-blob-p-active@alice", FileDescriptor, "Deny"),
	("FC-69", "connected@alice", "mirroredplacer-blob-p-active@alice", FileDescriptor, "Deny"),
	("FC-70", "m_leader@club", "mirroredplacer-blob-p-active@club", FileDescriptor, "Deny"),
	("FC-71", "owner@alice", "mirroredfshr-blob-d-active@alice", FileDescriptor, "Deny"),
	("FC-72", "anon@alice", "mirroredplacer-blob-p-active@alice", FileDescriptor, "Deny"),
	("FC-73", "sharelink-r@alice", "mirroredplacer-blob-p-active@alice", FileDescriptor, "Deny"),
];

const SHARES_ALICE: &str = "/api/shares?subjectType=U&subjectId=alice.test";

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
	// Hatted `file:` scope mint: opens its root for Read only; the closed room stays shut.
	("WS-23", "hatted-scoped@club", "root@club", WsCrdt(None), "Allow@Read"),
	("WS-24", "hatted-scoped@club", "root@club", WsCrdt(Some("write")), "Deny"),
	("WS-25", "hatted-scoped@club", "cur-chan-closed-w-crdt@club", WsCrdt(None), "Deny"),
	// A room doc's `~meta` is gated by the room like the doc itself.
	(
		"WS-26",
		"m_contributor@club",
		"f1~zqm-club-cur-chan-closed-w-crdt~meta",
		WsRtdb(None),
		"Allow",
	),
	("WS-27", "m_moderator@club", "f1~zqm-club-cur-chan-closed-w-crdt~meta", WsRtdb(None), "Deny"),
	("WS-28", "stranger@club", "f1~zqm-club-cur-chan-closed-w-crdt~meta", WsRtdb(None), "Deny"),
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

const OC_POST: &str = "cur-chan-open-contrib-post@club";
const OC_FILE: &str = "cur-chan-open-contrib-file@club";
const OC_CRDT: &str = "cur-chan-open-contrib-crdt@club";
const MODS_POST: &str = "cur-chan-mods-post@club";
const CW_POST: &str = "cur-chan-closed-w-post@club";
const CW_FILE: &str = "cur-chan-closed-w-file@club";
const CW_CRDT: &str = "cur-chan-closed-w-crdt@club";
const GONE_POST: &str = "cur-chan-gone-post@club";
const GONE_FILE: &str = "cur-chan-gone-file@club";
const CF_POST: &str = "cur-chan-close-friends-post@alice";
const CF_FILE: &str = "cur-chan-close-friends-file@alice";

/// Channel rooms. club: `open-contrib` (contributor+), `mods` (moderator+), `closed-w`
/// (closed, secret, only `m_contributor` rostered), `gone` (deleted); alice: `close-friends`
/// (supporter+). Room objects are Public, so only the room gates them: absent, not redacted.
/// `hatted` maps to contributor. `zqm-scratch` is created by the layer before the rows run.
pub const CH: &[Row] = &[
	// Feed.
	("CH-01", "owner@club", CW_POST, ActList, "Present"),
	("CH-02", "m_contributor@club", OC_POST, ActList, "Present"),
	("CH-03", "m_supporter@club", OC_POST, ActList, "Absent"),
	("CH-04", "m_follower@club", OC_POST, ActList, "Absent"),
	("CH-05", "stranger@club", OC_POST, ActList, "Absent"),
	("CH-06", "anon@club", OC_POST, ActList, "Absent"),
	("CH-07", "hatted@club", OC_POST, ActList, "Present"),
	("CH-08", "m_contributor@club", MODS_POST, ActList, "Absent"),
	("CH-09", "m_moderator@club", MODS_POST, ActList, "Present"),
	("CH-10", "m_contributor@club", CW_POST, ActList, "Present"),
	("CH-11", "m_supporter@club", CW_POST, ActList, "Absent"),
	// A closed room admits the roster only, whatever the role.
	("CH-12", "m_moderator@club", CW_POST, ActList, "Absent"),
	("CH-13", "hatted@club", CW_POST, ActList, "Absent"),
	("CH-14", "owner@club", GONE_POST, ActList, "Present"),
	("CH-15", "m_leader@club", GONE_POST, ActList, "Absent"),
	("CH-16", "owner@alice", CF_POST, ActList, "Present"),
	("CH-17", "anon@alice", CF_POST, ActList, "Absent"),
	// Single-action reads follow the feed.
	("CH-18", "m_contributor@club", CW_POST, ActGet, "Allow"),
	("CH-19", "m_moderator@club", CW_POST, ActGet, "Deny"),
	("CH-20", "hatted@club", CW_POST, ActGet, "Deny"),
	("CH-21", "m_contributor@club", GONE_POST, ActGet, "Deny"),
	// `?channel=` filter.
	("CH-22", "m_contributor@club", OC_POST, ChanFeed("open-contrib"), "Present"),
	("CH-23", "m_contributor@club", CW_POST, ChanFeed("open-contrib"), "Absent"),
	("CH-24", "m_supporter@club", OC_POST, ChanFeed("open-contrib"), "Absent"),
	("CH-25", "hatted@club", CW_POST, ChanFeed("closed-w"), "Absent"),
	// Files.
	("CH-26", "m_contributor@club", CW_FILE, FileList, "Present"),
	("CH-27", "m_moderator@club", CW_FILE, FileList, "Absent"),
	("CH-28", "m_supporter@club", OC_FILE, FileList, "Absent"),
	("CH-29", "hatted@club", CW_FILE, FileList, "Absent"),
	("CH-30", "owner@club", GONE_FILE, FileList, "Present"),
	("CH-31", "m_contributor@club", GONE_FILE, FileList, "Absent"),
	("CH-32", "m_contributor@club", CW_FILE, FileMeta, "Allow"),
	("CH-33", "m_moderator@club", CW_FILE, FileMeta, "Deny"),
	("CH-34", "hatted@club", CW_FILE, FileMeta, "Deny"),
	("CH-35", "stranger@club", OC_FILE, FileMeta, "Deny"),
	("CH-36", "anon@club", OC_FILE, FileMeta, "Deny"),
	("CH-37", "m_contributor@club", GONE_FILE, FileMeta, "Deny"),
	("CH-38", "owner@club", GONE_FILE, FileMeta, "Allow"),
	("CH-39", "stranger@alice", CF_FILE, FileMeta, "Deny"),
	("CH-40", "owner@alice", CF_FILE, FileMeta, "Allow"),
	("CH-41", "m_contributor@club", CW_CRDT, WsCrdt(None), "Allow"),
	("CH-42", "m_moderator@club", CW_CRDT, WsCrdt(None), "Deny"),
	("CH-43", "hatted@club", CW_CRDT, WsCrdt(None), "Deny"),
	("CH-44", "hatted@club", OC_CRDT, WsCrdt(None), "Allow"),
	("CH-45", "m_supporter@club", OC_CRDT, WsCrdt(None), "Deny"),
	// A share grant bypasses the room.
	("CH-46", "g_read@club", CW_FILE, FileMeta, "Allow@Read"),
	("CH-47", "g_read@club", CW_CRDT, WsCrdt(None), "Allow@Read"),
	// Search.
	("CH-48", "m_contributor@club", CW_POST, Search, "Present"),
	("CH-49", "m_moderator@club", CW_POST, Search, "Absent"),
	("CH-50", "stranger@club", OC_FILE, Search, "Absent"),
	("CH-51", "m_contributor@club", OC_FILE, Search, "Present"),
	("CH-52", "m_contributor@club", GONE_POST, Search, "Absent"),
	("CH-53", "owner@club", GONE_POST, Search, "Present"),
	// Porch.
	("CH-54", "m_contributor@club", "", ChanPorch("open-contrib"), "in"),
	("CH-55", "m_supporter@club", "", ChanPorch("open-contrib"), "needs:contributor"),
	("CH-56", "stranger@club", "", ChanPorch("open-contrib"), "needs:contributor"),
	("CH-57", "anon@club", "", ChanPorch("open-contrib"), "needs:contributor"),
	("CH-58", "m_contributor@club", "", ChanPorch("mods"), "needs:moderator"),
	("CH-59", "hatted@club", "", ChanPorch("open-contrib"), "in"),
	("CH-60", "hatted@club", "", ChanPorch("mods"), "needs:moderator"),
	("CH-61", "m_moderator@club", "", ChanPorch("closed-w"), "invitation-only"),
	// Secret room: only the tenant and admins see it on the porch.
	("CH-62", "m_contributor@club", "", ChanPorch("closed-w"), "Absent"),
	("CH-63", "stranger@club", "", ChanPorch("closed-w"), "Absent"),
	("CH-64", "hatted@club", "", ChanPorch("closed-w"), "Absent"),
	("CH-65", "owner@club", "", ChanPorch("closed-w"), "in"),
	("CH-66", "owner@club", "", ChanPorch("gone"), "Absent"),
	// Room facts beyond `status` go to members and admins only.
	("CH-66a", "m_contributor@club", "", ChanPorchKeys("open-contrib"), "minRole+closed"),
	("CH-66b", "m_supporter@club", "", ChanPorchKeys("open-contrib"), "none"),
	("CH-66c", "stranger@club", "", ChanPorchKeys("open-contrib"), "none"),
	("CH-66d", "anon@club", "", ChanPorchKeys("open-contrib"), "none"),
	("CH-66e", "m_moderator@club", "", ChanPorchKeys("closed-w"), "minRole+closed+memberCount"),
	("CH-66f", "owner@club", "", ChanPorchKeys("closed-w"), "minRole+closed+memberCount"),
	// Admin: moderator+ and un-scoped; a hat mapped below moderator is refused.
	("CH-67", "m_contributor@club", "", ChanCreate("zqm-contrib-new"), "Deny"),
	("CH-68", "hatted@club", "", ChanCreate("zqm-hat-new"), "Deny"),
	("CH-69", "anon@club", "", ChanCreate("zqm-anon-new"), "Deny"),
	("CH-70", "m_moderator@club", "", ChanCreate("zqm-mod-new"), "Allow"),
	("CH-71", "m_contributor@club", "", ChanPatch("zqm-scratch"), "Deny"),
	("CH-72", "hatted@club", "", ChanPatch("zqm-scratch"), "Deny"),
	("CH-73", "m_moderator@club", "", ChanPatch("zqm-scratch"), "Allow"),
	("CH-74", "m_contributor@club", "", ChanMembers("closed-w"), "Deny"),
	("CH-75", "hatted@club", "", ChanMembers("closed-w"), "Deny"),
	("CH-76", "anon@club", "", ChanMembers("closed-w"), "Deny"),
	("CH-77", "m_moderator@club", "", ChanMembers("closed-w"), "Allow"),
	("CH-78", "m_contributor@club", "", ChanDelete("zqm-scratch"), "Deny"),
	("CH-79", "hatted@club", "", ChanDelete("zqm-scratch"), "Deny"),
	// Last Allow row: runs after CH-73's patch.
	("CH-80", "m_leader@club", "", ChanDelete("zqm-scratch"), "Allow"),
	// Upload into a room: enterable Allow, not enterable Deny, bad or foreign room 400.
	("CH-81", "m_contributor@club", "", ChanUpload("@club.test~open-contrib"), "Allow"),
	("CH-82", "m_contributor@club", "", ChanUpload("@club.test~closed-w"), "Allow"),
	("CH-83", "m_contributor@club", "", ChanUpload("@club.test~mods"), "Deny"),
	("CH-84", "m_moderator@club", "", ChanUpload("@club.test~closed-w"), "Deny"),
	("CH-85", "hatted@club", "", ChanUpload("@club.test~closed-w"), "Deny"),
	("CH-86", "m_contributor@club", "", ChanUpload("@alice.test~close-friends"), "400"),
	("CH-87", "m_contributor@club", "", ChanUpload("@club.test~zqm-nope"), "400"),
	("CH-88", "m_contributor@club", "", ChanUpload("@club.test~gone"), "400"),
	("CH-89", "m_contributor@club", "", ChanUpload("open-contrib"), "400"),
	// Credentials naming the tenant without being it are gated as guests, not as the tenant.
	("CH-90", "idp-mgmt@alice", CF_POST, ActGet, "Deny"),
	("CH-91", "idp-mgmt@alice", CF_POST, ActList, "Absent"),
	("CH-92", "sharelink-r@club", CW_POST, ActGet, "Deny"),
	("CH-93", "sharelink-r@club", CW_POST, ActList, "Absent"),
	// A drive's root listing (`parentId=__root__&channel=…`) applies the room gate too.
	("CH-94", "owner@club", "tenant-blob-p-active@club", FileListQ(MAIN_ROOT), "Present"),
	("CH-95", "owner@club", CW_FILE, FileListQ(CW_ROOT), "Present"),
	("CH-96", "m_contributor@club", CW_FILE, FileListQ(CW_ROOT), "Present"),
	("CH-97", "m_moderator@club", CW_FILE, FileListQ(CW_ROOT), "Absent"),
	("CH-98", "m_supporter@club", CW_FILE, FileListQ(CW_ROOT), "Absent"),
	("CH-99", "m_follower@club", CW_FILE, FileListQ(CW_ROOT), "Absent"),
	("CH-100", "stranger@club", CW_FILE, FileListQ(CW_ROOT), "Absent"),
	("CH-101", "anon@club", CW_FILE, FileListQ(CW_ROOT), "Absent"),
	("CH-102", "hatted@club", CW_FILE, FileListQ(CW_ROOT), "Absent"),
	("CH-103", "sharelink-r@club", CW_FILE, FileListQ(CW_ROOT), "Absent"),
	// A share grant bypasses the room, at the root as in a by-id read (CH-46).
	("CH-104", "g_read@club", CW_FILE, FileListQ(CW_ROOT), "Present"),
	("CH-105", "idp-key@alice", CF_FILE, FileListQ(CF_ROOT), "Absent"),
	("CH-106", "stranger@alice", CF_FILE, FileListQ(CF_ROOT), "Absent"),
	// A room's object never lists at the main drive's root.
	("CH-107", "owner@club", CW_FILE, FileListQ(MAIN_ROOT), "Absent"),
];

const MAIN_ROOT: &str = "parentId=__root__&channel=";
const CW_ROOT: &str = "parentId=__root__&channel=@club.test~closed-w";
const CF_ROOT: &str = "parentId=__root__&channel=@alice.test~close-friends";

/// Blocked profile the partners layer seeds on club before [`PT`] runs.
pub const PT_BLOCKED: &str = "zqm-blocked.test";

/// Connected community the partners layer seeds on alice (a person): her membership.
pub const PT_MEMBERSHIP: &str = "zqm-membership.test";

/// Profile listing projection and partner lists on club (`connection_visibility.community` =
/// `public`). club's one partner is `peer.test`. Leader tier (owner, `m_leader`) sees hidden
/// statuses; members keep `roles`; others (incl. the derived-follower `m_follower`) see
/// neither.
pub const PT: &[Row] = &[
	("PT-01", "owner@club", "", Profiles("status=B,X"), "Hidden"),
	("PT-02", "m_leader@club", "", Profiles("status=B,X"), "Hidden"),
	("PT-03", "m_contributor@club", "", Profiles("status=B,X"), "Roles"),
	("PT-04", "m_follower@club", "", Profiles("status=B,X"), "Bare"),
	("PT-05", "stranger@club", "", Profiles("status=B,X"), "Bare"),
	("PT-06", "anon@club", "", Profiles("status=B,X"), "Deny"),
	// A hat is a member.
	("PT-07", "hatted@club", "", Profiles("status=B,X"), "Roles"),
	("PT-08", "m_supporter@club", "", Profiles("status=B,X"), "Roles"),
	("PT-10", "m_contributor@club", "", Partners, "Listed"),
	("PT-11", "stranger@club", "", Partners, "Listed"),
	("PT-12", "anon@club", "", Partners, "Listed"),
	("PT-17", "hatted@club", "", Partners, "Listed"),
	// A person's list is its memberships, at the default `connected` visibility. An
	// authenticated refusal is 403 (a syncing home node keeps its edges); anonymous is empty.
	("PT-13", "stranger@alice", "", Partners, "Deny"),
	("PT-14", "anon@alice", "", Partners, "Empty"),
	("PT-15", "owner@alice", "", Partners, PT_MEMBERSHIP),
	("PT-38", "connected@alice", "", Partners, PT_MEMBERSHIP),
	// Carry alice's id_tag without being alice: a guest.
	("PT-19", "sharelink-r@alice", "", Partners, "Empty"),
	("PT-09", "idp-mgmt@alice", "", Partners, "Empty"),
	// PTNR is server-emitted only, whatever subtype rides in `type`.
	("PT-16", "m_contributor@club", "", PtnrCreate, "Deny"),
	("PT-18", "m_contributor@club", "", PtnrDelCreate, "Deny"),
	("PT-47", "sharelink-w@alice", "", PtnrCreate, "Deny"),
	("PT-48", "idp-mgmt@alice", "", PtnrCreate, "Deny"),
	("PT-49", "idp-key@alice", "", PtnrDelCreate, "Deny"),
	("PT-50", "owner@alice", "", PtnrCreate, "Deny"),
	// Owner only: remote leader, scoped hat, scoped owner, anon refused.
	("PT-20", "m_leader@club", "", PartnersMap, "Deny"),
	("PT-21", "stranger@club", "", PartnersMap, "Deny"),
	("PT-22", "hatted-scoped@club", "", PartnersMap, "Deny"),
	("PT-23", "owner-scoped-r@alice", "", PartnersMap, "Deny"),
	("PT-24", "anon@club", "", PartnersMap, "Deny"),
	("PT-25", "owner@club", "", PartnersMap, "Allow"),
	("PT-26", "idp-mgmt@alice", "", PartnersMap, "Deny"),
	("PT-27", "sharelink-r@alice", "", PartnersMap, "Deny"),
	("PT-30", "m_leader@club", "", PartnersSync, "Deny"),
	("PT-31", "stranger@club", "", PartnersSync, "Deny"),
	("PT-32", "hatted-scoped@club", "", PartnersSync, "Deny"),
	("PT-33", "owner-scoped-r@alice", "", PartnersSync, "Deny"),
	("PT-34", "anon@club", "", PartnersSync, "Deny"),
	("PT-35", "owner@club", "", PartnersSync, "Allow"),
	// idp-mgmt@alice: LV-91.
	("PT-37", "sharelink-r@alice", "", PartnersSync, "Deny"),
];

/// [`PT`] partner rows re-run with club's `connection_visibility.community` = `supporter`:
/// non-members get an empty list, members still see the partner.
pub const PT_PRIVATE: &[Row] = &[
	// Below the floor: authenticated callers get 403, anonymous an empty list.
	("PT-40", "stranger@club", "", Partners, "Deny"),
	("PT-41", "anon@club", "", Partners, "Empty"),
	("PT-42", "m_follower@club", "", Partners, "Deny"),
	("PT-43", "m_contributor@club", "", Partners, "Listed"),
	("PT-44", "owner@club", "", Partners, "Listed"),
	// A hat is a member; `supporter` is the floor.
	("PT-45", "hatted@club", "", Partners, "Listed"),
	("PT-46", "m_supporter@club", "", Partners, "Listed"),
];

/// Pending connection request the list-visibility layer seeds on alice.
pub const LV_PENDING: &str = "zqm-pending.test";
/// Followed-only (not connected) community the list-visibility layer seeds on club.
pub const LV_FOLLOWED: &str = "zqm-followed-comm.test";
const COMM: &str = "/api/profiles?type=community";
const COMM_UNCONN: &str = "/api/profiles?type=community&connected=false";
const HATS: &[&str] = &["hats"];
const ALICE_CONN: &str = "/api/profiles/connected.test";
const CLUB_PEER: &str = "/api/profiles/peer.test";

const CONN: &str = "/api/profiles?connected=true";
const CONN_COMM: &str = "/api/profiles?type=community&connected=true";
const CONN_PERSON: &str = "/api/profiles?type=person&connected=true";
const CONN_REQ: &str = "/api/profiles?connected=R";
const CONNECTED: &[&str] = &["connected"];
const EVERY_STATUS: &str = "status=A,C,D,N,V,F";

/// List visibility: relationship-revealing filters and fields, explicit action statuses,
/// settings reads and an `idp_` management key. alice keeps the default
/// `profile.connection_visibility` (`connected`); the layer sets club's `.person` override to
/// `supporter` and `.community` to `public`, and seeds a membership and [`LV_PENDING`] on
/// alice.
pub const LV: &[Row] = &[
	// alice's connections: her connections only.
	("LV-01", "anon@alice", "", Ids(CONN), "Deny"),
	("LV-02", "stranger@alice", "", Ids(CONN), "Empty"),
	("LV-03", "follower@alice", "", Ids(CONN), "Empty"),
	("LV-04", "connected@alice", "", Ids(CONN), "Listed"),
	("LV-05", "owner@alice", "", Ids(CONN), "Listed"),
	("LV-06", "stranger@alice", "", Ids(CONN_COMM), "Empty"),
	("LV-07", "follower@alice", "", Ids(CONN_COMM), "Empty"),
	("LV-08", "connected@alice", "", Ids(CONN_COMM), "Listed"),
	("LV-09", "owner@alice", "", Ids(CONN_COMM), "Listed"),
	("LV-10", "stranger@alice", "", Ids(CONN_REQ), "Empty"),
	("LV-11", "follower@alice", "", Ids(CONN_REQ), "Empty"),
	// Pending requests are the owner's inbox.
	("LV-12", "connected@alice", "", Ids(CONN_REQ), "Empty"),
	("LV-13", "owner@alice", "", Ids(CONN_REQ), "Listed"),
	// Every listed profile is a contact: no filter is no bypass.
	("LV-14", "stranger@alice", "", Ids("/api/profiles"), "Empty"),
	("LV-15", "stranger@alice", "", Ids("/api/profiles?connected=false"), "Empty"),
	// club: members from `supporter` (a hat counts), partner communities to everyone.
	("LV-20", "anon@club", "", Ids(CONN_PERSON), "Deny"),
	("LV-21", "stranger@club", "", Ids(CONN_PERSON), "Empty"),
	("LV-22", "m_follower@club", "", Ids(CONN_PERSON), "Empty"),
	("LV-23", "m_supporter@club", "", Ids(CONN_PERSON), "Listed"),
	("LV-24", "hatted@club", "", Ids(CONN_PERSON), "Listed"),
	("LV-25", "owner@club", "", Ids(CONN_PERSON), "Listed"),
	("LV-26", "stranger@club", "", Ids(CONN_COMM), "Listed"),
	("LV-27", "m_follower@club", "", Ids(CONN_COMM), "Listed"),
	// No `type`: narrowed to the types the caller may see (here club's partner communities).
	("LV-28", "stranger@club", "", Ids(CONN), "Listed"),
	("LV-29", "m_follower@club", "", Ids(CONN), "Listed"),
	("LV-30", "m_supporter@club", "", Ids(CONN), "Listed"),
	("LV-31", "hatted@club", "", Ids(CONN), "Listed"),
	("LV-32", "stranger@club", "", Ids("/api/profiles?type=person"), "Empty"),
	("LV-33", "m_supporter@club", "", Ids("/api/profiles?type=person"), "Listed"),
	// The `connected` field follows the same rule, per row type.
	("LV-40", "stranger@alice", "", Fields("/api/profiles", CONNECTED), "Clean"),
	("LV-41", "follower@alice", "", Fields("/api/profiles", CONNECTED), "Clean"),
	("LV-42", "connected@alice", "", Fields("/api/profiles", CONNECTED), "Leak:connected"),
	("LV-43", "owner@alice", "", Fields("/api/profiles", CONNECTED), "Leak:connected"),
	("LV-44", "stranger@alice", "", Fields("/api/profiles/connected.test", CONNECTED), "Clean"),
	(
		"LV-45",
		"owner@alice",
		"",
		Fields("/api/profiles/connected.test", CONNECTED),
		"Leak:connected",
	),
	("LV-46", "stranger@club", "", Fields("/api/profiles?type=person", CONNECTED), "Clean"),
	(
		"LV-47",
		"stranger@club",
		"",
		Fields("/api/profiles?type=community", CONNECTED),
		"Leak:connected",
	),
	("LV-48", "m_follower@club", "", Fields("/api/profiles?type=person", CONNECTED), "Clean"),
	// The single read projects like the list: relationship fields are the owner tier's.
	(
		"LV-49",
		"stranger@alice",
		"",
		Fields("/api/profiles/connected.test", PROFILE_PRIVATE),
		"Clean",
	),
	// A visible type lists its connections only: never followed or disconnected contacts.
	("LV-50", "stranger@club", "", IdIn(COMM_UNCONN, LV_FOLLOWED), "Absent"),
	("LV-51", "m_follower@club", "", IdIn(COMM_UNCONN, LV_FOLLOWED), "Absent"),
	("LV-52", "stranger@club", "", IdIn(COMM, LV_FOLLOWED), "Absent"),
	("LV-53", "m_follower@club", "", IdIn(COMM, LV_FOLLOWED), "Absent"),
	("LV-54", "owner@club", "", IdIn(COMM_UNCONN, LV_FOLLOWED), "Present"),
	// `hats` is the tenant account's alone, not the full (leader) tier's.
	("LV-55", "owner@alice", "", Fields(ALICE_CONN, HATS), "Leak:hats"),
	("LV-56", "stranger@alice", "", Fields(ALICE_CONN, HATS), "Clean"),
	("LV-57", "follower@alice", "", Fields(ALICE_CONN, HATS), "Clean"),
	("LV-58", "sharelink-r@alice", "", Fields(ALICE_CONN, HATS), "Deny"),
	("LV-59", "idp-mgmt@alice", "", Fields(ALICE_CONN, HATS), "Clean"),
	("LV-160", "owner@club", "", Fields(CLUB_PEER, HATS), "Leak:hats"),
	("LV-161", "m_leader@club", "", Fields(CLUB_PEER, HATS), "Clean"),
	("LV-162", "m_moderator@club", "", Fields(CLUB_PEER, HATS), "Clean"),
	("LV-163", "stranger@alice", "", HatsPatch("connected.test"), "Deny"),
	("LV-164", "sharelink-w@alice", "", HatsPatch("connected.test"), "Deny"),
	("LV-165", "idp-mgmt@alice", "", HatsPatch("connected.test"), "Deny"),
	("LV-166", "m_contributor@club", "", HatsPatch("peer.test"), "Deny"),
	("LV-167", "m_leader@club", "", HatsPatch("peer.test"), "Deny"),
	("LV-168", "owner@alice", "", HatsPatch("connected.test"), "Allow"),
	("LV-169", "owner@club", "", HatsPatch("peer.test"), "Allow"),
	// The list carries `hats` too, for the tenant account alone.
	("LV-170", "owner@alice", "", Fields("/api/profiles", HATS), "Leak:hats"),
	("LV-171", "connected@alice", "", Fields("/api/profiles", HATS), "Clean"),
	("LV-172", "idp-mgmt@alice", "", Fields("/api/profiles", HATS), "Clean"),
	("LV-173", "sharelink-r@alice", "", Fields("/api/profiles", HATS), "Deny"),
	("LV-174", "owner@club", "", Fields(COMM, HATS), "Leak:hats"),
	("LV-175", "m_leader@club", "", Fields(COMM, HATS), "Clean"),
	// Explicit `status=` never widens the list: deleted / verifying / failed rows stay out,
	// pending moderation (`C`) is the tenant's and its leaders'.
	("LV-60", "anon@alice", "post-p-tenant-deleted@alice", ActListQ("status=D"), "Absent"),
	("LV-61", "stranger@alice", "post-p-tenant-deleted@alice", ActListQ("status=D"), "Absent"),
	("LV-62", "anon@alice", "post-p-tenant-deleted@alice", ActListQ("status=D,V,F"), "Absent"),
	("LV-63", "anon@alice", "post-p-tenant-pending@alice", ActListQ("status=C"), "Absent"),
	("LV-64", "stranger@alice", "post-p-tenant-pending@alice", ActListQ("status=C"), "Absent"),
	("LV-65", "anon@alice", "post-p-tenant-deleted@alice", ActListQ(EVERY_STATUS), "Absent"),
	("LV-66", "stranger@alice", "post-p-tenant-pending@alice", ActListQ(EVERY_STATUS), "Absent"),
	("LV-67", "anon@alice", "post-p-tenant-dismissed@alice", ActListQ("status=N"), "Present"),
	("LV-68", "anon@alice", "post-p-tenant-active@alice", ActListQ(EVERY_STATUS), "Present"),
	("LV-69", "owner@alice", "post-p-tenant-deleted@alice", ActListQ("status=D"), "Absent"),
	("LV-70", "owner@alice", "post-p-tenant-deleted@alice", ActListQ(EVERY_STATUS), "Absent"),
	("LV-71", "owner@alice", "post-p-tenant-pending@alice", ActListQ("status=C"), "Present"),
	("LV-72", "owner@alice", "post-p-tenant-dismissed@alice", ActListQ("status=N"), "Present"),
	("LV-73", "owner@alice", "post-p-tenant-active@alice", ActListQ("status=A"), "Present"),
	("LV-74", "m_leader@club", "post-p-tenant-pending@club", ActListQ("status=C"), "Present"),
	("LV-75", "m_contributor@club", "post-p-tenant-pending@club", ActListQ("status=C"), "Absent"),
	// Settings are read with the standing that writes them.
	("LV-80", "stranger@alice", "", Get("/api/settings"), "Deny"),
	("LV-81", "follower@alice", "", Get("/api/settings?prefix=profile"), "Deny"),
	("LV-82", "connected@alice", "", Get("/api/settings/profile.connection_visibility"), "Deny"),
	("LV-83", "m_contributor@club", "", Get("/api/settings?prefix=profile"), "Deny"),
	("LV-84", "hatted@club", "", Get("/api/settings?prefix=profile"), "Deny"),
	("LV-85", "owner@alice", "", Get("/api/settings"), "Allow"),
	("LV-86", "owner@alice", "", Get("/api/settings/profile.connection_visibility"), "Allow"),
	("LV-87", "m_leader@club", "", Get("/api/settings?prefix=profile"), "Allow"),
	// An `idp_` management key names the account but is not it.
	("LV-90", "idp-mgmt@alice", "", PartnersMap, "Deny"),
	("LV-91", "idp-mgmt@alice", "", PartnersSync, "Deny"),
	("LV-92", "idp-mgmt@alice", "", Get("/api/settings"), "Deny"),
	("LV-93", "idp-mgmt@alice", "", Ids(CONN), "Empty"),
	("LV-94", "idp-mgmt@alice", "", Fields("/api/profiles", CONNECTED), "Clean"),
	("LV-95", "idp-mgmt@alice", "tenant-blob-d-active@alice", FileList, "Absent"),
	("LV-96", "idp-mgmt@alice", "post-d-tenant-active@alice", ActList, "Absent"),
	("LV-97", "idp-mgmt@alice", "post-p-tenant-pending@alice", ActListQ("status=C"), "Absent"),
];

/// [`LV`] boundary rows re-run with alice's `connection_visibility.community` = `verified`:
/// an `idp_` key naming alice is an anonymous guest, not an authenticated caller.
pub const LV_VERIFIED: &[Row] = &[
	("LV-100", "stranger@alice", "", Ids(CONN_COMM), "Listed"),
	("LV-101", "idp-mgmt@alice", "", Ids(CONN_COMM), "Empty"),
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
		(ChanCreate(name), _) => raw(Method::POST, "/api/channels", j(json!({ "name": name }))),
		(ChanPatch(name), _) => {
			raw(Method::PATCH, &format!("/api/channels/{name}"), j(json!({ "title": MARK })))
		}
		(ChanDelete(name), _) => {
			raw(Method::DELETE, &format!("/api/channels/{name}"), Body::empty())
		}
		(ChanMembers(name), _) => {
			raw(Method::GET, &format!("/api/channels/{name}/members"), Body::empty())
		}
		(ChanUpload(ch), _) => {
			let body = json!({
				"fileTp": "CRDT",
				"contentType": "cloudillo/quillo",
				"fileName": "zqm-chan",
				"channel": ch,
			});
			raw(Method::POST, "/api/files", j(body))
		}
		(PartnersMap, _) => raw(Method::GET, "/api/partners/map", Body::empty()),
		(HatsPatch(id_tag), _) => {
			let body = j(json!({ "hats": ["zqm-hat.test"] }));
			raw(Method::PATCH, &format!("/api/profiles/{id_tag}"), body)
		}
		(Get(uri), _) => raw(Method::GET, uri, Body::empty()),
		(PartnersSync, _) => raw(Method::POST, "/api/partners/sync", Body::empty()),
		(PtnrCreate, _) => {
			raw(Method::POST, "/api/actions", j(json!({ "type": "PTNR", "subject": "@peer.test" })))
		}
		(PtnrDelCreate, _) => {
			let body = json!({ "type": "PTNR:DEL", "subject": "@peer.test" });
			raw(Method::POST, "/api/actions", j(body))
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
	let rows = match route {
		ChanFeed(room) => {
			let path = format!("/api/actions?channel=@{}~{room}&", s.host);
			list_paged(fx, s, &path, "actionId").await
		}
		ActListQ(q) => list_paged(fx, s, &format!("/api/actions?{q}&"), "actionId").await,
		FileListQ(q) => list_paged(fx, s, &format!("/api/files?{q}&"), "fileId").await,
		_ => list_presence(fx, s, op).await,
	};
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

/// Porch `status` of `room` on `s.host`'s `GET /api/channels`; `Absent` when unlisted.
async fn porch(fx: &Fixture, s: &Subject, room: &str) -> Result<String, String> {
	let r = req(&s.host, Method::GET, "/api/channels", bearer(s), Body::empty());
	let (status, body) = call(&fx.api, r).await;
	match status_class(status) {
		Actual::Allow => {}
		Actual::HarnessError(e) => return Err(e),
		a => return Ok(format!("{a:?}")),
	}
	let entry = body["data"].as_array().and_then(|a| a.iter().find(|e| e["name"] == room));
	Ok(entry.and_then(|e| e["status"].as_str()).unwrap_or("Absent").to_owned())
}

/// Disclosure keys present on `room`'s porch entry, in [`ChanPorchKeys`] form.
async fn porch_keys(fx: &Fixture, s: &Subject, room: &str) -> Result<String, String> {
	let rows = match get_data(fx, s, "/api/channels").await {
		Ok(rows) => rows,
		Err(r) => return r,
	};
	let Some(e) = rows.iter().find(|e| e["name"] == room) else {
		return Ok("Absent".into());
	};
	let keys: Vec<_> = ["minRole", "closed", "memberCount"]
		.into_iter()
		.filter(|k| e.get(*k).is_some_and(|v| !v.is_null() || *k == "minRole"))
		.collect();
	Ok(if keys.is_empty() { "none".into() } else { keys.join("+") })
}

/// `data` of a GET on `s.host` as rows (a single object is one row, `null` none);
/// `Err(Ok(outcome))` when refused.
async fn get_data(
	fx: &Fixture,
	s: &Subject,
	uri: &str,
) -> Result<Vec<Value>, Result<String, String>> {
	let r = req(&s.host, Method::GET, uri, bearer(s), Body::empty());
	let (status, body) = call(&fx.api, r).await;
	match status_class(status) {
		Actual::Allow => {}
		Actual::HarnessError(e) => return Err(Err(e)),
		a => return Err(Ok(format!("{a:?}"))),
	}
	match &body["data"] {
		Value::Array(a) => Ok(a.clone()),
		Value::Null => Ok(Vec::new()),
		o @ Value::Object(_) => Ok(vec![o.clone()]),
		_ => Err(Err(format!("no data rows: {body}"))),
	}
}

/// Relationship fields a non-leader never sees on `/api/profiles` rows.
const PROFILE_PRIVATE: &[&str] = &[
	"status",
	"trust",
	"following",
	"follower",
	"feedReadAt",
	"msgReadAt",
	"hatRoles",
	"peerHatRoles",
	"hiddenInHome",
];

/// `/api/profiles` projection: `Hidden` = a Blocked/Banned row listed; `Leak` = a
/// [`PROFILE_PRIVATE`] field set; `Roles` = only roles shown; `Bare` = neither.
async fn profiles(fx: &Fixture, s: &Subject, query: &str) -> Result<String, String> {
	let rows = match get_data(fx, s, &format!("/api/profiles?{query}")).await {
		Ok(rows) => rows,
		Err(r) => return r,
	};
	let set = |r: &Value, k: &str| !r[k].is_null();
	let hidden = |r: &Value| matches!(r["status"].as_str(), Some("B" | "X"));
	let leak = |r: &Value| PROFILE_PRIVATE.iter().any(|k| set(r, k));
	Ok(if rows.iter().any(hidden) {
		"Hidden"
	} else if rows.iter().any(leak) {
		"Leak"
	} else if rows.iter().any(|r| set(r, "roles")) {
		"Roles"
	} else {
		"Bare"
	}
	.into())
}

/// Sorted `idTag`s of the rows at `uri`.
async fn id_tags(
	fx: &Fixture,
	s: &Subject,
	uri: &str,
) -> Result<Vec<String>, Result<String, String>> {
	let rows = get_data(fx, s, uri).await?;
	let mut tags: Vec<String> =
		rows.iter().filter_map(|r| r["idTag"].as_str().map(str::to_owned)).collect();
	tags.sort();
	Ok(tags)
}

/// `Empty` or `Listed`: other layers add rows to the shared tenants, so membership is not exact.
async fn ids(fx: &Fixture, s: &Subject, uri: &str) -> Result<String, String> {
	match id_tags(fx, s, uri).await {
		Ok(t) => Ok(if t.is_empty() { "Empty" } else { "Listed" }.into()),
		Err(r) => r,
	}
}

/// `Clean`, or `Leak:{field}` for the first of `forbidden` set on any row at `uri`.
async fn fields(
	fx: &Fixture,
	s: &Subject,
	uri: &str,
	forbidden: &[&str],
) -> Result<String, String> {
	let rows = match get_data(fx, s, uri).await {
		Ok(rows) => rows,
		Err(r) => return r,
	};
	Ok(forbidden
		.iter()
		.find(|k| rows.iter().any(|r| !r[**k].is_null()))
		.map_or_else(|| "Clean".into(), |k| format!("Leak:{k}")))
}

/// `/api/partners`: `Listed` = exactly club's partner `peer.test`, `Empty`, else the idTags.
async fn partners(fx: &Fixture, s: &Subject) -> Result<String, String> {
	let tags = match id_tags(fx, s, "/api/partners").await {
		Ok(t) => t,
		Err(r) => return r,
	};
	Ok(match tags.as_slice() {
		[] => "Empty".into(),
		[p] if p == "peer.test" => "Listed".into(),
		t => t.join(","),
	})
}

/// Runs `cells` serially: refusals before allows, so an Allow row's mutation (accept,
/// delete) never precedes a Deny row on the same object.
pub async fn run(fx: &Fixture, layer: &'static str, mut cells: Vec<Cell>) -> Report {
	let mut rep = Report::new(layer);
	cells.sort_by_key(|c| c.want.starts_with("Allow"));
	for c in cells {
		rep.cell();
		let obj = c.object.to_owned();
		match (subject(fx, c.subject), target(fx, c.object)) {
			(Some(s), Some(tgt)) => {
				let want = c.want.trim_end_matches('*');
				let got = match c.route {
					ChanPorch(room) => porch(fx, s, room).await,
					ChanPorchKeys(room) => porch_keys(fx, s, room).await,
					Profiles(q) => profiles(fx, s, q).await,
					Partners => partners(fx, s).await,
					Ids(uri) => ids(fx, s, uri).await,
					IdIn(uri, id_tag) => match id_tags(fx, s, uri).await {
						Ok(t) => {
							Ok(if t.iter().any(|t| t == id_tag) { "Present" } else { "Absent" }
								.into())
						}
						Err(r) => r,
					},
					Fields(uri, f) => fields(fx, s, uri, f).await,
					r => render(c.want, observe(fx, s, r, &tgt).await),
				};
				match got {
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
