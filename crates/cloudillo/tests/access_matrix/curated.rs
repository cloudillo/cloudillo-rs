// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Curated layers: literal hand-picked rows, each with a stable case id, and their runner.
//! Names are short case names; [`subject`] and [`target`] map them to fixture names. The
//! report's `rule` is the row id.

use axum::body::Body;
use axum::http::{HeaderValue, Method, Request, header};
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
	/// `GET /api/files/{id}`.
	FileGet,
	/// `GET /api/files/variant/{blob}`.
	FileVariant,
	/// `POST /api/files/file/zqm-new.txt?parentId=` the object (a BLOB upload).
	FileUpload,
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
	/// [`WsCrdt`] / [`WsRtdb`] with the bearer in `?token=` (as browsers connect), no header.
	WsQuery(WsKind, Option<&'static str>),
	/// `GET {uri}` with the bearer in `?token=`, no header.
	GetQ(&'static str),
	/// `{method} {uri}` with `Authorization: Basic …` instead of the bearer, and a raw body
	/// (`""` = none).
	CallBasic(&'static str, &'static str, &'static str),
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
	/// `GET /api/search?q={MARK}&{query}` (one page): Present = the object is a hit.
	SearchQ(&'static str),
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
	/// `{method} {uri}` with a JSON body (`""` = none): Allow / Deny. `{obj}` in either is the
	/// row object's key.
	Call(&'static str, &'static str, &'static str),
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
			FileGet => Op::File(F::Get),
			FileVariant => Op::File(F::Variant),
			FileUpload => Op::File(F::CreateBlob),
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
			Search | SearchQ(_) => Op::Search,
			Outbox => Op::Outbox,
			WsCrdt(a) => Op::Ws(WsKind::Crdt, a),
			WsRtdb(a) => Op::Ws(WsKind::Rtdb, a),
			WsQuery(k, a) => Op::Ws(k, a),
			FileUser | ReadMarker | Subscribe | ChanPorch(_) | ChanPorchKeys(_) | ChanCreate(_)
			| ChanPatch(_) | ChanDelete(_) | ChanMembers(_) | ChanUpload(_) | Profiles(_)
			| Partners | PartnersMap | PartnersSync | PtnrCreate | PtnrDelCreate | Ids(_)
			| IdIn(..) | HatsPatch(_) | Fields(..) | Get(_) | GetQ(_) | CallBasic(..)
			| Call(..) => {
				return None;
			}
		})
	}

	fn is_listing(self) -> bool {
		matches!(
			self,
			FileList
				| FileListQ(_)
				| ActList | ActCount
				| Search | SearchQ(_)
				| Outbox | ChanFeed(_)
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
	// The real `idp_` key naming alice: refused on her host, not a guest.
	("G2-20", "idp-mgmt@alice", DENY6),
	// alice's own key off her host (her objects do not exist there: FC-79 is the live cell),
	// and an expired key: refused, not dropped to a guest.
	("G2-21", "apikey-xtenant@club", DENY6),
	("G2-22", "apikey-expired@alice", DENY6),
	// An identity's own `idp_` key on its IdP's host: that identity, a stranger to alice.
	("G2-23", "idp-ident@alice", ["Allow@Read", "Deny", "Allow", "Deny", "Deny", "Deny"]),
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
	// An `idp_` key naming alice is refused on her host; a refused listing shows nothing.
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
	// alice's `idp_` key off its IdP's host, on a community she may belong to: refused, not
	// even the guest view of a Public file.
	("FC-74", "idp-mgmt@club", "tenant-crdt-p-active@club", FileMeta, "Deny"),
	// Shares by subject: a scoped credential never reaches the route; `F` is plain file access.
	("FC-75", "sharelink-r@alice", "", Get(SHARES_F_ROOT), "Deny"),
	("FC-76", "g_read@alice", "", Get(SHARES_F_BLOB), "Allow"),
	("FC-77", "stranger@alice", "", Get(SHARES_F_BLOB), "Deny"),
	(
		"FC-78",
		"owner@alice",
		"",
		Get("/api/shares?subjectType=X&subjectId=f1~zqm-alice-tenant-blob-d-active"),
		"400",
	),
	// alice's key on club's host: refused, where an anonymous caller reads (G2-01 on alice).
	("FC-79", "apikey-xtenant@club", "tenant-crdt-p-active@club", FileMeta, "Deny"),
	// A user's share map: self, the tenant account or a leader; links: the tenant account.
	("FC-80", "stranger@alice", "", Get("/api/shares?subjectType=U&subjectId=g-read.test"), "Deny"),
	("FC-81", "g_read@alice", "", Get("/api/shares?subjectType=U&subjectId=g-read.test"), "Allow"),
	(
		"FC-82",
		"m_leader@club",
		"",
		Get("/api/shares?subjectType=U&subjectId=m-contributor.test"),
		"Allow",
	),
	(
		"FC-83",
		"m_contributor@club",
		"",
		Get("/api/shares?subjectType=U&subjectId=m-follower.test"),
		"Deny",
	),
	("FC-84", "m_leader@club", "", Get(SHARES_L), "Deny"),
	("FC-85", "stranger@alice", "", Get(SHARES_L), "Deny"),
	("FC-86", "owner@alice", "", Get(SHARES_L), "Allow"),
	("FC-87", "owner@club", "", Get(SHARES_L), "Allow"),
	// Ref listings: untyped = the tenant account's; `share.file` names its file and redacts
	// the ref for a non-manager; `register` is SADM's.
	("FC-88", "owner@alice", "", Get("/api/refs"), "Allow"),
	("FC-89", "owner@club", "", Get("/api/refs"), "Allow"),
	("FC-90", "m_leader@club", "", Get("/api/refs"), "Deny"),
	("FC-91", "stranger@alice", "", Get("/api/refs"), "Deny"),
	("FC-92", "sharelink-r@alice", "", Get("/api/refs"), "Deny"),
	("FC-93", "owner-scoped-r@alice", "", Get("/api/refs"), "Deny"),
	("FC-94", "owner@alice", "", Get("/api/refs?type=share.file"), "400"),
	("FC-95", "g_read@alice", "", Get(REFS_ROOT), "Deny"),
	("FC-96", "g_write@alice", "", Fields(REFS_ROOT, &["redacted"]), "Leak:redacted"),
	("FC-97", "owner@alice", "", Fields(REFS_ROOT, &["redacted"]), "Clean"),
	("FC-98", "owner@alice", "", Get("/api/refs?type=register"), "Deny"),
	("FC-99", "owner-sadm@admin", "", Get("/api/refs?type=register"), "Allow"),
	// A share link is no account ref: no IdP status behind it.
	("FC-100", "anon@alice", "", Get("/api/refs/zqref-alice-r/idp-status"), "400"),
	// A file's shares are its managers' and readers', never a scoped credential's.
	("FC-101", "sharelink-a@alice", "root@alice", Get(SHARES_OBJ), "Deny"),
	("FC-102", "owner-scoped-w@alice", "root@alice", Get(SHARES_OBJ), "Deny"),
	// The bytes of a Direct blob: its grantees only.
	("FC-103", "stranger@alice", "tenant-blob-d-active@alice", FileGet, "Deny"),
	("FC-104", "follower@alice", "tenant-blob-d-active@alice", FileGet, "Deny"),
	("FC-105", "connected@alice", "tenant-blob-d-active@alice", FileGet, "Deny"),
	("FC-106", "idp-key@alice", "tenant-blob-d-active@alice", FileGet, "Deny"),
	("FC-107", "sharelink-r@alice", "tenant-blob-d-active@alice", FileGet, "Deny"),
	("FC-108", "g_read@alice", "tenant-blob-d-active@alice", FileGet, "Allow"),
	("FC-109", "anon@alice", "tenant-blob-p-active@alice", FileGet, "Allow"),
	("FC-110", "stranger@alice", "tenant-blob-d-active@alice", FileVariant, "Deny"),
	("FC-111", "follower@alice", "tenant-blob-d-active@alice", FileVariant, "Deny"),
	("FC-112", "connected@alice", "tenant-blob-d-active@alice", FileVariant, "Deny"),
	("FC-113", "idp-key@alice", "tenant-blob-d-active@alice", FileVariant, "Deny"),
	("FC-114", "sharelink-r@alice", "tenant-blob-d-active@alice", FileVariant, "Deny"),
	("FC-115", "g_read@alice", "tenant-blob-d-active@alice", FileVariant, "Allow"),
	("FC-116", "anon@alice", "tenant-blob-p-active@alice", FileVariant, "Allow"),
	// App package content follows the package's visibility.
	("FC-117", "sharelink-r@alice", "apkg-blob-d-active@alice", FileContent, "Deny"),
	("FC-118", "idp-key@alice", "apkg-blob-d-active@alice", FileContent, "Deny"),
	("FC-119", "follower@alice", "apkg-blob-f-active@alice", FileContent, "Allow"),
	// Search with credentials the level layers do not carry: a `file:` key or link searches its
	// document tree, files only; `apkg:publish` searches as a guest.
	("FC-120", "apikey-file@alice", "root@alice", Search, "Present"),
	("FC-121", "apikey-file@alice", "tenant-crdt-p-active@alice", Search, "Absent"),
	("FC-122", "apikey-file@alice", "post-p-tenant-active@alice", Search, "Absent"),
	("FC-123", "apkg-publish@alice", "tenant-crdt-p-active@alice", Search, "Present"),
	("FC-124", "apkg-publish@alice", "tenant-blob-d-active@alice", Search, "Absent"),
	("FC-125", "sharelink-a@alice", "root@alice", Search, "Present"),
	("FC-126", "sharelink-a@alice", "post-p-tenant-active@alice", Search, "Absent"),
	// A lapsed `F` link opens nothing; the live one beside it does.
	("FC-127", "sharelink-r@alice", "cur-linktarget-expired@alice", FileMeta, "Deny"),
	("FC-128", "sharelink-r@alice", "linktarget-blob-d-active@alice", FileMeta, "Allow@Read"),
	// A folder link reaches the folder's descendants, nothing beside it; a document link
	// nothing beside its root.
	("FC-129", "folderlink-r@alice", "folderchild-blob-d-active@alice", FileMeta, "Allow@Read"),
	("FC-130", "folderlink-r@alice", FOLDER_CHILD, FileListQ("parentId={parent}"), "Present"),
	("FC-131", "folderlink-r@alice", "tenant-blob-d-active@alice", FileMeta, "Deny"),
	("FC-132", "folderlink-r@alice", "tenant-blob-d-active@alice", FileListQ(MAIN_ROOT), "Absent"),
	("FC-133", "sharelink-r@alice", "tenant-blob-d-active@alice", FileMeta, "Deny"),
	// A non-BLOB mirror's FSHR grant: WRITE to the tenant.
	("FC-134", "owner@alice", "mirroredfshr-crdt-p-active@alice", FileMeta, "Allow@Write"),
	// FC-135, FC-136: main.rs fshr_grants_follow_the_sub_type.
	("FC-137", "apkg-publish@alice", "", Call("POST", "/api/files/apkg/zqm.apkg", ""), "Allow*"),
	// Tagging is a writer's.
	("FC-138", "sharelink-w@alice", "tenant-blob-p-active@alice", FileTag, "Deny"),
	("FC-139", "idp-mgmt@alice", "tenant-blob-p-active@alice", FileTag, "Deny"),
	("FC-140", "follower@alice", "tenant-blob-p-active@alice", FileTag, "Deny"),
	// A comment link comments; it never writes.
	("FC-141", "sharelink-c@alice", "root@alice", FilePatch, "Deny"),
	("FC-142", "wefollow@alice", "tenant-blob-f-active@alice", FileMeta, "Deny"),
	("FC-143", "follower@alice", "tenant-blob-f-active@alice", FileMeta, "Allow@Read"),
	// Browsing a shared folder (`?parentId=`) lists at the share's level; a share on a sibling
	// file is no folder share.
	("FC-147", "g_folder@alice", FOLDER_CHILD, FileListQ("parentId={parent}"), "Present@Write"),
	("FC-148", "g_read@alice", FOLDER_CHILD, FileListQ("parentId={parent}"), "Absent"),
	// A `W` link writes inside its document tree: a new part under its root.
	(
		"FC-154",
		"sharelink-w@alice",
		"root@alice",
		Call(
			"POST",
			"/api/files",
			r#"{"fileTp":"CRDT","contentType":"cloudillo/quillo","fileName":"zqm-part","rootId":"{obj}"}"#,
		),
		"Allow",
	),
];
const FOLDER_CHILD: &str = "folderchild-blob-d-active@alice";

const SHARES_L: &str = "/api/shares?subjectType=L&subjectId=zqm";
const SHARES_OBJ: &str = "/api/files/{obj}/shares";
const REFS_ROOT: &str = "/api/refs?type=share.file&resourceId=f1~zqm-alice-tenant-crdt-d-active";

const SHARES_F_ROOT: &str = "/api/shares?subjectType=F&subjectId=f1~zqm-alice-tenant-crdt-d-active";
const SHARES_F_BLOB: &str = "/api/shares?subjectType=F&subjectId=f1~zqm-alice-tenant-blob-d-active";

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
	// Reject is moderator+, like accept (AC-26, AC-27).
	("AC-43", "m_contributor@club", "cur-reject-mod@club", ActReject, "Deny"),
	("AC-44", "hatted@club", "cur-reject-mod@club", ActReject, "Deny"),
	// Write-tier action routes refuse links and non-moderators.
	("AC-45", "sharelink-w@alice", "cur-draft-patch@alice", ActPatch, "Deny"),
	("AC-46", "stranger@club", "cur-accept-mod@club", ActAccept, "Deny"),
	("AC-47", "m_follower@club", "cur-accept-mod@club", ActAccept, "Deny"),
	("AC-48", "stranger@club", "cur-reject-mod@club", ActReject, "Deny"),
	("AC-49", "m_follower@club", "cur-reject-mod@club", ActReject, "Deny"),
	// A member's post club relayed under its own hat: the tenant's to read, not even its issuer's.
	("AC-50", "owner@club", "cur-hatrelay-own@club", ActGet, "Allow"),
	("AC-51", "m_leader@club", "cur-hatrelay-own@club", ActGet, "Deny"),
	("AC-52", "m_contributor@club", "cur-hatrelay-own@club", ActGet, "Deny"),
	("AC-53", "m_leader@club", "cur-hatrelay-own@club", ActList, "Absent"),
	// A Blocked profile's stored contributor role counts for nothing (`effective_roles`).
	("AC-54", "blocked-session@club", "", POST_ZQM, "Deny"),
	("AC-55", "blocked-session@club", "folder@club", FileCreate, "Deny"),
	// Publish, cancel and dismiss are the tenant's: no stranger, link or `idp_` key.
	("AC-56", "stranger@alice", "cur-draft-publish@alice", ActPublish, "Deny"),
	("AC-57", "sharelink-w@alice", "cur-draft-publish@alice", ActPublish, "Deny"),
	("AC-58", "idp-mgmt@alice", "cur-draft-publish@alice", ActPublish, "Deny"),
	("AC-59", "stranger@alice", "cur-sched-cancel@alice", ActCancel, "Deny"),
	("AC-60", "sharelink-w@alice", "cur-sched-cancel@alice", ActCancel, "Deny"),
	("AC-61", "idp-mgmt@alice", "cur-sched-cancel@alice", ActCancel, "Deny"),
	("AC-62", "stranger@alice", "cur-dismiss-owner@alice", ActDismiss, "Deny"),
	("AC-63", "sharelink-w@alice", "cur-dismiss-owner@alice", ActDismiss, "Deny"),
	("AC-64", "idp-mgmt@alice", "cur-dismiss-owner@alice", ActDismiss, "Deny"),
	("AC-65", "stranger@alice", "post-p-tenant-active@alice", ReadMarker, "Deny"),
	("AC-66", "idp-mgmt@alice", "post-p-tenant-active@alice", ReadMarker, "Deny"),
	// `apkg:publish` posts an APKG and nothing else.
	("AC-67", "apkg-publish@alice", "", POST_ZQM, "Deny"),
	("AC-68", "apkg-publish@alice", "", APKG_POST, "Allow*"),
	// F reaches followers, not those alice follows.
	("AC-69", "wefollow@alice", "post-f-tenant-active@alice", ActGet, "Deny"),
	("AC-70", "follower@alice", "post-f-tenant-active@alice", ActGet, "Allow"),
	// Server-emitted types are never a client's to sign as the tenant, whoever asks.
	("AC-71", "m_contributor@club", "tenant-blob-d-active@club", FSHR_CLUB, "Deny"),
	("AC-72", "owner@alice", "tenant-blob-d-active@alice", FSHR_ALICE, "Deny"),
	("AC-73", "m_contributor@club", "tenant-blob-d-active@club", FSHR_DEL_CLUB, "Deny"),
	("AC-74", "owner@alice", "tenant-blob-d-active@alice", FSHR_DEL_ALICE, "Deny"),
	("AC-75", "m_contributor@club", "post-p-tenant-active@club", STAT_POST, "Deny"),
	("AC-76", "owner@alice", "post-p-tenant-active@alice", STAT_POST, "Deny"),
	("AC-77", "owner@alice", "", IDP_REG_POST, "Deny"),
	("AC-118", "m_contributor@club", "", PRINVT_CLUB, "Deny"),
	("AC-119", "owner@alice", "", PRINVT_ALICE, "Deny"),
	// The revocation subtype in `subType` instead of embedded in `type`.
	("AC-120", "m_contributor@club", "tenant-blob-d-active@club", FSHR_SUB_DEL_CLUB, "Deny"),
	// A root's explicit room: enterable by the actor, a room of this tenant or the audience's.
	("AC-78", "m_supporter@club", "", POST_OC, "Deny"),
	("AC-79", "m_contributor@club", "", POST_OC, "Allow*"),
	("AC-80", "m_moderator@club", "", POST_CW, "Deny"),
	("AC-81", "m_contributor@club", "", POST_NOPE, "400"),
	("AC-82", "m_contributor@club", "", POST_CF, "400"),
	("AC-83", "m_contributor@club", "", POST_GONE, "400"),
	// A hat needs an audience other than itself, on a type that allows one.
	("AC-84", "owner@alice", "", HAT_NO_AUD, "400"),
	("AC-85", "owner@alice", "", HAT_IS_AUD, "400"),
	("AC-86", "owner@alice", "", HAT_ON_CONV, "400"),
	// A community invitation to a known profile (MG-300: unknown, 400).
	("AC-87", "m_moderator@club", "", INVT_KNOWN, "Allow*"),
	// No `allow_unknown`: a POST to an unknown audience.
	("AC-88", "owner@alice", "", POST_TO_NOBODY, "400"),
	// REPOST: public, not one's own, with an explicit audience.
	("AC-95", "owner@alice", "post-f-remote-active@alice", REPOST_ALICE, "400"),
	("AC-96", "owner@alice", "post-p-tenant-active@alice", REPOST_ALICE, "400"),
	("AC-97", "owner@alice", "post-p-remote-active@alice", REPOST_NO_AUD, "400"),
	("AC-98", "owner@alice", "post-p-remote-active@alice", REPOST_ALICE, "Allow"),
	// Unfollowing as the community is a leader's, as following is (MG-188..198).
	("AC-99", "m_moderator@club", "", FLLW_DEL_NOBODY, "Deny"),
	("AC-100", "m_contributor@club", "", FLLW_DEL_NOBODY, "Deny"),
	("AC-101", "m_leader@club", "", FLLW_DEL_NOBODY, "Allow*"),
	// A reply needs read on its parent, room gate included (`check_action_read`).
	("AC-103", "m_supporter@club", OC_POST, CMNT_PARENT, "Deny"),
	("AC-104", "m_contributor@club", MODS_POST, CMNT_PARENT, "Deny"),
	("AC-105", "m_contributor@club", OC_POST, CMNT_PARENT, "Allow*"),
	// An invitation into a room is a moderator's (`invt.rs` `check_community_authority`).
	("AC-106", "m_contributor@club", "", INVT_ROOM, "Deny"),
	("AC-107", "m_moderator@club", "", INVT_ROOM, "Allow*"),
	// Accepting or rejecting what was sent to the tenant: the tenant account, never a link or
	// a scoped or `idp_` credential (`scope_permits`).
	("AC-110", "sharelink-r@alice", "cur-accept-alice@alice", ActAccept, "Deny"),
	("AC-111", "owner-scoped-r@alice", "cur-accept-alice@alice", ActAccept, "Deny"),
	("AC-112", "idp-ident@alice", "cur-accept-alice@alice", ActAccept, "Deny"),
	("AC-113", "owner@alice", "cur-accept-alice@alice", ActAccept, "Allow"),
	("AC-114", "sharelink-r@alice", "cur-reject-alice@alice", ActReject, "Deny"),
	("AC-115", "idp-ident@alice", "cur-reject-alice@alice", ActReject, "Deny"),
	("AC-116", "owner@alice", "cur-reject-alice@alice", ActReject, "Allow"),
	("AC-117", "sharelink-r@alice", "container-p-tenant-active@alice", Subscribe, "Deny"),
];

/// FSHR to a profile connected to the host (`m-follower.test` on club, `connected.test` on alice),
/// so only the type itself can refuse it.
const FSHR_CLUB: Route = Call(
	"POST",
	"/api/actions",
	r#"{"type":"FSHR","subType":"WRITE","subject":"{obj}","audienceTag":"m-follower.test","content":{"contentType":"text/plain","fileName":"zqm","fileTp":"BLOB"}}"#,
);
const FSHR_ALICE: Route = Call(
	"POST",
	"/api/actions",
	r#"{"type":"FSHR","subType":"WRITE","subject":"{obj}","audienceTag":"connected.test","content":{"contentType":"text/plain","fileName":"zqm","fileTp":"BLOB"}}"#,
);
const FSHR_DEL_CLUB: Route = Call(
	"POST",
	"/api/actions",
	r#"{"type":"FSHR:DEL","subject":"{obj}","audienceTag":"m-follower.test"}"#,
);
const FSHR_DEL_ALICE: Route = Call(
	"POST",
	"/api/actions",
	r#"{"type":"FSHR:DEL","subject":"{obj}","audienceTag":"connected.test"}"#,
);
const FSHR_SUB_DEL_CLUB: Route = Call(
	"POST",
	"/api/actions",
	r#"{"type":"FSHR","subType":"DEL","subject":"{obj}","audienceTag":"m-follower.test"}"#,
);
/// PRINVT is `post_invite_community`'s alone, never a member's or the owner's to sign.
const PRINVT_CLUB: Route = Call(
	"POST",
	"/api/actions",
	r#"{"type":"PRINVT","audienceTag":"m-follower.test","content":{"refId":"zqm-ref"}}"#,
);
const PRINVT_ALICE: Route = Call(
	"POST",
	"/api/actions",
	r#"{"type":"PRINVT","audienceTag":"connected.test","content":{"refId":"zqm-ref"}}"#,
);
const STAT_POST: Route =
	Call("POST", "/api/actions", r#"{"type":"STAT","parentId":"{obj}","content":{"c":1}}"#);
const IDP_REG_POST: Route = Call(
	"POST",
	"/api/actions",
	r#"{"type":"IDP:REG","audienceTag":"connected.test","content":{"idTag":"zqm.connected.test"}}"#,
);
/// A root POST into a room (`channel`), one literal per room.
const POST_OC: Route = Call(
	"POST",
	"/api/actions",
	r#"{"type":"POST","content":"zqm","channel":"@club.test~open-contrib"}"#,
);
const POST_CW: Route = Call(
	"POST",
	"/api/actions",
	r#"{"type":"POST","content":"zqm","channel":"@club.test~closed-w"}"#,
);
const POST_NOPE: Route = Call(
	"POST",
	"/api/actions",
	r#"{"type":"POST","content":"zqm","channel":"@club.test~zqm-nope"}"#,
);
const POST_CF: Route = Call(
	"POST",
	"/api/actions",
	r#"{"type":"POST","content":"zqm","channel":"@alice.test~close-friends"}"#,
);
const POST_GONE: Route =
	Call("POST", "/api/actions", r#"{"type":"POST","content":"zqm","channel":"@club.test~gone"}"#);
const HAT_NO_AUD: Route =
	Call("POST", "/api/actions", r#"{"type":"POST","content":"zqm","hat":"peer.test"}"#);
const HAT_IS_AUD: Route = Call(
	"POST",
	"/api/actions",
	r#"{"type":"POST","content":"zqm","hat":"connected.test","audienceTag":"connected.test"}"#,
);
const HAT_ON_CONV: Route = Call(
	"POST",
	"/api/actions",
	r#"{"type":"CONV","content":{"name":"zqm"},"hat":"peer.test","audienceTag":"connected.test"}"#,
);
const INVT_KNOWN: Route = Call(
	"POST",
	"/api/actions",
	r#"{"type":"INVT","subject":"@club.test","audienceTag":"m-follower.test"}"#,
);
const POST_TO_NOBODY: Route = Call(
	"POST",
	"/api/actions",
	r#"{"type":"POST","content":"zqm","audienceTag":"zqm-nobody.test"}"#,
);
const REPOST_ALICE: Route = Call(
	"POST",
	"/api/actions",
	r#"{"type":"REPOST","subject":"{obj}","audienceTag":"alice.test"}"#,
);
const REPOST_NO_AUD: Route = Call("POST", "/api/actions", r#"{"type":"REPOST","subject":"{obj}"}"#);
const FLLW_DEL_NOBODY: Route =
	Call("POST", "/api/actions", r#"{"type":"FLLW:DEL","audienceTag":"zqm-nobody.test"}"#);
const CMNT_PARENT: Route =
	Call("POST", "/api/actions", r#"{"type":"CMNT","content":"zqm","parentId":"{obj}"}"#);
const INVT_ROOM: Route = Call(
	"POST",
	"/api/actions",
	r#"{"type":"INVT","subject":"@club.test~closed-w","audienceTag":"m-follower.test"}"#,
);
const APKG_POST: Route = Call(
	"POST",
	"/api/actions",
	r#"{"type":"APKG","content":{"name":"zqm-app","version":"1.0.0"}}"#,
);

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
	// Bus admission: the tenant account's own session only (the bus carries the tenant's
	// traffic). A leader, a member, a visitor, a link or a key is refused.
	("WS-29", "owner@alice", "", WS_BUS, "Allow"),
	("WS-30", "owner@club", "", WS_BUS, "Allow"),
	("WS-31", "m_leader@club", "", WS_BUS, "Deny"),
	("WS-32", "owner-sadm@admin", "", WS_BUS, "Allow"),
	("WS-33", "apikey-unscoped@alice", "", WS_BUS, "Deny"),
	("WS-34", "stranger@alice", "", WS_BUS, "Deny"),
	("WS-35", "follower@alice", "", WS_BUS, "Deny"),
	("WS-36", "connected@alice", "", WS_BUS, "Deny"),
	("WS-37", "m_contributor@club", "", WS_BUS, "Deny"),
	("WS-38", "m_moderator@club", "", WS_BUS, "Deny"),
	("WS-39", "hatted@club", "", WS_BUS, "Deny"),
	("WS-40", "sharelink-r@alice", "", WS_BUS, "Deny"),
	("WS-41", "apikey-dav@alice", "", WS_BUS, "Deny"),
	("WS-42", "apkg-publish@alice", "", WS_BUS, "Deny"),
	("WS-43", "anon@alice", "", WS_BUS, "Deny"),
	("WS-44", "tampered@alice", "", WS_BUS, "Deny"),
	// An `s~` store row is created on first connect only by an unscoped contributor or above;
	// for anyone else the missing row is refused (`store_rows_only_for_creators`).
	("WS-53", "owner@alice", "s~zqm-store-a", WsRtdb(None), "Allow"),
	("WS-54", "m_contributor@club", "s~zqm-store-b", WsRtdb(None), "Allow"),
	("WS-55", "stranger@alice", "s~zqm-store-c", WsRtdb(None), "Deny"),
	("WS-56", "sharelink-w@alice", "s~zqm-store-c", WsRtdb(None), "Deny"),
	("WS-57", "owner-scoped-w@alice", "s~zqm-store-c", WsRtdb(None), "Deny"),
	("WS-58", "owner@alice", "s~", WsRtdb(None), "Deny"),
	// Below contributor is no creator; a hat mapped to contributor is.
	("WS-81", "m_supporter@club", "s~zqm-store-e", WsRtdb(None), "Deny"),
	("WS-82", "hatted@club", "s~zqm-store-f", WsRtdb(None), "Allow"),
	("WS-83", "sharelink-c@alice", "root@alice", WsCrdt(Some("comment")), "Allow@Comment"),
	// Invalid credentials are refused, not dropped to a guest: the Public doc a guest opens.
	("WS-59", "expired@alice", "tenant-crdt-p-active@alice", WsCrdt(None), "Deny"),
	("WS-60", "xtenant-replay@alice", "tenant-crdt-p-active@alice", WsCrdt(None), "Deny"),
	("WS-61", "wrong-iss@alice", "tenant-crdt-p-active@alice", WsCrdt(None), "Deny"),
	("WS-62", "idp-mgmt@alice", "tenant-crdt-p-active@alice", WsCrdt(None), "Deny"),
	("WS-63", "idp-mgmt@club", "tenant-crdt-p-active@club", WsCrdt(None), "Deny"),
	("WS-64", "apikey-xtenant@club", "tenant-crdt-p-active@club", WsCrdt(None), "Deny"),
	("WS-65", "expired@alice", "", WS_BUS, "Deny"),
	("WS-66", "xtenant-replay@alice", "", WS_BUS, "Deny"),
	("WS-67", "wrong-iss@alice", "", WS_BUS, "Deny"),
	("WS-68", "idp-mgmt@alice", "", WS_BUS, "Deny"),
	("WS-69", "idp-mgmt@club", "", WS_BUS, "Deny"),
	("WS-70", "apikey-xtenant@club", "", WS_BUS, "Deny"),
	// A valid token with an unrecognised scope is a guest.
	("WS-71", "scope-foreign@alice", "tenant-crdt-p-active@alice", WsCrdt(None), "Allow@Read"),
	("WS-72", "apikey-file@alice", "", WS_BUS, "Deny"),
	// The bearer in `?token=`, as a browser connects: judged exactly like the header.
	(
		"WS-73",
		"g_write@alice",
		"tenant-crdt-d-active@alice",
		WsQuery(WsKind::Crdt, None),
		"Allow@Write",
	),
	("WS-74", "tampered@alice", "tenant-crdt-p-active@alice", WsQuery(WsKind::Crdt, None), "Deny"),
	// `?access=comment` needs Comment, and caps a writer at it.
	("WS-75", "g_read@alice", "tenant-crdt-d-active@alice", WsCrdt(Some("comment")), "Deny"),
	(
		"WS-76",
		"g_comment@alice",
		"tenant-crdt-d-active@alice",
		WsCrdt(Some("comment")),
		"Allow@Comment",
	),
	(
		"WS-77",
		"g_write@alice",
		"tenant-crdt-d-active@alice",
		WsCrdt(Some("comment")),
		"Allow@Comment",
	),
	// A link's target through `?via=` its root; a folder or a reference has no document here.
	(
		"WS-78",
		"sharelink-r@alice",
		"f1~zqm-alice-linktarget-crdt-d-active?via=f1~zqm-alice-tenant-crdt-d-active",
		WsCrdt(None),
		"Allow@Read",
	),
	("WS-79", "owner@alice", "folder@alice", WsCrdt(None), "Deny"),
	("WS-80", "owner@alice", "mirroredplacer-blob-p-active@alice", WsCrdt(None), "Deny"),
	// `?via=` caps every caller at the link's level, the owner too; a file the source does not
	// link is refused (`file_access.rs` via resolution).
	(
		"WS-93",
		"owner@alice",
		"f1~zqm-alice-linktarget-crdt-d-active?via=f1~zqm-alice-tenant-crdt-d-active",
		WsCrdt(None),
		"Allow@Read",
	),
	(
		"WS-94",
		"owner@alice",
		"f1~zqm-alice-linktarget-crdt-d-active?via=f1~zqm-alice-tenant-blob-d-active",
		WsCrdt(None),
		"Deny",
	),
];

const WS_BUS: Route = Call("GET", "/ws/bus", "");

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
	("SE-16", "owner@alice", "container-p-tenant-active@alice", Subscribe, "Allow"),
	// The outbox is a follower's or a connection's; each peer pulls what it may read.
	("SE-18", "follower@alice", "post-f-tenant-active@alice", Outbox, "Present"),
	("SE-19", "follower@alice", "post-p-tenant-active@alice", Outbox, "Present"),
	("SE-20", "wefollow@alice", "", Outbox, "Deny"),
	("SE-21", "follower@alice", "post-d-tenant-active@alice", Outbox, "Absent"),
	("SE-22", "connected@alice", "post-d-tenant-active@alice", Outbox, "Absent"),
	("SE-23", "follower@alice", "post-c-tenant-active@alice", Outbox, "Absent"),
	("SE-24", "connected@alice", "post-c-tenant-active@alice", Outbox, "Present"),
	("SE-25", "stranger@alice", "", Outbox, "Deny"),
	("SE-26", "connected@alice", "post-f-tenant-active@alice", Outbox, "Present"),
	// A profile by id is behind `require_auth` (no guest path); a tampered token is refused.
	("SE-27", "stranger@alice", "", Get(ALICE_CONN), "Allow"),
	("SE-28", "anon@alice", "", Get(ALICE_CONN), "Deny"),
	("SE-29", "tampered@alice", "", Get(ALICE_CONN), "Deny"),
];

const ADMIN_TENANTS: Route = Call("GET", "/api/admin/tenants", "");
const ADMIN_PROXY: Route = Call("GET", "/api/admin/proxy-sites", "");
const SET_USER: Route = Call("PUT", "/api/settings/file.sync_max_vis", r#"{"value":"md"}"#);
const PROF_SETTINGS: Route = Call("GET", "/api/profiles/m-contributor.test/settings", "");
const PROF_SETTING_PUT: Route =
	Call("PUT", "/api/profiles/m-contributor.test/settings/zqm.k", r#"{"value":1}"#);
const PATCH_FOLLOWER: Route = Call("PATCH", "/api/profiles/follower.test", "{}");
const PUT_COMMUNITY: Route = Call("PUT", "/api/profiles/zqm-new.test", r#"{"type":"community"}"#);
const PUT_COMMUNITY_BAD_REF: Route = Call(
	"PUT",
	"/api/profiles/zqm-new.test",
	r#"{"type":"community","inviteRef":"zqref-unknown"}"#,
);
const REFRESH_UNTRACKED: Route = Call("POST", "/api/profiles/zqm-untracked.test/refresh", "");
const TAGS: Route = Call("GET", "/api/tags", "");
const FORMATS: Route = Call("GET", "/api/doc-formats", "");
const FORMAT_PUT: Route =
	Call("PUT", "/api/doc-formats/zqm%2Fmatrix", r#"{"publisherTag":"zqm.test","appName":"zqm"}"#);
const FORMAT_DEL: Route = Call("DELETE", "/api/doc-formats/zqm%2Fmatrix", "");
const ADDR_BOOKS: Route = Call("GET", "/api/address-books", "");
const CALENDARS: Route = Call("GET", "/api/calendars", "");
const SITES: Route = Call("GET", "/api/sites", "");
const PUSH_SUB: Route = Call("POST", "/api/notifications/subscription", "{}");
const REINDEX: Route = Call("POST", "/api/search/reindex", "");
const API_KEYS: Route = Call("GET", "/api/auth/api-keys", "");
const WA_REG: Route = Call("GET", "/api/auth/wa/reg", "");
const PROXY_TOKEN: Route = Call("GET", "/api/auth/proxy-token", "");
const VAPID: Route = Call("GET", "/api/auth/vapid", "");
const IDP_IDENTITIES: Route = Call("GET", "/api/idp/identities", "");
const SHARES_F: &str = "/api/files/f1~zqm-alice-tenant-blob-d-active/shares";
const SHARES_GET: Route = Call("GET", SHARES_F, "");
const SHARES_POST: Route =
	Call("POST", SHARES_F, r#"{"subjectType":"U","subjectId":"zqm-nobody.test","permission":"R"}"#);
const UNTAG: Route = Call("DELETE", "/api/files/f1~zqm-alice-tenant-blob-d-active/tag/zqm", "");
const REF_SHARE: Route = Call(
	"POST",
	"/api/refs",
	r#"{"type":"share.file","resourceId":"f1~zqm-alice-tenant-blob-d-active","accessLevel":"R"}"#,
);
const REF_WELCOME: Route = Call("POST", "/api/refs", r#"{"type":"welcome"}"#);
const REF_DEL: Route = Call("DELETE", "/api/refs/zqref-alice-r", "");
const ME_PATCH: Route = Call("PATCH", "/api/me", r#"{"x":{"zqm":"1"}}"#);
const IDP_STATUS: Route = Call("GET", "/api/profiles/me/idp-status", "");
const ME_IMAGE: Route = Call("PUT", "/api/me/image", "");
const ME_COVER: Route = Call("PUT", "/api/me/cover", "");
const IDP_RESEND: Route = Call("POST", "/api/profiles/me/resend-activation", "");
const APPS_INSTALLED: Route = Call("GET", "/api/apps/installed", "");
const APPS_INSTALL: Route = Call("POST", "/api/apps/install", "{}");
const REF_FIELDS: Route = Fields("/api/refs/zqref-alice-r", &["resourceId", "accessLevel"]);

/// Management routes: admin, settings writes, profile writes and settings, tags, doc formats,
/// the `require_leader` and `require_tenant_self` groups, session helpers, IdP, file shares and
/// refs. Allow rows run in table order, so a write precedes the delete that clears it.
pub const MG: &[Row] = &[
	// `/api/admin/*`: SADM only.
	("MG-01", "owner-sadm@admin", "", ADMIN_TENANTS, "Allow"),
	("MG-02", "owner@alice", "", ADMIN_TENANTS, "Deny"),
	("MG-03", "m_leader@club", "", ADMIN_TENANTS, "Deny"),
	("MG-04", "apikey-unscoped@alice", "", ADMIN_TENANTS, "Deny"),
	("MG-05", "anon@alice", "", ADMIN_TENANTS, "Deny"),
	("MG-06", "owner-sadm@admin", "", ADMIN_PROXY, "Allow"),
	("MG-07", "owner@alice", "", ADMIN_PROXY, "Deny"),
	("MG-08", "m_leader@club", "", ADMIN_PROXY, "Deny"),
	("MG-09", "apikey-unscoped@alice", "", ADMIN_PROXY, "Deny"),
	("MG-10", "anon@alice", "", ADMIN_PROXY, "Deny"),
	// Settings writes, by permission level: User = the unscoped tenant or leader.
	("MG-11", "owner@alice", "", SET_USER, "Allow"),
	("MG-12", "m_leader@club", "", SET_USER, "Allow"),
	("MG-13", "apikey-unscoped@alice", "", SET_USER, "Allow"),
	("MG-14", "stranger@alice", "", SET_USER, "Deny"),
	("MG-15", "m_contributor@club", "", SET_USER, "Deny"),
	("MG-16", "sharelink-w@alice", "", SET_USER, "Deny"),
	("MG-17", "owner-scoped-w@alice", "", SET_USER, "Deny"),
	("MG-18", "apikey-dav@alice", "", SET_USER, "Deny"),
	(
		"MG-19",
		"owner-sadm@admin",
		"",
		Call("PUT", "/api/settings/auth.session_timeout", r#"{"value":86400}"#),
		"Allow",
	),
	(
		"MG-20",
		"owner@alice",
		"",
		Call("PUT", "/api/settings/auth.session_timeout", r#"{"value":86400}"#),
		"Deny",
	),
	// System level: config file only, even for SADM.
	(
		"MG-21",
		"owner-sadm@admin",
		"",
		Call("PUT", "/api/settings/email.template_dir", r#"{"value":"x"}"#),
		"Deny",
	),
	(
		"MG-22",
		"owner-sadm@admin",
		"",
		Call("PUT", "/api/settings/file.sync_max_vis?level=global", r#"{"value":"md"}"#),
		"Allow",
	),
	(
		"MG-23",
		"owner@alice",
		"",
		Call("PUT", "/api/settings/file.sync_max_vis?level=global", r#"{"value":"md"}"#),
		"Deny",
	),
	// After MG-11 set alice's row.
	(
		"MG-24",
		"owner@alice",
		"",
		Call("DELETE", "/api/settings/file.sync_max_vis?level=tenant", ""),
		"Allow",
	),
	(
		"MG-25",
		"stranger@alice",
		"",
		Call("DELETE", "/api/settings/file.sync_max_vis?level=tenant", ""),
		"Deny",
	),
	// A member's own settings: the member itself (or SADM), not the community's leaders.
	("MG-26", "m_contributor@club", "", PROF_SETTINGS, "Allow"),
	("MG-27", "owner@club", "", PROF_SETTINGS, "Deny"),
	("MG-28", "m_leader@club", "", PROF_SETTINGS, "Deny"),
	("MG-29", "m_moderator@club", "", PROF_SETTINGS, "Deny"),
	("MG-30", "stranger@club", "", PROF_SETTINGS, "Deny"),
	("MG-31", "m_contributor@club", "", PROF_SETTING_PUT, "Allow"),
	("MG-32", "owner@club", "", PROF_SETTING_PUT, "Deny"),
	("MG-33", "m_leader@club", "", PROF_SETTING_PUT, "Deny"),
	("MG-34", "m_moderator@club", "", PROF_SETTING_PUT, "Deny"),
	("MG-35", "stranger@club", "", PROF_SETTING_PUT, "Deny"),
	// Relationship PATCH: the tenant, or a community's leader.
	("MG-36", "owner@alice", "", PATCH_FOLLOWER, "Allow"),
	("MG-37", "stranger@alice", "", PATCH_FOLLOWER, "Deny"),
	("MG-38", "connected@alice", "", PATCH_FOLLOWER, "Deny"),
	("MG-39", "sharelink-w@alice", "", PATCH_FOLLOWER, "Deny"),
	("MG-40", "m_leader@club", "", Call("PATCH", "/api/profiles/m-follower.test", "{}"), "Allow"),
	(
		"MG-41",
		"m_contributor@club",
		"",
		Call("PATCH", "/api/profiles/m-follower.test", "{}"),
		"Deny",
	),
	// Community creation needs an invite or SADM; refused before any write either way.
	("MG-42", "sharelink-w@alice", "", PUT_COMMUNITY, "Deny"),
	("MG-43", "owner@alice", "", PUT_COMMUNITY_BAD_REF, "Deny"),
	// Pinned: any authenticated caller may refresh; an untracked profile is 404.
	("MG-44", "owner@alice", "", REFRESH_UNTRACKED, "Deny"),
	("MG-45", "anon@alice", "", REFRESH_UNTRACKED, "Deny"),
	// Pinned known exception: any authenticated caller lists the tenant's tags.
	("MG-46", "stranger@alice", "", TAGS, "Allow"),
	("MG-47", "owner@alice", "", TAGS, "Allow"),
	("MG-48", "anon@alice", "", TAGS, "Deny"),
	// Doc formats.
	("MG-49", "owner@alice", "", FORMATS, "Allow"),
	("MG-50", "m_leader@club", "", FORMATS, "Allow"),
	("MG-51", "m_contributor@club", "", FORMATS, "Deny"),
	("MG-52", "stranger@alice", "", FORMATS, "Deny"),
	("MG-53", "owner@alice", "", FORMAT_PUT, "Allow"),
	("MG-54", "m_leader@club", "", FORMAT_PUT, "Deny"),
	("MG-55", "sharelink-w@alice", "", FORMAT_PUT, "Deny"),
	("MG-56", "owner@alice", "", FORMAT_DEL, "Allow"),
	// The `require_leader` group (PIM, push, reindex, sites); a DAV key reaches PIM only.
	("MG-57", "owner@alice", "", ADDR_BOOKS, "Allow"),
	("MG-58", "m_leader@club", "", ADDR_BOOKS, "Allow"),
	("MG-59", "apikey-dav@alice", "", ADDR_BOOKS, "Allow"),
	("MG-60", "m_contributor@club", "", ADDR_BOOKS, "Deny"),
	("MG-61", "stranger@alice", "", ADDR_BOOKS, "Deny"),
	("MG-62", "sharelink-r@alice", "", ADDR_BOOKS, "Deny"),
	("MG-63", "apkg-publish@alice", "", ADDR_BOOKS, "Deny"),
	("MG-64", "owner@alice", "", CALENDARS, "Allow"),
	("MG-65", "m_leader@club", "", CALENDARS, "Allow"),
	("MG-66", "apikey-dav@alice", "", CALENDARS, "Allow"),
	("MG-67", "m_contributor@club", "", CALENDARS, "Deny"),
	("MG-68", "stranger@alice", "", CALENDARS, "Deny"),
	("MG-69", "sharelink-r@alice", "", CALENDARS, "Deny"),
	("MG-70", "apkg-publish@alice", "", CALENDARS, "Deny"),
	("MG-71", "owner@alice", "", SITES, "Allow"),
	("MG-72", "m_leader@club", "", SITES, "Allow"),
	("MG-73", "m_contributor@club", "", SITES, "Deny"),
	("MG-74", "stranger@alice", "", SITES, "Deny"),
	("MG-75", "sharelink-r@alice", "", SITES, "Deny"),
	("MG-76", "apkg-publish@alice", "", SITES, "Deny"),
	("MG-77", "apikey-dav@alice", "", SITES, "Deny"),
	// An empty subscription fails after the gate.
	("MG-78", "owner@alice", "", PUSH_SUB, "Allow*"),
	("MG-79", "m_leader@club", "", PUSH_SUB, "Allow*"),
	("MG-80", "m_contributor@club", "", PUSH_SUB, "Deny"),
	("MG-81", "stranger@alice", "", PUSH_SUB, "Deny"),
	("MG-82", "sharelink-r@alice", "", PUSH_SUB, "Deny"),
	("MG-83", "apkg-publish@alice", "", PUSH_SUB, "Deny"),
	("MG-84", "m_contributor@club", "", REINDEX, "Deny"),
	("MG-85", "stranger@alice", "", REINDEX, "Deny"),
	("MG-86", "sharelink-r@alice", "", REINDEX, "Deny"),
	("MG-87", "apkg-publish@alice", "", REINDEX, "Deny"),
	// The account's own credentials (`require_tenant_self`): not a leader, not scoped.
	("MG-88", "owner@alice", "", API_KEYS, "Allow"),
	("MG-89", "owner@club", "", API_KEYS, "Allow"),
	("MG-90", "apikey-unscoped@alice", "", API_KEYS, "Allow"),
	("MG-91", "m_leader@club", "", API_KEYS, "Deny"),
	("MG-92", "stranger@alice", "", API_KEYS, "Deny"),
	("MG-93", "sharelink-r@alice", "", API_KEYS, "Deny"),
	("MG-94", "owner-scoped-r@alice", "", API_KEYS, "Deny"),
	("MG-95", "apikey-dav@alice", "", API_KEYS, "Deny"),
	("MG-96", "owner@alice", "", WA_REG, "Allow"),
	("MG-97", "owner@club", "", WA_REG, "Allow"),
	("MG-98", "apikey-unscoped@alice", "", WA_REG, "Allow"),
	("MG-99", "m_leader@club", "", WA_REG, "Deny"),
	("MG-100", "stranger@alice", "", WA_REG, "Deny"),
	("MG-101", "sharelink-r@alice", "", WA_REG, "Deny"),
	("MG-102", "owner-scoped-r@alice", "", WA_REG, "Deny"),
	("MG-103", "apikey-dav@alice", "", WA_REG, "Deny"),
	// Session helpers: any session, not a scoped one.
	("MG-104", "stranger@alice", "", PROXY_TOKEN, "Allow"),
	("MG-105", "owner@alice", "", PROXY_TOKEN, "Allow"),
	("MG-106", "owner-scoped-r@alice", "", PROXY_TOKEN, "Deny"),
	("MG-107", "anon@alice", "", PROXY_TOKEN, "Deny"),
	("MG-108", "stranger@alice", "", VAPID, "Allow"),
	("MG-109", "owner@alice", "", VAPID, "Allow"),
	("MG-110", "anon@alice", "", VAPID, "Deny"),
	// IdP management with `idp.enabled` off: even the owner gets 404. The enabled state is
	// `management_flows::idp_management`.
	("MG-111", "owner@alice", "", IDP_IDENTITIES, "Deny"),
	("MG-112", "anon@alice", "", IDP_IDENTITIES, "Deny"),
	("MG-113", "sharelink-r@alice", "", IDP_IDENTITIES, "Deny"),
	// A file's shares: listed from Write, created from Admin.
	("MG-114", "g_write@alice", "", SHARES_GET, "Allow"),
	("MG-115", "g_admin@alice", "", SHARES_GET, "Allow"),
	("MG-116", "g_read@alice", "", SHARES_GET, "Deny"),
	("MG-117", "stranger@alice", "", SHARES_GET, "Deny"),
	("MG-118", "g_admin@alice", "", SHARES_POST, "Allow"),
	("MG-119", "g_write@alice", "", SHARES_POST, "Deny"),
	("MG-120", "g_read@alice", "", SHARES_POST, "Deny"),
	// Untagging needs Write (FC-10 for tagging).
	("MG-121", "g_comment@alice", "", UNTAG, "Deny"),
	("MG-122", "stranger@alice", "", UNTAG, "Deny"),
	// Refs: a share link is the tenant's to mint; `welcome` is SADM's.
	("MG-123", "owner@alice", "", REF_SHARE, "Allow"),
	("MG-124", "g_write@alice", "", REF_SHARE, "Deny"),
	("MG-125", "sharelink-w@alice", "", REF_SHARE, "Deny"),
	("MG-126", "owner@alice", "", REF_WELCOME, "Deny"),
	("MG-127", "stranger@alice", "", REF_DEL, "Deny"),
	// Pinned: an anonymous ref read is reduced, an authenticated one gets full details.
	("MG-128", "anon@alice", "", REF_FIELDS, "Clean"),
	("MG-129", "stranger@alice", "", REF_FIELDS, "Leak:resourceId"),
	// `/api/me` writes edit the tenant's record: its owner or an unscoped community leader.
	("MG-130", "owner@alice", "", ME_PATCH, "Allow"),
	("MG-131", "owner@club", "", ME_PATCH, "Allow"),
	("MG-132", "m_leader@club", "", ME_PATCH, "Allow"),
	("MG-133", "stranger@alice", "", ME_PATCH, "Deny"),
	("MG-134", "follower@alice", "", ME_PATCH, "Deny"),
	("MG-135", "connected@alice", "", ME_PATCH, "Deny"),
	("MG-136", "m_contributor@club", "", ME_PATCH, "Deny"),
	("MG-137", "hatted@club", "", ME_PATCH, "Deny"),
	("MG-138", "sharelink-w@alice", "", ME_PATCH, "Deny"),
	("MG-139", "owner-scoped-w@alice", "", ME_PATCH, "Deny"),
	("MG-140", "idp-mgmt@alice", "", ME_PATCH, "Deny"),
	("MG-141", "anon@alice", "", ME_PATCH, "Deny"),
	// An empty image is refused after the gate (400).
	("MG-142", "owner@alice", "", ME_IMAGE, "Allow*"),
	("MG-143", "m_leader@club", "", ME_IMAGE, "Allow*"),
	("MG-144", "m_contributor@club", "", ME_IMAGE, "Deny"),
	("MG-145", "stranger@alice", "", ME_IMAGE, "Deny"),
	("MG-146", "sharelink-w@alice", "", ME_IMAGE, "Deny"),
	("MG-147", "idp-mgmt@alice", "", ME_IMAGE, "Deny"),
	("MG-148", "apkg-publish@alice", "", ME_IMAGE, "Deny"),
	("MG-149", "follower@alice", "", ME_IMAGE, "Deny"),
	("MG-150", "anon@alice", "", ME_IMAGE, "Deny"),
	("MG-151", "owner@alice", "", ME_COVER, "Allow*"),
	("MG-152", "m_leader@club", "", ME_COVER, "Allow*"),
	("MG-153", "m_contributor@club", "", ME_COVER, "Deny"),
	("MG-154", "stranger@alice", "", ME_COVER, "Deny"),
	("MG-155", "sharelink-w@alice", "", ME_COVER, "Deny"),
	("MG-156", "idp-mgmt@alice", "", ME_COVER, "Deny"),
	("MG-157", "apkg-publish@alice", "", ME_COVER, "Deny"),
	("MG-158", "follower@alice", "", ME_COVER, "Deny"),
	("MG-159", "anon@alice", "", ME_COVER, "Deny"),
	// The tenant's IdP status: the account itself or an unscoped leader.
	("MG-160", "owner@alice", "", IDP_STATUS, "Allow*"),
	("MG-161", "sharelink-r@alice", "", IDP_STATUS, "Deny"),
	("MG-162", "m_contributor@club", "", IDP_STATUS, "Deny"),
	("MG-163", "m_leader@club", "", IDP_STATUS, "Allow*"),
	("MG-164", "stranger@alice", "", IDP_STATUS, "Deny"),
	("MG-165", "follower@alice", "", IDP_STATUS, "Deny"),
	("MG-166", "idp-mgmt@alice", "", IDP_STATUS, "Deny"),
	("MG-167", "apkg-publish@alice", "", IDP_STATUS, "Deny"),
	("MG-168", "anon@alice", "", IDP_STATUS, "Deny"),
	("MG-169", "g_read@alice", "", IDP_STATUS, "Deny"),
	// Resending the IdP activation mail: same gate; without an IdP it fails after the gate.
	("MG-170", "owner@alice", "", IDP_RESEND, "Allow*"),
	("MG-171", "m_contributor@club", "", IDP_RESEND, "Deny"),
	("MG-172", "stranger@alice", "", IDP_RESEND, "Deny"),
	("MG-173", "sharelink-w@alice", "", IDP_RESEND, "Deny"),
	("MG-174", "idp-mgmt@alice", "", IDP_RESEND, "Deny"),
	("MG-175", "anon@alice", "", IDP_RESEND, "Deny"),
	// App management: an unscoped leader; `apkg:publish` publishes, it does not install.
	("MG-176", "owner@alice", "", APPS_INSTALLED, "Allow"),
	("MG-177", "m_leader@club", "", APPS_INSTALLED, "Allow"),
	("MG-178", "m_contributor@club", "", APPS_INSTALLED, "Deny"),
	("MG-179", "m_moderator@club", "", APPS_INSTALLED, "Deny"),
	("MG-180", "stranger@club", "", APPS_INSTALLED, "Deny"),
	("MG-181", "apkg-publish@alice", "", APPS_INSTALLED, "Deny"),
	("MG-182", "sharelink-w@alice", "", APPS_INSTALLED, "Deny"),
	("MG-183", "anon@alice", "", APPS_INSTALLED, "Deny"),
	// An empty install request fails after the gate.
	("MG-184", "owner@alice", "", APPS_INSTALL, "Allow*"),
	("MG-185", "m_contributor@club", "", APPS_INSTALL, "Deny"),
	("MG-186", "apkg-publish@alice", "", APPS_INSTALL, "Deny"),
	// Signed as the tenant: an APRV is moderator+, a follow or connection request leader+.
	("MG-187", "m_contributor@club", APRV_TARGET, APRV, "Deny"),
	("MG-188", "m_contributor@club", "", FLLW_NOBODY, "Deny"),
	("MG-189", "m_contributor@club", "", CONN_NOBODY, "Deny"),
	("MG-190", "m_contributor@club", "", CONN_UPD_NOBODY, "Deny"),
	("MG-191", "hatted@club", APRV_TARGET, APRV, "Deny"),
	("MG-192", "hatted@club", "", FLLW_NOBODY, "Deny"),
	("MG-193", "m_moderator@club", APRV_TARGET, APRV, "Allow*"),
	("MG-194", "m_moderator@club", "", FLLW_NOBODY, "Deny"),
	("MG-195", "m_moderator@club", "", CONN_NOBODY, "Deny"),
	("MG-196", "m_moderator@club", "", CONN_UPD_NOBODY, "Deny"),
	("MG-197", "m_leader@club", APRV_TARGET, APRV, "Allow*"),
	("MG-198", "m_leader@club", "", FLLW_NOBODY, "Allow*"),
	("MG-199", "m_leader@club", "", CONN_NOBODY, "Allow*"),
	("MG-200", "owner@alice", "", FLLW_NOBODY, "Allow*"),
	// A draft goes through the same gate.
	("MG-201", "m_contributor@club", APRV_TARGET, APRV_DRAFT, "Deny"),
	// `/api/profiles/batch` skips the scope gate (public data only), never validity.
	("MG-202", "sharelink-r@alice", "", BATCH, "Allow"),
	("MG-203", "apkg-publish@alice", "", BATCH, "Allow"),
	("MG-204", "apikey-dav@alice", "", BATCH, "Allow"),
	("MG-205", "owner@alice", "", BATCH, "Allow"),
	("MG-206", "anon@alice", "", BATCH, "Deny"),
	("MG-207", "tampered@alice", "", BATCH, "Deny"),
	("MG-208", "expired@alice", "", BATCH, "Deny"),
	("MG-209", "xtenant-replay@alice", "", BATCH, "Deny"),
	("MG-210", "wrong-iss@alice", "", BATCH, "Deny"),
	("MG-211", "idp-mgmt@alice", "", BATCH, "Deny"),
	("MG-212", "apikey-xtenant@club", "", BATCH, "Deny"),
	("MG-213", "sharelink-r@alice", "", Fields(BATCH_URI, PROFILE_PRIVATE), "Clean"),
	// The two admin listings for the credentials [`ADMIN_DENIED`] adds to MG-01..10.
	("MG-225a", "owner-scoped-r@alice", "", ADMIN_TENANTS, "Deny"),
	("MG-225b", "sadm-scoped@admin", "", ADMIN_TENANTS, "Deny"),
	("MG-226a", "owner-scoped-r@alice", "", ADMIN_PROXY, "Deny"),
	("MG-226b", "sadm-scoped@admin", "", ADMIN_PROXY, "Deny"),
	// Another tenant's settings are SADM's alone, at every level.
	("MG-227", "owner@alice", "", Get("/api/settings/file.sync_max_vis?tenant=club.test"), "Deny"),
	(
		"MG-228",
		"owner@alice",
		"",
		Call("PUT", "/api/settings/file.sync_max_vis?tenant=club.test", r#"{"value":"md"}"#),
		"Deny",
	),
	(
		"MG-229",
		"owner@alice",
		"",
		Call("DELETE", "/api/settings/file.sync_max_vis?level=tenant&tenant=club.test", ""),
		"Deny",
	),
	(
		"MG-230",
		"m_leader@club",
		"",
		Get("/api/settings/file.sync_max_vis?tenant=alice.test"),
		"Deny",
	),
	(
		"MG-231",
		"owner-sadm@admin",
		"",
		Get("/api/settings/file.sync_max_vis?tenant=club.test"),
		"Allow",
	),
	// The raw global row of a Global-scoped key, and any global listing, are SADM's.
	(
		"MG-232",
		"owner@alice",
		"",
		Get("/api/settings/server.registration_enabled?level=global"),
		"Deny",
	),
	("MG-233", "owner@alice", "", Get("/api/settings?prefix=file&level=global"), "Deny"),
	// Clearing a row needs the key's write level: Admin is SADM's, System nobody's.
	(
		"MG-234",
		"owner@alice",
		"",
		Call("DELETE", "/api/settings/federation.history_sync.since_days?level=tenant", ""),
		"Deny",
	),
	(
		"MG-235",
		"owner-sadm@admin",
		"",
		Call("DELETE", "/api/settings/email.template_dir?level=global", ""),
		"Deny",
	),
	// A member's own settings need a role above `follower`; a hat's mapped role is one.
	("MG-236", "m_follower@club", "", Get("/api/profiles/m-follower.test/settings"), "Deny"),
	("MG-237", "hatted@club", "", Get("/api/profiles/hatted.test/settings"), "Allow"),
	// `apkg:publish` creates APKG actions and uploads packages, nothing else.
	("MG-238", "apkg-publish@alice", "", POST_ZQM, "Deny"),
	(
		"MG-239",
		"apkg-publish@alice",
		"",
		Call("POST", "/api/actions", r#"{"type":"APKG"}"#),
		"Allow*",
	),
	// A parent needs Write through the caller's own grant; the scope holds none on files.
	(
		"MG-240",
		"apkg-publish@alice",
		"folder@alice",
		Call("POST", "/api/files/apkg/zqm.apkg?parentId={obj}", ""),
		"Deny",
	),
	// A federated proxy token is the tenant vouching: owner or leader; a bad hat is refused.
	("MG-241", "stranger@alice", "", Get("/api/auth/proxy-token?idTag=peer.test"), "Deny"),
	("MG-242", "m_contributor@club", "", Get("/api/auth/proxy-token?idTag=peer.test"), "Deny"),
	("MG-243", "owner@alice", "", Get("/api/auth/proxy-token?hat=!!bad"), "400"),
	// A DAV key reaches its own capability only: read-only CardDAV writes and reads no calendar.
	("MG-244", "apikey-carddav-r@alice", "", Call("POST", "/api/address-books", "{}"), "Deny"),
	("MG-245", "apikey-carddav-r@alice", "", CALENDARS, "Deny"),
	("MG-246", "apikey-dav@alice", "", Get("/api/contacts"), "Allow"),
	// Writes to the account's own credentials (MG-88..103 for reads).
	("MG-247", "m_leader@club", "", Call("POST", "/api/auth/api-keys", "{}"), "Deny"),
	// Vacuous: no passkey is seeded, so a missing-row 404 passes as Deny too.
	("MG-248", "m_leader@club", "", Call("DELETE", "/api/auth/wa/reg/zqm", ""), "Deny"),
	// Only `share.file` is a client's to mint; every other type is SADM's.
	("MG-249", "m_leader@club", "", Call("POST", "/api/refs", r#"{"type":"password"}"#), "Deny"),
	("MG-250", "owner@alice", "", REF_REGISTER, "Deny"),
	("MG-251", "owner-sadm@admin", "", REF_REGISTER, "Allow*"),
	(
		"MG-252",
		"stranger@alice",
		"",
		Call("PATCH", "/api/refs/zqref-alice-r", r#"{"description":"zqm"}"#),
		"Deny",
	),
	// Session helpers: a password change verifies the caller's own account; onboarding retires
	// only the caller's tenant's welcome ref (`ONBOARD_REF`, seeded on club).
	(
		"MG-253",
		"stranger@alice",
		"",
		Call(
			"POST",
			"/api/auth/password",
			r#"{"currentPassword":"zqm-cur-0","newPassword":"zqm-new-0000"}"#,
		),
		"Deny",
	),
	(
		"MG-254",
		"owner@alice",
		"",
		Call("POST", "/api/onboarding/complete", r#"{"refId":"zqref-club-welcome"}"#),
		"Deny",
	),
	// Doc formats are the tenant account's; a claim another app holds (`zqm/held`, seeded on
	// both tenants) is not the owner's to take.
	("MG-255", "m_leader@club", "", FORMAT_HELD_DEL, "Deny"),
	("MG-256", "stranger@alice", "", FORMAT_HELD_DEL, "Deny"),
	(
		"MG-257",
		"owner@alice",
		"",
		Call(
			"PUT",
			"/api/doc-formats/zqm%2Fheld",
			r#"{"publisherTag":"zqm.test","appName":"zqm"}"#,
		),
		"Deny",
	),
	("MG-258", "owner@alice", "", REINDEX, "Allow*"),
	("MG-259", "m_leader@club", "", REINDEX, "Allow*"),
	("MG-260", "sharelink-r@alice", "", TAGS, "Deny"),
	// `/api/me/full` sections by tier: `zqmconn` is seeded `connected`.
	("MG-261", "anon@alice", "", ME_FULL, "Clean"),
	("MG-262", "stranger@alice", "", ME_FULL, "Clean"),
	("MG-263", "connected@alice", "", ME_FULL, "Leak:x.zqmconn"),
	("MG-264", "owner@alice", "", ME_FULL, "Leak:x.zqmconn"),
	// Pinned: the installed-app listing is public (the managing `/api/apps/installed` is not).
	("MG-265", "anon@alice", "", Get("/api/apps"), "Allow"),
	// Ref edits and revocation: the named file's share managers (MG-252 for a stranger).
	("MG-266", "g_write@alice", "", REF_PATCH_W, "Deny"),
	("MG-267", "sharelink-w@alice", "", REF_PATCH_W, "Deny"),
	(
		"MG-268",
		"owner@alice",
		"",
		Call("PATCH", "/api/refs/zqref-alice-r", r#"{"accessLevel":"admin"}"#),
		"400",
	),
	("MG-269", "g_write@alice", "", REF_DEL, "Deny"),
	("MG-270", "sharelink-w@alice", "", REF_DEL, "Deny"),
	("MG-271", "owner-scoped-w@alice", "", REF_DEL, "Deny"),
	("MG-272", "owner@alice", "", Call("DELETE", "/api/refs/zqref-alice-del", ""), "Allow"),
	// Minting a link is re-sharing: a leader on a local community row, never on a mirror.
	("MG-273", "m_leader@club", "memberowned-blob-d-active@club", REF_SHARE_OBJ, "Allow"),
	("MG-274", "m_leader@club", "mirroredplacer-blob-p-active@club", REF_SHARE_OBJ, "Deny"),
	("MG-275", "sharelink-a@alice", "root@alice", REF_SHARE_OBJ, "Deny"),
	(
		"MG-276",
		"owner@alice",
		"",
		Call(
			"POST",
			"/api/refs",
			r#"{"type":"share.file","resourceId":"f1~zqm-alice-tenant-blob-d-active","accessLevel":"admin"}"#,
		),
		"400",
	),
	// A share link is no account ref: nothing to re-send.
	(
		"MG-277",
		"anon@alice",
		"",
		Call("POST", "/api/refs/zqref-alice-r/resend-activation", ""),
		"400",
	),
	// Creating a file's shares: its managers; a scoped credential never; `A` is for users only.
	("MG-278", "sharelink-a@alice", "root@alice", Call("POST", SHARES_OBJ, SHARE_U), "Deny"),
	("MG-279", "owner-scoped-w@alice", "root@alice", Call("POST", SHARES_OBJ, SHARE_U), "Deny"),
	(
		"MG-280",
		"m_leader@club",
		"memberowned-blob-d-active@club",
		Call("POST", SHARES_OBJ, SHARE_U),
		"Allow",
	),
	(
		"MG-281",
		"m_leader@club",
		"mirroredplacer-blob-p-active@club",
		Call("POST", SHARES_OBJ, SHARE_U),
		"Deny",
	),
	(
		"MG-282",
		"m_contributor@club",
		"memberowned-blob-d-active@club",
		Call(
			"POST",
			SHARES_OBJ,
			r#"{"subjectType":"U","subjectId":"zqm-c.test","permission":"R"}"#,
		),
		"Allow",
	),
	(
		"MG-283",
		"owner@alice",
		"tenant-blob-d-active@alice",
		Call("POST", SHARES_OBJ, r#"{"subjectType":"L","subjectId":"zqm","permission":"A"}"#),
		"400",
	),
	(
		"MG-284",
		"owner@alice",
		"tenant-blob-d-active@alice",
		Call(
			"POST",
			SHARES_OBJ,
			r#"{"subjectType":"F","subjectId":"f1~zqm-alice-tenant-crdt-d-active","permission":"A"}"#,
		),
		"400",
	),
	// A BLOB upload needs create rights and Write on its parent, inside a scope's tree, into an
	// enterable room, never under the trash.
	("MG-285", "stranger@club", "folder@club", FileUpload, "Deny"),
	("MG-286", "m_supporter@club", "folder@club", FileUpload, "Deny"),
	("MG-287", "m_contributor@club", "folder@club", FileUpload, "Allow"),
	("MG-288", "sharelink-w@alice", "folder@alice", FileUpload, "Deny"),
	(
		"MG-289",
		"m_moderator@club",
		"",
		Call("POST", "/api/files/file/zqm-chan.txt?channel=@club.test~closed-w", "zqm"),
		"Deny",
	),
	("MG-290", "owner@alice", "folder-blob-p-trashed@alice", FileUpload, "Deny"),
	// A scope's write is the document's, not the record's: no delete, no restore.
	("MG-291", "sharelink-w@alice", "root@alice", FileDelete, "Deny"),
	("MG-292", "owner-scoped-w@alice", "root@alice", FileDelete, "Deny"),
	("MG-293", "owner-scoped-w@alice", "tenant-blob-p-trashed@alice", FileRestore, "Deny"),
	// Posting as the tenant: its unscoped account; no link, capability key or `idp_` key
	// (`apkg:publish`: MG-238).
	("MG-294", "apikey-unscoped@alice", "", POST_ZQM, "Allow*"),
	("MG-295", "sharelink-w@alice", "", POST_ZQM, "Deny"),
	("MG-296", "apikey-dav@alice", "", POST_ZQM, "Deny"),
	("MG-297", "idp-key@alice", "", POST_ZQM, "Deny"),
	("MG-298", "idp-mgmt@alice", "", POST_ZQM, "Deny"),
	// A community invitation is a moderator's; its revocation the inviter's or a moderator's;
	// an unknown subtype nobody's.
	("MG-299", "m_contributor@club", "", INVT_CLUB, "Deny"),
	// `zqm-invitee.test` is unknown to club and INVT is not `allow_unknown`: 400 past the gate
	// (`task.rs` outbound `allow_unknown`); AC-87 is the live Allow.
	("MG-300", "m_moderator@club", "", INVT_CLUB, "400"),
	(
		"MG-301",
		"m_contributor@club",
		"",
		Call(
			"POST",
			"/api/actions",
			r#"{"type":"INVT:DEL","subject":"@club.test","audienceTag":"zqm-invitee.test"}"#,
		),
		"Deny",
	),
	(
		"MG-302",
		"m_moderator@club",
		"",
		Call(
			"POST",
			"/api/actions",
			r#"{"type":"INVT:FOO","subject":"@club.test","audienceTag":"zqm-invitee.test"}"#,
		),
		"Deny",
	),
	// Pinned, open gap: a bearer in `?token=` is accepted on every authenticated route.
	("MG-303", "owner@alice", "", GetQ("/api/settings"), "Allow"),
	// A non-Bearer `Authorization` is refused where auth is required, and is no credential at
	// all where it is optional (an anonymous listing).
	("MG-304", "anon@alice", "", CallBasic("GET", "/api/settings", ""), "Deny"),
	("MG-305", "anon@alice", "", CallBasic("GET", "/api/files", ""), "Allow"),
	// Accepting a join request is a moderator's, in either subtype form; a removal in the
	// `subType` form meets the same hierarchy guard. Refused before any target lookup.
	("MG-306", "m_contributor@club", "", CONN_ACC_NOBODY, "Deny"),
	(
		"MG-307",
		"m_contributor@club",
		"",
		Call(
			"POST",
			"/api/actions",
			r#"{"type":"CONN","subType":"DEL","audienceTag":"zqm-nobody.test"}"#,
		),
		"Deny",
	),
	// A welcome ref is bound to its own tenant's host (`zqref-alice-welcome`, seeded by the
	// layer): alice is not IdP-gated, so on her host status is a synthetic 200 and resend 400.
	("MG-308", "anon@club", "", REF_IDP_STATUS, "Deny"),
	("MG-309", "anon@club", "", REF_IDP_RESEND, "Deny"),
	("MG-310", "anon@alice", "", REF_IDP_STATUS, "Allow"),
	("MG-311", "anon@alice", "", REF_IDP_RESEND, "400"),
	(
		"MG-312",
		"anon@club",
		"",
		Call(
			"POST",
			"/api/auth/set-password",
			r#"{"refId":"zqref-alice-welcome","newPassword":"zqm-new-0000"}"#,
		),
		"Deny",
	),
	// SADM reads the admin surface it alone may change (MG-214..224 deny it to everyone else).
	("MG-313", "owner-sadm@admin", "", Get("/api/admin/cert-status"), "Allow"),
	("MG-314", "owner-sadm@admin", "", Get("/api/admin/proxy-sites/1"), "Allow"),
	// The account's own credentials: a leader never manages its community's keys or passkeys
	// (MG-247 for creating one); the owner reads its own (MG-315..320 deny the rest).
	("MG-321", "m_leader@club", "", Get("/api/auth/api-keys/6"), "Deny"),
	(
		"MG-322",
		"m_leader@club",
		"",
		Call("PATCH", "/api/auth/api-keys/6", r#"{"name":"zqm"}"#),
		"Deny",
	),
	("MG-323", "m_leader@club", "", Call("DELETE", "/api/auth/api-keys/6", ""), "Deny"),
	("MG-324", "m_leader@club", "", Call("POST", "/api/auth/wa/reg", "{}"), "Deny"),
	("MG-325", "m_leader@club", "", Get("/api/auth/wa/reg/challenge"), "Deny"),
	("MG-326", "owner@alice", "", Get("/api/auth/api-keys/1"), "Allow"),
	("MG-327", "owner@alice", "", Get("/api/auth/wa/reg/challenge"), "Allow"),
	("MG-328", "owner@club", "", Get("/api/auth/api-keys/6"), "Allow"),
	// More of the `require_leader` group. The layer runs before the handler: a contributor's
	// 403 against the leader's 400 on a non-numeric id is not a missing-row 404.
	("MG-329", "m_contributor@club", "", SITES_PATCH, "Deny"),
	("MG-330", "m_leader@club", "", SITES_PATCH, "Allow*"),
	("MG-331", "m_contributor@club", "", Get("/api/sites/pages"), "Deny"),
	("MG-332", "m_leader@club", "", Get("/api/sites/pages"), "Allow*"),
	("MG-333", "m_contributor@club", "", SITES_PUBLISH, "Deny"),
	("MG-334", "m_leader@club", "", SITES_PUBLISH, "Allow*"),
	("MG-335", "m_contributor@club", "", AB_PATCH, "Deny"),
	("MG-336", "m_leader@club", "", AB_PATCH, "400"),
	("MG-337", "m_contributor@club", "", CAL_PATCH, "Deny"),
	("MG-338", "m_leader@club", "", CAL_PATCH, "400"),
	("MG-339", "m_contributor@club", "", PUSH_SUB_DEL, "Deny"),
	("MG-340", "m_leader@club", "", PUSH_SUB_DEL, "400"),
	("MG-341", "m_contributor@club", "", Get("/api/contacts"), "Deny"),
	("MG-342", "stranger@alice", "", Get("/api/contacts"), "Deny"),
	// A member's single setting, as MG-26..35 (after MG-31 wrote it); SADM writes and reads any.
	("MG-343", "m_contributor@club", "", PROF_SETTING_GET, "Allow"),
	("MG-344", "m_moderator@club", "", PROF_SETTING_GET, "Deny"),
	("MG-345", "m_follower@club", "", PROF_SETTING_GET, "Deny"),
	(
		"MG-346",
		"owner-sadm@admin",
		"",
		Call("PUT", "/api/profiles/zqm-sadm.test/settings/zqm.k", r#"{"value":1}"#),
		"Allow",
	),
	("MG-347", "owner-sadm@admin", "", Get("/api/profiles/zqm-sadm.test/settings/zqm.k"), "Allow"),
	(
		"MG-348",
		"owner-scoped-w@alice",
		"",
		Call("DELETE", "/api/settings/file.sync_max_vis?level=tenant", ""),
		"Deny",
	),
	// Shares and refs need an authenticated manager; the owner edits a ref of its own.
	("MG-349", "anon@alice", "", SHARES_POST, "Deny"),
	(
		"MG-350",
		"owner@alice",
		"",
		Call("PATCH", "/api/refs/zqref-alice-patch", r#"{"description":"zqm"}"#),
		"Allow",
	),
	("MG-351", "anon@alice", "", REF_DEL, "Deny"),
	// `/api/me/full`: a link or a follower sees no owner-tier section (MG-261..264).
	("MG-352", "sharelink-r@alice", "", ME_FULL, "Clean"),
	("MG-353", "follower@alice", "", ME_FULL, "Clean"),
	// A CONN with an empty or unknown subtype is a request in disguise: leader+, not open.
	("MG-354", "m_contributor@club", "", CONN_EMPTY_SUB, "Deny"),
	("MG-355", "m_contributor@club", "", CONN_XYZ_SUB, "Deny"),
	("MG-356", "m_moderator@club", "", CONN_EMPTY_SUB, "Deny"),
	("MG-357", "m_moderator@club", "", CONN_XYZ_SUB, "Deny"),
	("MG-358", "m_leader@club", "", CONN_EMPTY_SUB, "Allow*"),
	("MG-359", "m_leader@club", "", CONN_XYZ_SUB, "Allow*"),
	// The subtype in `type` and in `subType` must agree; the gate reads one, the pipeline both.
	(
		"MG-360",
		"m_leader@club",
		"",
		Call(
			"POST",
			"/api/actions",
			r#"{"type":"CONN:DEL","subType":"ACC","audienceTag":"zqm-nobody.test"}"#,
		),
		"400",
	),
	// DAV takes a `cl_` key as the Basic password, on its own tenant only.
	("MG-361", "apikey-dav@alice", "", CallBasic("GET", DAV_PRINCIPAL, ""), "Allow*"),
	("MG-362", "apikey-xtenant@club", "", CallBasic("GET", DAV_PRINCIPAL, ""), "Deny"),
	("MG-363", "apikey-dav@club", "", CallBasic("GET", DAV_PRINCIPAL, ""), "Deny"),
	// Past the gate: SADM creating a profile of an unknown type is a validation error.
	("MG-364", "owner-sadm@admin", "", PUT_ZQM_TYPE, "400"),
	("MG-365", "owner@alice", "cur-tag-gwrite@alice", Call("DELETE", UNTAG_OBJ, ""), "Allow"),
	("MG-366", "owner@alice", "", REFRESH_CONNECTED, "Allow*"),
	// A proxy token to another node is the account's or a leader's.
	("MG-367", "owner@alice", "", PROXY_TO_PEER, "Allow*"),
	("MG-368", "m_leader@club", "", PROXY_TO_PEER, "Allow*"),
	("MG-369", "m_contributor@club", "", PROXY_TO_PEER, "Deny"),
	// A read capability writes nothing.
	("MG-370", "apikey-carddav-r@alice", "", AB_CONTACT_POST, "Deny"),
	("MG-371", "apikey-dav@alice", "", CAL_OBJECT_POST, "Deny"),
	// Site mounts and rollback are a leader's.
	("MG-372", "m_contributor@club", "", SITE_MOUNT, "Deny"),
	("MG-373", "m_contributor@club", "", SITE_UNMOUNT, "Deny"),
	("MG-374", "m_contributor@club", "", SITE_ROLLBACK, "Deny"),
	("MG-375", "m_leader@club", "", SITE_MOUNT, "Allow*"),
	("MG-376", "m_leader@club", "", SITE_UNMOUNT, "Allow*"),
	("MG-377", "m_leader@club", "", SITE_ROLLBACK, "Allow*"),
	// Revoking a welcome ref is the tenant's (the Deny runs first, so the Allow is real).
	("MG-378", "m_leader@club", "", REF_WELCOME2_DEL, "Deny"),
	("MG-379", "owner@club", "", REF_WELCOME2_DEL, "Allow"),
	// A registration ref is SADM's to edit.
	("MG-380", "owner@alice", "", REF_REGISTER_PATCH, "Deny"),
	// A CONN addressed to the community itself is no relationship: refused in either form.
	(
		"MG-389",
		"m_contributor@club",
		"",
		Call("POST", "/api/actions", r#"{"type":"CONN:DEL","audienceTag":"club.test"}"#),
		"400",
	),
	(
		"MG-390",
		"m_contributor@club",
		"",
		Call(
			"POST",
			"/api/actions",
			r#"{"type":"CONN","subType":"DEL","audienceTag":"club.test"}"#,
		),
		"400",
	),
	// PIM by id (seeded by `seed_pim`): the owner reads; a DAV key reaches its own capability.
	("MG-415", "owner@alice", "", Get("/api/calendars/1"), "Allow"),
	("MG-416", "owner@alice", "", Get("/api/calendars/1/objects"), "Allow"),
	("MG-417", "owner@alice", "", Get(CAL_EV1), "Allow"),
	("MG-418", "owner@alice", "", Get(CAL_EXCS), "Allow"),
	("MG-419", "owner@alice", "", Get(CAL_EXC), "Allow"),
	("MG-420", "owner@alice", "", Get("/api/address-books/1/contacts"), "Allow"),
	("MG-421", "owner@alice", "", Get(AB_C1), "Allow"),
	("MG-422", "apikey-dav@alice", "", Get(CAL_EV1), "Allow"),
	("MG-423", "apikey-dav@alice", "", Call("PUT", CAL_EV1, "{}"), "Deny"),
	("MG-424", "apikey-carddav-r@alice", "", Get(AB_C1), "Allow"),
	("MG-425", "apikey-dav-rw@alice", "", CAL_OBJECT_POST_1, "Allow*"),
	("MG-426", "apikey-carddav-r@alice", "", Call("DELETE", AB_C1, ""), "Deny"),
	// A community's PIM is its leaders'.
	("MG-427", "m_leader@club", "", Get("/api/calendars/2"), "Allow"),
	("MG-428", "m_contributor@club", "", Get("/api/calendars/2"), "Deny"),
	("MG-429", "m_leader@club", "", Get("/api/address-books/2/contacts"), "Allow"),
	("MG-430", "m_contributor@club", "", Get("/api/address-books/2/contacts"), "Deny"),
	// Another tenant's id, or a row of another collection: 404 (the SQL is scoped by tenant
	// and collection).
	("MG-431", "owner@alice", "", Get("/api/calendars/2"), "Deny"),
	("MG-432", "owner@alice", "", Get("/api/calendars/3/objects/zqm-ev1"), "Deny"),
	("MG-433", "owner@alice", "", Get("/api/address-books/3/contacts/zqm-c1"), "Deny"),
	("MG-434", "owner@alice", "", Get("/api/address-books/2/contacts/zqm-c1club"), "Deny"),
	("MG-435", "owner@alice", "", Get(CAL3_EXC), "Deny"),
	("MG-436", "owner@alice", "", Call("DELETE", CAL3_EXC, ""), "Deny"),
	("MG-437", "owner@alice", "", Call("POST", "/api/address-books/2/import", ""), "Deny"),
	// DAV collections and resources: a `cl_` key's own capability, on its own tenant.
	("MG-438", "apikey-dav@alice", "", CallBasic("PROPFIND", DAV_AB, ""), "Allow*"),
	("MG-439", "apikey-dav@alice", "", CallBasic("PROPFIND", DAV_CAL, ""), "Allow*"),
	("MG-440", "apikey-dav@alice", "", CallBasic("GET", DAV_C1, ""), "Allow*"),
	("MG-441", "apikey-dav@alice", "", CallBasic("GET", DAV_EV1, ""), "Allow*"),
	("MG-442", "apikey-carddav-r@alice", "", CallBasic("PROPFIND", DAV_CAL, ""), "Deny"),
	("MG-443", "apikey-carddav-r@alice", "", CallBasic("PROPFIND", DAV_AB_ZQM, ""), "Allow*"),
	("MG-444", "apikey-dav@alice", "", CallBasic("PUT", DAV_C1, VCARD), "Deny"),
	("MG-445", "apikey-dav@alice", "", CallBasic("DELETE", DAV_EV1, ""), "Deny"),
	(
		"MG-446",
		"apikey-dav@alice",
		"",
		CallBasic("MKCOL", "/dav/addressbooks/zqm-new/", ""),
		"Deny",
	),
	(
		"MG-447",
		"apikey-dav@alice",
		"",
		CallBasic("MKCALENDAR", "/dav/calendars/zqm-new/", ""),
		"Deny",
	),
	("MG-448", "apikey-dav-rw@alice", "", CallBasic("PUT", DAV_NEW_VCF, VCARD), "Allow*"),
	// An empty scope reaches no DAV path; an expired key, a key off its tenant, a session
	// bearer and no credential are refused.
	("MG-449", "apikey-unscoped@club", "", CallBasic("GET", DAV_PRINCIPAL, ""), "Deny"),
	("MG-450", "apikey-expired@alice", "", CallBasic("GET", DAV_PRINCIPAL, ""), "Deny"),
	("MG-451", "apikey-xtenant@club", "", CallBasic("PROPFIND", DAV_AB, ""), "Deny"),
	("MG-452", "owner@alice", "", Get(DAV_PRINCIPAL), "Deny"),
	("MG-453", "anon@alice", "", CallBasic("GET", DAV_CAL, ""), "Deny"),
	// Public: DAV discovery redirects (301). The passkey login challenge is pinned at 404: no
	// passkey is seeded (`webauthn.rs:525`), so the route is reached but has nothing to offer.
	("MG-454", "anon@alice", "", Get("/.well-known/carddav"), "Allow*"),
	("MG-455", "anon@alice", "", Get("/.well-known/caldav"), "Allow*"),
	("MG-456", "anon@alice", "", Get("/api/auth/wa/login/challenge"), "Deny"),
	("MG-457", "owner@alice", "", Call("POST", "/api/auth/logout", "{}"), "Allow"),
	// A DAV key reaches no push or reindex route (it reads PIM only).
	(
		"MG-474",
		"apikey-dav@alice",
		"",
		Call("DELETE", "/api/notifications/subscription/1", ""),
		"Deny",
	),
	("MG-475", "apikey-dav@alice", "", REINDEX, "Deny"),
	(
		"MG-476",
		"m_contributor@club",
		"",
		Call("DELETE", "/api/settings/file.sync_max_vis?level=tenant", ""),
		"Deny",
	),
	// A member's own settings: no anonymous caller, no link naming the community.
	("MG-477", "anon@club", "", PROF_SETTINGS, "Deny"),
	("MG-478", "anon@club", "", PROF_SETTING_PUT, "Deny"),
	("MG-479", "sharelink-r@club", "", PROF_SETTINGS, "Deny"),
	("MG-480", "sharelink-r@club", "", PROF_SETTING_PUT, "Deny"),
	("MG-481", "sharelink-w@alice", "", UNTAG, "Deny"),
	// Another tenant's key and refs are not the owner's, by id.
	("MG-482", "owner@alice", "", Get("/api/auth/api-keys/6"), "Deny"),
	("MG-483", "owner@alice", "", Call("DELETE", "/api/auth/api-keys/6", ""), "Deny"),
	("MG-484", "owner@alice", "", Get("/api/refs/zqref-club-r"), "Deny"),
	("MG-485", "owner@alice", "", Call("DELETE", "/api/refs/zqref-club-del", ""), "Deny"),
	(
		"MG-486",
		"owner@alice",
		"",
		Call("PATCH", "/api/refs/zqref-club-patch", r#"{"description":"zqm"}"#),
		"Deny",
	),
	// Pinned like MG-129: an authenticated identity reads a ref's details; a link is a guest on
	// this optional-auth route (the `GUEST6` rule), so it gets the reduced view (MG-128).
	("MG-487", "sharelink-r@alice", "", REF_FIELDS, "Clean"),
	("MG-488", "idp-ident@alice", "", REF_FIELDS, "Leak:resourceId"),
	// `/api/me/full` `x` sections by tier (seeded by the layer): `follower` reaches followers,
	// an unknown tier fails closed to the owner tier, a role tier reaches that role and above.
	("MG-490", "follower@alice", "", Fields("/api/me/full", &["x.zqmfollow"]), "Leak:x.zqmfollow"),
	("MG-491", "stranger@alice", "", Fields("/api/me/full", &["x.zqmfollow"]), "Clean"),
	("MG-492", "connected@alice", "", Fields("/api/me/full", &["x.zqmbad"]), "Clean"),
	("MG-493", "owner@alice", "", Fields("/api/me/full", &["x.zqmbad"]), "Leak:x.zqmbad"),
	("MG-494", "m_supporter@club", "", Fields("/api/me/full", &["x.zqmrole"]), "Leak:x.zqmrole"),
	("MG-495", "m_follower@club", "", Fields("/api/me/full", &["x.zqmrole"]), "Clean"),
	// A mount names a document of the community's own: another tenant's id is not found
	// (scoped `read_file`, `cloudillo-site/src/handler.rs:494`).
	(
		"MG-489",
		"m_leader@club",
		"",
		Call(
			"POST",
			"/api/sites/mounts",
			r#"{"docFileId":"f1~zqm-alice-tenant-crdt-d-active","mountPath":"/zqm"}"#,
		),
		"400",
	),
];

const CAL_EV1: &str = "/api/calendars/1/objects/zqm-ev1";
const CAL_EXCS: &str = "/api/calendars/1/objects/zqm-ev1/exceptions";
const CAL_EXC: &str =
	concat!("/api/calendars/1/objects/zqm-ev1/exceptions/", crate::objects::pim_rid!());
const CAL3_EXC: &str =
	concat!("/api/calendars/3/objects/zqm-ev1/exceptions/", crate::objects::pim_rid!());
const AB_C1: &str = "/api/address-books/1/contacts/zqm-c1";
const CAL_OBJECT_POST_1: Route = Call("POST", "/api/calendars/1/objects", "{}");
const DAV_AB: &str = "/dav/addressbooks/";
const DAV_AB_ZQM: &str = "/dav/addressbooks/zqm-ab/";
const DAV_CAL: &str = "/dav/calendars/";
const DAV_C1: &str = "/dav/addressbooks/zqm-ab/zqm-c1.vcf";
const DAV_NEW_VCF: &str = "/dav/addressbooks/zqm-ab/zqm-dav.vcf";
const DAV_EV1: &str = "/dav/calendars/zqm-cal/zqm-ev1.ics";
const VCARD: &str = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:zqm-dav\r\nFN:Zqm\r\nEND:VCARD\r\n";

const DAV_PRINCIPAL: &str = "/dav/principal/";
const PUT_ZQM_TYPE: Route = Call("PUT", "/api/profiles/zqm-new.test", r#"{"type":"zqm"}"#);
const UNTAG_OBJ: &str = "/api/files/{obj}/tag/zqm";
const REFRESH_CONNECTED: Route = Call("POST", "/api/profiles/connected.test/refresh", "");
const PROXY_TO_PEER: Route = Get("/api/auth/proxy-token?idTag=peer.test");
const AB_CONTACT_POST: Route = Call("POST", "/api/address-books/zqm/contacts", "{}");
const CAL_OBJECT_POST: Route = Call("POST", "/api/calendars/zqm/objects", "{}");
const SITE_MOUNT: Route = Call("POST", "/api/sites/mounts", "{}");
const SITE_UNMOUNT: Route = Call("DELETE", "/api/sites/mounts", "{}");
const SITE_ROLLBACK: Route = Call("POST", "/api/sites/rollback", "{}");
const REF_WELCOME2_DEL: Route = Call("DELETE", "/api/refs/zqref-club-welcome2", "");
const REF_REGISTER_PATCH: Route =
	Call("PATCH", "/api/refs/zqref-alice-register", r#"{"description":"zqm"}"#);

const CONN_EMPTY_SUB: Route =
	Call("POST", "/api/actions", r#"{"type":"CONN","subType":"","audienceTag":"zqm-nobody.test"}"#);
const CONN_XYZ_SUB: Route = Call(
	"POST",
	"/api/actions",
	r#"{"type":"CONN","subType":"XYZ","audienceTag":"zqm-nobody.test"}"#,
);

const SITES_PATCH: Route = Call("PATCH", "/api/sites", "{}");
const SITES_PUBLISH: Route = Call("POST", "/api/sites/publish", "{}");
const AB_PATCH: Route = Call("PATCH", "/api/address-books/zqm", "{}");
const CAL_PATCH: Route = Call("PATCH", "/api/calendars/zqm", "{}");
const PUSH_SUB_DEL: Route = Call("DELETE", "/api/notifications/subscription/zqm", "");
const PROF_SETTING_GET: Route = Get("/api/profiles/m-contributor.test/settings/zqm.k");

const REF_IDP_STATUS: Route = Get("/api/refs/zqref-alice-welcome/idp-status");
const REF_IDP_RESEND: Route = Call("POST", "/api/refs/zqref-alice-welcome/resend-activation", "");

const CONN_ACC_NOBODY: Route =
	Call("POST", "/api/actions", r#"{"type":"CONN:ACC","audienceTag":"zqm-nobody.test"}"#);

const INVT_CLUB: Route = Call(
	"POST",
	"/api/actions",
	r#"{"type":"INVT","subject":"@club.test","audienceTag":"zqm-invitee.test"}"#,
);

const REF_PATCH_W: Route = Call("PATCH", "/api/refs/zqref-alice-r", r#"{"accessLevel":"write"}"#);
const REF_SHARE_OBJ: Route =
	Call("POST", "/api/refs", r#"{"type":"share.file","resourceId":"{obj}","accessLevel":"R"}"#);
const SHARE_U: &str = r#"{"subjectType":"U","subjectId":"zqm-l.test","permission":"R"}"#;

const POST_ZQM: Route = Call("POST", "/api/actions", r#"{"type":"POST","content":"zqm"}"#);
const REF_REGISTER: Route = Call("POST", "/api/refs", r#"{"type":"register"}"#);
const FORMAT_HELD_DEL: Route = Call("DELETE", "/api/doc-formats/zqm%2Fheld", "");
const ME_FULL: Route = Fields("/api/me/full", &["x.zqmconn"]);

/// `/api/admin/*` routes beyond the two listings, each refused to every [`ADMIN_DENIED`]
/// credential. Ids continue [`MG`]; bodies are empty, as the gate refuses before any handler.
const ADMIN_ROUTES: &[(&str, Route)] = &[
	("MG-214", Call("POST", "/api/admin/tenants/trash.test/password-reset", "{}")),
	("MG-215", Call("POST", "/api/admin/tenants/trash.test/purge", "{}")),
	("MG-216", Call("POST", "/api/admin/email/test", "{}")),
	("MG-217", Get("/api/admin/cert-status")),
	("MG-218", Call("POST", "/api/admin/db-maintenance", "{}")),
	("MG-219", Call("POST", "/api/admin/proxy-sites", "{}")),
	// The fixture's one proxy site.
	("MG-220", Get("/api/admin/proxy-sites/1")),
	("MG-221", Call("PATCH", "/api/admin/proxy-sites/1", "{}")),
	("MG-222", Call("DELETE", "/api/admin/proxy-sites/1", "")),
	("MG-223", Call("POST", "/api/admin/proxy-sites/1/renew-cert", "{}")),
	("MG-224", Call("POST", "/api/admin/invite-community", "{}")),
];

/// Every credential short of SADM's unscoped session: SADM itself is scoped down last.
const ADMIN_DENIED: &[&str] = &[
	"owner@alice",
	"follower@alice",
	"idp-mgmt@alice",
	"apikey-dav@alice",
	"apkg-publish@alice",
	"m_leader@club",
	"apikey-unscoped@alice",
	"owner-scoped-r@alice",
	"anon@alice",
	"sadm-scoped@admin",
	"stranger@alice",
	"sharelink-r@alice",
	"idp-ident@alice",
];

/// The account's own credentials (`require_tenant_self`), refused to every
/// [`OWNER_CRED_DENIED`] credential on alice's real key 1. Ids continue [`MG`].
const OWNER_CRED_ROUTES: &[(&str, Route)] = &[
	("MG-315", Get("/api/auth/api-keys/1")),
	("MG-316", Call("PATCH", "/api/auth/api-keys/1", r#"{"name":"zqm"}"#)),
	("MG-317", Call("DELETE", "/api/auth/api-keys/1", "")),
	("MG-318", Call("POST", "/api/auth/api-keys", "{}")),
	("MG-319", Call("POST", "/api/auth/wa/reg", "{}")),
	("MG-320", Get("/api/auth/wa/reg/challenge")),
	("MG-391", Call("DELETE", "/api/auth/wa/reg/zqm", "")),
];

const OWNER_CRED_DENIED: &[&str] = &[
	"stranger@alice",
	"sharelink-r@alice",
	"anon@alice",
	"idp-ident@alice",
	"follower@alice",
	"apkg-publish@alice",
	"apikey-dav@alice",
	"owner-scoped-r@alice",
];

/// Room management on club, refused below a leader and to every non-member credential.
const CHAN_WRITE_ROUTES: &[(&str, Route)] = &[
	("CH-121", ChanCreate("zqm-grid")),
	("CH-122", ChanPatch("open-contrib")),
	("CH-123", ChanDelete("mods")),
	("CH-124", ChanMembers("closed-w")),
];
const CHAN_WRITE_DENIED: &[&str] = &[
	"stranger@club",
	"m_follower@club",
	"sharelink-r@club",
	"idp-mgmt@club",
	"anon@club",
	"hatted-scoped@club",
];

/// Room management on alice, refused to every non-account credential.
const CHAN_WRITE_ALICE: &[(&str, Route)] = &[
	("CH-125", ChanCreate("zqm-grid-a")),
	("CH-126", ChanPatch("close-friends")),
	("CH-127", ChanDelete("close-friends")),
	("CH-128", ChanMembers("close-friends")),
];
const CHAN_WRITE_ALICE_DENIED: &[&str] = &[
	"stranger@alice",
	"follower@alice",
	"sharelink-r@alice",
	"owner-scoped-r@alice",
	"apkg-publish@alice",
	"apikey-dav@alice",
	"idp-ident@alice",
	"anon@alice",
];

/// Settings are read with the standing that writes them: no link or capability credential.
const SETTINGS_READ_ROUTES: &[(&str, Route)] = &[
	("MG-381", Get("/api/settings")),
	("MG-382", Get("/api/settings?prefix=profile")),
];
const SETTINGS_READ_DENIED: &[&str] = &[
	"sharelink-r@alice",
	"apikey-dav@alice",
	"apkg-publish@alice",
	"idp-ident@alice",
	"anon@alice",
	"owner-scoped-r@alice",
];

/// Settings writes at the User level: the unscoped tenant or a leader (MG-11..18).
const SETTINGS_WRITE_ROUTES: &[(&str, Route)] = &[
	("MG-470", SET_USER),
	("MG-471", Call("DELETE", "/api/settings/file.sync_max_vis?level=tenant", "")),
];
const SETTINGS_WRITE_DENIED: &[&str] = &[
	"sharelink-r@alice",
	"anon@alice",
	"apkg-publish@alice",
	"idp-ident@alice",
	"follower@alice",
];

/// The site routes beyond `GET /api/sites` (`require_leader`).
const SITE_ROUTES: &[(&str, Route)] = &[
	("MG-461", SITES_PATCH),
	("MG-462", Get("/api/sites/pages")),
	("MG-463", SITES_PUBLISH),
	("MG-464", SITE_MOUNT),
	("MG-465", SITE_UNMOUNT),
	("MG-466", SITE_ROLLBACK),
];
const SITE_DENIED: &[&str] = &[
	"stranger@alice",
	"follower@alice",
	"sharelink-r@alice",
	"anon@alice",
	"apkg-publish@alice",
	"apikey-dav@alice",
	"idp-ident@alice",
	"owner-scoped-r@alice",
];

/// Push, reindex and the contact listing (`require_leader`); `apikey-dav` reads contacts
/// (MG-246), so it is in neither list (MG-474, 475 for the rest).
const LEADER_MISC_ROUTES: &[(&str, Route)] = &[
	("MG-467", Call("DELETE", "/api/notifications/subscription/1", "")),
	("MG-468", REINDEX),
	("MG-469", Get("/api/contacts")),
];
const LEADER_MISC_DENIED: &[&str] = &[
	"stranger@alice",
	"follower@alice",
	"sharelink-r@alice",
	"anon@alice",
	"apkg-publish@alice",
	"idp-ident@alice",
	"owner-scoped-r@alice",
];

/// A file's share by id: its managers'. The manager check runs before the share-id lookup
/// (`cloudillo-file/src/share.rs:216`), so share 1 need not belong to the file.
const SHARE_WRITE_ROUTES: &[(&str, Route)] = &[
	("MG-472", Call("PATCH", "/api/files/f1~zqm-alice-tenant-blob-d-active/shares/1", "{}")),
	("MG-473", Call("DELETE", "/api/files/f1~zqm-alice-tenant-blob-d-active/shares/1", "")),
];
const SHARE_WRITE_DENIED: &[&str] = &[
	"anon@alice",
	"follower@alice",
	"stranger@alice",
	"g_read@alice",
	"apkg-publish@alice",
	"apikey-dav@alice",
	"idp-ident@alice",
	"sharelink-w@alice",
];

/// The account's own PIM, sites, refs, apps and push: never a link's or an `idp_` key's.
const ACCOUNT_ROUTES: &[(&str, Route)] = &[
	("MG-383", ADDR_BOOKS),
	("MG-384", CALENDARS),
	("MG-385", SITES),
	("MG-386", Get("/api/refs")),
	("MG-387", APPS_INSTALLED),
	("MG-388", PUSH_SUB),
];
/// Not `apikey-dav`: it reads address books and calendars (MG-59, MG-66).
const ACCOUNT_DENIED: &[&str] = &[
	"sharelink-r@alice",
	"idp-mgmt@alice",
	"idp-ident@alice",
	"stranger@alice",
	"follower@alice",
	"anon@alice",
	"apkg-publish@alice",
	"owner-scoped-r@alice",
];

/// The PIM by-id routes (`require_leader`; a DAV key its own capability), refused to every
/// [`CAL_DENIED`] credential. Bodies are empty: the gate refuses before any handler.
const CAL_ROUTES: &[(&str, Route)] = &[
	("MG-392", Get("/api/calendars/1")),
	("MG-393", Get("/api/calendars/1/objects")),
	("MG-394", Get(CAL_EV1)),
	("MG-395", Call("PUT", CAL_EV1, "")),
	("MG-396", Call("PATCH", CAL_EV1, "")),
	("MG-397", Call("DELETE", CAL_EV1, "")),
	("MG-398", Call("POST", "/api/calendars/1/objects/zqm-ev1/split", "")),
	("MG-399", Get(CAL_EXCS)),
	("MG-400", Get(CAL_EXC)),
	("MG-401", Call("PUT", CAL_EXC, "")),
	("MG-402", Call("PATCH", CAL_EXC, "")),
	("MG-403", Call("DELETE", CAL_EXC, "")),
	("MG-404", Call("POST", "/api/calendars", "")),
	("MG-405", Call("DELETE", "/api/calendars/1", "")),
];
const CAL_DENIED: &[&str] = &[
	"stranger@alice",
	"follower@alice",
	"sharelink-r@alice",
	"owner-scoped-r@alice",
	"apkg-publish@alice",
	"idp-ident@alice",
	"anon@alice",
	"apikey-carddav-r@alice",
];
const AB_ROUTES: &[(&str, Route)] = &[
	("MG-406", Get("/api/address-books/1/contacts")),
	("MG-407", Get(AB_C1)),
	("MG-408", Call("PUT", AB_C1, "")),
	("MG-409", Call("PATCH", AB_C1, "")),
	("MG-410", Call("DELETE", AB_C1, "")),
	("MG-411", Call("POST", "/api/address-books/1/import", "")),
	("MG-412", Call("POST", "/api/address-books", "")),
	("MG-413", Call("DELETE", "/api/address-books/1", "")),
	("MG-414", Call("POST", "/api/address-books/1/contacts", "")),
];
/// [`CAL_DENIED`] less `apikey-carddav-r`, which reads address books (MG-424).
const AB_DENIED: &[&str] = &[
	"stranger@alice",
	"follower@alice",
	"sharelink-r@alice",
	"owner-scoped-r@alice",
	"apkg-publish@alice",
	"idp-ident@alice",
	"anon@alice",
];

/// `(id, route)` rows of a Deny grid.
type GridRoutes = &'static [(&'static str, Route)];

/// `(routes, denied subjects)`: every cell is a Deny.
const GRIDS: &[(GridRoutes, &[&str])] = &[
	(ADMIN_ROUTES, ADMIN_DENIED),
	(OWNER_CRED_ROUTES, OWNER_CRED_DENIED),
	(CHAN_WRITE_ROUTES, CHAN_WRITE_DENIED),
	(SETTINGS_READ_ROUTES, SETTINGS_READ_DENIED),
	(ACCOUNT_ROUTES, ACCOUNT_DENIED),
	(CAL_ROUTES, CAL_DENIED),
	(AB_ROUTES, AB_DENIED),
	(SITE_ROUTES, SITE_DENIED),
	(LEADER_MISC_ROUTES, LEADER_MISC_DENIED),
	(SETTINGS_WRITE_ROUTES, SETTINGS_WRITE_DENIED),
	(SHARE_WRITE_ROUTES, SHARE_WRITE_DENIED),
	(CHAN_WRITE_ALICE, CHAN_WRITE_ALICE_DENIED),
];

/// [`MG`] plus the [`GRIDS`].
pub fn management_cells() -> Vec<Cell> {
	let mut out = cells(MG);
	for &(routes, subjects) in GRIDS {
		for &(id, route) in routes {
			for &subject in subjects {
				let op = format!("{route:?}");
				out.push(Cell { id, op, subject, object: "", route, want: "Deny" });
			}
		}
	}
	out
}

const BATCH_URI: &str = "/api/profiles/batch?idTags=connected.test";
const BATCH: Route = Get(BATCH_URI);

const APRV_TARGET: &str = "cur-aprv-target@club";
const APRV: Route = Call("POST", "/api/actions", r#"{"type":"APRV","subject":"{obj}"}"#);
const APRV_DRAFT: Route =
	Call("POST", "/api/actions", r#"{"type":"APRV","subject":"{obj}","draft":true}"#);
const FLLW_NOBODY: Route =
	Call("POST", "/api/actions", r#"{"type":"FLLW","audienceTag":"zqm-nobody.test"}"#);
const CONN_NOBODY: Route =
	Call("POST", "/api/actions", r#"{"type":"CONN","audienceTag":"zqm-nobody.test"}"#);
const CONN_UPD_NOBODY: Route =
	Call("POST", "/api/actions", r#"{"type":"CONN:UPD","audienceTag":"zqm-nobody.test"}"#);

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
const ROOM_SHARED: &str = "cur-room-shared@club";

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
	// A link naming club is a guest on the porch: a secret room stays unlisted (CH-62..64).
	("CH-108", "sharelink-r@club", "", ChanPorch("closed-w"), "Absent"),
	// The room caps roles: off the roster, a leader's or moderator's `R` share is all they hold.
	("CH-109", "m_leader@club", ROOM_SHARED, FileMeta, "Allow@Read"),
	("CH-110", "m_leader@club", ROOM_SHARED, FilePatch, "Deny"),
	("CH-111", "m_leader@club", ROOM_SHARED, Call("POST", SHARES_OBJ, SHARE_U), "Deny"),
	("CH-112", "m_leader@club", ROOM_SHARED, REF_SHARE_OBJ, "Deny"),
	("CH-113", "m_leader@club", ROOM_SHARED, FileDelete, "Deny"),
	("CH-114", "m_moderator@club", ROOM_SHARED, FileMeta, "Allow@Read"),
	("CH-115", "m_moderator@club", ROOM_SHARED, FilePatch, "Deny"),
	("CH-116", "m_moderator@club", ROOM_SHARED, Call("POST", SHARES_OBJ, SHARE_U), "Deny"),
	("CH-117", "m_moderator@club", ROOM_SHARED, REF_SHARE_OBJ, "Deny"),
	("CH-118", "m_moderator@club", ROOM_SHARED, FileDelete, "Deny"),
	// Control: a `W` share still writes there.
	("CH-119", "g_write@club", ROOM_SHARED, FilePatch, "Allow"),
	// A deleted or unknown room has no roster to show, even to the tenant.
	("CH-129", "owner@club", "", ChanMembers("gone"), "Deny"),
	("CH-130", "owner@club", "", ChanMembers("zqm-nope"), "Deny"),
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
	// Carry alice's id_tag without being alice: a guest; an `idp_` key is refused (401).
	("PT-19", "sharelink-r@alice", "", Partners, "Empty"),
	("PT-09", "idp-mgmt@alice", "", Partners, "Deny"),
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
	// The account's own unscoped key is the account; a capability key or an `idp_` key is not.
	("PT-51", "apikey-unscoped@club", "", PartnersMap, "Allow"),
	("PT-52", "apikey-unscoped@club", "", PartnersSync, "Allow*"),
	("PT-53", "apikey-dav@alice", "", PartnersMap, "Deny"),
	("PT-54", "apkg-publish@alice", "", PartnersMap, "Deny"),
	("PT-55", "idp-ident@alice", "", PartnersMap, "Deny"),
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
	("LV-59", "idp-mgmt@alice", "", Fields(ALICE_CONN, HATS), "Deny"),
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
	("LV-172", "idp-mgmt@alice", "", Fields("/api/profiles", HATS), "Deny"),
	("LV-173", "sharelink-r@alice", "", Fields("/api/profiles", HATS), "Deny"),
	("LV-174", "owner@club", "", Fields(COMM, HATS), "Leak:hats"),
	("LV-175", "m_leader@club", "", Fields(COMM, HATS), "Clean"),
	// Thread and id filters never reach a row the caller cannot read.
	(
		"LV-184",
		"stranger@alice",
		"child-d-tenant-active@alice",
		ActListQ("parentId={parent}"),
		"Absent",
	),
	(
		"LV-185",
		"owner@alice",
		"child-d-tenant-active@alice",
		ActListQ("parentId={parent}"),
		"Present",
	),
	(
		"LV-186",
		"stranger@alice",
		"child-d-tenant-active@alice",
		ActListQ("rootId={parent}"),
		"Absent",
	),
	(
		"LV-187",
		"owner@alice",
		"child-d-tenant-active@alice",
		ActListQ("rootId={parent}"),
		"Present",
	),
	(
		"LV-188",
		"stranger@alice",
		"post-d-tenant-active@alice",
		ActListQ("actionId={obj}"),
		"Absent",
	),
	("LV-189", "owner@alice", "post-d-tenant-active@alice", ActListQ("actionId={obj}"), "Present"),
	("LV-190", "stranger@club", CW_POST, ActListQ("actionId={obj}"), "Absent"),
	("LV-191", "owner@club", CW_POST, ActListQ("actionId={obj}"), "Present"),
	(
		"LV-192",
		"stranger@alice",
		"docchild-crdt-d-active@alice",
		FileListQ("rootId={root}"),
		"Absent",
	),
	(
		"LV-193",
		"owner@alice",
		"docchild-crdt-d-active@alice",
		FileListQ("rootId={root}"),
		"Present",
	),
	// Listing refs is the tenant's.
	("LV-194", "stranger@alice", "", Get("/api/refs?filter=all"), "Deny"),
	("LV-195", "sharelink-r@alice", "", Get("/api/refs?filter=all"), "Deny"),
	// Search narrowing never widens: a container scope or a tag adds no hit.
	("LV-196", "stranger@alice", "tenant-crdt-d-active@alice", SearchQ("fileId={obj}"), "Absent"),
	("LV-197", "owner@alice", "tenant-crdt-d-active@alice", SearchQ("fileId={obj}"), "Present"),
	("LV-198", "stranger@alice", "tenant-blob-d-active@alice", SearchQ("tags=zqm"), "Absent"),
	("LV-199", "anon@alice", "tenant-blob-d-active@alice", SearchQ("type=file"), "Absent"),
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
	// An `idp_` management key names the account but is not it: refused on its host.
	("LV-90", "idp-mgmt@alice", "", PartnersMap, "Deny"),
	("LV-91", "idp-mgmt@alice", "", PartnersSync, "Deny"),
	("LV-92", "idp-mgmt@alice", "", Get("/api/settings"), "Deny"),
	("LV-93", "idp-mgmt@alice", "", Ids(CONN), "Deny"),
	("LV-94", "idp-mgmt@alice", "", Fields("/api/profiles", CONNECTED), "Deny"),
	("LV-95", "idp-mgmt@alice", "tenant-blob-d-active@alice", FileList, "Absent"),
	("LV-96", "idp-mgmt@alice", "post-d-tenant-active@alice", ActList, "Absent"),
	("LV-97", "idp-mgmt@alice", "post-p-tenant-pending@alice", ActListQ("status=C"), "Absent"),
];

/// [`LV`] boundary rows re-run with alice's `connection_visibility.community` = `verified`:
/// an `idp_` key naming alice is refused on her host (401), not an authenticated caller.
pub const LV_VERIFIED: &[Row] = &[
	("LV-100", "stranger@alice", "", Ids(CONN_COMM), "Listed"),
	("LV-101", "idp-mgmt@alice", "", Ids(CONN_COMM), "Deny"),
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
	out.extend(g2_cells(G2));
	out
}

fn g2_cells(rows: &[(&'static str, &'static str, [&'static str; 6])]) -> Vec<Cell> {
	let mut out = Vec::new();
	for &(id, subject, wants) in rows {
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
	/// A file id with no row (WS-18), or an `s~` store id.
	Raw(&'static str),
}

/// Catalogue object name (`{spec}@{host}`, `root@X`, `folder@X`, raw `f1~…` / `s~…`) → fixture
/// object.
fn target<'a>(fx: &'a Fixture, name: &'static str) -> Option<Tgt<'a>> {
	if name.is_empty() {
		return Some(Tgt::None);
	}
	if name.starts_with("f1~") || name.starts_with("s~") {
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

/// The subject's bearer, for routes that carry it outside the header.
fn tok(s: &Subject) -> &str {
	bearer(s).unwrap_or_default()
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
		(Get(uri), _) => raw(Method::GET, &uri.replace("{obj}", &key), Body::empty()),
		(Call(m, uri, body), _) => {
			let (uri, body) = (uri.replace("{obj}", &key), body.replace("{obj}", &key));
			let body = if body.is_empty() { Body::empty() } else { Body::from(body) };
			raw(Method::from_bytes(m.as_bytes()).expect("method"), &uri, body)
		}
		(PartnersSync, _) => raw(Method::POST, "/api/partners/sync", Body::empty()),
		(PtnrCreate, _) => {
			raw(Method::POST, "/api/actions", j(json!({ "type": "PTNR", "subject": "@peer.test" })))
		}
		(PtnrDelCreate, _) => {
			let body = json!({ "type": "PTNR:DEL", "subject": "@peer.test" });
			raw(Method::POST, "/api/actions", j(body))
		}
		(GetQ(uri), _) => {
			let uri = format!("{uri}{}token={}", if uri.contains('?') { '&' } else { '?' }, tok(s));
			req(&s.host, Method::GET, &uri, None, Body::empty())
		}
		(CallBasic(m, uri, body), _) => {
			basic(s, Method::from_bytes(m.as_bytes()).expect("method"), uri, body)
		}
		(WsQuery(kind, access), Tgt::Obj(Obj::File(file))) => {
			let kind = if kind == WsKind::Crdt { "crdt" } else { "rtdb" };
			let access = access.map_or(String::new(), |level| format!("&access={level}"));
			let uri = format!("/ws/{kind}/{}?token={}{access}", file.path_id(), tok(s));
			req(&s.host, Method::GET, &uri, None, Body::empty())
		}
		(_, Tgt::Obj(o)) => route.op().expect("route has an op").request(s, o),
		(WsCrdt(None), Tgt::Raw(_)) => raw(Method::GET, &format!("/ws/crdt/{key}"), Body::empty()),
		(WsRtdb(None), Tgt::Raw(_)) => raw(Method::GET, &format!("/ws/rtdb/{key}"), Body::empty()),
		_ => panic!("{route:?} needs a seeded object"),
	}
}

/// `{method} {uri}` with `Authorization: Basic …`: a `cl_` key goes in as the DAV password;
/// anyone else sends `x:x`.
fn basic(s: &Subject, m: Method, uri: &str, body: &'static str) -> Request<Body> {
	let body = if body.is_empty() { Body::empty() } else { Body::from(body) };
	let mut r = req(&s.host, m, uri, None, body);
	let pair = bearer(s).filter(|t| t.starts_with("cl_")).unwrap_or("x");
	r.headers_mut().insert(header::AUTHORIZATION, basic_auth(&format!("x:{pair}")));
	r
}

/// `Basic base64(pair)`, `pair` being `user:password`.
pub(crate) fn basic_auth(pair: &str) -> HeaderValue {
	use base64::Engine;
	let b64 = base64::engine::general_purpose::STANDARD.encode(pair);
	HeaderValue::from_str(&format!("Basic {b64}")).expect("header")
}

/// A list query with `{obj}` (the object's key), `{parent}` and `{root}` (its parent's and
/// root's ids) filled in.
fn fill(q: &str, tgt: &Tgt<'_>) -> String {
	let Tgt::Obj(o) = tgt else { return q.to_owned() };
	let (parent, root) = match o {
		Obj::File(f) => (f.parent_id.clone(), f.root_id.clone()),
		Obj::Action(a) => (a.parent_id.clone(), a.parent_id.clone()),
	};
	q.replace("{obj}", &obj_key(o))
		.replace("{parent}", &parent.unwrap_or_default())
		.replace("{root}", &root.unwrap_or_default())
}

/// `(outcome, level, status)`; status is 0 for listings.
type Observed = (Actual, Option<AccessLevel>, u16);

async fn observe(fx: &Fixture, s: &Subject, route: Route, tgt: &Tgt<'_>) -> Observed {
	if !route.is_listing() {
		let ws = matches!(route, WsCrdt(_) | WsRtdb(_) | WsQuery(..))
			|| matches!(route, Call(_, u, _) if u.starts_with("/ws/"));
		let router = if ws { &fx.ws } else { &fx.api };
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
		ActListQ(q) => {
			list_paged(fx, s, &format!("/api/actions?{}&", fill(q, tgt)), "actionId").await
		}
		FileListQ(q) => list_paged(fx, s, &format!("/api/files?{}&", fill(q, tgt)), "fileId").await,
		SearchQ(q) => {
			let uri = format!("/api/search?q={}&limit=100&{}", crate::ops::MARK, fill(q, tgt));
			crate::ops::get(fx, s, &uri).await.map(|b| {
				crate::ops::rows(&b)
					.iter()
					.filter_map(|h| h.get("objId")?.as_str())
					.map(|id| (id.to_owned(), None))
					.collect()
			})
		}
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

/// `Clean`, or `Leak:{field}` for the first of `forbidden` set on any row at `uri`; a dotted
/// field (`x.key`) is a nested path.
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
		.find(|k| {
			let path = format!("/{}", k.replace('.', "/"));
			rows.iter().any(|r| r.pointer(&path).is_some_and(|v| !v.is_null()))
		})
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
