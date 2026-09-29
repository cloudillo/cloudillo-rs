// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Matrix objects, seeded by direct adapter writes: the level-layer set (every Active Blob file
//! shape × visibility, every Active action shape × visibility × issuer) plus the objects the
//! curated rows name.
//!
//! Each object carries the facts the oracle needs as plain data (owner, upstream, parent,
//! root, shares, refs) — the oracle never reads production code.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use cloudillo::App;
use cloudillo::action_types::CreateAction;
use cloudillo::auth_adapter::{ActionToken, CreateApiKeyOptions};
use cloudillo::blob_adapter::CreateBlobOptions;
use cloudillo::meta_adapter::{
	Action, ActionId, CreateFile, CreateRefOptions, CreateShareEntry, FileId, FileStatus,
	FileVariant, FinalizeActionOptions, InstallApp, SHARE_FILE_REF_TYPE, TRASH_PARENT_ID,
	UpdateActionDataOptions,
};
use cloudillo::types::{Patch, Timestamp, TnId};
use serde_json::json;

use crate::fixture::{CLUB, RemoteId, Remotes, Tenant, Tenants, sign};

/// Visibility axis: `P V 2 F C S` and Direct (`None`).
pub const VIS: [Option<char>; 7] =
	[Some('P'), Some('V'), Some('2'), Some('F'), Some('C'), Some('S'), None];

/// Committed minimal app package (one `index.html` entry).
const APKG: &[u8] = include_bytes!("fixtures/app.apkg");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileShape {
	/// `owner_tag` NULL: the tenant owns it.
	TenantOwned,
	/// Community only: `owner_tag` = `m_contributor`.
	MemberOwned,
	/// `upstream_tag` = `connected`, plus an `FSHR:{file}:{tenant}` WRITE row issued by it.
	MirroredFshr,
	/// `upstream_tag` = `connected`, no FSHR row (Pin/Place copy; placer = the tenant).
	MirroredPlacer,
	/// `FLDR`; carries a `U` WRITE share for `g_folder`.
	Folder,
	/// Child of the tenant's canonical folder (Direct, active) — inherits `g_folder`'s share.
	FolderChild,
	/// `root_id` = the tenant's canonical doc root.
	DocChild,
	/// Target of an `F→F` share (`subject_id` = canonical doc root, permission `R`).
	LinkTarget,
	/// `preset = apkg`; installed via `install_app` when active.
	Apkg,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
	Blob,
	Crdt,
	Rtdb,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileLife {
	Active,
	/// Active row moved under `TRASH_PARENT_ID`.
	Trashed,
	/// `status = 'P'`.
	Pending,
	/// Finalized, then purged by the adapter's tombstone delete (`status = 'D'`).
	Tombstoned,
}

#[derive(Clone, Debug)]
pub struct FileSpec {
	pub name: String,
	pub tn: &'static str,
	pub vis: Option<char>,
	pub shape: FileShape,
	pub kind: FileKind,
	pub life: FileLife,
}

/// A seeded share entry on a file.
#[derive(Clone, Debug)]
pub struct Share {
	/// `'U'` (user) or `'F'` (file link).
	pub subject_type: char,
	pub subject_id: String,
	pub perm: char,
	pub expired: bool,
}

/// A seeded share-link ref.
#[derive(Clone, Debug)]
pub struct ShareRef {
	pub ref_id: String,
	pub access: char,
}

#[derive(Clone, Debug)]
pub struct FileObj {
	pub spec: FileSpec,
	pub tn_id: TnId,
	pub file_id: String,
	pub parent_id: Option<String>,
	pub root_id: Option<String>,
	pub owner_tag: Option<String>,
	pub upstream_tag: Option<String>,
	/// `(issuer, audience, sub_typ)` of the seeded FSHR row.
	pub fshr: Option<(String, String, &'static str)>,
	/// Share entries on this file (not inherited ones).
	pub shares: Vec<Share>,
	pub refs: Vec<ShareRef>,
	/// Blob variant id (Blob/Apkg kinds).
	pub blob_id: Option<String>,
	/// `(app_name, publisher_tag)` when installed.
	pub installed: Option<(String, String)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionShape {
	/// Subscribable `CONV`; `subscriber` holds a `SUBS` row on every one.
	Container,
	/// Plain `POST`.
	Post,
	/// `MSG` under the tenant-issued active container of the same visibility.
	Child,
	/// club only: `POST` by `hatted` wearing `peer`'s hat (`h`), endorsed by a peer `APRV`.
	HatRelayed,
	/// `POST` at Direct with `audience = direct`.
	DirectAudience,
	/// `INVT` at Direct with `audience = direct` and `subject` = the tenant's active Direct
	/// container, which `subscriber` holds a `SUBS` row on.
	OnContainer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Issuer {
	/// Signed by the tenant's own profile key.
	Tenant,
	/// alice: `connected`; club: `m_contributor`; HatRelayed: `hatted`.
	Remote,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionLife {
	Active,
	/// Status `D` (soft-deleted).
	Deleted,
	/// Status `C` (pending confirmation).
	Pending,
	/// Status `N` — dismissable notification; dismissing turns it `A`.
	Dismissed,
	/// `@` draft, status `R`: no `action_id`, no token.
	Draft,
	/// `@` draft, status `S`, `created_at` = publish time (+1 day).
	Scheduled,
}

impl ActionLife {
	pub fn status(self) -> char {
		match self {
			Self::Active => 'A',
			Self::Deleted => 'D',
			Self::Pending => 'C',
			Self::Dismissed => 'N',
			Self::Draft => 'R',
			Self::Scheduled => 'S',
		}
	}

	pub fn is_draft(self) -> bool {
		matches!(self, Self::Draft | Self::Scheduled)
	}
}

#[derive(Clone, Debug)]
pub struct ActionSpec {
	pub name: String,
	pub tn: &'static str,
	pub typ: ActionShape,
	pub vis: Option<char>,
	pub issuer: Issuer,
	pub life: ActionLife,
	/// `audience = tenant` (curated accept/reject objects).
	pub to_tenant: bool,
}

#[derive(Debug)]
pub struct ActionObj {
	pub spec: ActionSpec,
	pub tn_id: TnId,
	/// `a1~…` (hash of the token); empty for drafts — address those via [`ActionObj::key`].
	pub action_id: String,
	/// Draft row id.
	pub a_id: AtomicU64,
	/// `CONV` / `POST` / `MSG` / `INVT`.
	pub typ: &'static str,
	pub issuer_tag: String,
	pub audience_tag: Option<String>,
	/// Container `action_id` (Child); also stored as `root_id`.
	pub parent_id: Option<String>,
	/// Container `action_id` the row names as `subject` (OnContainer).
	pub subject: Option<String>,
	pub hat_tag: Option<String>,
	pub content: serde_json::Value,
	/// The stored signed token (`None` for drafts).
	pub token: Option<String>,
	/// `action_id` of `peer`'s endorsing `APRV` (HatRelayed).
	pub aprv_id: Option<String>,
	/// `action_id` of `subscriber`'s `SUBS` row (Container).
	pub subs_id: Option<String>,
}

impl ActionObj {
	/// The id the adapter and routes accept: `action_id`, or `@{a_id}` for drafts.
	pub fn key(&self) -> String {
		if self.action_id.is_empty() {
			format!("@{}", self.a_id.load(Ordering::Relaxed))
		} else {
			self.action_id.clone()
		}
	}
}

pub enum Obj {
	File(FileObj),
	Action(ActionObj),
}

/// API keys minted on alice (`.plaintext_key`).
pub struct ApiKeys {
	pub unscoped: String,
	/// `file:{alice doc root}:R`.
	pub file_read: String,
	pub dav: String,
}

/// Non-level files the curated rows use (both tenants); `tenant-crdt-d-active` is also the
/// canonical doc root; `linktarget-crdt-d-active` is the `via-embed` scope target.
const CURATED_FILES: [&str; 13] = [
	"linktarget-crdt-d-active",
	"tenant-blob-p-trashed",
	"tenant-blob-p-pending",
	"tenant-blob-p-tombstoned",
	"folderchild-blob-p-pending",
	"memberowned-blob-p-pending",
	"docchild-blob-d-pending",
	"folder-blob-p-trashed",
	"apkg-blob-p-trashed",
	"tenant-crdt-p-active",
	"tenant-crdt-d-active",
	"tenant-rtdb-d-active",
	"docchild-crdt-d-active",
];

fn meaningful(is_club: bool, s: &FileSpec) -> bool {
	if s.shape == FileShape::MemberOwned && !is_club {
		return false;
	}
	(s.kind == FileKind::Blob && s.life == FileLife::Active)
		|| CURATED_FILES.contains(&s.name.as_str())
}

/// Dedicated `cur-*` object of one (mutating) curated row.
fn is_curated(name: &str) -> bool {
	name.starts_with("cur-")
}

/// Level-layer object: Active Blob file / Active action, not a dedicated `cur-*` object.
pub fn is_level(o: &Obj) -> bool {
	match o {
		Obj::File(f) => {
			f.spec.kind == FileKind::Blob
				&& f.spec.life == FileLife::Active
				&& !is_curated(&f.spec.name)
		}
		Obj::Action(a) => a.spec.life == ActionLife::Active && !is_curated(&a.spec.name),
	}
}

fn vis_name(v: Option<char>) -> char {
	v.map_or('d', |c| c.to_ascii_lowercase())
}

fn file_id(tn: &str, name: &str) -> String {
	// base64url-safe characters only (blob path validation).
	format!("f1~zqm-{}-{name}", tn.trim_end_matches(".test"))
}

/// The tenant's canonical folder (Direct, active) — parent of every `FolderChild`.
fn canon_folder(tn: &str) -> String {
	file_id(tn, "folder-blob-d-active")
}

/// The tenant's canonical doc root (tenant-owned CRDT, Direct, active).
pub fn canon_root(tn: &str) -> String {
	file_id(tn, "tenant-crdt-d-active")
}

fn specs(t: &Tenants) -> Vec<(FileSpec, TnId)> {
	use FileShape::*;
	// Folder and TenantOwned first: FolderChild / DocChild / LinkTarget point at them.
	let shapes = [
		Folder,
		TenantOwned,
		MemberOwned,
		MirroredFshr,
		MirroredPlacer,
		FolderChild,
		DocChild,
		LinkTarget,
		Apkg,
	];
	let mut out = Vec::new();
	for (tn, is_club) in [(&t.alice, false), (&t.club, true)] {
		for shape in shapes {
			for kind in [FileKind::Blob, FileKind::Crdt, FileKind::Rtdb] {
				for vis in VIS {
					for life in [
						FileLife::Active,
						FileLife::Trashed,
						FileLife::Pending,
						FileLife::Tombstoned,
					] {
						let name = format!("{shape:?}-{kind:?}-{}-{life:?}", vis_name(vis))
							.to_ascii_lowercase()
							.replace("tenantowned", "tenant");
						let s = FileSpec { name, tn: tn.id_tag, vis, shape, kind, life };
						if meaningful(is_club, &s) {
							out.push((s, tn.tn_id));
						}
					}
				}
			}
		}
	}
	// Dedicated objects of mutating curated rows.
	let cur = |name: &str, tn: &Tenant, shape, vis, life| {
		let s =
			FileSpec { name: name.into(), tn: tn.id_tag, vis, shape, kind: FileKind::Blob, life };
		(s, tn.tn_id)
	};
	out.extend([
		cur("cur-del-owner", &t.alice, TenantOwned, None, FileLife::Active),
		cur("cur-del-gadmin", &t.alice, TenantOwned, None, FileLife::Active),
		cur("cur-del-leader", &t.club, TenantOwned, None, FileLife::Active),
		cur("cur-del-moderator", &t.club, TenantOwned, None, FileLife::Active),
		cur("cur-del-member", &t.club, MemberOwned, None, FileLife::Active),
		cur("cur-restore-owner", &t.alice, TenantOwned, Some('P'), FileLife::Trashed),
		cur("cur-tag-gwrite", &t.alice, TenantOwned, None, FileLife::Active),
		cur("cur-mirror-del-placer", &t.alice, MirroredPlacer, Some('P'), FileLife::Active),
		cur("cur-mirror-del-remote", &t.alice, MirroredPlacer, Some('P'), FileLife::Active),
		cur("cur-mirror-del-leader", &t.club, MirroredPlacer, Some('P'), FileLife::Active),
		// `DELETE /api/trash` purges a whole tenant's trash: its cells run on `trash` only.
		cur("cur-emptytrash-owner", &t.trash, TenantOwned, Some('P'), FileLife::Trashed),
		cur("cur-emptytrash-mod", &t.trash, TenantOwned, Some('P'), FileLife::Trashed),
	]);
	out
}

/// Seed every meaningful file object plus shares, refs, the FSHR rows and the installed apkg.
pub async fn seed_files(app: &App, t: &Tenants, r: &Remotes) -> Vec<Obj> {
	let mut objs = Vec::new();
	for (spec, tn_id) in specs(t) {
		let obj = plan_file(spec, tn_id, r);
		seed_file(app, &obj).await;
		seed_extras(app, &obj).await;
		if obj.spec.life == FileLife::Tombstoned {
			app.meta_adapter.delete_file(obj.tn_id, &obj.file_id).await.unwrap();
		}
		objs.push(Obj::File(obj));
	}
	objs
}

/// Seed the API keys on alice.
pub async fn seed_api_keys(app: &App, t: &Tenants) -> ApiKeys {
	let tn = t.alice.tn_id;
	let root = canon_root(t.alice.id_tag);
	let file_scope = format!("file:{root}:R");
	let mut keys = Vec::new();
	for (name, scopes) in [
		("zqmatrix-unscoped", None),
		("zqmatrix-file", Some(file_scope.as_str())),
		("zqmatrix-dav", Some("carddav:read,caldav:read")),
	] {
		let k = app
			.auth_adapter
			.create_api_key(tn, CreateApiKeyOptions { name: Some(name), scopes, expires_at: None })
			.await
			.unwrap();
		keys.push(k.plaintext_key.to_string());
	}
	let [unscoped, file_read, dav] = <[String; 3]>::try_from(keys).unwrap();
	ApiKeys { unscoped, file_read, dav }
}

/// Derive every fact of a file object from its spec (pure).
fn plan_file(spec: FileSpec, tn_id: TnId, r: &Remotes) -> FileObj {
	use FileShape::*;
	let tn = spec.tn;
	let id = file_id(tn, &spec.name);
	let upstream = r.connected.id_tag.clone();
	let owner_tag = (spec.shape == MemberOwned).then(|| r.m_contributor.id_tag.clone());
	let upstream_tag = matches!(spec.shape, MirroredFshr | MirroredPlacer).then_some(upstream);
	let fshr =
		(spec.shape == MirroredFshr).then(|| (r.connected.id_tag.clone(), tn.to_string(), "WRITE"));
	let parent_id = match (spec.life, spec.shape) {
		(FileLife::Trashed, _) => Some(TRASH_PARENT_ID.to_string()),
		(_, FolderChild) => Some(canon_folder(tn)),
		_ => None,
	};
	let root_id = (spec.shape == DocChild).then(|| canon_root(tn));

	let u = |id: &crate::fixture::RemoteId, perm, expired| Share {
		subject_type: 'U',
		subject_id: id.id_tag.clone(),
		perm,
		expired,
	};
	let shares = match spec.shape {
		TenantOwned | MemberOwned => vec![
			u(&r.g_read, 'R', false),
			u(&r.g_comment, 'C', false),
			u(&r.g_write, 'W', false),
			u(&r.g_admin, 'A', false),
			u(&r.g_expired, 'W', true),
		],
		Folder => vec![u(&r.g_folder, 'W', false)],
		LinkTarget => {
			vec![Share { subject_type: 'F', subject_id: canon_root(tn), perm: 'R', expired: false }]
		}
		_ => Vec::new(),
	};
	// Share-link refs on the canonical doc root only (R/C/W + the bypass-seeded 'A').
	let refs = if id == canon_root(tn) {
		['R', 'C', 'W', 'A']
			.into_iter()
			.map(|access| ShareRef {
				ref_id: format!(
					"zqref-{}-{}",
					tn.trim_end_matches(".test"),
					access.to_ascii_lowercase()
				),
				access,
			})
			.collect()
	} else {
		Vec::new()
	};
	let blob_id = (spec.kind == FileKind::Blob && spec.shape != Folder)
		.then(|| cloudillo::hasher::hash("b1", blob_data(&spec, &id).as_slice()).to_string());
	let installed = (spec.shape == Apkg && spec.life == FileLife::Active)
		.then(|| (format!("zqmatrix-{}", spec.name), tn.to_string()));

	FileObj {
		spec,
		tn_id,
		file_id: id,
		parent_id,
		root_id,
		owner_tag,
		upstream_tag,
		fshr,
		shares,
		refs,
		blob_id,
		installed,
	}
}

fn blob_data(spec: &FileSpec, file_id: &str) -> Vec<u8> {
	if spec.shape == FileShape::Apkg {
		APKG.to_vec()
	} else {
		format!("zqmatrix {file_id}").into_bytes()
	}
}

/// Write the file row (and its blob variant). Idempotent only on a missing row.
async fn seed_file(app: &App, o: &FileObj) {
	let s = &o.spec;
	let (file_tp, content_type) = match (s.shape, s.kind) {
		(FileShape::Folder, _) => ("FLDR", "cloudillo/folder"),
		(FileShape::Apkg, _) => ("BLOB", "application/zip"),
		(_, FileKind::Blob) => ("BLOB", "text/plain"),
		(_, FileKind::Crdt) => ("CRDT", "cloudillo/quillo"),
		(_, FileKind::Rtdb) => ("RTDB", "cloudillo/rtdb"),
	};
	// Always created pending: variants can only be attached to a pending row.
	let fid = app
		.meta_adapter
		.create_file(
			o.tn_id,
			CreateFile {
				orig_variant_id: None,
				file_id: Some(o.file_id.clone().into()),
				parent_id: o.parent_id.clone().map(Into::into),
				root_id: o.root_id.clone().map(Into::into),
				upstream_tag: o.upstream_tag.clone().map(Into::into),
				owner_tag: o.owner_tag.clone().map(Into::into),
				preset: (s.shape == FileShape::Apkg).then(|| "apkg".into()),
				content_type: content_type.into(),
				file_name: format!("zqmatrix {}", s.name).into(),
				file_tp: Some(file_tp.into()),
				created_at: None,
				tags: None,
				x: None,
				visibility: s.vis,
				channel: None,
				hidden: false,
				status: Some(FileStatus::Pending),
			},
		)
		.await
		.unwrap();
	let FileId::FId(f_id) = fid else { panic!("file {} already existed", o.file_id) };

	if let Some(blob_id) = &o.blob_id {
		let data = blob_data(s, &o.file_id);
		app.blob_adapter
			.create_blob_buf(o.tn_id, blob_id, &data, &CreateBlobOptions {})
			.await
			.unwrap();
		app.meta_adapter
			.create_file_variant(
				o.tn_id,
				f_id,
				FileVariant {
					variant_id: blob_id.as_str(),
					variant: "orig",
					format: if s.shape == FileShape::Apkg { "zip" } else { "txt" },
					size: data.len() as u64,
					resolution: (0, 0),
					available: true,
					global: false,
					duration: None,
					bitrate: None,
					page_count: None,
				},
			)
			.await
			.unwrap();
	}
	if s.life != FileLife::Pending {
		app.meta_adapter.finalize_file(o.tn_id, f_id, &o.file_id).await.unwrap();
	}
}

/// Shares, refs, the FSHR row and the app install — everything beside the file row.
async fn seed_extras(app: &App, o: &FileObj) {
	let meta = &app.meta_adapter;
	let now = Timestamp::now();
	for sh in &o.shares {
		let expires_at = sh.expired.then(|| Timestamp(now.0 - 3600));
		meta.create_share_entry(
			o.tn_id,
			'F',
			&o.file_id,
			o.spec.tn,
			&CreateShareEntry {
				subject_type: sh.subject_type,
				subject_id: sh.subject_id.clone(),
				permission: sh.perm,
				expires_at,
			},
		)
		.await
		.unwrap();
	}
	// The adapter does not validate `access_level`; only the ref route refuses 'A' — so the
	// 'A' ref is seeded by calling the adapter directly, like the others.
	for rf in &o.refs {
		meta.create_ref(
			o.tn_id,
			&rf.ref_id,
			&CreateRefOptions {
				typ: SHARE_FILE_REF_TYPE.into(),
				description: Some("zqmatrix".into()),
				expires_at: None,
				count: None,
				resource_id: Some(o.file_id.clone()),
				access_level: Some(rf.access),
				params: None,
			},
		)
		.await
		.unwrap();
	}
	if let Some((issuer, audience, sub_typ)) = &o.fshr {
		// Only `typ`/`sub_typ`/`issuer_tag` are read by `fshr_grant_level`; the key is the lookup.
		let action_id = format!("a1~zqm-fshr-{}", o.file_id.trim_start_matches("f1~zqm-"));
		let key = format!("FSHR:{}:{audience}", o.file_id);
		meta.create_action(
			o.tn_id,
			&Action {
				action_id: action_id.as_str(),
				typ: "FSHR",
				sub_typ: Some(sub_typ),
				issuer_tag: issuer.as_str(),
				parent_id: None,
				root_id: None,
				audience_tag: Some(audience.as_str()),
				content: None,
				attachments: None,
				subject: Some(o.file_id.as_str()),
				created_at: now,
				expires_at: None,
				visibility: None,
				flags: None,
				x: None,
				hat_tag: None,
				channel: None,
			},
			Some(&key),
		)
		.await
		.unwrap();
	}
	if let (Some((app_name, publisher)), Some(blob_id)) = (&o.installed, &o.blob_id) {
		meta.install_app(
			o.tn_id,
			&InstallApp {
				app_name: app_name.as_str().into(),
				publisher_tag: publisher.as_str().into(),
				version: "1.0.0".into(),
				action_id: format!("a1~zqm-apkg-{}", o.file_id.trim_start_matches("f1~zqm-"))
					.into(),
				file_id: o.file_id.as_str().into(),
				blob_id: blob_id.as_str().into(),
				capabilities: None,
			},
		)
		.await
		.unwrap();
	}
}

// Actions
//*********

fn action_meaningful(is_club: bool, s: &ActionSpec) -> bool {
	if s.typ == ActionShape::HatRelayed && !(is_club && s.issuer == Issuer::Remote) {
		return false;
	}
	if matches!(s.typ, ActionShape::DirectAudience | ActionShape::OnContainer) && s.vis.is_some() {
		return false;
	}
	if s.life.is_draft() && s.issuer != Issuer::Tenant {
		return false;
	}
	// Non-active lives the curated rows use: every `post-{p,d}-*`, `container-p-tenant-deleted`.
	s.life == ActionLife::Active
		|| (s.typ == ActionShape::Post && matches!(s.vis, Some('P') | None))
		|| (s.name == "container-p-tenant-deleted")
}

fn action_specs(t: &Tenants) -> Vec<(ActionSpec, TnId)> {
	use ActionLife::*;
	use ActionShape::*;
	// Container first: every Child points at an active tenant-issued container.
	let shapes = [Container, Post, Child, HatRelayed, DirectAudience, OnContainer];
	let lives = [Active, Deleted, Pending, Dismissed, Draft, Scheduled];
	let mut out = Vec::new();
	for (tn, is_club) in [(&t.alice, false), (&t.club, true)] {
		for typ in shapes {
			for vis in VIS {
				for issuer in [Issuer::Tenant, Issuer::Remote] {
					for life in lives {
						let name = format!("{typ:?}-{}-{issuer:?}-{life:?}", vis_name(vis))
							.to_ascii_lowercase();
						let s = ActionSpec {
							name,
							tn: tn.id_tag,
							typ,
							vis,
							issuer,
							life,
							to_tenant: false,
						};
						if action_meaningful(is_club, &s) {
							out.push((s, tn.tn_id));
						}
					}
				}
			}
		}
	}
	// Dedicated public `POST`s of mutating curated rows.
	let cur = |name: &str, tn: &Tenant, issuer, life, to_tenant| {
		let s = ActionSpec {
			name: name.into(),
			tn: tn.id_tag,
			typ: Post,
			vis: Some('P'),
			issuer,
			life,
			to_tenant,
		};
		(s, tn.tn_id)
	};
	let (a, c) = (&t.alice, &t.club);
	out.extend([
		cur("cur-dismiss-owner", a, Issuer::Tenant, Dismissed, false),
		cur("cur-dismiss-leader", c, Issuer::Tenant, Dismissed, false),
		cur("cur-draft-patch", a, Issuer::Tenant, Draft, false),
		cur("cur-draft-publish", a, Issuer::Tenant, Draft, false),
		cur("cur-draft-publish-at", a, Issuer::Tenant, Draft, false),
		cur("cur-sched-cancel", a, Issuer::Tenant, Scheduled, false),
		cur("cur-draft-delete", a, Issuer::Tenant, Draft, false),
		cur("cur-del-action-owner", a, Issuer::Remote, Active, false),
		cur("cur-del-action-leader", c, Issuer::Remote, Active, false),
		cur("cur-accept-mod", c, Issuer::Remote, Pending, true),
		cur("cur-reject-owner", c, Issuer::Remote, Pending, true),
		cur("cur-reject-mod", c, Issuer::Remote, Pending, true),
	]);
	out
}

/// Seed every meaningful action object, its `APRV` endorsement and `SUBS` row.
pub async fn seed_actions(app: &App, t: &Tenants, r: &Remotes) -> Vec<Obj> {
	let mut containers: HashMap<(TnId, Option<char>), String> = HashMap::new();
	let mut objs = Vec::new();
	for (spec, tn_id) in action_specs(t) {
		let container = || containers[&(tn_id, spec.vis)].clone();
		let parent_id = (spec.typ == ActionShape::Child).then(&container);
		let subject = (spec.typ == ActionShape::OnContainer).then(&container);
		let o = seed_action(app, spec, tn_id, parent_id, subject, r).await;
		if o.spec.typ == ActionShape::Container
			&& o.spec.issuer == Issuer::Tenant
			&& o.spec.life == ActionLife::Active
		{
			containers.insert((tn_id, o.spec.vis), o.action_id.clone());
		}
		objs.push(Obj::Action(o));
	}
	objs
}

/// Index every seeded file and (non-draft) action directly — the scheduler is not running.
pub async fn index_all(app: &App, objs: &[Obj]) {
	for o in objs {
		match o {
			Obj::File(f) => {
				cloudillo_search::objects::index_file(app, f.tn_id, &f.file_id).await.unwrap();
			}
			Obj::Action(a) if !a.action_id.is_empty() => {
				cloudillo_search::objects::index_action(app, a.tn_id, &a.action_id)
					.await
					.unwrap();
			}
			Obj::Action(_) => {}
		}
	}
}

fn remote_issuer<'a>(s: &ActionSpec, r: &'a Remotes) -> Option<&'a RemoteId> {
	match (s.issuer, s.typ) {
		(Issuer::Tenant, _) => None,
		(_, ActionShape::HatRelayed) => Some(&r.hatted),
		_ if s.tn == CLUB => Some(&r.m_contributor),
		_ => Some(&r.connected),
	}
}

async fn seed_action(
	app: &App,
	spec: ActionSpec,
	tn_id: TnId,
	parent_id: Option<String>,
	subject: Option<String>,
	r: &Remotes,
) -> ActionObj {
	use ActionShape::*;
	let remote = remote_issuer(&spec, r);
	let typ = match spec.typ {
		Container => "CONV",
		Child => "MSG",
		OnContainer => "INVT",
		_ => "POST",
	};
	let text = format!("zqmatrix {}", spec.name);
	let content = if typ == "CONV" { json!({ "name": text }) } else { json!(text) };
	let audience_tag = match spec.typ {
		DirectAudience | OnContainer => Some(r.direct.id_tag.clone()),
		HatRelayed => Some(spec.tn.to_string()),
		_ if spec.to_tenant => Some(spec.tn.to_string()),
		_ => None,
	};
	let mut o = ActionObj {
		issuer_tag: remote.map_or_else(|| spec.tn.to_string(), |x| x.id_tag.clone()),
		hat_tag: (spec.typ == HatRelayed).then(|| r.peer.id_tag.clone()),
		spec,
		tn_id,
		action_id: String::new(),
		a_id: AtomicU64::new(0),
		typ,
		audience_tag,
		parent_id,
		subject,
		content,
		token: None,
		aprv_id: None,
		subs_id: None,
	};
	if o.spec.life.is_draft() {
		seed_draft(app, &o).await;
		return o;
	}

	let token = match remote {
		None => app
			.auth_adapter
			.create_action_token(
				tn_id,
				CreateAction {
					typ: typ.into(),
					parent_id: o.parent_id.as_deref().map(Into::into),
					audience_tag: o.audience_tag.as_deref().map(Into::into),
					subject: o.subject.as_deref().map(Into::into),
					content: Some(o.content.clone()),
					visibility: o.spec.vis,
					..Default::default()
				},
			)
			.await
			.unwrap()
			.to_string(),
		Some(rm) => sign(
			rm,
			&ActionToken {
				t: typ.into(),
				c: Some(o.content.clone()),
				p: o.parent_id.as_deref().map(Into::into),
				aud: o.audience_tag.as_deref().map(Into::into),
				sub: o.subject.as_deref().map(Into::into),
				v: o.spec.vis,
				h: o.hat_tag.as_deref().map(Into::into),
				..token_base(rm)
			},
		),
	};
	o.action_id = cloudillo::hasher::hash("a", token.as_bytes()).to_string();
	o.token = Some(token);
	insert_obj(app, &o).await;

	if o.spec.typ == HatRelayed {
		// `peer` endorses the post to club (shape per `check_hat_aprv` / `check_hat_attestation`).
		let aprv = sign(
			&r.peer,
			&ActionToken {
				t: "APRV".into(),
				c: Some(json!({ "r": "contributor" })),
				aud: Some(o.spec.tn.into()),
				sub: Some(o.action_id.as_str().into()),
				..token_base(&r.peer)
			},
		);
		let aprv_id = cloudillo::hasher::hash("a", aprv.as_bytes()).to_string();
		let row = Action {
			typ: "APRV",
			issuer_tag: r.peer.id_tag.as_str(),
			audience_tag: Some(o.spec.tn),
			content: Some(r#"{"r":"contributor"}"#),
			subject: Some(o.action_id.as_str()),
			created_at: Timestamp::now(),
			..Default::default()
		};
		insert_signed(app, tn_id, &row, &aprv_id, &aprv, None, 'A').await;
		o.aprv_id = Some(aprv_id);
	}
	if o.spec.typ == Container {
		// `subscriber` subscribes to every container (its `S` visibility gate).
		let subs = sign(
			&r.subscriber,
			&ActionToken {
				t: "SUBS".into(),
				aud: Some(o.issuer_tag.as_str().into()),
				sub: Some(o.action_id.as_str().into()),
				..token_base(&r.subscriber)
			},
		);
		let subs_id = cloudillo::hasher::hash("a", subs.as_bytes()).to_string();
		let key = format!("SUBS:{}:{}", o.action_id, r.subscriber.id_tag);
		let row = Action {
			typ: "SUBS",
			issuer_tag: r.subscriber.id_tag.as_str(),
			audience_tag: Some(o.issuer_tag.as_str()),
			subject: Some(o.action_id.as_str()),
			created_at: Timestamp::now(),
			..Default::default()
		};
		insert_signed(app, tn_id, &row, &subs_id, &subs, Some(&key), 'A').await;
		o.subs_id = Some(subs_id);
	}
	o
}

fn token_base(r: &RemoteId) -> ActionToken {
	ActionToken {
		iss: r.id_tag.as_str().into(),
		k: r.key_id.as_str().into(),
		iat: Timestamp::now(),
		..Default::default()
	}
}

/// The canonical row of an action object; `action_id` is set on finalize.
fn obj_row<'a>(o: &'a ActionObj, content: &'a str) -> Action<&'a str> {
	Action {
		typ: o.typ,
		issuer_tag: o.issuer_tag.as_str(),
		parent_id: o.parent_id.as_deref(),
		root_id: o.parent_id.as_deref(),
		audience_tag: o.audience_tag.as_deref(),
		content: Some(content),
		subject: o.subject.as_deref(),
		created_at: Timestamp::now(),
		visibility: o.spec.vis,
		hat_tag: o.hat_tag.as_deref(),
		channel: None,
		..Default::default()
	}
}

async fn insert_obj(app: &App, o: &ActionObj) {
	let content = serde_json::to_string(&o.content).unwrap();
	let token = o.token.as_deref().unwrap_or_default();
	let row = obj_row(o, &content);
	insert_signed(app, o.tn_id, &row, &o.action_id, token, None, o.spec.life.status()).await;
}

/// Production sequence (`task.rs` `finalize_action`): create (`P`, no id) → finalize (`A`,
/// id) → store token; then patch the lifecycle status. Also the recreate path.
async fn insert_signed(
	app: &App,
	tn_id: TnId,
	row: &Action<&str>,
	action_id: &str,
	token: &str,
	key: Option<&str>,
	status: char,
) {
	let meta = &app.meta_adapter;
	let ActionId::AId(a_id) = meta.create_action(tn_id, row, key).await.unwrap() else {
		panic!("action {action_id} already existed")
	};
	meta.finalize_action(tn_id, a_id, action_id, FinalizeActionOptions::default())
		.await
		.unwrap();
	meta.store_action_token(tn_id, action_id, token).await.unwrap();
	if status != 'A' {
		let opts = UpdateActionDataOptions { status: Patch::Value(status), ..Default::default() };
		meta.update_action_data(tn_id, action_id, &opts).await.unwrap();
	}
}

/// `@` draft: row without `action_id` or token, status `R`/`S`. Stores the new `a_id` on `o`.
async fn seed_draft(app: &App, o: &ActionObj) {
	let content = serde_json::to_string(&o.content).unwrap();
	let row = obj_row(o, &content);
	let ActionId::AId(a_id) = app.meta_adapter.create_action(o.tn_id, &row, None).await.unwrap()
	else {
		panic!("draft {} already existed", o.spec.name)
	};
	o.a_id.store(a_id, Ordering::Relaxed);
	let created_at = if o.spec.life == ActionLife::Scheduled {
		Patch::Value(Timestamp(Timestamp::now().0 + 86400))
	} else {
		Patch::Undefined
	};
	let opts = UpdateActionDataOptions {
		status: Patch::Value(o.spec.life.status()),
		created_at,
		..Default::default()
	};
	app.meta_adapter.update_action_data(o.tn_id, &o.key(), &opts).await.unwrap();
}

// vim: ts=4
