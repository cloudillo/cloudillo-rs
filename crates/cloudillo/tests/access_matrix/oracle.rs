// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Independent oracle: the *intended* access policy (file access ladder, community roles,
//! ABAC visibility, token scopes) and the DSL behaviour flags, re-stated from scratch.
//! It never calls production code. Every early return names its rung in `rule` (the report's
//! grouping key); a trailing `?` marks a doc gap resolved to the stricter reading.
//!
//! Precondition: the object lives on the subject's host (`obj_host(o) == subject.host`).

use cloudillo::types::AccessLevel;

use crate::objects::{
	ActionLife, ActionObj, ActionShape, FileKind, FileLife, FileObj, FileShape, Obj, canon_folder,
	canon_root,
};
use crate::ops::{ActionOp, FileOp, InboxCell, Op};
use crate::subjects::{CredKind, Grant, Hostile, MintCell, Relation, SubjectFacts};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
	Allow,
	Deny,
	Present,
	Absent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expect {
	pub outcome: Outcome,
	pub rule: &'static str,
	/// Expected granted / reported level (`Ws`, `File(Metadata)`, `File(List)` rows).
	pub level: Option<AccessLevel>,
}

fn ex(outcome: Outcome, rule: &'static str) -> Expect {
	Expect { outcome, rule, level: None }
}

fn allow(rule: &'static str) -> Expect {
	ex(Outcome::Allow, rule)
}

fn deny(rule: &'static str) -> Expect {
	ex(Outcome::Deny, rule)
}

fn absent(rule: &'static str) -> Expect {
	ex(Outcome::Absent, rule)
}

fn present(rule: &'static str, level: Option<AccessLevel>) -> Expect {
	Expect { outcome: Outcome::Present, rule, level }
}

// Subject
//*********

/// Role hierarchy, lowest first; index = rank.
const ROLES: [&str; 6] = ["public", "follower", "supporter", "contributor", "moderator", "leader"];
const SUPPORTER: usize = 2;
const CONTRIBUTOR: usize = 3;
const MODERATOR: usize = 4;
const LEADER: usize = 5;

/// Subject visibility levels (`Public < Verified < 2nd < Follower < Connected`).
const PUBLIC: u8 = 0;
const VERIFIED: u8 = 1;
const FOLLOWER: u8 = 3;
const CONNECTED: u8 = 4;

/// Holds a `SUBS` row on every seeded container (`fixture::remote("subscriber")`).
const SUBSCRIBER: &str = "subscriber.test";

/// The subject after the gate rules, as the rungs see it.
struct Who<'a> {
	/// Asserted identity; `None` = anonymous (incl. every scoped token: authority is the scope).
	id: Option<&'a str>,
	/// The holder's own identity, kept for scoped tokens that carry a `sub` (`id` drops it).
	/// Read only by owner-only lifecycle rules (pending uploads), never for authority.
	ident: Option<&'a str>,
	/// The tenant account itself, unscoped (session or unscoped API key).
	owner: bool,
	role: usize,
	vis: u8,
	grants: &'a [Grant],
	/// `file:{id}:{R|C|W}` — added on top of the guest view; lists and search stay confined to it.
	scope: Option<(&'a str, AccessLevel)>,
}

impl Who<'_> {
	fn leader(&self) -> bool {
		self.scope.is_none() && self.role >= LEADER
	}
}

fn role_rank(roles: &[String]) -> usize {
	roles
		.iter()
		.filter_map(|r| ROLES.iter().position(|x| x == r))
		.max()
		.unwrap_or(0)
}

fn perm_level(c: char) -> AccessLevel {
	match c {
		'A' => AccessLevel::Admin,
		'W' => AccessLevel::Write,
		'C' => AccessLevel::Comment,
		'R' => AccessLevel::Read,
		_ => AccessLevel::None,
	}
}

/// `file:{file_id}:{R|C|W}`; `'A'`, blank ids and anything else are unrecognised.
fn parse_file_scope(s: &str) -> Option<(&str, AccessLevel)> {
	let mut p = s.split(':');
	let (Some("file"), Some(id), Some(l), None) = (p.next(), p.next(), p.next(), p.next()) else {
		return None;
	};
	let level = match l {
		"R" | "C" | "W" => perm_level(l.chars().next()?),
		_ => return None,
	};
	(!id.is_empty()).then_some((id, level))
}

/// Paths a `file:` scope may reach (`scope.rs` `scope_permits`, re-stated).
fn file_scope_path(op: &Op) -> bool {
	matches!(op, Op::File(_) | Op::Ws(..) | Op::Search)
}

/// Gate rules: credential valid, host binding, scope path allowlist. `Err` = the failed gate.
fn gate<'a>(s: &'a SubjectFacts, op: &Op) -> Result<Who<'a>, &'static str> {
	use Hostile::*;
	if matches!(s.hostile, Some(CrossTenant | Expired | WrongIss | Tampered)) {
		return Err("gate.credential");
	}
	if s.kind == CredKind::Idp {
		return Err("gate.idp-key");
	}
	if let Some(sc) = s.scope.as_deref() {
		// Scope = guest + grant: never less than anonymous, never an identity rung. A recognised
		// `file:` scope adds its grant on paths it permits; anything else is the plain guest.
		let scope = parse_file_scope(sc).filter(|_| file_scope_path(op));
		let ident = s.id_tag.as_deref();
		return Ok(Who { id: None, ident, owner: false, role: 0, vis: PUBLIC, grants: &[], scope });
	}
	let owner = s.relation == Relation::Owner;
	let vis = match (s.id_tag.is_some(), s.relation) {
		(false, _) => PUBLIC,
		(_, Relation::Follower) => FOLLOWER,
		(_, Relation::Owner | Relation::Connected | Relation::Member) => CONNECTED,
		_ => VERIFIED,
	};
	Ok(Who {
		id: s.id_tag.as_deref(),
		ident: s.id_tag.as_deref(),
		owner,
		// Owner sessions and unscoped tenant API keys carry the owner role set (`leader`).
		role: if owner { LEADER } else { role_rank(&s.roles) },
		vis,
		grants: &s.grants,
		scope: None,
	})
}

/// Required subject level of a visibility char; `None` = Direct (`S`/NULL/unknown on files).
fn vis_need(v: Option<char>) -> Option<u8> {
	match v {
		Some('P') => Some(0),
		Some('V') => Some(1),
		Some('2') => Some(2),
		Some('F') => Some(3),
		Some('C') => Some(4),
		_ => None,
	}
}

// Files
//*******

/// Scope rung: matching file, doc-tree child, folder child, or `F` link (capped by `.min`).
fn scope_level(scope: (&str, AccessLevel), f: &FileObj) -> Option<AccessLevel> {
	let (id, l) = scope;
	if f.file_id == id || f.root_id.as_deref() == Some(id) || f.parent_id.as_deref() == Some(id) {
		return Some(l);
	}
	f.shares
		.iter()
		.find(|s| s.subject_type == 'F' && s.subject_id == id && !s.expired)
		.map(|s| l.min(perm_level(s.perm)))
}

/// The access ladder: scope, ownership, FSHR, roles, visibility. Mirrored rows (`upstream_tag`)
/// take their content level from the FSHR grant, else placer Read — never Admin, no role reach.
fn file_ladder(w: &Who, f: &FileObj) -> (AccessLevel, &'static str) {
	let owner = f.owner_tag.as_deref().unwrap_or(f.spec.tn);
	let mirrored = f.upstream_tag.is_some();
	if w.id == Some(owner) && !mirrored {
		return (AccessLevel::Admin, "file.owner");
	}
	if let Some(id) = w.id {
		if let Some(s) = f
			.shares
			.iter()
			.find(|s| s.subject_type == 'U' && s.subject_id == id && !s.expired)
		{
			return (perm_level(s.perm), "file.share");
		}
		if let Some(g) =
			w.grants.iter().find(|g| Some(&g.file_id) == f.parent_id.as_ref() && !g.expired)
		{
			return (perm_level(g.perm), "file.share.inherited");
		}
	}
	if !mirrored {
		// Leaders manage shares on local community files.
		if w.role >= LEADER {
			return (AccessLevel::Admin, "file.role.leader");
		}
		if w.role >= CONTRIBUTOR {
			return (AccessLevel::Write, "file.role.write");
		}
		// The follower rank grants nothing; role access starts at `supporter`.
		if w.role >= SUPPORTER {
			return (AccessLevel::Read, "file.role.read");
		}
	}
	if let Some((iss, aud, sub)) = &f.fshr
		&& w.id == Some(aud.as_str())
		&& f.upstream_tag.as_ref() == Some(iss)
	{
		// Keyed by the content, which on a BLOB may back several entries: capped at Read there.
		let l = if *sub == "WRITE" && f.spec.kind != FileKind::Blob {
			AccessLevel::Write
		} else {
			AccessLevel::Read
		};
		return (l, "file.fshr");
	}
	// The placer (the tenant) of a Pin/Place copy.
	if mirrored && w.id == Some(owner) {
		return (AccessLevel::Read, "file.placer");
	}
	(AccessLevel::None, "file.none")
}

/// Lifecycle gate, `Some(rule)` = the row does not exist for `w` (`level` = its ladder level).
/// Pending: its real owner only. Trashed: unscoped record authority, or on a local row Admin
/// level or a moderator. Tombstoned: nobody.
fn file_lifecycle(w: &Who, f: &FileObj, level: AccessLevel) -> Option<&'static str> {
	let owner = f.owner_tag.as_deref().unwrap_or(f.spec.tn);
	let mirrored = f.upstream_tag.is_some();
	match f.spec.life {
		FileLife::Active => None,
		FileLife::Tombstoned => Some("file.life.tombstoned"),
		FileLife::Pending => (w.ident != Some(owner)).then_some("file.life.pending"),
		FileLife::Trashed => {
			let may = w.scope.is_none()
				&& (w.id == Some(owner)
					|| (!mirrored && (level == AccessLevel::Admin || w.role >= MODERATOR)));
			(!may).then_some("file.life.trashed")
		}
	}
}

/// Effective level: lifecycle over scope → ladder → visibility ladder.
fn file_access(w: &Who, f: &FileObj) -> (AccessLevel, &'static str) {
	let (l, rule) = file_level(w, f);
	match file_lifecycle(w, f, l) {
		Some(r) => (AccessLevel::None, r),
		None => (l, rule),
	}
}

/// Scope → ladder → visibility ladder (read only). A scoped caller outside its scope is a
/// guest: the ladder yields nothing for it, the visibility rung decides.
fn file_level(w: &Who, f: &FileObj) -> (AccessLevel, &'static str) {
	if let Some(l) = w.scope.and_then(|sc| scope_level(sc, f)) {
		return (l, "file.scope");
	}
	let (l, rule) = file_ladder(w, f);
	if l >= AccessLevel::Read {
		return (l, rule);
	}
	match vis_need(f.spec.vis) {
		None => (AccessLevel::None, "file.vis.direct"),
		Some(n) if w.vis >= n => (AccessLevel::Read, "file.visibility"),
		Some(_) => (AccessLevel::None, "file.vis.insufficient"),
	}
}

/// Listed = readable ∧ default filters (active, not trashed/pending) ∧ scope subtree. Tree
/// members appear only when the query names their root: a document child lists only under a
/// scope (the scope tree names its root) and is never searched; a link target is outside a
/// scope's tree but an ordinary file to unscoped callers.
fn file_listed(w: &Who, f: &FileObj, search: bool) -> Expect {
	if f.spec.life != FileLife::Active {
		return absent("list.state");
	}
	file_query(w, f, search)
}

/// A targeted file query (`?fileId=`, `?parentId=`, `?status=`): any lifecycle (bar pending
/// under `?parentId=`), under the lifecycle gate; tree and scope confinement as a listing. Rows
/// are judged, not levels.
fn file_targeted(w: &Who, f: &FileObj) -> Expect {
	Expect { level: None, ..file_query(w, f, false) }
}

fn file_query(w: &Who, f: &FileObj, search: bool) -> Expect {
	let tree_member = match f.spec.shape {
		FileShape::DocChild => search || w.scope.is_none(),
		FileShape::LinkTarget => w.scope.is_some(),
		_ => false,
	};
	if tree_member {
		return absent("list.tree-member");
	}
	if w.scope.is_some_and(|sc| scope_level(sc, f).is_none()) {
		return absent("file.scope.out");
	}
	let (l, rule) = file_access(w, f);
	if l >= AccessLevel::Read { present(rule, Some(l)) } else { absent(rule) }
}

// Actions
//*********

/// `Ok(rule)` = visible. Tenant → issuer → audience → subscriber bridge → visibility ladder.
fn action_visible(w: &Who, a: &ActionObj) -> Result<&'static str, &'static str> {
	if a.spec.life.is_draft() {
		// Drafts are owned by their issuer (always the tenant here) and never shown to others.
		return if w.owner { Ok("action.draft.issuer") } else { Err("action.draft") };
	}
	if a.spec.life == ActionLife::Deleted {
		return Err("action.deleted?");
	}
	if w.owner {
		return Ok("action.tenant");
	}
	if w.leader() {
		return Ok("action.leader");
	}
	if w.id == Some(a.issuer_tag.as_str()) {
		return Ok("action.issuer");
	}
	if w.id.is_some() && w.id == a.audience_tag.as_deref() {
		return Ok("action.audience");
	}
	if w.id == Some(SUBSCRIBER) && matches!(a.spec.vis, Some('S') | None) {
		match a.spec.typ {
			ActionShape::Container => return Ok("action.subscriber"),
			ActionShape::Child => return Ok("action.subscriber.child?"),
			_ => {}
		}
	}
	match vis_need(a.spec.vis) {
		// The subscriber bridge never runs through `subject` for a Direct row.
		None if a.spec.vis == Some('S') => Err("action.vis.subscribers"),
		None => Err("action.vis.direct"),
		Some(n) if w.vis >= n => Ok("action.visibility"),
		Some(_) => Err("action.vis.insufficient"),
	}
}

fn action_listed(w: &Who, a: &ActionObj) -> Expect {
	match action_visible(w, a) {
		Ok(r) => present(r, None),
		Err(r) => absent(r),
	}
}

/// Searched = listed ∧ indexable; a `file:` scope confines to its document tree, files only.
/// Search hits carry no level.
fn searched(w: &Who, o: &Obj) -> Expect {
	match o {
		Obj::File(f) => Expect { level: None, ..file_listed(w, f, true) },
		Obj::Action(_) if w.scope.is_some() => absent("search.scope.files-only"),
		Obj::Action(a) if a.spec.life.is_draft() => absent("search.draft"),
		// `INVT` has no search manifest.
		Obj::Action(a) if a.spec.typ == ActionShape::OnContainer => absent("search.unindexed"),
		Obj::Action(a) => action_listed(w, a),
	}
}

// Entry points
//**************

/// Whether the listing `op` itself is served to `s`: `list.ok`, or the failed gate.
pub fn listing(s: &SubjectFacts, op: &Op) -> Expect {
	gate(s, op).map_or_else(deny, |_| allow("list.ok"))
}

/// Level-layer expectation of `op` by `s` on `o` (same host). A failed gate is a Deny on
/// every route, optional-auth included. Curated cases live in `curated.rs`, not here.
#[allow(clippy::many_single_char_names)]
pub fn expected(s: &SubjectFacts, o: &Obj, op: &Op) -> Expect {
	let w = match gate(s, op) {
		Ok(w) => w,
		Err(rule) => return deny(rule),
	};
	match (op, o) {
		(Op::File(FileOp::List), Obj::File(f)) => file_listed(&w, f, false),
		// A pending upload is never browsed, not even by its owner; `?fileId=` reaches it.
		(Op::File(FileOp::ByParent), Obj::File(f)) if f.spec.life == FileLife::Pending => {
			absent("list.pending")
		}
		(Op::File(FileOp::ById | FileOp::ByParent), Obj::File(f)) => file_targeted(&w, f),
		(Op::File(FileOp::ByStatus(c)), Obj::File(f)) => match (c, f.spec.life) {
			// Tombstones are never listable (`?status=D` is refused).
			(_, FileLife::Tombstoned) | ('D', _) => absent("list.status.tombstone"),
			('P', FileLife::Pending) => file_targeted(&w, f),
			_ => absent("list.status"),
		},
		// Emptying the trash purges the rows the caller may manage, so the route gate decides:
		// unscoped, and a contributor or up (the owner holds `leader`).
		(Op::File(FileOp::EmptyTrash), _) => {
			if w.scope.is_none() && (w.owner || w.role >= CONTRIBUTOR) {
				allow("file.trash.empty")
			} else {
				deny("file.trash.empty.authority")
			}
		}
		(Op::File(FileOp::Metadata), Obj::File(f)) => {
			let (l, rule) = file_access(&w, f);
			if l >= AccessLevel::Read {
				Expect { outcome: Outcome::Allow, rule, level: Some(l) }
			} else if w.leader()
				&& f.spec.life == FileLife::Active
				&& matches!(f.spec.shape, FileShape::MirroredFshr | FileShape::MirroredPlacer)
			{
				// A leader sees every row of the community's file table; content stays FSHR-only.
				Expect { outcome: Outcome::Allow, rule: "file.mirror.leader-meta", level: None }
			} else {
				deny(rule)
			}
		}
		// `PATCH {}`: the write guard only, no mutation.
		(Op::File(FileOp::Patch), Obj::File(f)) => {
			let (l, rule) = file_access(&w, f);
			if w.leader() || l >= AccessLevel::Write { allow(rule) } else { deny(rule) }
		}
		(Op::Search, _) => searched(&w, o),
		(Op::Action(ActionOp::Get), Obj::Action(a)) => {
			action_visible(&w, a).map_or_else(deny, allow)
		}
		(Op::Action(ActionOp::List), Obj::Action(a)) => action_listed(&w, a),
		// Drafts are the tenant's own: only the unscoped owner creates or schedules one.
		(Op::Action(ActionOp::CreateDraft | ActionOp::PublishAt), _) => {
			if w.owner {
				allow("action.draft.issuer")
			} else {
				deny("action.draft")
			}
		}
		// Every guarded tier refuses a caller with no identity (probed on Direct objects).
		(Op::Probe(..), _) if w.id.is_none() && w.scope.is_none() => deny("probe.tier-gate"),
		_ => panic!("{} is not a level-layer op", op.name()),
	}
}

/// Inbound federation: DSL `allow_unknown` / `requires_connected` / `requires_subscription` /
/// `local_only`, plus the acceptance rules R1–R3 (REPOST, STAT, APRV; see below).
pub fn expected_inbox(c: &InboxCell) -> Expect {
	// "Known" = the tenant follows or is connected to the issuer; a follower-only issuer is
	// unknown.
	let known = matches!(c.rel, Relation::WeFollow | Relation::Connected | Relation::Member);
	let connected = matches!(c.rel, Relation::Connected | Relation::Member);
	match c.typ {
		// A blocked issuer is refused ahead of every type rule, `allow_unknown` included.
		_ if c.rel == Relation::Blocked => deny("inbox.issuer-restricted"),
		// CONN (incl. CONN:UPD) is allow_unknown; an update is inert unless the issuer is
		// connected or pending (`native_hooks/conn.rs`). The receive-side subtypes ride their
		// base type's definition; what they may change is `inbound_effects`'.
		"CONN" | "CONN:UPD" | "CONN:ACC" | "CONN:DEL" | "FLLW" | "FLLW:DEL" | "REACT" | "CMNT"
		| "PRES" | "SUBS" | "SUBS:UPD" => allow("inbox.allow-unknown"),
		"APKG" => deny("inbox.local-only"),
		// allow_unknown, but `idp.enabled` is off on the host (the hook refuses).
		"IDP:REG" => deny("inbox.idp-reg.disabled"),
		// Hat endorsement: APRV authority over X when `APRV.iss == X.h`.
		"APRV" if c.hat && c.rel == Relation::PeerHat && c.target => allow("inbox.aprv.hat"),
		// A hat-admitted APRV still needs authority over its own subject.
		"APRV" if c.hat && c.rel == Relation::PeerHat => deny("inbox.aprv.hat.subject-authority"),
		"APRV" if c.hat => deny("inbox.aprv.not-hat"),
		// A bundled subject counts only once its signature verifies.
		"APRV" if c.forged => deny("inbox.aprv.subject-unverified"),
		// An APRV is signed by the approved action's audience; a fresh issuer never is.
		"APRV" => deny("inbox.aprv.not-audience"),
		"PRINVT" if connected => allow("inbox.connected"),
		"PRINVT" => deny("inbox.requires-connected"),
		"MSG" if c.target => deny("inbox.msg.requires-subscription"),
		// An INVT on our CONV is the tenant's or a moderator subscriber's; a revocation also the
		// original inviter's. A fresh issuer is none of them, whatever its relation.
		"INVT" | "INVT:DEL" => deny("inbox.invt.conv-authority"),
		_ if known => allow("inbox.known"),
		// Subject-anchored rules override `allow_unknown: false`: R1 (REPOST on the tenant's
		// own public subject) and R2 (STAT from anyone).
		"REPOST" => allow("inbox.repost-r1"),
		"STAT" if c.target => allow("inbox.stat-r2"),
		// R2 holds only for content held here.
		"STAT" => deny("inbox.stat-r2.not-held"),
		// POST, POST:LDOC, MSG (bare), CONV, FSHR, FSHR:DEL, INVT.
		_ => deny("inbox.unknown-issuer"),
	}
}

/// Expected outcome of a token-exchange cell, by its fixture name.
pub fn expected_mint(c: &MintCell) -> Expect {
	let n = c.name.as_str();
	match n {
		// A hatted session mints only `file:` scopes, and the room gate still applies.
		"scope-hatted@club" => return allow("mint.hat.scoped"),
		"scope-hatted-closed@club" => return deny("mint.hat.closed-room"),
		"refresh-hatted@club" | "proxytoken-hatted@club" => return deny("mint.hat.refresh"),
		_ => {}
	}
	match n {
		// Via mints over a `W` link: capped to the caller's own `R`, refused without access to
		// the source or without a link.
		"via-gread-overask@alice" | "via-scoped-overask@alice" => return allow("mint.via.capped"),
		"via-noaccess-stranger@alice" => return deny("mint.via.no-access"),
		"via-nolink@alice" => return deny("mint.via.no-link"),
		_ => {}
	}
	let legit = [
		"login-",
		"proxy-",
		"ref-sharelink-",
		"scope-owner-scoped-",
		"scope-g-write-scoped-",
		"via-",
		"xchg-apikey-unscoped@",
		"xchg-apikey-file@",
	];
	if legit.iter().any(|p| n.starts_with(p)) || n == "scope-apkg@alice" {
		return allow("mint.legit");
	}
	match n {
		// Re-scoping never widens past the caller's own level: the scope is capped, not refused.
		"scope-g-read-overask@alice" => allow("mint.overask"),
		// A community leader holds the community's publishing authority.
		"scope-apkg-m-leader@club" => allow("mint.apkg.leader"),
		"scope-apkg-m-contributor@club" => deny("mint.apkg.role"),
		// Capability keys reach PIM routes directly; a scoped key is never exchanged.
		"xchg-apikey-dav@alice" => deny("mint.capability-key"),
		// A key, or a ref, is its own tenant's: refused on another host.
		"xchg-apikey-xtenant@club" | "ref-xtenant@club" | "ref-once-xtenant@club" => {
			deny("mint.cross-tenant")
		}
		// The wrong-host attempt left the single-use ref unspent.
		"ref-once@alice" => allow("mint.ref.not-burned"),
		// A scoped bearer never mints a session, not even its own refresh.
		"refresh-sharelink-r@alice" | "refresh-sharelink-w@alice" | "refresh-apikey-file@alice" => {
			deny("mint.refresh.scoped")
		}
		"ref-deleted@alice" => deny("mint.ref.deleted"),
		"ref-folderlink-r@alice" => allow("mint.ref.folder"),
		// Open gap: `refresh=true` re-validates uncounted and tokenless; once fixed, a Deny.
		"ref-refresh@alice" => allow("mint.ref.refresh"),
		// Unrecognised scopes fail closed (400); a DAV capability only narrows a session.
		"scope-foreign-ask@alice" => deny("mint.scope.unrecognised"),
		"scope-carddav@alice" => allow("mint.scope.dav"),
		// A scope is only for a file the caller already reaches.
		"scope-stranger-root@alice" => deny("mint.scope.no-access"),
		// `hat=` excludes every other mode, `scope=` included (400).
		"hatscope-hatted@club" => deny("mint.hat.with-scope"),
		// SADM narrows its own session to a document like any owner.
		"scope-sadm@admin" => allow("mint.sadm.scoped"),
		// A Blocked profile still exchanges a PROXY, for a session with no role (claims); a
		// hat never lifts the block.
		"blocked-session@club" => allow("mint.blocked.no-roles"),
		"blocked-hat@club" => deny("mint.blocked.hat"),
		_ if n.starts_with("hostile-proxy-") => deny("mint.hostile-proxy"),
		_ => deny("mint.unlisted?"),
	}
}

/// Claims a successful mint must carry; `Err` names the first wrong claim.
pub fn check_mint_claims(c: &MintCell) -> Result<(), String> {
	let Some(cl) = &c.claims else { return Ok(()) };
	let n = c.name.as_str();
	let root = canon_root(&c.host);
	let lvl = |prefix: &str| n.strip_prefix(prefix).and_then(|r| r.chars().next());
	let want = if let Some(l) = lvl("ref-sharelink-") {
		// An `'A'` ref is capped to `W`: no scope carries share management.
		Some(format!("file:{root}:{}", if l == 'a' { 'W' } else { l.to_ascii_uppercase() }))
	} else if let Some(l) = lvl("scope-owner-scoped-").or_else(|| lvl("scope-g-write-scoped-")) {
		Some(format!("file:{root}:{}", l.to_ascii_uppercase()))
	} else if n == "via-gread-overask@alice" || n == "via-scoped-overask@alice" {
		Some(format!("file:{}:R", root.replace("tenant-crdt-d-active", "cur-linktarget-w")))
	} else if n.starts_with("via-") {
		Some(format!("file:{}:R", root.replace("-tenant-crdt-", "-linktarget-crdt-")))
	} else if n.starts_with("xchg-apikey-file@") || n == "scope-g-read-overask@alice" {
		// The over-ask (`W`) is capped to g_read's own `R`.
		Some(format!("file:{root}:R"))
	} else if n == "scope-hatted@club" || n == "ref-refresh@alice" || n == "ref-once@alice" {
		Some(format!("file:{root}:R"))
	} else if n == "ref-folderlink-r@alice" {
		Some(format!("file:{}:R", canon_folder(&c.host)))
	} else if n == "scope-sadm@admin" {
		Some("file:f1~zqm-admin-doc:R".into())
	} else if n == "scope-carddav@alice" {
		Some("carddav:read".into())
	} else if n.starts_with("scope-apkg@") || n == "scope-apkg-m-leader@club" {
		Some("apkg:publish".into())
	} else {
		None
	};
	// A link-minted token names its ref; a via embed minted from a link carries the link's.
	let link_ref = match n {
		"via-guest@alice" | "ref-refresh@alice" => Some("zqref-alice-r".to_owned()),
		"ref-once@alice" => Some("zqref-alice-once".to_owned()),
		"ref-folderlink-r@alice" => Some("zqref-alice-folder".to_owned()),
		_ => n
			.strip_prefix("ref-sharelink-")
			.and_then(|r| r.split_once('@'))
			.map(|(l, h)| format!("zqref-{h}-{l}")),
	};
	let want = match (want, link_ref) {
		(Some(w), Some(r)) => Some(format!("{w}:{r}")),
		(w, _) => w,
	};
	if cl.scope.as_deref() != want.as_deref() {
		return Err(format!("scope {:?} != {want:?}", cl.scope));
	}
	let has = |r: &str| cl.roles.iter().any(|x| &**x == r);
	if n == "proxy-hat-hatted@club" && !(cl.hat.is_some() && has("contributor")) {
		return Err("hat: missing hat or mapped contributor role".into());
	}
	if n == "scope-hatted@club" {
		if cl.hat.as_deref() != Some("peer.test") || !has("contributor") {
			return Err(format!(
				"hat: {:?} / roles {:?}, want peer.test + contributor",
				cl.hat, cl.roles
			));
		}
		match (cl.exp, c.parent_exp) {
			(Some(e), Some(p)) if e.0 <= p.0 => {}
			(e, p) => return Err(format!("exp {e:?} not <= parent {p:?}")),
		}
	}
	if n == "blocked-session@club" && !cl.roles.is_empty() {
		return Err(format!("blocked session carries roles {:?}", cl.roles));
	}
	if n.starts_with("proxy-") && !n.contains("m-leader") && has("leader") {
		return Err("roles: remote PROXY session carries leader".into());
	}
	Ok(())
}

// vim: ts=4
