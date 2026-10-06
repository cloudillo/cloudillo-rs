// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! File access level helpers
//!
//! Provides functions to determine user access levels to files based on:
//! - Scoped tokens (file:{file_id}:{R|C|W} grants Read/Comment/Write access)
//! - Ownership (the owner of a locally originating row has Admin access — write, plus share
//!   management)
//! - FSHR action grants, but only from the row's upstream source (ADMIN subtype = Admin,
//!   WRITE = Write, COMMENT = Comment, else Read)

use std::sync::Arc;

use crate::abac;
use crate::dir_cache::{DirCache, DirEntry};
use crate::prelude::*;
use cloudillo_types::auth_adapter::AuthCtx;
use cloudillo_types::meta_adapter;
use cloudillo_types::meta_adapter::FileView;
use cloudillo_types::types::{AccessLevel, TokenScope};

/// Maximum parent-chain depth for bounded folder-tree traversals.
pub const MAX_PARENT_DEPTH: usize = 64;

/// Result of checking file access
pub struct FileAccessResult {
	pub file_view: FileView,
	pub access_level: AccessLevel,
	pub read_only: bool,
}

/// Error type for file access checks
pub enum FileAccessError {
	NotFound,
	AccessDenied,
	InternalError(String),
}

/// Context describing the subject requesting file access
#[derive(Clone, Copy)]
pub struct FileAccessCtx<'a> {
	pub user_id_tag: &'a str,
	pub tenant_id_tag: &'a str,
	pub user_roles: &'a [Box<str>],
	/// The subject wears a hat (`AuthCtx.hat.is_some()`), which bypasses closed-room rosters.
	pub hatted: bool,
	/// Delegated token scope (`AuthCtx.scope`). A scoped caller is scope grant + guest: the
	/// identity rungs are never evaluated for it, whatever `user_id_tag` holds (the holder's
	/// `sub`, or the tenant's own for an anonymous share-link token).
	pub scope: Option<&'a str>,
	/// [`AuthCtx::names_holder`]; false when unauthenticated.
	pub names_holder: bool,
}

impl<'a> FileAccessCtx<'a> {
	/// The subject of `auth` (`None` = unauthenticated: no identity, roles, hat or scope).
	pub fn from_auth(auth: Option<&'a AuthCtx>, tenant_id_tag: &'a str) -> Self {
		match auth {
			Some(a) => Self {
				user_id_tag: &a.id_tag,
				tenant_id_tag,
				user_roles: &a.roles,
				hatted: a.hat.is_some(),
				scope: a.scope.as_deref(),
				names_holder: a.names_holder(),
			},
			None => Self {
				user_id_tag: "",
				tenant_id_tag,
				user_roles: &[],
				hatted: false,
				scope: None,
				names_holder: false,
			},
		}
	}

	/// The subject the visibility ladder sees: a scoped caller is a guest there (scope =
	/// guest + grant), so its identity, roles and hat are stripped.
	fn visibility_subject(&self) -> Self {
		if self.scope.is_some() {
			Self { user_id_tag: "", user_roles: &[], hatted: false, scope: None, ..*self }
		} else {
			*self
		}
	}
}

/// The object side of a file access check: which row, plus its two ownership facts.
///
/// Kept apart from [`FileAccessCtx`], which describes the *subject*: mixing the two would let a
/// caller hand in an upstream that does not belong to the row it is asking about.
#[derive(Clone, Copy)]
pub struct FileRef<'a> {
	/// Authority. A NULL `entries.owner_tag` resolves to the tenant.
	pub owner_id_tag: &'a str,
	/// Provenance, not authority. `None` means the row originates here, which is what gates the
	/// owner shortcut and role access below. Never falls back to the tenant.
	pub upstream_id_tag: Option<&'a str>,
	/// Content id: FSHR keys, attachments, document trees. `None` for a local folder.
	pub file_id: Option<&'a str>,
	/// Placement id: share entries and share-link scopes name this.
	pub entry_id: &'a str,
	/// Absolute channel (`@tenant~name`); `None` = open floor. Gates only the ambient rungs.
	pub channel: Option<&'a str>,
	/// Document-tree root; a scope for the root grants its children.
	pub root_id: Option<&'a str>,
	/// `entries.visibility`, read by the final visibility rung.
	pub visibility: Option<char>,
	/// `files.file_tp`. A `BLOB` is the only kind with several entries, so a content-keyed grant
	/// on one is capped at Read and never reaches a placement write.
	pub file_tp: Option<&'a str>,
}

impl<'a> FileRef<'a> {
	/// Resolve both ownership facts off a loaded row, so callers cannot forget the upstream and
	/// hand a mirrored row role access. An absent *or empty* profile counts as absent.
	///
	/// The NULL-owner fallback to the tenant rests on an invariant worth naming: **every locally
	/// originating row a profile creates carries a non-NULL `owner_tag`.** Every user-facing
	/// creation path stamps `auth.id_tag` — `file::handler`'s upload and cross-context-post sites,
	/// `file::management::duplicate_file`, `profile::media`. The three sites that leave it NULL
	/// create tenant infrastructure with no member creator to lose anything: `file::sync`'s variant
	/// cache (profile pics and inbound action attachments; user uploads never reach it), and
	/// `websocket`'s `s~{app_id}` store and `{file_id}~meta` rows. So the fallback never demotes a
	/// real creator — in particular not in `share_access::is_share_manager`, which reads ownership
	/// straight off the resulting `AccessLevel`.
	pub fn from_view(view: &'a FileView, tenant_id_tag: &'a str) -> Self {
		let tag = |p: Option<&'a meta_adapter::ProfileInfo>| {
			p.map(|p| p.id_tag.as_ref()).filter(|s| !s.is_empty())
		};
		Self {
			owner_id_tag: tag(view.owner.as_ref()).unwrap_or(tenant_id_tag),
			upstream_id_tag: tag(view.upstream.as_ref()),
			file_id: view.file_id.as_deref(),
			entry_id: &view.entry_id,
			channel: view.channel.as_deref(),
			root_id: view.root_id.as_deref(),
			visibility: view.visibility,
			file_tp: view.file_tp.as_deref(),
		}
	}
}

/// Resolve one `(tn, file_id)` → `DirEntry` through the folder cache, falling back
/// to a single `read_file` on a miss. The row is cached **only when it is a folder**
/// (`is_folder`), keeping the cache small and folder-only; non-folder rows (e.g. the
/// leaf that starts a descendant walk) are returned but never inserted.
///
/// Propagates read errors as `Err` so request-path callers can surface a genuine
/// fault as 5xx instead of mistaking it for "missing / not a descendant".
pub async fn resolve_dir_entry(
	meta: &Arc<dyn meta_adapter::MetaAdapter>,
	cache: &DirCache,
	tn_id: TnId,
	file_id: &str,
) -> ClResult<Option<DirEntry>> {
	if let Some(entry) = cache.get(tn_id, file_id) {
		return Ok(Some(entry)); // cached ⇒ folder
	}
	match meta.read_file(tn_id, file_id).await? {
		Some(view) => {
			let is_folder = view.file_tp.as_deref() == Some("FLDR");
			let entry = DirEntry {
				parent_id: view.parent_id.clone(),
				name: view.file_name.clone(),
				is_folder,
			};
			if is_folder {
				cache.put(tn_id, file_id, entry.clone());
			}
			Ok(Some(entry))
		}
		None => Ok(None),
	}
}

/// Walk the parent chain of a file to find an inherited share entry.
///
/// Checks each ancestor's share_access for the given user. Returns the first
/// (closest ancestor) match's access level, or None if no ancestor is shared.
/// Bounded to `MAX_PARENT_DEPTH` levels to prevent runaway traversal.
///
/// This is one of the single, cache-backed parent-chain walkers: every hop goes
/// through `resolve_dir_entry`, memoizing folder rows in the shared `DirCache`.
pub async fn walk_parent_chain_for_share(
	app: &App,
	tn_id: TnId,
	file_id: &str,
	user_id_tag: &str,
) -> Option<AccessLevel> {
	// DirCache is a required process-wide extension registered at app build (see
	// crates/cloudillo/src/app.rs); a missing cache means misconfiguration, so log
	// rather than silently dropping inherited-share access.
	let Ok(cache) = app.ext::<DirCache>() else {
		warn!("DirCache extension missing; skipping inherited-share parent walk");
		return None;
	};
	let mut current_id = file_id.to_string();
	for _ in 0..MAX_PARENT_DEPTH {
		// Best-effort: a read error ends the walk (treated as no inherited share).
		let Ok(Some(entry)) = resolve_dir_entry(&app.meta_adapter, cache, tn_id, &current_id).await
		else {
			break;
		};
		let Some(parent_id) = entry.parent_id else { break };
		if let Ok(Some(perm)) = app
			.meta_adapter
			.check_share_access(tn_id, 'F', &parent_id, 'U', user_id_tag)
			.await
		{
			return Some(AccessLevel::from_perm_char(perm));
		}
		current_id = parent_id.to_string();
	}
	None
}

/// Return true if `ancestor_id` is an ancestor folder of `file_id`.
///
/// Walks the `parent_id` chain upward from `file_id`, bounded to
/// `MAX_PARENT_DEPTH` levels to prevent runaway traversal. Used to extend
/// file-scope tokens (folder share links) to every descendant of a shared
/// folder. The file itself is not considered its own descendant — callers
/// handle the direct match separately.
///
/// Propagates read errors as `Err` so callers on request paths can surface a
/// genuine fault as 5xx instead of silently treating it as "not a descendant".
///
/// This is one of the single, cache-backed parent-chain walkers: every hop goes
/// through `resolve_dir_entry`, memoizing folder rows in the shared `DirCache`.
pub async fn is_descendant_of(
	meta: &Arc<dyn meta_adapter::MetaAdapter>,
	cache: &DirCache,
	tn_id: TnId,
	file_id: &str,
	ancestor_id: &str,
) -> ClResult<bool> {
	let mut current_id = file_id.to_string();
	for _ in 0..MAX_PARENT_DEPTH {
		let Some(entry) = resolve_dir_entry(meta, cache, tn_id, &current_id).await? else {
			break;
		};
		let Some(parent_id) = entry.parent_id else { break };
		if parent_id.as_ref() == ancestor_id {
			return Ok(true);
		}
		current_id = parent_id.to_string();
	}
	Ok(false)
}

/// Return true if the scoped target file is a folder (`file_tp == "FLDR"`).
///
/// Used to gate the folder-subtree extension of a file-scope token: only a
/// scope whose target is an actual folder grants access across its `parent_id`
/// descendants. Answered straight from the folder cache via `resolve_dir_entry`:
/// returns `Ok(true)` only for an existing `FLDR` row, `Ok(false)` for a missing
/// or non-folder row, and `Err` for a genuine read fault so request-path callers
/// that can return 5xx surface the fault instead of masking it as "not a folder".
pub async fn scope_target_is_folder(
	meta: &Arc<dyn meta_adapter::MetaAdapter>,
	cache: &DirCache,
	tn_id: TnId,
	scope_file_id: &str,
) -> ClResult<bool> {
	Ok(resolve_dir_entry(meta, cache, tn_id, scope_file_id)
		.await?
		.is_some_and(|e| e.is_folder))
}

/// Check if a user has share access to a file — either a direct share entry
/// on the file itself or an inherited share from an ancestor folder.
pub async fn check_share_for_file(
	app: &App,
	tn_id: TnId,
	file_id: &str,
	user_id_tag: &str,
) -> Option<AccessLevel> {
	if let Ok(Some(perm)) =
		app.meta_adapter.check_share_access(tn_id, 'F', file_id, 'U', user_id_tag).await
	{
		return Some(AccessLevel::from_perm_char(perm));
	}
	walk_parent_chain_for_share(app, tn_id, file_id, user_id_tag).await
}

/// Access level granted purely by community-role membership on a *locally originating*
/// file. Only roles from `crate::roles::ROLE_HIERARCHY` count.
///
/// Membership is matched explicitly rather than by testing "the role slice is
/// non-empty": a `[""]` slice reads as "has a role" and would hand every
/// federated stranger Read access. Second defence behind `roles::parse_roles`,
/// which drops empty segments.
///
/// `public` and `follower` grant nothing: every role-less follower reads back as `follower`
/// (derived in the meta adapter), and this tier ignores visibility, so counting it would
/// hand every follower Read on every local file, Direct ones included.
pub fn role_access_level(user_roles: &[Box<str>]) -> AccessLevel {
	// A leader resolves to `Admin`, not `Write`: leadership over a local file *is* the right
	// to manage its share set, so `access_level` alone answers "may manage shares".
	if crate::roles::is_leader(user_roles) {
		return AccessLevel::Admin;
	}
	if user_roles.iter().any(|r| matches!(r.as_ref(), "moderator" | "contributor")) {
		return AccessLevel::Write;
	}
	// Not `public` / `follower`: see the doc comment (derived follower rung).
	if user_roles.iter().any(|r| r.as_ref() == "supporter") {
		return AccessLevel::Read;
	}
	AccessLevel::None
}

/// The one lifecycle gate: delete, restore and trash visibility (trash view, trashed
/// metadata/content). `level` is the subject's [`get_access_level`] for `file`.
///
/// Record authority (the owner, i.e. the placer of a mirrored row) always passes. On a mirrored
/// row nothing else does — the remote owner and the community leader included. On a local row,
/// Admin level or the community `moderator` role pass too; Write grantees may edit, not delete.
/// The room caps the role: a moderator outside the file's room does not pass on that.
/// Scoped callers never pass: a scope carries no lifecycle authority, whoever holds it.
pub async fn can_manage_lifecycle(
	app: &App,
	tn_id: TnId,
	file: &FileRef<'_>,
	ctx: &FileAccessCtx<'_>,
	level: AccessLevel,
) -> bool {
	if ctx.scope.is_some() {
		return false;
	}
	if file.owner_id_tag == ctx.user_id_tag {
		return true;
	}
	file.upstream_id_tag.is_none()
		&& (level == AccessLevel::Admin
			|| (crate::roles::is_moderator(ctx.user_roles)
				&& channel_admits(app, tn_id, file.channel, ctx).await))
}

/// Whether `view` sits in the trash: trashed itself, a document-tree child of a trashed root, or
/// a descendant of a trashed folder. Soft delete moves only the root row, so the ancestors decide.
pub async fn in_trash(app: &App, tn_id: TnId, view: &FileView) -> ClResult<bool> {
	use meta_adapter::TRASH_PARENT_ID;
	if view.parent_id.as_deref() == Some(TRASH_PARENT_ID) {
		return Ok(true);
	}
	// A tree child stands behind its root; the root's own ancestry decides from there.
	let root;
	let view = match view.root_id.as_deref() {
		Some(root_id) => {
			root = app.meta_adapter.read_file(tn_id, root_id).await?;
			let Some(root) = root.as_ref() else { return Ok(false) };
			if root.parent_id.as_deref() == Some(TRASH_PARENT_ID) {
				return Ok(true);
			}
			root
		}
		None => view,
	};
	let Some(parent_id) = view.parent_id.as_deref() else { return Ok(false) };
	let cache = app.ext::<DirCache>()?;
	is_descendant_of(&app.meta_adapter, cache, tn_id, parent_id, TRASH_PARENT_ID).await
}

/// The lifecycle gate every file read and write passes: a tombstone exists for nobody, a trashed
/// row (see [`in_trash`]) only for those who [`can_manage_lifecycle`], a pending upload only for
/// its real owner. `names_holder` is [`AuthCtx::names_holder`]: a share-link token's `id_tag` is
/// the tenant's, so it never owns a pending upload. Everything else is `NotFound`.
pub async fn check_lifecycle(
	app: &App,
	tn_id: TnId,
	view: &FileView,
	file: &FileRef<'_>,
	ctx: &FileAccessCtx<'_>,
	level: AccessLevel,
	names_holder: bool,
) -> ClResult<()> {
	use meta_adapter::FileStatus;
	if matches!(view.status, FileStatus::Deleted) {
		return Err(Error::NotFound);
	}
	if matches!(view.status, FileStatus::Pending)
		&& (!names_holder || file.owner_id_tag != ctx.user_id_tag)
	{
		return Err(Error::NotFound);
	}
	if !can_manage_lifecycle(app, tn_id, file, ctx, level).await
		&& in_trash(app, tn_id, view).await?
	{
		return Err(Error::NotFound);
	}
	Ok(())
}

/// Whether a file in `channel` is within the subject's ambient reach: open floor always is,
/// a room only when the subject can enter it. Fails closed on a lookup error.
pub async fn channel_admits(
	app: &App,
	tn_id: TnId,
	channel: Option<&str>,
	ctx: &FileAccessCtx<'_>,
) -> bool {
	let Some(channel) = channel else { return true };
	match crate::channels::enterable_channels(
		app,
		tn_id,
		ctx.tenant_id_tag,
		ctx.user_id_tag,
		ctx.user_roles,
		ctx.hatted,
	)
	.await
	{
		Ok(set) => channel_in(channel, set.as_deref()),
		Err(e) => {
			warn!("enterable_channels failed, denying ambient file access: {}", e);
			false
		}
	}
}

/// The room caps roles: inside a room the caller cannot enter, `auth` with its roles dropped
/// (no leader override, share ceiling or moderator lifecycle). A share grant and record
/// ownership are not roles, so they still count; the tenant always enters.
pub async fn room_capped(
	app: &App,
	tn_id: TnId,
	tenant_id_tag: &str,
	auth: &AuthCtx,
	channel: Option<&str>,
) -> AuthCtx {
	let mut capped = auth.clone();
	if channel.is_some()
		&& !auth.roles.is_empty()
		&& !channel_admits(
			app,
			tn_id,
			channel,
			&FileAccessCtx::from_auth(Some(auth), tenant_id_tag),
		)
		.await
	{
		capped.roles = Box::default();
	}
	capped
}

/// `None` = the tenant itself, unrestricted.
fn channel_in(channel: &str, enterable: Option<&[Box<str>]>) -> bool {
	enterable.is_none_or(|set| set.iter().any(|c| c.as_ref() == channel))
}

/// Resolve the grant an `FSHR:{file_id}:{audience}` action row carries: `ADMIN` → Admin, `WRITE` →
/// Write, `COMMENT` → Comment, `DEL` → None (a revocation is not a grant), anything else → Read.
///
/// An FSHR is a *claim by its issuer* that they granted access, so only the node the row is
/// mirrored from — the entry's own `upstream_tag` — can make it credibly. Testing the *owner* instead would be
/// worse than useless on a community tenant: an FSHR-accepted row leaves `owner_tag` NULL, so the
/// owner resolves to the recipient tenant and any member could forge a grant on their own row. A
/// row with no upstream originates here, so no FSHR on it is credible from anyone — its live grant
/// path is the `share_entries` row, resolved earlier.
///
/// Without the issuer test the row is a self-service grant: `POST /api/actions` is gated only by
/// the `contributor` role, the action DSL's `key_pattern` builds the key straight from the
/// client's `subject` and `aud`, and hooks run *after* the row is stored with no rollback, so
/// `fshr::on_create` rejecting the write leaves the row behind. Federated peers can post such a
/// token to the inbox just as easily.
///
/// Both live paths survive the test: on the recipient's node `fshr::on_accept` creates an entry
/// with `upstream_tag = issuer`, and on the owner's node the grantee's access resolves earlier, from
/// the `share_entries` row.
fn fshr_grant_level(
	typ: &str,
	sub_typ: Option<&str>,
	issuer_tag: &str,
	upstream_id_tag: Option<&str>,
	file_id: &str,
) -> AccessLevel {
	if typ != "FSHR" {
		return AccessLevel::None;
	}
	// Covers both mismatch and a NULL upstream: a locally originating row can carry no credible
	// FSHR at all.
	if upstream_id_tag != Some(issuer_tag) {
		warn!(
			file_id = %file_id,
			issuer = %issuer_tag,
			upstream = ?upstream_id_tag,
			sub_typ = ?sub_typ,
			"Ignoring FSHR grant: issuer is not the file's upstream source"
		);
		return AccessLevel::None;
	}
	match sub_typ {
		Some("ADMIN") => AccessLevel::Admin,
		Some("WRITE") => AccessLevel::Write,
		Some("COMMENT") => AccessLevel::Comment,
		// A `DEL` shares the key `FSHR:{subject}:{audience}`, so it replaces the row it revokes —
		// without this arm the catch-all reads it back as Read and revocation leaves read access.
		Some("DEL") => AccessLevel::None,
		_ => AccessLevel::Read,
	}
}

/// Get access level for a subject on a file — the one level function.
///
/// Scoped caller (`ctx.scope` set): the scope rung (see [`scope_grant`]); on a mismatch the
/// identity rungs are skipped. Unscoped caller, first match wins:
/// 1. Ownership — the owner of a locally originating row has Admin access
/// 2. Direct `share_entries` grant on this file, then the caller-supplied `inherited_share`, then a
///    parent-chain walk for a folder-inherited grant
/// 3. Role-based access — any locally originating row (`upstream_id_tag` is `None`): leader →
///    Admin, moderator/contributor → Write, supporter → Read. `role_access_level` ignores
///    `visibility`, so this deliberately reaches a peer member's own upload too.
/// 4. FSHR action issued by the row's upstream source — ADMIN → Admin, WRITE → Write, COMMENT → Comment,
///    DEL → None (a revocation is not a grant), other sub-types → Read (see [`fshr_grant_level`])
/// 5. Placer read on a mirrored row with no FSHR at all — a Pin/Place copy stays readable by the
///    profile that placed it. Read only, and last, so a revoked FSHR does not reach it.
///
/// Both end in the visibility rung (see [`visibility_level`]): at most Read, scoped callers scored
/// as guest, so a scope never yields less than the anonymous view.
///
/// Beside it, opt-in per request: [`action_attachment_level`] when the caller names an action.
pub async fn get_access_level(
	app: &App,
	tn_id: TnId,
	file: FileRef<'_>,
	ctx: &FileAccessCtx<'_>,
	inherited_share: Option<AccessLevel>,
) -> AccessLevel {
	access_level(app, tn_id, file, ctx, inherited_share, false).await
}

/// [`get_access_level`]; `skip_direct` when the caller already looked up the direct share (the
/// union's one query) and passes its hit, if any, as `inherited_share`.
async fn access_level(
	app: &App,
	tn_id: TnId,
	file: FileRef<'_>,
	ctx: &FileAccessCtx<'_>,
	inherited_share: Option<AccessLevel>,
	skip_direct: bool,
) -> AccessLevel {
	let level = match ctx.scope {
		Some(scope) => scope_grant(app, tn_id, &file, scope).await.unwrap_or(AccessLevel::None),
		None => identity_level(app, tn_id, file, ctx, inherited_share, skip_direct).await,
	};
	if level != AccessLevel::None {
		return level;
	}
	visibility_level(app, tn_id, &file, ctx).await
}

/// `Read` when `action_id` is an active action here, issued by the file's owner, addressed to
/// the caller and attaching the file: the action named its audience. An unscoped caller only,
/// on a row that originates here. One point lookup, made only when the caller names the action
/// (`?action=`, sent by the audience's attachment sync).
pub async fn action_attachment_level(
	app: &App,
	tn_id: TnId,
	file: &FileRef<'_>,
	ctx: &FileAccessCtx<'_>,
	action_id: &str,
) -> AccessLevel {
	// Unscoped: share links carry the tenant id_tag. Local row: a mirror's
	// access belongs to its upstream.
	if ctx.scope.is_some()
		|| file.upstream_id_tag.is_some()
		|| ctx.user_id_tag.is_empty()
		|| ctx.user_id_tag == "guest"
	{
		return AccessLevel::None;
	}
	let view = match app.meta_adapter.get_action(tn_id, action_id).await {
		Ok(Some(view)) => view,
		Ok(None) => return AccessLevel::None,
		Err(e) => {
			warn!(action_id, error = %e, "action attachment lookup failed");
			return AccessLevel::None;
		}
	};
	// Issuer = owner: a remote's action stored here cannot grant our file by attaching it.
	// Audience = caller: a third party who knows the action id gains nothing.
	let grants = view.status.as_deref() == Some("A")
		&& &*view.issuer.id_tag == file.owner_id_tag
		&& view.audience.as_ref().map(|p| &*p.id_tag) == Some(ctx.user_id_tag)
		&& view.attachments.iter().flatten().any(|a| file.file_id == Some(&*a.file_id));
	if grants { AccessLevel::Read } else { AccessLevel::None }
}

/// Rungs 1–5 of [`get_access_level`], for an unscoped caller.
async fn identity_level(
	app: &App,
	tn_id: TnId,
	file: FileRef<'_>,
	ctx: &FileAccessCtx<'_>,
	inherited_share: Option<AccessLevel>,
	skip_direct: bool,
) -> AccessLevel {
	let FileRef { file_id, entry_id, owner_id_tag, upstream_id_tag, channel, .. } = file;
	// FSHR keys name the content id, or a folder's entry id.
	let file_id = file_id.unwrap_or(entry_id);
	// The owner is the file's admin: write plus share management. Callers must test
	// `can_write()`/`can_manage_shares()` rather than `== AccessLevel::Write`.
	//
	// Locally originating rows only: owner authority over a mirrored *record* is not authority over
	// its content. A mirror's access resolves from its share entries and from the FSHR grant below —
	// otherwise the FSHR recipient on a personal tenant (owner = tenant = caller) would stop here and
	// never see the level the sharer actually sent, and the placer of a Pin/Place row would gain
	// share management over someone else's file.
	//
	// `abac::PermissionChecker::has_permission`'s ownership branch is deliberately *not* gated
	// this way: there `owner_id_tag` means authority over the local record (rename, move, hide,
	// delete, tag), which the placer keeps. Content and shares are decided here and in
	// `crate::share_access`.
	if upstream_id_tag.is_none() && ctx.user_id_tag == owner_id_tag {
		return AccessLevel::Admin;
	}

	// Direct share on this specific file
	if !skip_direct
		&& let Ok(Some(perm)) = app
			.meta_adapter
			.check_share_access(tn_id, 'F', entry_id, 'U', ctx.user_id_tag)
			.await
	{
		return AccessLevel::from_perm_char(perm);
	}
	// Inherited share from parent folder (already resolved by caller)
	if let Some(level) = inherited_share {
		return level;
	}
	// No known inheritance — walk the parent chain
	if let Some(level) = walk_parent_chain_for_share(app, tn_id, entry_id, ctx.user_id_tag).await {
		return level;
	}

	// Role-based access. A mirrored entry (Pin/Place copy, FSHR-accepted share) names its source in
	// its own `upstream_tag` and its access is that node's business — roles held here say nothing
	// about it. Provenance is per entry: a local entry of the same BLOB content still qualifies.
	//
	// ponytail: on a row that originates here, ANY role reaches it — including a peer member's own
	// Direct-visibility upload on a community tenant, since `role_access_level` ignores
	// `visibility`. Deliberate for now: contributors need to be able to write freely. Narrow it by
	// reintroducing an owner/visibility gate here (leaders exempt, as they were) when the community
	// model calls for it.
	let role_level = if upstream_id_tag.is_none() {
		role_access_level(ctx.user_roles)
	} else {
		AccessLevel::None
	};
	// The room governs ambient reach: a role grants nothing inside a room it cannot enter.
	if role_level != AccessLevel::None && channel_admits(app, tn_id, channel, ctx).await {
		return role_level;
	}

	// FSHR action keyed `FSHR:{file_id}:{audience}`: the content id, which for a folder is its
	// entry id. The grant reaches only placements the context admits — the room gates it like the
	// role rung — and `fshr_grant_level` only honours the content's own upstream.
	//
	// `get_action_by_key` does not filter on action status, so a pending ('C') or rejected FSHR
	// resolves here too. Moot in practice: the local file row only exists once `on_accept` ran.
	let found = app
		.meta_adapter
		.get_action_by_key(tn_id, &format!("FSHR:{}:{}", file_id, ctx.user_id_tag))
		.await;
	match found {
		Ok(Some(action)) => {
			if !channel_admits(app, tn_id, channel, ctx).await {
				return AccessLevel::None;
			}
			let level = fshr_grant_level(
				&action.typ,
				action.sub_typ.as_ref().map(AsRef::as_ref),
				&action.issuer_tag,
				upstream_id_tag,
				file_id,
			);
			// The key names content, and a BLOB's content may back several entries: the grant
			// never reaches a placement write on one.
			if file.file_tp == Some("BLOB") { level.min(AccessLevel::Read) } else { level }
		}
		// No FSHR row at all — a Pin/Place copy. Its placer keeps *read* over their own pin:
		// owner standing is withheld (that is the first rung, and it is what keeps a revoked FSHR
		// recipient out), but on a personal tenant a Pin lands at Direct visibility with no share
		// of any kind, so every other rung comes up empty. This rung must stay *after* the FSHR
		// lookup: on such a tenant an FSHR-accepted row also leaves `owner_tag` NULL and so
		// resolves to the caller, and running it earlier would cap a WRITE share at Read and hand
		// a `DEL`-revoked one its access back. Read only — content authority and share management
		// stay with the upstream node.
		Ok(None) if upstream_id_tag.is_some() && ctx.user_id_tag == owner_id_tag => {
			AccessLevel::Read
		}
		Ok(None) | Err(_) => AccessLevel::None,
	}
}

/// The scope rung: what a `file:{file_id}:{R|C|W}` scope grants on `file`. `None` on a mismatch,
/// an `ApkgPublish` scope, or an unparseable one — the caller then falls to the visibility rung.
///
/// Matches, in order: the scoped file itself; a child in its document tree (`root_id`); a file
/// linked from it by an `'F'` share entry, capped at that entry; a descendant of a scoped folder.
async fn scope_grant(
	app: &App,
	tn_id: TnId,
	file: &FileRef<'_>,
	scope: &str,
) -> Option<AccessLevel> {
	let Some(TokenScope::File { file_id: scope_file_id, access, .. }) = TokenScope::parse(scope)
	else {
		return None;
	};
	let entry_id = file.entry_id;
	let scope_view = resolve_scope_entry(&app.meta_adapter, tn_id, &scope_file_id).await?;
	// Direct match, or document tree (depth-1: root_id always points to a top-level file) in the
	// scoped entry's drive: another drive's placement of a tree part is not under this scope.
	if *scope_view.entry_id == *entry_id
		|| (file.root_id.is_some_and(|r| Some(r) == scope_view.file_id.as_deref())
			&& file.channel == scope_view.channel.as_deref())
	{
		return Some(access);
	}
	let scope_entry_id = &*scope_view.entry_id;

	// Cross-document link: an `'F'` share entry with resource = target (`entry_id`) and
	// subject = the scoped container — the order `share::post_share` writes.
	if let Ok(Some(perm)) = app
		.meta_adapter
		.check_share_access(tn_id, 'F', entry_id, 'F', scope_entry_id)
		.await
	{
		return Some(access.min(AccessLevel::from_perm_char(perm)));
	}

	// Folder share: scope targets a folder; grant the scope's level to any file nested under
	// it (linked via parent_id). Gated on the scoped target actually being a folder, so a
	// document/file share link does not leak access across its parent_id siblings. Fails
	// closed — a missing cache or read error yields no grant. DirCache is a required
	// process-wide extension registered at app build (see crates/cloudillo/src/app.rs), so
	// the else arm only fires on misconfiguration — log rather than fail silently.
	let Ok(cache) = app.ext::<DirCache>() else {
		warn!("DirCache extension missing; folder-share scope grant skipped");
		return None;
	};
	let nested_under_scope =
		scope_target_is_folder(&app.meta_adapter, cache, tn_id, scope_entry_id)
			.await
			.unwrap_or(false)
			&& is_descendant_of(&app.meta_adapter, cache, tn_id, entry_id, scope_entry_id)
				.await
				.unwrap_or(false);
	nested_under_scope.then_some(access)
}

/// What an id names, in `resolve_file`'s lookup order.
enum IdTarget {
	/// An entry id, or a non-BLOB content id naming a single entry.
	Entry(Box<FileView>),
	/// A BLOB content id, possibly shared by several entries.
	Content(Box<str>),
}

/// Classify `id`. `None` when it names nothing.
async fn classify_id(
	meta: &Arc<dyn meta_adapter::MetaAdapter>,
	tn_id: TnId,
	id: &str,
) -> ClResult<Option<IdTarget>> {
	Ok(match meta.resolve_file(tn_id, id).await? {
		meta_adapter::FileResolution::Entry(v)
			if *v.entry_id == *id || v.file_tp.as_deref() != Some("BLOB") =>
		{
			Some(IdTarget::Entry(v))
		}
		meta_adapter::FileResolution::Entry(v) => v.file_id.map(IdTarget::Content),
		// Several entries: a BLOB, or local content beside references to it.
		meta_adapter::FileResolution::Ambiguous => Some(IdTarget::Content(id.into())),
		// A deduped pending `@<f_id>`: `resolve` stays raw, the content listing follows
		// `merged_into` to the survivor.
		meta_adapter::FileResolution::NotFound if id.starts_with('@') => {
			Some(IdTarget::Content(id.into()))
		}
		meta_adapter::FileResolution::NotFound => None,
	})
}

/// The entry a `file:{id}` scope is bound to. A BLOB content id binds no entry, so it grants
/// nothing: scopes are minted on the granting entry id (see the access-token handler).
pub async fn resolve_scope_entry(
	meta: &Arc<dyn meta_adapter::MetaAdapter>,
	tn_id: TnId,
	scope_id: &str,
) -> Option<FileView> {
	match classify_id(meta, tn_id, scope_id).await {
		Ok(Some(IdTarget::Entry(v))) => Some(*v),
		Ok(Some(IdTarget::Content(_)) | None) | Err(_) => None,
	}
}

/// The entries an access check on `id` weighs: the entry `id` names, or every entry of the
/// content it names, managed ones included.
pub async fn access_entries(app: &App, tn_id: TnId, id: &str) -> ClResult<Vec<FileView>> {
	match classify_id(&app.meta_adapter, tn_id, id).await? {
		Some(IdTarget::Entry(v)) => Ok(vec![*v]),
		Some(IdTarget::Content(c)) => app.meta_adapter.list_content_entries(tn_id, &c).await,
		None => Ok(Vec::new()),
	}
}

/// The entries of `entries` the caller's context admits, each with its level, in input order.
/// An entry the lifecycle gate hides ([`check_lifecycle`]: trashed, pending, tombstone) drops out;
/// direct shares come from one query over the active entries.
///
/// One entry: it alone, at its level — `AccessLevel::None` too, so ABAC can still weigh record
/// ownership. Several: only the entries that grant something. `PermissionDenied` when entries pass
/// the lifecycle gate but none grants; `NotFound` when none passes.
pub async fn admitted(
	app: &App,
	tn_id: TnId,
	mut entries: Vec<FileView>,
	ctx: &FileAccessCtx<'_>,
	via_action: Option<&str>,
) -> ClResult<Vec<(FileView, AccessLevel)>> {
	if entries.len() <= 1 {
		let view = entries.pop().ok_or(Error::NotFound)?;
		let level = entry_level(app, tn_id, &view, ctx, via_action, None, false).await;
		let file = FileRef::from_view(&view, ctx.tenant_id_tag);
		check_lifecycle(app, tn_id, &view, &file, ctx, level, ctx.names_holder).await?;
		return Ok(vec![(view, level)]);
	}
	let direct = match (ctx.scope, entries.first().and_then(|e| e.file_id.as_deref())) {
		(None, Some(content_id)) if !ctx.user_id_tag.is_empty() => {
			app.meta_adapter
				.check_content_share_access(tn_id, content_id, ctx.user_id_tag)
				.await?
		}
		_ => Vec::new(),
	};
	let mut out = Vec::new();
	let mut visible = false;
	for view in entries {
		let inherited = direct
			.iter()
			.find(|(eid, _)| *eid == view.entry_id)
			.map(|(_, perm)| AccessLevel::from_perm_char(*perm));
		let level = entry_level(app, tn_id, &view, ctx, via_action, inherited, true).await;
		let file = FileRef::from_view(&view, ctx.tenant_id_tag);
		match check_lifecycle(app, tn_id, &view, &file, ctx, level, ctx.names_holder).await {
			Ok(()) => visible = true,
			Err(Error::NotFound) => continue,
			Err(e) => return Err(e),
		}
		if level != AccessLevel::None {
			out.push((view, level));
		}
	}
	match out.is_empty() {
		false => Ok(out),
		true if visible => Err(Error::PermissionDenied),
		true => Err(Error::NotFound),
	}
}

/// The read resolver: of the entries the context [`admitted`], the one granting the highest level
/// (on a tie a local entry over a reference, which holds no bytes here, then lowest `e_id`). The
/// returned view is that admitted entry, so no sibling's metadata reaches the caller.
pub async fn union_access(
	app: &App,
	tn_id: TnId,
	entries: Vec<FileView>,
	ctx: &FileAccessCtx<'_>,
	via_action: Option<&str>,
) -> ClResult<(FileView, AccessLevel)> {
	let mut best: Option<(FileView, AccessLevel)> = None;
	for (view, level) in admitted(app, tn_id, entries, ctx, via_action).await? {
		if best.as_ref().is_none_or(|(b_view, b)| {
			level > *b
				|| (level == *b && b_view.upstream_tag.is_some() && view.upstream_tag.is_none())
		}) {
			best = Some((view, level));
		}
	}
	best.ok_or(Error::NotFound)
}

/// Exactly one of `candidates`, or `Conflict` when the id names several ("use the entry id").
/// Empty is `PermissionDenied`.
pub fn single_placement<T>(mut candidates: Vec<(FileView, T)>) -> ClResult<(FileView, T)> {
	// A content id never targets an action-managed entry while a user entry qualifies: managed
	// entries live and die with their action.
	if candidates.iter().any(|(v, _)| v.action_id.is_none()) {
		candidates.retain(|(v, _)| v.action_id.is_none());
	}
	match candidates.len() {
		0 => Err(Error::PermissionDenied),
		1 => candidates.pop().ok_or(Error::PermissionDenied),
		_ => Err(Error::Conflict("file id names several entries; use the entry id".into())),
	}
}

/// One entry's level, with the opt-in [`action_attachment_level`] when the caller names an action.
async fn entry_level(
	app: &App,
	tn_id: TnId,
	view: &FileView,
	ctx: &FileAccessCtx<'_>,
	via_action: Option<&str>,
	inherited_share: Option<AccessLevel>,
	skip_direct: bool,
) -> AccessLevel {
	let file = FileRef::from_view(view, ctx.tenant_id_tag);
	let level = access_level(app, tn_id, file, ctx, inherited_share, skip_direct).await;
	match via_action {
		Some(action_id) if !level.can_read() => {
			action_attachment_level(app, tn_id, &file, ctx, action_id).await
		}
		_ => level,
	}
}

/// The visibility rung: `Read` when the file's `visibility` admits the caller and its channel is
/// within their ambient reach, else `None`. A scoped caller is scored as an anonymous guest — its
/// `user_id_tag` is the tenant's own and must not be scored against the tenant's relationships.
/// Fails closed on a relation lookup error.
async fn visibility_level(
	app: &App,
	tn_id: TnId,
	file: &FileRef<'_>,
	ctx: &FileAccessCtx<'_>,
) -> AccessLevel {
	let ctx = &ctx.visibility_subject();
	let is_real_auth = !ctx.user_id_tag.is_empty() && ctx.user_id_tag != "guest";
	// Only 'F'/'C'/'2' need the profile row; 'V' is settled by authentication alone.
	let rel = if is_real_auth
		&& abac::visibility_needs_relation(abac::VisibilityLevel::from_char(file.visibility))
	{
		match abac::subject_relation_to_tenant(app, tn_id, ctx.user_id_tag).await {
			Ok(rel) => rel,
			Err(e) => {
				warn!("subject_relation_to_tenant failed, denying visibility read: {}", e);
				return AccessLevel::None;
			}
		}
	} else {
		meta_adapter::ProfileRelation::default()
	};
	// The room governs ambient reach, visibility included.
	if visibility_grants_read(file.visibility, is_real_auth, rel)
		&& channel_admits(app, tn_id, file.channel, ctx).await
	{
		AccessLevel::Read
	} else {
		AccessLevel::None
	}
}

/// Whether the file's own `visibility` alone grants a caller `Read` — the decision of
/// [`get_access_level`]'s final rung, which has already replaced a scoped caller by a guest
/// (`is_real_auth = false`, default `rel`). `'P'` grants anyone.
///
/// Provenance is deliberately NOT a gate. A cross-context placement's `visibility` is
/// authored locally by the placing member — a community Pin lands at `'C'` — so refusing
/// mirrored rows here hid every pin from the members it was placed for, while `file::list`
/// and `search` showed it. What a mirror withholds is *owner* standing, and that happens
/// upstream of this function: `get_access_level` resolves ownership, roles and FSHR first,
/// so `is_owner` is provably `false` below and `Direct` (a revoked FSHR share) still grants
/// nothing.
///
/// `rel` is the subject's relationship *to the tenant*, loaded by the caller (see
/// [`abac::subject_relation_to_tenant`]) — `follower` is "they follow us".
pub fn visibility_grants_read(
	visibility: Option<char>,
	is_real_auth: bool,
	rel: meta_adapter::ProfileRelation,
) -> bool {
	abac::relationship_level(false, rel.connected, rel.follower, is_real_auth)
		.can_access(abac::VisibilityLevel::from_char(visibility))
}

/// Check file access and return file view with access level
///
/// This is the main helper for WebSocket handlers. It:
/// 1. Loads the entries `file_id` names ([`access_entries`]: one entry, or every entry of a
///    content id)
/// 2. Takes the union over them ([`union_access`]: scope, identity and visibility rungs per
///    entry; `ctx.scope` carries the delegated scope)
/// 3. Caps it by the `'F'` share entry when opened `?via=` an embedding (unscoped callers only)
/// 4. Returns combined result (`file_view` = the granting entry) or error
pub async fn check_file_access(
	app: &App,
	tn_id: TnId,
	file_id: &str,
	ctx: &FileAccessCtx<'_>,
	via: Option<&str>,
) -> Result<FileAccessResult, FileAccessError> {
	let entries = access_entries(app, tn_id, file_id)
		.await
		.map_err(|e| FileAccessError::InternalError(e.to_string()))?;
	access_result(app, tn_id, entries, ctx, via).await
}

/// The placement resolver: of the entries of `id` the context [`admitted`], those granting at
/// least `needed`. Exactly one → it; none → `PermissionDenied`; several → `Conflict` (409, "use
/// the entry id"). An entry id resolves to itself, then is access-checked.
pub async fn resolve_placement(
	app: &App,
	tn_id: TnId,
	id: &str,
	ctx: &FileAccessCtx<'_>,
	needed: AccessLevel,
) -> ClResult<FileAccessResult> {
	let entries = access_entries(app, tn_id, id).await?;
	let mut candidates = admitted(app, tn_id, entries, ctx, None).await?;
	candidates.retain(|(_, level)| *level != AccessLevel::None && *level >= needed);
	let (file_view, access_level) = single_placement(candidates)?;
	Ok(FileAccessResult { file_view, access_level, read_only: !access_level.can_write() })
}

async fn access_result(
	app: &App,
	tn_id: TnId,
	entries: Vec<FileView>,
	ctx: &FileAccessCtx<'_>,
	via: Option<&str>,
) -> Result<FileAccessResult, FileAccessError> {
	let (file_view, mut access_level) = match union_access(app, tn_id, entries, ctx, None).await {
		Ok(r) => r,
		Err(Error::NotFound) => return Err(FileAccessError::NotFound),
		Err(Error::PermissionDenied) => return Err(FileAccessError::AccessDenied),
		Err(e) => return Err(FileAccessError::InternalError(e.to_string())),
	};

	// Cap access by file-to-file share entry when opened via embedding
	// (resource = target, subject = the embedding container)
	if let Some(via_file_id) = via
		&& ctx.scope.is_none()
		&& access_level != AccessLevel::None
	{
		// The embedding container is named by any file id — a deduplicated content id names
		// several placements. Share entries hold entry ids: weigh every placement the caller
		// reaches, and take the best link. None (or a lookup failure) means no embedding: deny.
		let vias = access_entries(app, tn_id, via_file_id).await.unwrap_or_default();
		let reachable = admitted(app, tn_id, vias, ctx, None).await.unwrap_or_default();
		let mut link: Option<AccessLevel> = None;
		for (v, _) in &reachable {
			if let Ok(Some(perm)) = app
				.meta_adapter
				.check_share_access(tn_id, 'F', &file_view.entry_id, 'F', &v.entry_id)
				.await
			{
				let perm = AccessLevel::from_perm_char(perm);
				link = Some(link.map_or(perm, |l| l.max(perm)));
			}
		}
		access_level = link.map_or(AccessLevel::None, |p| access_level.min(p));
	}

	if access_level == AccessLevel::None {
		return Err(FileAccessError::AccessDenied);
	}

	let read_only = !access_level.can_write();

	Ok(FileAccessResult { file_view, access_level, read_only })
}

/// Result of checking whether a file is allowed by scope
pub enum ScopeCheck {
	/// No scope restriction — fall through to normal access checks
	NoScope,
	/// File is within scope with this access level
	Allowed(AccessLevel),
	/// File is outside scope — deny access
	Denied,
}

/// Check if a file operation is allowed by scope.
///
/// Returns `ScopeCheck::NoScope` when there is no scope restriction,
/// `ScopeCheck::Allowed(level)` when the file is within scope,
/// or `ScopeCheck::Denied` when the file is outside scope.
///
/// The scope names an entry; it is resolved like `read_file` and matched against `file`'s
/// `entry_id`, or against its `root_id` by the scope target's content `file_id`.
pub async fn check_scope_allows_file(
	meta: &Arc<dyn meta_adapter::MetaAdapter>,
	tn_id: TnId,
	scope: Option<&str>,
	file: &FileView,
) -> ScopeCheck {
	let Some(scope_str) = scope else { return ScopeCheck::NoScope };
	// If a scope string is present but can't be parsed, deny access (least privilege)
	let Some(token_scope) = TokenScope::parse(scope_str) else { return ScopeCheck::Denied };
	match &token_scope {
		TokenScope::File { file_id: scope_file_id, access, .. } => {
			let Some(target) = resolve_scope_entry(meta, tn_id, scope_file_id).await else {
				return ScopeCheck::Denied;
			};
			// Direct match, or document tree: scope is for a root, this file is a child in the
			// root entry's drive
			if target.entry_id == file.entry_id
				|| (file.root_id.as_deref().is_some_and(|r| Some(r) == target.file_id.as_deref())
					&& file.channel == target.channel)
			{
				return ScopeCheck::Allowed(*access);
			}
			ScopeCheck::Denied
		}
		TokenScope::ApkgPublish => ScopeCheck::Denied,
	}
}

/// Check if a scoped token allows file creation, honoring folder subtrees.
///
/// Like the simple document-tree scope check (Write scope where
/// `root_id == scope_file_id`), but also permits creation when the new file's
/// parent is the scoped folder itself or a descendant of it. This is the path
/// used by folder share links with editor (Write) access, letting guests upload
/// directly into the shared folder (or any subfolder).
///
/// Allowed (with Write scope) when ANY of:
/// - `root_id == scope_file_id` (document-tree rule, same as the sync variant)
/// - `parent_id == scope_file_id` (direct child of the shared folder)
/// - `parent_id` is a descendant of `scope_file_id` (nested subfolder)
///
/// Returns `Ok(())` if allowed, `Err(Error::PermissionDenied)` if denied.
pub async fn check_scope_allows_create_in(
	meta: &Arc<dyn meta_adapter::MetaAdapter>,
	cache: &DirCache,
	tn_id: TnId,
	scope: Option<&str>,
	parent_id: Option<&str>,
	root_id: Option<&str>,
) -> Result<(), Error> {
	let Some(scope_str) = scope else { return Ok(()) };
	// If a scope string is present but can't be parsed, deny access (least privilege)
	let Some(token_scope) = TokenScope::parse(scope_str) else {
		return Err(Error::PermissionDenied);
	};
	match &token_scope {
		TokenScope::File { file_id: scope_file_id, access, .. } => {
			if !access.can_write() {
				return Err(Error::PermissionDenied);
			}
			// The scope names an entry; `root_id` names content. Resolve the scope target.
			let Some(target) = resolve_scope_entry(meta, tn_id, scope_file_id).await else {
				return Err(Error::PermissionDenied);
			};
			let scope_file_id = &*target.entry_id;
			// Document-tree rule: new file is a child in the scoped document tree.
			if root_id.is_some_and(|r| Some(r) == target.file_id.as_deref()) {
				return Ok(());
			}
			// Folder-subtree rule: new file's parent is the scoped folder or nested
			// under it. Only applies when the scoped target is actually a folder, so
			// a document/file share link can't authorize creation across its
			// parent_id siblings.
			if let Some(parent) = parent_id
				&& scope_target_is_folder(meta, cache, tn_id, scope_file_id).await?
				&& (parent == scope_file_id
					|| is_descendant_of(meta, cache, tn_id, parent, scope_file_id).await?)
			{
				return Ok(());
			}
			Err(Error::PermissionDenied)
		}
		TokenScope::ApkgPublish => Ok(()), // Middleware already restricts to /api/files/apkg/
	}
}

/// The scope char a token mint may stamp for a caller who asked for `requested` and
/// actually holds `held`: never more than they hold, and never share-management
/// authority — [`AccessLevel::to_scope_char`] caps `Admin` at `'W'`. `None` when nothing
/// may be granted.
///
/// Shared by both minting paths in `cloudillo_auth::handler::get_access_token` so a cap
/// can never be tightened on one and forgotten on the other.
pub fn scope_char_within(requested: AccessLevel, held: AccessLevel) -> Option<char> {
	requested.min(held).to_scope_char()
}

/// Returns true when a scoped token is itself sufficient authorization for a
/// collection-level operation, letting the middleware skip the role/quota path.
///
/// A file share link with Write access authorizes file *creation* only; the
/// file handlers (`check_scope_allows_create_in`) then enforce the scope's
/// subtree boundary. It must NOT authorize action/app creation, trash emptying,
/// or any other collection operation.
pub fn scope_grants_collection_op(scope: Option<&str>, resource_type: &str, action: &str) -> bool {
	let Some(scope) = scope else { return false };
	// `Write` is the top of the scope vocabulary — `AccessLevel::to_scope_char` caps `Admin` at
	// `'W'` and `TokenScope::parse` refuses any other char, so `Admin` is unreachable here.
	matches!(TokenScope::parse(scope), Some(TokenScope::File { access: AccessLevel::Write, .. }))
		&& resource_type == "file"
		&& action == "create"
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn visibility_subject_strips_a_scoped_caller_to_a_guest() {
		let roles: [Box<str>; 1] = ["leader".into()];
		let scoped = FileAccessCtx {
			user_id_tag: "alice",
			tenant_id_tag: "club",
			user_roles: &roles,
			hatted: true,
			scope: Some("file:f1~x:R"),
			names_holder: true,
		};
		let g = scoped.visibility_subject();
		assert_eq!(
			(g.user_id_tag, g.tenant_id_tag, g.user_roles.len(), g.hatted, g.scope),
			("", "club", 0, false, None)
		);

		let plain = FileAccessCtx { scope: None, ..scoped };
		let p = plain.visibility_subject();
		assert_eq!(
			(p.user_id_tag, p.tenant_id_tag, p.user_roles.len(), p.hatted, p.scope),
			("alice", "club", 1, true, None)
		);
	}

	#[test]
	fn folder_write_scope_grants_file_create() {
		assert!(scope_grants_collection_op(Some("file:f1~abc:W"), "file", "create"));
	}

	#[test]
	fn write_scope_denies_non_file_create_ops() {
		assert!(!scope_grants_collection_op(Some("file:f1~abc:W"), "action", "create"));
		assert!(!scope_grants_collection_op(Some("file:f1~abc:W"), "file", "delete"));
	}

	#[test]
	fn read_scope_denies_file_create() {
		assert!(!scope_grants_collection_op(Some("file:f1~abc:R"), "file", "create"));
	}

	#[test]
	fn no_scope_denies_file_create() {
		assert!(!scope_grants_collection_op(None, "file", "create"));
	}

	#[test]
	fn unparseable_scope_denies_file_create() {
		assert!(!scope_grants_collection_op(Some("not-a-valid-scope"), "file", "create"));
	}

	#[test]
	fn role_access_level_requires_a_known_role() {
		// The federated-stranger case.
		assert_eq!(role_access_level(&[]), AccessLevel::None);
		// A single empty role string is not a role.
		assert_eq!(role_access_level(&["".into()]), AccessLevel::None);
		assert_eq!(role_access_level(&["SADM".into()]), AccessLevel::None);
	}

	#[test]
	fn role_access_level_maps_community_roles() {
		// A derived follower (expanded to public+follower) gets no file access.
		assert_eq!(role_access_level(&["public".into()]), AccessLevel::None);
		assert_eq!(role_access_level(&["follower".into()]), AccessLevel::None);
		assert_eq!(role_access_level(&["public".into(), "follower".into()]), AccessLevel::None);
		assert_eq!(role_access_level(&["supporter".into()]), AccessLevel::Read);
		assert_eq!(role_access_level(&["contributor".into()]), AccessLevel::Write);
		assert_eq!(role_access_level(&["moderator".into()]), AccessLevel::Write);
		// Leadership over a local file carries share management, hence Admin not Write.
		assert_eq!(role_access_level(&["leader".into()]), AccessLevel::Admin);
		// The highest role in a mixed set wins.
		assert_eq!(
			role_access_level(&["public".into(), "follower".into(), "leader".into()]),
			AccessLevel::Admin
		);
		assert_eq!(role_access_level(&["public".into(), "contributor".into()]), AccessLevel::Write);
	}

	#[test]
	fn channel_gate_only_admits_enterable_rooms() {
		let set: &[Box<str>] = &["@t.example~open".into()];
		assert!(channel_in("@t.example~open", Some(set)));
		assert!(!channel_in("@t.example~closed", Some(set)));
		assert!(!channel_in("@t.example~open", Some(&[])));
		// The tenant itself is unrestricted.
		assert!(channel_in("@t.example~closed", None));
	}

	/// The node an FSHR-accepted entry is mirrored from — `entries.upstream_tag`, not its owner.
	const UPSTREAM: &str = "alice.example.com";
	const ATTACKER: &str = "mallory.example.com";

	#[test]
	fn fshr_from_a_non_upstream_grants_nothing() {
		// The action row is stored before `fshr::on_create` runs and a hook denial does not roll it
		// back, so any contributor — or any followed peer posting to the inbox — can self-address
		// an FSHR naming someone else's file. Every sub-type must be inert, `ADMIN` above all: it
		// would otherwise read back as share-manager standing with an admin grant ceiling.
		for sub_typ in [Some("ADMIN"), Some("WRITE"), Some("COMMENT"), Some("READ"), None] {
			assert_eq!(
				fshr_grant_level("FSHR", sub_typ, ATTACKER, Some(UPSTREAM), "f1~doc"),
				AccessLevel::None,
				"{sub_typ:?} from a non-upstream issuer must grant nothing"
			);
		}
	}

	#[test]
	fn fshr_from_the_upstream_grants_its_sub_type() {
		// The live path: on the recipient's node `fshr::on_accept` writes `upstream_tag = issuer`, so
		// the grant resolves exactly as the sender sent it. It stays live because `get_access_level`'s
		// owner shortcut is gated on `upstream_id_tag.is_none()` — without that gate the recipient
		// tenant would return `Admin` at step 1 and never reach here.
		for (sub_typ, level) in [
			(Some("ADMIN"), AccessLevel::Admin),
			(Some("WRITE"), AccessLevel::Write),
			(Some("COMMENT"), AccessLevel::Comment),
			(Some("READ"), AccessLevel::Read),
			(None, AccessLevel::Read),
		] {
			assert_eq!(
				fshr_grant_level("FSHR", sub_typ, UPSTREAM, Some(UPSTREAM), "f1~doc"),
				level
			);
		}
	}

	#[test]
	fn a_del_from_the_upstream_revokes_rather_than_granting_read() {
		// `delete_share` drops the `share_entries` row and emits an FSHR `DEL`, which — same key —
		// overwrites the grant. Falling through to the catch-all would hand the read back.
		assert_eq!(
			fshr_grant_level("FSHR", Some("DEL"), UPSTREAM, Some(UPSTREAM), "f1~doc"),
			AccessLevel::None
		);
	}

	#[test]
	fn fshr_on_a_locally_originating_row_grants_nothing() {
		// `upstream_tag` NULL means the row originates here: nobody is in a position to have granted
		// access to it from elsewhere, so no FSHR on it is credible — not even from the owner, whose
		// own access already resolved at step 1.
		for issuer in [UPSTREAM, ATTACKER] {
			for sub_typ in [Some("ADMIN"), Some("WRITE"), Some("COMMENT"), Some("READ"), None] {
				assert_eq!(
					fshr_grant_level("FSHR", sub_typ, issuer, None, "f1~doc"),
					AccessLevel::None,
					"{sub_typ:?} on a local row must grant nothing"
				);
			}
		}
	}

	#[test]
	fn only_fshr_rows_grant_anything() {
		// The key is `FSHR:{file}:{audience}`, but `get_action_by_key` does not filter on type.
		assert_eq!(
			fshr_grant_level("CONN", Some("ADMIN"), UPSTREAM, Some(UPSTREAM), "f1~doc"),
			AccessLevel::None
		);
	}

	fn entry(entry_id: &str, action_id: Option<&str>) -> (FileView, ()) {
		let json = serde_json::json!({
			"entryId": entry_id, "fileId": "f1~c", "fileName": "x", "createdAt": 0, "status": "A",
		});
		let Ok(mut view) = serde_json::from_value::<FileView>(json) else {
			unreachable!("file view");
		};
		view.action_id = action_id.map(Into::into);
		(view, ())
	}

	/// PMG-04: a content id skips managed entries while a user entry qualifies; managed only →
	/// one is picked, several are a `Conflict`.
	#[test]
	fn single_placement_skips_managed_entries() {
		let picked = single_placement(vec![entry("m1", Some("a1~x")), entry("u1", None)]);
		assert!(matches!(picked, Ok((v, ())) if &*v.entry_id == "u1"));

		let picked = single_placement(vec![entry("m1", Some("a1~x"))]);
		assert!(matches!(picked, Ok((v, ())) if &*v.entry_id == "m1"));

		let picked = single_placement(vec![entry("m1", Some("a1~x")), entry("m2", Some("a1~y"))]);
		assert!(matches!(picked, Err(Error::Conflict(_))));

		let picked = single_placement(vec![entry("u1", None), entry("u2", None)]);
		assert!(matches!(picked, Err(Error::Conflict(_))));
	}
}

// vim: ts=4
