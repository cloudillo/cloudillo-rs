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
pub struct FileAccessCtx<'a> {
	pub user_id_tag: &'a str,
	pub tenant_id_tag: &'a str,
	pub user_roles: &'a [Box<str>],
}

/// The object side of a file access check: which row, plus its two ownership facts.
///
/// Kept apart from [`FileAccessCtx`], which describes the *subject*: mixing the two would let a
/// caller hand in an upstream that does not belong to the row it is asking about.
#[derive(Clone, Copy)]
pub struct FileRef<'a> {
	/// Authority. A NULL `files.owner_tag` resolves to the tenant.
	pub owner_id_tag: &'a str,
	/// Provenance, not authority. `None` means the row originates here, which is what gates the
	/// owner shortcut and role access below. Never falls back to the tenant.
	pub upstream_id_tag: Option<&'a str>,
	pub file_id: &'a str,
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
			file_id: &view.file_id,
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
pub fn role_access_level(user_roles: &[Box<str>]) -> AccessLevel {
	// A leader resolves to `Admin`, not `Write`: leadership over a local file *is* the right
	// to manage its share set, so `access_level` alone answers "may manage shares".
	if user_roles.iter().any(|r| r.as_ref() == "leader") {
		return AccessLevel::Admin;
	}
	if user_roles.iter().any(|r| matches!(r.as_ref(), "moderator" | "contributor")) {
		return AccessLevel::Write;
	}
	if user_roles
		.iter()
		.any(|r| matches!(r.as_ref(), "public" | "follower" | "supporter"))
	{
		return AccessLevel::Read;
	}
	AccessLevel::None
}

/// Resolve the grant an `FSHR:{file_id}:{audience}` action row carries: `ADMIN` → Admin, `WRITE` →
/// Write, `COMMENT` → Comment, `DEL` → None (a revocation is not a grant), anything else → Read.
///
/// An FSHR is a *claim by its issuer* that they granted access, so only the node the row is
/// mirrored from — its `upstream_tag` — can make it credibly. Testing the *owner* instead would be
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
/// Both live paths survive the test: on the recipient's node `fshr::on_accept` creates the file row
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

/// Get access level for a user on a file
///
/// Determines access level based on:
/// 1. Ownership — the owner of a locally originating row has Admin access
/// 2. Direct `share_entries` grant on this file, then the caller-supplied `inherited_share`, then a
///    parent-chain walk for a folder-inherited grant
/// 3. Role-based access — any locally originating row (`upstream_id_tag` is `None`): leader →
///    Admin, moderator/contributor → Write, any role → Read. `role_access_level` ignores
///    `visibility`, so this deliberately reaches a peer member's own upload too.
/// 4. FSHR action issued by the row's upstream source — ADMIN → Admin, WRITE → Write, COMMENT → Comment,
///    DEL → None (a revocation is not a grant), other sub-types → Read (see [`fshr_grant_level`])
/// 5. Placer read on a mirrored row with no FSHR at all — a Pin/Place copy stays readable by the
///    profile that placed it. Read only, and last, so a revoked FSHR does not reach it.
/// 6. No access — returns None
pub async fn get_access_level(
	app: &App,
	tn_id: TnId,
	file: FileRef<'_>,
	ctx: &FileAccessCtx<'_>,
	inherited_share: Option<AccessLevel>,
) -> AccessLevel {
	let FileRef { file_id, owner_id_tag, upstream_id_tag } = file;
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
	if let Ok(Some(perm)) = app
		.meta_adapter
		.check_share_access(tn_id, 'F', file_id, 'U', ctx.user_id_tag)
		.await
	{
		return AccessLevel::from_perm_char(perm);
	}
	// Inherited share from parent folder (already resolved by caller)
	if let Some(level) = inherited_share {
		return level;
	}
	// No known inheritance — walk the parent chain
	if let Some(level) = walk_parent_chain_for_share(app, tn_id, file_id, ctx.user_id_tag).await {
		return level;
	}

	// Role-based access. A mirrored row (Pin/Place copy, FSHR-accepted share) names its source in
	// `upstream_tag` and its access is that node's business — roles held here say nothing about it.
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
	if role_level != AccessLevel::None {
		return role_level;
	}

	// Look up FSHR action: key pattern is "FSHR:{file_id}:{audience}"
	let action_key = format!("FSHR:{}:{}", file_id, ctx.user_id_tag);

	// `get_action_by_key` does not filter on action status, so a pending ('C') or rejected FSHR
	// resolves here too. Moot in practice: the local file row only exists once `on_accept` ran.
	match app.meta_adapter.get_action_by_key(tn_id, &action_key).await {
		Ok(Some(action)) => fshr_grant_level(
			&action.typ,
			action.sub_typ.as_ref().map(AsRef::as_ref),
			&action.issuer_tag,
			upstream_id_tag,
			file_id,
		),
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

/// Get access level for a user on a file, considering scoped tokens
///
/// Determines access level based on:
/// 1. Scoped token — file:{file_id}:{R|C|W} grants Read/Comment/Write access
///    (also checks document tree: a token for a root grants access to children)
/// 2. Everything [`get_access_level`] resolves, in its order
/// 3. No access — returns None
pub async fn get_access_level_with_scope(
	app: &App,
	tn_id: TnId,
	file: FileRef<'_>,
	ctx: &FileAccessCtx<'_>,
	scope: Option<&str>,
	root_id: Option<&str>,
) -> AccessLevel {
	let file_id = file.file_id;
	// Check scope-based access first (for share links)
	if let Some(scope_str) = scope {
		// Use typed TokenScope for safe parsing
		if let Some(token_scope) = TokenScope::parse(scope_str) {
			match &token_scope {
				TokenScope::File { file_id: scope_file_id, access } => {
					// Direct match: scope matches this file_id
					if scope_file_id == file_id {
						return *access;
					}

					// Document tree check: scope is for a root, this file is a child
					// Depth-1 invariant: root_id always points directly to a top-level file
					if let Some(root) = root_id
						&& scope_file_id.as_str() == root
					{
						return *access;
					}

					// Cross-document link: file-type share entry ('F')
					// If scope grants access to file A, check if there's a share entry
					// linking file A → target file
					// resource=container (scope_file_id), subject=target (file_id)
					if let Ok(Some(perm)) = app
						.meta_adapter
						.check_share_access(tn_id, 'F', scope_file_id, 'F', file_id)
						.await
					{
						// Cap at min(scope_access, share_permission)
						return (*access).min(AccessLevel::from_perm_char(perm));
					}

					// Folder share: scope targets a folder; grant the scope's level
					// to any file nested under it (linked via parent_id). Gated on
					// the scoped target actually being a folder, so a document/file
					// share link does not leak access across its parent_id siblings.
					// Fails closed — a missing cache or read error yields no grant,
					// since returning a bare AccessLevel here cannot signal a 5xx.
					// DirCache is a required process-wide extension registered at app
					// build (see crates/cloudillo/src/app.rs), so the else arm only
					// fires on misconfiguration — log rather than fail silently.
					if let Ok(cache) = app.ext::<DirCache>() {
						let target_is_folder =
							scope_target_is_folder(&app.meta_adapter, cache, tn_id, scope_file_id)
								.await
								.unwrap_or(false);
						let nested_under_scope = target_is_folder
							&& is_descendant_of(
								&app.meta_adapter,
								cache,
								tn_id,
								file_id,
								scope_file_id,
							)
							.await
							.unwrap_or(false);
						if nested_under_scope {
							return *access;
						}
					} else {
						warn!("DirCache extension missing; folder-share scope grant skipped");
					}

					// Scope exists for a different file - deny access
					return AccessLevel::None;
				}
				TokenScope::ApkgPublish => {
					// APKG publish scope has no file access
					return AccessLevel::None;
				}
			}
		}
		// Scope string present but unparseable — deny access (least privilege)
		return AccessLevel::None;
	}

	// Fall back to existing logic (ownership, roles, FSHR actions)
	get_access_level(app, tn_id, file, ctx, None).await
}

/// Whether the file's own `visibility` alone grants a caller `Read`, for the ladder
/// [`check_file_access_with_scope`] falls back to once every explicit grant has come up
/// empty. `'P'` is handled separately by that caller and is deliberately not here.
///
/// `scope.is_none()` is the one gate: a share-link token carries `sub: None`, so on
/// re-presentation `auth.id_tag` is the *tenant's own* id_tag and such a guest would be
/// scored against the tenant's own relationships. It also keeps
/// `get_access_level_with_scope`'s deliberate `None` for a non-matching scope final.
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
pub fn visibility_grants_read_fallback(
	scope: Option<&str>,
	visibility: Option<char>,
	is_real_auth: bool,
	rel: meta_adapter::ProfileRelation,
) -> bool {
	scope.is_none()
		&& abac::relationship_level(false, rel.connected, rel.follower, is_real_auth)
			.can_access(abac::VisibilityLevel::from_char(visibility))
}

/// Check file access and return file view with access level
///
/// This is the main helper for WebSocket handlers. It:
/// 1. Loads file metadata
/// 2. Determines access level (considering scoped tokens for share links)
/// 3. Falls back to the file's `visibility` for unscoped callers on tenant-owned rows —
///    `'P'` for anyone, `'V'`/`'2'`/`'F'`/`'C'` per the subject's relationship *to the
///    tenant* (see [`visibility_grants_read_fallback`]). Never grants more than `Read`;
///    `Direct` (NULL) and `'S'` grant nothing.
/// 4. Returns combined result or error
///
/// The scope parameter should be auth_ctx.scope.as_deref().
pub async fn check_file_access_with_scope(
	app: &App,
	tn_id: TnId,
	file_id: &str,
	ctx: &FileAccessCtx<'_>,
	scope: Option<&str>,
	via: Option<&str>,
) -> Result<FileAccessResult, FileAccessError> {
	use tracing::debug;

	// Load file metadata
	let file_view = match app.meta_adapter.read_file(tn_id, file_id).await {
		Ok(Some(f)) => f,
		Ok(None) => return Err(FileAccessError::NotFound),
		Err(e) => return Err(FileAccessError::InternalError(e.to_string())),
	};

	// Both ownership facts come off the row itself, so this function's callers cannot forget the
	// upstream and hand a mirrored row role access.
	let file_ref = FileRef::from_view(&file_view, ctx.tenant_id_tag);

	debug!(file_id = file_id, user = ctx.user_id_tag, owner = file_ref.owner_id_tag, scope = ?scope, "Checking file access");

	// Get access level (considering scope for share links and document trees)
	let mut access_level =
		get_access_level_with_scope(app, tn_id, file_ref, ctx, scope, file_view.root_id.as_deref())
			.await;

	// Public files are readable by anyone (including unauthenticated guests).
	// Deliberately scope-agnostic and separate from the ladder below: a scoped
	// caller reaching an unrelated *public* file is relied on by
	// `share::list_shares_by_subject` and `management::duplicate_file`.
	if access_level == AccessLevel::None && file_view.visibility == Some('P') {
		access_level = AccessLevel::Read;
	}

	// The rest of the visibility ladder ('V'/'2'/'F'/'C'); the whole decision lives in
	// `visibility_grants_read_fallback`, which the integration tests call directly.
	if access_level == AccessLevel::None {
		let vis = abac::VisibilityLevel::from_char(file_view.visibility);
		let is_real_auth = !ctx.user_id_tag.is_empty() && ctx.user_id_tag != "guest";
		// Only 'F'/'C'/'2' need the profile row; 'V' is settled by authentication alone.
		// The scope case is not re-tested here — the fallback refuses it anyway, so the
		// only cost of loading `rel` is one read on a row that was going to be denied.
		let rel = if is_real_auth && abac::visibility_needs_relation(vis) {
			abac::subject_relation_to_tenant(app, tn_id, ctx.user_id_tag)
				.await
				.map_err(|e| FileAccessError::InternalError(e.to_string()))?
		} else {
			meta_adapter::ProfileRelation::default()
		};
		if visibility_grants_read_fallback(scope, file_view.visibility, is_real_auth, rel) {
			access_level = AccessLevel::Read;
		}
	}

	// Cap access by file-to-file share entry when opened via embedding
	if let Some(via_file_id) = via
		&& scope.is_none()
		&& access_level != AccessLevel::None
	{
		match app.meta_adapter.check_share_access(tn_id, 'F', via_file_id, 'F', file_id).await {
			Ok(Some(perm)) => {
				access_level = access_level.min(AccessLevel::from_perm_char(perm));
			}
			Ok(None) | Err(_) => {
				// No file-to-file share entry — embedding doesn't exist, deny
				access_level = AccessLevel::None;
			}
		}
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
pub fn check_scope_allows_file(
	scope: Option<&str>,
	file_id: &str,
	root_id: Option<&str>,
) -> ScopeCheck {
	let Some(scope_str) = scope else { return ScopeCheck::NoScope };
	// If a scope string is present but can't be parsed, deny access (least privilege)
	let Some(token_scope) = TokenScope::parse(scope_str) else { return ScopeCheck::Denied };
	match &token_scope {
		TokenScope::File { file_id: scope_file_id, access } => {
			// Direct match: scope matches this file_id
			if scope_file_id == file_id {
				return ScopeCheck::Allowed(*access);
			}
			// Document tree check: scope is for a root, this file is a child
			if let Some(root) = root_id
				&& scope_file_id.as_str() == root
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
		TokenScope::File { file_id: scope_file_id, access } => {
			if !access.can_write() {
				return Err(Error::PermissionDenied);
			}
			// Document-tree rule: new file is a child in the scoped document tree.
			if root_id == Some(scope_file_id.as_str()) {
				return Ok(());
			}
			// Folder-subtree rule: new file's parent is the scoped folder or nested
			// under it. Only applies when the scoped target is actually a folder, so
			// a document/file share link can't authorize creation across its
			// parent_id siblings.
			if let Some(parent) = parent_id
				&& scope_target_is_folder(meta, cache, tn_id, scope_file_id).await?
				&& (parent == scope_file_id.as_str()
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
		assert_eq!(role_access_level(&["public".into()]), AccessLevel::Read);
		assert_eq!(role_access_level(&["follower".into()]), AccessLevel::Read);
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

	/// The node an FSHR-accepted row is mirrored from — `files.upstream_tag`, not its owner.
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
}

// vim: ts=4
