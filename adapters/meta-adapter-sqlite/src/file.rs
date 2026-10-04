// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! File management and variant handling

use std::collections::HashSet;

use sqlx::{Row, SqlitePool, sqlite::SqliteRow};

use crate::utils::{Db, collect_res, map_res, parse_str_list, push_patch};
use cloudillo_types::meta_adapter::{
	BrokenReason, ContentInfo, CreateFile, CreatedFile, DeleteFileResult, FileId, FileResolution,
	FileStatus, FileUserData, FileVariant, FileView, ListFileOptions, ProfileInfo, ProfileType,
	ROOT_PARENT_ID, SHARE_FILE_REF_TYPE, UpdateFileOptions,
};
use cloudillo_types::prelude::*;
use cloudillo_types::types::AccessLevel;
use cloudillo_types::utils::normalize_id_tag;

/// Build a ProfileInfo from raw SQL columns with the given prefix.
/// Returns None if the id_tag column is NULL or empty (i.e. the LEFT JOIN didn't match).
fn profile_from_row(row: &SqliteRow, prefix: &str) -> Option<ProfileInfo> {
	let id_tag: Box<str> = row
		.try_get::<Box<str>, _>(&*format!("{prefix}id_tag"))
		.ok()
		.filter(|s| !s.as_ref().is_empty())?;
	let name: Box<str> =
		row.try_get(&*format!("{prefix}name")).ok().unwrap_or_else(|| id_tag.clone());
	let typ = match row.try_get::<&str, _>(&*format!("{prefix}type")).ok() {
		Some("C") => ProfileType::Community,
		_ => ProfileType::Person,
	};
	let profile_pic: Option<Box<str>> = row.try_get(&*format!("{prefix}profile_pic")).ok();
	Some(ProfileInfo { id_tag, name, typ, profile_pic })
}

/// Map the on-disk `broken_reason` text to the typed enum. Unknown / NULL
/// strings produce `None`; callers should treat that as "no tombstone".
fn parse_broken_reason(s: Option<&str>) -> Option<BrokenReason> {
	match s {
		Some("deleted") => Some(BrokenReason::Deleted),
		Some("revoked") => Some(BrokenReason::Revoked),
		None => None,
		Some(other) => {
			warn!("unknown broken_reason on disk: {}", other);
			None
		}
	}
}

/// Build a tag-only ProfileInfo for when the tag is set but no local profile exists.
fn tag_only_profile(tag: &str) -> ProfileInfo {
	ProfileInfo { id_tag: tag.into(), name: "".into(), typ: ProfileType::Person, profile_pic: None }
}

/// Build the upstream ProfileInfo: upstream profile → upstream tag-only → None.
/// No tenant fallback — a NULL `upstream_tag` means the entry originates here.
fn build_upstream_profile(row: &SqliteRow) -> Option<ProfileInfo> {
	let upstream_tag: Option<Box<str>> = row.try_get("upstream_tag").ok().flatten();
	profile_from_row(row, "upstream_").or_else(|| upstream_tag.as_deref().map(tag_only_profile))
}

/// Build the owner ProfileInfo with fallback chain:
/// owner profile → tenant profile (when the owner IS the tenant, which has no `profiles` row
/// of its own) → owner tag-only → tenant. A NULL `owner_tag` means the tenant owns the row.
fn build_owner_profile(row: &SqliteRow) -> Option<ProfileInfo> {
	let owner_tag: Option<Box<str>> = row.try_get("owner_tag").ok().flatten();
	let tn_id_tag: Option<Box<str>> = row.try_get("tn_id_tag").ok();
	if let Some(p) = profile_from_row(row, "owner_") {
		return Some(p);
	}
	match owner_tag {
		Some(tag) if Some(tag.as_ref()) != tn_id_tag.as_deref() => Some(tag_only_profile(&tag)),
		_ => profile_from_row(row, "tn_"),
	}
}

/// `Some(f_id)` for an `@<f_id>` id, `None` for any other id.
fn parse_f_id(id: &str) -> ClResult<Option<i64>> {
	id.strip_prefix('@')
		.map(|n| n.parse().map_err(|_| Error::ValidationError("invalid f_id".into())))
		.transpose()
}

/// Get file_id by numeric f_id (following a dedup redirect)
pub(crate) async fn get_id(db: &SqlitePool, tn_id: TnId, f_id: u64) -> ClResult<Box<str>> {
	let res = sqlx::query(concat!(
		"SELECT file_id FROM files o WHERE o.tn_id=? AND o.f_id=",
		canon_f_id!("o.tn_id")
	))
	.bind(tn_id.0)
	.bind(f_id.cast_signed())
	.fetch_one(db)
	.await;

	map_res(res, |row| row.try_get("file_id"))
}

/// Columns every `FileView` read selects. Alias convention: `e` = entries (placement),
/// `f` = files (content, NULL for folders and references). `file_id` falls back to `@<f_id>` for
/// a pending upload and to the upstream content id for a reference (NULL for a local folder);
/// `file_tp` reports folders as `'FLDR'` and `content_type` as `cloudillo/folder` (clients require
/// it). A reference's content fields come off its `ref_*` columns: it holds no local `files` row.
const FILE_VIEW_COLS: &str = "e.e_id, e.entry_id, f.f_id, \
	COALESCE(f.file_id, '@' || f.f_id, e.ref_file_id) AS file_id, \
	e.parent_id, f.root_id, e.file_name, \
	CASE WHEN e.ref_file_id IS NOT NULL THEN e.ref_file_tp \
	WHEN e.f_id IS NULL THEN 'FLDR' ELSE f.file_tp END AS file_tp, \
	e.created_at, f.accessed_at, f.modified_at, e.status, e.tags, e.upstream_tag, e.owner_tag, \
	e.action_id, COALESCE(f.preset, e.ref_preset) AS preset, \
	CASE WHEN e.f_id IS NULL AND e.ref_file_id IS NULL THEN 'cloudillo/folder' \
	ELSE COALESCE(f.content_type, e.ref_content_type) END AS content_type, e.visibility, \
	e.hidden, COALESCE(f.x, e.ref_x) AS x, e.broken_at, e.broken_reason, e.channel, \
	t.id_tag as tn_id_tag, t.name as tn_name, t.type as tn_type, t.profile_pic as tn_profile_pic, \
	p.id_tag as upstream_id_tag, p.name as upstream_name, p.type as upstream_type, \
	p.profile_pic as upstream_profile_pic, \
	p2.id_tag as owner_id_tag, p2.name as owner_name, p2.type as owner_type, \
	p2.profile_pic as owner_profile_pic";

/// Per-user columns from the `fud` (`file_user_data`) join, read by [`user_data_from_row`].
const FUD_COLS: &str = ", fud.accessed_at as fud_accessed_at, fud.modified_at as fud_modified_at, \
	fud.pinned as fud_pinned, fud.starred as fud_starred, fud.access_level as fud_access_level";

type OptStr = Option<Box<str>>;

/// `FROM` clause matching [`FILE_VIEW_COLS`].
const FILE_VIEW_FROM: &str = " FROM entries e \
	LEFT JOIN files f ON f.f_id=e.f_id \
	INNER JOIN tenants t ON t.tn_id=e.tn_id \
	LEFT JOIN profiles p ON p.tn_id=e.tn_id AND p.id_tag=e.upstream_tag \
	LEFT JOIN profiles p2 ON p2.tn_id=e.tn_id AND p2.id_tag=e.owner_tag";

/// A live entry: active and not in the trash. Alias `e`. Managed entries count: an action
/// attachment is reached by its content id. Search adds [`NOT_MANAGED`] on top.
pub(crate) const LIVE_ENTRY: &str = "e.status='A' AND e.parent_id IS NOT '__trash__'";

/// Excludes managed attachment entries (`MANAGED_PARENT_ID`). Alias `e`.
pub(crate) const NOT_MANAGED: &str = "e.parent_id IS NOT '__managed__'";

/// What [`resolve`] found for an id.
enum Resolved {
	None,
	One(i64),
	Many,
}

/// Resolve an id to its entry's `e_id`, in the fixed lookup order: `entries.entry_id`, then the
/// content id (`files.file_id` of a linked entry, or a reference's `ref_file_id`), then the
/// `@<f_id>` placeholder (content `files.f_id`). A tombstone is never reachable by a content id. A
/// BLOB content id and a reference count only live entries ([`LIVE_ENTRY`]): a trashed one is
/// reachable only by its own entry id, a pending one only by the `@<f_id>` its upload handed out
/// (the lifecycle gate keeps it to its uploader). Other local content has one entry, which its id
/// names whatever its state — `root_id`, scopes and links rely on that. More than one candidate
/// is ambiguous; callers with a caller context resolve through `file_access` instead.
async fn resolve(db: &SqlitePool, tn_id: TnId, id: &str) -> ClResult<Resolved> {
	let e_id: Option<i64> =
		sqlx::query_scalar("SELECT e_id FROM entries WHERE tn_id=? AND entry_id=?")
			.bind(tn_id.0)
			.bind(id)
			.fetch_optional(db)
			.await
			.db()?;
	if let Some(e_id) = e_id {
		return Ok(Resolved::One(e_id));
	}

	let candidates: Vec<i64> = if let Some(f_id) = parse_f_id(id)? {
		// Raw match, no merge redirect: after a dedup merge the `@<f_id>` names no entry and
		// the client uses its `entryId`. Content lookups (`get_id`, variants) still follow it.
		let sql = format!(
			"SELECT e_id FROM entries e WHERE e.tn_id=? AND e.f_id=? \
			 AND (({LIVE_ENTRY}) OR e.status='P')"
		);
		sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
			.bind(tn_id.0)
			.bind(f_id)
			.fetch_all(db)
			.await
			.db()?
	} else {
		let sql = format!(
			"SELECT e.e_id FROM entries e JOIN files f ON f.f_id=e.f_id \
			 WHERE f.tn_id=? AND f.file_id=? AND e.status<>'D' \
			 AND (f.file_tp IS NOT 'BLOB' OR ({LIVE_ENTRY})) \
			 UNION SELECT e.e_id FROM entries e WHERE e.tn_id=? AND e.ref_file_id=? AND {LIVE_ENTRY}"
		);
		sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
			.bind(tn_id.0)
			.bind(id)
			.bind(tn_id.0)
			.bind(id)
			.fetch_all(db)
			.await
			.db()?
	};

	Ok(match candidates.as_slice() {
		[] => Resolved::None,
		[e_id] => Resolved::One(*e_id),
		_ => Resolved::Many,
	})
}

/// [`resolve`] for callers without a caller context: several candidates are `Error::Conflict`.
pub(crate) async fn resolve_entry(db: &SqlitePool, tn_id: TnId, id: &str) -> ClResult<Option<i64>> {
	match resolve(db, tn_id, id).await? {
		Resolved::None => Ok(None),
		Resolved::One(e_id) => Ok(Some(e_id)),
		Resolved::Many => Err(Error::Conflict("file id names several entries".into())),
	}
}

/// Push `(<subquery>)` yielding every entry_id `subject` holds a live `'U'` share entry on,
/// directly or through an ancestor folder (descends `parent_id`, capped at 64 hops like
/// `file_access::MAX_PARENT_DEPTH`). A recursive CTE rather than a `DirCache` walk: the
/// grant must filter in SQL so pagination stays correct.
pub(crate) fn push_shared_file_ids(
	query: &mut sqlx::QueryBuilder<sqlx::Sqlite>,
	tn_id: TnId,
	subject: &str,
) {
	query
		.push(
			"(WITH RECURSIVE shared(id, depth) AS (\
			 SELECT resource_id, 0 FROM share_entries WHERE tn_id=",
		)
		.push_bind(tn_id.0)
		.push(" AND resource_type='F' AND subject_type='U' AND subject_id=")
		.push_bind(normalize_id_tag(subject).into_owned())
		.push(
			" AND (expires_at IS NULL OR expires_at > unixepoch()) \
			 UNION SELECT c.entry_id, s.depth + 1 FROM shared s \
			 JOIN entries c ON c.tn_id=",
		)
		.push_bind(tn_id.0)
		.push(" AND c.parent_id=s.id WHERE s.depth < 64) SELECT id FROM shared)");
}

/// `((1=1 [AND visibility|role] [AND channel]) [OR shared]` — the caller closes the outer `)`.
/// The visibility + channel gate on entry `e` (ABAC pushed into SQL for correct pagination); a
/// share entry for `share_subject`, on the entry or an ancestor folder, bypasses both.
pub(crate) fn push_entry_gate(
	q: &mut sqlx::QueryBuilder<sqlx::Sqlite>,
	tn_id: TnId,
	visible_levels: Option<&[char]>,
	role_grant: bool,
	enterable_channels: Option<&[Box<str>]>,
	share_subject: Option<&str>,
) {
	q.push("((1=1");
	if let Some(levels) = visible_levels {
		q.push(" AND (e.visibility IN (");
		let mut sep = q.separated(", ");
		for level in levels {
			sep.push_bind(level.to_string());
		}
		sep.push_unseparated(")");
		if role_grant {
			q.push(" OR e.upstream_tag IS NULL");
		}
		q.push(")");
	}
	if let Some(enterable) = enterable_channels {
		q.push(" AND ");
		crate::utils::push_channel_in(q, "e.channel", enterable);
	}
	q.push(")");
	if let Some(subject) = share_subject {
		q.push(" OR e.entry_id IN ");
		push_shared_file_ids(q, tn_id, subject);
	}
}

/// List files with filtering and pagination
pub(crate) async fn list(
	db: &SqlitePool,
	tn_id: TnId,
	opts: &ListFileOptions,
) -> ClResult<Vec<FileView>> {
	// Check if we need user-specific data (JOIN with file_user_data)
	let has_user = opts.user_id_tag.is_some();
	let needs_user_join = has_user
		&& (opts.pinned.is_some()
			|| opts.starred.is_some()
			|| matches!(opts.sort.as_deref(), Some("recent" | "modified")));

	let mut query = sqlx::QueryBuilder::new("SELECT ");
	query.push(FILE_VIEW_COLS);

	// Add user data columns if user is authenticated
	if has_user {
		query.push(FUD_COLS);
	}

	query.push(FILE_VIEW_FROM);

	// Add file_user_data JOIN if needed for filtering/sorting or to include user data
	if has_user {
		if needs_user_join && (opts.pinned == Some(true) || opts.starred == Some(true)) {
			// INNER JOIN when filtering by pinned/starred (must have the data)
			query.push(
				" INNER JOIN file_user_data fud ON fud.tn_id=e.tn_id AND fud.e_id=e.e_id AND fud.id_tag=",
			);
		} else {
			// LEFT JOIN to include user data when available
			query.push(
				" LEFT JOIN file_user_data fud ON fud.tn_id=e.tn_id AND fud.e_id=e.e_id AND fud.id_tag=",
			);
		}
		query.push_bind(normalize_id_tag(opts.user_id_tag.as_deref().unwrap_or("")).into_owned());
	}

	query.push(" WHERE e.tn_id=");
	query.push_bind(tn_id.0);

	if let Some(file_ids) = &opts.file_id {
		// Partition into @-prefixed internal IDs (content f_id) and external ids. An external id
		// matches an entry_id or a content file_id (every entry of that content).
		let mut f_ids: Vec<i64> = Vec::new();
		let mut ext_ids: Vec<&String> = Vec::new();
		for id in file_ids {
			match parse_f_id(id) {
				Ok(Some(f_id)) => f_ids.push(f_id),
				Ok(None) => ext_ids.push(id),
				// A malformed `@` id matches nothing; skip it rather than fail the list.
				Err(_) => {}
			}
		}

		let has_f_ids = !f_ids.is_empty();
		let has_ext_ids = !ext_ids.is_empty();

		if !has_f_ids && !has_ext_ids {
			// All entries were invalid @-prefixed IDs
			query.push(" AND 1=0");
		} else {
			let needs_or = has_f_ids && has_ext_ids;
			if needs_or {
				query.push(" AND (");
			} else {
				query.push(" AND ");
			}
			if has_f_ids {
				// Through the dedup redirect (see `canon_f_id!`).
				query.push(
					"f.f_id IN (SELECT COALESCE(merged_into, f_id) FROM files \
					 WHERE tn_id=e.tn_id AND f_id IN (",
				);
				let mut sep = query.separated(", ");
				for f_id in &f_ids {
					sep.push_bind(*f_id);
				}
				sep.push_unseparated("))");
			}
			if needs_or {
				query.push(" OR ");
			}
			if has_ext_ids {
				for (i, col) in ["e.entry_id", "f.file_id", "e.ref_file_id"].into_iter().enumerate()
				{
					query.push(if i == 0 { "(" } else { " OR " }).push(col).push(" IN (");
					let mut sep = query.separated(", ");
					for id in &ext_ids {
						sep.push_bind(id.as_str());
					}
					sep.push_unseparated(")");
				}
				query.push(")");
			}
			if needs_or {
				query.push(")");
			}
		}
	}

	// Filter by parent folder
	if let Some(parent_id) = &opts.parent_id {
		if parent_id == ROOT_PARENT_ID {
			// Explicit root: files with no parent (not in any folder, not in trash)
			query.push(" AND e.parent_id IS NULL");
			// Drive filter: `""` = the main drive, otherwise that room.
			match opts.channel.as_deref() {
				Some("") => {
					query.push(" AND e.channel IS NULL");
				}
				Some(channel) => {
					query.push(" AND e.channel=").push_bind(channel);
				}
				None => {}
			}
		} else {
			// Specific folder (including "__trash__" / "__managed__" for those contents)
			query.push(" AND e.parent_id=").push_bind(parent_id.as_str());
		}
	} else if opts.file_id.is_none() && !opts.sweep_all {
		// Default browse listing (no targeted fileId): exclude trashed and managed
		// files. A by-id lookup with no parentId deliberately skips this so it
		// returns the file wherever it lives (managed or trash included), and so
		// does `sweep_all`, which must see a trashed file to take its derived
		// state back out.
		query
			.push(" AND (e.parent_id IS NULL OR e.parent_id NOT IN (")
			.push_bind(cloudillo_types::meta_adapter::TRASH_PARENT_ID)
			.push(", ")
			.push_bind(cloudillo_types::meta_adapter::MANAGED_PARENT_ID)
			.push("))");
	}
	// else (fileId present, no parentId): no parent-folder predicate — return the
	// file regardless of folder.

	// Pending uploads are not browsable — default or `parentId` browse — not even by their
	// owner (lifecycle ruling). A `fileId` lookup or an explicit `status` filter reaches the
	// caller's own (owner guard below).
	if opts.status.is_none() && opts.file_id.is_none() && !opts.sweep_all {
		query.push(" AND e.status != 'P'");
	}

	// Exclude files inside a specific folder (used by the "outside this
	// folder" probe). `parent_id IS NULL` rows are kept (they live at root,
	// not inside the excluded folder).
	if let Some(not_parent_id) = &opts.not_parent_id {
		if not_parent_id == ROOT_PARENT_ID {
			query.push(" AND e.parent_id IS NOT NULL");
		} else {
			query
				.push(" AND (e.parent_id IS NULL OR e.parent_id<>")
				.push_bind(not_parent_id.as_str())
				.push(")");
		}
	}

	// Scope filter (scoped tokens, share links): the scope entry itself, or a tree child of its
	// content in the same channel. Never a sibling entry of the same content (e.g. a private
	// room placement). Overrides the normal root_id filter since scoped access spans the tree.
	if let Some(scope_eid) = &opts.scope_entry_id {
		query
			.push(" AND (e.entry_id=")
			.push_bind(scope_eid.as_str())
			.push(
				" OR EXISTS (SELECT 1 FROM entries se JOIN files sf ON sf.f_id=se.f_id \
				 WHERE se.tn_id=e.tn_id AND se.entry_id=",
			)
			.push_bind(scope_eid.as_str())
			.push(" AND f.root_id=sf.file_id AND e.channel IS se.channel))");
	} else if let Some(root_id) = &opts.root_id {
		// Filter by document tree root
		query.push(" AND f.root_id=").push_bind(root_id.as_str());
	} else if opts.include_tree_children {
		// Server-only sweeps: no root_id constraint, so files inside a document
		// tree are walked too.
	} else {
		query.push(" AND f.root_id IS NULL");
	}

	if let Some(tag) = &opts.tag {
		query
			.push(" AND e.tags LIKE ")
			.push_bind(format!("%{}%", crate::utils::escape_like(tag)))
			.push(" ESCAPE '\\'");
	}

	if let Some(preset) = &opts.preset {
		query.push(" AND COALESCE(f.preset, e.ref_preset)=").push_bind(preset.as_str());
	}

	if let Some(file_types) = &opts.file_type
		&& !file_types.is_empty()
	{
		query.push(" AND (");
		if file_types.len() == 1 {
			query
				.push("COALESCE(f.file_tp, e.ref_file_tp)=")
				.push_bind(file_types[0].as_str());
		} else {
			query.push("COALESCE(f.file_tp, e.ref_file_tp) IN ");
			query = crate::utils::push_in(query, file_types.as_slice());
		}
		if opts.include_folders {
			query.push(" OR (e.f_id IS NULL AND e.ref_file_id IS NULL)");
		}
		query.push(")");
	}

	// Filter by content type (MIME type pattern, e.g., "image/*" or "image/*,video/*")
	if let Some(content_types) = &opts.content_type
		&& !content_types.is_empty()
	{
		query.push(" AND (");
		for (i, ct) in content_types.iter().enumerate() {
			if i > 0 {
				query.push(" OR ");
			}
			let pattern = crate::utils::escape_like(ct).replace('*', "%");
			query
				.push("COALESCE(f.content_type, e.ref_content_type) LIKE ")
				.push_bind(pattern)
				.push(" ESCAPE '\\'");
		}
		if opts.include_folders {
			query.push(" OR (e.f_id IS NULL AND e.ref_file_id IS NULL)");
		}
		query.push(")");
	}

	// Filter by file name (substring search)
	if let Some(file_name) = &opts.file_name {
		query
			.push(" AND e.file_name LIKE ")
			.push_bind(format!("%{}%", crate::utils::escape_like(file_name)))
			.push(" ESCAPE '\\'");
	}

	// Author attribution, not authority: COALESCE(owner_tag, upstream_tag, tenant id_tag).
	// A member's file is theirs, a Pin/Place row is the placer's, an FSHR-accepted row is
	// attributed to the sharer. All three terms are load-bearing — do not shorten.
	if let Some(owner_id_tag) = &opts.owner_id_tag {
		query
			.push(" AND COALESCE(e.owner_tag, e.upstream_tag, t.id_tag)=")
			.push_bind(normalize_id_tag(owner_id_tag).into_owned());
	}

	// Exclude files by that same attribution (for "others" filter)
	if let Some(not_owner_id_tag) = &opts.not_owner_id_tag {
		query
			.push(" AND COALESCE(e.owner_tag, e.upstream_tag, t.id_tag)!=")
			.push_bind(normalize_id_tag(not_owner_id_tag).into_owned());
	}

	// Restrict to tenant-owned files (exclude remote/federated cached copies).
	// Local files leave upstream_tag NULL; only cross-context Pin/Place rows set it.
	if opts.local_only {
		query.push(" AND e.upstream_tag IS NULL");
	}

	query.push(" AND ");
	push_entry_gate(
		&mut query,
		tn_id,
		opts.visible_levels.as_deref(),
		opts.role_grant,
		opts.enterable_channels.as_deref(),
		opts.share_subject.as_deref(),
	);
	query.push(")");

	// Filter by status - if no status specified, exclude deleted files by default
	// (except under `sweep_all`, which must see a soft-deleted row to clean up after it)
	if let Some(status) = opts.status {
		let status_char = match status {
			FileStatus::Active => "A",
			FileStatus::Pending => "P",
			FileStatus::Deleted => "D",
		};
		query.push(" AND e.status=").push_bind(status_char);
	} else if !opts.sweep_all {
		// By default, exclude deleted files
		query.push(" AND e.status != 'D'");
	}
	// Pending uploads are their owner's alone on the paths that reach them at all (by id, by
	// status; browse drops them above). Only `sweep_all` sees everyone's.
	if !opts.sweep_all {
		if let Some(viewer) = opts.pending_viewer.as_deref() {
			query
				.push(" AND (e.status != 'P' OR COALESCE(e.owner_tag, t.id_tag)=")
				.push_bind(normalize_id_tag(viewer).into_owned())
				.push(")");
		} else {
			query.push(" AND e.status != 'P'");
		}
	}

	// Filter by hidden flag. `sweep_all` with no explicit `hidden` pushes nothing:
	// a hidden file is a normal, indexable file a browse listing just does not show.
	match opts.hidden {
		Some(true) => {
			query.push(" AND e.hidden = 1");
		}
		None if opts.sweep_all => {}
		_ => {
			query.push(" AND (e.hidden IS NULL OR e.hidden = 0)");
		}
	}

	// Filter by pinned/starred (user-specific) — only valid when the
	// file_user_data JOIN was added (i.e. an authenticated user is present).
	// Without auth there is no `fud` alias, so referencing fud.* would be a
	// sqlite "no such column" error.
	if has_user {
		if opts.pinned == Some(true) {
			query.push(" AND fud.pinned = 1");
		}
		if opts.starred == Some(true) {
			query.push(" AND fud.starred = 1");
		}
	}

	// Determine sort order
	let sort_field = opts.sort.as_deref().unwrap_or("created");
	let sort_dir = match opts.sort_dir.as_deref() {
		Some("asc") => "ASC",
		Some("desc") => "DESC",
		_ => match sort_field {
			"name" => "ASC",
			_ => "DESC", // Default DESC for date-based sorts
		},
	};
	let is_desc = sort_dir == "DESC";

	// Parse cursor for keyset pagination
	if let Some(cursor_str) = &opts.cursor
		&& let Some(cursor) = cloudillo_types::types::CursorData::decode(cursor_str)
	{
		// Look up the cursor row's e_id (lookup order: entry_id, then file_id, then `@<f_id>`)
		let cursor_e_id: Option<i64> = resolve_entry(db, tn_id, &cursor.id).await?;

		if let Some(cursor_e_id) = cursor_e_id {
			// Add keyset pagination WHERE clause based on sort field
			// For DESC: (sort_field, f_id) < (cursor_value, cursor_e_id)
			// For ASC: (sort_field, f_id) > (cursor_value, cursor_e_id)
			// Note: push_bind() adds bind placeholders, don't use ? in push() strings
			let comparison = if is_desc { "<" } else { ">" };

			match sort_field {
				"recent" if has_user => {
					if let Some(ts) = cursor.timestamp() {
						query.push(format!(
							" AND ((fud.accessed_at IS NULL AND e.e_id {} ",
							comparison
						));
						query.push_bind(cursor_e_id);
						query.push(format!(
							") OR (fud.accessed_at IS NOT NULL AND (fud.accessed_at, e.e_id) {} (",
							comparison
						));
						query.push_bind(ts);
						query.push(", ");
						query.push_bind(cursor_e_id);
						query.push(")))");
					}
				}
				"modified" if has_user => {
					if let Some(ts) = cursor.timestamp() {
						query.push(format!(
							" AND ((fud.modified_at IS NULL AND e.e_id {} ",
							comparison
						));
						query.push_bind(cursor_e_id);
						query.push(format!(
							") OR (fud.modified_at IS NOT NULL AND (fud.modified_at, e.e_id) {} (",
							comparison
						));
						query.push_bind(ts);
						query.push(", ");
						query.push_bind(cursor_e_id);
						query.push(")))");
					}
				}
				"name" => {
					if let Some(name) = cursor.string_value() {
						query.push(format!(" AND (e.file_name, e.e_id) {} (", comparison));
						query.push_bind(name.to_string());
						query.push(", ");
						query.push_bind(cursor_e_id);
						query.push(")");
					}
				}
				_ => {
					// "created" or default
					if let Some(ts) = cursor.timestamp() {
						query.push(format!(" AND (e.created_at, e.e_id) {} (", comparison));
						query.push_bind(ts);
						query.push(", ");
						query.push_bind(cursor_e_id);
						query.push(")");
					}
				}
			}
		}
	}

	match sort_field {
		"recent" if has_user => {
			// Sort by user's access time (NULLs last for DESC, NULLs first for ASC)
			query.push(format!(
				" ORDER BY CASE WHEN fud.accessed_at IS NULL THEN {} ELSE {} END, fud.accessed_at {}, e.e_id {}",
				i32::from(is_desc),
				i32::from(!is_desc),
				sort_dir, sort_dir
			));
		}
		"modified" if has_user => {
			// Sort by user's modification time (NULLs last for DESC, NULLs first for ASC)
			query.push(format!(
				" ORDER BY CASE WHEN fud.modified_at IS NULL THEN {} ELSE {} END, fud.modified_at {}, e.e_id {}",
				i32::from(is_desc),
				i32::from(!is_desc),
				sort_dir, sort_dir
			));
		}
		"name" => {
			query.push(format!(" ORDER BY e.file_name {}, e.e_id {}", sort_dir, sort_dir));
		}
		_ => {
			// Default (including "created"): sort by file creation time
			query.push(format!(" ORDER BY e.created_at {}, e.e_id {}", sort_dir, sort_dir));
		}
	}

	// Fetch limit+1 to determine hasMore
	// Note: SQLite doesn't allow bound parameters in LIMIT clause, so we use format!
	let limit = i64::from(opts.limit.unwrap_or(30));
	query.push(format!(" LIMIT {}", limit + 1));

	debug!("SQL: {}", query.sql().as_str());

	let res = query.build().fetch_all(db).await.db()?;

	res.iter()
		.map(|row| {
			let user_data = if has_user { user_data_from_row(row) } else { None };
			row_to_file_view(row, user_data)
		})
		.collect()
}

/// List file variants for a file
pub(crate) async fn list_variants(
	db: &SqlitePool,
	tn_id: TnId,
	file_id: FileId<&str>,
) -> ClResult<Vec<FileVariant<Box<str>>>> {
	let res = match file_id {
		FileId::FId(f_id) => sqlx::query(
			"SELECT variant_id, variant, res_x, res_y, format, size, available, global, duration, bitrate, page_count
			FROM file_variants WHERE tn_id=? AND f_id=?",
		)
		.bind(tn_id.0)
		.bind(f_id.cast_signed())
		.fetch_all(db)
		.await
		.db()?,
		FileId::FileId(file_id) => {
			if let Some(f_id) = parse_f_id(file_id)? {
				sqlx::query(concat!(
					"SELECT variant_id, variant, res_x, res_y, format, size, available, global, \
					 duration, bitrate, page_count FROM file_variants fv WHERE fv.tn_id=? AND fv.f_id=",
					canon_f_id!("fv.tn_id")
				))
				.bind(tn_id.0)
				.bind(f_id)
				.fetch_all(db)
				.await
				.db()?
			} else {
				sqlx::query("SELECT fv.variant_id, fv.variant, fv.res_x, fv.res_y, fv.format, fv.size, fv.available, fv.global, fv.duration, fv.bitrate, fv.page_count
					FROM files f
					JOIN file_variants fv ON fv.tn_id=f.tn_id AND fv.f_id=f.f_id
					WHERE f.tn_id=? AND f.file_id=?")
					.bind(tn_id.0).bind(file_id)
					.fetch_all(db).await.db()?
			}
		}
	};

	collect_res(res.iter().map(|row| {
		let res_x = row.try_get("res_x")?;
		let res_y = row.try_get("res_y")?;
		Ok(FileVariant {
			variant_id: row.try_get("variant_id")?,
			variant: row.try_get("variant")?,
			resolution: (res_x, res_y),
			format: row.try_get("format")?,
			size: row.try_get("size")?,
			available: row.try_get("available")?,
			global: row.try_get::<Option<bool>, _>("global").ok().flatten().unwrap_or(false),
			duration: row.try_get::<Option<f64>, _>("duration").ok().flatten(),
			bitrate: row
				.try_get::<Option<i64>, _>("bitrate")
				.ok()
				.flatten()
				.map(|v| u32::try_from(v).unwrap_or_default()),
			page_count: row
				.try_get::<Option<i64>, _>("page_count")
				.ok()
				.flatten()
				.map(|v| u32::try_from(v).unwrap_or_default()),
		})
	}))
}

/// List available (locally present) variant names for a file by file_id
pub(crate) async fn list_available_variants(
	db: &SqlitePool,
	tn_id: TnId,
	file_id: &str,
) -> ClResult<Vec<Box<str>>> {
	let res = sqlx::query(
		"SELECT fv.variant
		 FROM files f
		 JOIN file_variants fv ON fv.tn_id=f.tn_id AND fv.f_id=f.f_id
		 WHERE f.tn_id=? AND f.file_id=? AND fv.available=1",
	)
	.bind(tn_id.0)
	.bind(file_id)
	.fetch_all(db)
	.await
	.db()?;

	collect_res(res.iter().map(|row| row.try_get("variant")))
}

/// List every `variant_id` whose blob is expected to be on disk for a given
/// tenant's blob store.
///
/// - `tn_id != 0`: variants with `global=0` (stored in this tenant's store).
/// - `tn_id == 0`: variants with `global=1` across all tenants (the union
///   referencing the shared store).
pub(crate) async fn list_referenced_variant_ids(
	db: &SqlitePool,
	tn_id: TnId,
) -> ClResult<Vec<Box<str>>> {
	let res = if tn_id.0 == 0 {
		sqlx::query(
			"SELECT DISTINCT variant_id FROM file_variants WHERE global = 1 AND variant_id IS NOT NULL",
		)
		.fetch_all(db)
		.await
		.db()?
	} else {
		sqlx::query(
			"SELECT DISTINCT variant_id FROM file_variants
			 WHERE tn_id = ? AND COALESCE(global, 0) = 0 AND variant_id IS NOT NULL",
		)
		.bind(tn_id.0)
		.fetch_all(db)
		.await
		.db()?
	};

	collect_res(res.iter().map(|row| row.try_get("variant_id")))
}

/// Targeted check used by the blob GC just before a delete: is there
/// currently a `file_variants` row that expects this blob in `tn_id`'s store?
pub(crate) async fn is_variant_referenced(
	db: &SqlitePool,
	tn_id: TnId,
	variant_id: &str,
) -> ClResult<bool> {
	let row = if tn_id.0 == 0 {
		sqlx::query("SELECT 1 FROM file_variants WHERE variant_id = ? AND global = 1 LIMIT 1")
			.bind(variant_id)
			.fetch_optional(db)
			.await
			.db()?
	} else {
		sqlx::query(
			"SELECT 1 FROM file_variants
			 WHERE tn_id = ? AND variant_id = ? AND COALESCE(global, 0) = 0 LIMIT 1",
		)
		.bind(tn_id.0)
		.bind(variant_id)
		.fetch_optional(db)
		.await
		.db()?
	};
	Ok(row.is_some())
}

/// List available (locally present) variant names for a file by f_id
pub(crate) async fn list_available_variants_by_fid(
	db: &SqlitePool,
	tn_id: TnId,
	f_id: i64,
) -> ClResult<Vec<Box<str>>> {
	let res = sqlx::query(concat!(
		"SELECT fv.variant FROM file_variants fv WHERE fv.available=1 AND fv.tn_id=? AND fv.f_id=",
		canon_f_id!("fv.tn_id")
	))
	.bind(tn_id.0)
	.bind(f_id)
	.fetch_all(db)
	.await
	.db()?;

	collect_res(res.iter().map(|row| row.try_get("variant")))
}

/// Read a single file variant by ID
pub(crate) async fn read_variant(
	db: &SqlitePool,
	tn_id: TnId,
	variant_id: &str,
) -> ClResult<FileVariant<Box<str>>> {
	debug!("read_variant: tn_id={}, variant_id={}", tn_id.0, variant_id);
	let res = sqlx::query(
		"SELECT variant_id, variant, res_x, res_y, format, size, available, global, duration, bitrate, page_count
			FROM file_variants WHERE tn_id=? AND variant_id=?",
	)
	.bind(tn_id.0)
	.bind(variant_id)
	.fetch_one(db)
	.await;
	debug!("read_variant result: {:?}", res.is_ok());

	map_res(res, |row| {
		let res_x = row.try_get("res_x")?;
		let res_y = row.try_get("res_y")?;
		Ok(FileVariant {
			variant_id: row.try_get("variant_id")?,
			variant: row.try_get("variant")?,
			resolution: (res_x, res_y),
			format: row.try_get("format")?,
			size: row.try_get("size")?,
			available: row.try_get("available")?,
			global: row.try_get::<Option<bool>, _>("global").ok().flatten().unwrap_or(false),
			duration: row.try_get::<Option<f64>, _>("duration").ok().flatten(),
			bitrate: row
				.try_get::<Option<i64>, _>("bitrate")
				.ok()
				.flatten()
				.map(|v| u32::try_from(v).unwrap_or_default()),
			page_count: row
				.try_get::<Option<i64>, _>("page_count")
				.ok()
				.flatten()
				.map(|v| u32::try_from(v).unwrap_or_default()),
		})
	})
}

/// Look up the file_id for a given variant_id
pub(crate) async fn read_file_id_by_variant(
	db: &SqlitePool,
	tn_id: TnId,
	variant_id: &str,
) -> ClResult<Box<str>> {
	let res = sqlx::query(
		"SELECT f.file_id
			FROM files f
			JOIN file_variants fv ON f.tn_id=fv.tn_id AND f.f_id=fv.f_id
			WHERE fv.tn_id=? AND fv.variant_id=?",
	)
	.bind(tn_id.0)
	.bind(variant_id)
	.fetch_one(db)
	.await;

	map_res(res, |row| row.try_get("file_id"))
}

/// See `MetaAdapter::read_content`.
pub(crate) async fn read_content(
	db: &SqlitePool,
	tn_id: TnId,
	file_id: &str,
) -> ClResult<ContentInfo> {
	let row: Option<(i64, OptStr, bool)> = sqlx::query_as(
		"SELECT f.f_id, f.preset, EXISTS (SELECT 1 FROM entries e WHERE e.f_id=f.f_id) \
		 FROM files f WHERE f.tn_id=? AND f.file_id=?",
	)
	.bind(tn_id.0)
	.bind(file_id)
	.fetch_optional(db)
	.await
	.db()?;
	let (f_id, preset, has_entries) = row.ok_or(Error::NotFound)?;
	Ok(ContentInfo { f_id: f_id.cast_unsigned(), preset, has_entries })
}

/// See `MetaAdapter::create_sync_content`.
pub(crate) async fn create_sync_content(
	db: &SqlitePool,
	tn_id: TnId,
	file_id: &str,
	root_id: Option<&str>,
	content_type: &str,
	x: Option<serde_json::Value>,
) -> ClResult<u64> {
	let mut tx = db.begin().await.db()?;
	let existing: Option<i64> =
		sqlx::query_scalar("SELECT f_id FROM files WHERE tn_id=? AND file_id=?")
			.bind(tn_id.0)
			.bind(file_id)
			.fetch_optional(&mut *tx)
			.await
			.db()?;
	let f_id = match existing {
		Some(f_id) => f_id,
		None => sqlx::query_scalar(
			"INSERT INTO files (tn_id, file_id, root_id, preset, content_type, file_tp, x) \
			 VALUES(?, ?, ?, 'sync', ?, 'BLOB', ?) RETURNING f_id",
		)
		.bind(tn_id.0)
		.bind(file_id)
		.bind(root_id)
		.bind(content_type)
		.bind(x)
		.fetch_one(&mut *tx)
		.await
		.db()?,
	};
	tx.commit().await.db()?;
	Ok(f_id.cast_unsigned())
}

/// Insert one entry (placement row) for `f_id` (`None` = folder, or a reference when
/// `opts.upstream_tag` is set) from `opts`'s placement fields.
/// `opts.owner_tag` and `opts.upstream_tag` must already be canonical (see [`create`]).
async fn insert_entry(
	tx: &mut sqlx::SqliteConnection,
	tn_id: TnId,
	entry_id: &str,
	f_id: Option<i64>,
	status: &str,
	opts: &CreateFile,
) -> ClResult<()> {
	let created_at = opts.created_at.unwrap_or_else(Timestamp::now);
	// A reference (upstream set, no local file) carries the upstream content on the entry.
	let reference = f_id.is_none() && opts.upstream_tag.is_some();
	let r = |v| if reference { v } else { None };
	sqlx::query(
		"INSERT INTO entries (tn_id, entry_id, f_id, status, owner_tag, upstream_tag, file_name, \
		 tags, visibility, hidden, parent_id, channel, action_id, created_at, \
		 ref_file_id, ref_file_tp, ref_content_type, ref_x, ref_preset) \
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	)
	.bind(tn_id.0)
	.bind(entry_id)
	.bind(f_id)
	.bind(status)
	.bind(opts.owner_tag.as_deref())
	.bind(opts.upstream_tag.as_deref())
	.bind(opts.file_name.as_ref())
	.bind(opts.tags.as_ref().map(|tags| tags.join(",")))
	.bind(opts.visibility.map(|c| c.to_string()))
	.bind(i32::from(opts.hidden))
	.bind(opts.parent_id.as_deref())
	.bind(opts.channel.as_deref())
	.bind(opts.action_id.as_deref())
	.bind(created_at.0)
	.bind(r(opts.file_id.as_deref()))
	.bind(r(opts.file_tp.as_deref()))
	.bind(r(Some(opts.content_type.as_ref())))
	.bind(if reference { opts.x.clone() } else { None })
	.bind(r(opts.preset.as_deref()))
	.execute(&mut *tx)
	.await
	.db()?;
	Ok(())
}

/// Create a file: a `files` content row plus its entry, or — for a folder or a reference — an
/// entry alone.
///
/// - Reference (`upstream_tag` set: Pin / Place / FSHR, any `file_tp`): entry only, `f_id` NULL,
///   a fresh `entry_id`, the upstream content id and display fields in its `ref_*` columns. Never
///   looks at local `files`: holding the id proves nothing about holding the bytes. Idempotent for
///   the same placement. Checked first, so a remote folder can't take a local id as `entry_id`.
/// - Local folder (`file_tp = 'FLDR'`): entry only, `entry_id` = the caller's `file_id`.
/// - Upload dedup (preset + orig variant + `root_id`): a finalized local BLOB gets a **new entry**
///   at the requested placement; returns `FileId::FileId`.
/// - Explicit `file_id` already present (verified sync, federation retries): idempotent for the
///   same placement (live entry, same parent, owner and drive); otherwise a BLOB gets a new entry
///   and any other type with a live entry elsewhere is `Conflict`.
/// - Otherwise a new content row (`FileId::FId`) and a new entry with a random `entry_id`.
pub(crate) async fn create(
	db: &SqlitePool,
	tn_id: TnId,
	mut opts: CreateFile,
) -> ClResult<CreatedFile> {
	// Use provided status or default to 'P' (Pending)
	let status = match opts.status {
		Some(FileStatus::Active) => "A",
		Some(FileStatus::Deleted) => "D",
		Some(FileStatus::Pending) | None => "P",
	};
	let file_tp = opts.file_tp.as_deref().unwrap_or("BLOB"); // Default to BLOB if not specified

	// `profiles.id_tag` is joined by value against both of these columns (see the
	// `upstream_id_tag`/`owner_id_tag` LEFT JOINs in the list and read queries), and
	// profiles are stored canonical — so these must be stored canonical too.
	opts.upstream_tag = opts.upstream_tag.as_deref().map(|t| normalize_id_tag(t).into());
	opts.owner_tag = opts.owner_tag.as_deref().map(|t| normalize_id_tag(t).into());

	let mut tx = db.begin().await.db()?;

	if opts.upstream_tag.is_some() {
		let ref_file_id = opts
			.file_id
			.clone()
			.ok_or_else(|| Error::ValidationError("a reference needs a file id".into()))?;
		let same_placement: Option<Box<str>> = sqlx::query_scalar(
			"SELECT entry_id FROM entries WHERE tn_id=? AND ref_file_id=? AND upstream_tag=? \
			 AND status='A' AND parent_id IS ? AND owner_tag IS ? AND channel IS ? \
			 ORDER BY e_id LIMIT 1",
		)
		.bind(tn_id.0)
		.bind(ref_file_id.as_ref())
		.bind(opts.upstream_tag.as_deref())
		.bind(opts.parent_id.as_deref())
		.bind(opts.owner_tag.as_deref())
		.bind(opts.channel.as_deref())
		.fetch_optional(&mut *tx)
		.await
		.db()?;
		let entry_id = if let Some(id) = same_placement {
			id
		} else {
			let id: Box<str> = cloudillo_types::utils::random_id()?.into();
			insert_entry(&mut tx, tn_id, &id, None, status, &opts).await?;
			id
		};
		tx.commit().await.db()?;
		return Ok(CreatedFile { entry_id, file_id: FileId::FileId(ref_file_id) });
	}

	if file_tp == "FLDR" {
		let entry_id: Box<str> = match &opts.file_id {
			Some(id) => {
				// A repeated create with an explicit id is idempotent, as for content below; an
				// id taken by a non-folder entry is a conflict.
				let is_folder: Option<bool> = sqlx::query_scalar(
					"SELECT f_id IS NULL AND ref_file_id IS NULL FROM entries \
					 WHERE tn_id=? AND entry_id=?",
				)
				.bind(tn_id.0)
				.bind(id.as_ref())
				.fetch_optional(&mut *tx)
				.await
				.db()?;
				match is_folder {
					Some(true) => {
						tx.commit().await.db()?;
						let entry_id = id.clone();
						return Ok(CreatedFile { file_id: FileId::FileId(id.clone()), entry_id });
					}
					Some(false) => return Err(Error::Conflict("entry id in use".into())),
					None => id.clone(),
				}
			}
			None => cloudillo_types::utils::random_id()?.into(),
		};
		insert_entry(&mut tx, tn_id, &entry_id, None, status, &opts).await?;
		tx.commit().await.db()?;
		return Ok(CreatedFile { file_id: FileId::FileId(entry_id.clone()), entry_id });
	}

	// Upload dedup. Only immutable BLOBs may carry several entries. `root_id` is hashed into the
	// content id, so content from another document tree is other content.
	if file_tp == "BLOB"
		&& let (Some(preset), Some(orig_variant_id)) = (&opts.preset, &opts.orig_variant_id)
	{
		let hit: Option<(i64, Box<str>)> = sqlx::query_as(
			"SELECT f.f_id, f.file_id FROM file_variants fv \
			 JOIN files f ON f.tn_id=fv.tn_id AND f.f_id=fv.f_id \
			 WHERE fv.tn_id=? AND fv.variant_id=? AND fv.variant='orig' \
			   AND f.preset=? AND f.file_tp='BLOB' AND f.file_id IS NOT NULL AND f.root_id IS ? \
			 ORDER BY f.file_id LIMIT 1",
		)
		.bind(tn_id.0)
		.bind(orig_variant_id.as_ref())
		.bind(preset.as_ref())
		.bind(opts.root_id.as_deref())
		.fetch_optional(&mut *tx)
		.await
		.db()?;

		if let Some((f_id, file_id)) = hit {
			let entry_id: Box<str> = cloudillo_types::utils::random_id()?.into();
			insert_entry(&mut tx, tn_id, &entry_id, Some(f_id), "A", &opts).await?;
			tx.commit().await.db()?;
			return Ok(CreatedFile { entry_id, file_id: FileId::FileId(file_id) });
		}
	}

	// For shared files (with explicit file_id), an existing row makes this idempotent. The
	// transaction holds the single write connection, so a racing create() for the same
	// file_id sees this row committed instead of tripping the UNIQUE(file_id, tn_id) index.
	let existing: Option<i64> = match &opts.file_id {
		Some(file_id) => sqlx::query_scalar("SELECT f_id FROM files WHERE tn_id=? AND file_id=?")
			.bind(tn_id.0)
			.bind(file_id.as_ref())
			.fetch_optional(&mut *tx)
			.await
			.db()?,
		None => None,
	};

	let f_id: i64 = match existing {
		Some(f_id) => f_id,
		None => sqlx::query_scalar(
			"INSERT INTO files (tn_id, file_id, root_id, preset, content_type, file_tp, x) \
			 VALUES(?, ?, ?, ?, ?, ?, ?) RETURNING f_id",
		)
		.bind(tn_id.0)
		.bind(opts.file_id.as_deref())
		.bind(opts.root_id.as_deref())
		.bind(opts.preset.as_deref())
		.bind(opts.content_type.as_ref())
		.bind(file_tp)
		.bind(opts.x.clone())
		.fetch_one(&mut *tx)
		.await
		.db()?,
	};

	// Idempotent only for the same placement re-created: a live entry (or one pending like the
	// request, a sync retry) at the requested parent, owner and drive. Any other entry of the
	// content — trashed, tombstoned or placed elsewhere — is never handed back; a BLOB gets a new
	// entry beside it.
	let same_placement: Option<Box<str>> = sqlx::query_scalar(
		"SELECT entry_id FROM entries WHERE tn_id=? AND f_id=? AND status IN ('A', ?) \
		 AND parent_id IS ? AND owner_tag IS ? AND channel IS ? \
		 ORDER BY e_id LIMIT 1",
	)
	.bind(tn_id.0)
	.bind(f_id)
	.bind(status)
	.bind(opts.parent_id.as_deref())
	.bind(opts.owner_tag.as_deref())
	.bind(opts.channel.as_deref())
	.fetch_optional(&mut *tx)
	.await
	.db()?;
	let entry_id = if let Some(id) = same_placement {
		id
	} else {
		if file_tp != "BLOB" && existing.is_some() {
			// Only an immutable BLOB may carry several entries.
			let placed: Option<i64> = sqlx::query_scalar(
				"SELECT e_id FROM entries WHERE tn_id=? AND f_id=? AND status='A' LIMIT 1",
			)
			.bind(tn_id.0)
			.bind(f_id)
			.fetch_optional(&mut *tx)
			.await
			.db()?;
			if placed.is_some() {
				return Err(Error::Conflict("file already placed elsewhere".into()));
			}
		}
		let id: Box<str> = cloudillo_types::utils::random_id()?.into();
		insert_entry(&mut tx, tn_id, &id, Some(f_id), status, &opts).await?;
		id
	};

	tx.commit().await.db()?;
	Ok(CreatedFile {
		entry_id,
		file_id: FileId::FId(u64::try_from(f_id).map_err(|_| Error::DbError)?),
	})
}

/// Create a file variant
/// Note: Only works for pending content (an entry in status 'P') or for a verified sync mirror
/// (`preset = 'sync'`), whose variants were hashed into its id by the descriptor sync checked —
/// either way the content-based id stays intact.
pub(crate) async fn create_variant<'a>(
	db: &SqlitePool,
	tn_id: TnId,
	f_id: u64,
	opts: FileVariant<&'a str>,
) -> ClResult<&'a str> {
	let mut tx = db.begin().await.db()?;
	sqlx::query(
		"SELECT 1 FROM files f WHERE f.tn_id=? AND f.f_id=? AND (f.preset='sync' \
		 OR EXISTS (SELECT 1 FROM entries e WHERE e.f_id=f.f_id AND e.status='P'))",
	)
	.bind(tn_id.0)
	.bind(f_id.cast_signed())
	.fetch_optional(&mut *tx)
	.await
	.db()?
	.ok_or(Error::NotFound)?;
	// Touch the content so a long sync keeps it out of the orphan GC's window.
	sqlx::query("UPDATE files SET updated_at = unixepoch() WHERE tn_id = ? AND f_id = ?")
		.bind(tn_id.0)
		.bind(f_id.cast_signed())
		.execute(&mut *tx)
		.await
		.db()?;

	// Upgrade-friendly insert: a prior sync may have written a metadata-only
	// row (`available=0, global=0`) for this variant when content was not
	// being fetched. A later sync that *does* fetch content (and may route
	// the blob to the shared `TnId(0)` store) must overwrite size/available/
	// global on that placeholder row, otherwise reads would route to the
	// wrong store and a backfilled blob would have no `global=1` reference
	// — the GC would then collect it.
	//
	// The `WHERE file_variants.available = 0` guard preserves the existing
	// "first writer wins" semantics for already-available rows: two concurrent
	// uploaders racing the original INSERT OR IGNORE both succeeded without
	// overwriting; the same property holds here for the available case.
	let _res = sqlx::query(
		"INSERT INTO file_variants (tn_id, f_id, variant_id, variant, res_x, res_y, format, size, available, global, duration, bitrate, page_count) \
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
		 ON CONFLICT(f_id, variant_id, tn_id) DO UPDATE SET \
		     size      = excluded.size, \
		     available = excluded.available, \
		     global    = excluded.global \
		 WHERE file_variants.available = 0",
	)
		.bind(tn_id.0).bind(f_id.cast_signed()).bind(opts.variant_id).bind(opts.variant).bind(opts.resolution.0).bind(opts.resolution.1).bind(opts.format).bind(opts.size.cast_signed()).bind(opts.available).bind(opts.global).bind(opts.duration).bind(opts.bitrate.map(i64::from)).bind(opts.page_count.map(i64::from))
		.execute(&mut *tx).await.db()?;
	tx.commit().await.db()?;

	Ok(opts.variant_id)
}

/// Flip a content row's pending entries to active.
async fn activate_entries(tx: &mut sqlx::SqliteConnection, tn_id: TnId, f_id: i64) -> ClResult<()> {
	sqlx::query("UPDATE entries SET status='A' WHERE tn_id=? AND f_id=? AND status='P'")
		.bind(tn_id.0)
		.bind(f_id)
		.execute(&mut *tx)
		.await
		.db()?;
	Ok(())
}

/// Finalize a pending upload: set the content row's `file_id` and flip its entry 'P' → 'A'.
///
/// When a file with `file_id` already exists (identical content uploaded or mirrored before), the
/// pending entry is repointed to it and the row stays as a `merged_into` redirect for its
/// `@<f_id>`. Origin plays no part: each entry keeps its own `upstream_tag`. The pending row's
/// variants move to the existing content where it lacks an available one (a Pin-style mirror
/// holds no local bytes); the rest are dropped.
pub(crate) async fn finalize_file(
	db: &SqlitePool,
	tn_id: TnId,
	f_id: u64,
	file_id: &str,
) -> ClResult<()> {
	let f_id = f_id.cast_signed();
	let mut tx = db.begin().await.db()?;

	let current: Option<OptStr> =
		sqlx::query_scalar("SELECT file_id FROM files WHERE tn_id=? AND f_id=?")
			.bind(tn_id.0)
			.bind(f_id)
			.fetch_optional(&mut *tx)
			.await
			.db()?;
	let Some(current_id) = current else { return Err(Error::NotFound) };

	match current_id {
		// Idempotent: already finalized with this id; fix an entry left pending.
		Some(id) if &*id == file_id => activate_entries(&mut tx, tn_id, f_id).await?,
		Some(id) => {
			let msg = format!(
				"Attempted to finalize f_id={} to file_id={} but already set to {}",
				f_id, file_id, id
			);
			error!("{}", msg);
			return Err(Error::Conflict(msg));
		}
		None => {
			let other: Option<i64> =
				sqlx::query_scalar("SELECT f_id FROM files WHERE tn_id=? AND file_id=?")
					.bind(tn_id.0)
					.bind(file_id)
					.fetch_optional(&mut *tx)
					.await
					.db()?;
			if let Some(other_f_id) = other {
				sqlx::query(
					"UPDATE entries SET f_id=?, \
					 status=CASE WHEN status='P' THEN 'A' ELSE status END \
					 WHERE tn_id=? AND f_id=?",
				)
				.bind(other_f_id)
				.bind(tn_id.0)
				.bind(f_id)
				.execute(&mut *tx)
				.await
				.db()?;
				// Move the upload's variants over: an available one replaces a placeholder, a
				// missing one is added, one the target already has is dropped. Blob bytes are
				// keyed by `variant_id`, so moving the rows is enough.
				sqlx::query(
					"DELETE FROM file_variants WHERE tn_id=? AND f_id=? AND available=0 \
					 AND variant IN (SELECT variant FROM file_variants \
					   WHERE tn_id=? AND f_id=? AND available=1)",
				)
				.bind(tn_id.0)
				.bind(other_f_id)
				.bind(tn_id.0)
				.bind(f_id)
				.execute(&mut *tx)
				.await
				.db()?;
				sqlx::query("UPDATE OR IGNORE file_variants SET f_id=? WHERE tn_id=? AND f_id=?")
					.bind(other_f_id)
					.bind(tn_id.0)
					.bind(f_id)
					.execute(&mut *tx)
					.await
					.db()?;
				sqlx::query("DELETE FROM file_variants WHERE tn_id=? AND f_id=?")
					.bind(tn_id.0)
					.bind(f_id)
					.execute(&mut *tx)
					.await
					.db()?;
				// Keep the row as a redirect, forever for now: drafts and pending attachments
				// hold `@<f_id>` (purge once drafts store content ids). `file_id` stays NULL —
				// the unique index forbids copying it.
				sqlx::query("UPDATE files SET merged_into=? WHERE tn_id=? AND f_id=?")
					.bind(other_f_id)
					.bind(tn_id.0)
					.bind(f_id)
					.execute(&mut *tx)
					.await
					.db()?;
				info!("Finalized f_id={} by repointing to existing file_id={}", f_id, file_id);
			} else {
				sqlx::query("UPDATE files SET file_id=? WHERE tn_id=? AND f_id=?")
					.bind(file_id)
					.bind(tn_id.0)
					.bind(f_id)
					.execute(&mut *tx)
					.await
					.db()?;
				activate_entries(&mut tx, tn_id, f_id).await?;
				info!("Finalized file f_id={} → file_id={}, status='A'", f_id, file_id);
			}
		}
	}

	tx.commit().await.db()?;
	Ok(())
}

/// Update one entry's metadata, never its siblings'. The content fields (`content_type`,
/// `file_tp`, `x`) change only a reference's `ref_*` columns: a `files` row is never rewritten
/// after creation.
pub(crate) async fn update_data(
	db: &SqlitePool,
	tn_id: TnId,
	file_id: &str,
	opts: &UpdateFileOptions,
) -> ClResult<()> {
	// Pre-serialize the `x` Patch so the macro can bind a plain string; doing
	// this before the QueryBuilder is built keeps the `?` operator usable
	// (panic-free, per workspace lint).
	let x_serialized: Patch<String> = match &opts.x {
		Patch::Undefined => Patch::Undefined,
		Patch::Null => Patch::Null,
		Patch::Value(v) => Patch::Value(serde_json::to_string(v)?),
	};

	let mut entry_q = sqlx::QueryBuilder::new("UPDATE entries SET ");
	let mut entry_set = false;

	entry_set = push_patch!(entry_q, entry_set, "file_name", &opts.file_name, |v| v.as_str());
	entry_set = push_patch!(entry_q, entry_set, "parent_id", &opts.parent_id, |v| v.as_str());
	entry_set = push_patch!(entry_q, entry_set, "visibility", &opts.visibility, |c| c.to_string());
	entry_set = push_patch!(entry_q, entry_set, "status", &opts.status, |c| c.to_string());
	entry_set = push_patch!(entry_q, entry_set, "hidden", &opts.hidden, |b| i32::from(*b));
	entry_set = push_patch!(entry_q, entry_set, "channel", &opts.channel, |v| v.as_str());
	entry_set = push_patch!(entry_q, entry_set, "tags", &opts.tags, |v| v.join(","));

	// `broken` is a paired update: `Value` sets broken_at to the current time
	// and broken_reason to the supplied code; `Null` clears both.
	match &opts.broken {
		Patch::Undefined => {}
		Patch::Null => {
			if entry_set {
				entry_q.push(", ");
			}
			entry_q.push("broken_at = NULL, broken_reason = NULL");
			entry_set = true;
		}
		Patch::Value(reason) => {
			if entry_set {
				entry_q.push(", ");
			}
			entry_q
				.push("broken_at = unixepoch(), broken_reason = ")
				.push_bind(reason.as_str());
			entry_set = true;
		}
	}

	let mut ref_q = sqlx::QueryBuilder::new("UPDATE entries SET ");
	let mut ref_set = false;

	ref_set = push_patch!(ref_q, ref_set, "ref_content_type", &opts.content_type, |v| v.as_str());
	ref_set = push_patch!(ref_q, ref_set, "ref_file_tp", &opts.file_tp, |v| v.as_str());
	ref_set = push_patch!(ref_q, ref_set, "ref_x", &x_serialized, |v| v.as_str());

	if !entry_set && !ref_set {
		return Ok(()); // Nothing to update
	}
	let Some(e_id) = resolve_entry(db, tn_id, file_id).await? else { return Ok(()) };

	let mut tx = db.begin().await.db()?;
	if entry_set {
		entry_q
			.push(" WHERE tn_id = ")
			.push_bind(tn_id.0)
			.push(" AND e_id = ")
			.push_bind(e_id);
		entry_q.build().execute(&mut *tx).await.db()?;
	}
	if ref_set {
		ref_q
			.push(" WHERE tn_id = ")
			.push_bind(tn_id.0)
			.push(" AND e_id = ")
			.push_bind(e_id)
			.push(" AND ref_file_id IS NOT NULL");
		ref_q.build().execute(&mut *tx).await.db()?;
	}
	tx.commit().await.db()?;

	Ok(())
}

/// `sub(e_id)`: the entry `?` and its folder subtree, for a `WITH RECURSIVE` prefix. Binds
/// `tn_id`, root `e_id`, `tn_id`.
const SUBTREE_CTE: &str = "WITH RECURSIVE sub(e_id, entry_id, depth) AS (\
	SELECT e_id, entry_id, 0 FROM entries WHERE tn_id=? AND e_id=? \
	UNION SELECT c.e_id, c.entry_id, s.depth + 1 FROM sub s \
	JOIN entries c ON c.tn_id=? AND c.parent_id=s.entry_id WHERE s.depth < 64) ";

/// Move an entry and stamp `channel` on its subtree — folder children by `parent_id` plus the
/// document-tree parts (`files.root_id`) of every file in it — in one transaction.
pub(crate) async fn move_entry_subtree(
	db: &SqlitePool,
	tn_id: TnId,
	entry_id: &str,
	parent_id: Option<&str>,
	channel: Option<&str>,
) -> ClResult<()> {
	let e_id = resolve_entry(db, tn_id, entry_id).await?.ok_or(Error::NotFound)?;
	let mut tx = db.begin().await.db()?;
	let old_channel: Option<Box<str>> =
		sqlx::query_scalar("SELECT channel FROM entries WHERE tn_id=? AND e_id=?")
			.bind(tn_id.0)
			.bind(e_id)
			.fetch_one(&mut *tx)
			.await
			.db()?;
	sqlx::query("UPDATE entries SET parent_id=?, updated_at=unixepoch() WHERE tn_id=? AND e_id=?")
		.bind(parent_id)
		.bind(tn_id.0)
		.bind(e_id)
		.execute(&mut *tx)
		.await
		.db()?;
	// Document parts follow their root, but only their placement in the drive being left: another
	// drive's placement of the same part stays put.
	sqlx::query(sqlx::AssertSqlSafe(format!(
		"{SUBTREE_CTE}UPDATE entries SET channel=?, updated_at=unixepoch() WHERE tn_id=? AND \
		 (e_id IN (SELECT e_id FROM sub) OR (channel IS ? AND f_id IN (SELECT p.f_id FROM files p \
		 JOIN files r ON r.tn_id=p.tn_id AND r.file_id=p.root_id \
		 JOIN entries re ON re.f_id=r.f_id JOIN sub ON sub.e_id=re.e_id WHERE p.tn_id=?)))"
	)))
	.bind(tn_id.0)
	.bind(e_id)
	.bind(tn_id.0)
	.bind(channel)
	.bind(tn_id.0)
	.bind(old_channel.as_deref())
	.bind(tn_id.0)
	.execute(&mut *tx)
	.await
	.db()?;
	tx.commit().await.db()?;
	Ok(())
}

/// Whether every entry in the folder subtree of `entry_id` has the raw `owner_tag` `owner_tag`.
pub(crate) async fn subtree_owned_by(
	db: &SqlitePool,
	tn_id: TnId,
	entry_id: &str,
	owner_tag: &str,
) -> ClResult<bool> {
	let e_id = resolve_entry(db, tn_id, entry_id).await?.ok_or(Error::NotFound)?;
	let foreign: Option<i64> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
		"{SUBTREE_CTE}SELECT e.e_id FROM entries e JOIN sub ON sub.e_id=e.e_id \
		 WHERE e.owner_tag IS NOT ? LIMIT 1"
	)))
	.bind(tn_id.0)
	.bind(e_id)
	.bind(tn_id.0)
	.bind(owner_tag)
	.fetch_optional(db)
	.await
	.db()?;
	Ok(foreign.is_none())
}

/// Live entries in drive `channel`: its root entries and their folder subtrees. Trash and
/// managed entries sit outside the root, so they and everything under them are skipped.
pub(crate) async fn count_channel_entries(
	db: &SqlitePool,
	tn_id: TnId,
	channel: &str,
) -> ClResult<u32> {
	let count: i64 = sqlx::query_scalar(
		"WITH RECURSIVE sub(entry_id, depth) AS (\
		 SELECT entry_id, 0 FROM entries WHERE tn_id=? AND channel=? AND parent_id IS NULL \
		 AND status != 'D' \
		 UNION SELECT c.entry_id, s.depth + 1 FROM sub s JOIN entries c ON c.tn_id=? \
		 AND c.parent_id=s.entry_id AND c.status != 'D' WHERE s.depth < 64) \
		 SELECT count(*) FROM sub",
	)
	.bind(tn_id.0)
	.bind(channel)
	.bind(tn_id.0)
	.fetch_one(db)
	.await
	.db()?;
	Ok(u32::try_from(count).unwrap_or(u32::MAX))
}

/// Resolve a file id per [`resolve`] (entry_id, content id, `@<f_id>`) and read its entry.
pub(crate) async fn resolve_file(
	db: &SqlitePool,
	tn_id: TnId,
	file_id: &str,
) -> ClResult<FileResolution> {
	let e_id = match resolve(db, tn_id, file_id).await? {
		Resolved::None => return Ok(FileResolution::NotFound),
		Resolved::Many => return Ok(FileResolution::Ambiguous),
		Resolved::One(e_id) => e_id,
	};
	let sql = format!("SELECT {FILE_VIEW_COLS}{FILE_VIEW_FROM} WHERE e.tn_id=? AND e.e_id=?");
	let row = sqlx::query(sqlx::AssertSqlSafe(sql))
		.bind(tn_id.0)
		.bind(e_id)
		.fetch_optional(db)
		.await
		.db()?;
	Ok(match row {
		Some(row) => FileResolution::Entry(Box::new(row_to_file_view(&row, None)?)),
		None => FileResolution::NotFound,
	})
}

/// [`resolve_file`] for HTTP callers: an ambiguous id is `Error::Conflict` (409).
pub(crate) async fn read(
	db: &SqlitePool,
	tn_id: TnId,
	file_id: &str,
) -> ClResult<Option<FileView>> {
	match resolve_file(db, tn_id, file_id).await? {
		FileResolution::NotFound => Ok(None),
		FileResolution::Entry(view) => Ok(Some(*view)),
		FileResolution::Ambiguous => Err(Error::Conflict("file id names several entries".into())),
	}
}

/// Matches the entries of content `?1`/`?2`/`?3`: bind `parse_f_id(file_id)`, then `file_id`
/// twice. An `@<f_id>` follows a dedup redirect; any other id is a `files.file_id` or a
/// reference's `ref_file_id`.
const CONTENT_FILTER: &str = concat!(
	"(e.f_id=COALESCE(",
	canon_f_id!("e.tn_id"),
	", (SELECT f_id FROM files WHERE tn_id=e.tn_id AND file_id=?)) OR e.ref_file_id=?)"
);

/// Every live entry ([`LIVE_ENTRY`]) of content `file_id` (`files.file_id`, a reference's
/// `ref_file_id`, or `@<f_id>`), managed included, by `e_id`. An `@<f_id>` also yields its pending
/// entries (the lifecycle gate keeps those to their uploader). Empty for unknown or entry ids.
pub(crate) async fn list_content_entries(
	db: &SqlitePool,
	tn_id: TnId,
	file_id: &str,
) -> ClResult<Vec<FileView>> {
	let f_id = parse_f_id(file_id)?;
	let pending = if f_id.is_some() { " OR e.status='P'" } else { "" };
	let sql = format!(
		"SELECT {FILE_VIEW_COLS}{FILE_VIEW_FROM} WHERE e.tn_id=? AND {CONTENT_FILTER} \
			AND (({LIVE_ENTRY}){pending}) \
		 ORDER BY e.e_id"
	);
	let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
		.bind(tn_id.0)
		.bind(f_id)
		.bind(file_id)
		.bind(file_id)
		.fetch_all(db)
		.await
		.db()?;
	rows.iter().map(|row| row_to_file_view(row, None)).collect()
}

/// The direct `'U'` shares `id_tag` holds on the active entries of content `file_id`: one JOIN,
/// highest permission first. `(entry_id, permission)`.
pub(crate) async fn check_content_share_access(
	db: &SqlitePool,
	tn_id: TnId,
	file_id: &str,
	id_tag: &str,
) -> ClResult<Vec<(Box<str>, char)>> {
	let f_id = parse_f_id(file_id)?;
	let sql = format!(
		"SELECT e.entry_id, s.permission FROM share_entries s \
		 JOIN entries e ON e.tn_id=s.tn_id AND e.entry_id=s.resource_id \
		 WHERE s.tn_id=? AND s.resource_type='F' AND s.subject_type='U' AND s.subject_id=? \
			AND (s.expires_at IS NULL OR s.expires_at > unixepoch()) \
			AND {LIVE_ENTRY} AND {CONTENT_FILTER} \
		 ORDER BY CASE s.permission WHEN 'A' THEN 0 WHEN 'W' THEN 1 WHEN 'C' THEN 2 ELSE 3 END"
	);
	let query = sqlx::query(sqlx::AssertSqlSafe(sql))
		.bind(tn_id.0)
		.bind(normalize_id_tag(id_tag).as_ref())
		.bind(f_id)
		.bind(file_id)
		.bind(file_id);
	let rows = query.fetch_all(db).await.db()?;
	Ok(rows
		.iter()
		.filter_map(|r| {
			let perm: String = r.get("permission");
			Some((r.get::<String, _>("entry_id").into(), perm.chars().next()?))
		})
		.collect())
}

/// Per-user data from the [`FUD_COLS`] columns; `None` when the row carries none.
fn user_data_from_row(row: &SqliteRow) -> Option<FileUserData> {
	let accessed_at: Option<i64> = row.try_get("fud_accessed_at").ok().flatten();
	let modified_at: Option<i64> = row.try_get("fud_modified_at").ok().flatten();
	let pinned: Option<i64> = row.try_get("fud_pinned").ok().flatten();
	let starred: Option<i64> = row.try_get("fud_starred").ok().flatten();
	let access_level_str: Option<String> = row.try_get("fud_access_level").ok().flatten();
	let access_level =
		access_level_str.and_then(|s| s.chars().next()).map(AccessLevel::from_perm_char);

	if accessed_at.is_none()
		&& modified_at.is_none()
		&& pinned.is_none()
		&& starred.is_none()
		&& access_level.is_none()
	{
		return None;
	}
	Some(FileUserData {
		accessed_at: accessed_at.map(Timestamp),
		modified_at: modified_at.map(Timestamp),
		pinned: pinned.unwrap_or(0) != 0,
		starred: starred.unwrap_or(0) != 0,
		access_level,
	})
}

/// Project a [`FILE_VIEW_COLS`] row into a `FileView`. Shared by [`list`], [`read`] and
/// [`read_with_user_data`], which pass `user_data` from the joined `file_user_data` row.
fn row_to_file_view(row: &SqliteRow, user_data: Option<FileUserData>) -> ClResult<FileView> {
	let status = match row.try_get("status").db()? {
		"A" => FileStatus::Active,
		"P" => FileStatus::Pending,
		"D" => FileStatus::Deleted,
		_ => return Err(Error::DbError),
	};

	let tags_str: Option<Box<str>> = row.try_get("tags").ok().flatten();
	let tags = tags_str.map(|s| parse_str_list(&s).to_vec());

	let upstream = build_upstream_profile(row);
	let owner = build_owner_profile(row);

	let visibility: Option<String> = row.try_get("visibility").ok().flatten();
	let visibility = visibility.and_then(|s| s.chars().next());

	let accessed_at: Option<i64> = row.try_get("accessed_at").ok().flatten();
	let modified_at: Option<i64> = row.try_get("modified_at").ok().flatten();
	let x: Option<serde_json::Value> = row.try_get("x").ok().flatten();
	let hidden = row.try_get::<Option<i32>, _>("hidden").ok().flatten().unwrap_or(0) != 0;
	let broken_at: Option<i64> = row.try_get("broken_at").ok().flatten();
	let broken_reason: Option<String> = row.try_get("broken_reason").ok().flatten();
	let broken_reason = parse_broken_reason(broken_reason.as_deref());

	Ok(FileView {
		entry_id: row.try_get("entry_id").db()?,
		file_id: row.try_get("file_id").db()?,
		parent_id: row.try_get("parent_id").ok().flatten(),
		root_id: row.try_get("root_id").ok().flatten(),
		upstream,
		upstream_tag: row.try_get("upstream_tag").ok().flatten(),
		owner,
		owner_tag: row.try_get("owner_tag").ok().flatten(),
		action_id: row.try_get("action_id").db()?,
		preset: row.try_get("preset").ok().flatten(),
		content_type: row.try_get("content_type").ok().flatten(),
		file_name: row.try_get("file_name").db()?,
		file_tp: row.try_get("file_tp").ok().flatten(),
		created_at: row.try_get::<i64, _>("created_at").map(Timestamp).db()?,
		accessed_at: accessed_at.map(Timestamp),
		modified_at: modified_at.map(Timestamp),
		status,
		tags,
		visibility,
		channel: row.try_get("channel").ok().flatten(),
		hidden,
		access_level: None, // Computed later by filter_files_by_visibility
		user_data,
		x,
		parent_name: None, // Filled in by handler when with_parent=true
		path: None,        // Filled in by handler when with_path=true
		broken_at: broken_at.map(Timestamp),
		broken_reason,
	})
}

/// Read a single file and include the caller's per-user data (pinned, starred,
/// per-user timestamps, cached cross-context access_level).
///
/// Unlike [`read`], this performs the same LEFT JOIN on `file_user_data` as the
/// list query so callers like `refresh_file` can read back the freshly stored
/// `access_level` without an extra round-trip.
pub(crate) async fn read_with_user_data(
	db: &SqlitePool,
	tn_id: TnId,
	file_id: &str,
	id_tag: &str,
) -> ClResult<Option<FileView>> {
	let Some(e_id) = resolve_entry(db, tn_id, file_id).await? else { return Ok(None) };
	let id_tag = normalize_id_tag(id_tag);
	let sql = format!(
		"SELECT {FILE_VIEW_COLS}{FUD_COLS}{FILE_VIEW_FROM} \
		 LEFT JOIN file_user_data fud ON fud.tn_id=e.tn_id AND fud.e_id=e.e_id AND fud.id_tag=? \
		 WHERE e.tn_id=? AND e.e_id=?"
	);
	let row = sqlx::query(sqlx::AssertSqlSafe(sql))
		.bind(id_tag.as_ref())
		.bind(tn_id.0)
		.bind(e_id)
		.fetch_optional(db)
		.await
		.db()?;
	row.map(|row| row_to_file_view(&row, user_data_from_row(&row))).transpose()
}

/// List `(e_id, f_id)` of entries whose `parent_id` equals the given sentinel
/// (e.g. `__managed__`) and whose `created_at` is strictly before `before`.
/// `f_id` is the content whose references keep the entry; `None` = only its action could (or a
/// folder). An action-owned entry is listed only once that action is gone or deleted, so it
/// lives exactly as long as its action. Used by the file GC to enumerate candidates. Content
/// still pending finalization (no `file_id`) is skipped: it is mid-upload and may be referenced
/// via an `@<f_id>` placeholder.
pub(crate) async fn list_files_by_parent(
	db: &SqlitePool,
	tn_id: TnId,
	parent_id: &str,
	before: Timestamp,
) -> ClResult<Vec<(u64, Option<u64>)>> {
	let rows: Vec<(i64, Option<i64>)> = sqlx::query_as(
		"SELECT e.e_id, CASE WHEN e.action_id IS NULL THEN e.f_id END FROM entries e
		 LEFT JOIN files f ON f.f_id = e.f_id
		 WHERE e.tn_id = ? AND e.parent_id = ?
		   AND (e.f_id IS NULL OR f.file_id IS NOT NULL)
		   AND e.status IN ('A', 'P', 'D')
		   AND e.created_at < ?
		   AND (e.action_id IS NULL OR NOT EXISTS (SELECT 1 FROM actions a \
				WHERE a.tn_id = e.tn_id AND a.action_id = e.action_id \
				AND coalesce(a.status, 'A') <> 'D'))",
	)
	.bind(tn_id.0)
	.bind(parent_id)
	.bind(before.0)
	.fetch_all(db)
	.await
	.db()?;

	Ok(rows
		.into_iter()
		.map(|(e_id, f_id)| (e_id.cast_unsigned(), f_id.map(i64::cast_unsigned)))
		.collect())
}

/// Content `f` has an entry in the managed folder. Binds `?1` = tn_id, `?2` = the managed id.
const IN_MANAGED: &str = "EXISTS (SELECT 1 FROM entries e \
	WHERE e.tn_id = ?1 AND e.f_id = f.f_id AND e.parent_id = ?2)";

/// Internal `f_id`s of files in the managed folder that are still referenced
/// by at least one canonical column. Used by the file GC.
///
/// The set is naturally scoped to managed-folder rows via the join, so
/// references to files in other folders never enter the set. Returning
/// numeric `f_id`s instead of `file_id` strings keeps the in-memory set tiny.
///
/// Sources (one query per source, UNIONed at application level — readable and
/// each subquery is index-friendly):
/// - `actions.attachments` CSV (every action but deleted ones; drafts count). Both raw
///   `f.file_id` tokens and `@<f.f_id>` draft-time placeholders match; an `@<f_id>`
///   follows the dedup redirect (`merged_into`) to the content that survived.
/// - `tenants.profile_pic`, `tenants.cover_pic` (this tenant).
/// - `profiles.profile_pic` (cached remote profile images).
/// - `site_docs.published_file_id`, `site_docs.previous_file_id` (the live and
///   rollback generations of every published site container).
///
/// MUST be updated when a new column names a file in the managed folder — and so must the
/// column guards in [`reap_orphan_files`], which keep that content alive without an entry.
pub(crate) async fn list_referenced_managed_fids(
	db: &SqlitePool,
	tn_id: TnId,
) -> ClResult<HashSet<u64>> {
	let mut out: HashSet<u64> = HashSet::new();

	// 1. actions.attachments via recursive CSV split. `IN_MANAGED` scopes results to content
	//    with a managed-folder entry in this tenant.
	let attachment_refs: Vec<(i64,)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
		"WITH RECURSIVE split(item, rest) AS (
			SELECT NULL, attachments || ',' FROM actions
			 WHERE tn_id = ?1 AND attachments IS NOT NULL AND attachments != ''
			   AND coalesce(status, 'A') != 'D'
			UNION ALL
			SELECT substr(rest, 1, instr(rest, ',') - 1),
				   substr(rest, instr(rest, ',') + 1)
			  FROM split WHERE rest != ''
		)
		SELECT DISTINCT f.f_id FROM split s
		  JOIN files f ON f.tn_id = ?1 AND {IN_MANAGED}
		 WHERE s.item IS NOT NULL AND s.item != ''
		   AND (
			   (s.item LIKE '@%' AND f.f_id = (SELECT COALESCE(merged_into, f_id) FROM files
				   WHERE tn_id = ?1 AND f_id = CAST(substr(s.item, 2) AS INTEGER)))
			   OR (s.item NOT LIKE '@%' AND f.file_id = s.item)
		   )"
	)))
	.bind(tn_id.0)
	.bind(cloudillo_types::meta_adapter::MANAGED_PARENT_ID)
	.fetch_all(db)
	.await
	.db()?;
	for (f_id,) in attachment_refs {
		out.insert(f_id.cast_unsigned());
	}

	// 2. tenants.profile_pic / cover_pic (this tenant).
	let tenant_refs: Vec<(i64,)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
		"SELECT f.f_id FROM files f JOIN tenants t ON t.tn_id = f.tn_id
		 WHERE f.tn_id = ?1 AND {IN_MANAGED}
		   AND (t.profile_pic = f.file_id OR t.cover_pic = f.file_id)"
	)))
	.bind(tn_id.0)
	.bind(cloudillo_types::meta_adapter::MANAGED_PARENT_ID)
	.fetch_all(db)
	.await
	.db()?;
	for (f_id,) in tenant_refs {
		out.insert(f_id.cast_unsigned());
	}

	// 3. profiles.profile_pic (cached remote profile images).
	let profile_refs: Vec<(i64,)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
		"SELECT DISTINCT f.f_id FROM files f
		  JOIN profiles p ON p.tn_id = f.tn_id AND p.profile_pic = f.file_id
		 WHERE f.tn_id = ?1 AND {IN_MANAGED}"
	)))
	.bind(tn_id.0)
	.bind(cloudillo_types::meta_adapter::MANAGED_PARENT_ID)
	.fetch_all(db)
	.await
	.db()?;
	for (f_id,) in profile_refs {
		out.insert(f_id.cast_unsigned());
	}

	// 4. site_docs.published_file_id / previous_file_id (published site containers).
	//    Both generations are plain scalar columns, so this is a plain join — the
	//    reason the schema rejected a CSV `previous_file_ids` list. A NULL
	//    `previous_file_id` needs no special case: `x IN (a, NULL)` is true when
	//    x = a and NULL otherwise, and NULL filters out like false.
	let site_docs_refs: Vec<(i64,)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
		"SELECT DISTINCT f.f_id FROM files f
		  JOIN site_docs d ON d.tn_id = f.tn_id
		   AND f.file_id IN (d.published_file_id, d.previous_file_id)
		 WHERE f.tn_id = ?1 AND {IN_MANAGED}"
	)))
	.bind(tn_id.0)
	.bind(cloudillo_types::meta_adapter::MANAGED_PARENT_ID)
	.fetch_all(db)
	.await
	.db()?;
	for (f_id,) in site_docs_refs {
		out.insert(f_id.cast_unsigned());
	}

	Ok(out)
}

/// Sweep everything that references an entry: its `share.file` links, and its `share_entries` on
/// both sides — as the *resource*, and as the *subject* of the file-to-file embed rows
/// `list_share_entries_by_subject` serves. All of them hold the `entry_id` since v58. Returns
/// `(refs_removed, share_entries_removed)`.
///
/// Shared by [`delete`] and [`hard_delete_file`] so the tombstone path and the GC path cannot
/// drift.
async fn sweep_file_shares(
	tx: &mut sqlx::SqliteConnection,
	tn_id: TnId,
	entry_id: &str,
) -> ClResult<(u64, u64)> {
	// `resource_id` is free-form on every ref type, so filter by type or an unrelated row
	// naming the same id gets swept up.
	let refs_removed =
		sqlx::query("DELETE FROM refs WHERE tn_id = ? AND resource_id = ? AND type = ?")
			.bind(tn_id.0)
			.bind(entry_id)
			.bind(SHARE_FILE_REF_TYPE)
			.execute(&mut *tx)
			.await
			.db()?
			.rows_affected();

	let share_entries_removed = sqlx::query(
		"DELETE FROM share_entries WHERE tn_id = ? \
		 AND ((resource_type = 'F' AND resource_id = ?) \
		   OR (subject_type = 'F' AND subject_id = ?))",
	)
	.bind(tn_id.0)
	.bind(entry_id)
	.bind(entry_id)
	.execute(&mut *tx)
	.await
	.db()?
	.rows_affected();

	// FSHR grants are keyed by content id (`FSHR:{file_id}:{audience}`; a folder: its entry id),
	// so they die with the content's last live entry — local or reference: another placement
	// still backs the share.
	let entry: Option<(Option<i64>, OptStr, OptStr)> = sqlx::query_as(
		"SELECT e.f_id, f.file_id, e.ref_file_id FROM entries e LEFT JOIN files f \
		 ON f.f_id = e.f_id WHERE e.tn_id = ? AND e.entry_id = ?",
	)
	.bind(tn_id.0)
	.bind(entry_id)
	.fetch_optional(&mut *tx)
	.await
	.db()?;
	let subject: Option<Box<str>> = match entry {
		Some((None, _, None)) => Some(entry_id.into()),
		Some((_, Some(content_id), _) | (None, None, Some(content_id))) => {
			let live: Option<i64> = sqlx::query_scalar(
				"SELECT e_id FROM entries WHERE tn_id = ? AND status = 'A' AND entry_id <> ? \
				 AND (f_id = (SELECT f_id FROM files WHERE tn_id = ? AND file_id = ?) \
				   OR ref_file_id = ?) LIMIT 1",
			)
			.bind(tn_id.0)
			.bind(entry_id)
			.bind(tn_id.0)
			.bind(content_id.as_ref())
			.bind(content_id.as_ref())
			.fetch_optional(&mut *tx)
			.await
			.db()?;
			live.is_none().then_some(content_id)
		}
		// Unfinalized content has no id to be shared by.
		Some((Some(_), None, _)) | None => None,
	};
	if let Some(subject) = subject {
		// A prefix compare, not LIKE: `_` in an id is a LIKE wildcard.
		let fshr_prefix = format!("FSHR:{subject}:");
		sqlx::query("DELETE FROM actions WHERE tn_id = ? AND substr(key, 1, length(?)) = ?")
			.bind(tn_id.0)
			.bind(&fshr_prefix)
			.bind(&fshr_prefix)
			.execute(&mut *tx)
			.await
			.db()?;
	}

	Ok((refs_removed, share_entries_removed))
}

/// Hard-delete one entry inside a single transaction. Intended for the file GC.
///
/// Runs the same [`sweep_file_shares`] cascade [`delete`] does: an entry can reach `status = 'D'`
/// by routes other than `delete`, and removing it without clearing its links and grants would
/// leave them dangling. Content is never deleted here: a `files` row left with no entry is reaped
/// by [`reap_orphan_files`] after the GC window, so a re-attach in between keeps the bytes.
/// Returns the search object key the entry belonged to (its content id; a folder's entry id),
/// so the caller can reindex what is left of it.
pub(crate) async fn hard_delete_file(
	db: &SqlitePool,
	tn_id: TnId,
	e_id: u64,
) -> ClResult<Option<Box<str>>> {
	let mut tx = db.begin().await.db()?;
	let key: Option<Box<str>> = sqlx::query_scalar(
		"SELECT COALESCE(f.file_id, e.ref_file_id, e.entry_id) FROM entries e \
		 LEFT JOIN files f ON f.f_id = e.f_id WHERE e.tn_id = ? AND e.e_id = ?",
	)
	.bind(tn_id.0)
	.bind(e_id.cast_signed())
	.fetch_optional(&mut *tx)
	.await
	.db()?;
	hard_delete_entry(&mut tx, tn_id, e_id).await?;
	tx.commit().await.db()?;
	Ok(key)
}

/// Hard-delete every tombstoned entry of `tn_id` ([`hard_delete_entry`]), in one transaction.
pub(crate) async fn purge_tombstones(db: &SqlitePool, tn_id: TnId) -> ClResult<u64> {
	let mut tx = db.begin().await.db()?;
	let e_ids: Vec<i64> =
		sqlx::query_scalar("SELECT e_id FROM entries WHERE tn_id = ? AND status = 'D'")
			.bind(tn_id.0)
			.fetch_all(&mut *tx)
			.await
			.db()?;
	for &e_id in &e_ids {
		hard_delete_entry(&mut tx, tn_id, e_id.cast_unsigned()).await?;
	}
	tx.commit().await.db()?;
	Ok(e_ids.len() as u64)
}

/// [`hard_delete_file`] inside the caller's transaction.
async fn hard_delete_entry(
	tx: &mut sqlx::SqliteConnection,
	tn_id: TnId,
	e_id: u64,
) -> ClResult<()> {
	let entry_id: Option<Box<str>> =
		sqlx::query_scalar("SELECT entry_id FROM entries WHERE tn_id = ? AND e_id = ?")
			.bind(tn_id.0)
			.bind(e_id.cast_signed())
			.fetch_optional(&mut *tx)
			.await
			.db()?;
	let Some(entry_id) = entry_id else { return Ok(()) };

	sweep_file_shares(&mut *tx, tn_id, &entry_id).await?;
	delete_entry_rows(tx, tn_id, e_id.cast_signed()).await
}

/// Delete an entry row and its per-user `file_user_data` rows: `e_id` is a reused rowid, so a
/// later entry would otherwise inherit stale stars, pins and cached access levels.
async fn delete_entry_rows(
	tx: &mut sqlx::SqliteConnection,
	tn_id: TnId,
	e_id: i64,
) -> ClResult<()> {
	// Starts the content's orphan window (see `reap_orphan_files`) at its last entry's removal.
	sqlx::query(
		"UPDATE files SET updated_at = unixepoch() \
		 WHERE f_id = (SELECT f_id FROM entries WHERE tn_id = ?1 AND e_id = ?2)",
	)
	.bind(tn_id.0)
	.bind(e_id)
	.execute(&mut *tx)
	.await
	.db()?;
	sqlx::query("DELETE FROM file_user_data WHERE tn_id = ? AND e_id = ?")
		.bind(tn_id.0)
		.bind(e_id)
		.execute(&mut *tx)
		.await
		.db()?;
	sqlx::query("DELETE FROM entries WHERE tn_id = ? AND e_id = ?")
		.bind(tn_id.0)
		.bind(e_id)
		.execute(&mut *tx)
		.await
		.db()?;
	Ok(())
}

/// Delete content no entry references, last touched before `before`, with its `file_variants`
/// (the blob sweep then reclaims the bytes) and any dedup redirect pointing at it. A redirect row
/// itself (`merged_into` set) is kept while its target lives. Returns the reaped content ids.
pub(crate) async fn reap_orphan_files(
	db: &SqlitePool,
	tn_id: TnId,
	before: Timestamp,
) -> ClResult<Vec<Box<str>>> {
	let mut tx = db.begin().await.db()?;
	let orphans: Vec<(i64, OptStr)> = sqlx::query_as(
		"SELECT f.f_id, f.file_id FROM files f WHERE f.tn_id = ? AND f.merged_into IS NULL \
		 AND f.updated_at < ? \
		 AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.f_id = f.f_id) \
		 AND NOT EXISTS (SELECT 1 FROM tenants t WHERE t.tn_id = f.tn_id \
		   AND f.file_id IN (t.profile_pic, t.cover_pic)) \
		 AND NOT EXISTS (SELECT 1 FROM profiles p WHERE p.tn_id = f.tn_id \
		   AND p.profile_pic = f.file_id) \
		 AND NOT EXISTS (SELECT 1 FROM site_docs d WHERE d.tn_id = f.tn_id \
		   AND f.file_id IN (d.published_file_id, d.previous_file_id))",
	)
	.bind(tn_id.0)
	.bind(before.0)
	.fetch_all(&mut *tx)
	.await
	.db()?;
	let mut reaped = Vec::new();
	for (f_id, file_id) in orphans {
		for sql in [
			"DELETE FROM file_variants WHERE tn_id = ?1 AND f_id = ?2",
			"DELETE FROM files WHERE tn_id = ?1 AND (f_id = ?2 OR merged_into = ?2)",
		] {
			sqlx::query(sql).bind(tn_id.0).bind(f_id).execute(&mut *tx).await.db()?;
		}
		reaped.extend(file_id);
	}
	tx.commit().await.db()?;
	Ok(reaped)
}

/// [`delete_action_entries`] in its own transaction.
pub(crate) async fn delete_managed_entries(
	db: &SqlitePool,
	tn_id: TnId,
	action_id: &str,
) -> ClResult<()> {
	let mut tx = db.begin().await.db()?;
	delete_action_entries(&mut tx, tn_id, action_id).await?;
	tx.commit().await.db()
}

/// Hard-delete the managed attachment entries owned by `action_id`, inside the caller's
/// transaction (action delete and key supersession). Content left with no entry stays until
/// [`reap_orphan_files`] — a superseding action re-attaches it in the meantime. Managed entries
/// are never search-indexed, so there is no index entry to drop.
pub(crate) async fn delete_action_entries(
	tx: &mut sqlx::SqliteConnection,
	tn_id: TnId,
	action_id: &str,
) -> ClResult<()> {
	let e_ids: Vec<i64> = sqlx::query_scalar(
		"SELECT e_id FROM entries WHERE tn_id = ? AND action_id = ? AND parent_id = ?",
	)
	.bind(tn_id.0)
	.bind(action_id)
	.bind(cloudillo_types::meta_adapter::MANAGED_PARENT_ID)
	.fetch_all(&mut *tx)
	.await
	.db()?;
	for e_id in e_ids {
		hard_delete_entry(tx, tn_id, e_id.cast_unsigned()).await?;
	}
	Ok(())
}

/// The `f_id` of BLOB content `file_id` (only immutable BLOBs may carry several entries);
/// `NotFound` for unknown or non-BLOB content.
async fn blob_f_id(tx: &mut sqlx::SqliteConnection, tn_id: TnId, file_id: &str) -> ClResult<i64> {
	sqlx::query_scalar(
		"SELECT f_id FROM files WHERE tn_id = ? AND file_id = ? \
		 AND IFNULL(file_tp, 'BLOB') = 'BLOB'",
	)
	.bind(tn_id.0)
	.bind(file_id)
	.fetch_optional(&mut *tx)
	.await
	.db()?
	.ok_or(Error::NotFound)
}

/// See `MetaAdapter::create_entry_for_content`. Not [`create`]: its same-placement check would
/// hand back the existing entry for a copy landing in the same folder.
pub(crate) async fn create_entry_for_content(
	db: &SqlitePool,
	tn_id: TnId,
	file_id: &str,
	mut opts: CreateFile,
) -> ClResult<Box<str>> {
	opts.owner_tag = opts.owner_tag.as_deref().map(|t| normalize_id_tag(t).into());
	let mut tx = db.begin().await.db()?;
	let f_id = blob_f_id(&mut tx, tn_id, file_id).await?;
	let entry_id: Box<str> = cloudillo_types::utils::random_id()?.into();
	insert_entry(&mut tx, tn_id, &entry_id, Some(f_id), "A", &opts).await?;
	tx.commit().await.db()?;
	Ok(entry_id)
}

/// See `MetaAdapter::create_managed_entry`. The owner is the tenant (NULL).
pub(crate) async fn create_managed_entry(
	db: &SqlitePool,
	tn_id: TnId,
	file_id: &str,
	file_name: &str,
	action_id: Option<&str>,
	visibility: Option<char>,
	channel: Option<&str>,
) -> ClResult<Box<str>> {
	let mut tx = db.begin().await.db()?;
	let f_id = blob_f_id(&mut tx, tn_id, file_id).await?;

	let existing: Option<Box<str>> = sqlx::query_scalar(
		"SELECT entry_id FROM entries WHERE tn_id = ? AND f_id = ? AND action_id IS ? \
		 AND parent_id = ? LIMIT 1",
	)
	.bind(tn_id.0)
	.bind(f_id)
	.bind(action_id)
	.bind(cloudillo_types::meta_adapter::MANAGED_PARENT_ID)
	.fetch_optional(&mut *tx)
	.await
	.db()?;
	if let Some(entry_id) = existing {
		return Ok(entry_id);
	}

	// A managed entry always originates here (`upstream_tag` NULL): its caller verified the bytes.
	let entry_id: Box<str> = cloudillo_types::utils::random_id()?.into();
	let opts = CreateFile {
		file_name: file_name.into(),
		visibility,
		channel: channel.map(Into::into),
		action_id: action_id.map(Into::into),
		parent_id: Some(cloudillo_types::meta_adapter::MANAGED_PARENT_ID.into()),
		..Default::default()
	};
	insert_entry(&mut tx, tn_id, &entry_id, Some(f_id), "A", &opts).await?;
	tx.commit().await.db()?;
	Ok(entry_id)
}

/// Delete a document tree and everything that would otherwise outlive it.
///
/// Entries are tombstoned (`status = 'D'`); the file GC purges them, then their content. Not
/// soft delete — that moves the file into the trash folder and deliberately keeps links and grants
/// so a restore keeps them working. This path is terminal, so it clears them.
///
/// Only the resolved entry and the entries of its document tree (files whose `root_id` is its
/// content id) are tombstoned — never sibling entries of the same content elsewhere.
///
/// `share_entries` is swept on both sides: as the *resource*, and as the *subject* (the
/// file-to-file embed rows `list_share_entries_by_subject` serves).
pub(crate) async fn delete(
	db: &SqlitePool,
	tn_id: TnId,
	file_id: &str,
) -> ClResult<DeleteFileResult> {
	let root_e_id = resolve_entry(db, tn_id, file_id).await?.ok_or(Error::NotFound)?;
	let mut tx = db.begin().await.db()?;

	// Content id of the root: a folder's is its entry_id, a pending upload has none, and a
	// reference roots no local tree.
	let root: Option<(Box<str>, Option<i64>, OptStr, OptStr)> = sqlx::query_as(
		"SELECT e.entry_id, e.f_id, \
		 CASE WHEN e.ref_file_id IS NOT NULL THEN NULL \
		 WHEN e.f_id IS NULL THEN e.entry_id ELSE f.file_id END, e.channel \
		 FROM entries e LEFT JOIN files f ON f.f_id = e.f_id WHERE e.tn_id = ? AND e.e_id = ?",
	)
	.bind(tn_id.0)
	.bind(root_e_id)
	.fetch_optional(&mut *tx)
	.await
	.db()?;
	let Some((root_entry_id, root_f_id, root_content_id, root_channel)) = root else {
		return Err(Error::NotFound);
	};

	let mut files_deleted =
		sqlx::query("UPDATE entries SET status = 'D' WHERE tn_id = ? AND e_id = ?")
			.bind(tn_id.0)
			.bind(root_e_id)
			.execute(&mut *tx)
			.await
			.db()?
			.rows_affected();

	let mut entry_ids: Vec<Box<str>> = vec![root_entry_id];

	if let Some(root_id) = root_content_id {
		// Read inside the transaction so the tree cannot grow underneath the cascade. No `status`
		// filter: a child soft-deleted on its own still owns links and grants this path must sweep.
		// `f.f_id IS NOT ?` keeps a self-rooted root's sibling entries out of the tree; the
		// channel keeps out another drive's placement of a part.
		let children: Vec<(i64, Box<str>)> = sqlx::query_as(
			"SELECT e.e_id, e.entry_id FROM entries e JOIN files f ON f.f_id = e.f_id \
			 WHERE f.tn_id = ? AND f.root_id = ? AND f.f_id IS NOT ? AND e.channel IS ?",
		)
		.bind(tn_id.0)
		.bind(root_id.as_ref())
		.bind(root_f_id)
		.bind(root_channel.as_deref())
		.fetch_all(&mut *tx)
		.await
		.db()?;

		for (e_id, _) in &children {
			files_deleted +=
				sqlx::query("UPDATE entries SET status = 'D' WHERE tn_id = ? AND e_id = ?")
					.bind(tn_id.0)
					.bind(e_id)
					.execute(&mut *tx)
					.await
					.db()?
					.rows_affected();
		}

		entry_ids.extend(children.into_iter().map(|(_, entry_id)| entry_id));
	}

	let mut refs_removed = 0u64;
	let mut share_entries_removed = 0u64;

	for id in &entry_ids {
		let (refs, entries) = sweep_file_shares(&mut tx, tn_id, id).await?;
		refs_removed += refs;
		share_entries_removed += entries;
	}

	tx.commit().await.db()?;

	Ok(DeleteFileResult { entry_ids, files_deleted, refs_removed, share_entries_removed })
}

#[cfg(test)]
mod tests {
	use super::parse_broken_reason;
	use cloudillo_types::meta_adapter::BrokenReason;

	#[test]
	fn test_parse_broken_reason_roundtrip() {
		for reason in [BrokenReason::Deleted, BrokenReason::Revoked] {
			let parsed = parse_broken_reason(Some(reason.as_str()));
			assert_eq!(parsed, Some(reason), "round-trip diverged for {:?}", reason);
		}
	}

	#[test]
	fn test_parse_broken_reason_none() {
		assert_eq!(parse_broken_reason(None), None);
	}

	#[test]
	fn test_parse_broken_reason_unknown_value() {
		assert_eq!(parse_broken_reason(Some("not-a-real-reason")), None);
	}

	use cloudillo_types::meta_adapter::{CreateFile, FileId, FileStatus};
	use cloudillo_types::prelude::TnId;
	use sqlx::Row;
	use sqlx::sqlite::{self, SqlitePool};

	// Build a production-like single-connection write pool over a temp DB file
	// (mirrors `MetaAdapterSqlite::new`: WAL, single write connection).
	async fn test_pool(dir: &std::path::Path) -> SqlitePool {
		let opts = sqlite::SqliteConnectOptions::new()
			.filename(dir.join("meta.db"))
			.create_if_missing(true)
			.journal_mode(sqlite::SqliteJournalMode::Wal);
		let db = sqlite::SqlitePoolOptions::new()
			.max_connections(1)
			.connect_with(opts)
			.await
			.expect("connect test pool");
		crate::schema::init_db(&db).await.expect("init schema");
		db
	}

	fn shared_file_opts(file_id: &str) -> CreateFile {
		CreateFile {
			orig_variant_id: None,
			file_id: Some(file_id.into()),
			parent_id: None,
			root_id: None,
			upstream_tag: None,
			owner_tag: None,
			preset: Some("sync".into()),
			content_type: "image/jpeg".into(),
			file_name: "shared.jpg".into(),
			file_tp: Some("BLOB".into()),
			created_at: None,
			tags: None,
			x: None,
			visibility: None,
			channel: None,
			hidden: false,
			status: Some(FileStatus::Active),
			action_id: None,
		}
	}

	// Reproduces the bulk-federation race: N concurrent create() calls (a verified sync) for the
	// same explicit (file_id, tn_id). All must succeed, return the same f_id,
	// and leave exactly one row — no UNIQUE constraint crash.
	#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
	async fn create_file_concurrent_same_file_id() {
		for iter in 0..10 {
			let dir = tempfile::tempdir().expect("tempdir");
			let db = test_pool(dir.path()).await;
			let tn_id = TnId(1);
			let file_id = "f1~6A_MV8F8cImk_6XZsDgvKgnA0gDmREC0rFhLLYbOJWs";

			let mut handles = Vec::new();
			for _ in 0..8 {
				let db = db.clone();
				handles.push(tokio::spawn(async move {
					super::create(&db, tn_id, shared_file_opts(file_id)).await
				}));
			}

			let mut f_ids = Vec::new();
			for h in handles {
				let res = h.await.expect("task join");
				let created =
					res.unwrap_or_else(|e| panic!("iter {iter}: create() returned Err: {e:?}"));
				match created.file_id {
					FileId::FId(f_id) => f_ids.push(f_id),
					other @ FileId::FileId(_) => {
						panic!("iter {iter}: expected FId, got {other:?}")
					}
				}
			}

			let first = f_ids[0];
			assert!(f_ids.iter().all(|&f| f == first), "iter {iter}: divergent f_ids: {f_ids:?}");

			let count: i64 = sqlx::query("SELECT count(*) FROM files WHERE tn_id=? AND file_id=?")
				.bind(tn_id.0)
				.bind(file_id)
				.fetch_one(&db)
				.await
				.expect("count query")
				.get(0);
			assert_eq!(count, 1, "iter {iter}: expected exactly one files row");

			// Repeat creates of an explicit file_id are idempotent: one entry, never a second.
			let entries: i64 = sqlx::query("SELECT count(*) FROM entries WHERE tn_id=?")
				.bind(tn_id.0)
				.fetch_one(&db)
				.await
				.expect("entry count query")
				.get(0);
			assert_eq!(entries, 1, "iter {iter}: expected exactly one entry");
		}
	}
}
