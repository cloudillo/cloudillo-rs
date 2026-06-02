// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Action management and federation

use sqlx::{Row, SqlitePool};

use crate::utils::{collect_res, escape_like, inspect, map_res, parse_str_list, push_in};
use cloudillo_types::meta_adapter::{
	Action, ActionData, ActionId, ActionView, AttachmentView, AudienceType, FinalizeActionOptions,
	ListActionOptions, ProfileInfo, ProfileStatus, ProfileType, UpdateActionDataOptions,
};
use cloudillo_types::prelude::*;

/// Map a DB visibility column value to the ActionView representation.
/// Storage uses 'D' for Direct uniformly; ActionView treats Direct as None to
/// keep the wire/token format unchanged.
fn db_visibility_to_action(s: Option<String>) -> Option<char> {
	s.and_then(|s| s.chars().next()).filter(|c| *c != 'D')
}

/// Append the WHERE filters shared by `list`, `count`, and `count_grouped`.
/// Caller has already emitted `... WHERE a.tn_id=<bind>`; this appends `AND ...`
/// clauses. Operates on alias `a`, with `pi` (issuer profile) and `pa`
/// (effective-audience profile) joins available for the profile-status and
/// audience-type filters. Does NOT touch sort/cursor/limit (list-only).
fn push_action_filters(
	mut query: sqlx::QueryBuilder<sqlx::Sqlite>,
	opts: &ListActionOptions,
) -> sqlx::QueryBuilder<sqlx::Sqlite> {
	if let Some(status) = &opts.status {
		query.push(" AND coalesce(a.status, 'A') IN ");
		query = push_in(query, status);
	} else {
		// Default: hide deleted ('D'), inbound-verifying ('V'), and permanently
		// failed ('F') rows. 'V' covers inbound actions whose attachment sync
		// hasn't finished — surfacing them would expose half-synced posts and
		// break the descriptor-hash invariant for downstream peers fetching
		// attachments. 'F' is the terminal state for verifier tasks that
		// exhausted retries.
		query.push(" AND coalesce(a.status, 'A') NOT IN ('D', 'V', 'F')");
	}
	if let Some(typ) = &opts.typ {
		query.push(" AND a.type IN ");
		query = push_in(query, typ.as_slice());
	}
	if let Some(issuer) = &opts.issuer {
		query.push(" AND a.issuer_tag=").push_bind(issuer);
	}
	if let Some(audience) = &opts.audience {
		// `audience IS NULL` means "on the issuer's wall" by codebase convention
		// (see helpers::effective_audience). Match the same semantics here so
		// callers asking "show me actions on T's wall" get both T's own rows
		// and 3rd-party rows explicitly addressed to T (the audience-bridge
		// case used by federation history sync).
		query.push(" AND coalesce(a.audience, a.issuer_tag)=").push_bind(audience);
	}
	if let Some(audience_type) = opts.audience_type {
		// Filter on the type of the *effective audience* profile (i.e., the
		// profile whose wall the action lives on). `pa` is joined on
		// `coalesce(audience, issuer_tag)`, so this works both for explicitly
		// addressed actions and for actions on the issuer's own wall. Both
		// branches are strict on `pa.type`: unknown remote profiles (no `pa`
		// row, e.g. cross-tenant observer never synced locally) are excluded
		// from both filters rather than guessed-as-Personal — callers asking
		// for a specific audience type get only confirmed matches, and the
		// profile sync flow is the right place to populate `pa`.
		match audience_type {
			AudienceType::Personal => {
				query.push(" AND pa.type='P'");
			}
			AudienceType::Community => {
				query.push(" AND pa.type='C'");
			}
		}
	}
	if let Some(involved) = &opts.involved {
		if let Some(viewer) = &opts.viewer_id_tag {
			if viewer == involved {
				// Self-messages: both issuer and audience must be the user
				query
					.push(" AND a.issuer_tag=")
					.push_bind(involved)
					.push(" AND a.audience=")
					.push_bind(involved);
			} else {
				// Conversation between viewer and involved person
				query
					.push(" AND ((a.issuer_tag=")
					.push_bind(viewer)
					.push(" AND a.audience=")
					.push_bind(involved)
					.push(") OR (a.issuer_tag=")
					.push_bind(involved)
					.push(" AND a.audience=")
					.push_bind(viewer)
					.push("))");
			}
		} else {
			// No viewer (unauthenticated): fall back to simple OR
			query
				.push(" AND (a.audience=")
				.push_bind(involved)
				.push(" OR a.issuer_tag=")
				.push_bind(involved)
				.push(")");
		}
	}
	if let Some(parent_id) = &opts.parent_id {
		query.push(" AND a.parent_id=").push_bind(parent_id);
	}
	if let Some(root_id) = &opts.root_id {
		query.push(" AND a.root_id=").push_bind(root_id);
	}
	if let Some(subject) = &opts.subject {
		query.push(" AND a.subject=").push_bind(subject);
	}
	if let Some(created_after) = &opts.created_after {
		query.push(" AND a.created_at>").push_bind(created_after.0);
	}
	// Materialize excluded-status codes ahead of push_bind so the &str slice
	// outlives the QueryBuilder (push_in takes references with lifetime 'a).
	let excluded_status_codes: Option<Vec<&str>> = opts
		.exclude_issuer_profile_status
		.as_ref()
		.filter(|v| !v.is_empty())
		.map(|excluded| {
			excluded
				.iter()
				.map(|s| match s {
					ProfileStatus::Active => "A",
					ProfileStatus::Blocked => "B",
					ProfileStatus::Muted => "M",
					ProfileStatus::Suspended => "S",
					ProfileStatus::Banned => "X",
				})
				.collect()
		});
	if let Some(codes) = excluded_status_codes.as_ref() {
		// Reuses the `pi` LEFT JOIN above. NULL pi.status (missing profile or
		// stored-as-NULL Active) is NOT excluded — open-federation default.
		query.push(" AND (pi.status IS NULL OR pi.status NOT IN ");
		query = push_in(query, codes.as_slice());
		query.push(")");
	}
	if let Some(tag) = &opts.tag {
		query
			.push(" AND a.content LIKE ")
			.push_bind(format!("%#{}%", escape_like(tag)))
			.push(" ESCAPE '\\'");
	}
	if let Some(search) = &opts.search {
		query
			.push(" AND a.content LIKE ")
			.push_bind(format!("%{}%", escape_like(search)))
			.push(" ESCAPE '\\'");
	}
	if let Some(visibility) = &opts.visibility
		&& !visibility.is_empty()
	{
		query.push(" AND a.visibility IN ");
		query = push_in(query, visibility);
	}
	if let Some(action_id) = &opts.action_id {
		// Handle both @{a_id} placeholders and real action_ids
		if let Some(a_id_str) = action_id.strip_prefix('@') {
			// Query by a_id
			if let Ok(a_id) = a_id_str.parse::<i64>() {
				query.push(" AND a.a_id=").push_bind(a_id);
			} else {
				// Invalid a_id format - no results
				query.push(" AND 1=0");
			}
		} else {
			// Query by action_id
			query.push(" AND a.action_id=").push_bind(action_id);
		}
	}
	query
}

/// Append only the profile joins that the active filters in `opts` actually
/// reference, then ` WHERE a.tn_id=<bind>`. `pi` (issuer profile) is needed by
/// `exclude_issuer_profile_status`; `pa` (effective-audience profile) by
/// `audience_type`. Count paths that set neither skip both joins — SQLite does
/// NOT elide the unused LEFT JOINs here (verified via EXPLAIN QUERY PLAN: it
/// still does a covering-index SEARCH per row even when pi/pa are unreferenced),
/// so omitting them removes a per-row index probe. The emitted alias set must
/// stay a superset of what `push_action_filters` references for the same `opts`.
fn push_count_from_where(
	mut query: sqlx::QueryBuilder<sqlx::Sqlite>,
	tn_id: TnId,
	opts: &ListActionOptions,
) -> sqlx::QueryBuilder<sqlx::Sqlite> {
	if opts.exclude_issuer_profile_status.as_ref().is_some_and(|v| !v.is_empty()) {
		query.push(" LEFT JOIN profiles pi ON pi.tn_id=a.tn_id AND pi.id_tag=a.issuer_tag");
	}
	if opts.audience_type.is_some() {
		query.push(
			" LEFT JOIN profiles pa ON pa.tn_id=a.tn_id AND pa.id_tag=coalesce(a.audience, a.issuer_tag)",
		);
	}
	query.push(" WHERE a.tn_id=");
	query.push_bind(tn_id.0);
	query
}

/// Count actions matching `opts` (same filters as `list`), with NO limit/sort/
/// cursor. Generic and type-agnostic — callers supply the business filters.
pub(crate) async fn count(db: &SqlitePool, tn_id: TnId, opts: &ListActionOptions) -> ClResult<i64> {
	let mut query = sqlx::QueryBuilder::new("SELECT COUNT(DISTINCT a.a_id) FROM actions a");
	query = push_count_from_where(query, tn_id, opts);
	query = push_action_filters(query, opts);
	query
		.build_query_scalar::<i64>()
		.fetch_one(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)
}

/// Count actions matching `opts`, grouped by `group_by`. Returns
/// `(group_value, count)` pairs (group value NULL-able). Used to derive
/// per-reaction-type counts without baking reaction semantics into the adapter.
pub(crate) async fn count_grouped(
	db: &SqlitePool,
	tn_id: TnId,
	opts: &ListActionOptions,
	group_by: cloudillo_types::meta_adapter::ActionCountGroupBy,
) -> ClResult<Vec<(Option<String>, i64)>> {
	use cloudillo_types::meta_adapter::ActionCountGroupBy;
	// Fixed column mapping — never interpolate caller input (injection-safe).
	let col = match group_by {
		ActionCountGroupBy::SubType => "a.sub_type",
	};
	let mut query = sqlx::QueryBuilder::new(format!(
		"SELECT {col} AS grp, COUNT(DISTINCT a.a_id) AS cnt FROM actions a"
	));
	query = push_count_from_where(query, tn_id, opts);
	query = push_action_filters(query, opts);
	query.push(format!(" GROUP BY {col}"));
	let rows = query
		.build()
		.fetch_all(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;
	let mut out = Vec::with_capacity(rows.len());
	for r in &rows {
		let grp: Option<String> = r.try_get("grp").map_err(|_| Error::DbError)?;
		let cnt: i64 = r.try_get("cnt").map_err(|_| Error::DbError)?;
		out.push((grp, cnt));
	}
	Ok(out)
}

/// Fetch the viewer's active reposts of `subject_ids`, keyed by subject and then
/// by target audience: `{subject_action_id: {target: repost_action_id}}`.
///
/// Shared by `list()` (batched over many subjects) and `get()` (a single
/// subject) so the two read paths cannot drift on the `type='REPOST'` /
/// `status NOT IN ('D')` / issuer filter. Returns an empty map for an empty
/// input. Errors are logged via `inspect` and surfaced to the caller, which
/// decides whether to degrade gracefully.
async fn fetch_own_repost_ids(
	db: &SqlitePool,
	tn_id: TnId,
	subject_ids: &[&str],
	viewer: &str,
) -> ClResult<std::collections::HashMap<String, serde_json::Map<String, serde_json::Value>>> {
	use std::collections::HashMap;
	let mut map: HashMap<String, serde_json::Map<String, serde_json::Value>> = HashMap::new();
	if subject_ids.is_empty() {
		return Ok(map);
	}
	let mut q = sqlx::QueryBuilder::new(
		"SELECT subject, coalesce(audience, issuer_tag) as target, action_id
		FROM actions WHERE tn_id=",
	);
	q.push_bind(tn_id.0);
	q.push(" AND type='REPOST' AND coalesce(status,'A') NOT IN ('D') AND issuer_tag=");
	q.push_bind(viewer);
	q.push(" AND subject IN ");
	q = push_in(q, subject_ids);
	let rows = q.build().fetch_all(db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;
	for r in &rows {
		let subject: Option<String> = r.try_get("subject").ok().flatten();
		let target: Option<String> = r.try_get("target").ok().flatten();
		let aid: Option<String> = r.try_get("action_id").ok().flatten();
		if let (Some(subject), Some(target), Some(aid)) = (subject, target, aid) {
			map.entry(subject).or_default().insert(target, serde_json::Value::String(aid));
		}
	}
	Ok(map)
}

/// List actions with filtering options
pub(crate) async fn list(
	db: &SqlitePool,
	tn_id: TnId,
	opts: &ListActionOptions,
) -> ClResult<Vec<ActionView>> {
	let mut query = sqlx::QueryBuilder::new(
		"SELECT DISTINCT a.a_id, a.type, a.sub_type, a.action_id, a.parent_id, a.root_id, a.issuer_tag,
		pi.name as issuer_name, pi.profile_pic as issuer_profile_pic, pi.type as issuer_type,
		a.audience, pa.name as audience_name, pa.profile_pic as audience_profile_pic, pa.type as audience_type,
		a.subject, ps.id_tag as subject_id_tag, ps.name as subject_name, ps.profile_pic as subject_profile_pic, ps.type as subject_type,
		a.content, a.created_at, a.expires_at,
		own.sub_type as own_reaction,
		a.attachments, a.status, a.reactions, a.comments, a.comments_read, a.reposts, a.visibility, a.flags, a.x
		FROM actions a
		LEFT JOIN profiles pi ON pi.tn_id=a.tn_id AND pi.id_tag=a.issuer_tag
		LEFT JOIN profiles pa ON pa.tn_id=a.tn_id AND pa.id_tag=coalesce(a.audience, a.issuer_tag)
		LEFT JOIN profiles ps ON ps.tn_id=a.tn_id
			AND a.subject LIKE '@%'
			AND ps.id_tag = substr(a.subject, 2)
		LEFT JOIN actions own ON own.tn_id=a.tn_id AND own.subject=a.action_id AND own.issuer_tag=",
	);
	query.push_bind(opts.viewer_id_tag.as_deref());
	query.push(
		" AND own.type='REACT' AND own.sub_type!='DEL' AND coalesce(own.status, 'A') NOT IN ('D')
		WHERE a.tn_id=",
	);
	query.push_bind(tn_id.0);

	query = push_action_filters(query, opts);

	// Determine sort order (currently only created_at is supported)
	let _sort_field = opts.sort.as_deref().unwrap_or("created");
	let sort_dir = match opts.sort_dir.as_deref() {
		Some("asc") => "ASC",
		_ => "DESC", // Default DESC for actions
	};
	let is_desc = sort_dir == "DESC";

	// Parse cursor for keyset pagination
	if let Some(cursor_str) = &opts.cursor
		&& let Some(cursor) = cloudillo_types::types::CursorData::decode(cursor_str)
	{
		// Look up internal a_id from cursor's external action_id
		let cursor_a_id: Option<i64> =
			match sqlx::query_scalar("SELECT a_id FROM actions WHERE tn_id=? AND action_id=?")
				.bind(tn_id.0)
				.bind(&cursor.id)
				.fetch_optional(db)
				.await
			{
				Ok(v) => v,
				Err(e) => {
					warn!("cursor a_id lookup failed: {}", e);
					None
				}
			};

		if let Some(cursor_a_id) = cursor_a_id {
			// Keyset pagination: (created_at, a_id) < (cursor_ts, cursor_a_id) for DESC
			// Note: push_bind() adds bind placeholders, don't use ? in push() strings
			let comparison = if is_desc { "<" } else { ">" };
			if let Some(ts) = cursor.timestamp() {
				query.push(format!(" AND (a.created_at, a.a_id) {} (", comparison));
				query.push_bind(ts);
				query.push(", ");
				query.push_bind(cursor_a_id);
				query.push(")");
			}
		}
	}

	query.push(format!(" ORDER BY a.created_at {}, a.a_id {}", sort_dir, sort_dir));

	// Fetch limit+1 to determine hasMore
	// Note: SQLite doesn't allow bound parameters in LIMIT clause, so we use format!
	let limit = i64::from(opts.limit.unwrap_or(20));
	query.push(format!(" LIMIT {}", limit + 1));

	debug!("SQL: {}", query.sql().as_str());

	let res = query
		.build()
		.fetch_all(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	let mut actions = Vec::new();
	for row in res {
		// action_id might be NULL for pending actions - use @{a_id} placeholder
		let action_id: Box<str> = row
			.try_get::<Option<String>, _>("action_id")
			.map_err(|_| Error::DbError)?
			.map_or_else(
				|| {
					// NULL action_id - construct @{a_id} placeholder
					let a_id: i64 = row.try_get("a_id").unwrap_or(0);
					format!("@{}", a_id).into_boxed_str()
				},
				String::into_boxed_str,
			);

		let issuer_tag = row.try_get::<Box<str>, _>("issuer_tag").map_err(|_| Error::DbError)?;
		let audience_tag =
			row.try_get::<Option<Box<str>>, _>("audience").map_err(|_| Error::DbError)?;

		// collect attachments
		let attachments = row
			.try_get::<Option<Box<str>>, _>("attachments")
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;
		let attachments = if let Some(attachments) = &attachments {
			let mut attachments = parse_str_list(attachments)
				.iter()
				.map(|a| AttachmentView { file_id: a.clone(), dim: None, local_variants: None })
				.collect::<Vec<_>>();
			for a in &mut attachments {
				// Handle both @{f_id} placeholders and real file_ids
				let query_result = if let Some(f_id_str) = a.file_id.strip_prefix('@') {
					// Query by f_id
					if let Ok(f_id) = f_id_str.parse::<i64>() {
						sqlx::query("SELECT x->>'dim' as dim FROM files WHERE tn_id=? AND f_id=?")
							.bind(tn_id.0)
							.bind(f_id)
							.fetch_one(db)
							.await
					} else {
						Err(sqlx::Error::RowNotFound)
					}
				} else {
					// Query by file_id
					sqlx::query("SELECT x->>'dim' as dim FROM files WHERE tn_id=? AND file_id=?")
						.bind(tn_id.0)
						.bind(&a.file_id)
						.fetch_one(db)
						.await
				};

				if let Ok(file_res) = query_result.inspect_err(inspect)
					&& let Ok(Some(dim_str)) = file_res.try_get::<Option<&str>, _>("dim")
					&& !dim_str.is_empty()
				{
					a.dim = serde_json::from_str(dim_str)?;
				}

				// Query local variants
				let variants = if let Some(f_id_str) = a.file_id.strip_prefix('@') {
					// Query by f_id for placeholder IDs
					if let Ok(f_id) = f_id_str.parse::<i64>() {
						crate::file::list_available_variants_by_fid(db, tn_id, f_id).await.ok()
					} else {
						None
					}
				} else {
					// Query by file_id for real IDs
					crate::file::list_available_variants(db, tn_id, &a.file_id).await.ok()
				};
				if let Some(variants) = variants
					&& !variants.is_empty()
				{
					a.local_variants = Some(variants);
				}
				debug!("attachment: {:?}", a);
			}
			Some(attachments)
		} else {
			None
		};

		// stat - build from reactions and comments counts
		let reactions: Option<String> = row.try_get("reactions").ok().flatten();
		let comments_count: i64 = row.try_get("comments").unwrap_or(0);
		let comments_read: i64 = row.try_get("comments_read").unwrap_or(0);
		let own_reaction: Option<String> = row.try_get("own_reaction").ok().flatten();
		let reposts: i64 = row.try_get("reposts").unwrap_or(0);
		let mut stat_obj = serde_json::json!({
			"comments": comments_count,
			"commentsRead": comments_read
		});
		if let Some(reactions) = reactions {
			stat_obj["reactions"] = serde_json::Value::String(reactions);
		}
		if let Some(own_reaction) = own_reaction {
			stat_obj["ownReaction"] = serde_json::Value::String(own_reaction);
		}
		if reposts > 0 {
			stat_obj["reposts"] = serde_json::Value::from(reposts);
		}
		let stat = Some(stat_obj);
		let visibility: Option<String> = row.try_get("visibility").ok().flatten();
		let visibility = db_visibility_to_action(visibility);
		actions.push(ActionView {
			action_id,
			typ: row.try_get::<Box<str>, _>("type").map_err(|_| Error::DbError)?,
			sub_typ: row.try_get::<Option<Box<str>>, _>("sub_type").map_err(|_| Error::DbError)?,
			parent_id: row
				.try_get::<Option<Box<str>>, _>("parent_id")
				.map_err(|_| Error::DbError)?,
			root_id: row.try_get::<Option<Box<str>>, _>("root_id").map_err(|_| Error::DbError)?,
			issuer: ProfileInfo {
				id_tag: issuer_tag,
				name: row.try_get::<Box<str>, _>("issuer_name").map_err(|_| Error::DbError)?,
				typ: match row
					.try_get::<Option<&str>, _>("issuer_type")
					.map_err(|_| Error::DbError)?
				{
					Some("C") => ProfileType::Community,
					_ => ProfileType::Person,
				},
				profile_pic: row
					.try_get::<Option<Box<str>>, _>("issuer_profile_pic")
					.map_err(|_| Error::DbError)?,
			},
			audience: if let Some(audience_tag) = audience_tag {
				Some(ProfileInfo {
					id_tag: audience_tag,
					name: row
						.try_get::<Box<str>, _>("audience_name")
						.map_err(|_| Error::DbError)?,
					typ: match row
						.try_get::<Option<&str>, _>("audience_type")
						.map_err(|_| Error::DbError)?
					{
						Some("C") => ProfileType::Community,
						_ => ProfileType::Person,
					},
					profile_pic: row
						.try_get::<Option<Box<str>>, _>("audience_profile_pic")
						.map_err(|_| Error::DbError)?,
				})
			} else {
				None
			},
			subject: row.try_get("subject").map_err(|_| Error::DbError)?,
			subject_profile: match row
				.try_get::<Option<Box<str>>, _>("subject_id_tag")
				.map_err(|_| Error::DbError)?
			{
				Some(id_tag) => Some(ProfileInfo {
					id_tag,
					name: row
						.try_get::<Option<Box<str>>, _>("subject_name")
						.map_err(|_| Error::DbError)?
						.unwrap_or_else(|| "Unknown".into()),
					typ: match row
						.try_get::<Option<&str>, _>("subject_type")
						.map_err(|_| Error::DbError)?
					{
						Some("C") => ProfileType::Community,
						_ => ProfileType::Person,
					},
					profile_pic: row
						.try_get::<Option<Box<str>>, _>("subject_profile_pic")
						.map_err(|_| Error::DbError)?,
				}),
				None => None,
			},
			// Hydrated below for REPOST rows.
			subject_action: None,
			content: row
				.try_get::<Option<String>, _>("content")
				.map_err(|_| Error::DbError)?
				.and_then(|s| serde_json::from_str(&s).ok()),
			attachments,
			created_at: row.try_get("created_at").map(Timestamp).map_err(|_| Error::DbError)?,
			expires_at: row
				.try_get("expires_at")
				.map(|ts: Option<i64>| ts.map(Timestamp))
				.map_err(|_| Error::DbError)?,
			status: row.try_get("status").map_err(|_| Error::DbError)?,
			stat,
			visibility,
			flags: row.try_get("flags").map_err(|_| Error::DbError)?,
			x: row
				.try_get::<Option<String>, _>("x")
				.map_err(|_| Error::DbError)?
				.and_then(|s| serde_json::from_str(&s).ok()),
			token: None,
		});
	}

	// Opt-in: populate each action's raw signed JWS from action_tokens. Only
	// runs when the caller passes includeTokens=true (e.g. the engagement
	// dialog's signature-verification path), so normal feed lists stay lean.
	if opts.include_tokens == Some(true) && !actions.is_empty() {
		let ids: Vec<&str> = actions.iter().map(|a| a.action_id.as_ref()).collect();
		let mut q =
			sqlx::QueryBuilder::new("SELECT action_id, token FROM action_tokens WHERE tn_id=");
		q.push_bind(tn_id.0);
		q.push(" AND action_id IN ");
		q = push_in(q, &ids);
		drop(ids);
		match q.build().fetch_all(db).await {
			Ok(rows) => {
				use std::collections::HashMap;
				let mut map: HashMap<String, Box<str>> = HashMap::new();
				for r in &rows {
					let aid: Option<String> = r.try_get("action_id").ok().flatten();
					let token: Option<Box<str>> = r.try_get("token").ok().flatten();
					if let (Some(aid), Some(token)) = (aid, token) {
						map.insert(aid, token);
					}
				}
				for a in &mut actions {
					if let Some(token) = map.get(a.action_id.as_ref()) {
						a.token = Some(token.clone());
					}
				}
			}
			Err(e) => warn!("list: includeTokens fetch failed: {e}"),
		}
	}

	// Post-pass hydration for reposts.
	// 1. Embedded original action for REPOST rows, so the client renders the
	//    shared post without a second round-trip. The inner get() is called with
	//    hydrate_subject=false so the embedded subject never re-hydrates *its*
	//    subject — one level only, structurally, regardless of stored data.
	for action in &mut actions {
		if action.typ.as_ref() == "REPOST"
			&& let Some(subject_id) = action.subject.clone()
			&& !subject_id.starts_with('@')
			&& let Ok(Some(sub)) =
				get(db, tn_id, &subject_id, opts.viewer_id_tag.as_deref(), false).await
		{
			action.subject_action = Some(Box::new(sub));
		}
	}

	// 2. The viewer's own reposts of any listed action, keyed by target audience,
	//    merged into stat.ownRepostIds (drives ✓-badges and the undo affordance).
	if let Some(viewer) = opts.viewer_id_tag.as_deref()
		&& !actions.is_empty()
	{
		let ids: Vec<&str> = actions.iter().map(|a| a.action_id.as_ref()).collect();
		match fetch_own_repost_ids(db, tn_id, &ids, viewer).await {
			Ok(map) => {
				// `ids` borrows `actions` immutably; it is dropped here before the
				// mutable pass below.
				drop(ids);
				for a in &mut actions {
					if let Some(obj) = map.get(a.action_id.as_ref())
						&& !obj.is_empty() && let Some(stat) = a.stat.as_mut()
					{
						stat["ownRepostIds"] = serde_json::Value::Object(obj.clone());
					}
				}
			}
			Err(e) => warn!("list: ownRepostIds fetch failed: {e}"),
		}
	}

	Ok(actions)
}

/// List action tokens
pub(crate) async fn list_tokens(
	db: &SqlitePool,
	tn_id: TnId,
	opts: &ListActionOptions,
) -> ClResult<Box<[Box<str>]>> {
	let mut query = sqlx::QueryBuilder::new(
		"SELECT at.token FROM action_tokens at
		 JOIN actions a ON a.tn_id=at.tn_id AND a.action_id=at.action_id
		 WHERE at.tn_id=",
	);
	query.push_bind(tn_id.0);

	if let Some(status) = &opts.status {
		query.push(" AND coalesce(a.status, 'A') IN ");
		query = push_in(query, status);
	} else {
		// Same default as list_actions: hide 'D', 'V' (inbound verifying) and
		// 'F' (terminal failure) so peers polling the outbox never see
		// half-finished inbound actions.
		query.push(" AND coalesce(a.status, 'A') NOT IN ('D', 'V', 'F')");
	}

	if let Some(typ) = &opts.typ {
		query.push(" AND a.type IN ");
		query = push_in(query, typ.as_slice());
	}

	if let Some(action_id) = &opts.action_id {
		query.push(" AND a.action_id=").push_bind(action_id.as_str());
	}

	query.push(" ORDER BY a.created_at DESC LIMIT 100");

	let res = query
		.build()
		.fetch_all(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	let tokens = collect_res(res.iter().map(|row| row.try_get("token")))?;

	Ok(tokens.into_boxed_slice())
}

/// Create a new action (creates pending action with a_id, no action_id yet)
pub(crate) async fn create(
	db: &SqlitePool,
	tn_id: TnId,
	action: &Action<&str>,
	key: Option<&str>,
) -> ClResult<ActionId<Box<str>>> {
	// If action already has action_id (inbound federation), check if it exists
	if !action.action_id.is_empty() {
		let action_id_exists =
			sqlx::query("SELECT action_id FROM actions WHERE tn_id=? AND action_id=?")
				.bind(tn_id.0)
				.bind(action.action_id)
				.fetch_optional(db)
				.await
				.inspect_err(inspect)
				.map_err(|_| Error::DbError)?
				.and_then(|row| row.get(0));

		if let Some(action_id) = action_id_exists {
			return Ok(ActionId::ActionId(action_id));
		}
	}

	// For inbound actions with a key, delete old actions with the same key first
	// This handles key-based deduplication for inbound actions (outbound actions
	// handle this in finalize())
	if !action.action_id.is_empty()
		&& let Some(key) = key
	{
		info!("Inbound action with key: {}, deleting old entries", key);
		sqlx::query(
			"UPDATE actions SET status='D' WHERE tn_id=? AND key=? AND coalesce(status, 'A')!='D'",
		)
		.bind(tn_id.0)
		.bind(key)
		.execute(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;
	}

	let status = "P";
	// Storage uses 'D' for Direct uniformly; ActionView still maps 'D' → None at
	// the read-side boundary, keeping the wire/token format unchanged.
	// Never write NULL here — migration 25 (schema.rs) backfilled NULLs to 'D'
	// and the fresh-DB schema declares the column NOT NULL DEFAULT 'D'.
	let visibility = action.visibility.unwrap_or('D').to_string();
	let x_json = action.x.as_ref().and_then(|v| serde_json::to_string(v).ok());
	let res = sqlx::query(
		"INSERT INTO actions (tn_id, action_id, key, type, sub_type, parent_id, root_id, issuer_tag, audience, subject, content, created_at, expires_at, attachments, status, visibility, flags, x)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING a_id"
	)
		.bind(tn_id.0)
		.bind(if action.action_id.is_empty() { None } else { Some(action.action_id) })
		.bind(key)
		.bind(action.typ)
		.bind(action.sub_typ)
		.bind(action.parent_id)
		.bind(action.root_id)
		.bind(action.issuer_tag)
		.bind(action.audience_tag)
		.bind(action.subject)
		.bind(action.content)
		.bind(action.created_at.0)
		.bind(action.expires_at.map(|t| t.0))
		.bind(action.attachments.as_ref().map(|s| s.join(",")))
		.bind(status)
		.bind(visibility)
		.bind(action.flags)
		.bind(x_json)
		.fetch_one(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	Ok(ActionId::AId(res.get(0)))
}

/// Finalize action - atomically set action_id, update attachments/subject/audience/key, and transition from 'P' to 'A' status
pub(crate) async fn finalize(
	db: &SqlitePool,
	tn_id: TnId,
	a_id: u64,
	action_id: &str,
	options: FinalizeActionOptions<'_>,
) -> ClResult<()> {
	// First check if action exists and what its current action_id is
	let existing = sqlx::query("SELECT action_id, status FROM actions WHERE tn_id=? AND a_id=?")
		.bind(tn_id.0)
		.bind(a_id.cast_signed())
		.fetch_optional(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	match existing {
		None => {
			// Action doesn't exist at all
			return Err(Error::NotFound);
		}
		Some(row) => {
			let existing_action_id: Option<String> = row.try_get("action_id").ok().flatten();
			let status: Option<String> = row.try_get("status").ok().flatten();

			if let Some(existing_id) = existing_action_id {
				// Already has an action_id - check if it matches
				if existing_id == action_id {
					// Idempotent success - already set to the correct value
					return Ok(());
				}
				// Different action_id - this is a conflict
				let msg = format!(
					"Attempted to finalize a_id={} to action_id={} but already set to {}",
					a_id, action_id, existing_id
				);
				error!("{}", msg);
				return Err(Error::Conflict(msg));
			}

			// action_id is NULL - verify status is 'P'
			if status.as_deref() != Some("P") {
				let msg = format!(
					"Attempted to finalize a_id={} but status is {:?}, expected 'P'",
					a_id, status
				);
				error!("{}", msg);
				return Err(Error::Conflict(msg));
			}
		}
	}

	// Update NULL action_id to new value, update attachments/subject/audience/key, and transition status from 'P' to 'A'
	let mut tx = db.begin().await.map_err(|_| Error::DbError)?;

	let attachments_str = options.attachments.map(|a| a.join(","));
	let res = sqlx::query(
		"UPDATE actions SET action_id=?, attachments=?, subject=COALESCE(?, subject), audience=COALESCE(?, audience), key=COALESCE(?, key), status='A' WHERE tn_id=? AND a_id=? AND action_id IS NULL AND status='P'"
	)
		.bind(action_id)
		.bind(attachments_str)
		.bind(options.subject)
		.bind(options.audience_tag)
		.bind(options.key)
		.bind(tn_id.0)
		.bind(a_id.cast_signed())
		.execute(&mut *tx)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	if res.rows_affected() == 0 {
		// Race condition - someone else just set it between our check and update.
		// Re-check what value was set (idempotent verification)
		let current = sqlx::query("SELECT action_id FROM actions WHERE tn_id=? AND a_id=?")
			.bind(tn_id.0)
			.bind(a_id.cast_signed())
			.fetch_optional(&mut *tx)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		tx.rollback().await.map_err(|_| Error::DbError)?;

		if let Some(row) = current
			&& let Some(existing_id) = row.try_get::<Option<String>, _>("action_id").ok().flatten()
		{
			if existing_id == action_id {
				// Idempotent success - another task set it to the same value
				return Ok(());
			}
			// Conflict - set to different value
			let msg = format!(
				"Race condition: a_id={} was set to {} instead of {}",
				a_id, existing_id, action_id
			);
			error!("{}", msg);
			return Err(Error::Conflict(msg));
		}

		return Err(Error::Internal("Failed to finalize action".into()));
	}

	// Handle key-based deduplication for finalized actions
	let action = sqlx::query("SELECT key FROM actions WHERE tn_id=? AND a_id=?")
		.bind(tn_id.0)
		.bind(a_id.cast_signed())
		.fetch_one(&mut *tx)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	let key: Option<String> = action.try_get("key").ok().flatten();

	if let Some(key) = &key {
		info!("Finalizing with key: {}", key);
		// Delete old entries with the same key (key-based deduplication)
		sqlx::query(
			"UPDATE actions SET status='D' WHERE tn_id=? AND key=? AND a_id!=? AND coalesce(status, 'A')!='D'",
		)
		.bind(tn_id.0)
		.bind(key)
		.bind(a_id.cast_signed())
		.execute(&mut *tx)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;
	}

	tx.commit().await.inspect_err(inspect).map_err(|_| Error::DbError)?;
	Ok(())
}

/// Get action_id from a_id
pub(crate) async fn get_id(db: &SqlitePool, tn_id: TnId, a_id: u64) -> ClResult<Box<str>> {
	let res = sqlx::query("SELECT action_id FROM actions WHERE tn_id=? AND a_id=?")
		.bind(tn_id.0)
		.bind(a_id.cast_signed())
		.fetch_one(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::NotFound)?;

	let action_id: String = res.try_get("action_id").map_err(|_| Error::NotFound)?;
	Ok(action_id.into_boxed_str())
}

/// Create an inbound action
pub(crate) async fn create_inbound(
	db: &SqlitePool,
	tn_id: TnId,
	action_id: &str,
	token: &str,
	ack_token: Option<&str>,
) -> ClResult<()> {
	sqlx::query(
		"INSERT OR IGNORE INTO action_tokens (tn_id, action_id, token, status, ack)
		VALUES (?, ?, ?, ?, ?)",
	)
	.bind(tn_id.0)
	.bind(action_id)
	.bind(token)
	.bind("P")
	.bind(ack_token)
	.execute(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;
	Ok(())
}

/// Get related action tokens by APRV action_id
/// Returns (action_id, token) pairs for actions that have ack = aprv_action_id
pub(crate) async fn get_related_tokens(
	db: &SqlitePool,
	tn_id: TnId,
	aprv_action_id: &str,
) -> ClResult<Vec<(Box<str>, Box<str>)>> {
	let rows =
		sqlx::query("SELECT action_id, token FROM action_tokens WHERE tn_id = ? AND ack = ?")
			.bind(tn_id.0)
			.bind(aprv_action_id)
			.fetch_all(db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

	let mut result = Vec::with_capacity(rows.len());
	for row in rows {
		let action_id: String = row.try_get("action_id").map_err(|_| Error::DbError)?;
		let token: String = row.try_get("token").map_err(|_| Error::DbError)?;
		result.push((action_id.into_boxed_str(), token.into_boxed_str()));
	}

	Ok(result)
}

/// Get action root ID
pub(crate) async fn get_root_id(
	db: &SqlitePool,
	tn_id: TnId,
	action_id: &str,
) -> ClResult<Box<str>> {
	let res = sqlx::query("SELECT root_id FROM actions WHERE tn_id=? AND action_id=?")
		.bind(tn_id.0)
		.bind(action_id)
		.fetch_one(db)
		.await;

	map_res(res, |row| row.try_get("root_id"))
}

/// Get action data
pub(crate) async fn get_data(
	db: &SqlitePool,
	tn_id: TnId,
	action_id: &str,
) -> ClResult<Option<ActionData>> {
	let res = sqlx::query(
		"SELECT subject, reactions, comments, stat_at FROM actions WHERE tn_id=? AND action_id=?",
	)
	.bind(tn_id.0)
	.bind(action_id)
	.fetch_optional(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

	match res {
		Some(row) => Ok(Some(ActionData {
			subject: row.try_get("subject").ok().flatten(),
			reactions: row.try_get::<Option<String>, _>("reactions").ok().flatten().map(Into::into),
			comments: row.try_get("comments").ok().flatten(),
			stat_at: row.try_get::<Option<i64>, _>("stat_at").ok().flatten().map(Timestamp),
		})),
		None => Ok(None),
	}
}

/// Get action by key
pub(crate) async fn get_by_key(
	db: &SqlitePool,
	tn_id: TnId,
	action_key: &str,
) -> ClResult<Option<Action<Box<str>>>> {
	let res = sqlx::query("SELECT action_id, type, sub_type, issuer_tag, parent_id, root_id, audience, content, attachments, subject, created_at, expires_at, visibility, flags, x
		FROM actions WHERE tn_id=? AND key=? AND coalesce(status, 'A')!='D'
		ORDER BY a_id DESC LIMIT 1")
		.bind(tn_id.0)
		.bind(action_key)
		.fetch_optional(db).await;

	match res {
		Ok(Some(row)) => {
			let attachments_str: Option<Box<str>> = row.try_get("attachments").ok().flatten();
			let attachments = attachments_str.map(|s| parse_str_list(&s).to_vec());
			let visibility: Option<String> = row.try_get("visibility").ok().flatten();
			let visibility = db_visibility_to_action(visibility);

			Ok(Some(Action {
				action_id: row.try_get("action_id").map_err(|_| Error::DbError)?,
				typ: row.try_get("type").map_err(|_| Error::DbError)?,
				sub_typ: row.try_get("sub_type").ok().flatten(),
				issuer_tag: row.try_get("issuer_tag").map_err(|_| Error::DbError)?,
				parent_id: row.try_get("parent_id").ok().flatten(),
				root_id: row.try_get("root_id").ok().flatten(),
				audience_tag: row.try_get("audience").ok().flatten(),
				content: row.try_get("content").ok().flatten(),
				attachments,
				subject: row.try_get("subject").ok().flatten(),
				created_at: row.try_get("created_at").map(Timestamp).map_err(|_| Error::DbError)?,
				expires_at: row
					.try_get("expires_at")
					.ok()
					.and_then(|v: Option<i64>| v.map(Timestamp)),
				visibility,
				flags: row.try_get("flags").ok().flatten(),
				x: row
					.try_get::<Option<String>, _>("x")
					.ok()
					.flatten()
					.and_then(|s| serde_json::from_str(&s).ok()),
			}))
		}
		Ok(None) => Ok(None),
		Err(_) => Err(Error::DbError),
	}
}

/// Store action token
pub(crate) async fn store_token(
	db: &SqlitePool,
	tn_id: TnId,
	action_id: &str,
	token: &str,
) -> ClResult<()> {
	sqlx::query(
		"INSERT OR REPLACE INTO action_tokens (tn_id, action_id, token, status)
		VALUES (?, ?, ?, 'L')",
	)
	.bind(tn_id.0)
	.bind(action_id)
	.bind(token)
	.execute(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

	Ok(())
}

/// Get action token
pub(crate) async fn get_token(
	db: &SqlitePool,
	tn_id: TnId,
	action_id: &str,
) -> ClResult<Option<Box<str>>> {
	let res = sqlx::query("SELECT token FROM action_tokens WHERE tn_id=? AND action_id=?")
		.bind(tn_id.0)
		.bind(action_id)
		.fetch_optional(db)
		.await;

	match res {
		Ok(Some(row)) => Ok(Some(row.try_get("token").map_err(|_| Error::DbError)?)),
		Ok(None) => Ok(None),
		Err(_) => Err(Error::DbError),
	}
}

/// Update action data
pub(crate) async fn update_data(
	db: &SqlitePool,
	tn_id: TnId,
	action_id: &str,
	opts: &UpdateActionDataOptions,
) -> ClResult<()> {
	// Build dynamic UPDATE query based on which fields are set
	let mut set_clauses = Vec::new();

	if !opts.subject.is_undefined() {
		set_clauses.push("subject = ?");
	}
	if !opts.reactions.is_undefined() {
		set_clauses.push("reactions = ?");
	}
	if !opts.comments.is_undefined() {
		set_clauses.push("comments = ?");
	}
	if !opts.comments_read.is_undefined() {
		set_clauses.push("comments_read = ?");
	}
	if !opts.reposts.is_undefined() {
		set_clauses.push("reposts = ?");
	}
	if !opts.status.is_undefined() {
		set_clauses.push("status = ?");
	}
	if !opts.visibility.is_undefined() {
		set_clauses.push("visibility = ?");
	}
	if !opts.x.is_undefined() {
		set_clauses.push("x = ?");
	}
	if !opts.content.is_undefined() {
		set_clauses.push("content = ?");
	}
	if !opts.attachments.is_undefined() {
		set_clauses.push("attachments = ?");
	}
	if !opts.flags.is_undefined() {
		set_clauses.push("flags = ?");
	}
	if !opts.sub_typ.is_undefined() {
		set_clauses.push("sub_type = ?");
	}
	if !opts.created_at.is_undefined() {
		set_clauses.push("created_at = ?");
	}
	if !opts.stat_at.is_undefined() {
		set_clauses.push("stat_at = ?");
	}

	if set_clauses.is_empty() {
		return Ok(()); // Nothing to update
	}

	// Support both action_id and @{a_id} format
	let where_clause = if action_id.starts_with('@') {
		"WHERE tn_id = ? AND a_id = ?"
	} else {
		"WHERE tn_id = ? AND action_id = ?"
	};
	let sql = format!("UPDATE actions SET {} {}", set_clauses.join(", "), where_clause);

	let mut query = sqlx::query(sqlx::AssertSqlSafe(sql));

	// Bind values in the same order as set_clauses
	if !opts.subject.is_undefined() {
		let val: Option<&str> = match &opts.subject {
			Patch::Null => None,
			Patch::Value(v) => Some(v.as_str()),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}
	if !opts.reactions.is_undefined() {
		let val: Option<&str> = match &opts.reactions {
			Patch::Null => None,
			Patch::Value(v) => {
				if v.is_empty() {
					None
				} else {
					Some(v.as_str())
				}
			}
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}
	if !opts.comments.is_undefined() {
		let val: Option<u32> = match &opts.comments {
			Patch::Null => None,
			Patch::Value(v) => Some(*v),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}
	if !opts.comments_read.is_undefined() {
		let val: Option<u32> = match &opts.comments_read {
			Patch::Null => None,
			Patch::Value(v) => Some(*v),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}
	if !opts.reposts.is_undefined() {
		let val: Option<u32> = match &opts.reposts {
			Patch::Null => None,
			Patch::Value(v) => Some(*v),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}
	if !opts.status.is_undefined() {
		let val: Option<String> = match &opts.status {
			Patch::Null => None,
			Patch::Value(c) => Some(c.to_string()),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}
	if !opts.visibility.is_undefined() {
		// 'D' (Direct) is the storage representation of None on the wire/Patch::Null.
		let val: String = match &opts.visibility {
			Patch::Null => "D".to_string(),
			Patch::Value(c) => c.to_string(),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}
	if !opts.x.is_undefined() {
		let val: Option<String> = match &opts.x {
			Patch::Null => None,
			Patch::Value(v) => serde_json::to_string(v).ok(),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}
	if !opts.content.is_undefined() {
		let val: Option<&str> = match &opts.content {
			Patch::Null => None,
			Patch::Value(v) => Some(v.as_str()),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}
	if !opts.attachments.is_undefined() {
		let val: Option<&str> = match &opts.attachments {
			Patch::Null => None,
			Patch::Value(v) => Some(v.as_str()),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}
	if !opts.flags.is_undefined() {
		let val: Option<&str> = match &opts.flags {
			Patch::Null => None,
			Patch::Value(v) => Some(v.as_str()),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}
	if !opts.sub_typ.is_undefined() {
		let val: Option<&str> = match &opts.sub_typ {
			Patch::Null => None,
			Patch::Value(v) => Some(v.as_str()),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}
	if !opts.created_at.is_undefined() {
		let val: Option<i64> = match &opts.created_at {
			Patch::Null => None,
			Patch::Value(ts) => Some(ts.0),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}
	if !opts.stat_at.is_undefined() {
		let val: Option<i64> = match &opts.stat_at {
			Patch::Null => None,
			Patch::Value(ts) => Some(ts.0),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}

	// Bind WHERE clause params
	query = query.bind(tn_id.0);
	if let Some(a_id_str) = action_id.strip_prefix('@') {
		let a_id: i64 = a_id_str.parse().map_err(|_| Error::NotFound)?;
		query = query.bind(a_id);
	} else {
		query = query.bind(action_id);
	}

	let res = query.execute(db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

	if res.rows_affected() == 0 {
		return Err(Error::NotFound);
	}

	Ok(())
}

/// Update inbound action status
pub(crate) async fn update_inbound(
	db: &SqlitePool,
	tn_id: TnId,
	action_id: &str,
	status: Option<char>,
) -> ClResult<()> {
	let status_str = status.map(|c| c.to_string());
	let res = sqlx::query("UPDATE action_tokens SET status=? WHERE tn_id=? AND action_id=?")
		.bind(status_str.as_deref())
		.bind(tn_id.0)
		.bind(action_id)
		.execute(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	if res.rows_affected() == 0 {
		return Err(Error::NotFound);
	}

	Ok(())
}

/// Get a single action by action_id with issuer and audience profiles.
///
/// `hydrate_subject` controls whether a REPOST row embeds its referenced
/// `subject_action`. Top-level callers pass `true` for a single embedded level;
/// the internal recursive call passes `false`, capping hydration at exactly one
/// level. This bound is structural — it does NOT rely on create-time
/// canonicalization, so a non-conformant federated repost-of-a-repost (or even
/// a cyclic A→B→A pair) can never drive unbounded recursion / stack overflow.
pub(crate) async fn get(
	db: &SqlitePool,
	tn_id: TnId,
	action_id: &str,
	viewer_id_tag: Option<&str>,
	hydrate_subject: bool,
) -> ClResult<Option<ActionView>> {
	// Handle @{a_id} format for drafts/pending actions
	let row = if let Some(a_id_str) = action_id.strip_prefix('@') {
		let a_id: i64 = a_id_str.parse().map_err(|_| Error::NotFound)?;
		sqlx::query(
			"SELECT a.a_id, a.type, a.sub_type, a.action_id, a.parent_id, a.root_id, a.issuer_tag,
			pi.name as issuer_name, pi.profile_pic as issuer_profile_pic, pi.type as issuer_type,
			a.audience, pa.name as audience_name, pa.profile_pic as audience_profile_pic, pa.type as audience_type,
			a.subject, ps.id_tag as subject_id_tag, ps.name as subject_name, ps.profile_pic as subject_profile_pic, ps.type as subject_type,
			a.content, a.created_at, a.expires_at,
			a.attachments, a.status, a.reactions, a.comments, a.comments_read, a.reposts, a.visibility, a.flags, a.x
			FROM actions a
			LEFT JOIN profiles pi ON pi.tn_id=a.tn_id AND pi.id_tag=a.issuer_tag
			LEFT JOIN profiles pa ON pa.tn_id=a.tn_id AND pa.id_tag=coalesce(a.audience, a.issuer_tag)
			LEFT JOIN profiles ps ON ps.tn_id=a.tn_id
				AND a.subject LIKE '@%'
				AND ps.id_tag = substr(a.subject, 2)
			WHERE a.tn_id=? AND a.a_id=? AND coalesce(a.status, 'A') NOT IN ('D')",
		)
		.bind(tn_id.0)
		.bind(a_id)
		.fetch_optional(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?
	} else {
		sqlx::query(
			"SELECT a.a_id, a.type, a.sub_type, a.action_id, a.parent_id, a.root_id, a.issuer_tag,
			pi.name as issuer_name, pi.profile_pic as issuer_profile_pic, pi.type as issuer_type,
			a.audience, pa.name as audience_name, pa.profile_pic as audience_profile_pic, pa.type as audience_type,
			a.subject, ps.id_tag as subject_id_tag, ps.name as subject_name, ps.profile_pic as subject_profile_pic, ps.type as subject_type,
			a.content, a.created_at, a.expires_at,
			a.attachments, a.status, a.reactions, a.comments, a.comments_read, a.reposts, a.visibility, a.flags, a.x
			FROM actions a
			LEFT JOIN profiles pi ON pi.tn_id=a.tn_id AND pi.id_tag=a.issuer_tag
			LEFT JOIN profiles pa ON pa.tn_id=a.tn_id AND pa.id_tag=coalesce(a.audience, a.issuer_tag)
			LEFT JOIN profiles ps ON ps.tn_id=a.tn_id
				AND a.subject LIKE '@%'
				AND ps.id_tag = substr(a.subject, 2)
			WHERE a.tn_id=? AND a.action_id=? AND coalesce(a.status, 'A') NOT IN ('D')",
		)
		.bind(tn_id.0)
		.bind(action_id)
		.fetch_optional(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?
	};

	let Some(row) = row else {
		return Ok(None);
	};

	let issuer_tag = row.try_get::<Box<str>, _>("issuer_tag").map_err(|_| Error::DbError)?;
	let audience_tag =
		row.try_get::<Option<Box<str>>, _>("audience").map_err(|_| Error::DbError)?;

	// Parse attachments
	let attachments = row
		.try_get::<Option<Box<str>>, _>("attachments")
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;
	let attachments = if let Some(attachments) = &attachments {
		let mut attachments = parse_str_list(attachments)
			.iter()
			.map(|a| AttachmentView { file_id: a.clone(), dim: None, local_variants: None })
			.collect::<Vec<_>>();
		for a in &mut attachments {
			// Query file dimensions
			let query_result = if let Some(f_id_str) = a.file_id.strip_prefix('@') {
				if let Ok(f_id) = f_id_str.parse::<i64>() {
					sqlx::query("SELECT x->>'dim' as dim FROM files WHERE tn_id=? AND f_id=?")
						.bind(tn_id.0)
						.bind(f_id)
						.fetch_one(db)
						.await
				} else {
					Err(sqlx::Error::RowNotFound)
				}
			} else {
				sqlx::query("SELECT x->>'dim' as dim FROM files WHERE tn_id=? AND file_id=?")
					.bind(tn_id.0)
					.bind(&a.file_id)
					.fetch_one(db)
					.await
			};

			if let Ok(file_res) = query_result.inspect_err(inspect)
				&& let Ok(Some(dim_str)) = file_res.try_get::<Option<&str>, _>("dim")
				&& !dim_str.is_empty()
			{
				a.dim = serde_json::from_str(dim_str)?;
			}

			// Query local variants
			let variants = if let Some(f_id_str) = a.file_id.strip_prefix('@') {
				// Query by f_id for placeholder IDs
				if let Ok(f_id) = f_id_str.parse::<i64>() {
					crate::file::list_available_variants_by_fid(db, tn_id, f_id).await.ok()
				} else {
					None
				}
			} else {
				// Query by file_id for real IDs
				crate::file::list_available_variants(db, tn_id, &a.file_id).await.ok()
			};
			if let Some(variants) = variants
				&& !variants.is_empty()
			{
				a.local_variants = Some(variants);
			}
		}
		Some(attachments)
	} else {
		None
	};

	// Build stat from reactions and comments counts
	let reactions: Option<String> = row.try_get("reactions").ok().flatten();
	let comments_count: i64 = row.try_get("comments").unwrap_or(0);
	let comments_read: i64 = row.try_get("comments_read").unwrap_or(0);
	let reposts: i64 = row.try_get("reposts").unwrap_or(0);
	let mut stat_obj = serde_json::json!({
		"comments": comments_count,
		"commentsRead": comments_read
	});
	if let Some(reactions) = reactions {
		stat_obj["reactions"] = serde_json::Value::String(reactions);
	}
	if reposts > 0 {
		stat_obj["reposts"] = serde_json::Value::from(reposts);
	}
	// Per-user stat, only when a viewer is supplied. Mirrors the list path's
	// own_reaction (lines 341-360) and ownRepostIds (lines 468-505) so an
	// embedded subject_action carries the viewer's reaction/repost state.
	if let Some(viewer) = viewer_id_tag {
		let own_reaction: Option<String> = sqlx::query_scalar(
			"SELECT sub_type FROM actions
			WHERE tn_id=? AND subject=? AND issuer_tag=? AND type='REACT'
				AND sub_type!='DEL' AND coalesce(status, 'A') NOT IN ('D') LIMIT 1",
		)
		.bind(tn_id.0)
		.bind(action_id)
		.bind(viewer)
		.fetch_optional(db)
		.await
		.ok()
		.flatten();
		if let Some(own_reaction) = own_reaction {
			stat_obj["ownReaction"] = serde_json::Value::String(own_reaction);
		}
		// Viewer's active reposts of this action, keyed by target audience.
		// Shares fetch_own_repost_ids with list() so the filter can't drift.
		let own_reposts =
			fetch_own_repost_ids(db, tn_id, &[action_id], viewer).await.unwrap_or_default();
		if let Some(map) = own_reposts.get(action_id)
			&& !map.is_empty()
		{
			stat_obj["ownRepostIds"] = serde_json::Value::Object(map.clone());
		}
	}
	let stat = Some(stat_obj);

	let visibility: Option<String> = row.try_get("visibility").ok().flatten();
	let visibility = db_visibility_to_action(visibility);

	// action_id might be NULL for draft/pending actions - use @{a_id} placeholder
	let result_action_id: Box<str> = row
		.try_get::<Option<String>, _>("action_id")
		.map_err(|_| Error::DbError)?
		.map_or_else(
			|| {
				let a_id: i64 = row.try_get("a_id").unwrap_or(0);
				format!("@{}", a_id).into_boxed_str()
			},
			String::into_boxed_str,
		);

	let mut action = ActionView {
		action_id: result_action_id,
		typ: row.try_get::<Box<str>, _>("type").map_err(|_| Error::DbError)?,
		sub_typ: row.try_get::<Option<Box<str>>, _>("sub_type").map_err(|_| Error::DbError)?,
		parent_id: row.try_get::<Option<Box<str>>, _>("parent_id").map_err(|_| Error::DbError)?,
		root_id: row.try_get::<Option<Box<str>>, _>("root_id").map_err(|_| Error::DbError)?,
		issuer: ProfileInfo {
			id_tag: issuer_tag,
			name: row
				.try_get::<Option<Box<str>>, _>("issuer_name")
				.map_err(|_| Error::DbError)?
				.unwrap_or_else(|| "Unknown".into()),
			typ: match row.try_get::<Option<&str>, _>("issuer_type").map_err(|_| Error::DbError)? {
				Some("C") => ProfileType::Community,
				_ => ProfileType::Person,
			},
			profile_pic: row
				.try_get::<Option<Box<str>>, _>("issuer_profile_pic")
				.map_err(|_| Error::DbError)?,
		},
		audience: if let Some(audience_tag) = audience_tag {
			Some(ProfileInfo {
				id_tag: audience_tag,
				name: row
					.try_get::<Option<Box<str>>, _>("audience_name")
					.map_err(|_| Error::DbError)?
					.unwrap_or_else(|| "Unknown".into()),
				typ: match row
					.try_get::<Option<&str>, _>("audience_type")
					.map_err(|_| Error::DbError)?
				{
					Some("C") => ProfileType::Community,
					_ => ProfileType::Person,
				},
				profile_pic: row
					.try_get::<Option<Box<str>>, _>("audience_profile_pic")
					.map_err(|_| Error::DbError)?,
			})
		} else {
			None
		},
		subject: row.try_get("subject").map_err(|_| Error::DbError)?,
		subject_profile: match row
			.try_get::<Option<Box<str>>, _>("subject_id_tag")
			.map_err(|_| Error::DbError)?
		{
			Some(id_tag) => Some(ProfileInfo {
				id_tag,
				name: row
					.try_get::<Option<Box<str>>, _>("subject_name")
					.map_err(|_| Error::DbError)?
					.unwrap_or_else(|| "Unknown".into()),
				typ: match row
					.try_get::<Option<&str>, _>("subject_type")
					.map_err(|_| Error::DbError)?
				{
					Some("C") => ProfileType::Community,
					_ => ProfileType::Person,
				},
				profile_pic: row
					.try_get::<Option<Box<str>>, _>("subject_profile_pic")
					.map_err(|_| Error::DbError)?,
			}),
			None => None,
		},
		// Hydrated below for REPOST rows (see post-construction embed).
		subject_action: None,
		content: row
			.try_get::<Option<String>, _>("content")
			.map_err(|_| Error::DbError)?
			.and_then(|s| serde_json::from_str(&s).ok()),
		attachments,
		created_at: row.try_get("created_at").map(Timestamp).map_err(|_| Error::DbError)?,
		expires_at: row
			.try_get("expires_at")
			.map(|ts: Option<i64>| ts.map(Timestamp))
			.map_err(|_| Error::DbError)?,
		status: row.try_get("status").map_err(|_| Error::DbError)?,
		stat,
		visibility,
		flags: row.try_get("flags").map_err(|_| Error::DbError)?,
		x: row
			.try_get::<Option<String>, _>("x")
			.map_err(|_| Error::DbError)?
			.and_then(|s| serde_json::from_str(&s).ok()),
		token: None,
	};

	// Embed the shared original for REPOST rows so a single-action fetch (e.g. a
	// repost permalink) renders without a second round trip — mirrors list().
	// The inner call passes hydrate_subject=false, so the embedded subject never
	// re-hydrates *its* subject: hydration is capped at one level structurally,
	// independent of whether the stored data was canonicalized.
	if hydrate_subject
		&& action.typ.as_ref() == "REPOST"
		&& let Some(subject_id) = action.subject.clone()
		&& !subject_id.starts_with('@')
		&& let Ok(Some(sub)) = Box::pin(get(db, tn_id, &subject_id, viewer_id_tag, false)).await
	{
		action.subject_action = Some(Box::new(sub));
	}

	Ok(Some(action))
}

/// Update action content and attachments (drafts only, status='R')
pub(crate) async fn update(
	db: &SqlitePool,
	tn_id: TnId,
	action_id: &str,
	content: Option<&str>,
	attachments: Option<&[&str]>,
) -> ClResult<()> {
	// Only allow updates to draft actions (status='R'), identified by @{a_id}
	let Some(a_id_str) = action_id.strip_prefix('@') else {
		return Err(Error::ValidationError("Only draft actions (@{a_id}) can be updated".into()));
	};
	let a_id: i64 = a_id_str.parse().map_err(|_| Error::NotFound)?;

	let mut set_clauses = Vec::new();
	if content.is_some() {
		set_clauses.push("content=?");
	}
	if attachments.is_some() {
		set_clauses.push("attachments=?");
	}
	if set_clauses.is_empty() {
		return Ok(());
	}

	let sql = format!(
		"UPDATE actions SET {} WHERE tn_id=? AND a_id=? AND status='R'",
		set_clauses.join(", ")
	);
	let mut query = sqlx::query(sqlx::AssertSqlSafe(sql));
	if let Some(content) = content {
		query = query.bind(content);
	}
	if let Some(attachments) = attachments {
		query = query.bind(attachments.join(","));
	}
	query = query.bind(tn_id.0).bind(a_id);

	let res = query.execute(db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

	if res.rows_affected() == 0 {
		return Err(Error::NotFound);
	}

	Ok(())
}

/// Delete action (soft delete for published, hard delete for drafts)
pub(crate) async fn delete(db: &SqlitePool, tn_id: TnId, action_id: &str) -> ClResult<()> {
	if let Some(a_id_str) = action_id.strip_prefix('@') {
		// Draft action: hard delete by a_id, only if status='R'
		let a_id: i64 = a_id_str.parse().map_err(|_| Error::NotFound)?;
		sqlx::query("DELETE FROM actions WHERE tn_id=? AND a_id=? AND status='R'")
			.bind(tn_id.0)
			.bind(a_id)
			.execute(db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;
	} else {
		// Published action: soft delete by marking status as 'D'
		sqlx::query("UPDATE actions SET status = 'D' WHERE tn_id = ? AND action_id = ?")
			.bind(tn_id.0)
			.bind(action_id)
			.execute(db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use cloudillo_types::meta_adapter::ActionCountGroupBy;
	use sqlx::sqlite;

	// Single-connection write pool over a temp DB file, mirroring
	// `MetaAdapterSqlite::new` (WAL, one write connection). Same pattern as the
	// file.rs test harness.
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

	// Insert one finalized (status 'A') action row directly. Bypasses create()
	// so tests can mint many distinct rows for one subject without the
	// pending→finalize dance.
	async fn insert_action(
		db: &SqlitePool,
		tn_id: TnId,
		action_id: &str,
		typ: &str,
		sub_type: &str,
		subject: &str,
	) {
		sqlx::query(
			"INSERT INTO actions (tn_id, action_id, type, sub_type, issuer_tag, subject, status, visibility, created_at)
			VALUES (?, ?, ?, ?, ?, ?, 'A', 'P', unixepoch())",
		)
		.bind(tn_id.0)
		.bind(action_id)
		.bind(typ)
		.bind(sub_type)
		.bind("alice.example")
		.bind(subject)
		.execute(db)
		.await
		.expect("insert action");
	}

	// Build a public REPOST Action for the keyed-create tests. Empty `sub_type`
	// → None (a normal repost); "DEL" → the un-repost marker.
	fn repost_action<'a>(
		action_id: &'a str,
		sub_type: &'a str,
		subject: &'a str,
		issuer: &'a str,
		audience: &'a str,
	) -> Action<&'a str> {
		Action {
			action_id,
			typ: "REPOST",
			sub_typ: if sub_type.is_empty() { None } else { Some(sub_type) },
			issuer_tag: issuer,
			audience_tag: Some(audience),
			subject: Some(subject),
			visibility: Some('P'),
			..Default::default()
		}
	}

	// Drive the real keyed create() path for an inbound action so the key-based
	// supersede SQL actually runs (insert_action writes rows directly and bypasses
	// it). A non-empty action_id marks the action inbound — the branch that
	// supersedes prior rows sharing the same key, exactly the mechanism that turns
	// a REPOST:DEL into a real deletion and dedups repeated reposts. The supersede
	// key is derived from the action itself ({type}:{subject}:{issuer}:{audience}).
	async fn create_keyed(db: &SqlitePool, tn_id: TnId, action: &Action<&str>) {
		let key = format!(
			"{}:{}:{}:{}",
			action.typ,
			action.subject.unwrap_or_default(),
			action.issuer_tag,
			action.audience_tag.unwrap_or_default(),
		);
		create(db, tn_id, action, Some(&key)).await.expect("create keyed action");
	}

	// H1 regression: count() must report the true total, not the LIMIT-20
	// saturated value the old `list_actions().len()` path returned (21).
	#[tokio::test]
	async fn count_reposts_does_not_saturate_at_limit() {
		let dir = tempfile::tempdir().expect("tempdir");
		let db = test_pool(dir.path()).await;
		let tn_id = TnId(1);
		let subject = "a1~the-shared-post";

		for i in 0..25 {
			insert_action(&db, tn_id, &format!("a1~repost-{i}"), "REPOST", "", subject).await;
		}

		let opts = ListActionOptions {
			typ: Some(vec!["REPOST".into()]),
			subject: Some(subject.to_string()),
			..Default::default()
		};

		// count() sees all 25 active reposts.
		let n = count(&db, tn_id, &opts).await.expect("count");
		assert_eq!(n, 25, "count() must report the true repost total");

		// The old buggy path (list + len) saturates at limit+1 = 21.
		let listed = list(&db, tn_id, &opts).await.expect("list");
		assert_eq!(listed.len(), 21, "list() is capped at LIMIT+1, proving why count() is needed");
	}

	// H1 regression (real keyed flow): a REPOST:DEL un-repost with the same
	// {subject,issuer,audience} key as the original REPOST must supersede it
	// (status→'D'), dropping the live repost count to 0. The previous version of
	// this test inserted a standalone DEL row and asserted the live total stayed
	// 3 — it enshrined the bug (REPOST had key_pattern: None, so :DEL never
	// superseded anything). With REPOST now keyed, the un-repost actually deletes.
	#[tokio::test]
	async fn count_reposts_keyed_del_supersedes() {
		let dir = tempfile::tempdir().expect("tempdir");
		let db = test_pool(dir.path()).await;
		let tn_id = TnId(1);
		let subject = "a1~the-shared-post";
		let issuer = "bob.example";
		let audience = "bob.example"; // boost to own wall

		let opts = ListActionOptions {
			typ: Some(vec!["REPOST".into()]),
			subject: Some(subject.to_string()),
			..Default::default()
		};

		// A single keyed repost.
		create_keyed(&db, tn_id, &repost_action("a1~repost-1", "", subject, issuer, audience))
			.await;
		assert_eq!(count(&db, tn_id, &opts).await.expect("count"), 1, "one live repost");

		// The un-repost: same {subject,issuer,audience} ⇒ same key ⇒ supersedes the
		// original. The DEL marker row is grouped separately and excluded by the
		// caller-side filter, so the live total returns to 0.
		create_keyed(&db, tn_id, &repost_action("a1~unrepost-1", "DEL", subject, issuer, audience))
			.await;

		let grouped = count_grouped(&db, tn_id, &opts, ActionCountGroupBy::SubType)
			.await
			.expect("count_grouped");
		let live: i64 = grouped
			.iter()
			.filter(|(g, _)| g.as_deref() != Some("DEL"))
			.map(|(_, c)| *c)
			.sum();
		assert_eq!(live, 0, "un-repost must supersede the original; live count back to 0");
	}

	// H2 regression: two keyed reposts of the same {subject,issuer,audience}
	// collapse to a single live row (the prior is superseded to status='D'), so a
	// peer cannot inflate the count by re-delivering the same repost.
	#[tokio::test]
	async fn count_reposts_keyed_dedup() {
		let dir = tempfile::tempdir().expect("tempdir");
		let db = test_pool(dir.path()).await;
		let tn_id = TnId(1);
		let subject = "a1~the-shared-post";
		let issuer = "bob.example";
		let audience = "community.example"; // wall-repost to a community

		create_keyed(&db, tn_id, &repost_action("a1~repost-1", "", subject, issuer, audience))
			.await;
		create_keyed(&db, tn_id, &repost_action("a1~repost-2", "", subject, issuer, audience))
			.await;

		let opts = ListActionOptions {
			typ: Some(vec!["REPOST".into()]),
			subject: Some(subject.to_string()),
			..Default::default()
		};
		assert_eq!(
			count(&db, tn_id, &opts).await.expect("count"),
			1,
			"duplicate reposts of the same target collapse to one live row"
		);
	}

	// A boost (own wall) and a wall-repost (community) of the same subject by the
	// same issuer have DISTINCT keys (audience differs) and therefore coexist as
	// two independent, independently un-repostable rows — the model the
	// ownRepostIds-by-target design assumes.
	#[tokio::test]
	async fn count_reposts_keyed_distinct_audiences_coexist() {
		let dir = tempfile::tempdir().expect("tempdir");
		let db = test_pool(dir.path()).await;
		let tn_id = TnId(1);
		let subject = "a1~the-shared-post";
		let issuer = "bob.example";

		create_keyed(&db, tn_id, &repost_action("a1~repost-1", "", subject, issuer, "bob.example"))
			.await;
		create_keyed(
			&db,
			tn_id,
			&repost_action("a1~repost-2", "", subject, issuer, "community.example"),
		)
		.await;

		let opts = ListActionOptions {
			typ: Some(vec!["REPOST".into()]),
			subject: Some(subject.to_string()),
			..Default::default()
		};
		assert_eq!(
			count(&db, tn_id, &opts).await.expect("count"),
			2,
			"reposts to distinct audiences are distinct keys and coexist"
		);
	}

	// Grouped count over >20 same-type reactions returns the true per-type total.
	#[tokio::test]
	async fn count_grouped_reactions_true_total() {
		let dir = tempfile::tempdir().expect("tempdir");
		let db = test_pool(dir.path()).await;
		let tn_id = TnId(1);
		let subject = "a1~liked-post";

		for i in 0..23 {
			insert_action(&db, tn_id, &format!("a1~like-{i}"), "REACT", "LIKE", subject).await;
		}
		// A removed reaction (REACT:DEL) must not inflate the LIKE total.
		insert_action(&db, tn_id, "a1~del-1", "REACT", "DEL", subject).await;

		let opts = ListActionOptions {
			typ: Some(vec!["REACT".into()]),
			subject: Some(subject.to_string()),
			..Default::default()
		};
		let grouped = count_grouped(&db, tn_id, &opts, ActionCountGroupBy::SubType)
			.await
			.expect("count_grouped");

		let like = grouped.iter().find(|(g, _)| g.as_deref() == Some("LIKE")).map(|(_, c)| *c);
		assert_eq!(like, Some(23), "LIKE total must reflect all 23 active reactions");
		let del = grouped.iter().find(|(g, _)| g.as_deref() == Some("DEL")).map(|(_, c)| *c);
		assert_eq!(del, Some(1), "DEL rows are grouped separately; caller excludes them");
	}

	// Guards the conditional `pa` join: when `audience_type` is set, count() must
	// add the effective-audience profile join so the filter resolves correctly.
	// The default (counter) path omits the join entirely; this path must not.
	#[tokio::test]
	async fn count_filters_by_audience_type_via_conditional_join() {
		use cloudillo_types::meta_adapter::AudienceType;
		let dir = tempfile::tempdir().expect("tempdir");
		let db = test_pool(dir.path()).await;
		let tn_id = TnId(1);

		// Two audience profiles: one community, one personal.
		for (id_tag, typ) in [("community.example", "C"), ("person.example", "P")] {
			sqlx::query("INSERT INTO profiles (tn_id, id_tag, name, type) VALUES (?, ?, ?, ?)")
				.bind(tn_id.0)
				.bind(id_tag)
				.bind(id_tag)
				.bind(typ)
				.execute(&db)
				.await
				.expect("insert profile");
		}

		// Two POSTs addressed to those audiences.
		for (action_id, audience) in
			[("a1~p-community", "community.example"), ("a1~p-person", "person.example")]
		{
			sqlx::query(
				"INSERT INTO actions (tn_id, action_id, type, issuer_tag, audience, status, visibility, created_at)
				VALUES (?, ?, 'POST', 'alice.example', ?, 'A', 'P', unixepoch())",
			)
			.bind(tn_id.0)
			.bind(action_id)
			.bind(audience)
			.execute(&db)
			.await
			.expect("insert post");
		}

		let opts = ListActionOptions {
			typ: Some(vec!["POST".into()]),
			audience_type: Some(AudienceType::Community),
			..Default::default()
		};
		let n = count(&db, tn_id, &opts).await.expect("count");
		assert_eq!(n, 1, "only the community-addressed POST matches audienceType=community");
	}
}
