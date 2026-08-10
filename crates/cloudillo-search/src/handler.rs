// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! `GET /api/search` — the single full-text query surface.
//!
//! # Authorization
//!
//! The endpoint is reachable **unauthenticated** — it sits under `optional_auth`
//! in `routes/public.rs`, and a tokenless caller is treated as the `"guest"`
//! subject, which the derivation below turns into [`SubjectAccessLevel::Public`],
//! the level `GET /api/files` gives the same caller. Three layers, in order:
//!
//! 1. **Scoped tokens.** A share-link holder carries `file:{id}:{R|C|W}`. Only
//!    that variant is accepted — an unparseable or `apkg:publish` scope is a
//!    hard 403, never a widening. The token confines the query to its own
//!    document tree and to file/document rows: a link recipient has no business
//!    searching the tenant's posts or profiles.
//!
//!    A scope narrows the *subtree*; the visibility derivation below still runs
//!    for every caller and the scope applies on top of it. A share link to a
//!    folder is not a grant over that folder's Direct and Connected children, and
//!    `GET /api/files` does not treat it as one either. The one exception is
//!    [`SearchOptions::scope_grant_file_id`]: the shared file's own row and the
//!    deep `'D'` parts of its tree bypass the level filter, because the share
//!    *is* permission to read that document — without it a link to a private
//!    note would search to zero hits inside a note its holder can open. Child
//!    `'F'` rows in the tree keep the level filter.
//!
//!    A scoped token is never the owner, whatever its subject says: share-link
//!    tokens are minted with `sub: None` and `iss` = the tenant, and validation
//!    resolves `id_tag` as `sub.unwrap_or(iss)`. See [`subject_level`].
//! 2. **SQL prefilter.** Per object type, the same rule the corresponding list
//!    endpoint applies, so pagination counts only rows the caller could see:
//!
//!    - `'P'` profiles are **not** filtered — tenant-scoped, and any
//!      authenticated caller in the tenant may find them, exactly as
//!      `GET /api/profiles` allows. That does not extend to an anonymous caller,
//!      so an unauthenticated request has `'P'` dropped from its `obj_tp` filter
//!      outright (see [`guest_obj_tp`]); otherwise anyone could enumerate the
//!      tenant's whole contact graph, cached remote profiles included.
//!    - `'F'` files and `'D'` deep parts are filtered by `visible_levels`,
//!      derived from the caller's relationship to the tenant precisely as
//!      `GET /api/files` derives it — the tenant owns both.
//!    - `'A'` actions use the canonical predicate shared with `GET /api/actions`,
//!      keyed on the **issuer**, not the tenant: following the tenant does not
//!      make the caller a follower of every issuer whose posts it federated in.
//!
//!    An owner — caller `id_tag` == tenant `id_tag` *and* no scope — gets
//!    `visible_levels = None`, and then no predicate is emitted at all.
//! 3. **Redundant post-check.** The SQL prefilter above *is* the authorization.
//!    [`file_access::check_scope_allows_file`] is exactly
//!    `file_id == scope || root_id == scope`, the same predicate the adapter
//!    already pushed down for `scope_file_id`, so under a correct prefilter it
//!    never drops a row. Kept as a cross-check against future drift in either
//!    half, and loud: a non-zero drop count logs at `warn!`.
//!
//! # Pagination
//!
//! Results are relevance-ordered, so this endpoint uses `limit`/`offset` rather
//! than the keyset cursor the rest of the API uses — a cursor over a `bm25()`
//! ordering has nothing stable to anchor on. `offset` is capped.
//!
//! `pagination.total` is the only has-more signal the response carries: derived
//! from the page alone it would equal `offset + len` and every page would look
//! like the last one. It normally comes from a second adapter call,
//! [`cloudillo_types::meta_adapter::MetaAdapter::count_search`], over the same SQL
//! filters as the page itself.
//!
//! That second call is **skipped when the page answers the question by itself**:
//! a first page (`offset == 0`) shorter than `limit` is the whole match set, so
//! its length *is* the total. This is the common case on a route reachable with
//! no token at all, where `?q=a` — a `"a"*` prefix matching most of the corpus —
//! would otherwise cost two full ranked FTS scans, each re-running the per-row
//! correlated `EXISTS` over `actions`. The decision reads the raw adapter row
//! count, before the post-check, so it stays consistent with what the SQL
//! matched. Not `tokio::join!`ed with the page: that would undo the skip.
//!
//! When it does run, the count **saturates** at
//! `SEARCH_MAX_OFFSET + SEARCH_MAX_LIMIT`. `offset` is clamped to
//! `SEARCH_MAX_OFFSET`, so no page a caller can reach lies past it and the
//! has-more signal stays exact where a caller can act on it. Uncapped, such a
//! request would walk the tenant's whole match set.

use std::collections::HashMap;

use axum::{
	Json,
	extract::{Query, State},
	http::StatusCode,
};
use cloudillo_core::{
	abac::{SubjectAccessLevel, relationship_level},
	extract::{IdTag, OptionalAuth, OptionalRequestId},
	file_access::{self, ScopeCheck},
};
use cloudillo_types::{
	auth_adapter::AuthCtx,
	meta_adapter::{
		SEARCH_MAX_CONTENT_TYPES, SEARCH_MAX_LIMIT, SEARCH_MAX_OFFSET, SEARCH_MAX_TAGS,
		SearchMatch, SearchOptions, SearchRow,
	},
	types::{ApiResponse, TokenScope, serialize_timestamp_iso},
};
use serde::{Deserialize, Serialize};

use crate::{
	indexer::{OBJ_DOC, OBJ_FILE},
	objects::{OBJ_ACTION, OBJ_PROFILE},
	prelude::*,
};

const DEFAULT_LIMIT: u32 = 20;

/// Longest accepted `q`. Every token becomes a quoted term plus an ` AND ` in
/// the FTS5 MATCH expression, so an unbounded query is an unbounded expression;
/// `limit` and `offset` are capped and this is the third knob.
const MAX_QUERY_CHARS: usize = 256;

/// Longest accepted single `tags` / `contentType` entry. A tag is a word and a
/// content type is a short MIME string; the cap only bounds a pathological one.
const MAX_FILTER_ENTRY_CHARS: usize = 128;

/// Query parameters for `GET /api/search`.
///
/// Deliberately **not** `deny_unknown_fields`, matching every other query struct in
/// the API. This route is reachable with no token at all, and a parameter this build
/// has never heard of must degrade to "ignored" rather than to a 400 on the whole
/// request — the same stance [`parse_types`] takes for an unknown `?type=` name.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchQuery {
	pub q: String,
	/// Comma-separated subset of `file,doc,action,profile`.
	pub r#type: Option<String>,
	/// Restrict to one container document and its parts.
	pub file_id: Option<String>,
	/// Comma-separated content types.
	pub content_type: Option<String>,
	/// Comma-separated tags, AND-combined. Applied inside the FTS match, so a
	/// text+tag query cannot lose a hit to the relevance cut.
	///
	/// With `tags` present, `q` may be empty — that is a tag-only browse.
	pub tags: Option<String>,
	pub limit: Option<u32>,
	pub offset: Option<u32>,
}

/// One result row on the wire.
///
/// Absent fields are omitted rather than sent as `null`: the frontend types
/// these as optional (`T.optional` in `libs/types/src/types.ts`), which in
/// `@symbion/runtype` means "may be missing", not "may be null". A hit is
/// mostly-empty for whole-object rows, so this also keeps the payload small.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchHit {
	/// `'F'` file, `'D'` deep document part, `'A'` action, `'P'` profile.
	pub obj_tp: char,
	pub obj_id: Box<str>,
	/// Deep-link key — for notillo, the page id.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub part_id: Option<Box<str>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub part_kind: Option<Box<str>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub parent_part: Option<Box<str>>,
	/// Finest-grained anchor inside the part — for notillo, the block id.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub anchor_id: Option<Box<str>>,
	/// App id parsed out of `cloudillo/<appId>`, for building a `cl:` ref.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub app_id: Option<Box<str>>,
	/// Deep-link query param name from the format manifest, e.g. `"nav"`.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub nav_param: Option<Box<str>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub content_type: Option<Box<str>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub title: Option<Box<str>>,
	/// Server-built excerpt as plain text; `snippetMatches` carries the highlight
	/// out of band. Contains no markup and must not be fed to an HTML sink.
	///
	/// **Absent for every hit** when the tenant has `search.store_text` off:
	/// that mode keeps no plain-text copy to cut an excerpt out of. A result list
	/// must fall back to title + tags rather than assume a snippet is there.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub snippet: Option<Box<str>>,
	/// Ranges within `snippet` to emphasise. **UTF-16 code-unit** offsets, so a
	/// client can slice `snippet` directly; ascending and non-overlapping.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub snippet_matches: Option<Box<[SearchMatch]>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub tags: Option<Box<[Box<str>]>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub owner_tag: Option<Box<str>>,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub updated_at: Timestamp,
	/// Sign-flipped `bm25()`: higher is more relevant.
	pub score: f64,
}

pub async fn get_search(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	OptionalAuth(maybe_auth): OptionalAuth,
	OptionalRequestId(req_id): OptionalRequestId,
	Query(q): Query<SearchQuery>,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<SearchHit>>>)> {
	let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, SEARCH_MAX_LIMIT);
	let offset = q.offset.unwrap_or(0).min(SEARCH_MAX_OFFSET);
	let authenticated = maybe_auth.is_some();
	// The same synthesis `check_file_permission` uses for unauthenticated file
	// reads, so the `"guest"` subject the visibility derivation below tests for is
	// the one it actually sees.
	let auth = maybe_auth.unwrap_or_else(|| AuthCtx {
		tn_id,
		id_tag: "guest".into(),
		roles: vec![].into(),
		scope: None,
	});
	if q.q.chars().count() > MAX_QUERY_CHARS {
		return Err(Error::ValidationError("Search query too long".into()));
	}
	let content_type =
		csv_filter(q.content_type.as_deref(), SEARCH_MAX_CONTENT_TYPES, "contentType")?;
	let tags = csv_filter(q.tags.as_deref(), SEARCH_MAX_TAGS, "tags")?;

	let mut opts = SearchOptions {
		q: q.q,
		obj_tp: obj_tp_filter(q.r#type.as_deref()),
		file_id: q.file_id,
		content_type,
		tags,
		limit,
		offset,
		// Read from the same setting the write path uses, so a query always hits
		// the table this tenant's rows are actually in. Hits from the contentless
		// one carry no `snippet`, and the result list falls back to title + tags.
		fts_cl: !crate::store_text(&app, tn_id).await,
		..Default::default()
	};

	// Same derivation as `GET /api/files`, and unconditional: a scope *narrows*
	// the result set on top of this, it never replaces it. Leaving
	// `visible_levels` at `None` for a scoped caller would hand a share-link guest
	// the tenant-owner level over the whole shared document tree.
	let subject = auth.id_tag.as_ref();
	let rels = app.meta_adapter.get_relationships(tn_id, &[subject]).await?;
	let (following, connected) = rels.get(subject).copied().unwrap_or((false, false));
	let level =
		subject_level(auth.scope.as_deref(), subject, tenant_id_tag.as_ref(), connected, following);
	opts.visible_levels = level.visible_levels().map(<[char]>::to_vec);
	// Same test `subject_level` uses, so the two can never disagree: a share-link
	// guest resolves to the tenant's own id_tag, and handing that to the adapter
	// as the viewer would match every row the tenant owns. `None` is an
	// unidentified viewer.
	opts.viewer_id_tag =
		(!is_anonymous_share(auth.scope.as_deref(), subject, tenant_id_tag.as_ref()))
			.then(|| subject.to_owned());

	// Applied before the scope narrowing below, so a file scope still narrows on
	// top of it.
	if !authenticated {
		opts.obj_tp = Some(guest_obj_tp(opts.obj_tp.take()));
	}

	if let Some(scope) = auth.scope.as_deref() {
		// Only a file scope reaches here; anything else — including a scope
		// string this build cannot parse — is denied rather than ignored.
		let Some(TokenScope::File { file_id, .. }) = TokenScope::parse(scope) else {
			return Err(Error::PermissionDenied);
		};
		opts.scope_file_id = Some(file_id.clone());
		// The share itself is the grant: the shared file's own row and the deep
		// parts of its document tree stay visible even at Direct visibility, or a
		// share link to a private document would search to zero hits inside a
		// document its holder can open. Child `'F'` rows in the tree keep the level
		// filter — same split `GET /api/files` makes.
		opts.scope_grant_file_id = Some(file_id.clone().into());
		opts.obj_tp = Some(scope_obj_tp(opts.obj_tp.take()));
	}

	// Redundant cross-check, not a second gate — see the module docs.
	let scope = auth.scope.as_deref();
	let fetched = app.meta_adapter.search(tn_id, &opts).await?;
	let fetched_len = fetched.len();

	// Decided off `fetched_len`, the raw adapter row count, not the post-checked
	// `rows.len()` below, so it stays consistent with what the SQL matched.
	let total = match total_from_page(offset, fetched_len, limit) {
		Some(total) => total,
		// Taken over the same SQL filters as the page, so it agrees with it
		// exactly — see the module docs on the one case that makes it an upper
		// bound.
		None => app.meta_adapter.count_search(tn_id, &opts).await?,
	};

	let rows: Vec<SearchRow> = fetched
		.into_iter()
		.filter(|row| {
			!matches!(row.obj_tp, OBJ_FILE | OBJ_DOC)
				|| !matches!(
					file_access::check_scope_allows_file(
						scope,
						&row.obj_id,
						row.root_id.as_deref()
					),
					ScopeCheck::Denied
				)
		})
		.collect();
	if rows.len() < fetched_len {
		warn!(
			tn_id = %tn_id,
			dropped = fetched_len - rows.len(),
			"Search scope post-check dropped rows the SQL prefilter admitted"
		);
	}

	let nav_params = read_nav_params(&app, tn_id, &rows).await;
	let hits: Vec<SearchHit> = rows.into_iter().map(|row| to_hit(row, &nav_params)).collect();

	let total = usize::try_from(total).unwrap_or(0);
	let response = ApiResponse::with_pagination(hits, offset as usize, limit as usize, total)
		.with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

/// `pagination.total` when the page alone settles it, `None` when the second FTS
/// scan has to run.
///
/// A *first* page shorter than `limit` is the whole match set, so its length is
/// the answer. Anywhere else the page says nothing about what lies past it.
///
/// `len` is the raw adapter row count, before the scope post-check, so the
/// decision matches what the SQL matched rather than what survived a cross-check
/// that never fires under a correct prefilter.
fn total_from_page(offset: u32, len: usize, limit: u32) -> Option<i64> {
	(offset == 0 && len < usize::try_from(limit).unwrap_or(usize::MAX))
		.then(|| i64::try_from(len).unwrap_or(i64::MAX))
}

/// Is this caller a scoped token holder who identifies nobody the handler can
/// tell apart from the tenant?
///
/// A share-link token is minted with `sub: None`, so token validation resolves
/// its `id_tag` to `iss` — the tenant itself. Everything that would otherwise
/// hand such a caller the tenant's own privileges must test for it the same way:
/// [`subject_level`] for the visibility level, and the `viewer_id_tag` assignment
/// in [`get_search`]. A viewer tag makes the caller *identified* to the adapter —
/// admitting every `'P'` profile row and feeding the issuer-keyed action
/// predicate — so passing the tenant's own tag would hand an anonymous link
/// holder the tenant's contact graph. What such a caller may see comes from
/// [`SearchOptions::scope_grant_file_id`] alone.
fn is_anonymous_share(scope: Option<&str>, subject: &str, tenant_id_tag: &str) -> bool {
	scope.is_some() && subject == tenant_id_tag
}

/// Which visibility levels a caller may see.
///
/// Pure, so the rule is testable without an `App`, and because getting it wrong
/// is a disclosure bug rather than a wrong result.
///
/// The first branch is the load-bearing one. A share-link token is minted with
/// `sub: None` (`cloudillo-auth`'s share-token handler) and `iss` = the tenant,
/// and validation resolves `id_tag` as `claims.sub.unwrap_or(claims.iss)` — so
/// `auth.id_tag` for a share-link guest *is* the tenant's own id_tag. Testing the
/// subject alone would derive `Owner` for every such guest and skip the
/// visibility block entirely. Such a token identifies nobody, so it is treated as
/// the anonymous caller it is; what it may see beyond the public level comes from
/// [`SearchOptions::scope_grant_file_id`] alone.
///
/// **Any** scoped token is demoted this way, including the tenant owner's own —
/// minted with `sub: Some(&auth.id_tag)`, which resolves to the same `id_tag` as
/// `iss`, and `AuthCtx` keeps no `sub` to tell the two apart. That is the
/// intended sandbox: a file scope is handed to a potentially untrusted app, so it
/// grants its own scope plus public content and no ambient authority from
/// whoever's session minted it. The observable consequence — not a bug — is that
/// the tenant owner searching from inside their own app iframe sees only
/// `visibility='P'` rows outside the `scope_grant_file_id` exemption.
fn subject_level(
	scope: Option<&str>,
	subject: &str,
	tenant_id_tag: &str,
	connected: bool,
	following: bool,
) -> SubjectAccessLevel {
	if is_anonymous_share(scope, subject, tenant_id_tag) {
		return SubjectAccessLevel::Public;
	}
	let is_real_auth = !subject.is_empty() && subject != "guest";
	relationship_level(subject == tenant_id_tag, connected, following, is_real_auth)
}

/// Look up the deep-link query param of every content type on this page.
///
/// One `doc_format::resolve` per *distinct* content type, not one per hit: the value
/// is identical across every row sharing a type, and a page rarely spans more
/// than one or two. Awaited inside the result loop it would be up to `limit`
/// serialized round-trips for the same answer.
async fn read_nav_params(
	app: &App,
	tn_id: TnId,
	rows: &[SearchRow],
) -> HashMap<Box<str>, Option<Box<str>>> {
	let mut out: HashMap<Box<str>, Option<Box<str>>> = HashMap::new();
	// Only deep rows need it — a whole-file hit has no part to navigate to.
	for row in rows.iter().filter(|r| !r.part_id.is_empty()) {
		let Some(ct) = row.content_type.as_deref() else { continue };
		if out.contains_key(ct) {
			continue;
		}
		let nav_param = cloudillo_core::doc_format::resolve(app, tn_id, ct)
			.await
			.inspect_err(|e| {
				warn!(content_type = ct, error = %e, "Cannot read doc format for nav param");
			})
			.ok()
			.flatten()
			.and_then(|f| f.nav_param);
		out.insert(ct.into(), nav_param);
	}
	out
}

/// Build the client-facing hit, enriching it with the deep-link metadata the
/// client needs to construct `cl:{appId}/{owner}:{fileId}?{navParam}={partId}`.
///
/// `nav_params` is [`read_nav_params`]' per-content-type lookup, so this is a
/// plain synchronous mapping with no database access of its own.
fn to_hit(row: SearchRow, nav_params: &HashMap<Box<str>, Option<Box<str>>>) -> SearchHit {
	let content_type = row.content_type;
	let nav_param = match (&content_type, row.part_id.is_empty()) {
		(Some(ct), false) => nav_params.get(ct.as_ref()).cloned().flatten(),
		_ => None,
	};

	// The stored ids are namespaced by part kind; the client deep-links with the
	// app's own document id.
	let kind = row.part_kind.as_deref();
	let part_id: Option<Box<str>> =
		(!row.part_id.is_empty()).then(|| strip_kind(&row.part_id, kind).into());
	let parent_part: Option<Box<str>> =
		row.parent_part.as_deref().map(|p| strip_kind(p, kind).into());

	SearchHit {
		obj_tp: row.obj_tp,
		obj_id: row.obj_id,
		part_id,
		part_kind: row.part_kind,
		parent_part,
		anchor_id: row.anchor_id,
		app_id: content_type.as_deref().and_then(app_id_of).map(Into::into),
		nav_param,
		content_type,
		title: row.title,
		snippet: row.snippet,
		snippet_matches: row.snippet_matches,
		tags: row.tags.as_deref().map(split_tags),
		owner_tag: row.owner_tag,
		updated_at: row.updated_at,
		// `bm25()` is negative and ascending-relevant; flip it so the client's
		// "higher is better" intuition holds.
		score: -row.score,
	}
}

/// `cloudillo/notillo` → `notillo`. Anything else has no app to launch.
fn app_id_of(content_type: &str) -> Option<&str> {
	content_type.strip_prefix("cloudillo/").filter(|s| !s.is_empty())
}

/// Undo `indexer::build_parts`' `{kind}/{id}` namespacing for the wire.
///
/// The prefix exists only to keep `idx_search_docs_key` unique across
/// collections; the client deep-links with the app's own document id.
fn strip_kind<'a>(part: &'a str, kind: Option<&str>) -> &'a str {
	kind.and_then(|k| part.strip_prefix(k)?.strip_prefix('/')).unwrap_or(part)
}

/// Map the API's `type` names onto `search_docs.obj_tp` codes. Unknown names
/// are dropped rather than erroring, so a newer client asking for a type this
/// build has never heard of degrades to "no such results" instead of a 400.
///
/// An all-unknown list therefore returns an *empty* vec, which the caller keeps
/// as `Some(vec![])` — the adapter reads that as "match nothing". Collapsing it
/// to `None` would turn `?type=quantum` into an unfiltered search, which is the
/// opposite of what a filter the caller wrote should do.
fn parse_types(raw: &str) -> Vec<char> {
	raw.split(',')
		.map(str::trim)
		.filter_map(|t| match t {
			"file" => Some('F'),
			"doc" => Some('D'),
			"action" => Some('A'),
			"profile" => Some('P'),
			_ => None,
		})
		.collect()
}

/// The mapping `get_search` applies to `?type=`: a blank or absent parameter is
/// "no filter at all" (`None`), while a non-blank one naming nothing this build
/// knows keeps its empty vec — which the adapter reads as "match nothing".
///
/// A free function rather than an inline expression so the test that guards the
/// `Some(vec![])` / `None` distinction exercises the production path.
fn obj_tp_filter(raw: Option<&str>) -> Option<Vec<char>> {
	raw.map(str::trim).filter(|t| !t.is_empty()).map(parse_types)
}

/// Narrow an unauthenticated caller's `obj_tp` filter to the types a guest may
/// see — everything except `'P'`.
///
/// The SQL prefilter exempts profiles from the visibility predicate on the
/// grounds that any *authenticated* caller may already list them via
/// `GET /api/profiles`; that does not hold for an anonymous one. A guest asking
/// for `?type=profile` therefore ends with an empty vec, which the adapter reads
/// as "match nothing" — an empty page, not an unfiltered one — and both
/// `count_search` and `search` see the same `opts`, so the count agrees with it.
fn guest_obj_tp(requested: Option<Vec<char>>) -> Vec<char> {
	match requested {
		Some(tps) => tps.into_iter().filter(|tp| *tp != OBJ_PROFILE).collect(),
		None => vec![OBJ_FILE, OBJ_DOC, OBJ_ACTION],
	}
}

/// Narrow a file-scoped caller's `obj_tp` filter to what a file scope can hold.
///
/// Intersect, don't replace: a scope narrows what the caller asked for, it does
/// not answer a different question. A share-link holder asking `?type=action`
/// gets an empty page, not a page of files. `Some(empty)` is "match nothing",
/// which the adapter emits as `AND 1=0` — the same contract [`guest_obj_tp`]
/// relies on, and both `count_search` and `search` see the same `opts`.
fn scope_obj_tp(requested: Option<Vec<char>>) -> Vec<char> {
	match requested {
		Some(tps) => tps.into_iter().filter(|tp| matches!(*tp, OBJ_FILE | OBJ_DOC)).collect(),
		None => vec![OBJ_FILE, OBJ_DOC],
	}
}

/// Split one comma-separated filter list and bound it.
///
/// Rejected rather than truncated: a caller that asked for forty tags and was
/// quietly served sixteen would get an answer to a question it did not ask. The
/// cap matters because neither list is otherwise bounded — ~33k `contentType`
/// values overrun SQLite's 32766 bound-variable limit into a 500, and a long
/// `tags` list builds an arbitrarily deep FTS5 `MATCH` expression.
fn csv_filter(raw: Option<&str>, max: usize, what: &str) -> ClResult<Option<Vec<String>>> {
	let Some(values) = raw.map(split_csv) else { return Ok(None) };
	if values.len() > max {
		return Err(Error::ValidationError(format!("Too many {what} values (max {max})")));
	}
	if values.iter().any(|v| v.chars().count() > MAX_FILTER_ENTRY_CHARS) {
		return Err(Error::ValidationError(format!("A {what} value is too long")));
	}
	Ok((!values.is_empty()).then_some(values))
}

fn split_csv(raw: &str) -> Vec<String> {
	raw.split(',')
		.map(str::trim)
		.filter(|s| !s.is_empty())
		.map(ToOwned::to_owned)
		.collect()
}

fn split_tags(raw: &str) -> Box<[Box<str>]> {
	raw.split_whitespace().map(Into::into).collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn type_names_map_to_obj_tp_codes() {
		assert_eq!(parse_types("file,doc"), vec!['F', 'D']);
		assert_eq!(parse_types(" action , profile "), vec!['A', 'P']);
	}

	#[test]
	fn unknown_type_names_are_dropped_not_rejected() {
		assert_eq!(parse_types("doc,quantum"), vec!['D']);
		assert!(parse_types("quantum").is_empty());
	}

	/// An all-unknown list must stay `Some(vec![])` — "match nothing"; only a
	/// blank one may become `None`, which is "no filter at all".
	#[test]
	fn an_all_unknown_type_filter_matches_nothing_rather_than_everything() {
		assert_eq!(obj_tp_filter(Some("quantum")), Some(vec![]));
		assert_eq!(obj_tp_filter(Some("quantum,warp")), Some(vec![]));
		// A blank or absent parameter is the only "no filter" case.
		assert_eq!(obj_tp_filter(Some("")), None);
		assert_eq!(obj_tp_filter(Some("  ")), None);
		assert_eq!(obj_tp_filter(None), None);
		// A partially-recognised list keeps what it understood.
		assert_eq!(obj_tp_filter(Some("doc,quantum")), Some(vec!['D']));
	}

	/// A page that filled up may or may not be the last one, and no page past the
	/// first says anything about the size of the match set.
	#[test]
	fn the_second_fts_scan_is_skipped_only_for_a_short_first_page() {
		// Short first page: the page *is* the match set.
		assert_eq!(total_from_page(0, 3, 20), Some(3));
		assert_eq!(total_from_page(0, 0, 20), Some(0));
		assert_eq!(total_from_page(0, 19, 20), Some(19));

		// Full first page: there may be more behind it.
		assert_eq!(total_from_page(0, 20, 20), None);

		// Any later page, however short: `offset + len` is not the total.
		assert_eq!(total_from_page(20, 3, 20), None);
		assert_eq!(total_from_page(20, 0, 20), None);
		assert_eq!(total_from_page(1, 0, 20), None);
	}

	/// An explicit `?type=profile` becomes "match nothing" rather than falling
	/// back to "no filter".
	#[test]
	fn a_guest_never_sees_profiles() {
		assert_eq!(guest_obj_tp(None), vec![OBJ_FILE, OBJ_DOC, OBJ_ACTION]);
		assert_eq!(guest_obj_tp(Some(vec!['P'])), Vec::<char>::new());
		assert_eq!(guest_obj_tp(Some(vec!['F', 'P'])), vec!['F']);
		assert_eq!(guest_obj_tp(Some(vec![])), Vec::<char>::new());
	}

	/// Asking for actions inside a file scope is an empty page, not a page of
	/// files the caller never asked for.
	#[test]
	fn a_file_scope_intersects_the_type_filter() {
		assert_eq!(scope_obj_tp(None), vec![OBJ_FILE, OBJ_DOC]);
		assert_eq!(scope_obj_tp(Some(vec!['A'])), Vec::<char>::new());
		assert_eq!(scope_obj_tp(Some(vec!['F'])), vec!['F']);
		assert_eq!(scope_obj_tp(Some(vec!['F', 'A', 'D'])), vec!['F', 'D']);
		assert_eq!(scope_obj_tp(Some(vec![])), Vec::<char>::new());
	}

	/// A share-link token resolves its `id_tag` to the tenant's own, so testing
	/// the subject alone would derive `Owner` for every share-link guest. The
	/// scope is what tells the two apart.
	#[test]
	fn a_scoped_token_is_never_the_owner() {
		let tenant = "alice.example.com";
		assert_eq!(
			subject_level(Some("file:f1~x:R"), tenant, tenant, false, false),
			SubjectAccessLevel::Public
		);
		assert_eq!(subject_level(None, tenant, tenant, false, false), SubjectAccessLevel::Owner);
	}

	/// Getting this wrong pushes `OR d.owner_tag = '<tenant>'` into the adapter's
	/// visibility predicate and hands an anonymous link holder owner-equivalent
	/// visibility on every row carrying the tenant's tag.
	#[test]
	fn an_anonymous_share_is_not_handed_the_tenants_own_tag() {
		let tenant = "alice.example.com";
		// A scoped token naming nobody resolves its subject to the tenant.
		assert!(is_anonymous_share(Some("file:f1~x:R"), tenant, tenant));
		// A logged-in user holding a file-scoped credential is still themselves.
		assert!(!is_anonymous_share(Some("file:f1~x:R"), "bob.example.com", tenant));
		// An unscoped call by the tenant is the real owner.
		assert!(!is_anonymous_share(None, tenant, tenant));
		assert!(!is_anonymous_share(None, "bob.example.com", tenant));
	}

	/// The two derivations agree by construction: whenever `is_anonymous_share`
	/// holds, `subject_level` drops to `Public` and the caller gets no viewer tag.
	#[test]
	fn the_anonymity_test_and_the_visibility_level_agree() {
		let tenant = "alice.example.com";
		for scope in [None, Some("file:f1~x:R")] {
			for subject in [tenant, "bob.example.com"] {
				if is_anonymous_share(scope, subject, tenant) {
					assert_eq!(
						subject_level(scope, subject, tenant, false, false),
						SubjectAccessLevel::Public
					);
				}
			}
		}
	}

	/// A scope does not *lower* a caller below what their relationship earns
	/// either — it only removes the owner shortcut.
	#[test]
	fn a_scope_leaves_the_relationship_levels_alone() {
		let tenant = "alice.example.com";
		assert_eq!(
			subject_level(Some("file:f1~x:R"), "bob.example.com", tenant, true, false),
			SubjectAccessLevel::Connected
		);
		assert_eq!(
			subject_level(Some("file:f1~x:R"), "bob.example.com", tenant, false, true),
			SubjectAccessLevel::Follower
		);
		assert_eq!(subject_level(None, "guest", tenant, false, false), SubjectAccessLevel::Public);
		assert_eq!(
			subject_level(None, "bob.example.com", tenant, false, false),
			SubjectAccessLevel::Verified
		);
	}

	#[test]
	fn an_over_long_filter_list_is_rejected() {
		let tags = (0..=SEARCH_MAX_TAGS).map(|i| format!("t{i}")).collect::<Vec<_>>().join(",");
		assert!(matches!(
			csv_filter(Some(&tags), SEARCH_MAX_TAGS, "tags"),
			Err(Error::ValidationError(_))
		));
		// Exactly at the cap is fine.
		let tags = (0..SEARCH_MAX_TAGS).map(|i| format!("t{i}")).collect::<Vec<_>>().join(",");
		assert_eq!(
			csv_filter(Some(&tags), SEARCH_MAX_TAGS, "tags").expect("ok").map(|v| v.len()),
			Some(SEARCH_MAX_TAGS)
		);
	}

	#[test]
	fn an_over_long_filter_entry_is_rejected() {
		let long = "x".repeat(MAX_FILTER_ENTRY_CHARS + 1);
		assert!(matches!(
			csv_filter(Some(&long), SEARCH_MAX_TAGS, "tags"),
			Err(Error::ValidationError(_))
		));
	}

	#[test]
	fn an_empty_filter_list_is_no_filter() {
		assert_eq!(csv_filter(None, SEARCH_MAX_TAGS, "tags").expect("ok"), None);
		assert_eq!(csv_filter(Some(" , "), SEARCH_MAX_TAGS, "tags").expect("ok"), None);
	}

	#[test]
	fn app_id_is_parsed_only_from_the_cloudillo_namespace() {
		assert_eq!(app_id_of("cloudillo/notillo"), Some("notillo"));
		assert_eq!(app_id_of("application/pdf"), None);
		assert_eq!(app_id_of("cloudillo/"), None);
	}

	#[test]
	fn the_kind_prefix_comes_off_the_wire_value() {
		assert_eq!(strip_kind("p/page1", Some("p")), "page1");
		// A row written before the namespacing, or one whose id happens not to
		// carry the prefix, passes through untouched.
		assert_eq!(strip_kind("page1", Some("p")), "page1");
		assert_eq!(strip_kind("p/page1", None), "p/page1");
	}
}

// vim: ts=4
