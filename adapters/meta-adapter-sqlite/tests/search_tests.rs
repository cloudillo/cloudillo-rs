// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Full-text search adapter tests.
//!
//! `fresh_db_has_the_fts5_virtual_table` is the standing regression guard that
//! FTS5 is compiled into the bundled SQLite — `libsqlite3-sys` enables it by
//! default and `LIBSQLITE3_FLAGS` in `.cargo/config.toml` only *adds* flags,
//! but a dependency bump could silently take it away.

#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use cloudillo_meta_adapter_sqlite::MetaAdapterSqlite;
use cloudillo_types::{
	error::Error,
	meta_adapter::{
		Action, ActionId, CreateFile, FileStatus, FinalizeActionOptions, ListActionOptions,
		ListFileOptions, ListProfileOptions, MANAGED_PARENT_ID, MetaAdapter, ProfileType,
		SearchObject, SearchOptions, SearchPart, SearchRow, TRASH_PARENT_ID, UpdateFileOptions,
		UpsertProfileFields,
	},
	types::{Patch, Timestamp, TnId},
	worker::WorkerPool,
};
use tempfile::TempDir;

/// Emit one `#[tokio::test]` per index route, so the contentless path gets
/// exactly the coverage the external-content one has.
///
/// The body takes `fts_cl` and threads it through every fixture helper: `false`
/// stores the extracted text in `search_docs.body` and indexes it through the
/// external-content `search_fts`, `true` stores no text and indexes it into the
/// contentless `search_fts_cl`. Everything a caller observes must match, apart
/// from `snippet`, which only the external route can produce.
macro_rules! both_modes {
	($( $(#[$attr:meta])* async fn $name:ident($cl:ident: bool) $body:block )+) => {$(
		$(#[$attr])*
		async fn $name($cl: bool) $body

		mod $name {
			#[tokio::test]
			async fn external_content() {
				super::$name(false).await;
			}
			#[tokio::test]
			async fn contentless() {
				super::$name(true).await;
			}
		}
	)+};
}

/// The same shape, on the external-content route only.
///
/// [`both_modes!`] is for behaviour the index route can actually change:
/// snippet production, the delete and cleanup paths, the hash short-circuit, and
/// route migration. Everything else here — tokenizer behaviour, the SQL
/// visibility and filter predicates, tag phrasing, `count` versus page — reaches
/// the same code whichever table the text landed in, so a second run buys a
/// second `TempDir` plus a full schema migration and no coverage.
///
/// The body still takes `fts_cl` so a test can be moved back to `both_modes!`
/// with a one-word edit if it ever grows a route-sensitive assertion.
macro_rules! one_mode {
	($( $(#[$attr:meta])* async fn $name:ident($cl:ident: bool) $body:block )+) => {$(
		$(#[$attr])*
		#[tokio::test]
		async fn $name() {
			let $cl = false;
			$body
		}
	)+};
}

async fn create_test_adapter() -> (MetaAdapterSqlite, TempDir) {
	let temp_dir = TempDir::new().expect("Failed to create temp directory");
	let worker_pool = Arc::new(WorkerPool::new(1, 1, 1));
	let adapter = MetaAdapterSqlite::new(worker_pool, temp_dir.path())
		.await
		.expect("Failed to create adapter");
	(adapter, temp_dir)
}

fn opts(q: &str, fts_cl: bool) -> SearchOptions {
	SearchOptions { q: q.into(), limit: 20, fts_cl, ..Default::default() }
}

/// Index one deep-document part with the given body.
async fn index_text(
	adapter: &MetaAdapterSqlite,
	tn_id: TnId,
	file_id: &str,
	body: &str,
	fts_cl: bool,
) {
	adapter
		.replace_search_object(
			tn_id,
			&SearchObject {
				obj_tp: 'D',
				obj_id: file_id,
				content_type: Some("cloudillo/notillo"),
				visibility: Some('P'),
				fts_cl,
				..Default::default()
			},
			&[SearchPart { part_id: "page1", body: Some(body), ..Default::default() }],
		)
		.await
		.expect("index");
}

async fn find(adapter: &MetaAdapterSqlite, tn_id: TnId, q: &str, fts_cl: bool) -> Vec<SearchRow> {
	adapter.search(tn_id, &opts(q, fts_cl)).await.expect("search")
}

/// Search as a follower of the tenant: the level set `SubjectAccessLevel::Follower`
/// yields, plus a viewer id_tag so the own-row and issuer arms can fire.
async fn find_as(
	adapter: &MetaAdapterSqlite,
	tn_id: TnId,
	q: &str,
	viewer: &str,
	fts_cl: bool,
) -> Vec<SearchRow> {
	let o = SearchOptions {
		visible_levels: Some(vec!['P', 'V', '2', 'F']),
		viewer_id_tag: Some(viewer.into()),
		..opts(q, fts_cl)
	};
	adapter.search(tn_id, &o).await.expect("search")
}

/// What `publish_action` needs to mint one action.
#[derive(Default)]
struct NewAction<'a> {
	action_id: &'a str,
	typ: &'a str,
	issuer_tag: &'a str,
	visibility: Option<char>,
	text: &'a str,
	subject: Option<&'a str>,
}

/// Index one file's `'F'` row the way `cloudillo_search::objects::index_file_row`
/// does.
///
/// This crate cannot reach that crate (dependency cycle), so the fixtures restate
/// the mapping: title = `file_name`, tags = the tag list respaced, nothing at all
/// for a file `objects::is_indexable` rejects — a deleted, trashed, managed or
/// hidden one. Managed files are the cached peer avatars, `'P'`-visible by
/// construction, so indexing them would expose the tenant's contact graph to an
/// unauthenticated search.
///
/// Deliberately narrower in one place: a *live published site container* is managed but
/// exempt, judged by `objects::is_live_site_indexable`. Restating that here would mean
/// restating `site_docs` liveness, and no fixture in this file publishes a site.
async fn index_file(adapter: &MetaAdapterSqlite, tn_id: TnId, file_id: &str, fts_cl: bool) {
	let file = adapter.read_file(tn_id, file_id).await.expect("read file").filter(|f| {
		f.parent_id.as_deref() != Some(TRASH_PARENT_ID)
			&& f.parent_id.as_deref() != Some(MANAGED_PARENT_ID)
			&& !f.hidden
			&& !matches!(f.status, FileStatus::Deleted)
	});
	let tags = file.as_ref().and_then(|f| f.tags.as_ref()).map(|t| t.join(" "));
	let part = file.as_ref().map(|f| SearchPart {
		title: Some(&*f.file_name),
		tags: tags.as_deref(),
		..Default::default()
	});
	adapter
		.replace_search_row(tn_id, 'F', file_id, part.as_slice(), fts_cl)
		.await
		.expect("index file");
}

/// Same, for a profile: title = `name`, body = `id_tag`.
///
/// Read through the listing rather than `read_profile`, exactly as `objects`
/// does — a row with a NULL `type` is a relationship placeholder, not a profile,
/// and neither the index nor any listing endpoint should see it.
async fn index_profile(adapter: &MetaAdapterSqlite, tn_id: TnId, id_tag: &str, fts_cl: bool) {
	let opts = ListProfileOptions { id_tag: Some(id_tag.to_owned()), ..Default::default() };
	let profile = adapter
		.list_profiles(tn_id, &opts)
		.await
		.expect("list profiles")
		.into_iter()
		.next();
	let part = profile.as_ref().map(|p| SearchPart {
		title: Some(&*p.name),
		body: Some(&*p.id_tag),
		..Default::default()
	});
	adapter
		.replace_search_row(tn_id, 'P', id_tag, part.as_slice(), fts_cl)
		.await
		.expect("index profile");
}

/// Same, for an action carrying a POST/CMNT/MSG-shaped `search` manifest: the
/// text out of `content`, and nothing at all unless the row is Active. An action
/// type with no manifest never reaches this in production, which is what the
/// SUBS fixtures below stand in for.
async fn index_action(adapter: &MetaAdapterSqlite, tn_id: TnId, action_id: &str, fts_cl: bool) {
	let action = adapter.get_action(tn_id, action_id).await.expect("get action");
	let body = action
		.as_ref()
		.filter(|a| a.status.as_deref() == Some("A"))
		.and_then(|a| a.content.as_ref())
		.and_then(|c| c.get("text"))
		.and_then(serde_json::Value::as_str)
		.filter(|t| !t.is_empty())
		.map(ToOwned::to_owned);
	let part = body.as_ref().map(|b| SearchPart { body: Some(b), ..Default::default() });
	adapter
		.replace_search_row(tn_id, 'A', action_id, part.as_slice(), fts_cl)
		.await
		.expect("index action");
}

/// Create an action, finalize it, and index it — the three steps a live write
/// path takes to publish an action.
async fn publish_action(adapter: &MetaAdapterSqlite, tn_id: TnId, a: NewAction<'_>, fts_cl: bool) {
	let content = serde_json::json!({ "text": a.text }).to_string();
	let id = adapter
		.create_action(
			tn_id,
			&Action {
				action_id: "",
				typ: a.typ,
				sub_typ: None,
				issuer_tag: a.issuer_tag,
				parent_id: None,
				root_id: None,
				audience_tag: None,
				content: Some(&content),
				attachments: None,
				subject: a.subject,
				created_at: Timestamp::now(),
				expires_at: None,
				visibility: a.visibility,
				flags: None,
				x: None,
			},
			None,
		)
		.await
		.expect("create action");
	let ActionId::AId(a_id) = id else { panic!("expected an internal a_id") };
	adapter
		.finalize_action(tn_id, a_id, a.action_id, FinalizeActionOptions::default())
		.await
		.expect("finalize");
	index_action(adapter, tn_id, a.action_id, fts_cl).await;
}

both_modes! {
	async fn fresh_db_has_the_fts5_virtual_table(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);

		// Only a working FTS5 module lets this round-trip at all.
		index_text(&adapter, tn_id, "f1~a", "hello indexed world", fts_cl).await;
		let hits = find(&adapter, tn_id, "indexed", fts_cl).await;
		assert_eq!(hits.len(), 1);
		assert_eq!(&*hits[0].obj_id, "f1~a");
		assert_eq!(&*hits[0].part_id, "page1");
	}
}

both_modes! {
	async fn fts_mirror_follows_insert_update_and_delete(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);

		index_text(&adapter, tn_id, "f1~a", "alpha content", fts_cl).await;
		assert_eq!(find(&adapter, tn_id, "alpha", fts_cl).await.len(), 1);

		// `replace_search_object` deletes then reinserts — the old text must go.
		index_text(&adapter, tn_id, "f1~a", "bravo content", fts_cl).await;
		assert!(find(&adapter, tn_id, "alpha", fts_cl).await.is_empty(), "stale FTS row survived replace");
		assert_eq!(find(&adapter, tn_id, "bravo", fts_cl).await.len(), 1);

		adapter.delete_search_object(tn_id, 'D', "f1~a").await.expect("delete");
		assert!(find(&adapter, tn_id, "bravo", fts_cl).await.is_empty(), "stale FTS row survived delete");
	}
}

one_mode! {
	async fn diacritics_are_folded_both_ways(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);

		index_text(&adapter, tn_id, "f1~a", "Keresés a dokumentumban", fts_cl).await;

		assert_eq!(find(&adapter, tn_id, "kereses", fts_cl).await.len(), 1, "unaccented query must match");
		assert_eq!(find(&adapter, tn_id, "Keresés", fts_cl).await.len(), 1, "accented query must match");
	}
}

one_mode! {
	async fn hashtags_are_single_tokens(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);

		index_text(&adapter, tn_id, "f1~a", "napi jegyzet #projekt", fts_cl).await;

		assert_eq!(find(&adapter, tn_id, "#projekt", fts_cl).await.len(), 1);
		// Mid-token substrings never match a token-based index.
		assert!(find(&adapter, tn_id, "rojek", fts_cl).await.is_empty());
	}
}

one_mode! {
	async fn only_the_last_term_prefix_matches(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);

		index_text(&adapter, tn_id, "f1~a", "keresés a dokumentumban", fts_cl).await;

		assert_eq!(find(&adapter, tn_id, "keres", fts_cl).await.len(), 1, "type-ahead prefix must match");
		assert_eq!(find(&adapter, tn_id, "keresés doku", fts_cl).await.len(), 1);
		// The leading term is exact, so a truncated one cannot match.
		assert!(find(&adapter, tn_id, "keres dokumentumban", fts_cl).await.is_empty());
	}
}

both_modes! {
	async fn snippet_marks_the_hit(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);

		index_text(&adapter, tn_id, "f1~a", "the quick brown fox jumps", fts_cl).await;

		let hits = find(&adapter, tn_id, "brown", fts_cl).await;
		if fts_cl {
			// Highlighting an excerpt needs the stored text this route drops, so
			// the hit is honest about having none rather than guessing.
			assert_eq!(hits[0].snippet, None);
			assert!(hits[0].snippet_matches.is_none(), "no snippet, so no ranges");
		} else {
			let snippet = hits[0].snippet.as_deref().expect("snippet");
			// The excerpt is plain text; the highlight is the range beside it.
			assert!(!snippet.contains("<mark>"), "unexpected markup: {snippet}");
			let matches = hits[0].snippet_matches.as_deref().expect("ranges");
			let m = matches.first().expect("a match range");
			// Slicing a UTF-16 offset by byte index is sound *here only* because
			// this fixture is pure ASCII. See `split_snippet_counts_utf16_units`
			// in `src/search.rs` for the case where the two units diverge.
			assert_eq!(&snippet[m.start as usize..m.end as usize], "brown");
		}
	}
}

one_mode! {
	/// A document *about* HTML keeps the literal string in its excerpt, and the
	/// stray opener does not swallow the real match's delimiter and spread the
	/// highlight over unmatched text. No attacker required to hit this.
	async fn a_literal_mark_tag_in_the_body_survives_and_does_not_widen_the_range(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);

		index_text(&adapter, tn_id, "f1~a", "wrap it in <mark>needle</mark> to emphasise", fts_cl)
			.await;

		let hits = find(&adapter, tn_id, "needle", fts_cl).await;
		let snippet = hits[0].snippet.as_deref().expect("snippet");
		assert!(snippet.contains("<mark>needle</mark>"), "text was deleted: {snippet}");

		let matches = hits[0].snippet_matches.as_deref().expect("ranges");
		assert_eq!(matches.len(), 1, "the literal tag must not open a range: {matches:?}");
		let m = matches[0];
		assert_eq!(&snippet[m.start as usize..m.end as usize], "needle");
	}
}

one_mode! {
	/// The sentinels are control characters no prose contains, and they are
	/// stripped on the way into the index besides, so a body carrying one cannot
	/// come back out of `snippet()` looking like a highlight.
	async fn an_injected_sentinel_cannot_forge_a_range(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);

		index_text(&adapter, tn_id, "f1~a", "alpha \u{2}beta\u{3} needle gamma", fts_cl).await;

		let hits = find(&adapter, tn_id, "needle", fts_cl).await;
		let snippet = hits[0].snippet.as_deref().expect("snippet");
		assert!(!snippet.contains('\u{2}') && !snippet.contains('\u{3}'), "sentinel leaked");

		let matches = hits[0].snippet_matches.as_deref().expect("ranges");
		assert_eq!(matches.len(), 1, "only the real match may be a range: {matches:?}");
		assert_eq!(&snippet[matches[0].start as usize..matches[0].end as usize], "needle");
	}
}

one_mode! {
	/// Every matched term is emphasised, not just the first.
	async fn every_matched_term_gets_a_range(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);

		index_text(&adapter, tn_id, "f1~a", "the quick brown fox jumps", fts_cl).await;

		let hits = find(&adapter, tn_id, "quick fox", fts_cl).await;
		let snippet = hits[0].snippet.as_deref().expect("snippet");
		let matches = hits[0].snippet_matches.as_deref().expect("ranges");
		assert_eq!(matches.len(), 2, "both terms must be emphasised: {matches:?}");
		assert!(matches[0].end <= matches[1].start, "ranges must be ascending and disjoint");
		assert_eq!(&snippet[matches[0].start as usize..matches[0].end as usize], "quick");
		assert_eq!(&snippet[matches[1].start as usize..matches[1].end as usize], "fox");
	}
}

one_mode! {
	async fn visible_levels_filter_out_hidden_rows(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);

		for (file_id, visibility) in [("f1~pub", Some('P')), ("f1~conn", Some('C')), ("f1~dir", None)] {
			adapter
				.replace_search_object(
					tn_id,
					&SearchObject {
						obj_tp: 'F',
						obj_id: file_id,
						owner_tag: Some("alice"),
						visibility,
						fts_cl,
						..Default::default()
					},
					&[SearchPart { body: Some("shared secret"), ..Default::default() }],
				)
				.await
				.expect("index");
		}

		// Owner / tenant: no level filter at all, Direct included.
		assert_eq!(find(&adapter, tn_id, "secret", fts_cl).await.len(), 3);

		let public_only = SearchOptions { visible_levels: Some(vec!['P']), ..opts("secret", fts_cl) };
		assert_eq!(adapter.search(tn_id, &public_only).await.expect("search").len(), 1);

		let connected =
			SearchOptions { visible_levels: Some(vec!['P', 'V', '2', 'F', 'C']), ..opts("secret", fts_cl) };
		assert_eq!(adapter.search(tn_id, &connected).await.expect("search").len(), 2);

		// `owner_tag` does *not* exempt a row from the level predicate. It is the
		// raw `files.owner_tag` column — NULL for a tenant-owned file, set only on
		// a cross-context Pin/Place copy — so an exemption here would fire exactly
		// when a federated peer searches a copy this tenant pinned, and hand them
		// rows `GET /api/files` denies. `file::list` has no such exemption either.
		// See `a_pinned_copys_owner_does_not_bypass_the_level_predicate`.
		let as_owner = SearchOptions {
			visible_levels: Some(vec!['P']),
			viewer_id_tag: Some("alice".into()),
			..opts("secret", fts_cl)
		};
		assert_eq!(adapter.search(tn_id, &as_owner).await.expect("search").len(), 1);
	}
}

one_mode! {
	async fn scope_file_id_confines_results_to_one_document_tree(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);

		// The container file itself...
		adapter
			.replace_search_object(
				tn_id,
				&SearchObject { obj_tp: 'F', obj_id: "f1~doc", fts_cl,
						..Default::default() },
				&[SearchPart { body: Some("shared token"), ..Default::default() }],
			)
			.await
			.expect("index");
		// ...its deep parts, linked by root_id...
		adapter
			.replace_search_object(
				tn_id,
				&SearchObject {
					obj_tp: 'D',
					obj_id: "f1~doc",
					root_id: Some("f1~doc"),
					fts_cl,
						..Default::default()
				},
				&[SearchPart { part_id: "p1", body: Some("shared token"), ..Default::default() }],
			)
			.await
			.expect("index");
		// ...and an unrelated document that must never leak.
		adapter
			.replace_search_object(
				tn_id,
				&SearchObject { obj_tp: 'D', obj_id: "f1~other", fts_cl,
						..Default::default() },
				&[SearchPart { part_id: "p1", body: Some("shared token"), ..Default::default() }],
			)
			.await
			.expect("index");

		assert_eq!(find(&adapter, tn_id, "token", fts_cl).await.len(), 3);

		let scoped = SearchOptions { scope_file_id: Some("f1~doc".into()), ..opts("token", fts_cl) };
		let hits = adapter.search(tn_id, &scoped).await.expect("search");
		assert_eq!(hits.len(), 2);
		assert!(hits.iter().all(|h| &*h.obj_id == "f1~doc"));
	}
}

one_mode! {
	/// A scope **narrows**; it is not a grant. `get_search` derives
	/// `visible_levels` for every caller and only then applies `scope_file_id`, so
	/// a share-link guest holding `file:R:R` sees the tree's *Public* rows and no
	/// more. Handing such a caller `visible_levels = None` — the tenant-owner
	/// setting — would leak titles, tags and highlighted snippets for exactly the
	/// Direct children `GET /api/files` denies them.
	async fn a_scope_does_not_widen_the_visibility_levels(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();

		// A Public container...
		adapter
			.replace_search_object(
				tn_id,
				&SearchObject {
					obj_tp: 'F',
					obj_id: "f1~root",
					visibility: Some('P'),
					fts_cl,
					..Default::default()
				},
				&[SearchPart { body: Some("shared token"), ..Default::default() }],
			)
			.await
			.expect("index");
		// ...holding a Direct child. NULL visibility is "Direct": tenant owner only.
		adapter
			.replace_search_object(
				tn_id,
				&SearchObject {
					obj_tp: 'D',
					obj_id: "f1~child",
					root_id: Some("f1~root"),
					visibility: None,
					fts_cl,
					..Default::default()
				},
				&[SearchPart { part_id: "p1", body: Some("shared token"), ..Default::default() }],
			)
			.await
			.expect("index");

		// A share-link guest: inside the scope, but only at Public level.
		let guest = SearchOptions {
			scope_file_id: Some("f1~root".into()),
			visible_levels: Some(vec!['P']),
			viewer_id_tag: Some("guest".into()),
			..opts("token", fts_cl)
		};
		let hits = adapter.search(tn_id, &guest).await.expect("search");
		assert_eq!(hits.len(), 1, "the Direct child leaked to a scoped guest");
		assert_eq!(&*hits[0].obj_id, "f1~root");
		assert_eq!(adapter.count_search(tn_id, &guest).await.expect("count"), 1);

		// The tenant owner, unscoped, still finds both.
		assert_eq!(find(&adapter, tn_id, "token", fts_cl).await.len(), 2);
	}
}

one_mode! {
	async fn obj_tp_and_content_type_filters_narrow_results(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);

		adapter
			.replace_search_object(
				tn_id,
				&SearchObject {
					obj_tp: 'F',
					obj_id: "f1~a",
					content_type: Some("text/plain"),
					fts_cl,
						..Default::default()
				},
				&[SearchPart { body: Some("common word"), ..Default::default() }],
			)
			.await
			.expect("index");
		adapter
			.replace_search_object(
				tn_id,
				&SearchObject {
					obj_tp: 'A',
					obj_id: "a1~b",
					content_type: Some("cloudillo/action"),
					fts_cl,
						..Default::default()
				},
				&[SearchPart { body: Some("common word"), ..Default::default() }],
			)
			.await
			.expect("index");

		let files = SearchOptions { obj_tp: Some(vec!['F']), ..opts("common", fts_cl) };
		assert_eq!(adapter.search(tn_id, &files).await.expect("search").len(), 1);

		let by_ct = SearchOptions { content_type: Some(vec!["text/plain".into()]), ..opts("common", fts_cl) };
		let hits = adapter.search(tn_id, &by_ct).await.expect("search");
		assert_eq!(hits.len(), 1);
		assert_eq!(&*hits[0].obj_id, "f1~a");

		// An *empty* type list is what the handler passes on when every name in a
		// caller's `?type=` was unknown to this build. It means "no such results" —
		// reading it as "no filter" would widen the query to every object type.
		let none = SearchOptions { obj_tp: Some(vec![]), ..opts("common", fts_cl) };
		assert!(adapter.search(tn_id, &none).await.expect("search").is_empty());
		assert_eq!(adapter.count_search(tn_id, &none).await.expect("count"), 0);
		// Absent, on the other hand, still means unfiltered.
		assert_eq!(adapter.search(tn_id, &opts("common", fts_cl)).await.expect("search").len(), 2);
	}
}

one_mode! {
	async fn empty_query_is_a_validation_error_not_a_match_all(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);

		index_text(&adapter, tn_id, "f1~a", "something", fts_cl).await;

		assert!(adapter.search(tn_id, &opts("   ", fts_cl)).await.is_err());
		assert!(adapter.search(tn_id, &opts(r#" *"( "#, fts_cl)).await.is_err());
	}
}

both_modes! {
	async fn tenant_purge_clears_search_rows_and_their_fts_entries(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		let other = TnId(2);
		adapter.create_tenant(tn_id, "alice").await.ok();
		adapter.create_tenant(other, "bob").await.ok();

		index_text(&adapter, tn_id, "f1~a", "purgeable content", fts_cl).await;
		index_text(&adapter, other, "f1~b", "purgeable content", fts_cl).await;

		adapter.delete_tenant(tn_id).await.expect("delete tenant");

		assert!(find(&adapter, tn_id, "purgeable", fts_cl).await.is_empty());
		// The other tenant's row — and its FTS entry — must survive intact.
		assert_eq!(find(&adapter, other, "purgeable", fts_cl).await.len(), 1);
	}
}

// --- whole-object rows -----------------------------------------------------
//
// These go through the ordinary adapter write paths, then through
// `replace_search_row` exactly as `cloudillo_search::objects` would. What they
// really test is that `replace_search_row` derives its ACL columns from the
// source row correctly — the caller supplies only title/body/tags.

one_mode! {
	async fn writing_a_file_makes_it_searchable_by_name_and_tags(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();

		adapter
			.create_file(
				tn_id,
				CreateFile {
					file_id: Some("f1~doc".into()),
					content_type: "text/plain".into(),
					file_name: "Költségvetés 2026.txt".into(),
					file_tp: Some("BLOB".into()),
					status: Some(FileStatus::Active),
					tags: Some(vec!["munka".into(), "penzugy".into()]),
					visibility: Some('P'),
					..Default::default()
				},
			)
			.await
			.expect("create file");
		index_file(&adapter, tn_id, "f1~doc", fts_cl).await;

		// Diacritic folding applies to file names too.
		let hits = find(&adapter, tn_id, "koltsegvetes", fts_cl).await;
		assert_eq!(hits.len(), 1);
		assert_eq!(hits[0].obj_tp, 'F');
		assert_eq!(&*hits[0].obj_id, "f1~doc");

		// The comma-joined tags column is respaced so each tag is its own token.
		assert_eq!(find(&adapter, tn_id, "penzugy", fts_cl).await.len(), 1);
	}
}

both_modes! {
	async fn soft_deleting_a_file_removes_it_and_its_deep_parts_at_once(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();

		adapter
			.create_file(
				tn_id,
				CreateFile {
					file_id: Some("f1~doc".into()),
					content_type: "cloudillo/notillo".into(),
					file_name: "Jegyzetek".into(),
					file_tp: Some("RTDB".into()),
					status: Some(FileStatus::Active),
					visibility: Some('P'),
					..Default::default()
				},
			)
			.await
			.expect("create file");
		index_file(&adapter, tn_id, "f1~doc", fts_cl).await;
		// A deep part, as the document indexer would write it.
		index_text(&adapter, tn_id, "f1~doc", "titkos tartalom", fts_cl).await;

		assert_eq!(find(&adapter, tn_id, "Jegyzetek", fts_cl).await.len(), 1);
		assert_eq!(find(&adapter, tn_id, "titkos", fts_cl).await.len(), 1);

		adapter
			.update_file_data(
				tn_id,
				"f1~doc",
				&UpdateFileOptions { status: Patch::Value('D'), ..Default::default() },
			)
			.await
			.expect("soft delete");
		index_file(&adapter, tn_id, "f1~doc", fts_cl).await;

		assert!(find(&adapter, tn_id, "Jegyzetek", fts_cl).await.is_empty(), "file row survived deletion");
		assert!(
			find(&adapter, tn_id, "titkos", fts_cl).await.is_empty(),
			"deep parts of a deleted document must stop being searchable immediately"
		);
	}
}

one_mode! {
	async fn renaming_a_file_replaces_the_old_text(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();

		adapter
			.create_file(
				tn_id,
				CreateFile {
					file_id: Some("f1~doc".into()),
					content_type: "text/plain".into(),
					file_name: "regi.txt".into(),
					file_tp: Some("BLOB".into()),
					status: Some(FileStatus::Active),
					..Default::default()
				},
			)
			.await
			.expect("create file");

		adapter
			.update_file_data(
				tn_id,
				"f1~doc",
				&UpdateFileOptions {
					file_name: Patch::Value("ujnev.txt".into()),
					..Default::default()
				},
			)
			.await
			.expect("rename");
		index_file(&adapter, tn_id, "f1~doc", fts_cl).await;

		assert!(find(&adapter, tn_id, "regi", fts_cl).await.is_empty(), "stale name still matches");
		assert_eq!(find(&adapter, tn_id, "ujnev", fts_cl).await.len(), 1);
	}
}

one_mode! {
	async fn upserting_a_profile_makes_it_searchable_by_name_and_tag(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();

		adapter
			.upsert_profile(
				tn_id,
				"bob.example.com",
				&UpsertProfileFields {
					name: Patch::Value("Bob Példa".into()),
					// A row with no `type` is a relationship placeholder that no
					// listing — and so no index — should see.
					typ: Patch::Value(ProfileType::Person),
					..Default::default()
				},
			)
			.await
			.expect("upsert profile");
		index_profile(&adapter, tn_id, "bob.example.com", fts_cl).await;

		let by_name = find(&adapter, tn_id, "pelda", fts_cl).await;
		assert_eq!(by_name.len(), 1);
		assert_eq!(by_name[0].obj_tp, 'P');
		assert_eq!(&*by_name[0].obj_id, "bob.example.com");

		assert_eq!(find(&adapter, tn_id, "bob.example.com", fts_cl).await.len(), 1);
	}
}

one_mode! {
	async fn an_action_becomes_searchable_only_once_it_is_active(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();

		let content = serde_json::json!({ "text": "Egy nyilvános bejegyzés #projekt" }).to_string();
		let id = adapter
			.create_action(
				tn_id,
				&Action {
					// Local creation leaves the id empty; `finalize_action` assigns
					// it and flips status 'P' -> 'A'.
					action_id: "",
					typ: "POST",
					sub_typ: None,
					issuer_tag: "alice",
					parent_id: None,
					root_id: None,
					audience_tag: None,
					content: Some(&content),
					attachments: None,
					subject: None,
					created_at: Timestamp::now(),
					expires_at: None,
					visibility: Some('P'),
					flags: None,
					x: None,
				},
				None,
			)
			.await
			.expect("create action");

		// Created as Pending, with no `action_id` yet — nothing to find.
		assert!(
			find(&adapter, tn_id, "bejegyzes", fts_cl).await.is_empty(),
			"a pending action must not be searchable"
		);

		let a_id = match id {
			ActionId::AId(a_id) => a_id,
			ActionId::ActionId(_) => panic!("expected an internal a_id"),
		};
		adapter
			.finalize_action(tn_id, a_id, "a1~post", FinalizeActionOptions::default())
			.await
			.expect("finalize");
		index_action(&adapter, tn_id, "a1~post", fts_cl).await;

		let hits = find(&adapter, tn_id, "bejegyzes", fts_cl).await;
		assert_eq!(hits.len(), 1, "finalizing must publish the action to the index");
		assert_eq!(hits[0].obj_tp, 'A');
		assert_eq!(&*hits[0].obj_id, "a1~post");
		// `tokenchars '#'` is what makes hashtag search work without a LIKE scan.
		assert_eq!(find(&adapter, tn_id, "#projekt", fts_cl).await.len(), 1);

		adapter.delete_action(tn_id, "a1~post").await.expect("delete action");
		index_action(&adapter, tn_id, "a1~post", fts_cl).await;
		assert!(
			find(&adapter, tn_id, "bejegyzes", fts_cl).await.is_empty(),
			"a deleted action must stop being searchable"
		);
	}
}

both_modes! {
	async fn a_source_row_that_vanishes_takes_its_index_row_with_it(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();

		// `replace_search_row` derives the ACL columns from the source row, so with
		// no source row there is nothing to derive and the write becomes a delete.
		// That is what keeps a stale row from outliving a file deleted between the
		// caller's read and the index run.
		let part = SearchPart { title: Some("kiserteties"), ..Default::default() };
		adapter
			.replace_search_row(tn_id, 'F', "f1~ghost", std::slice::from_ref(&part), fts_cl)
			.await
			.expect("index ghost");
		assert!(
			find(&adapter, tn_id, "kiserteties", fts_cl).await.is_empty(),
			"an index row must never outlive the source row it mirrors"
		);
	}
}

both_modes! {
	/// The orphan sweep decides on the *container*, never on the part.
	///
	/// A `'D'` row's `obj_id` is its container `file_id`, so "is the `files` row
	/// still there" is as answerable for a part as for the file's own row — and it
	/// is the only question this sweep asks. Which parts a living document should
	/// have is `cloudillo-search`'s call, and the sweep must not second-guess it.
	/// The orphan half is
	/// [`the_orphan_sweep_reaps_deep_rows_of_a_deleted_file`].
	async fn reap_leaves_the_deep_parts_of_a_living_file_alone(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();

		create_doc_file(&adapter, tn_id, "f1~doc", None).await;
		index_text(&adapter, tn_id, "f1~doc", "melyen indexelt", fts_cl).await;
		adapter.reap_search_orphans(tn_id).await.expect("reap");

		assert_eq!(
			find(&adapter, tn_id, "melyen", fts_cl).await.len(),
			1,
			"the sweep took a part of a file that is still there"
		);
	}
}

one_mode! {
	async fn count_reports_the_whole_match_set_not_the_page(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		for i in 0..5 {
			index_text(&adapter, tn_id, &format!("f1~d{i}"), "kozos szo", fts_cl).await;
		}

		// The handler's only has-more signal: derived from a page alone it would
		// always equal `offset + len` and every page would look like the last.
		let page = SearchOptions { limit: 2, offset: 2, ..opts("kozos", fts_cl) };
		assert_eq!(adapter.search(tn_id, &page).await.expect("search").len(), 2);
		assert_eq!(adapter.count_search(tn_id, &page).await.expect("count"), 5);
	}
}

both_modes! {
	async fn dropping_a_content_types_rules_spares_the_files_own_rows(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();

		adapter
			.create_file(
				tn_id,
				CreateFile {
					file_id: Some("f1~doc".into()),
					content_type: "cloudillo/notillo".into(),
					file_name: "Jegyzetek".into(),
					file_tp: Some("RTDB".into()),
					status: Some(FileStatus::Active),
					visibility: Some('P'),
					..Default::default()
				},
			)
			.await
			.expect("create file");
		index_file(&adapter, tn_id, "f1~doc", fts_cl).await;
		index_text(&adapter, tn_id, "f1~doc", "melyen indexelt", fts_cl).await;

		adapter
			.delete_deep_search_by_content_type(tn_id, "cloudillo/notillo")
			.await
			.expect("drop deep rows");

		assert!(
			find(&adapter, tn_id, "melyen", fts_cl).await.is_empty(),
			"the deep parts a changed manifest produced must go"
		);
		// The `'F'` row carries the same content_type but is server-owned, and the
		// content-type sweep that follows rebuilds deep parts only — taking it here
		// would make the file unfindable by name until the weekly sweep.
		assert_eq!(
			find(&adapter, tn_id, "Jegyzetek", fts_cl).await.len(),
			1,
			"the file's own row must survive a manifest change"
		);
	}
}

// --- ACL mirror ------------------------------------------------------------

one_mode! {
	async fn changing_a_files_visibility_updates_its_deep_parts(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();

		adapter
			.create_file(
				tn_id,
				CreateFile {
					file_id: Some("f1~doc".into()),
					content_type: "cloudillo/notillo".into(),
					file_name: "Jegyzetek".into(),
					file_tp: Some("RTDB".into()),
					status: Some(FileStatus::Active),
					visibility: Some('P'),
					..Default::default()
				},
			)
			.await
			.expect("create file");
		index_file(&adapter, tn_id, "f1~doc", fts_cl).await;
		index_text(&adapter, tn_id, "f1~doc", "titkos tartalom", fts_cl).await;

		// Public: a follower of the tenant finds the deep part and the file itself.
		assert_eq!(find_as(&adapter, tn_id, "titkos", "bob", fts_cl).await.len(), 1);
		assert_eq!(find_as(&adapter, tn_id, "Jegyzetek", "bob", fts_cl).await.len(), 1);

		adapter
			.update_file_data(
				tn_id,
				"f1~doc",
				&UpdateFileOptions { visibility: Patch::Null, ..Default::default() },
			)
			.await
			.expect("make direct");
		// The `'F'` arm of `replace_search_row` refreshes the deep rows' ACL columns
		// as a side effect — the whole reason the ACL half stayed in SQL. The
		// refresh is guarded on an actual column change (see `renaming_a_file_…`
		// below); this is the direction that guard must never break.
		index_file(&adapter, tn_id, "f1~doc", fts_cl).await;

		// Direct: the deep parts must stop being visible at once, not at the next
		// document edit or weekly sweep.
		assert!(
			find_as(&adapter, tn_id, "titkos", "bob", fts_cl).await.is_empty(),
			"the deep rows kept a stale ACL mirror after the file went Direct"
		);
		// And so must the file's own `'F'` row. The re-index above hashes title and
		// tags only — neither moved — so it takes the short-circuit and never
		// reaches the upsert that re-derives the ACL columns. The refresh below it
		// is therefore the *only* statement that can update this row, which is why
		// it must run on every path rather than just the upsert one.
		assert!(
			find_as(&adapter, tn_id, "Jegyzetek", "bob", fts_cl).await.is_empty(),
			"the file's own row stayed publicly findable after it went Direct"
		);
		// The owner still sees everything.
		assert_eq!(find(&adapter, tn_id, "titkos", fts_cl).await.len(), 1);
		assert_eq!(find(&adapter, tn_id, "Jegyzetek", fts_cl).await.len(), 1);
	}
}

one_mode! {
	/// The converse of the test above. The ACL refresh is a no-op when no ACL
	/// column moved, so a rename does not fire `search_docs_au` for a document's
	/// deep rows — on a 5000-page file that trigger is 5000 FTS5 delete +
	/// re-insert pairs for nothing. The saving itself is invisible from outside;
	/// what is observable, and asserted here, is that a rename leaves the deep
	/// rows' text, `s_id` and `updated_at` exactly as they were.
	async fn renaming_a_file_leaves_its_deep_parts_untouched(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();

		adapter
			.create_file(
				tn_id,
				CreateFile {
					file_id: Some("f1~doc".into()),
					content_type: "cloudillo/notillo".into(),
					file_name: "Jegyzetek".into(),
					file_tp: Some("RTDB".into()),
					status: Some(FileStatus::Active),
					visibility: Some('P'),
					..Default::default()
				},
			)
			.await
			.expect("create file");
		index_file(&adapter, tn_id, "f1~doc", fts_cl).await;
		index_text(&adapter, tn_id, "f1~doc", "titkos tartalom", fts_cl).await;

		let before = find(&adapter, tn_id, "titkos", fts_cl).await;
		assert_eq!(before.len(), 1);

		adapter
			.update_file_data(
				tn_id,
				"f1~doc",
				&UpdateFileOptions {
					file_name: Patch::Value("Jegyzetek2".into()),
					..Default::default()
				},
			)
			.await
			.expect("rename");
		index_file(&adapter, tn_id, "f1~doc", fts_cl).await;

		let after = find(&adapter, tn_id, "titkos", fts_cl).await;
		assert_eq!(after.len(), 1, "the rename must not disturb the deep rows");
		assert_eq!(after[0].s_id, before[0].s_id);
		assert_eq!(after[0].updated_at.0, before[0].updated_at.0);
		assert_eq!(after[0].title, before[0].title);
		assert_eq!(after[0].snippet, before[0].snippet);
		// The file's own row did follow the rename.
		assert_eq!(find(&adapter, tn_id, "Jegyzetek2", fts_cl).await.len(), 1);
		// …carrying its unchanged ACL columns. The refresh runs for the `'F'` row
		// too now, so this is the direction its `IS NOT` guard must not break:
		// the file is still Public and a follower still finds it.
		assert_eq!(find_as(&adapter, tn_id, "Jegyzetek2", "bob", fts_cl).await.len(), 1);
	}
}

one_mode! {
	/// The index is only ever written by an explicit `replace_search_row` call, so
	/// no adapter method can quietly rewrite a row as a side effect. The write
	/// paths that must *not* make that call — `record_file_access` and the other
	/// timestamp bumps — are gated in `cloudillo-file`; this is the adapter-side
	/// half of that invariant.
	async fn bumping_accessed_at_does_not_touch_the_index(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();

		adapter
			.create_file(
				tn_id,
				CreateFile {
					file_id: Some("f1~doc".into()),
					content_type: "text/plain".into(),
					file_name: "olvasando.txt".into(),
					file_tp: Some("BLOB".into()),
					status: Some(FileStatus::Active),
					..Default::default()
				},
			)
			.await
			.expect("create file");
		index_file(&adapter, tn_id, "f1~doc", fts_cl).await;
		assert_eq!(find(&adapter, tn_id, "olvasando", fts_cl).await.len(), 1);

		// Clear the index row, then bump `accessed_at`. `unixepoch()` has one-second
		// granularity, so comparing `updated_at` would prove nothing inside a test
		// run — observing that the row stays gone does.
		adapter.delete_search_object(tn_id, 'F', "f1~doc").await.expect("clear");
		adapter.record_file_access(tn_id, "alice", "f1~doc").await.expect("access");
		assert!(
			find(&adapter, tn_id, "olvasando", fts_cl).await.is_empty(),
			"a plain read must not rewrite the index row"
		);

		// An explicit index call after a real change brings it back.
		adapter
			.update_file_data(
				tn_id,
				"f1~doc",
				&UpdateFileOptions {
					file_name: Patch::Value("olvasando2.txt".into()),
					..Default::default()
				},
			)
			.await
			.expect("rename");
		index_file(&adapter, tn_id, "f1~doc", fts_cl).await;
		assert_eq!(find(&adapter, tn_id, "olvasando2", fts_cl).await.len(), 1);
	}
}

// --- per-object-type visibility --------------------------------------------

one_mode! {
	async fn action_visibility_follows_the_issuer_not_the_tenant(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();

		// A follower-only post federated in from an issuer the tenant does not
		// follow. `bob` following the *tenant* says nothing about `carol`.
		adapter
			.upsert_profile(
				tn_id,
				"carol.example",
				&UpsertProfileFields {
					name: Patch::Value("Carol".into()),
					typ: Patch::Value(ProfileType::Person),
					following: Patch::Value(false),
					..Default::default()
				},
			)
			.await
			.expect("upsert issuer profile");
		index_profile(&adapter, tn_id, "carol.example", fts_cl).await;
		publish_action(
			&adapter,
			tn_id,
			NewAction {
				action_id: "a1~post",
				typ: "POST",
				issuer_tag: "carol.example",
				visibility: Some('F'),
				text: "kovetoknek szolo bejegyzes",
				..Default::default()
			},
			fts_cl,
		)
		.await;

		assert!(
			find_as(&adapter, tn_id, "kovetoknek", "bob.example", fts_cl).await.is_empty(),
			"a follower-only post must stay hidden while its issuer is not followed"
		);

		adapter
			.upsert_profile(
				tn_id,
				"carol.example",
				&UpsertProfileFields { following: Patch::Value(true), ..Default::default() },
			)
			.await
			.expect("follow issuer");

		assert_eq!(
			find_as(&adapter, tn_id, "kovetoknek", "bob.example", fts_cl).await.len(),
			1,
			"following the issuer must reveal their follower-only post"
		);
	}
}

one_mode! {
	async fn a_subscribed_action_needs_an_active_subs_row(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();

		publish_action(
			&adapter,
			tn_id,
			NewAction {
				action_id: "a1~conv",
				typ: "CONV",
				issuer_tag: "carol.example",
				visibility: Some('S'),
				text: "elofizeteses beszelgetes",
				..Default::default()
			},
			fts_cl,
		)
		.await;

		assert!(
			find_as(&adapter, tn_id, "elofizeteses", "bob.example", fts_cl).await.is_empty(),
			"a Subscribed action must stay hidden without a SUBS row"
		);

		// A SUBS action is not itself indexable; it only has to exist and be Active.
		publish_action(
			&adapter,
			tn_id,
			NewAction {
				action_id: "a1~subs",
				typ: "SUBS",
				issuer_tag: "bob.example",
				visibility: Some('P'),
				subject: Some("a1~conv"),
				..Default::default()
			},
			fts_cl,
		)
		.await;

		assert_eq!(
			find_as(&adapter, tn_id, "elofizeteses", "bob.example", fts_cl).await.len(),
			1,
			"an active SUBS row must reveal the subscribed action"
		);
	}
}

one_mode! {
	async fn profiles_are_searchable_by_any_authenticated_caller(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();

		adapter
			.upsert_profile(
				tn_id,
				"carol.example",
				&UpsertProfileFields {
					name: Patch::Value("Karolina".into()),
					typ: Patch::Value(ProfileType::Person),
					..Default::default()
				},
			)
			.await
			.expect("upsert profile");
		index_profile(&adapter, tn_id, "carol.example", fts_cl).await;

		// Profiles are tenant-scoped and carry no per-profile ACL — the same rule
		// `GET /api/profiles` applies. Even the narrowest level set finds them.
		let narrow = SearchOptions {
			visible_levels: Some(vec!['P']),
			viewer_id_tag: Some("bob.example".into()),
			..opts("karolina", fts_cl)
		};
		let hits = adapter.search(tn_id, &narrow).await.expect("search");
		assert_eq!(hits.len(), 1);
		assert_eq!(hits[0].obj_tp, 'P');
	}
}

one_mode! {
	/// What an unauthenticated caller gets: `SubjectAccessLevel::Public`'s level
	/// set, plus the `'P'` object type struck out of `obj_tp` by
	/// `cloudillo_search::handler::guest_obj_tp`.
	///
	/// The type filter is load-bearing, not belt-and-braces: the SQL prefilter
	/// deliberately exempts profile rows from the visibility predicate — see
	/// `profiles_are_searchable_by_any_authenticated_caller` — so `visible_levels`
	/// alone would still hand a guest the tenant's whole contact graph.
	async fn a_guest_sees_only_public_non_profile_rows(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();

		for (file_id, visibility) in [("f1~pub", Some('P')), ("f1~conn", Some('C'))] {
			adapter
				.replace_search_object(
					tn_id,
					&SearchObject {
						obj_tp: 'F',
						obj_id: file_id,
						owner_tag: Some("alice"),
						visibility,
						fts_cl,
						..Default::default()
					},
					&[SearchPart { body: Some("kozos kulcsszo"), ..Default::default() }],
				)
				.await
				.expect("index");
		}

		// An issuer the tenant does not follow, so their follower-only post stays
		// hidden even though the tenant federated it in.
		adapter
			.upsert_profile(
				tn_id,
				"carol.example",
				&UpsertProfileFields {
					name: Patch::Value("Kozos Karolina".into()),
					typ: Patch::Value(ProfileType::Person),
					following: Patch::Value(false),
					..Default::default()
				},
			)
			.await
			.expect("upsert issuer profile");
		index_profile(&adapter, tn_id, "carol.example", fts_cl).await;

		for (action_id, visibility) in [("a1~pub", Some('P')), ("a1~foll", Some('F'))] {
			publish_action(
				&adapter,
				tn_id,
				NewAction {
					action_id,
					typ: "POST",
					issuer_tag: "carol.example",
					visibility,
					text: "kozos kulcsszo",
					..Default::default()
				},
				fts_cl,
			)
			.await;
		}

		// The tenant owner finds all five rows — two files, two posts, one profile.
		assert_eq!(find(&adapter, tn_id, "kozos", fts_cl).await.len(), 5);

		let guest = SearchOptions {
			// `SubjectAccessLevel::Public.visible_levels()`.
			visible_levels: Some(vec!['P']),
			viewer_id_tag: Some("guest".into()),
			obj_tp: Some(vec!['F', 'D', 'A']),
			..opts("kozos", fts_cl)
		};
		let hits = adapter.search(tn_id, &guest).await.expect("search");
		// Relevance-ordered, so compare as a set.
		let mut ids: Vec<&str> = hits.iter().map(|h| &*h.obj_id).collect();
		ids.sort_unstable();
		assert_eq!(ids, ["a1~pub", "f1~pub"]);
		assert!(hits.iter().all(|h| h.obj_tp != 'P'), "a profile row leaked to a guest");
		// The count runs the same filters, so pagination agrees with the page.
		assert_eq!(adapter.count_search(tn_id, &guest).await.expect("count"), 2);

		// A guest asking for profiles gets an empty page, never an unfiltered one.
		let guest_profiles = SearchOptions { obj_tp: Some(vec![]), ..guest };
		assert!(adapter.search(tn_id, &guest_profiles).await.expect("search").is_empty());
		assert_eq!(adapter.count_search(tn_id, &guest_profiles).await.expect("count"), 0);
	}
}

one_mode! {
	async fn an_owner_sees_everything(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();

		adapter
			.create_file(
				tn_id,
				CreateFile {
					file_id: Some("f1~priv".into()),
					content_type: "text/plain".into(),
					file_name: "maganjegyzet.txt".into(),
					file_tp: Some("BLOB".into()),
					status: Some(FileStatus::Active),
					// Direct: NULL visibility.
					..Default::default()
				},
			)
			.await
			.expect("create file");
		index_file(&adapter, tn_id, "f1~priv", fts_cl).await;
		publish_action(
			&adapter,
			tn_id,
			NewAction {
				action_id: "a1~direct",
				typ: "MSG",
				issuer_tag: "carol.example",
				text: "maganjegyzet uzenet",
				..Default::default()
			},
			fts_cl,
		)
		.await;

		// `visible_levels: None` is what the handler passes for the tenant owner:
		// no predicate is emitted at all, so Direct rows come back too.
		assert_eq!(find(&adapter, tn_id, "maganjegyzet", fts_cl).await.len(), 2);
		assert!(find_as(&adapter, tn_id, "maganjegyzet", "bob.example", fts_cl).await.is_empty());
	}
}

one_mode! {
	/// `search_docs.owner_tag` is the raw `files.owner_tag` column: NULL for a
	/// tenant-owned file, set only on a cross-context Pin/Place copy. It must not
	/// exempt a row from the level predicate — `GET /api/files` has no such
	/// exemption, and for `'F'`/`'D'` the SQL prefilter *is* the authorization,
	/// so an exemption here would hand a federated peer the titles, tags and
	/// snippets of every part of a document the tenant has since made Direct.
	async fn a_pinned_copys_owner_does_not_bypass_the_level_predicate(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "bob").await.ok();

		// A copy the tenant pinned from alice, now Direct (NULL visibility).
		adapter
			.replace_search_object(
				tn_id,
				&SearchObject {
					obj_tp: 'F',
					obj_id: "f1~pinned",
					owner_tag: Some("alice"),
					visibility: None,
					fts_cl,
					..Default::default()
				},
				&[SearchPart { body: Some("kozos kulcsszo"), ..Default::default() }],
			)
			.await
			.expect("index file");
		adapter
			.replace_search_object(
				tn_id,
				&SearchObject {
					obj_tp: 'D',
					obj_id: "f1~pinned",
					owner_tag: Some("alice"),
					visibility: None,
					fts_cl,
					..Default::default()
				},
				&[SearchPart {
					part_id: "page1",
					body: Some("kozos kulcsszo"),
					..Default::default()
				}],
			)
			.await
			.expect("index deep part");

		// alice searching this tenant is still just a follower-level caller.
		assert!(find_as(&adapter, tn_id, "kozos", "alice", fts_cl).await.is_empty());
		let o = SearchOptions {
			visible_levels: Some(vec!['P', 'V', '2', 'F', 'C']),
			viewer_id_tag: Some("alice".into()),
			..opts("kozos", fts_cl)
		};
		assert!(adapter.search(tn_id, &o).await.expect("search").is_empty());
		assert_eq!(adapter.count_search(tn_id, &o).await.expect("count"), 0);

		// The tenant owner still sees both rows.
		assert_eq!(find(&adapter, tn_id, "kozos", fts_cl).await.len(), 2);
	}
}

// --- reaping ---------------------------------------------------------------

both_modes! {
	async fn reap_removes_rows_whose_source_is_gone(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();

		adapter
			.create_file(
				tn_id,
				CreateFile {
					file_id: Some("f1~real".into()),
					content_type: "text/plain".into(),
					file_name: "letezo.txt".into(),
					file_tp: Some("BLOB".into()),
					status: Some(FileStatus::Active),
					..Default::default()
				},
			)
			.await
			.expect("create file");
		index_file(&adapter, tn_id, "f1~real", fts_cl).await;

		// An 'F' row for a file that has no `files` row at all — what a hard delete
		// on a path that forgot to ask for an index update would leave behind.
		// `replace_search_object` is the one writer that does *not* check the
		// source table, so it can stage the inconsistency this sweep cleans up.
		adapter
			.replace_search_object(
				tn_id,
				&SearchObject { obj_tp: 'F', obj_id: "f1~ghost", fts_cl,
						..Default::default() },
				&[SearchPart { body: Some("kiserteties"), ..Default::default() }],
			)
			.await
			.expect("index ghost");
		assert_eq!(find(&adapter, tn_id, "kiserteties", fts_cl).await.len(), 1);

		adapter.reap_search_orphans(tn_id).await.expect("reap");

		assert!(
			find(&adapter, tn_id, "kiserteties", fts_cl).await.is_empty(),
			"the sweep must reap index rows whose source row is gone"
		);
		assert_eq!(find(&adapter, tn_id, "letezo", fts_cl).await.len(), 1, "a real file's row must survive");
	}
}

both_modes! {
	async fn reap_keeps_a_non_qualifying_row_it_did_not_write(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();

		adapter
			.create_file(
				tn_id,
				CreateFile {
					file_id: Some("f1~doc".into()),
					content_type: "text/plain".into(),
					file_name: "torolt.txt".into(),
					file_tp: Some("BLOB".into()),
					status: Some(FileStatus::Deleted),
					..Default::default()
				},
			)
			.await
			.expect("create file");
		adapter
			.replace_search_object(
				tn_id,
				&SearchObject { obj_tp: 'F', obj_id: "f1~doc", fts_cl,
						..Default::default() },
				&[SearchPart { body: Some("torolt"), ..Default::default() }],
			)
			.await
			.expect("index");

		// Whether an object *qualifies* is a Rust decision, made per object and
		// applied through `replace_search_row`. The reap only knows about missing
		// source rows, so a soft-deleted file's row survives it — and is removed by
		// the `index_file` call on the delete path instead.
		adapter.reap_search_orphans(tn_id).await.expect("reap");
		assert_eq!(find(&adapter, tn_id, "torolt", fts_cl).await.len(), 1);

		index_file(&adapter, tn_id, "f1~doc", fts_cl).await;
		assert!(find(&adapter, tn_id, "torolt", fts_cl).await.is_empty());
	}
}

/// One past `INSERT_CHUNK` in `adapters/meta-adapter-sqlite/src/search.rs` (500)
/// — the size `delete_contentless` batches its `s_id` list at, and the only page
/// boundary the sweep has. Anything larger only buys setup time.
const MANY_ROWS: usize = 501;

/// A sweep whose orphan list outgrows one internal chunk must reap all of it,
/// and still leave a living row alone.
///
/// Contentless rather than `both_modes!`: the chunking is in
/// `delete_contentless`, and only this route reaches it — external-content rows
/// leave through the `search_docs_ad` trigger, one row at a time, with no batch
/// to get the boundary wrong at.
///
/// The orphans are written straight through `replace_search_object`, which is
/// the one writer that does not check the source table, rather than by creating
/// and then deleting ~500 files: that is what `reap_search_orphans` means by an
/// orphan, and it costs one write transaction per row instead of three.
#[tokio::test]
async fn reap_spans_a_large_tenant() {
	let (adapter, dir) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.ok();
	let db = probe(&dir).await;

	adapter
		.create_file(
			tn_id,
			CreateFile {
				file_id: Some("f1~elo".into()),
				content_type: "text/plain".into(),
				file_name: "tulelo.txt".into(),
				file_tp: Some("BLOB".into()),
				status: Some(FileStatus::Active),
				..Default::default()
			},
		)
		.await
		.expect("create file");
	index_file(&adapter, tn_id, "f1~elo", true).await;

	for i in 0..MANY_ROWS {
		adapter
			.replace_search_object(
				tn_id,
				&SearchObject {
					obj_tp: 'F',
					obj_id: &format!("f1~{i}"),
					fts_cl: true,
					..Default::default()
				},
				&[SearchPart { body: Some("darabolando"), ..Default::default() }],
			)
			.await
			.expect("index orphan");
	}
	assert_eq!(contentless_rows(&db).await, i64::try_from(MANY_ROWS).expect("fits") + 1);

	adapter.reap_search_orphans(tn_id).await.expect("reap");

	// The raw index, not `search`: the `search_docs` rows go in one `DELETE`
	// whatever the chunking does, so a search-level count would read 0 with the
	// second chunk's `search_fts_cl` entries still sitting there.
	assert_eq!(
		contentless_rows(&db).await,
		1,
		"the sweep must clear every orphan's index entry, not just the first chunk"
	);
	assert_indexes_intact(&db).await;
	assert_eq!(
		find(&adapter, tn_id, "tulelo", true).await.len(),
		1,
		"a living file lost its row to the sweep"
	);
}

// --- what a sweep can see --------------------------------------------------

/// A file at an explicit location, with an explicit `hidden` flag.
async fn create_file_at(
	adapter: &MetaAdapterSqlite,
	tn_id: TnId,
	file_id: &str,
	file_name: &str,
	parent_id: Option<&str>,
	hidden: bool,
) {
	adapter
		.create_file(
			tn_id,
			CreateFile {
				file_id: Some(file_id.into()),
				parent_id: parent_id.map(Into::into),
				hidden,
				content_type: "text/plain".into(),
				file_name: file_name.into(),
				file_tp: Some("BLOB".into()),
				status: Some(FileStatus::Active),
				visibility: Some('P'),
				..Default::default()
			},
		)
		.await
		.expect("create file");
}

fn file_ids(files: &[cloudillo_types::meta_adapter::FileView]) -> Vec<&str> {
	let mut ids: Vec<&str> = files.iter().map(|f| &*f.file_id).collect();
	ids.sort_unstable();
	ids
}

both_modes! {
	/// The action counterpart of `the_sweep_listing_returns_the_rows_a_browse_listing_hides`
	/// in `tests/query_tests.rs`.
	///
	/// A retracted action is *soft*-deleted: the `actions` row stays, so nothing
	/// in the index reaps it — `reap_search_orphans` only drops rows whose source
	/// row is physically gone. Only the sweep can un-index it, and the sweep can
	/// only un-index what its listing returns. `ListActionOptions` with no
	/// `status` is not "every row": the adapter reads it as the client-facing
	/// default `NOT IN ('D', 'V', 'F')`, which hides exactly these. So the sweep
	/// asks for every status explicitly, and `cloudillo_search`'s `is_live` check
	/// then routes anything but an Active row to the deletion path — mirrored here
	/// by `index_action`.
	async fn the_action_sweep_un_indexes_a_retracted_action(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();

		publish_action(
			&adapter,
			tn_id,
			NewAction {
				action_id: "a1~visszavont",
				typ: "POST",
				issuer_tag: "alice",
				subject: None,
				visibility: Some('P'),
				text: "titkos bejelentes",
			},
			fts_cl,
		)
		.await;
		assert_eq!(find(&adapter, tn_id, "titkos", fts_cl).await.len(), 1);

		adapter.delete_action(tn_id, "a1~visszavont").await.expect("retract");
		assert_eq!(
			find(&adapter, tn_id, "titkos", fts_cl).await.len(),
			1,
			"a soft delete alone leaves the index row behind — that is the bug"
		);

		// The default listing cannot see it — a sweep using it would miss the row.
		let browse = adapter
			.list_actions(tn_id, &ListActionOptions::default())
			.await
			.expect("browse");
		assert!(browse.iter().all(|a| &*a.action_id != "a1~visszavont"));

		// The sweep's listing does, and re-indexing what it returns removes the row.
		let opts = ListActionOptions {
			status: Some(["A", "P", "R", "D", "V", "F"].iter().map(|s| (*s).to_owned()).collect()),
			..Default::default()
		};
		let sweep = adapter.list_actions(tn_id, &opts).await.expect("sweep");
		assert_eq!(sweep.len(), 1, "the sweep must see the retracted action");
		for action in &sweep {
			index_action(&adapter, tn_id, &action.action_id, fts_cl).await;
		}
		assert!(
			find(&adapter, tn_id, "titkos", fts_cl).await.is_empty(),
			"a retracted action stayed searchable"
		);
	}
}

/// Set `actions.status` behind the index's back — no `search_docs` write and no
/// notification, exactly what the two raw-SQL key-dedup paths in `action.rs` do.
async fn force_action_status(
	db: &sqlx::SqlitePool,
	tn_id: TnId,
	action_id: &str,
	status: Option<&str>,
) {
	sqlx::query("UPDATE actions SET status=? WHERE tn_id=? AND action_id=?")
		.bind(status)
		.bind(tn_id.0)
		.bind(action_id)
		.execute(db)
		.await
		.expect("force action status");
}

one_mode! {
	/// A non-live `actions.status` hides the hit at query time.
	///
	/// `reap_search_orphans` cannot catch a status change — the `actions` row is
	/// still physically there — and neither dedup path notifies the index, so
	/// without the guard inside the `'A'` `EXISTS` a superseded action stays
	/// searchable until the weekly full reindex.
	async fn a_non_live_action_status_hides_the_hit(fts_cl: bool) {
		let (adapter, dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();

		publish_action(
			&adapter,
			tn_id,
			NewAction {
				action_id: "a1~allapot",
				typ: "POST",
				issuer_tag: "alice",
				subject: None,
				visibility: Some('P'),
				text: "titkos bejelentes",
			},
			fts_cl,
		)
		.await;

		let viewer = SearchOptions {
			visible_levels: Some(vec!['P', 'V', '2', 'F']),
			viewer_id_tag: Some("bob".into()),
			..opts("titkos", fts_cl)
		};
		assert_eq!(adapter.search(tn_id, &viewer).await.expect("search").len(), 1);

		let db = probe(&dir).await;
		for status in ["D", "V", "F"] {
			force_action_status(&db, tn_id, "a1~allapot", Some(status)).await;
			assert!(
				adapter.search(tn_id, &viewer).await.expect("search").is_empty(),
				"status {status} must hide the action from search"
			);
			// `count` shares `push_search_filters`, so the total moves with the page.
			assert_eq!(
				adapter.count_search(tn_id, &viewer).await.expect("count"),
				0,
				"count disagreed with the page for status {status}"
			);
		}

		// `coalesce(a.status, 'A')` — both spellings of "live" stay findable.
		for status in [Some("A"), None] {
			force_action_status(&db, tn_id, "a1~allapot", status).await;
			assert_eq!(
				adapter.search(tn_id, &viewer).await.expect("search").len(),
				1,
				"a live action must stay searchable (status {status:?})"
			);
			assert_eq!(adapter.count_search(tn_id, &viewer).await.expect("count"), 1);
		}
	}
}

one_mode! {
	/// Managed files are the cached peer avatars, written `'P'`-visible, so an
	/// indexed one would let an unauthenticated search enumerate the tenant's
	/// contacts by file name. `hidden` is the legacy spelling of the same
	/// placement. Neither is searchable, and the sweep takes an existing row back
	/// out — a plain file in the same tenant is unaffected.
	async fn hidden_and_managed_files_are_not_searchable(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();

		create_file_at(&adapter, tn_id, "f1~hidden", "rejtett.txt", None, true).await;
		create_file_at(&adapter, tn_id, "f1~managed", "kezelt.txt", Some(MANAGED_PARENT_ID), false)
			.await;
		create_file_at(&adapter, tn_id, "f1~plain", "sima.txt", None, false).await;
		index_file(&adapter, tn_id, "f1~hidden", fts_cl).await;
		index_file(&adapter, tn_id, "f1~managed", fts_cl).await;
		index_file(&adapter, tn_id, "f1~plain", fts_cl).await;

		assert!(find(&adapter, tn_id, "rejtett", fts_cl).await.is_empty());
		assert!(find(&adapter, tn_id, "kezelt", fts_cl).await.is_empty());
		assert_eq!(find(&adapter, tn_id, "sima", fts_cl).await.len(), 1);
	}
}

both_modes! {
	/// The failure the weekly sweep exists for: a file trashed by a write path that
	/// forgot its index call. The sweep sees it (`sweep_all`), decides it is not
	/// indexable, and takes both its `'F'` row and its deep `'D'` parts back out.
	async fn the_sweep_removes_a_trashed_files_rows_when_the_live_hook_was_forgotten(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();

		adapter
			.create_file(
				tn_id,
				CreateFile {
					file_id: Some("f1~doc".into()),
					content_type: "cloudillo/notillo".into(),
					file_name: "Jegyzetek".into(),
					file_tp: Some("RTDB".into()),
					status: Some(FileStatus::Active),
					visibility: Some('P'),
					..Default::default()
				},
			)
			.await
			.expect("create file");
		index_file(&adapter, tn_id, "f1~doc", fts_cl).await;
		index_text(&adapter, tn_id, "f1~doc", "titkos tartalom", fts_cl).await;
		assert_eq!(find(&adapter, tn_id, "Jegyzetek", fts_cl).await.len(), 1);
		assert_eq!(find(&adapter, tn_id, "titkos", fts_cl).await.len(), 1);

		// Trashed with no index call after it — the forgotten hook.
		adapter
			.update_file_data(
				tn_id,
				"f1~doc",
				&UpdateFileOptions {
					parent_id: Patch::Value(TRASH_PARENT_ID.to_owned()),
					..Default::default()
				},
			)
			.await
			.expect("trash");
		assert_eq!(find(&adapter, tn_id, "Jegyzetek", fts_cl).await.len(), 1, "still stale, as expected");

		// The sweep: page every row, re-derive what each contributes, write it back.
		let opts =
			ListFileOptions { sweep_all: true, include_tree_children: true, ..Default::default() };
		let files = adapter.list_files(tn_id, &opts).await.expect("sweep");
		assert_eq!(file_ids(&files), vec!["f1~doc"], "the sweep must reach a trashed file");
		for file in &files {
			index_file(&adapter, tn_id, &file.file_id, fts_cl).await;
		}

		assert!(find(&adapter, tn_id, "Jegyzetek", fts_cl).await.is_empty(), "the 'F' row survived the sweep");
		assert!(find(&adapter, tn_id, "titkos", fts_cl).await.is_empty(), "the 'D' rows survived the sweep");
	}
}

// ── Tag filter ──

/// Index one page-like part carrying a title, body and space-separated tags,
/// the same shape `cloudillo_search::indexer` produces from a notillo manifest.
async fn index_tagged_page(
	adapter: &MetaAdapterSqlite,
	tn_id: TnId,
	file_id: &str,
	part_id: &str,
	body: &str,
	tags: &str,
	fts_cl: bool,
) {
	adapter
		.replace_search_object(
			tn_id,
			&SearchObject {
				obj_tp: 'D',
				obj_id: file_id,
				content_type: Some("cloudillo/notillo"),
				visibility: Some('P'),
				fts_cl,
				..Default::default()
			},
			&[SearchPart { part_id, body: Some(body), tags: Some(tags), ..Default::default() }],
		)
		.await
		.expect("index");
}

fn tag_opts(q: &str, tags: &[&str], fts_cl: bool) -> SearchOptions {
	SearchOptions { tags: Some(tags.iter().map(|t| (*t).to_string()).collect()), ..opts(q, fts_cl) }
}

async fn seed_tagged(adapter: &MetaAdapterSqlite, tn_id: TnId, fts_cl: bool) {
	index_tagged_page(
		adapter,
		tn_id,
		"f1~a",
		"p1",
		"quarterly planning notes",
		"munka docs",
		fts_cl,
	)
	.await;
	index_tagged_page(adapter, tn_id, "f2~a", "p2", "quarterly planning notes", "otthon", fts_cl)
		.await;
	index_tagged_page(adapter, tn_id, "f3~a", "p3", "unrelated content", "munka", fts_cl).await;
}

one_mode! {
	async fn tag_only_query_needs_no_search_text(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		seed_tagged(&adapter, tn_id, fts_cl).await;

		// An empty `q` is a validation error on its own, but a tag filter is a
		// complete match expression by itself — this is what makes tag browsing
		// servable at all.
		let hits = adapter.search(tn_id, &tag_opts("", &["munka"], fts_cl)).await.expect("search");
		let ids: Vec<&str> = hits.iter().map(|h| &*h.obj_id).collect();
		assert_eq!(ids.len(), 2);
		assert!(ids.contains(&"f1~a") && ids.contains(&"f3~a"));
	}
}

one_mode! {
	async fn text_and_tag_are_combined_not_applied_in_sequence(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		seed_tagged(&adapter, tn_id, fts_cl).await;

		// f1 matches the text and the tag; f2 matches the text but not the tag;
		// f3 matches the tag but not the text.
		let hits = adapter.search(tn_id, &tag_opts("planning", &["munka"], fts_cl)).await.expect("search");
		assert_eq!(hits.len(), 1);
		assert_eq!(&*hits[0].obj_id, "f1~a");
	}
}

one_mode! {
	async fn multiple_tags_are_and_combined(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		seed_tagged(&adapter, tn_id, fts_cl).await;

		let both = adapter.search(tn_id, &tag_opts("", &["munka", "docs"], fts_cl)).await.expect("search");
		assert_eq!(both.len(), 1);
		assert_eq!(&*both[0].obj_id, "f1~a");

		let neither = adapter
			.search(tn_id, &tag_opts("", &["munka", "otthon"], fts_cl))
			.await
			.expect("search");
		assert!(neither.is_empty());
	}
}

one_mode! {
	async fn a_tag_that_prefixes_another_does_not_match_it(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);

		index_tagged_page(&adapter, tn_id, "f1~a", "p1", "alpha", "doc", fts_cl).await;
		index_tagged_page(&adapter, tn_id, "f2~a", "p2", "beta", "docs", fts_cl).await;

		// Unlike the free-text query, tag clauses carry no `*` suffix, so `doc` is
		// exactly `doc`.
		let hits = adapter.search(tn_id, &tag_opts("", &["doc"], fts_cl)).await.expect("search");
		assert_eq!(hits.len(), 1);
		assert_eq!(&*hits[0].obj_id, "f1~a");
	}
}

one_mode! {
	async fn a_multi_word_tag_matches_as_a_phrase(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);

		index_tagged_page(&adapter, tn_id, "f1~a", "p1", "alpha", "project management", fts_cl).await;
		index_tagged_page(&adapter, tn_id, "f2~a", "p2", "beta", "management", fts_cl).await;

		// Quoting is what makes this a phrase rather than two loose terms AND-ed
		// across the whole document — f2 carries one of the two words and must not
		// match.
		let hits = adapter
			.search(tn_id, &tag_opts("", &["project management"], fts_cl))
			.await
			.expect("search");
		assert_eq!(hits.len(), 1);
		assert_eq!(&*hits[0].obj_id, "f1~a");
	}
}

one_mode! {
	async fn a_tag_filter_never_reaches_the_fts_parser_as_syntax(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		seed_tagged(&adapter, tn_id, fts_cl).await;

		// A quote cannot be escaped inside an FTS5 phrase, so such a tag is
		// rejected rather than passed through — and rejected, not dropped. Dropping
		// it would leave `q` as the whole query: the caller would get every
		// "quarterly" document back believing the set was tag-filtered, and `count`
		// would agree, so nothing would signal the filter had vanished.
		assert!(adapter.search(tn_id, &tag_opts("", &[r#"mun"ka"#], fts_cl)).await.is_err());
		assert!(adapter.search(tn_id, &tag_opts("quarterly", &[r#"mun"ka"#], fts_cl)).await.is_err());
		// `count` must reject identically, or a rejected page would come back with
		// a plausible `total` attached.
		assert!(adapter.count_search(tn_id, &tag_opts("quarterly", &[r#"mun"ka"#], fts_cl)).await.is_err());
		// One bad tag among good ones poisons the whole filter.
		assert!(
			adapter.search(tn_id, &tag_opts("", &["munka", r#"do"cs"#], fts_cl)).await.is_err()
		);

		// Column and operator syntax inside a tag is inert: it is quoted whole, so
		// it simply matches nothing.
		let hits = adapter.search(tn_id, &tag_opts("", &["body:quarterly"], fts_cl)).await.expect("search");
		assert!(hits.is_empty());
	}
}

one_mode! {
	async fn neither_text_nor_tags_is_still_rejected(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		seed_tagged(&adapter, tn_id, fts_cl).await;

		assert!(adapter.search(tn_id, &tag_opts("  ", &[], fts_cl)).await.is_err());
		assert!(adapter.search(tn_id, &opts("  ", fts_cl)).await.is_err());
	}
}

// ── Two index routes ──
//
// A tenant with `search.store_text = false` has its rows indexed in the
// contentless `search_fts_cl` with `search_docs.body` left NULL. Nothing but this
// adapter maintains that table — no trigger can, since there is no stored text
// for one to read — so the tests below check both halves: that a body query still
// matches, and that every delete path takes its entries with it. A contentless
// table cannot be rebuilt from its content, so a leak there is permanent;
// `'integrity-check'` is what surfaces one.

/// A second connection to the same `meta.db`, for the internals no adapter
/// method exposes.
async fn probe(dir: &TempDir) -> sqlx::SqlitePool {
	sqlx::sqlite::SqlitePoolOptions::new()
		.max_connections(1)
		.connect(&format!("sqlite://{}", dir.path().join("meta.db").display()))
		.await
		.expect("probe pool")
}

/// Rows currently in the contentless index.
async fn contentless_rows(db: &sqlx::SqlitePool) -> i64 {
	sqlx::query_scalar("SELECT count(*) FROM search_fts_cl")
		.fetch_one(db)
		.await
		.expect("count search_fts_cl")
}

/// The check that catches a missed `search_fts_cl` cleanup or a row written to
/// the wrong index. Run it after anything that deletes.
async fn assert_indexes_intact(db: &sqlx::SqlitePool) {
	for table in ["search_fts", "search_fts_cl"] {
		let sql = format!("INSERT INTO {table}({table}) VALUES('integrity-check')");
		sqlx::query(sqlx::AssertSqlSafe(sql))
			.execute(db)
			.await
			.unwrap_or_else(|e| panic!("{table} integrity-check failed: {e}"));
	}
}

#[tokio::test]
async fn the_contentless_route_matches_bodies_but_returns_no_snippet() {
	let (adapter, dir) = create_test_adapter().await;
	let (plain, cl) = (TnId(1), TnId(2));

	index_text(&adapter, plain, "f1~a", "the quick brown fox jumps", false).await;
	index_text(&adapter, cl, "f1~a", "the quick brown fox jumps", true).await;

	let a = find(&adapter, plain, "brown", false).await;
	let b = find(&adapter, cl, "brown", true).await;
	assert_eq!(a.len(), 1);
	assert_eq!(b.len(), 1);

	// Everything the caller sees agrees, except the excerpt — producing one
	// needs the stored text the contentless route deliberately does not keep.
	assert_eq!(a[0].title, b[0].title);
	assert_eq!(a[0].tags, b[0].tags);
	assert!((a[0].score - b[0].score).abs() < f64::EPSILON, "ranking must not depend on the route");
	assert!(a[0].snippet.is_some(), "the external route must still highlight");
	assert!(a[0].snippet_matches.is_some(), "the external route must still report ranges");
	assert_eq!(b[0].snippet, None, "the contentless route cannot produce an excerpt");
	assert!(b[0].snippet_matches.is_none(), "no excerpt means nothing to point ranges into");

	// The stored text really is gone.
	let db = probe(&dir).await;
	let bodies: i64 =
		sqlx::query_scalar("SELECT count(*) FROM search_docs WHERE tn_id = 2 AND body IS NOT NULL")
			.fetch_one(&db)
			.await
			.expect("count bodies");
	assert_eq!(bodies, 0);
	assert_indexes_intact(&db).await;
}

both_modes! {
	/// An RTDB commit that touches no indexed field re-runs the extractor and
	/// hands back byte-identical parts. Rewriting the rows then costs an FTS
	/// delete plus re-insert per part for nothing, so `obj_hash` short-circuits
	/// it — observable as an unchanged `s_id`.
	async fn replacing_an_object_with_identical_parts_rewrites_nothing(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);

		index_text(&adapter, tn_id, "f1~a", "valtozatlan tartalom", fts_cl).await;
		let before = find(&adapter, tn_id, "valtozatlan", fts_cl).await;
		assert_eq!(before.len(), 1);

		index_text(&adapter, tn_id, "f1~a", "valtozatlan tartalom", fts_cl).await;
		let after = find(&adapter, tn_id, "valtozatlan", fts_cl).await;
		assert_eq!(after.len(), 1);
		assert_eq!(after[0].s_id, before[0].s_id, "an identical re-index must not rewrite the row");

		// A real change still lands.
		index_text(&adapter, tn_id, "f1~a", "megvaltozott tartalom", fts_cl).await;
		assert!(find(&adapter, tn_id, "valtozatlan", fts_cl).await.is_empty());
		assert_eq!(find(&adapter, tn_id, "megvaltozott", fts_cl).await.len(), 1);
	}
}

/// Every path that removes `search_docs` rows must clear the matching
/// `search_fts_cl` entries by hand.
///
/// The contentless table cannot be rebuilt from its content, so a missed cleanup
/// leaks tokens nothing can ever reap — a later search still matches text that
/// is gone. The API-level consequence of each of these deletions is already
/// covered by the `both_modes!` tests above; what only a raw count can see is
/// the orphaned FTS entry left behind a `search_docs` row that did go.
///
/// One tenant per case rather than one test per case: a separate test would cost
/// a `TempDir` plus a full schema migration for four lines of assertion.
#[tokio::test]
async fn every_delete_path_clears_the_contentless_index() {
	let (adapter, dir) = create_test_adapter().await;
	let db = probe(&dir).await;

	// A tenant the sweep must never touch, so each case also shows it deleted
	// only its own rows.
	let bystander = TnId(99);
	adapter.create_tenant(bystander, "bob").await.ok();
	index_text(&adapter, bystander, "f1~b", "megmarado tartalom", true).await;

	let paths = [
		"delete_search_object",
		"delete_deep_search_by_content_type",
		"delete_tenant",
		"reap_search_orphans",
	];
	for (i, what) in paths.into_iter().enumerate() {
		let tn_id = TnId(u32::try_from(i).expect("fits") + 1);
		adapter.create_tenant(tn_id, &format!("alice{i}")).await.ok();
		let before = contentless_rows(&db).await;

		if what == "reap_search_orphans" {
			// An 'F' row with no `files` row behind it — what a hard delete on a
			// path that forgot its index call leaves behind.
			adapter
				.replace_search_object(
					tn_id,
					&SearchObject {
						obj_tp: 'F',
						obj_id: "f1~ghost",
						fts_cl: true,
						..Default::default()
					},
					&[SearchPart { body: Some("kiserteties"), ..Default::default() }],
				)
				.await
				.expect("index ghost");
		} else {
			index_text(&adapter, tn_id, "f1~a", "torlendo tartalom", true).await;
		}
		assert_eq!(contentless_rows(&db).await, before + 1, "{what}: nothing was indexed");

		match what {
			"delete_search_object" => {
				adapter.delete_search_object(tn_id, 'D', "f1~a").await.expect("delete");
			}
			"delete_deep_search_by_content_type" => {
				adapter
					.delete_deep_search_by_content_type(tn_id, "cloudillo/notillo")
					.await
					.expect("drop deep rows");
			}
			"delete_tenant" => adapter.delete_tenant(tn_id).await.expect("delete tenant"),
			_ => adapter.reap_search_orphans(tn_id).await.expect("reap"),
		}

		assert_eq!(contentless_rows(&db).await, before, "{what} leaked FTS entries");
		assert_indexes_intact(&db).await;
	}

	assert_eq!(
		find(&adapter, bystander, "megmarado", true).await.len(),
		1,
		"a delete path reached past its own tenant"
	);
}

#[tokio::test]
async fn switching_a_tenant_to_the_contentless_route_moves_its_rows() {
	let (adapter, dir) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.ok();
	let db = probe(&dir).await;

	// A deep part and a whole-object row, so both write paths are exercised.
	adapter
		.create_file(
			tn_id,
			CreateFile {
				file_id: Some("f1~doc".into()),
				content_type: "cloudillo/notillo".into(),
				file_name: "Jegyzetek".into(),
				file_tp: Some("RTDB".into()),
				status: Some(FileStatus::Active),
				visibility: Some('P'),
				..Default::default()
			},
		)
		.await
		.expect("create file");
	index_file(&adapter, tn_id, "f1~doc", false).await;
	index_text(&adapter, tn_id, "f1~doc", "koltozo tartalom", false).await;

	assert_eq!(find(&adapter, tn_id, "koltozo", false).await.len(), 1);
	assert_eq!(contentless_rows(&db).await, 0);

	// The flip, applied the way `reindex_tenant` applies it: re-index every
	// object of the tenant with the new route.
	index_file(&adapter, tn_id, "f1~doc", true).await;
	index_text(&adapter, tn_id, "f1~doc", "koltozo tartalom", true).await;

	assert_eq!(contentless_rows(&db).await, 2, "both rows must land in the contentless index");
	assert_eq!(find(&adapter, tn_id, "koltozo", true).await.len(), 1);
	assert_eq!(find(&adapter, tn_id, "Jegyzetek", true).await.len(), 1);
	// Nothing may be left behind in the index the rows came from. Counting
	// `search_fts` directly would not show it — a full scan of an external-content
	// table reads its *content* table, so it would just count `search_docs` again.
	// Querying it is what actually reaches the index.
	assert!(find(&adapter, tn_id, "koltozo", false).await.is_empty());
	assert!(find(&adapter, tn_id, "Jegyzetek", false).await.is_empty());
	assert_indexes_intact(&db).await;
}

// ── Space reclaim ──

both_modes! {
	/// The merge and the measure-only path must both be transparent: same rows
	/// before and after. The `100` threshold is unreachable (it would need every
	/// page free), so this asserts the gate holds rather than that VACUUM works.
	async fn optimizing_and_measuring_leave_the_index_alone(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);

		for i in 0..5 {
			index_text(&adapter, tn_id, &format!("f1~d{i}"), "kozos szo", fts_cl).await;
		}
		let before = find(&adapter, tn_id, "kozos", fts_cl).await.len();
		assert_eq!(before, 5);

		adapter.optimize_search_index(false).await.expect("merge");
		let report = adapter.reclaim_space(100).await.expect("reclaim");
		assert!(!report.vacuumed, "a 100% free-page threshold must never vacuum");
		assert!(report.page_size > 0 && report.page_count > 0);

		assert_eq!(find(&adapter, tn_id, "kozos", fts_cl).await.len(), before);
	}
}

both_modes! {
	/// The real guard: a VACUUM rewrites every page, so an external-content FTS
	/// index that lost its link to `search_docs` would show up here as a search
	/// returning nothing.
	async fn vacuuming_preserves_both_indexes(fts_cl: bool) {
		let (adapter, dir) = create_test_adapter().await;
		let tn_id = TnId(1);

		for i in 0..5 {
			index_text(&adapter, tn_id, &format!("f1~d{i}"), "kozos szo", fts_cl).await;
		}
		// Leave some free pages behind for the vacuum to actually reclaim.
		adapter.delete_search_object(tn_id, 'D', "f1~d0").await.expect("delete");

		let report = adapter.reclaim_space(0).await.expect("reclaim");
		assert!(report.vacuumed, "a 0% threshold must always vacuum");

		assert_eq!(find(&adapter, tn_id, "kozos", fts_cl).await.len(), 4);
		assert_indexes_intact(&probe(&dir).await).await;
	}
}

// --- tenant isolation ------------------------------------------------------

one_mode! {
	/// Both FTS tables are node-wide, so nothing but the query construction keeps
	/// one tenant out of another's results. The `tn_id:` clause pushed into the
	/// MATCH expression is what makes FTS5 narrow *before* ranking, rather than
	/// matching the whole node's corpus and letting `d.tn_id` trim it afterwards;
	/// this asserts the narrowing is correct as well as cheap.
	async fn a_search_never_crosses_tenants(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;

		index_text(&adapter, TnId(1), "f1~egy", "kozos szoveg", fts_cl).await;
		index_text(&adapter, TnId(2), "f1~ketto", "kozos szoveg", fts_cl).await;

		let one = find(&adapter, TnId(1), "kozos", fts_cl).await;
		assert_eq!(one.len(), 1, "tenant 1 must see only its own row");
		assert_eq!(&*one[0].obj_id, "f1~egy");

		let two = find(&adapter, TnId(2), "kozos", fts_cl).await;
		assert_eq!(two.len(), 1, "tenant 2 must see only its own row");
		assert_eq!(&*two[0].obj_id, "f1~ketto");

		// `count_search` shares `push_search_filters`, so it must agree — a total
		// counted across both tenants would page a caller into empty results.
		let count_one = adapter.count_search(TnId(1), &opts("kozos", fts_cl)).await.expect("count");
		let count_two = adapter.count_search(TnId(2), &opts("kozos", fts_cl)).await.expect("count");
		assert_eq!((count_one, count_two), (1, 1));
	}
}

one_mode! {
	/// A query term must not match the synthetic `tn_id` FTS column.
	///
	/// Both FTS tables index `tn_id` as a real column, so every row of tenant *N*
	/// contains the token *N*. An unqualified term therefore matched the whole
	/// tenant: `?q=1` on `tn_id = 1` returned the first page of the entire corpus
	/// and `count_search` agreed, so nothing in the response said the query had
	/// been misread. `escape_fts_query` now confines the user's terms to
	/// `{title body tags}`.
	async fn a_query_term_does_not_match_the_tenant_id_column(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);

		index_text(&adapter, tn_id, "f1~a", "kozos szoveg", fts_cl).await;
		index_text(&adapter, tn_id, "f1~b", "masik szoveg", fts_cl).await;

		let hits = find(&adapter, tn_id, "1", fts_cl).await;
		assert!(hits.is_empty(), "'1' matched the tn_id column: {hits:?}");
		let total = adapter.count_search(tn_id, &opts("1", fts_cl)).await.expect("count");
		assert_eq!(total, 0, "count_search must agree with search");
	}
}

one_mode! {
	/// The converse of [`a_query_term_does_not_match_the_tenant_id_column`]: text
	/// that legitimately *is* the tenant id must still be findable, so the column
	/// filter has not simply made bare numbers unsearchable.
	async fn body_text_matching_the_tenant_id_is_still_found(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);

		index_text(&adapter, tn_id, "f1~a", "1 szamu melleklet", fts_cl).await;
		index_text(&adapter, tn_id, "f1~b", "masik szoveg", fts_cl).await;

		let hits = find(&adapter, tn_id, "1", fts_cl).await;
		assert_eq!(hits.len(), 1, "a body containing '1' must still match");
		assert_eq!(&*hits[0].obj_id, "f1~a");
	}
}

// ── ACL columns denormalised out of `files` ──
//
// `search_docs` copies `visibility`, `owner_tag`, `root_id` and `content_type`
// off the `files` row so a query can filter on them without a join. Two rows
// describe one document — its own `'F'` row and every `'D'` part — and they must
// agree, or the API reports a hit's owner differently depending on which row
// matched, and the share-link grant stops finding the pages of the document it
// was minted for.

/// Create a real `files` row so the ACL-refresh statement has a source to read.
async fn create_doc_file(
	adapter: &MetaAdapterSqlite,
	tn_id: TnId,
	file_id: &str,
	owner_tag: Option<&str>,
) {
	adapter
		.create_file(
			tn_id,
			CreateFile {
				file_id: Some(file_id.into()),
				owner_tag: owner_tag.map(Into::into),
				// Standalone: its own tree root, which is what NULL means here.
				root_id: None,
				content_type: "application/x-notillo".into(),
				file_name: "Jegyzet".into(),
				file_tp: Some("RTDB".into()),
				status: Some(FileStatus::Active),
				visibility: Some('P'),
				..Default::default()
			},
		)
		.await
		.expect("create file");
}

/// The `search_docs` rows of one object, as `(obj_tp, root_id, owner_tag)`.
async fn acl_rows(
	db: &sqlx::SqlitePool,
	tn_id: TnId,
	obj_id: &str,
) -> Vec<(String, Option<String>, Option<String>)> {
	sqlx::query_as(
		"SELECT obj_tp, root_id, owner_tag FROM search_docs \
		 WHERE tn_id = ? AND obj_id = ? ORDER BY obj_tp, part_id",
	)
	.bind(tn_id.0)
	.bind(obj_id)
	.fetch_all(db)
	.await
	.expect("read acl columns")
}

/// Index a standalone document's `'D'` parts the way `cloudillo_search::indexer`
/// does: `root_id = COALESCE(files.root_id, file_id)`, `owner_tag` the raw column.
async fn index_doc_parts(
	adapter: &MetaAdapterSqlite,
	tn_id: TnId,
	file_id: &str,
	owner_tag: Option<&str>,
	fts_cl: bool,
) {
	adapter
		.replace_search_object(
			tn_id,
			&SearchObject {
				obj_tp: 'D',
				obj_id: file_id,
				content_type: Some("application/x-notillo"),
				owner_tag,
				visibility: Some('P'),
				root_id: Some(file_id),
				fts_cl,
				..Default::default()
			},
			&[
				SearchPart { part_id: "page1", body: Some("elso oldal"), ..Default::default() },
				SearchPart { part_id: "page2", body: Some("masodik oldal"), ..Default::default() },
			],
		)
		.await
		.expect("index doc parts");
}

one_mode! {
	/// A rename must not clobber the `'D'` rows' `root_id`.
	///
	/// `files.root_id` is NULL for a standalone document — it *is* its own tree
	/// root — but the `'D'` rows carry the resolved root so a file-scoped share
	/// token can prefilter them in SQL. Copying `f.root_id` straight across on
	/// the next `'F'` write NULLed every part, and the share-grant clause
	/// (`d.root_id = ? AND d.obj_tp='D'`) then stopped matching: a share link to
	/// a private standalone document searched to zero hits on its own pages.
	async fn a_rename_leaves_the_deep_rows_tree_root_alone(fts_cl: bool) {
		let (adapter, dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();
		let db = probe(&dir).await;

		create_doc_file(&adapter, tn_id, "f1~note", None).await;
		index_doc_parts(&adapter, tn_id, "f1~note", None, fts_cl).await;
		index_file(&adapter, tn_id, "f1~note", fts_cl).await;

		// The rename, then the reindex of the `'F'` row it triggers.
		adapter
			.update_file_data(
				tn_id,
				"f1~note",
				&UpdateFileOptions {
					file_name: Patch::Value("Atnevezett".into()),
					..Default::default()
				},
			)
			.await
			.expect("rename");
		index_file(&adapter, tn_id, "f1~note", fts_cl).await;

		for (obj_tp, root_id, _) in acl_rows(&db, tn_id, "f1~note").await {
			let expected = if obj_tp == "D" { Some("f1~note".to_string()) } else { None };
			assert_eq!(root_id, expected, "'{obj_tp}' row lost its tree root to the rename");
		}

		// What the regression actually broke: the share-link grant.
		let granted = SearchOptions {
			visible_levels: Some(vec!['P']),
			scope_file_id: Some("f1~note".into()),
			scope_grant_file_id: Some("f1~note".into()),
			..opts("oldal", fts_cl)
		};
		assert_eq!(
			adapter.search(tn_id, &granted).await.expect("search").len(),
			2,
			"a share link must still find the document's own pages after a rename"
		);
	}

	/// The `'D'` and `'F'` rows of one file must report the same `owner_tag`.
	///
	/// `FileView.owner` resolves through a fallback chain that answers the
	/// *tenant's* profile when `files.owner_tag` is NULL, so an indexer reading it
	/// wrote the tenant's tag into the `'D'` rows while the `'F'` row kept the raw
	/// NULL. Both rows are now derived from the same column.
	async fn the_deep_and_file_rows_agree_on_the_owner(fts_cl: bool) {
		let (adapter, dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();
		let db = probe(&dir).await;

		// Tenant-owned: `files.owner_tag` is NULL, and both rows must say so.
		create_doc_file(&adapter, tn_id, "f1~mine", None).await;
		index_doc_parts(&adapter, tn_id, "f1~mine", None, fts_cl).await;
		index_file(&adapter, tn_id, "f1~mine", fts_cl).await;

		// Federated: owned by someone else, and both rows must carry their tag.
		create_doc_file(&adapter, tn_id, "f1~theirs", Some("bob.example.com")).await;
		index_doc_parts(&adapter, tn_id, "f1~theirs", Some("bob.example.com"), fts_cl).await;
		index_file(&adapter, tn_id, "f1~theirs", fts_cl).await;

		for (file_id, expected) in [("f1~mine", None), ("f1~theirs", Some("bob.example.com"))] {
			let rows = acl_rows(&db, tn_id, file_id).await;
			assert_eq!(rows.len(), 3, "one 'F' row and two 'D' parts");
			for (obj_tp, _, owner_tag) in rows {
				assert_eq!(
					owner_tag.as_deref(),
					expected,
					"'{obj_tp}' row of {file_id} disagrees on the owner"
				);
			}
		}
	}

	/// A deep write must take its visibility from `files`, never from the caller.
	///
	/// `cloudillo_search::indexer` reads the `files` row, then waits on a
	/// process-wide materialisation permit before writing. A visibility flip
	/// landing inside that window makes the `SearchObject` it finally submits
	/// stale — and the `'F'` write the flip triggered has already corrected both
	/// the `'F'` row and its `'D'` parts, so a deep write that trusted the caller
	/// would re-publish the pages of a document that is no longer public.
	///
	/// Both deep-write paths are exercised: the full insert, and the hash
	/// short-circuit. The hash covers text only, so a pure visibility flip takes
	/// the short-circuit — which must therefore refresh and commit rather than
	/// return early with nothing written.
	async fn a_deep_write_cannot_publish_a_file_that_is_no_longer_public(fts_cl: bool) {
		let (adapter, dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();
		let db = probe(&dir).await;

		let visibilities = async |db: &sqlx::SqlitePool| -> Vec<Option<String>> {
			sqlx::query_scalar(
				"SELECT visibility FROM search_docs \
				 WHERE tn_id = ? AND obj_tp = 'D' AND obj_id = ? ORDER BY part_id",
			)
			.bind(tn_id.0)
			.bind("f1~note")
			.fetch_all(db)
			.await
			.expect("read deep visibility")
		};

		create_doc_file(&adapter, tn_id, "f1~note", None).await;
		index_doc_parts(&adapter, tn_id, "f1~note", None, fts_cl).await;
		index_file(&adapter, tn_id, "f1~note", fts_cl).await;
		assert_eq!(visibilities(&db).await, vec![Some("P".into()), Some("P".into())]);

		// The flip. `Patch::Null` is Direct — owner-only.
		adapter
			.update_file_data(
				tn_id,
				"f1~note",
				&UpdateFileOptions { visibility: Patch::Null, ..Default::default() },
			)
			.await
			.expect("make direct");
		index_file(&adapter, tn_id, "f1~note", fts_cl).await;
		assert_eq!(visibilities(&db).await, vec![None, None], "the 'F' write must cascade");

		// The debounced deep write finally lands, still carrying `Some('P')`.
		index_doc_parts(&adapter, tn_id, "f1~note", None, fts_cl).await;
		assert_eq!(
			visibilities(&db).await,
			vec![None, None],
			"a stale deep write re-published a non-public document"
		);

		// Same again, but reaching the hash short-circuit: identical text, so the
		// insert path is skipped entirely.
		adapter
			.update_file_data(
				tn_id,
				"f1~note",
				&UpdateFileOptions { visibility: Patch::Value('P'), ..Default::default() },
			)
			.await
			.expect("make public");
		index_doc_parts(&adapter, tn_id, "f1~note", None, fts_cl).await;
		assert_eq!(
			visibilities(&db).await,
			vec![Some("P".into()), Some("P".into())],
			"the short-circuit must still re-derive the ACL columns"
		);
		assert_indexes_intact(&db).await;
	}

}

both_modes! {
	/// With the ACL columns already correct, a second `'F'` write must touch no
	/// row at all.
	///
	/// The guard on the refresh `UPDATE` is what keeps a rename off the FTS
	/// tables: every row it touches fires the `search_docs_au` trigger, which is
	/// an FTS5 delete plus a re-insert. A document indexed with values the SQL
	/// would derive differently defeats it, and a 5000-page document pays 5000
	/// FTS rewrites on every rename.
	async fn a_no_op_refresh_touches_nothing(fts_cl: bool) {
		let (adapter, dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();
		let db = probe(&dir).await;

		create_doc_file(&adapter, tn_id, "f1~note", None).await;
		index_doc_parts(&adapter, tn_id, "f1~note", None, fts_cl).await;
		index_file(&adapter, tn_id, "f1~note", fts_cl).await;

		// `search_docs.s_id` is the FTS rowid, and the trigger rewrites the entry
		// in place, so identity is not observable. `updated_at` is: the refresh
		// does not set it, but an upsert of the same part does — so freeze it and
		// assert nothing moved.
		sqlx::query("UPDATE search_docs SET updated_at = 0 WHERE tn_id = ?")
			.bind(tn_id.0)
			.execute(&db)
			.await
			.expect("freeze updated_at");
		let before = acl_rows(&db, tn_id, "f1~note").await;

		// A `refresh_file` with no ACL change: the same `'F'` write again.
		index_file(&adapter, tn_id, "f1~note", fts_cl).await;

		assert_eq!(acl_rows(&db, tn_id, "f1~note").await, before, "the ACL columns moved");
		let touched: i64 = sqlx::query_scalar(
			"SELECT count(*) FROM search_docs WHERE tn_id = ? AND updated_at <> 0",
		)
		.bind(tn_id.0)
		.fetch_one(&db)
		.await
		.expect("count touched");
		assert_eq!(touched, 0, "a no-op refresh rewrote rows");
		assert_indexes_intact(&db).await;
	}

	/// A hard delete that skipped the index leaves the document's page bodies
	/// searchable forever unless the orphan sweep reaps `'D'` rows too.
	///
	/// A `'D'` row's `obj_id` *is* its container `file_id`, so the same
	/// missing-`files`-row test that reaps an `'F'` row reaps its parts. The
	/// reindex sweep cannot reach them: it iterates `list_files`, and the file is
	/// gone.
	async fn the_orphan_sweep_reaps_deep_rows_of_a_deleted_file(fts_cl: bool) {
		let (adapter, dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();
		let db = probe(&dir).await;

		create_doc_file(&adapter, tn_id, "f1~ghost", None).await;
		index_doc_parts(&adapter, tn_id, "f1~ghost", None, fts_cl).await;
		index_file(&adapter, tn_id, "f1~ghost", fts_cl).await;

		// A living document, to pin that the sweep only takes the orphans.
		create_doc_file(&adapter, tn_id, "f1~alive", None).await;
		index_doc_parts(&adapter, tn_id, "f1~alive", None, fts_cl).await;
		index_file(&adapter, tn_id, "f1~alive", fts_cl).await;

		assert_eq!(find(&adapter, tn_id, "oldal", fts_cl).await.len(), 4);

		// The hard delete that forgot to notify the index.
		sqlx::query("DELETE FROM files WHERE tn_id = ? AND file_id = ?")
			.bind(tn_id.0)
			.bind("f1~ghost")
			.execute(&db)
			.await
			.expect("hard delete");

		adapter.reap_search_orphans(tn_id).await.expect("reap");

		assert!(
			acl_rows(&db, tn_id, "f1~ghost").await.is_empty(),
			"the deleted document's rows survived the sweep"
		);
		let hits = find(&adapter, tn_id, "oldal", fts_cl).await;
		assert_eq!(hits.len(), 2, "the living document's parts must survive");
		assert!(hits.iter().all(|r| &*r.obj_id == "f1~alive"));
		assert_indexes_intact(&db).await;
	}
}

// --- delegated (share-link) scope grant ------------------------------------

/// Index one row with explicit ACL columns, bypassing the `files` table.
///
/// The other file fixtures here read a real row through `replace_search_row`;
/// what these cases turn on is the exact `visibility`/`root_id`/`obj_tp`
/// combination the SQL predicate branches on, so they are written directly.
async fn index_row(
	adapter: &MetaAdapterSqlite,
	tn_id: TnId,
	obj: &SearchObject<'_>,
	part_id: &str,
) {
	adapter
		.replace_search_object(
			tn_id,
			obj,
			&[SearchPart { part_id, body: Some("kozos titok"), ..Default::default() }],
		)
		.await
		.expect("index");
}

one_mode! {
	/// A share link to a Direct-visibility document must be searchable *inside*
	/// the document its holder can already open, and no wider.
	///
	/// The guest's derived level is Public (a scoped token is never the owner),
	/// so without the grant every Direct row in the tree is filtered out and the
	/// search returns nothing at all. With it, the shared file's own row and every
	/// deep `'D'` part of its tree come back — but a sibling `'F'` file in the same
	/// tree stays hidden, which is the split `GET /api/files` makes too.
	async fn a_share_link_scope_grants_its_document_tree(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);

		// The shared container itself: Direct (NULL visibility).
		let root = SearchObject {
			obj_tp: 'F', obj_id: "f1~doc", visibility: None, fts_cl, ..Default::default()
		};
		index_row(&adapter, tn_id, &root, "").await;
		// Its own deep part.
		let root_part = SearchObject {
			obj_tp: 'D', obj_id: "f1~doc", visibility: None, root_id: Some("f1~doc"),
			fts_cl, ..Default::default()
		};
		index_row(&adapter, tn_id, &root_part, "page1").await;
		// A deep part belonging to a child file of the same tree — the row the
		// `root_id` half of the grant exists for.
		let child_part = SearchObject {
			obj_tp: 'D', obj_id: "f1~child", visibility: None, root_id: Some("f1~doc"),
			fts_cl, ..Default::default()
		};
		index_row(&adapter, tn_id, &child_part, "page1").await;
		// The child file's own row. Direct, in the tree, and deliberately *not*
		// granted.
		let child = SearchObject {
			obj_tp: 'F', obj_id: "f1~child", visibility: None, root_id: Some("f1~doc"),
			fts_cl, ..Default::default()
		};
		index_row(&adapter, tn_id, &child, "").await;

		let granted = SearchOptions {
			visible_levels: Some(vec!['P']),
			scope_file_id: Some("f1~doc".into()),
			scope_grant_file_id: Some("f1~doc".into()),
			..opts("kozos", fts_cl)
		};
		let mut got: Vec<(char, String)> = adapter
			.search(tn_id, &granted)
			.await
			.expect("search")
			.iter()
			.map(|r| (r.obj_tp, r.obj_id.to_string()))
			.collect();
		got.sort();
		assert_eq!(
			got,
			vec![
				('D', "f1~child".to_string()),
				('D', "f1~doc".to_string()),
				('F', "f1~doc".to_string()),
			],
			"the shared file and its deep parts, but not the sibling file's own row"
		);
		assert_eq!(adapter.count_search(tn_id, &granted).await.expect("count"), 3);

		// Same query without the grant: a Public-level caller sees no Direct row.
		let ungranted = SearchOptions { scope_grant_file_id: None, ..granted };
		assert!(adapter.search(tn_id, &ungranted).await.expect("search").is_empty());
	}
}

one_mode! {
	/// The visibility prefilter is the authoritative ACL gate, so it must not let
	/// `'P'` rows through on the strength of a caller in another crate narrowing
	/// `obj_tp` first. An anonymous search sees no profiles at all.
	async fn an_anonymous_caller_gets_no_profile_rows(fts_cl: bool) {
		let (adapter, _dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();
		adapter
			.upsert_profile(
				tn_id,
				"carol.example",
				&UpsertProfileFields {
					name: Patch::Value("Carol Karolina".into()),
					typ: Patch::Value(ProfileType::Person),
					..Default::default()
				},
			)
			.await
			.expect("upsert profile");
		index_profile(&adapter, tn_id, "carol.example", fts_cl).await;

		// No `obj_tp` narrowing at all — the adapter must filter on its own.
		let anon = SearchOptions {
			visible_levels: Some(vec!['P']),
			viewer_id_tag: None,
			..opts("carol", fts_cl)
		};
		assert!(
			adapter.search(tn_id, &anon).await.expect("search").is_empty(),
			"a profile leaked to an anonymous caller"
		);
		assert_eq!(adapter.count_search(tn_id, &anon).await.expect("count"), 0);

		// The same for the "guest"/empty sentinels the handler may pass instead.
		for sentinel in ["guest", ""] {
			let o = SearchOptions {
				visible_levels: Some(vec!['P']),
				viewer_id_tag: Some(sentinel.into()),
				..opts("carol", fts_cl)
			};
			assert!(
				adapter.search(tn_id, &o).await.expect("search").is_empty(),
				"a profile leaked to viewer_id_tag={sentinel:?}"
			);
		}

		// An identified caller still finds it, at the same Public level.
		let identified = SearchOptions { viewer_id_tag: Some("bob.example".into()), ..anon };
		let hits = adapter.search(tn_id, &identified).await.expect("search");
		assert_eq!(hits.len(), 1, "an identified caller must still find profiles");
		assert_eq!(hits[0].obj_tp, 'P');
	}
}

both_modes! {
	/// `replace_search_row` writes the whole-object row, whose `part_kind` comes
	/// from the source row — so hashing the caller's `part_kind` would bust the
	/// short-circuit for a change that cannot be persisted anyway.
	async fn a_part_kind_only_change_does_not_rewrite_the_whole_object_row(fts_cl: bool) {
		let (adapter, dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();
		let db = probe(&dir).await;

		create_doc_file(&adapter, tn_id, "f1~note", None).await;
		let write = async |part_kind: Option<&str>| {
			let part = SearchPart {
				title: Some("cim"),
				part_kind,
				..Default::default()
			};
			adapter
				.replace_search_row(tn_id, 'F', "f1~note", std::slice::from_ref(&part), fts_cl)
				.await
				.expect("index file");
		};
		write(None).await;

		sqlx::query("UPDATE search_docs SET updated_at = 0 WHERE tn_id = ?")
			.bind(tn_id.0)
			.execute(&db)
			.await
			.expect("freeze updated_at");

		write(Some("pages")).await;

		let touched: i64 = sqlx::query_scalar(
			"SELECT count(*) FROM search_docs WHERE tn_id = ? AND updated_at <> 0",
		)
		.bind(tn_id.0)
		.fetch_one(&db)
		.await
		.expect("count touched");
		assert_eq!(touched, 0, "a part_kind-only change rewrote the row");
		assert_indexes_intact(&db).await;
	}
}

// ── `'F'` parts ──
//
// A static file's addressable pieces — a site container's pages, a PDF's pages — get
// their own `search_docs` rows, `obj_tp = 'F'` with a non-empty `part_id`. So
// `replace_search_row` addresses two disjoint row spaces for one object, and one slice
// carries both: replaced together, in one transaction, with no caller-supplied ACL.

/// The file name `create_doc_file` gives every file it makes, and so the title of
/// the metadata part the indexer builds from that row.
const DOC_FILE_NAME: &str = "Jegyzet";

/// Index a container the way the file indexer does: **one** slice, the metadata
/// part first and then one part per addressable piece — for a site, its published
/// pages, keyed by published path.
async fn index_file_parts(
	adapter: &MetaAdapterSqlite,
	tn_id: TnId,
	file_id: &str,
	pages: &[(&str, &str)],
	fts_cl: bool,
) {
	let parts: Vec<SearchPart> =
		std::iter::once(SearchPart { title: Some(DOC_FILE_NAME), ..Default::default() })
			.chain(pages.iter().map(|&(path, body)| SearchPart {
				part_id: path,
				body: Some(body),
				..Default::default()
			}))
			.collect();
	adapter
		.replace_search_row(tn_id, 'F', file_id, &parts, fts_cl)
		.await
		.expect("index file parts");
}

/// The part rows of one `'F'` object, as
/// `(part_id, content_type, owner_tag, visibility, root_id)`.
async fn part_acl_rows(
	db: &sqlx::SqlitePool,
	tn_id: TnId,
	obj_id: &str,
) -> Vec<(String, Option<String>, Option<String>, Option<String>, Option<String>)> {
	sqlx::query_as(
		"SELECT part_id, content_type, owner_tag, visibility, root_id FROM search_docs \
		 WHERE tn_id = ? AND obj_tp = 'F' AND obj_id = ? AND part_id <> '' ORDER BY part_id",
	)
	.bind(tn_id.0)
	.bind(obj_id)
	.fetch_all(db)
	.await
	.expect("read part acl columns")
}

#[tokio::test]
async fn replace_search_row_rejects_mixed_and_non_file_parts() {
	let (adapter, _dir) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.ok();
	create_doc_file(&adapter, tn_id, "f1~note", None).await;

	for parts in [
		// `SEARCH_COLS` has no `parent_part`/`anchor_id` column on the whole-object
		// row, so passing either must reject rather than be silently dropped.
		vec![SearchPart { parent_part: Some("p1"), title: Some("cim"), ..Default::default() }],
		vec![SearchPart { anchor_id: Some("b1"), title: Some("cim"), ..Default::default() }],
		// One call writes one whole-object row.
		vec![
			SearchPart { title: Some("cim"), ..Default::default() },
			SearchPart { title: Some("masik"), ..Default::default() },
		],
		// The whole-object part leads the slice; a second empty `part_id` after a
		// page means something the row space cannot express.
		vec![
			SearchPart { part_id: "/rolunk", title: Some("oldal"), ..Default::default() },
			SearchPart { title: Some("cim"), ..Default::default() },
		],
	] {
		let err = adapter
			.replace_search_row(tn_id, 'F', "f1~note", &parts, false)
			.await
			.expect_err("an ambiguous or unwritable part slice must be rejected");
		assert!(matches!(err, Error::ValidationError(_)), "got {err:?}");
	}

	// Only static files have parts. A profile and an action have no addressable
	// pieces, and a live document's parts go through `replace_search_object`.
	let part = SearchPart { part_id: "/rolunk", title: Some("cim"), ..Default::default() };
	for obj_tp in ['P', 'A', 'D'] {
		let err = adapter
			.replace_search_row(tn_id, obj_tp, "f1~note", std::slice::from_ref(&part), false)
			.await
			.expect_err("only 'F' objects carry parts");
		assert!(matches!(err, Error::ValidationError(_)), "got {err:?}");
	}
}

/// `idx_search_docs_key` is UNIQUE on `(tn_id, obj_tp, obj_id, part_id)` and the part
/// insert carries no `ON CONFLICT`, so two parts on one `part_id` cannot both be written.
/// Two site pages that slugify to one path are exactly that slice — the manifest is
/// publisher-written — and it must come back named rather than as an opaque `DbError`,
/// leaving the file's existing rows alone.
#[tokio::test]
async fn replace_search_row_rejects_a_repeated_part_id() {
	let (adapter, dir) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.ok();
	let db = probe(&dir).await;
	create_doc_file(&adapter, tn_id, "f1~note", None).await;

	index_file_parts(
		&adapter,
		tn_id,
		"f1~note",
		&[("/", "kezdolap"), ("/rolunk", "rolunk")],
		false,
	)
	.await;
	let before = part_acl_rows(&db, tn_id, "f1~note").await;
	assert_eq!(before.len(), 2);

	let parts = vec![
		SearchPart { title: Some(DOC_FILE_NAME), ..Default::default() },
		SearchPart { part_id: "/rolunk", body: Some("egyik"), ..Default::default() },
		SearchPart { part_id: "/rolunk", body: Some("masik"), ..Default::default() },
	];
	let err = adapter
		.replace_search_row(tn_id, 'F', "f1~note", &parts, false)
		.await
		.expect_err("two parts on one part_id must be rejected");
	assert!(matches!(err, Error::ValidationError(_)), "got {err:?}");

	assert_eq!(part_acl_rows(&db, tn_id, "f1~note").await, before, "the rejected call wrote");
	assert_indexes_intact(&db).await;
}

both_modes! {
	/// The part set is replaced whole, so a page dropped from the site stops being
	/// searchable at the next publish rather than lingering as an orphan —
	/// "unpublished" is a real operation, not an absence nobody acts on.
	async fn an_f_part_absent_from_the_new_set_is_dropped(fts_cl: bool) {
		let (adapter, dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();
		let db = probe(&dir).await;

		create_doc_file(&adapter, tn_id, "f1~site", None).await;
		index_file_parts(
			&adapter,
			tn_id,
			"f1~site",
			&[("/", "kezdolap szoveg"), ("/rolunk", "bemutatkozas")],
			fts_cl,
		)
		.await;
		assert_eq!(find(&adapter, tn_id, "bemutatkozas", fts_cl).await.len(), 1);

		index_file_parts(&adapter, tn_id, "f1~site", &[("/", "kezdolap szoveg")], fts_cl).await;

		assert!(
			find(&adapter, tn_id, "bemutatkozas", fts_cl).await.is_empty(),
			"an unpublished page must stop being searchable"
		);
		let hits = find(&adapter, tn_id, "kezdolap", fts_cl).await;
		assert_eq!(hits.len(), 1, "the page still in the set must survive");
		assert_eq!(hits[0].obj_tp, 'F');
		assert_eq!(&*hits[0].part_id, "/", "the site path is the part id");
		assert_indexes_intact(&db).await;
	}
}

both_modes! {
	/// Every ACL column on an `'F'` part comes from the container's `files` row.
	///
	/// `SearchPart` carries no ACL field, so `refresh_file_acl` (and
	/// `fill_part_created_at` for `created_at`) is the only thing that can give one a
	/// value — index and source cannot disagree about who may see a hit. `root_id` is
	/// plain `files.root_id`, so a file-scoped share token prefilters a part exactly as it
	/// prefilters the file.
	async fn f_part_acl_columns_come_from_the_container_file_row(fts_cl: bool) {
		let (adapter, dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();
		let db = probe(&dir).await;

		create_doc_file(&adapter, tn_id, "f1~site", Some("bob.example")).await;
		index_file_parts(&adapter, tn_id, "f1~site", &[("/", "kezdolap szoveg")], fts_cl).await;

		let rows = part_acl_rows(&db, tn_id, "f1~site").await;
		assert_eq!(rows.len(), 1);
		let (part_id, content_type, owner_tag, visibility, root_id) = &rows[0];
		assert_eq!(part_id, "/");
		assert_eq!(content_type.as_deref(), Some("application/x-notillo"));
		assert_eq!(owner_tag.as_deref(), Some("bob.example"));
		assert_eq!(visibility.as_deref(), Some("P"));
		assert_eq!(root_id.as_deref(), None, "an 'F' part must not resolve root_id");

		// A republish that changed no text takes the hash short-circuit, which
		// skips the upsert but must still re-derive — it is then the only statement
		// that carries a visibility flip onto the part rows.
		sqlx::query("UPDATE files SET visibility = 'D' WHERE tn_id = ? AND file_id = ?")
			.bind(tn_id.0)
			.bind("f1~site")
			.execute(&db)
			.await
			.expect("flip visibility");
		index_file_parts(&adapter, tn_id, "f1~site", &[("/", "kezdolap szoveg")], fts_cl).await;

		let rows = part_acl_rows(&db, tn_id, "f1~site").await;
		assert_eq!(rows[0].3.as_deref(), Some("D"), "the hash short-circuit skipped the derive");
		// `find` is the tenant-owner search (`visible_levels: None`), which is
		// unfiltered and keeps seeing the row; an anonymous caller gets `['P']`.
		let anon = SearchOptions { visible_levels: Some(vec!['P']), ..opts("kezdolap", fts_cl) };
		assert!(
			adapter.search(tn_id, &anon).await.expect("search").is_empty(),
			"a page of a file no longer Public must drop out of an anonymous search"
		);
		assert_eq!(
			find(&adapter, tn_id, "kezdolap", fts_cl).await.len(),
			1,
			"the owner keeps finding their own page"
		);
		assert_indexes_intact(&db).await;
	}
}

both_modes! {
	/// A file's metadata row and its parts are one slice and one replacement, so a write
	/// can never land half of it. Dropping the page parts — what a container displaced out
	/// of `published_file_id` produces — takes its pages out of the index and leaves the
	/// container searchable by name.
	async fn an_f_slice_carries_the_file_row_and_its_pages_together(fts_cl: bool) {
		let (adapter, dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();
		let db = probe(&dir).await;

		create_doc_file(&adapter, tn_id, "f1~site", None).await;
		index_file_parts(&adapter, tn_id, "f1~site", &[("/", "kezdolap szoveg")], fts_cl).await;

		assert_eq!(
			find(&adapter, tn_id, DOC_FILE_NAME, fts_cl).await.len(),
			1,
			"the file's own row"
		);
		assert_eq!(find(&adapter, tn_id, "kezdolap", fts_cl).await.len(), 1, "the page row");
		assert_eq!(part_acl_rows(&db, tn_id, "f1~site").await.len(), 1);

		// The metadata part alone, and a changed title so this takes the
		// delete-and-insert path rather than the short-circuit.
		let part = SearchPart { title: Some("Atnevezett"), ..Default::default() };
		adapter
			.replace_search_row(tn_id, 'F', "f1~site", std::slice::from_ref(&part), fts_cl)
			.await
			.expect("reindex the container with no live pages");

		assert_eq!(find(&adapter, tn_id, "Atnevezett", fts_cl).await.len(), 1);
		assert!(
			find(&adapter, tn_id, "kezdolap", fts_cl).await.is_empty(),
			"a slice with no page parts drops the pages it replaces"
		);
		assert!(part_acl_rows(&db, tn_id, "f1~site").await.is_empty());
		assert_indexes_intact(&db).await;
	}
}

both_modes! {
	/// With no `files` row there is no ACL to derive, so a part write becomes a delete —
	/// the same postcondition the whole-object path keeps, and what stops a container
	/// reaped between the caller's read and the index run leaving its pages searchable.
	async fn an_f_part_write_with_no_source_row_is_a_delete(fts_cl: bool) {
		let (adapter, dir) = create_test_adapter().await;
		let tn_id = TnId(1);
		adapter.create_tenant(tn_id, "alice").await.ok();
		let db = probe(&dir).await;

		create_doc_file(&adapter, tn_id, "f1~site", None).await;
		index_file_parts(&adapter, tn_id, "f1~site", &[("/", "kezdolap szoveg")], fts_cl).await;
		assert_eq!(find(&adapter, tn_id, "kezdolap", fts_cl).await.len(), 1);

		sqlx::query("DELETE FROM files WHERE tn_id = ? AND file_id = ?")
			.bind(tn_id.0)
			.bind("f1~site")
			.execute(&db)
			.await
			.expect("drop the source row");

		// Identical parts, so the hash still matches — but the short-circuit is
		// gated on the source row being there, and it is not.
		index_file_parts(&adapter, tn_id, "f1~site", &[("/", "kezdolap szoveg")], fts_cl).await;

		assert!(
			find(&adapter, tn_id, "kezdolap", fts_cl).await.is_empty(),
			"an index row must never outlive the source row it mirrors"
		);
		assert!(part_acl_rows(&db, tn_id, "f1~site").await.is_empty());
		assert_indexes_intact(&db).await;
	}
}

#[tokio::test]
async fn a_row_with_an_undecodable_obj_tp_is_skipped_not_reported_as_a_file() {
	let (adapter, dir) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.ok();
	index_text(&adapter, tn_id, "f1~note", "korte alma", false).await;
	assert_eq!(find(&adapter, tn_id, "alma", false).await.len(), 1);

	// `obj_tp` is `char(1) NOT NULL`, but SQLite enforces neither the length nor a
	// CHECK, so corrupt index data can carry `''`.
	let db = probe(&dir).await;
	sqlx::query("UPDATE search_docs SET obj_tp = '' WHERE tn_id = ?")
		.bind(tn_id.0)
		.execute(&db)
		.await
		.expect("corrupt obj_tp");

	assert!(
		find(&adapter, tn_id, "alma", false).await.is_empty(),
		"a corrupt row came back, most likely mislabelled as a file"
	);
}

// vim: ts=4
