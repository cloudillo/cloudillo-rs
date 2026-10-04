// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! The v58 entry/file split: one immutable BLOB placed by several entries.
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use cloudillo_meta_adapter_sqlite::MetaAdapterSqlite;
use cloudillo_types::error::Error;
use cloudillo_types::meta_adapter::{
	CreateFile, CreatedFile, FileId, FileStatus, ListFileOptions, MANAGED_PARENT_ID, MetaAdapter,
	TRASH_PARENT_ID, UpdateFileOptions,
};
use cloudillo_types::types::{Patch, Timestamp, TnId};
use cloudillo_types::worker::WorkerPool;
use tempfile::TempDir;

const TN: TnId = TnId(1);

async fn create_test_adapter() -> (MetaAdapterSqlite, TempDir) {
	let temp_dir = TempDir::new().expect("Failed to create temp directory");
	let worker_pool = Arc::new(WorkerPool::new(1, 1, 1));
	let adapter = MetaAdapterSqlite::new(worker_pool, temp_dir.path())
		.await
		.expect("Failed to create adapter");
	adapter.create_tenant(TN, "alice").await.expect("create tenant");
	(adapter, temp_dir)
}

async fn folder(adapter: &MetaAdapterSqlite, id: &str) -> CreatedFile {
	adapter
		.create_file(
			TN,
			CreateFile {
				file_id: Some(id.into()),
				file_name: id.into(),
				file_tp: Some("FLDR".into()),
				status: Some(FileStatus::Active),
				..Default::default()
			},
		)
		.await
		.expect("create folder")
}

/// One upload into `parent`, see [`common::upload`].
async fn upload(
	adapter: &MetaAdapterSqlite,
	parent: &str,
	upstream_tag: Option<&str>,
	variant_id: &str,
	file_id: &str,
) -> CreatedFile {
	let file = CreateFile {
		parent_id: Some(parent.into()),
		upstream_tag: upstream_tag.map(Into::into),
		orig_variant_id: Some(variant_id.into()),
		file_name: "kep.png".into(),
		..Default::default()
	};
	common::upload(adapter, TN, file, file_id).await
}

#[tokio::test]
async fn dedup_into_two_folders_gives_two_entries_one_file() {
	let (adapter, temp) = create_test_adapter().await;
	folder(&adapter, "fold-a").await;
	folder(&adapter, "fold-b").await;

	let first = upload(&adapter, "fold-a", None, "b1~same", "f1~same").await;
	let second = upload(&adapter, "fold-b", None, "b1~same", "f1~other").await;
	assert!(matches!(&second.file_id, FileId::FileId(id) if &**id == "f1~same"), "{second:?}");
	// Clients require a content type; a folder has no `files` row to carry one.
	let fold = adapter.read_file(TN, "fold-a").await.expect("read").expect("folder");
	assert_eq!(fold.content_type.as_deref(), Some("cloudillo/folder"));
	assert_ne!(first.entry_id, second.entry_id);

	for (entry, parent) in [(&first.entry_id, "fold-a"), (&second.entry_id, "fold-b")] {
		let view = adapter.read_file(TN, entry).await.expect("read").expect("entry");
		assert_eq!(view.index_id(), "f1~same");
		assert_eq!(view.parent_id.as_deref(), Some(parent));
	}
	// The content id names two placements: ambiguous.
	assert!(adapter.read_file(TN, "f1~same").await.is_err());

	// Deleting one entry keeps the other and the content.
	let gone = adapter
		.hard_delete_file(TN, common::e_id_of_entry(&temp, &first.entry_id).await)
		.await;
	assert_eq!(gone.expect("hard delete").as_deref(), Some("f1~same"), "reindex key");
	let left = adapter.read_file(TN, "f1~same").await.expect("read").expect("single entry");
	assert_eq!(left.entry_id, second.entry_id);

	// Nor does the last entry take the content: it outlives it until the orphan reap.
	adapter
		.hard_delete_file(TN, common::e_id_of_entry(&temp, &second.entry_id).await)
		.await
		.expect("hard delete");
	let variants = adapter.list_file_variants(TN, FileId::FileId("f1~same")).await;
	assert_eq!(variants.expect("variants").len(), 1, "content kept");
}

/// Content no entry references is reaped only once its window has passed, variants included.
#[tokio::test]
async fn orphan_content_is_reaped_only_after_the_window() {
	let (adapter, temp) = create_test_adapter().await;
	folder(&adapter, "fold-a").await;
	let up = upload(&adapter, "fold-a", None, "b1~orph", "f1~orph").await;
	let kept = upload(&adapter, "fold-a", None, "b1~kept", "f1~kept").await;
	adapter
		.hard_delete_file(TN, common::e_id_of_entry(&temp, &up.entry_id).await)
		.await
		.expect("hard delete");

	let early = adapter.reap_orphan_files(TN, Timestamp(0)).await.expect("reap");
	assert!(early.is_empty(), "inside the window: {early:?}");
	let late = Timestamp(Timestamp::now().0 + 10);
	let reaped = adapter.reap_orphan_files(TN, late).await.expect("reap");
	assert_eq!(reaped, vec![Box::<str>::from("f1~orph")]);
	let variants = adapter.list_file_variants(TN, FileId::FileId("f1~orph")).await;
	assert!(variants.expect("variants").is_empty(), "variants go with the content");
	// Placed content is never an orphan.
	assert!(adapter.read_file(TN, &kept.entry_id).await.expect("read").is_some());
	assert!(adapter.reap_orphan_files(TN, late).await.expect("reap").is_empty());
}

/// Content a column names (profile picture, published site container) is kept although no
/// entry places it: the GC sources that protect managed content protect orphans too.
#[tokio::test]
async fn column_referenced_content_is_never_reaped() {
	let (adapter, temp) = create_test_adapter().await;
	folder(&adapter, "fold-a").await;
	let pic = upload(&adapter, "fold-a", None, "b1~pic", "f1~pic").await;
	let site = upload(&adapter, "fold-a", None, "b1~site", "f1~site").await;
	for up in [&pic, &site] {
		adapter
			.hard_delete_file(TN, common::e_id_of_entry(&temp, &up.entry_id).await)
			.await
			.expect("hard delete");
	}
	let pool = sqlx::sqlite::SqlitePoolOptions::new()
		.connect(&format!("sqlite://{}/meta.db", temp.path().display()))
		.await
		.expect("open meta.db");
	for sql in [
		"INSERT INTO profiles (tn_id, id_tag, name, profile_pic) \
		 VALUES (?1, 'bob.example', 'Bob', 'f1~pic')",
		"INSERT INTO site_docs (tn_id, doc_file_id, mount_path, published_file_id) \
		 VALUES (?1, 'doc', '/', 'f1~site')",
	] {
		sqlx::query(sql).bind(TN.0).execute(&pool).await.expect(sql);
	}
	pool.close().await;

	let late = Timestamp(Timestamp::now().0 + 10);
	let reaped = adapter.reap_orphan_files(TN, late).await.expect("reap");
	assert!(reaped.is_empty(), "referenced content reaped: {reaped:?}");
}

/// A folder create reusing a non-folder entry's id is a conflict, not a constraint failure.
#[tokio::test]
async fn a_folder_cannot_take_a_content_entrys_id() {
	let (adapter, _temp) = create_test_adapter().await;
	folder(&adapter, "fold-a").await;
	let up = upload(&adapter, "fold-a", None, "b1~taken", "f1~taken").await;
	let res = adapter
		.create_file(
			TN,
			CreateFile {
				file_id: Some(up.entry_id.clone()),
				file_name: "dup".into(),
				file_tp: Some("FLDR".into()),
				status: Some(FileStatus::Active),
				..Default::default()
			},
		)
		.await;
	assert!(matches!(res, Err(Error::Conflict(_))), "{res:?}");
	// The folder's own id stays idempotent.
	assert_eq!(folder(&adapter, "fold-a").await.entry_id.as_ref(), "fold-a");
}

/// Sync content only an action's entry holds gets an action-free managed entry (a profile
/// picture landing on it), so the content outlives the action.
#[tokio::test]
async fn an_action_free_managed_entry_outlives_the_action() {
	let (adapter, temp) = create_test_adapter().await;
	folder(&adapter, "fold-a").await;
	let up = upload(&adapter, "fold-a", None, "b1~shared", "f1~shared").await;
	adapter
		.create_managed_entry(TN, "f1~shared", "x", Some("a1~post"), Some('F'), None)
		.await
		.expect("action entry");
	adapter
		.hard_delete_file(TN, common::e_id_of_entry(&temp, &up.entry_id).await)
		.await
		.expect("hard delete");

	let pic = adapter
		.create_managed_entry(TN, "f1~shared", "x", None, Some('P'), None)
		.await
		.expect("action-free entry");
	let again = adapter
		.create_managed_entry(TN, "f1~shared", "x", None, Some('P'), None)
		.await
		.expect("idempotent");
	assert_eq!(pic, again, "one action-free entry per content");

	adapter.delete_managed_entries(TN, "a1~post").await.expect("action dies");
	let late = Timestamp(Timestamp::now().0 + 10);
	let reaped = adapter.reap_orphan_files(TN, late).await.expect("reap");
	assert!(reaped.is_empty(), "content reaped under its profile picture: {reaped:?}");
	assert!(adapter.read_file(TN, &pic).await.expect("read").is_some());
}

/// A removed entry's per-user rows go with it: `e_id` is a reused rowid.
#[tokio::test]
async fn hard_delete_removes_the_entrys_user_data() {
	let (adapter, temp) = create_test_adapter().await;
	folder(&adapter, "fold-a").await;
	let up = upload(&adapter, "fold-a", None, "b1~fud", "f1~fud").await;
	adapter
		.update_file_user_data(
			TN,
			"bob",
			&up.entry_id,
			Patch::Value(true),
			Patch::Value(true),
			Patch::Value('W'),
		)
		.await
		.expect("user data");
	let e_id = common::e_id_of_entry(&temp, &up.entry_id).await;
	adapter.hard_delete_file(TN, e_id).await.expect("hard delete");

	let pool = sqlx::sqlite::SqlitePoolOptions::new()
		.connect(&format!("sqlite://{}/meta.db", temp.path().display()))
		.await
		.expect("open meta.db");
	let left: i64 = sqlx::query_scalar("SELECT count(*) FROM file_user_data WHERE e_id = ?")
		.bind(i64::try_from(e_id).expect("e_id"))
		.fetch_one(&pool)
		.await
		.expect("count");
	assert_eq!(left, 0);
}

/// `root_id` is hashed into the content id: the same bytes in another document tree (or none)
/// are other content, never a new entry over it.
#[tokio::test]
async fn upload_dedup_respects_the_document_root() {
	let (adapter, _temp) = create_test_adapter().await;
	folder(&adapter, "fold-a").await;
	let file = |root: Option<&str>| CreateFile {
		parent_id: Some("fold-a".into()),
		root_id: root.map(Into::into),
		orig_variant_id: Some("b1~tree".into()),
		file_name: "kep.png".into(),
		..Default::default()
	};
	common::upload(&adapter, TN, file(Some("c1~doc")), "f1~in-tree").await;
	let private = common::upload(&adapter, TN, file(None), "f1~private").await;
	assert!(matches!(private.file_id, FileId::FId(_)), "no dedup across roots: {private:?}");
	let view = adapter.read_file(TN, &private.entry_id).await.expect("read").expect("entry");
	assert_eq!(view.index_id(), "f1~private");
	assert!(view.root_id.is_none());
	// Same root: dedup as before.
	let again = common::upload(&adapter, TN, file(Some("c1~doc")), "f1~x").await;
	assert!(matches!(&again.file_id, FileId::FileId(id) if &**id == "f1~in-tree"), "{again:?}");
}

/// A reference (upstream set) never links local content: it is an entry alone, carrying the
/// upstream content id and display fields, however much local content shares the id.
#[tokio::test]
async fn a_reference_never_links_local_content() {
	let (adapter, temp) = create_test_adapter().await;
	folder(&adapter, "fold-a").await;
	let local = upload(&adapter, "fold-a", None, "b1~l", "f1~same").await;

	let pin = adapter
		.create_file(
			TN,
			CreateFile {
				file_id: Some("f1~same".into()),
				parent_id: Some("fold-a".into()),
				upstream_tag: Some("bob.example".into()),
				owner_tag: Some("mallory".into()),
				content_type: "image/jpeg".into(),
				file_name: "pinned.jpg".into(),
				file_tp: Some("BLOB".into()),
				x: Some(serde_json::json!({"dim": [4, 3]})),
				preset: Some("apkg".into()),
				status: Some(FileStatus::Active),
				..Default::default()
			},
		)
		.await
		.expect("pin");
	assert!(matches!(&pin.file_id, FileId::FileId(id) if &**id == "f1~same"), "{pin:?}");

	let p = adapter.read_file(TN, &pin.entry_id).await.expect("read").expect("pin");
	assert_eq!(p.index_id(), "f1~same");
	assert_eq!(p.upstream_tag.as_deref(), Some("bob.example"));
	assert_eq!(p.file_tp.as_deref(), Some("BLOB"), "a reference is not a folder");
	assert_eq!(p.content_type.as_deref(), Some("image/jpeg"), "its own display fields");
	assert_eq!(p.preset.as_deref(), Some("apkg"), "its own preset, not the local content's");
	let l = adapter.read_file(TN, &local.entry_id).await.expect("read").expect("local");
	assert_eq!(l.content_type.as_deref(), Some("image/png"), "local content untouched");

	let pool = sqlx::sqlite::SqlitePoolOptions::new()
		.connect(&format!("sqlite://{}/meta.db", temp.path().display()))
		.await
		.expect("open meta.db");
	let f_id: Option<i64> = sqlx::query_scalar("SELECT f_id FROM entries WHERE entry_id = ?")
		.bind(&*pin.entry_id)
		.fetch_one(&pool)
		.await
		.expect("f_id");
	assert_eq!(f_id, None, "a reference has no local file");

	// The content id now names the local entry and the reference: ambiguous.
	assert!(matches!(adapter.read_file(TN, "f1~same").await, Err(Error::Conflict(_))));
	let entries = adapter.list_content_entries(TN, "f1~same").await.expect("entries");
	assert_eq!(entries.len(), 2);
	// A reference with no local content anywhere still lists by its content id.
	let listed = adapter
		.list_files(
			TN,
			&ListFileOptions { file_id: Some(vec!["f1~same".into()]), ..Default::default() },
		)
		.await
		.expect("list");
	assert_eq!(listed.len(), 2, "{listed:?}");
}

/// A Pin-style mirror holds no local bytes; finalizing an upload of the same content onto it
/// must move the upload's variants over, not drop them.
#[tokio::test]
async fn finalize_onto_a_variantless_mirror_moves_the_variants() {
	let (adapter, _temp) = create_test_adapter().await;
	folder(&adapter, "fold-a").await;

	adapter
		.create_file(
			TN,
			CreateFile {
				file_id: Some("f1~pin".into()),
				parent_id: Some("fold-a".into()),
				upstream_tag: Some("bob.example".into()),
				content_type: "image/png".into(),
				file_name: "kep.png".into(),
				file_tp: Some("BLOB".into()),
				status: Some(FileStatus::Active),
				..Default::default()
			},
		)
		.await
		.expect("pin");
	upload(&adapter, "fold-a", None, "b1~up", "f1~pin").await;

	let variants = adapter
		.list_file_variants(TN, FileId::FileId("f1~pin"))
		.await
		.expect("variants");
	assert!(
		variants
			.iter()
			.any(|v| &*v.variant == "orig" && &*v.variant_id == "b1~up" && v.available),
		"{variants:?}"
	);
}

#[tokio::test]
async fn explicit_id_create_is_idempotent_per_origin() {
	let (adapter, _temp) = create_test_adapter().await;
	let create = |file_id: &'static str, tp: &'static str, upstream: Option<&'static str>| {
		let adapter = &adapter;
		async move {
			adapter
				.create_file(
					TN,
					CreateFile {
						file_id: Some(file_id.into()),
						upstream_tag: upstream.map(Into::into),
						content_type: "application/octet-stream".into(),
						file_name: "x".into(),
						file_tp: Some(tp.into()),
						status: Some(FileStatus::Active),
						..Default::default()
					},
				)
				.await
		}
	};

	let a = create("f1~blob", "BLOB", Some("bob.example")).await.expect("first");
	let b = create("f1~blob", "BLOB", Some("bob.example")).await.expect("retry");
	assert_eq!(a.entry_id, b.entry_id, "same reference: idempotent");
	let c = create("f1~blob", "BLOB", Some("carol.example")).await.expect("other origin");
	assert_ne!(a.entry_id, c.entry_id, "one reference per origin");
	let c = adapter.read_file(TN, &c.entry_id).await.expect("read").expect("entry");
	assert_eq!(c.upstream_tag.as_deref(), Some("carol.example"));

	// References never touch local content, so they never collide with it.
	create("c1~doc", "CRDT", Some("bob.example")).await.expect("crdt reference");
	create("c1~doc", "CRDT", Some("carol.example")).await.expect("second reference");
	create("c1~doc", "CRDT", None).await.expect("local content of the same id");
	// Local non-BLOB content still carries a single live entry.
	assert!(matches!(
		adapter
			.create_file(
				TN,
				CreateFile {
					file_id: Some("c1~doc".into()),
					parent_id: Some("elsewhere".into()),
					content_type: "application/octet-stream".into(),
					file_name: "x".into(),
					file_tp: Some("CRDT".into()),
					status: Some(FileStatus::Active),
					..Default::default()
				},
			)
			.await,
		Err(Error::Conflict(_))
	));
}

#[tokio::test]
async fn a_pinned_folder_keeps_its_upstream() {
	let (adapter, _temp) = create_test_adapter().await;
	let created = adapter
		.create_file(
			TN,
			CreateFile {
				file_id: Some("fold-pin".into()),
				upstream_tag: Some("bob.example".into()),
				file_name: "pinned".into(),
				file_tp: Some("FLDR".into()),
				status: Some(FileStatus::Active),
				..Default::default()
			},
		)
		.await
		.expect("pin folder");
	// A reference never takes the remote id as its entry id: it could shadow local content.
	assert_ne!(&*created.entry_id, "fold-pin");
	let view = adapter.read_file(TN, &created.entry_id).await.expect("read").expect("folder");
	assert_eq!(view.upstream_tag.as_deref(), Some("bob.example"));
	assert_eq!(view.index_id(), "fold-pin");
	assert_eq!(view.file_tp.as_deref(), Some("FLDR"));
}

/// A sync mirror's content gets no entry until its variants are in: a sync that fails midway
/// leaves the row entry-less, and the retry's managed entry lands exactly once.
#[tokio::test]
async fn sync_content_gets_its_entry_only_after_finalize() {
	let (adapter, _temp) = create_test_adapter().await;
	let f_id = adapter
		.create_sync_content(TN, "f1~mirror", None, "image/png", None)
		.await
		.expect("sync content");
	let again = adapter
		.create_sync_content(TN, "f1~mirror", None, "image/png", None)
		.await
		.expect("sync content again");
	assert_eq!(f_id, again, "idempotent");

	let content = adapter.read_content(TN, "f1~mirror").await.expect("content");
	assert_eq!(content.f_id, f_id);
	assert_eq!(content.preset.as_deref(), Some("sync"));
	assert!(!content.has_entries);
	assert!(adapter.read_file(TN, "f1~mirror").await.expect("read").is_none(), "no entry");

	adapter.finalize_file(TN, f_id, "f1~mirror").await.expect("finalize");
	let entry = adapter
		.create_managed_entry(TN, "f1~mirror", "pic.png", None, Some('P'), None)
		.await
		.expect("managed entry");
	let repeat = adapter
		.create_managed_entry(TN, "f1~mirror", "pic.png", None, Some('P'), None)
		.await
		.expect("managed entry again");
	assert_eq!(entry, repeat, "idempotent for a NULL action");
	let view = adapter.read_file(TN, "f1~mirror").await.expect("read").expect("one entry");
	assert_eq!(view.entry_id, entry);
	assert!(matches!(view.status, FileStatus::Active));
	assert!(adapter.read_content(TN, "f1~mirror").await.expect("content").has_entries);
}

#[tokio::test]
async fn finalize_repoints_onto_existing_content() {
	let (adapter, _temp) = create_test_adapter().await;
	folder(&adapter, "fold-a").await;

	upload(&adapter, "fold-a", None, "b1~one", "f1~same").await;
	// A different orig variant: no dedup hit, but it hashes to the same content id.
	let second = upload(&adapter, "fold-a", None, "b1~two", "f1~same").await;
	assert!(matches!(second.file_id, FileId::FId(_)));

	let view = adapter.read_file(TN, &second.entry_id).await.expect("read").expect("entry");
	assert_eq!(view.index_id(), "f1~same", "the pending entry moved to the existing file");
	let f_id = adapter.read_content(TN, "f1~same").await.expect("f_id").f_id;
	assert!(adapter.read_file(TN, &format!("@{f_id}")).await.is_err(), "two entries now");
}

/// After a dedup merge the upload's `@<f_id>` names no entry (clients use the `entryId`), but
/// content lookups through it still follow the redirect.
#[tokio::test]
async fn a_deduped_pending_f_id_redirects_to_the_surviving_content() {
	let (adapter, _temp) = create_test_adapter().await;
	folder(&adapter, "fold-a").await;

	upload(&adapter, MANAGED_PARENT_ID, None, "b1~one", "f1~same").await;
	let second = upload(&adapter, "fold-a", None, "b1~two", "f1~same").await;
	let FileId::FId(old) = second.file_id else { panic!("no dedup hit expected: {second:?}") };

	assert_eq!(&*adapter.get_file_id(TN, old).await.expect("get_file_id"), "f1~same");
	let at_old = format!("@{old}");
	let variants = adapter.list_file_variants(TN, FileId::FileId(&at_old)).await.expect("variants");
	assert!(variants.iter().any(|v| &*v.variant_id == "b1~one"), "{variants:?}");
	// Entry-level: no entry matches, rather than every entry of the merged content.
	assert!(adapter.read_file(TN, &format!("@{old}")).await.expect("read").is_none());
	let view = adapter.read_file(TN, &second.entry_id).await.expect("read").expect("entry");
	assert_eq!(view.index_id(), "f1~same");
	let entries = adapter.list_content_entries(TN, &format!("@{old}")).await.expect("list");
	assert_eq!(entries.len(), 2, "the redirect reaches every entry of the content");
}

#[tokio::test]
async fn a_fresh_entry_keeps_entry_and_content_ids_apart() {
	let (adapter, temp) = create_test_adapter().await;
	// Folders take entry rows but no file rows, so every later e_id runs ahead of its f_id.
	folder(&adapter, "fold-a").await;
	folder(&adapter, "fold-b").await;

	let created = upload(&adapter, "fold-a", None, "b1~fresh", "f1~fresh").await;
	let e_id = common::e_id_of_entry(&temp, &created.entry_id).await;
	let f_id = adapter.read_content(TN, "f1~fresh").await.expect("f_id").f_id;
	assert_ne!(e_id, f_id, "the fixture must separate the two id spaces");

	// `@<f_id>` names content, never an entry's e_id.
	let view = adapter
		.read_file(TN, &format!("@{f_id}"))
		.await
		.expect("read")
		.expect("by f_id");
	assert_eq!(view.entry_id, created.entry_id);
	assert!(adapter.read_file(TN, &format!("@{e_id}")).await.expect("read").is_none());

	// `hard_delete_file` takes the e_id and reports the content id.
	let gone = adapter.hard_delete_file(TN, e_id).await.expect("hard delete");
	assert_eq!(gone.as_deref(), Some("f1~fresh"));
}

#[tokio::test]
async fn managed_references_report_content_f_ids() {
	use cloudillo_types::meta_adapter::MANAGED_PARENT_ID;

	let (adapter, temp) = create_test_adapter().await;
	folder(&adapter, "fold-a").await;
	folder(&adapter, "fold-b").await;

	let created = upload(&adapter, MANAGED_PARENT_ID, None, "b1~pic", "f1~pic").await;
	let e_id = common::e_id_of_entry(&temp, &created.entry_id).await;
	let f_id = adapter.read_content(TN, "f1~pic").await.expect("f_id").f_id;
	assert_ne!(e_id, f_id, "the fixture must separate the two id spaces");

	// A tenant profile picture is a managed reference; set it directly in the db.
	let pool = sqlx::sqlite::SqlitePoolOptions::new()
		.connect(&format!("sqlite://{}/meta.db", temp.path().display()))
		.await
		.expect("open meta.db");
	sqlx::query("UPDATE tenants SET profile_pic = 'f1~pic' WHERE tn_id = ?")
		.bind(TN.0)
		.execute(&pool)
		.await
		.expect("set profile_pic");
	pool.close().await;

	let fids = adapter.list_referenced_managed_fids(TN).await.expect("referenced");
	assert!(fids.contains(&f_id), "content f_id reported");
	assert!(!fids.contains(&e_id), "never the entry's e_id");
}

/// A deleted action keeps no managed attachment alive; a live one does.
#[tokio::test]
async fn only_live_actions_keep_managed_attachments() {
	let (adapter, temp) = create_test_adapter().await;
	upload(&adapter, MANAGED_PARENT_ID, None, "b1~live", "f1~live").await;
	upload(&adapter, MANAGED_PARENT_ID, None, "b1~dead", "f1~dead").await;
	let live = adapter.read_content(TN, "f1~live").await.expect("live").f_id;
	let dead = adapter.read_content(TN, "f1~dead").await.expect("dead").f_id;

	let pool = sqlx::sqlite::SqlitePoolOptions::new()
		.connect(&format!("sqlite://{}/meta.db", temp.path().display()))
		.await
		.expect("open meta.db");
	sqlx::query(
		"INSERT INTO actions (tn_id, type, issuer_tag, status, attachments) \
		 VALUES (?1, 'POST', 'alice', 'A', 'f1~live'), (?1, 'POST', 'alice', 'D', 'f1~dead')",
	)
	.bind(TN.0)
	.execute(&pool)
	.await
	.expect("insert actions");
	pool.close().await;

	let fids = adapter.list_referenced_managed_fids(TN).await.expect("referenced");
	assert!(fids.contains(&live), "a live action keeps its attachment");
	assert!(!fids.contains(&dead), "a deleted action keeps nothing");
}

/// An action-owned managed entry lives and dies with its action, whatever else references the
/// content: a deleted action's entry is a GC candidate (no f_id to keep it), a live one's is not,
/// and an unowned upload entry keeps the per-content rule.
#[tokio::test]
async fn a_dead_action_frees_its_own_managed_entry() {
	let (adapter, temp) = create_test_adapter().await;
	let upload_entry = upload(&adapter, MANAGED_PARENT_ID, None, "b1~m3", "f1~m3").await;
	let f_id = adapter.read_content(TN, "f1~m3").await.expect("f_id").f_id;
	let live = adapter
		.create_managed_entry(TN, "f1~m3", "x", Some("a1~live"), None, None)
		.await
		.expect("live entry");
	let dead = adapter
		.create_managed_entry(TN, "f1~m3", "x", Some("a1~dead"), None, None)
		.await
		.expect("dead entry");

	let pool = sqlx::sqlite::SqlitePoolOptions::new()
		.connect(&format!("sqlite://{}/meta.db", temp.path().display()))
		.await
		.expect("open meta.db");
	sqlx::query(
		"INSERT INTO actions (tn_id, action_id, type, issuer_tag, status, attachments) \
		 VALUES (?1, 'a1~live', 'POST', 'alice', 'A', 'f1~m3'), \
		 (?1, 'a1~dead', 'POST', 'alice', 'D', 'f1~m3')",
	)
	.bind(TN.0)
	.execute(&pool)
	.await
	.expect("insert actions");
	pool.close().await;

	let candidates = adapter
		.list_files_by_parent(TN, MANAGED_PARENT_ID, Timestamp(i64::MAX))
		.await
		.expect("candidates");
	let (live, dead, unowned) = (
		common::e_id_of_entry(&temp, &live).await,
		common::e_id_of_entry(&temp, &dead).await,
		common::e_id_of_entry(&temp, &upload_entry.entry_id).await,
	);
	assert!(candidates.contains(&(dead, None)), "dead action's entry: {candidates:?}");
	assert!(!candidates.iter().any(|(e, _)| *e == live), "live action's entry listed");
	assert!(candidates.contains(&(unowned, Some(f_id))), "unowned upload: {candidates:?}");
}

/// A draft names its attachment as `@<f_id>` until the creator task resolves it. When that
/// upload dedups into existing content, the GC scan follows the redirect: the draft still
/// protects the content its managed entry was repointed onto.
#[tokio::test]
async fn a_draft_at_f_id_protects_the_content_it_was_deduped_into() {
	let (adapter, temp) = create_test_adapter().await;

	upload(&adapter, MANAGED_PARENT_ID, None, "b1~one", "f1~same").await;
	let second = upload(&adapter, MANAGED_PARENT_ID, None, "b1~two", "f1~same").await;
	let FileId::FId(old) = second.file_id else { panic!("no dedup hit expected: {second:?}") };
	let surviving = adapter.read_content(TN, "f1~same").await.expect("f_id").f_id;
	assert_ne!(old, surviving, "the fixture must dedup onto other content");

	let pool = sqlx::sqlite::SqlitePoolOptions::new()
		.connect(&format!("sqlite://{}/meta.db", temp.path().display()))
		.await
		.expect("open meta.db");
	sqlx::query(
		"INSERT INTO actions (tn_id, type, issuer_tag, status, attachments) \
		 VALUES (?, 'POST', 'alice', 'R', ?)",
	)
	.bind(TN.0)
	.bind(format!("@{old}"))
	.execute(&pool)
	.await
	.expect("insert draft");
	pool.close().await;

	let fids = adapter.list_referenced_managed_fids(TN).await.expect("referenced");
	assert!(fids.contains(&surviving), "the draft no longer protects its content: {fids:?}");
}

/// Moving a room folder to the main drive re-stamps every descendant and keeps content ids;
/// the room then counts no files.
#[tokio::test]
async fn moving_a_room_folder_to_main_restamps_its_subtree() {
	const ROOM: &str = "@alice~club";
	let (adapter, _temp) = create_test_adapter().await;
	for (id, parent) in [("room-f", None), ("room-sub", Some("room-f"))] {
		adapter
			.create_file(
				TN,
				CreateFile {
					file_id: Some(id.into()),
					parent_id: parent.map(Into::into),
					file_name: id.into(),
					file_tp: Some("FLDR".into()),
					channel: Some(ROOM.into()),
					status: Some(FileStatus::Active),
					..Default::default()
				},
			)
			.await
			.expect("create room folder");
	}
	let pic = upload(&adapter, "room-sub", None, "b1~roompic", "f1~roompic").await;
	assert!(adapter.count_channel_entries(TN, ROOM).await.expect("count") >= 2);

	adapter
		.move_entry_subtree(TN, "room-f", None, None)
		.await
		.expect("move to main");

	for id in ["room-f", "room-sub", &pic.entry_id] {
		let view = adapter.read_file(TN, id).await.expect("read").expect("entry");
		assert_eq!(view.channel, None, "{id} re-stamped to the main drive");
	}
	let pic = adapter.read_file(TN, &pic.entry_id).await.expect("read").expect("pic");
	assert_eq!(pic.index_id(), "f1~roompic", "a move never changes the content id");
	assert_eq!(pic.parent_id.as_deref(), Some("room-sub"));
	assert_eq!(adapter.count_channel_entries(TN, ROOM).await.expect("count"), 0);
}

#[tokio::test]
async fn a_repeated_folder_create_with_an_explicit_id_is_idempotent() {
	let (adapter, _temp) = create_test_adapter().await;
	let first = folder(&adapter, "fold-a").await;
	let second = folder(&adapter, "fold-a").await;
	assert_eq!(&*first.entry_id, "fold-a");
	assert_eq!(first.entry_id, second.entry_id);
}

/// A permanent delete leaves a tombstone, which never collides with a re-upload of the same
/// bytes — the content id names the new live entry alone.
#[tokio::test]
async fn a_reupload_after_permanent_delete_resolves() {
	let (adapter, _temp) = create_test_adapter().await;
	folder(&adapter, "fold-a").await;

	let first = upload(&adapter, "fold-a", None, "b1~h2", "f1~h2").await;
	adapter.delete_file(TN, &first.entry_id).await.expect("permanent delete");
	assert!(adapter.read_file(TN, "f1~h2").await.expect("read").is_none(), "tombstone hidden");

	let again = upload(&adapter, "fold-a", None, "b1~h2", "f1~h2").await;
	let view = adapter.read_file(TN, "f1~h2").await.expect("no conflict").expect("re-upload");
	assert_eq!(view.entry_id, again.entry_id);
}

/// An explicit-`file_id` create never hands back another placement's entry — managed or
/// trashed — but re-creating the same placement is idempotent.
#[tokio::test]
async fn an_explicit_create_reuses_only_its_own_placement() {
	let (adapter, _temp) = create_test_adapter().await;
	folder(&adapter, "fold-a").await;
	let managed = upload(&adapter, MANAGED_PARENT_ID, None, "b1~m4", "f1~m4").await;
	let create = |parent: &'static str| CreateFile {
		file_id: Some("f1~m4".into()),
		parent_id: Some(parent.into()),
		content_type: "image/png".into(),
		file_name: "placed.png".into(),
		file_tp: Some("BLOB".into()),
		status: Some(FileStatus::Active),
		..Default::default()
	};

	let placed = adapter.create_file(TN, create("fold-a")).await.expect("create");
	assert_ne!(placed.entry_id, managed.entry_id, "the managed entry is not reused");
	let again = adapter.create_file(TN, create("fold-a")).await.expect("re-create");
	assert_eq!(again.entry_id, placed.entry_id, "the same placement is idempotent");

	let opts =
		UpdateFileOptions { parent_id: Patch::Value(TRASH_PARENT_ID.into()), ..Default::default() };
	adapter.update_file_data(TN, &placed.entry_id, &opts).await.expect("trash");
	let fresh = adapter.create_file(TN, create("fold-a")).await.expect("create over trash");
	assert_ne!(fresh.entry_id, placed.entry_id, "a trashed entry is not reused");
	let view = adapter.read_file(TN, &fresh.entry_id).await.expect("read").expect("entry");
	assert_eq!(view.parent_id.as_deref(), Some("fold-a"));
	assert_eq!(&*view.file_name, "placed.png", "never a sibling's name");
}

/// Moving a document into another drive restamps its parts' placement in the drive being
/// left, never another drive's placement of the same part.
#[tokio::test]
async fn a_drive_move_leaves_another_drives_part_placement() {
	let (adapter, _temp) = create_test_adapter().await;
	let root = adapter
		.create_file(
			TN,
			CreateFile {
				file_id: Some("f1~l4-root".into()),
				content_type: "cloudillo/quillo".into(),
				file_name: "doc".into(),
				file_tp: Some("CRDT".into()),
				status: Some(FileStatus::Active),
				..Default::default()
			},
		)
		.await
		.expect("root");
	let part = |channel: Option<&str>| CreateFile {
		root_id: Some("f1~l4-root".into()),
		orig_variant_id: Some("b1~l4-part".into()),
		channel: channel.map(Into::into),
		file_name: "part.png".into(),
		..Default::default()
	};
	let main = common::upload(&adapter, TN, part(None), "f1~l4-part").await;
	let room = common::upload(&adapter, TN, part(Some("@alice~r")), "f1~l4-part").await;
	assert_ne!(main.entry_id, room.entry_id);

	adapter
		.move_entry_subtree(TN, &root.entry_id, None, Some("@alice~x"))
		.await
		.expect("move");
	let channel = |id: Box<str>| {
		let adapter = &adapter;
		async move { adapter.read_file(TN, &id).await.expect("read").expect("entry").channel }
	};
	assert_eq!(channel(root.entry_id).await.as_deref(), Some("@alice~x"));
	assert_eq!(channel(main.entry_id).await.as_deref(), Some("@alice~x"), "the part follows");
	assert_eq!(channel(room.entry_id).await.as_deref(), Some("@alice~r"), "the other drive's");
}

/// A list cursor naming a content placed by several entries is ambiguous, not a silent
/// restart at page one.
#[tokio::test]
async fn an_ambiguous_list_cursor_is_a_conflict() {
	let (adapter, _temp) = create_test_adapter().await;
	folder(&adapter, "fold-a").await;
	upload(&adapter, "fold-a", None, "b1~l3", "f1~l3").await;
	upload(&adapter, "fold-a", None, "b1~l3", "f1~l3").await;

	let cursor = cloudillo_types::types::CursorData::new("created", 0.into(), "f1~l3").encode();
	let opts = ListFileOptions { cursor: Some(cursor), ..Default::default() };
	assert!(matches!(adapter.list_files(TN, &opts).await, Err(Error::Conflict(_))));
}

/// FSHR grants are keyed by the content id: deleting one of two entries keeps
/// `FSHR:{content}:*`, deleting the last one sweeps it.
#[tokio::test]
async fn the_content_fshr_goes_with_the_last_live_entry() {
	use cloudillo_types::meta_adapter::Action;
	use cloudillo_types::types::Timestamp;

	let (adapter, _temp) = create_test_adapter().await;
	folder(&adapter, "fold-a").await;
	folder(&adapter, "fold-b").await;
	let a = upload(&adapter, "fold-a", None, "b1~sw", "f1~sw").await;
	let b = upload(&adapter, "fold-b", None, "b1~sw", "f1~sw").await;
	let key = "FSHR:f1~sw:bob.example";
	let action = Action {
		action_id: "a1~sw",
		typ: "FSHR",
		sub_typ: Some("WRITE"),
		issuer_tag: "alice",
		parent_id: None,
		root_id: None,
		audience_tag: Some("bob.example"),
		content: None,
		attachments: None,
		subject: Some("f1~sw"),
		created_at: Timestamp::now(),
		expires_at: None,
		visibility: None,
		flags: None,
		x: None,
		hat_tag: None,
		channel: None,
	};
	adapter.create_action(TN, &action, Some(key)).await.expect("fshr");

	adapter.delete_file(TN, &a.entry_id).await.expect("delete one");
	assert!(adapter.get_action_by_key(TN, key).await.expect("get").is_some(), "swept early");
	adapter.delete_file(TN, &b.entry_id).await.expect("delete last");
	assert!(adapter.get_action_by_key(TN, key).await.expect("get").is_none(), "not swept");
}

/// Migration 58 over a v57-shaped DB: every legacy `files` row becomes an entry, references
/// move off local content, and the dropped columns are gone.
#[tokio::test]
async fn v58_migrates_a_legacy_files_table() {
	let temp = TempDir::new().expect("temp dir");
	let url = format!("sqlite://{}/meta.db", temp.path().display());
	{
		let worker_pool = Arc::new(WorkerPool::new(1, 1, 1));
		let adapter = MetaAdapterSqlite::new(worker_pool, temp.path()).await.expect("adapter");
		adapter.create_tenant(TN, "alice").await.expect("create tenant");
	}
	let pool = sqlx::sqlite::SqlitePoolOptions::new()
		.max_connections(1)
		.connect(&url)
		.await
		.expect("open meta.db");
	// Back to the v57 shape: placement on `files`, `file_user_data` keyed by `f_id`, the search
	// mirror columns present, no `merged_into`.
	let mut seed = vec![
		"ALTER TABLE files DROP COLUMN merged_into".to_string(),
		"ALTER TABLE file_user_data RENAME COLUMN e_id TO f_id".to_string(),
		"ALTER TABLE search_docs ADD COLUMN visibility char(1)".to_string(),
		"ALTER TABLE search_docs ADD COLUMN channel text".to_string(),
	];
	for col in [
		"status char(1)",
		"owner_tag text",
		"upstream_tag text",
		"file_name text",
		"tags json",
		"visibility char(1)",
		"hidden INTEGER",
		"parent_id text",
		"channel text",
		"created_at INTEGER",
		"broken_at INTEGER",
		"broken_reason TEXT",
	] {
		seed.push(format!("ALTER TABLE files ADD COLUMN {col}"));
	}
	seed.extend(
		[
			// 10 pending upload, 11 folder, 12 a shared local file in it, 13 a Pin holding no
			// bytes, 14 a Pin that landed on local bytes, 15 a remote folder, 16 a file in it.
			"INSERT INTO files (f_id, tn_id, file_id, file_tp, status, parent_id, file_name, \
			 upstream_tag, content_type, x) VALUES \
			 (10, 1, NULL, 'BLOB', 'P', NULL, 'up.png', NULL, 'image/png', NULL), \
			 (11, 1, 'fold1', 'FLDR', 'A', NULL, 'Folder', NULL, NULL, NULL), \
			 (12, 1, 'f1~local', 'BLOB', 'A', 'fold1', 'local.png', NULL, 'image/png', NULL), \
			 (13, 1, 'f1~pinned', 'BLOB', 'A', NULL, 'pin.jpg', 'bob.example', 'image/jpeg', \
			  '{\"dim\":[4,3]}'), \
			 (14, 1, 'f1~pinlocal', 'CRDT', 'A', NULL, 'doc', 'carol.example', \
			  'cloudillo/quillo', NULL), \
			 (15, 1, 'fold-remote', 'FLDR', 'A', NULL, 'Remote', 'bob.example', \
			  'cloudillo/folder', NULL), \
			 (16, 1, 'f1~inremote', 'BLOB', 'A', 'fold-remote', 'in.png', NULL, 'image/png', \
			  NULL)",
			"INSERT INTO file_variants (tn_id, f_id, variant_id, variant, format, size, \
			 available) VALUES (1, 12, 'b1~l', 'orig', 'png', 1, 1), \
			 (1, 14, 'b1~p', 'orig', 'bin', 1, 1)",
			"INSERT INTO share_entries (tn_id, resource_type, resource_id, subject_type, \
			 subject_id, permission, created_by) VALUES (1, 'F', 'f1~local', 'U', 'bob', 'R', 'me')",
			"INSERT INTO file_user_data (tn_id, id_tag, f_id, starred) VALUES (1, 'bob', 12, 1)",
			"UPDATE files SET preset = 'gallery' WHERE f_id = 13",
			"UPDATE vars SET value = '57' WHERE key = 'db_version'",
		]
		.map(String::from),
	);
	for sql in seed {
		sqlx::query(sqlx::AssertSqlSafe(sql.clone())).execute(&pool).await.expect(&sql);
	}
	pool.close().await;

	// Reopening runs the migration.
	let worker_pool = Arc::new(WorkerPool::new(1, 1, 1));
	let adapter = MetaAdapterSqlite::new(worker_pool, temp.path()).await.expect("migrate");
	let pool = sqlx::sqlite::SqlitePoolOptions::new().connect(&url).await.expect("reopen");

	let entry = |e_id: i64| {
		let pool = pool.clone();
		async move {
			sqlx::query_as::<_, (String, Option<i64>, Option<String>, Option<String>)>(
				"SELECT entry_id, f_id, ref_file_id, ref_content_type FROM entries WHERE e_id = ?",
			)
			.bind(e_id)
			.fetch_one(&pool)
			.await
			.expect("entry")
		}
	};
	let (pending, f, r, _) = entry(10).await;
	assert_eq!((f, r), (Some(10), None));
	let by_f_id = adapter.read_file(TN, "@10").await.expect("read").expect("pending");
	assert_eq!(by_f_id.entry_id.as_ref(), pending, "the upload's @<f_id> still resolves");
	let (folder_id, f, _, _) = entry(11).await;
	assert_eq!((folder_id.as_str(), f), ("fold1", None), "folder keeps its id, no file");
	let (local, f, r, _) = entry(12).await;
	assert_eq!((f, r), (Some(12), None));
	assert_ne!(local, "f1~local", "content entries get a fresh id");
	let (pin, f, r, ct) = entry(13).await;
	assert_eq!((f, r.as_deref(), ct.as_deref()), (None, Some("f1~pinned"), Some("image/jpeg")));
	let pin = adapter.read_file(TN, &pin).await.expect("read").expect("pin");
	assert_eq!(pin.preset.as_deref(), Some("gallery"), "the pin keeps its preset");
	let (_, f, r, _) = entry(14).await;
	assert_eq!((f, r.as_deref()), (None, Some("f1~pinlocal")), "a pin is always a reference");

	let files: Vec<i64> = sqlx::query_scalar("SELECT f_id FROM files ORDER BY f_id")
		.fetch_all(&pool)
		.await
		.expect("files");
	assert_eq!(files, [10, 12, 14, 16], "folder and byte-less pin rows go; local bytes stay");

	// A remote folder becomes a reference: a fresh entry id, its upstream id on `ref_file_id`,
	// and its children follow the new id.
	let (remote, f, r, ct) = entry(15).await;
	assert_ne!(remote, "fold-remote", "a remote folder gets a fresh entry id");
	assert_eq!(
		(f, r.as_deref(), ct.as_deref()),
		(None, Some("fold-remote"), Some("cloudillo/folder"))
	);
	let child_parent: Option<String> =
		sqlx::query_scalar("SELECT parent_id FROM entries WHERE e_id = 16")
			.fetch_one(&pool)
			.await
			.expect("child");
	assert_eq!(child_parent.as_deref(), Some(remote.as_str()), "the child follows the folder");
	let folder = adapter
		.read_file(TN, "fold-remote")
		.await
		.expect("read")
		.expect("remote folder");
	assert_eq!(*folder.entry_id, *remote);
	assert_eq!(folder.file_id.as_deref(), Some("fold-remote"));
	assert_eq!(folder.file_tp.as_deref(), Some("FLDR"));
	assert_eq!(folder.upstream_tag.as_deref(), Some("bob.example"));

	let share: String =
		sqlx::query_scalar("SELECT resource_id FROM share_entries WHERE subject_id = 'bob'")
			.fetch_one(&pool)
			.await
			.expect("share");
	assert_eq!(share, local, "the share names the entry");
	let starred: i64 = sqlx::query_scalar("SELECT e_id FROM file_user_data WHERE id_tag = 'bob'")
		.fetch_one(&pool)
		.await
		.expect("star");
	assert_eq!(starred, 12);

	for (table, col, present) in [
		("files", "parent_id", false),
		("files", "upstream_tag", false),
		("files", "merged_into", true),
		("search_docs", "visibility", false),
		("search_docs", "channel", false),
	] {
		let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
			"SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = '{col}'"
		)))
		.fetch_one(&pool)
		.await
		.expect("pragma");
		assert_eq!(n > 0, present, "{table}.{col}");
	}

	// The migrated pin reads as a reference through the adapter.
	let pin = adapter.read_file(TN, "f1~pinned").await.expect("read").expect("pin");
	assert_eq!(pin.upstream_tag.as_deref(), Some("bob.example"));
	assert_eq!(pin.file_tp.as_deref(), Some("BLOB"));
}

/// A permanent delete reports the entries it tombstoned: a reference roots no local tree, so
/// the Pin's own entry is all there is.
#[tokio::test]
async fn deleting_a_pin_reports_its_entry() {
	let (adapter, _temp) = create_test_adapter().await;
	folder(&adapter, "fold-a").await;
	let pin = adapter
		.create_file(
			TN,
			CreateFile {
				file_id: Some("f1~p1".into()),
				upstream_tag: Some("carol.example".into()),
				parent_id: Some("fold-a".into()),
				file_name: "pin".into(),
				file_tp: Some("BLOB".into()),
				status: Some(FileStatus::Active),
				..Default::default()
			},
		)
		.await
		.expect("pin");
	let purged = adapter.delete_file(TN, &pin.entry_id).await.expect("permanent delete");
	assert_eq!(purged.entry_ids, vec![pin.entry_id]);
}

/// A copy over existing content lands even beside its source in the same folder, and writes no
/// content row; unknown content is `NotFound`.
#[tokio::test]
async fn an_entry_for_content_never_reuses_the_source_placement() {
	let (adapter, _temp) = create_test_adapter().await;
	folder(&adapter, "fold-a").await;
	let source = upload(&adapter, "fold-a", None, "b1~c1", "f1~c1").await;
	let copy = CreateFile {
		parent_id: Some("fold-a".into()),
		file_name: "copy".into(),
		..Default::default()
	};
	let entry = adapter.create_entry_for_content(TN, "f1~c1", copy.clone()).await.expect("copy");
	assert_ne!(entry, source.entry_id);
	let entries = adapter.list_content_entries(TN, "f1~c1").await.expect("entries");
	assert_eq!(entries.len(), 2);
	let r = adapter.create_entry_for_content(TN, "f1~nope", copy).await;
	assert!(matches!(r, Err(Error::NotFound)), "{r:?}");
}
