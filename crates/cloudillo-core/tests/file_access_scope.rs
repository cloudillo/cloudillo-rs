// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Integration tests for folder share-link scope authorization
//!
//! Exercises the adapter-backed access helpers in `cloudillo_core::file_access`
//! against a real SQLite meta adapter:
//! - `is_descendant_of` parent-chain walk
//! - `scope_target_is_folder` folder gate (M1)
//! - `check_scope_allows_create_in` create authorization, including the
//!   document-tree rule and the folder-subtree rule suppressed for non-folders.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use cloudillo_core::dir_cache::DirCache;
use cloudillo_core::file_access;
use cloudillo_meta_adapter_sqlite::MetaAdapterSqlite;
use cloudillo_types::error::Error;
use cloudillo_types::meta_adapter::{
	CreateFile, CreateShareEntry, MetaAdapter, ProfileType, UpsertProfileFields,
};
use cloudillo_types::types::Patch;
use cloudillo_types::types::{AccessLevel, TnId};
use cloudillo_types::worker::WorkerPool;
use tempfile::TempDir;

async fn create_test_adapter() -> (MetaAdapterSqlite, TempDir) {
	let temp_dir = TempDir::new().expect("Failed to create temp directory");
	let worker_pool = Arc::new(WorkerPool::new(1, 1, 1));
	let adapter = MetaAdapterSqlite::new(worker_pool, temp_dir.path())
		.await
		.expect("Failed to create adapter");
	(adapter, temp_dir)
}

async fn make_folder(
	adapter: &MetaAdapterSqlite,
	tn_id: TnId,
	file_id: &str,
	name: &str,
	parent: Option<&str>,
) {
	let opts = CreateFile {
		file_id: Some(file_id.into()),
		parent_id: parent.map(Into::into),
		content_type: "application/x-folder".into(),
		file_name: name.into(),
		file_tp: Some("FLDR".into()),
		..Default::default()
	};
	adapter.create_file(tn_id, opts).await.expect("create folder");
}

async fn make_file(
	adapter: &MetaAdapterSqlite,
	tn_id: TnId,
	file_id: &str,
	name: &str,
	parent: Option<&str>,
) {
	let opts = CreateFile {
		file_id: Some(file_id.into()),
		parent_id: parent.map(Into::into),
		content_type: "text/plain".into(),
		file_name: name.into(),
		file_tp: Some("BLOB".into()),
		..Default::default()
	};
	adapter.create_file(tn_id, opts).await.expect("create file");
}

/// Seed the shared tree under TnId(1):
///   F0 (FLDR, root) ─ F1 (FLDR) ─ X (BLOB)
///   Z  (BLOB, root) ─ Zc (BLOB)
///   Y  (BLOB, root, unrelated)
async fn seed() -> (Arc<dyn MetaAdapter>, TnId, TempDir) {
	let (adapter, temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "owner").await.ok();

	make_folder(&adapter, tn_id, "F0", "Shared", None).await;
	make_folder(&adapter, tn_id, "F1", "Sub", Some("F0")).await;
	make_file(&adapter, tn_id, "X", "x.txt", Some("F1")).await;
	make_file(&adapter, tn_id, "Z", "z.txt", None).await;
	make_file(&adapter, tn_id, "Zc", "zc.txt", Some("Z")).await;
	make_file(&adapter, tn_id, "Y", "y.txt", None).await;

	let meta: Arc<dyn MetaAdapter> = Arc::new(adapter);
	(meta, tn_id, temp)
}

#[tokio::test]
async fn is_descendant_of_walks_parent_chain() {
	let (meta, tn_id, _temp) = seed().await;
	let cache = DirCache::new(64);

	assert!(file_access::is_descendant_of(&meta, &cache, tn_id, "X", "F0").await.unwrap());
	assert!(file_access::is_descendant_of(&meta, &cache, tn_id, "F1", "F0").await.unwrap());
	assert!(!file_access::is_descendant_of(&meta, &cache, tn_id, "Y", "F0").await.unwrap());
	// Self is not its own descendant.
	assert!(!file_access::is_descendant_of(&meta, &cache, tn_id, "F0", "F0").await.unwrap());
	// Folder ancestors were cached during the walk; the non-folder leaf X was not.
	assert!(cache.get(tn_id, "F1").is_some());
	assert!(cache.get(tn_id, "X").is_none());
}

#[tokio::test]
async fn scope_target_is_folder_distinguishes_types() {
	let (meta, tn_id, _temp) = seed().await;
	let cache = DirCache::new(64);

	assert!(file_access::scope_target_is_folder(&meta, &cache, tn_id, "F0").await.unwrap());
	assert!(!file_access::scope_target_is_folder(&meta, &cache, tn_id, "Z").await.unwrap());
}

#[tokio::test]
async fn create_allowed_within_folder_subtree() {
	let (meta, tn_id, _temp) = seed().await;
	let cache = DirCache::new(64);

	// Parent is a descendant of the scoped folder F0.
	assert!(matches!(
		file_access::check_scope_allows_create_in(
			&meta,
			&cache,
			tn_id,
			Some("file:F0:W"),
			Some("F1"),
			None
		)
		.await,
		Ok(())
	));
}

#[tokio::test]
async fn create_denied_outside_folder_subtree() {
	let (meta, tn_id, _temp) = seed().await;
	let cache = DirCache::new(64);

	assert!(matches!(
		file_access::check_scope_allows_create_in(
			&meta,
			&cache,
			tn_id,
			Some("file:F0:W"),
			Some("Y"),
			None
		)
		.await,
		Err(Error::PermissionDenied)
	));
}

#[tokio::test]
async fn create_denied_for_non_write_scope() {
	let (meta, tn_id, _temp) = seed().await;
	let cache = DirCache::new(64);

	assert!(matches!(
		file_access::check_scope_allows_create_in(
			&meta,
			&cache,
			tn_id,
			Some("file:F0:R"),
			Some("F1"),
			None
		)
		.await,
		Err(Error::PermissionDenied)
	));
}

#[tokio::test]
async fn create_allowed_via_document_tree_rule() {
	let (meta, tn_id, _temp) = seed().await;
	let cache = DirCache::new(64);

	// root_id == scope_file_id: document-tree rule, unconditional on folder type.
	assert!(matches!(
		file_access::check_scope_allows_create_in(
			&meta,
			&cache,
			tn_id,
			Some("file:F0:W"),
			None,
			Some("F0")
		)
		.await,
		Ok(())
	));
}

#[tokio::test]
async fn m1_subtree_rule_suppressed_for_non_folder_scope() {
	let (meta, tn_id, _temp) = seed().await;
	let cache = DirCache::new(64);

	// Zc is a descendant of Z, but Z is not a folder, so the folder-subtree rule
	// is suppressed and creation is denied.
	assert!(matches!(
		file_access::check_scope_allows_create_in(
			&meta,
			&cache,
			tn_id,
			Some("file:Z:W"),
			Some("Zc"),
			None
		)
		.await,
		Err(Error::PermissionDenied)
	));

	// The document-tree rule (root_id == scope_file_id) still works for Z.
	assert!(matches!(
		file_access::check_scope_allows_create_in(
			&meta,
			&cache,
			tn_id,
			Some("file:Z:W"),
			None,
			Some("Z")
		)
		.await,
		Ok(())
	));
}

#[tokio::test]
async fn document_scope_cannot_place_copy_in_unrelated_folder() {
	// H1 regression, for `cloudillo_file::management::duplicate_file`: a share-link
	// editor scoped to a single *document* (Z, a BLOB) asks for the copy to land in
	// an unrelated folder (F1). Neither the document-tree rule (root_id != Z) nor
	// the folder-subtree rule (Z is not a folder) applies, so it must be denied.
	let (meta, tn_id, _temp) = seed().await;
	let cache = DirCache::new(64);

	assert!(matches!(
		file_access::check_scope_allows_create_in(
			&meta,
			&cache,
			tn_id,
			Some("file:Z:W"),
			Some("F1"),
			None
		)
		.await,
		Err(Error::PermissionDenied)
	));

	// …and the same for the tenant root (`parent_id = None`).
	assert!(matches!(
		file_access::check_scope_allows_create_in(
			&meta,
			&cache,
			tn_id,
			Some("file:Z:W"),
			None,
			None
		)
		.await,
		Err(Error::PermissionDenied)
	));

	// An unscoped caller (the ordinary logged-in owner) is unaffected.
	assert!(matches!(
		file_access::check_scope_allows_create_in(&meta, &cache, tn_id, None, Some("F1"), None)
			.await,
		Ok(())
	));
}

#[tokio::test]
async fn m2_by_id_listing_filters_to_in_subtree_ids() {
	// Mirrors the by-id filter in `cloudillo_file::handler::get_file_list`: under a
	// folder-share scope, a by-id batch keeps only the ids that are the scoped
	// folder itself or a descendant of it, dropping out-of-subtree ids rather than
	// failing the whole request.
	let (meta, tn_id, _temp) = seed().await;
	let cache = DirCache::new(64);
	let scope_fid = "F0";

	let requested = ["F1", "Y"];
	let mut in_subtree: Vec<String> = Vec::with_capacity(requested.len());
	for id in requested {
		if id == scope_fid
			|| file_access::is_descendant_of(&meta, &cache, tn_id, id, scope_fid)
				.await
				.unwrap()
		{
			in_subtree.push(id.to_string());
		}
	}

	// Mixed batch: the in-subtree row survives, the unrelated one is dropped.
	assert_eq!(in_subtree, vec!["F1".to_string()]);

	// The scoped folder itself is always kept (matched by id, not descendant walk).
	let mut self_only: Vec<String> = Vec::new();
	for id in ["F0"] {
		if id == scope_fid
			|| file_access::is_descendant_of(&meta, &cache, tn_id, id, scope_fid)
				.await
				.unwrap()
		{
			self_only.push(id.to_string());
		}
	}
	assert_eq!(self_only, vec!["F0".to_string()]);

	// A batch entirely outside the subtree filters to empty (the handler then
	// returns the empty 200 response).
	let mut none: Vec<String> = Vec::new();
	for id in ["Y", "Z"] {
		if id == scope_fid
			|| file_access::is_descendant_of(&meta, &cache, tn_id, id, scope_fid)
				.await
				.unwrap()
		{
			none.push(id.to_string());
		}
	}
	assert!(none.is_empty());
}

#[tokio::test]
async fn create_uses_cache_backed_folder_gate() {
	let (meta, tn_id, _temp) = seed().await;
	let cache = DirCache::new(64);
	// F1 is a descendant of folder F0 → allowed.
	assert!(matches!(
		file_access::check_scope_allows_create_in(
			&meta,
			&cache,
			tn_id,
			Some("file:F0:W"),
			Some("F1"),
			None
		)
		.await,
		Ok(())
	));
	// Y is outside F0's subtree → denied.
	assert!(matches!(
		file_access::check_scope_allows_create_in(
			&meta,
			&cache,
			tn_id,
			Some("file:F0:W"),
			Some("Y"),
			None
		)
		.await,
		Err(Error::PermissionDenied)
	));
}

/// An `'A'` grant on a folder confers admin over everything nested under it.
///
/// `file_access::walk_parent_chain_for_share` needs a full `App`, so this pins the two halves it
/// composes against the real adapter instead: the ancestor walk that finds F0 from X, and the
/// `check_share_access` → `from_perm_char` conversion that must report `Admin`, not `Write`.
#[tokio::test]
async fn folder_inherited_admin_grant_reaches_nested_files() {
	let (meta, tn_id, _temp) = seed().await;
	let cache = DirCache::new(64);
	let grantee = "bob.example.com";

	meta.create_share_entry(
		tn_id,
		'F',
		"F0",
		"owner",
		&CreateShareEntry {
			subject_type: 'U',
			subject_id: grantee.to_string(),
			permission: 'A',
			expires_at: None,
		},
	)
	.await
	.expect("create admin share entry on the folder");

	// X sits two levels below F0, so the parent-chain walk reaches the grant...
	assert!(file_access::is_descendant_of(&meta, &cache, tn_id, "X", "F0").await.unwrap());
	// ...and there is no grant on X itself, so inheritance is the only route.
	assert_eq!(meta.check_share_access(tn_id, 'F', "X", 'U', grantee).await.unwrap(), None);

	let inherited = meta
		.check_share_access(tn_id, 'F', "F0", 'U', grantee)
		.await
		.unwrap()
		.expect("the folder grant is readable");
	assert_eq!(inherited, 'A');
	assert_eq!(AccessLevel::from_perm_char(inherited), AccessLevel::Admin);
	assert!(AccessLevel::from_perm_char(inherited).can_manage_shares());

	// The unrelated root file Y inherits nothing.
	assert!(!file_access::is_descendant_of(&meta, &cache, tn_id, "Y", "F0").await.unwrap());
}

/// A `?scope=file:{id}:{R|C|W}` on `/api/auth/access-token` used to be stamped into the minted
/// token verbatim, and `get_access_level_with_scope` treats a matching file scope as *the* grant —
/// so naming any file id handed out a capability for it. The mint now runs the same access check
/// first and caps with `min()` (`cloudillo_auth::handler::validated_scope`).
///
/// That helper needs a full `App`, so this pins the two halves it composes: the ladder finds
/// nothing for an unrelated caller on an owner-less, `visibility = NULL` file (checked against the
/// real adapter), and the cap itself — `file_access::scope_char_within`, the very function both
/// mint sites call — narrows a `:W` request down to a Read-only grant.
#[tokio::test]
async fn scope_mint_denies_strangers_and_caps_at_real_access() {
	let (meta, tn_id, _temp) = seed().await;
	let stranger = "mallory.example.com";

	// Y is a root BLOB with no owner of its own (so the tenant owns it) and no visibility.
	let y = meta.read_file(tn_id, "Y").await.unwrap().expect("Y exists");
	let owner = y.owner.as_ref().map_or("", |p| p.id_tag.as_ref());
	assert!(owner.is_empty() || owner == "owner", "unexpected owner {owner:?}");
	assert_eq!(y.visibility, None);

	// Every rung of the ladder the mint runs comes up empty for the stranger: no direct share,
	// no ancestor to inherit from, no role on the tenant, no FSHR.
	assert_eq!(meta.check_share_access(tn_id, 'F', "Y", 'U', stranger).await.unwrap(), None);
	assert_eq!(y.parent_id, None);
	assert_eq!(file_access::role_access_level(&[]), AccessLevel::None);
	assert!(
		meta.get_action_by_key(tn_id, &format!("FSHR:Y:{}", stranger))
			.await
			.unwrap()
			.is_none()
	);

	// A reader, on the other hand, gets in — but only as far as their grant reaches.
	let reader = "bob.example.com";
	meta.create_share_entry(
		tn_id,
		'F',
		"Y",
		"owner",
		&CreateShareEntry {
			subject_type: 'U',
			subject_id: reader.to_string(),
			permission: 'R',
			expires_at: None,
		},
	)
	.await
	.expect("create read share entry");

	let granted = AccessLevel::from_perm_char(
		meta.check_share_access(tn_id, 'F', "Y", 'U', reader)
			.await
			.unwrap()
			.expect("share found"),
	);
	assert_eq!(granted, AccessLevel::Read);
	// Ask for `:W`, hold Read — the mint stamps `:R`.
	assert_eq!(file_access::scope_char_within(AccessLevel::Write, granted), Some('R'));
	// Hold nothing — nothing may be stamped, so the mint returns `PermissionDenied`.
	assert_eq!(file_access::scope_char_within(AccessLevel::Write, AccessLevel::None), None);
}

/// The visibility ladder in `file_access::check_file_access_with_scope` scores a row on the
/// caller's relationship to the tenant, whatever the row's provenance. A cross-context Pin is
/// authored locally at `'C'`/`'F'` by the placing member, so a provenance gate here made every
/// community pin unreadable on the detail path while `file::list` and `search` showed it.
///
/// What a mirror withholds is *owner* standing, and that is resolved before this runs — so
/// `Direct` (the shape of a revoked FSHR share) still grants nothing.
///
/// `check_file_access_with_scope` itself needs a full `App`, but the decision it falls back to
/// is `file_access::visibility_grants_read_fallback` — called here directly, on a relation row
/// loaded from the real adapter.
#[tokio::test]
async fn visibility_ladder_scores_mirrored_and_local_rows_alike() {
	let (meta, tn_id, _temp) = seed().await;
	let tenant = "owner";
	let follower = "carol.example.com";

	// The caller follows the tenant and holds no roles.
	meta.upsert_profile(
		tn_id,
		follower,
		&UpsertProfileFields {
			name: Patch::Value("Carol".into()),
			typ: Patch::Value(ProfileType::Person),
			// "they follow us" — the direction the ladder reads, not `following`.
			follower: Patch::Value(true),
			..Default::default()
		},
	)
	.await
	.expect("upsert follower profile");

	let rel = meta
		.get_relationships(tn_id, &[follower])
		.await
		.expect("get_relationships")
		.get(follower)
		.copied()
		.expect("relation row");
	assert!(rel.follower);

	// A member's own locally-created file, and the same content pinned in from another node.
	for (file_id, upstream) in [("MEMBER", None), ("MIRROR", Some("bob.example.com".to_string()))] {
		meta.create_file(
			tn_id,
			CreateFile {
				file_id: Some(file_id.into()),
				owner_tag: Some("alice.example.com".into()),
				upstream_tag: upstream.map(Into::into),
				visibility: Some('F'),
				content_type: "text/plain".into(),
				file_name: format!("{file_id}.txt").into(),
				file_tp: Some("BLOB".into()),
				..Default::default()
			},
		)
		.await
		.expect("create row");
	}

	// The caller reaches nothing on the earlier rungs (no share, no role, no FSHR), so the
	// fallback is the whole decision — and it says the same thing about both rows.
	for file_id in ["MEMBER", "MIRROR"] {
		let f = meta.read_file(tn_id, file_id).await.unwrap().expect("row exists");
		let r = file_access::FileRef::from_view(&f, tenant);
		// Owner identity is not what the ladder reads: neither row is tenant-owned.
		assert_ne!(r.owner_id_tag, tenant);
		assert!(
			file_access::visibility_grants_read_fallback(None, f.visibility, true, rel),
			"{file_id}: a follower must reach an 'F' row whatever its provenance"
		);
		// ...and a scoped caller never reaches the ladder, on either row.
		assert!(!file_access::visibility_grants_read_fallback(
			Some("file:MEMBER:R"),
			f.visibility,
			true,
			rel
		));
	}
}

/// The ladder a visibility char alone confers, pinned. `follower` is "they follow us" —
/// passing `following` here is the bug this table exists to catch. `Direct` and `'S'` grant
/// nothing at any rung below Owner, which is what keeps a revoked FSHR share closed.
#[test]
fn visibility_grants_read_ladder() {
	use cloudillo_types::meta_adapter::ProfileRelation;

	let rel = |connected, follower| ProfileRelation { connected, follower, ..Default::default() };
	// vis, is_real_auth, connected, follower -> expected
	let cases = [
		(Some('F'), true, false, true, true),
		(Some('F'), true, true, false, true),
		(Some('F'), true, false, false, false),
		(Some('C'), true, false, true, false),
		(Some('V'), true, false, false, true),
		(Some('V'), false, false, false, false),
		(Some('P'), false, false, false, true),
		(None, true, true, true, false),
		(Some('S'), true, true, true, false),
	];
	for (vis, auth, connected, follower, want) in cases {
		assert_eq!(
			file_access::visibility_grants_read_fallback(None, vis, auth, rel(connected, follower)),
			want,
			"{vis:?} auth={auth} connected={connected} follower={follower}"
		);
	}
}

/// The role rung of `get_access_level`, for a row that originates on this node. Roles say nothing
/// about `visibility`, so this deliberately reaches a peer member's own upload as well as the
/// tenant's — contributors must be able to write freely for now. Narrowing it is a future change;
/// see the `ponytail:` note at the call site in `file_access::get_access_level`.
#[test]
fn any_role_reaches_a_locally_originating_row() {
	let roles = |r: &[&str]| -> Vec<Box<str>> { r.iter().map(|s| (*s).into()).collect() };

	for (role, want) in [
		("leader", AccessLevel::Admin),
		("moderator", AccessLevel::Write),
		("contributor", AccessLevel::Write),
		("follower", AccessLevel::Read),
	] {
		assert_eq!(file_access::role_access_level(&roles(&[role])), want, "{role}");
	}

	// No roles at all still reaches nothing.
	assert_eq!(file_access::role_access_level(&[]), AccessLevel::None);
}

/// A Pin placed into a *personal* tenant lands at Direct visibility with no FSHR, so every rung
/// of `get_access_level` but the placer one comes up empty. `owner_tag` is NULL on such a row,
/// which `FileRef::from_view` back-fills with the tenant — so the placer resolves to the tenant
/// itself, and the rung must fire for them and for nobody else.
#[tokio::test]
async fn a_pin_into_a_personal_tenant_names_its_placer_as_owner() {
	let (meta, tn_id, _temp) = seed().await;
	let tenant = "owner";

	meta.create_file(
		tn_id,
		CreateFile {
			file_id: Some("PIN".into()),
			owner_tag: None,
			upstream_tag: Some("remote.example".into()),
			visibility: None,
			content_type: "text/plain".into(),
			file_name: "pin.txt".into(),
			file_tp: Some("BLOB".into()),
			..Default::default()
		},
	)
	.await
	.expect("create pin");

	let f = meta.read_file(tn_id, "PIN").await.unwrap().expect("row exists");
	let r = file_access::FileRef::from_view(&f, tenant);
	assert_eq!(r.upstream_id_tag, Some("remote.example"));
	assert_eq!(r.owner_id_tag, tenant, "a NULL owner_tag resolves to the tenant");
	assert_ne!(r.owner_id_tag, "stranger.example.com");

	// Direct visibility, so the fallback ladder grants a stranger nothing — the placer rung is
	// the only thing that can make this row readable.
	assert!(!file_access::visibility_grants_read_fallback(
		None,
		f.visibility,
		true,
		cloudillo_types::meta_adapter::ProfileRelation::default()
	));
}

// vim: ts=4
