// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Database schema initialization and migrations
//!
//! This module handles creating tables, indexes, and running migrations
//! to ensure the database schema is up to date.

use sqlx::{Sqlite, SqlitePool, Transaction};

/// Get the current database version from vars table
async fn get_db_version(tx: &mut Transaction<'_, Sqlite>) -> i64 {
	sqlx::query_scalar::<_, String>("SELECT value FROM vars WHERE key = 'db_version'")
		.fetch_optional(&mut **tx)
		.await
		.ok()
		.flatten()
		.and_then(|v| v.parse().ok())
		.unwrap_or(0)
}

/// Set the database version in vars table
async fn set_db_version(tx: &mut Transaction<'_, Sqlite>, version: i64) {
	let _ = sqlx::query("INSERT OR REPLACE INTO vars (key, value) VALUES ('db_version', ?)")
		.bind(version.to_string())
		.execute(&mut **tx)
		.await;
}

/// Initialize the database schema with all required tables and indexes
pub(crate) async fn init_db(db: &SqlitePool) -> Result<(), sqlx::Error> {
	// Current schema version - update this when adding new migrations
	const CURRENT_DB_VERSION: i64 = 23;

	let mut tx = db.begin().await?;

	// Create vars table first (needed for version tracking)
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS vars (
		key text NOT NULL,
		value text NOT NULL,
		created_at INTEGER DEFAULT (unixepoch()),
		updated_at INTEGER DEFAULT (unixepoch()),
		PRIMARY KEY(key)
	)",
	)
	.execute(&mut *tx)
	.await?;

	let mut version = get_db_version(&mut tx).await;

	// Schema creation - safe to run every time (uses IF NOT EXISTS)
	// New tables, indexes, triggers are added here

	// Tenants
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS tenants (
			tn_id integer NOT NULL,
			id_tag text NOT NULL,
			type char(1),
			name text,
			profile_pic text,
			cover_pic text,
			x json,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(tn_id)
		)",
	)
	.execute(&mut *tx)
	.await?;

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS tenant_data (
			tn_id integer NOT NULL,
			name text NOT NULL,
			value text,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(tn_id, name)
		)",
	)
	.execute(&mut *tx)
	.await?;

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS settings (
			tn_id integer NOT NULL,
			name text NOT NULL,
			value text,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(tn_id, name)
		)",
	)
	.execute(&mut *tx)
	.await?;

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS subscriptions (
			tn_id integer NOT NULL,
			subs_id integer PRIMARY KEY AUTOINCREMENT,
			subscription json,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch())
		)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_subscriptions_tnid ON subscriptions(tn_id)")
		.execute(&mut *tx)
		.await?;

	// Profiles
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS profiles (
			tn_id integer NOT NULL,
			id_tag text,
			name text NOT NULL,
			type char(1),
			profile_pic text,
			status char(1),
			perm char(1),
			following boolean,
			connected boolean,
			roles text,
			trust char(1),					-- Per-profile trust preference: 'A' always, 'N' never, NULL ask
			synced_at INTEGER,
			etag text,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(tn_id, id_tag)
		)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_profiles_tnid_idtag ON profiles(tn_id, id_tag)",
	)
	.execute(&mut *tx)
	.await?;

	// Metadata
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS tags (
			tn_id integer NOT NULL,
			tag text,
			perms json,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(tn_id, tag)
		)",
	)
	.execute(&mut *tx)
	.await?;

	// Files
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS files (
			f_id integer NOT NULL,
			tn_id integer NOT NULL,
			file_id text,
			file_tp char(4),			-- 'BLOB', 'CRDT', 'RTDB' file type (storage type)
			status char(1),				-- 'A' - Active, 'P' - Pending, 'D' - Deleted
			owner_tag text,				-- Set only for files owned by someone OTHER than the tenant (e.g., shared files)
			creator_tag text,			-- The user who actually created the file
			preset text,
			content_type text,
			file_name text,
			tags json,
			x json,
			visibility char(1),			-- NULL: Direct (owner only), P: Public, V: Verified,
										-- 2: 2nd degree, F: Follower, C: Connected
			hidden INTEGER DEFAULT 0,
			parent_id text,				-- Folder hierarchy: references file_id of parent folder
			root_id text,				-- Document tree: access control root file_id
			accessed_at INTEGER,		-- Global: when anyone last accessed this file
			modified_at INTEGER,		-- Global: when anyone last modified this file
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(f_id)
		)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_files_fileid ON files(file_id, tn_id)")
		.execute(&mut *tx)
		.await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_files_parent ON files(tn_id, parent_id)")
		.execute(&mut *tx)
		.await?;
	// Note: idx_files_root is created in migration 10 after the root_id column is added
	// Do NOT add it here as it would fail for existing databases being migrated

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS file_variants (
			tn_id integer NOT NULL,
			f_id integer NOT NULL,
			variant_id text,
			variant text,				-- 'vis.sd' - visual small density, 'vid.hd' - video high density, etc.
			res_x integer,
			res_y integer,
			format text,
			size integer,
			available boolean,
			global boolean,				-- true: stored in global cache
			duration real,				-- duration in seconds (for video/audio)
			bitrate integer,			-- bitrate in kbps (for video/audio)
			page_count integer,			-- page count (for documents)
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(f_id, variant_id, tn_id)
		)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
			"CREATE UNIQUE INDEX IF NOT EXISTS idx_file_variants_fileid ON file_variants(f_id, variant, tn_id)",
		)
		.execute(&mut *tx)
		.await?;

	// Refs
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS refs (
			tn_id integer NOT NULL,
			ref_id text NOT NULL,
			type text NOT NULL,
			description text,
			expires_at INTEGER,
			count integer,
			resource_id text,
			access_level char(1),
			params text,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(tn_id, ref_id)
		)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_refs_resource_id ON refs(resource_id) WHERE resource_id IS NOT NULL",
		)
		.execute(&mut *tx)
		.await?;
	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_refs_ref_id ON refs(ref_id)")
		.execute(&mut *tx)
		.await?;

	// Key cache
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS key_cache (
			id_tag text,
			key_id text,
			tn_id integer,
			expire integer,
			public_key text,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(id_tag, key_id)
		)",
	)
	.execute(&mut *tx)
	.await?;

	// Actions
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS actions (
			tn_id integer NOT NULL,
			a_id integer PRIMARY KEY AUTOINCREMENT,
			action_id text,
			key text,
			type text NOT NULL,
			sub_type text,
			parent_id text,
			root_id text,
			issuer_tag text NOT NULL,
			status char(1) DEFAULT 'P',		-- 'P' - Pending, 'A' - Active/finalized, 'D' - Deleted
			audience text,
			subject text,
			content json,
			expires_at INTEGER,
			attachments text,
			reactions text,
			comments integer,
			comments_read integer,
			visibility char(1),				-- NULL: Direct (owner only), P: Public, V: Verified,
											-- 2: 2nd degree, F: Follower, C: Connected
			flags text,						-- Action flags: R/r (reactions), C/c (comments), O/o (open)
			x json,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch())
		)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
			"CREATE UNIQUE INDEX IF NOT EXISTS idx_actions_action_id ON actions(tn_id, action_id) WHERE action_id NOT NULL",
		)
		.execute(&mut *tx)
		.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_actions_key ON actions(key, tn_id) WHERE key NOT NULL",
	)
	.execute(&mut *tx)
	.await?;
	// Note: idx_actions_subject_role is created in migration 6 after the x column is added
	// Do NOT add it here as it would fail for existing databases being migrated

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS action_tokens (
			tn_id integer NOT NULL,
			action_id text NOT NULL,
			token text NOT NULL,
			status char(1),				-- 'L': local, 'R': received, 'P': received pending, 'D': deleted
			ack text,
			next integer,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(action_id, tn_id)
		)",
	)
	.execute(&mut *tx)
	.await?;

	// Task scheduler
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS tasks (
			task_id integer NOT NULL,
			tn_id integer NOT NULL,
			kind text NOT NULL,
			key text,
			status char(1),				-- 'P': pending, 'F': finished, 'E': error
			next_at INTEGER,
			retry text,
			cron text,
			input text,
			output text,
			error text,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(task_id)
		)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_task_kind_key ON tasks(kind, key) WHERE status='P'",
	)
	.execute(&mut *tx)
	.await?;

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS task_dependencies (
			task_id integer NOT NULL,
			dep_id integer NOT NULL,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(task_id, dep_id)
		)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_task_dependencies_dep_id ON task_dependencies(dep_id)",
	)
	.execute(&mut *tx)
	.await?;

	// File user data (per-user file activity tracking)
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS file_user_data (
			tn_id INTEGER NOT NULL,
			id_tag TEXT NOT NULL,
			f_id INTEGER NOT NULL,
			accessed_at INTEGER,
			modified_at INTEGER,
			pinned INTEGER DEFAULT 0,
			starred INTEGER DEFAULT 0,
			created_at INTEGER NOT NULL DEFAULT (unixepoch()),
			updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
			PRIMARY KEY (tn_id, id_tag, f_id)
		)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_fud_recent ON file_user_data(tn_id, id_tag, accessed_at DESC) \
		WHERE accessed_at IS NOT NULL",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_fud_modified ON file_user_data(tn_id, id_tag, modified_at DESC) \
		WHERE modified_at IS NOT NULL",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_fud_pinned ON file_user_data(tn_id, id_tag) WHERE pinned = 1",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_fud_starred ON file_user_data(tn_id, id_tag) WHERE starred = 1",
	)
	.execute(&mut *tx)
	.await?;

	// Share entries (unified sharing: user shares, link shares, file-to-file links)
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS share_entries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			tn_id INTEGER NOT NULL,
			resource_type CHAR(1) NOT NULL,
			resource_id TEXT NOT NULL,
			subject_type CHAR(1) NOT NULL,
			subject_id TEXT NOT NULL,
			permission CHAR(1) NOT NULL,
			expires_at INTEGER,
			created_by TEXT NOT NULL,
			created_at INTEGER NOT NULL DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			UNIQUE(tn_id, resource_type, resource_id, subject_type, subject_id)
		)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_share_entries_resource \
		 ON share_entries(tn_id, resource_type, resource_id)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_share_entries_subject \
		 ON share_entries(tn_id, subject_type, subject_id)",
	)
	.execute(&mut *tx)
	.await?;

	// Triggers for automatic updated_at on INSERT
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS vars_insert_at AFTER INSERT ON vars FOR EACH ROW \
			BEGIN UPDATE vars SET updated_at = unixepoch() WHERE key = NEW.key; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS tenants_insert_at AFTER INSERT ON tenants FOR EACH ROW \
			BEGIN UPDATE tenants SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS tenant_data_insert_at AFTER INSERT ON tenant_data FOR EACH ROW \
			BEGIN UPDATE tenant_data SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND name = NEW.name; END",
		)
		.execute(&mut *tx)
		.await?;
	sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS settings_insert_at AFTER INSERT ON settings FOR EACH ROW \
			BEGIN UPDATE settings SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND name = NEW.name; END",
		)
		.execute(&mut *tx)
		.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS subscriptions_insert_at AFTER INSERT ON subscriptions FOR EACH ROW \
			BEGIN UPDATE subscriptions SET updated_at = unixepoch() WHERE subs_id = NEW.subs_id; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS profiles_insert_at AFTER INSERT ON profiles FOR EACH ROW \
			BEGIN UPDATE profiles SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND id_tag = NEW.id_tag; END",
		)
		.execute(&mut *tx)
		.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS tags_insert_at AFTER INSERT ON tags FOR EACH ROW \
			BEGIN UPDATE tags SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND tag = NEW.tag; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS files_insert_at AFTER INSERT ON files FOR EACH ROW \
			BEGIN UPDATE files SET updated_at = unixepoch() WHERE f_id = NEW.f_id; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS file_variants_insert_at AFTER INSERT ON file_variants FOR EACH ROW \
			BEGIN UPDATE file_variants SET updated_at = unixepoch() WHERE f_id = NEW.f_id AND variant_id = NEW.variant_id AND tn_id = NEW.tn_id; END",
		)
		.execute(&mut *tx)
		.await?;
	sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS refs_insert_at AFTER INSERT ON refs FOR EACH ROW \
			BEGIN UPDATE refs SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND ref_id = NEW.ref_id; END",
		)
		.execute(&mut *tx)
		.await?;
	sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS key_cache_insert_at AFTER INSERT ON key_cache FOR EACH ROW \
			BEGIN UPDATE key_cache SET updated_at = unixepoch() WHERE id_tag = NEW.id_tag AND key_id = NEW.key_id; END",
		)
		.execute(&mut *tx)
		.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS actions_insert_at AFTER INSERT ON actions FOR EACH ROW \
			BEGIN UPDATE actions SET updated_at = unixepoch() WHERE a_id = NEW.a_id; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS action_tokens_insert_at AFTER INSERT ON action_tokens FOR EACH ROW \
			BEGIN UPDATE action_tokens SET updated_at = unixepoch() WHERE action_id = NEW.action_id AND tn_id = NEW.tn_id; END",
		)
		.execute(&mut *tx)
		.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS tasks_insert_at AFTER INSERT ON tasks FOR EACH ROW \
			BEGIN UPDATE tasks SET updated_at = unixepoch() WHERE task_id = NEW.task_id; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS task_dependencies_insert_at AFTER INSERT ON task_dependencies FOR EACH ROW \
			BEGIN UPDATE task_dependencies SET updated_at = unixepoch() WHERE task_id = NEW.task_id AND dep_id = NEW.dep_id; END",
		)
		.execute(&mut *tx)
		.await?;
	sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS file_user_data_insert_at AFTER INSERT ON file_user_data FOR EACH ROW \
			BEGIN UPDATE file_user_data SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND id_tag = NEW.id_tag AND f_id = NEW.f_id; END",
		)
		.execute(&mut *tx)
		.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS share_entries_insert_at AFTER INSERT ON share_entries FOR EACH ROW \
			BEGIN UPDATE share_entries SET updated_at = unixepoch() WHERE id = NEW.id; END",
	)
	.execute(&mut *tx)
	.await?;

	// Triggers for automatic updated_at on UPDATE
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS vars_updated_at AFTER UPDATE ON vars FOR EACH ROW \
			BEGIN UPDATE vars SET updated_at = unixepoch() WHERE key = NEW.key; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS tenants_updated_at AFTER UPDATE ON tenants FOR EACH ROW \
			BEGIN UPDATE tenants SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS tenant_data_updated_at AFTER UPDATE ON tenant_data FOR EACH ROW \
			BEGIN UPDATE tenant_data SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND name = NEW.name; END",
		)
		.execute(&mut *tx)
		.await?;
	sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS settings_updated_at AFTER UPDATE ON settings FOR EACH ROW \
			BEGIN UPDATE settings SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND name = NEW.name; END",
		)
		.execute(&mut *tx)
		.await?;
	sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS subscriptions_updated_at AFTER UPDATE ON subscriptions FOR EACH ROW \
			BEGIN UPDATE subscriptions SET updated_at = unixepoch() WHERE subs_id = NEW.subs_id; END",
		)
		.execute(&mut *tx)
		.await?;
	sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS profiles_updated_at AFTER UPDATE ON profiles FOR EACH ROW \
			BEGIN UPDATE profiles SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND id_tag = NEW.id_tag; END",
		)
		.execute(&mut *tx)
		.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS tags_updated_at AFTER UPDATE ON tags FOR EACH ROW \
			BEGIN UPDATE tags SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND tag = NEW.tag; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS files_updated_at AFTER UPDATE ON files FOR EACH ROW \
			BEGIN UPDATE files SET updated_at = unixepoch() WHERE f_id = NEW.f_id; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS file_variants_updated_at AFTER UPDATE ON file_variants FOR EACH ROW \
			BEGIN UPDATE file_variants SET updated_at = unixepoch() WHERE f_id = NEW.f_id AND variant_id = NEW.variant_id AND tn_id = NEW.tn_id; END",
		)
		.execute(&mut *tx)
		.await?;
	sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS refs_updated_at AFTER UPDATE ON refs FOR EACH ROW \
			BEGIN UPDATE refs SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND ref_id = NEW.ref_id; END",
		)
		.execute(&mut *tx)
		.await?;
	sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS key_cache_updated_at AFTER UPDATE ON key_cache FOR EACH ROW \
			BEGIN UPDATE key_cache SET updated_at = unixepoch() WHERE id_tag = NEW.id_tag AND key_id = NEW.key_id; END",
		)
		.execute(&mut *tx)
		.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS actions_updated_at AFTER UPDATE ON actions FOR EACH ROW \
			BEGIN UPDATE actions SET updated_at = unixepoch() WHERE a_id = NEW.a_id; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS action_tokens_updated_at AFTER UPDATE ON action_tokens FOR EACH ROW \
			BEGIN UPDATE action_tokens SET updated_at = unixepoch() WHERE action_id = NEW.action_id AND tn_id = NEW.tn_id; END",
		)
		.execute(&mut *tx)
		.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS tasks_updated_at AFTER UPDATE ON tasks FOR EACH ROW \
			BEGIN UPDATE tasks SET updated_at = unixepoch() WHERE task_id = NEW.task_id; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS task_dependencies_updated_at AFTER UPDATE ON task_dependencies FOR EACH ROW \
			BEGIN UPDATE task_dependencies SET updated_at = unixepoch() WHERE task_id = NEW.task_id AND dep_id = NEW.dep_id; END",
		)
		.execute(&mut *tx)
		.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS file_user_data_updated_at AFTER UPDATE ON file_user_data FOR EACH ROW \
		BEGIN UPDATE file_user_data SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND id_tag = NEW.id_tag AND f_id = NEW.f_id; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS share_entries_updated_at AFTER UPDATE ON share_entries FOR EACH ROW \
			BEGIN UPDATE share_entries SET updated_at = unixepoch() WHERE id = NEW.id; END",
	)
	.execute(&mut *tx)
	.await?;

	// Installed apps (app store)
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS installed_apps (
			tn_id INTEGER NOT NULL,
			app_name TEXT NOT NULL,
			publisher_tag TEXT NOT NULL,
			version TEXT NOT NULL,
			action_id TEXT NOT NULL,
			file_id TEXT NOT NULL,
			blob_id TEXT NOT NULL,
			status CHAR(1) DEFAULT 'A',
			capabilities TEXT,
			auto_update INTEGER DEFAULT 0,
			installed_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(tn_id, app_name, publisher_tag)
		)",
	)
	.execute(&mut *tx)
	.await?;

	// Triggers for installed_apps
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS installed_apps_insert_at AFTER INSERT ON installed_apps FOR EACH ROW \
		BEGIN UPDATE installed_apps SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND app_name = NEW.app_name AND publisher_tag = NEW.publisher_tag; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS installed_apps_updated_at AFTER UPDATE ON installed_apps FOR EACH ROW \
		BEGIN UPDATE installed_apps SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND app_name = NEW.app_name AND publisher_tag = NEW.publisher_tag; END",
	)
	.execute(&mut *tx)
	.await?;

	// Address books (CardDAV collections) and contacts
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS address_books (
			tn_id INTEGER NOT NULL,
			ab_id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL DEFAULT 'Contacts',
			description TEXT,
			ctag TEXT NOT NULL,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			UNIQUE(tn_id, name)
		)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_address_books_tnid ON address_books(tn_id)")
		.execute(&mut *tx)
		.await?;

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS contacts (
			tn_id INTEGER NOT NULL,
			c_id INTEGER PRIMARY KEY AUTOINCREMENT,
			ab_id INTEGER NOT NULL,
			uid TEXT NOT NULL,
			etag TEXT NOT NULL,
			vcard TEXT NOT NULL,
			fn_name TEXT,
			given_name TEXT,
			family_name TEXT,
			email TEXT,
			emails TEXT,
			tel TEXT,
			tels TEXT,
			org TEXT,
			title TEXT,
			note TEXT,
			photo_uri TEXT,
			profile_id_tag TEXT,
			deleted_at INTEGER,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			UNIQUE(tn_id, ab_id, uid)
		)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_contacts_ab ON contacts(tn_id, ab_id)")
		.execute(&mut *tx)
		.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_contacts_fn ON contacts(tn_id, fn_name COLLATE NOCASE)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_contacts_email ON contacts(tn_id, email)")
		.execute(&mut *tx)
		.await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_contacts_uid ON contacts(tn_id, uid)")
		.execute(&mut *tx)
		.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_contacts_profile_tag ON contacts(tn_id, profile_id_tag) \
		 WHERE profile_id_tag IS NOT NULL",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_contacts_updated ON contacts(tn_id, ab_id, updated_at)",
	)
	.execute(&mut *tx)
	.await?;

	// Triggers for address_books / contacts
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS address_books_insert_at AFTER INSERT ON address_books FOR EACH ROW \
		BEGIN UPDATE address_books SET updated_at = unixepoch() WHERE ab_id = NEW.ab_id; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS address_books_updated_at AFTER UPDATE ON address_books FOR EACH ROW \
		BEGIN UPDATE address_books SET updated_at = unixepoch() WHERE ab_id = NEW.ab_id; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS contacts_insert_at AFTER INSERT ON contacts FOR EACH ROW \
		BEGIN UPDATE contacts SET updated_at = unixepoch() WHERE c_id = NEW.c_id; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS contacts_updated_at AFTER UPDATE ON contacts FOR EACH ROW \
		BEGIN UPDATE contacts SET updated_at = unixepoch() WHERE c_id = NEW.c_id; END",
	)
	.execute(&mut *tx)
	.await?;

	// Calendars (CalDAV) — mirror of address_books
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS calendars (
			tn_id INTEGER NOT NULL,
			cal_id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL DEFAULT 'Calendar',
			description TEXT,
			color TEXT,
			timezone TEXT,
			components TEXT NOT NULL DEFAULT 'VEVENT,VTODO',
			ctag TEXT NOT NULL,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			UNIQUE(tn_id, name)
		)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_calendars_tnid ON calendars(tn_id)")
		.execute(&mut *tx)
		.await?;

	// Uniqueness enforced via partial indexes below (not a table-level UNIQUE).
	// SQLite treats NULLs in a UNIQUE index as distinct, so a plain
	// UNIQUE(tn_id, cal_id, uid, recurrence_id) would let duplicate masters
	// (recurrence_id IS NULL) coexist.
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS calendar_objects (
			tn_id INTEGER NOT NULL,
			co_id INTEGER PRIMARY KEY AUTOINCREMENT,
			cal_id INTEGER NOT NULL,
			uid TEXT NOT NULL,
			component TEXT NOT NULL,
			etag TEXT NOT NULL,
			ical TEXT NOT NULL,
			summary TEXT,
			location TEXT,
			description TEXT,
			dtstart INTEGER,
			dtend INTEGER,
			all_day INTEGER NOT NULL DEFAULT 0,
			status TEXT,
			priority INTEGER,
			organizer TEXT,
			rrule TEXT,
			exdate TEXT,
			recurrence_id INTEGER,
			sequence INTEGER NOT NULL DEFAULT 0,
			deleted_at INTEGER,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch())
		)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_cobj_cal ON calendar_objects(tn_id, cal_id)")
		.execute(&mut *tx)
		.await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_cobj_uid ON calendar_objects(tn_id, uid)")
		.execute(&mut *tx)
		.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_cobj_component ON calendar_objects(tn_id, cal_id, component)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_cobj_dtstart ON calendar_objects(tn_id, cal_id, dtstart)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_cobj_dtend ON calendar_objects(tn_id, cal_id, dtend)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_cobj_updated ON calendar_objects(tn_id, cal_id, updated_at)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_cobj_unique_master \
		 ON calendar_objects(tn_id, cal_id, uid) \
		 WHERE recurrence_id IS NULL AND deleted_at IS NULL",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_cobj_unique_override \
		 ON calendar_objects(tn_id, cal_id, uid, recurrence_id) \
		 WHERE recurrence_id IS NOT NULL AND deleted_at IS NULL",
	)
	.execute(&mut *tx)
	.await?;

	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS calendars_insert_at AFTER INSERT ON calendars FOR EACH ROW \
		BEGIN UPDATE calendars SET updated_at = unixepoch() WHERE cal_id = NEW.cal_id; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS calendars_updated_at AFTER UPDATE ON calendars FOR EACH ROW \
		BEGIN UPDATE calendars SET updated_at = unixepoch() WHERE cal_id = NEW.cal_id; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS calendar_objects_insert_at \
		AFTER INSERT ON calendar_objects FOR EACH ROW \
		BEGIN UPDATE calendar_objects SET updated_at = unixepoch() WHERE co_id = NEW.co_id; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS calendar_objects_updated_at \
		AFTER UPDATE ON calendar_objects FOR EACH ROW \
		BEGIN UPDATE calendar_objects SET updated_at = unixepoch() WHERE co_id = NEW.co_id; END",
	)
	.execute(&mut *tx)
	.await?;

	// Fresh database: skip migrations (schema already has all columns)
	if version == 0 {
		// Create indexes that depend on columns added in migrations
		// For existing databases, these indexes are created in the respective migrations
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_actions_subject_role ON actions(subject, json_extract(x, '$.role')) WHERE type = 'SUBS'",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_files_root ON files(tn_id, root_id) \
			 WHERE root_id IS NOT NULL",
		)
		.execute(&mut *tx)
		.await?;

		set_db_version(&mut tx, CURRENT_DB_VERSION).await;
		version = CURRENT_DB_VERSION;
	}

	// Migrations for existing databases (ALTER TABLE only)
	if version < 2 {
		// Version 2: Fix tenant names and create profile entries for existing tenants

		// Step 1: Update tenant names where NULL
		// Derives name from first part of id_tag, capitalized
		// SQLite: UPPER(SUBSTR(x,1,1)) || SUBSTR(x,2) for capitalize
		sqlx::query(
			"UPDATE tenants SET name =
			 UPPER(SUBSTR(
				 CASE WHEN INSTR(id_tag, '.') > 0
					  THEN SUBSTR(id_tag, 1, INSTR(id_tag, '.') - 1)
					  ELSE id_tag
				 END, 1, 1)) ||
			 SUBSTR(
				 CASE WHEN INSTR(id_tag, '.') > 0
					  THEN SUBSTR(id_tag, 1, INSTR(id_tag, '.') - 1)
					  ELSE id_tag
				 END, 2)
			 WHERE name IS NULL",
		)
		.execute(&mut *tx)
		.await?;

		// Step 2: Create profile entries for existing tenants that don't have one
		sqlx::query(
			"INSERT OR IGNORE INTO profiles (tn_id, id_tag, name, type, created_at)
			 SELECT tn_id, id_tag, name, COALESCE(type, 'P'), unixepoch()
			 FROM tenants",
		)
		.execute(&mut *tx)
		.await?;

		set_db_version(&mut tx, 2).await;
	}

	// Version 3: Share link support - add resource_id and access_level to refs
	if version < 3 {
		// Add resource_id column for linking refs to resources (e.g., files)
		sqlx::query("ALTER TABLE refs ADD COLUMN resource_id TEXT")
			.execute(&mut *tx)
			.await?;

		// Add access_level column for share permissions ('R'=Read, 'W'=Write)
		sqlx::query("ALTER TABLE refs ADD COLUMN access_level CHAR(1)")
			.execute(&mut *tx)
			.await?;

		// Index for efficient resource_id lookups (only for refs with resource_id)
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_refs_resource_id ON refs(resource_id) WHERE resource_id IS NOT NULL",
		)
		.execute(&mut *tx)
		.await?;

		// Global unique index on ref_id for unauthenticated lookups
		sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_refs_ref_id ON refs(ref_id)")
			.execute(&mut *tx)
			.await?;

		set_db_version(&mut tx, 3).await;
	}

	// Version 4: Folder hierarchy and collections support
	if version < 4 {
		// Add parent_id column to files table for folder hierarchy
		// parent_id references file_id of a folder (file_tp = 'FLDR')
		// NULL means root level
		sqlx::query("ALTER TABLE files ADD COLUMN parent_id TEXT")
			.execute(&mut *tx)
			.await?;

		// Index for efficient folder listing queries
		sqlx::query("CREATE INDEX IF NOT EXISTS idx_files_parent ON files(tn_id, parent_id)")
			.execute(&mut *tx)
			.await?;

		// Collections table for favorites, recent files, bookmarks, pins
		// Unified table for all user item references across entity types
		// Item IDs encode their type via prefix (f1~, a1~, etc.)
		sqlx::query(
			"CREATE TABLE IF NOT EXISTS collections (
			tn_id INTEGER NOT NULL,
			coll_type CHAR(4) NOT NULL,		-- 'FAVR', 'RCNT', 'BKMK', 'PIND'
			item_id TEXT NOT NULL,			-- Entity ID with built-in type prefix
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY (tn_id, coll_type, item_id)
		)",
		)
		.execute(&mut *tx)
		.await?;

		// Index for listing collections by type with ordering
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_collections ON collections(tn_id, coll_type, created_at DESC)",
		)
		.execute(&mut *tx)
		.await?;

		// Trigger for automatic updated_at on INSERT
		sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS collections_insert_at AFTER INSERT ON collections FOR EACH ROW \
			BEGIN UPDATE collections SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND coll_type = NEW.coll_type AND item_id = NEW.item_id; END",
		)
		.execute(&mut *tx)
		.await?;

		// Trigger for automatic updated_at on UPDATE
		sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS collections_updated_at AFTER UPDATE ON collections FOR EACH ROW \
			BEGIN UPDATE collections SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND coll_type = NEW.coll_type AND item_id = NEW.item_id; END",
		)
		.execute(&mut *tx)
		.await?;

		set_db_version(&mut tx, 4).await;
	}

	// Version 5: Add flags column to actions table for action flags (R/C/O)
	if version < 5 {
		// Add flags column to actions table
		// Flags: R/r (reactions allowed), C/c (comments allowed), O/o (open/closed)
		sqlx::query("ALTER TABLE actions ADD COLUMN flags TEXT")
			.execute(&mut *tx)
			.await?;

		set_db_version(&mut tx, 5).await;
	}

	// Version 6: Add x JSON column for extensible metadata
	if version < 6 {
		// Add x column to actions table for extensible metadata (JSON)
		// Used for: x.role (SUBS), and future extensible data
		sqlx::query("ALTER TABLE actions ADD COLUMN x JSON").execute(&mut *tx).await?;

		// Index for efficient role-based queries on SUBS actions
		// SQLite JSON extraction: json_extract(x, '$.role')
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_actions_subject_role ON actions(subject, json_extract(x, '$.role')) WHERE type = 'SUBS'",
		)
		.execute(&mut *tx)
		.await?;

		set_db_version(&mut tx, 6).await;
	}

	// Version 7: Add global activity timestamps to files table
	// (file_user_data table is created in schema descriptor section above)
	if version < 7 {
		// Add global accessed_at and modified_at columns to files table
		// These track when ANY user last accessed or modified the file
		sqlx::query("ALTER TABLE files ADD COLUMN accessed_at INTEGER")
			.execute(&mut *tx)
			.await?;
		sqlx::query("ALTER TABLE files ADD COLUMN modified_at INTEGER")
			.execute(&mut *tx)
			.await?;

		set_db_version(&mut tx, 7).await;
	}

	// Version 8: Convert roles from JSON array to bare string
	if version < 8 {
		// Convert JSON array roles (e.g. '["leader"]') to bare string (e.g. 'leader')
		// json_extract with '$[0]' extracts the first element from a JSON array
		sqlx::query(
			"UPDATE profiles SET roles = json_extract(roles, '$[0]') \
			 WHERE roles IS NOT NULL AND roles LIKE '[%'",
		)
		.execute(&mut *tx)
		.await?;

		set_db_version(&mut tx, 8).await;
	}

	// Version 9: Add creator_tag column to files table
	// creator_tag tracks who actually created a file, while owner_tag is reserved
	// for files owned by someone OTHER than the tenant (e.g., shared files via FSHR)
	if version < 9 {
		sqlx::query("ALTER TABLE files ADD COLUMN creator_tag text")
			.execute(&mut *tx)
			.await?;

		// Backfill: existing files with owner_tag set → copy to creator_tag, clear owner_tag
		// (except shared files which have no preset — those keep their owner_tag)
		sqlx::query(
			"UPDATE files SET creator_tag = owner_tag, owner_tag = NULL WHERE owner_tag IS NOT NULL AND preset IS NOT NULL",
		)
		.execute(&mut *tx)
		.await?;

		set_db_version(&mut tx, 9).await;
	}

	// Version 10: Document tree root_id on files
	if version < 10 {
		sqlx::query("ALTER TABLE files ADD COLUMN root_id TEXT")
			.execute(&mut *tx)
			.await?;
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_files_root ON files(tn_id, root_id) \
			 WHERE root_id IS NOT NULL",
		)
		.execute(&mut *tx)
		.await?;

		set_db_version(&mut tx, 10).await;
	}

	// Version 11: Share entries table
	if version < 11 {
		sqlx::query(
			"CREATE TABLE IF NOT EXISTS share_entries (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				tn_id INTEGER NOT NULL,
				resource_type CHAR(1) NOT NULL,
				resource_id TEXT NOT NULL,
				subject_type CHAR(1) NOT NULL,
				subject_id TEXT NOT NULL,
				permission CHAR(1) NOT NULL,
				expires_at INTEGER,
				created_by TEXT NOT NULL,
				created_at INTEGER NOT NULL DEFAULT (unixepoch()),
				updated_at INTEGER DEFAULT (unixepoch()),
				UNIQUE(tn_id, resource_type, resource_id, subject_type, subject_id)
			)",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_share_entries_resource \
			 ON share_entries(tn_id, resource_type, resource_id)",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_share_entries_subject \
			 ON share_entries(tn_id, subject_type, subject_id)",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS share_entries_insert_at AFTER INSERT ON share_entries FOR EACH ROW \
				BEGIN UPDATE share_entries SET updated_at = unixepoch() WHERE id = NEW.id; END",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS share_entries_updated_at AFTER UPDATE ON share_entries FOR EACH ROW \
				BEGIN UPDATE share_entries SET updated_at = unixepoch() WHERE id = NEW.id; END",
		)
		.execute(&mut *tx)
		.await?;

		set_db_version(&mut tx, 11).await;
	}

	// Version 12: Migrate existing FSHR actions into share_entries (sender side only)
	if version < 12 {
		// Only where issuer_tag matches the tenant's own id_tag
		// (receiver-side FSHR actions have a foreign issuer — skip those)
		sqlx::query(
			"INSERT OR IGNORE INTO share_entries \
				(tn_id, resource_type, resource_id, subject_type, subject_id, \
				 permission, created_by, created_at) \
			 SELECT a.tn_id, 'F', a.subject, 'U', a.audience, \
				CASE WHEN a.sub_type = 'WRITE' THEN 'W' ELSE 'R' END, \
				a.issuer_tag, a.created_at \
			 FROM actions a \
			 INNER JOIN tenants t ON a.tn_id = t.tn_id AND a.issuer_tag = t.id_tag \
			 WHERE a.type = 'FSHR' \
				AND a.subject IS NOT NULL \
				AND a.audience IS NOT NULL \
				AND (a.sub_type IS NULL OR a.sub_type != 'DEL') \
				AND (a.status IS NULL OR a.status != 'D')",
		)
		.execute(&mut *tx)
		.await?;

		set_db_version(&mut tx, 12).await;
	}

	// Version 13: Installed apps table + drop orphaned action_outbox_queue
	if version < 13 {
		// Drop orphaned action_outbox_queue table and its triggers from earlier development
		sqlx::query("DROP TRIGGER IF EXISTS action_outbox_queue_insert_at")
			.execute(&mut *tx)
			.await?;
		sqlx::query("DROP TRIGGER IF EXISTS action_outbox_queue_updated_at")
			.execute(&mut *tx)
			.await?;
		sqlx::query("DROP TABLE IF EXISTS action_outbox_queue")
			.execute(&mut *tx)
			.await?;

		sqlx::query(
			"CREATE TABLE IF NOT EXISTS installed_apps (
				tn_id INTEGER NOT NULL,
				app_name TEXT NOT NULL,
				publisher_tag TEXT NOT NULL,
				version TEXT NOT NULL,
				action_id TEXT NOT NULL,
				file_id TEXT NOT NULL,
				blob_id TEXT NOT NULL,
				status CHAR(1) DEFAULT 'A',
				capabilities TEXT,
				auto_update INTEGER DEFAULT 0,
				installed_at INTEGER DEFAULT (unixepoch()),
				updated_at INTEGER DEFAULT (unixepoch()),
				PRIMARY KEY(tn_id, app_name, publisher_tag)
			)",
		)
		.execute(&mut *tx)
		.await?;

		sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS installed_apps_insert_at AFTER INSERT ON installed_apps FOR EACH ROW \
			BEGIN UPDATE installed_apps SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND app_name = NEW.app_name AND publisher_tag = NEW.publisher_tag; END",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS installed_apps_updated_at AFTER UPDATE ON installed_apps FOR EACH ROW \
			BEGIN UPDATE installed_apps SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND app_name = NEW.app_name AND publisher_tag = NEW.publisher_tag; END",
		)
		.execute(&mut *tx)
		.await?;

		set_db_version(&mut tx, 13).await;
	}

	// Version 14: Convert reactions column from integer to text (per-type counts)
	// Format: "L5:V3:W1" (Like=5, Love=3, Wow=1)
	// Existing integer values are converted to "L{n}" (assume all were likes)
	if version < 14 {
		// SQLite doesn't support ALTER COLUMN, but it's flexible with types.
		// The column stays as-is structurally, we just convert existing integer values to text format.
		// Convert non-null integer reaction counts to "L{n}" format
		sqlx::query(
			"UPDATE actions SET reactions = 'L' || reactions \
			 WHERE reactions IS NOT NULL AND typeof(reactions) = 'integer' AND reactions > 0",
		)
		.execute(&mut *tx)
		.await?;

		// Clear zero-value reactions (they're meaningless)
		sqlx::query(
			"UPDATE actions SET reactions = NULL \
			 WHERE reactions IS NOT NULL AND (reactions = '0' OR reactions = 0)",
		)
		.execute(&mut *tx)
		.await?;

		set_db_version(&mut tx, 14).await;
	}

	// Version 15: Add params column to refs for share link launch params
	if version < 15 {
		sqlx::query("ALTER TABLE refs ADD COLUMN params TEXT").execute(&mut *tx).await?;

		set_db_version(&mut tx, 15).await;
	}

	// Version 16: Add trust column to profiles for per-profile proxy-token preference
	// ('A' always, 'N' never, NULL = ask / default anonymous)
	if version < 16 {
		sqlx::query("ALTER TABLE profiles ADD COLUMN trust CHAR(1)")
			.execute(&mut *tx)
			.await?;

		set_db_version(&mut tx, 16).await;
	}

	// Version 17: Contact management with CardDAV sync
	if version < 17 {
		sqlx::query(
			"CREATE TABLE IF NOT EXISTS address_books (
				tn_id INTEGER NOT NULL,
				ab_id INTEGER PRIMARY KEY AUTOINCREMENT,
				name TEXT NOT NULL DEFAULT 'Contacts',
				description TEXT,
				ctag TEXT NOT NULL,
				created_at INTEGER DEFAULT (unixepoch()),
				updated_at INTEGER DEFAULT (unixepoch()),
				UNIQUE(tn_id, name)
			)",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query("CREATE INDEX IF NOT EXISTS idx_address_books_tnid ON address_books(tn_id)")
			.execute(&mut *tx)
			.await?;

		sqlx::query(
			"CREATE TABLE IF NOT EXISTS contacts (
				tn_id INTEGER NOT NULL,
				c_id INTEGER PRIMARY KEY AUTOINCREMENT,
				ab_id INTEGER NOT NULL,
				uid TEXT NOT NULL,
				etag TEXT NOT NULL,
				vcard TEXT NOT NULL,
				fn_name TEXT,
				given_name TEXT,
				family_name TEXT,
				email TEXT,
				emails TEXT,
				tel TEXT,
				tels TEXT,
				org TEXT,
				title TEXT,
				note TEXT,
				photo_uri TEXT,
				profile_id_tag TEXT,
				deleted_at INTEGER,
				created_at INTEGER DEFAULT (unixepoch()),
				updated_at INTEGER DEFAULT (unixepoch()),
				UNIQUE(tn_id, ab_id, uid)
			)",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query("CREATE INDEX IF NOT EXISTS idx_contacts_ab ON contacts(tn_id, ab_id)")
			.execute(&mut *tx)
			.await?;
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_contacts_fn ON contacts(tn_id, fn_name COLLATE NOCASE)",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query("CREATE INDEX IF NOT EXISTS idx_contacts_email ON contacts(tn_id, email)")
			.execute(&mut *tx)
			.await?;
		sqlx::query("CREATE INDEX IF NOT EXISTS idx_contacts_uid ON contacts(tn_id, uid)")
			.execute(&mut *tx)
			.await?;
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_contacts_profile_tag ON contacts(tn_id, profile_id_tag) \
			 WHERE profile_id_tag IS NOT NULL",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_contacts_updated ON contacts(tn_id, ab_id, updated_at)",
		)
		.execute(&mut *tx)
		.await?;

		sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS address_books_insert_at AFTER INSERT ON address_books FOR EACH ROW \
			BEGIN UPDATE address_books SET updated_at = unixepoch() WHERE ab_id = NEW.ab_id; END",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS address_books_updated_at AFTER UPDATE ON address_books FOR EACH ROW \
			BEGIN UPDATE address_books SET updated_at = unixepoch() WHERE ab_id = NEW.ab_id; END",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS contacts_insert_at AFTER INSERT ON contacts FOR EACH ROW \
			BEGIN UPDATE contacts SET updated_at = unixepoch() WHERE c_id = NEW.c_id; END",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS contacts_updated_at AFTER UPDATE ON contacts FOR EACH ROW \
			BEGIN UPDATE contacts SET updated_at = unixepoch() WHERE c_id = NEW.c_id; END",
		)
		.execute(&mut *tx)
		.await?;

		set_db_version(&mut tx, 17).await;
	}

	// Migration v18: calendars + calendar_objects (CalDAV).
	if version < 18 {
		sqlx::query(
			"CREATE TABLE IF NOT EXISTS calendars (
				tn_id INTEGER NOT NULL,
				cal_id INTEGER PRIMARY KEY AUTOINCREMENT,
				name TEXT NOT NULL DEFAULT 'Calendar',
				description TEXT,
				color TEXT,
				timezone TEXT,
				components TEXT NOT NULL DEFAULT 'VEVENT,VTODO',
				ctag TEXT NOT NULL,
				created_at INTEGER DEFAULT (unixepoch()),
				updated_at INTEGER DEFAULT (unixepoch()),
				UNIQUE(tn_id, name)
			)",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query("CREATE INDEX IF NOT EXISTS idx_calendars_tnid ON calendars(tn_id)")
			.execute(&mut *tx)
			.await?;

		sqlx::query(
			"CREATE TABLE IF NOT EXISTS calendar_objects (
				tn_id INTEGER NOT NULL,
				co_id INTEGER PRIMARY KEY AUTOINCREMENT,
				cal_id INTEGER NOT NULL,
				uid TEXT NOT NULL,
				component TEXT NOT NULL,
				etag TEXT NOT NULL,
				ical TEXT NOT NULL,
				summary TEXT,
				location TEXT,
				description TEXT,
				dtstart INTEGER,
				dtend INTEGER,
				all_day INTEGER NOT NULL DEFAULT 0,
				status TEXT,
				priority INTEGER,
				organizer TEXT,
				rrule TEXT,
				recurrence_id INTEGER,
				sequence INTEGER NOT NULL DEFAULT 0,
				deleted_at INTEGER,
				created_at INTEGER DEFAULT (unixepoch()),
				updated_at INTEGER DEFAULT (unixepoch()),
				UNIQUE(tn_id, cal_id, uid, recurrence_id)
			)",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query("CREATE INDEX IF NOT EXISTS idx_cobj_cal ON calendar_objects(tn_id, cal_id)")
			.execute(&mut *tx)
			.await?;
		sqlx::query("CREATE INDEX IF NOT EXISTS idx_cobj_uid ON calendar_objects(tn_id, uid)")
			.execute(&mut *tx)
			.await?;
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_cobj_component ON calendar_objects(tn_id, cal_id, component)",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_cobj_dtstart ON calendar_objects(tn_id, cal_id, dtstart)",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_cobj_dtend ON calendar_objects(tn_id, cal_id, dtend)",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_cobj_updated ON calendar_objects(tn_id, cal_id, updated_at)",
		)
		.execute(&mut *tx)
		.await?;

		sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS calendars_insert_at AFTER INSERT ON calendars FOR EACH ROW \
			BEGIN UPDATE calendars SET updated_at = unixepoch() WHERE cal_id = NEW.cal_id; END",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS calendars_updated_at AFTER UPDATE ON calendars FOR EACH ROW \
			BEGIN UPDATE calendars SET updated_at = unixepoch() WHERE cal_id = NEW.cal_id; END",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS calendar_objects_insert_at \
			AFTER INSERT ON calendar_objects FOR EACH ROW \
			BEGIN UPDATE calendar_objects SET updated_at = unixepoch() WHERE co_id = NEW.co_id; END",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS calendar_objects_updated_at \
			AFTER UPDATE ON calendar_objects FOR EACH ROW \
			BEGIN UPDATE calendar_objects SET updated_at = unixepoch() WHERE co_id = NEW.co_id; END",
		)
		.execute(&mut *tx)
		.await?;

		set_db_version(&mut tx, 18).await;
	}

	// Migration v19: fix calendar_objects uniqueness.
	//
	// v18 shipped with UNIQUE(tn_id, cal_id, uid, recurrence_id), which SQLite
	// treats as distinct for NULL recurrence_id — so PUT on a non-recurring
	// event never hit the ON CONFLICT branch and inserted a duplicate row.
	// Replace the broken uniqueness with partial unique indexes keyed on
	// whether recurrence_id is NULL. Any pre-existing duplicates must be
	// cleaned up manually before this migration runs, or the CREATE UNIQUE
	// INDEX will fail.
	if version < 19 {
		sqlx::query(
			"CREATE UNIQUE INDEX IF NOT EXISTS idx_cobj_unique_master \
			 ON calendar_objects(tn_id, cal_id, uid) \
			 WHERE recurrence_id IS NULL AND deleted_at IS NULL",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query(
			"CREATE UNIQUE INDEX IF NOT EXISTS idx_cobj_unique_override \
			 ON calendar_objects(tn_id, cal_id, uid, recurrence_id) \
			 WHERE recurrence_id IS NOT NULL AND deleted_at IS NULL",
		)
		.execute(&mut *tx)
		.await?;

		set_db_version(&mut tx, 19).await;
	}

	// Migration v20: add calendar_objects.exdate (CSV of unix seconds).
	//
	// Stores EXDATE exclusions on the master VEVENT so we can skip occurrences
	// on the client without creating a separate cancelled override row. CSV of
	// unix-second timestamps matches the recurrence_id convention.
	if version < 20 {
		let has_exdate: (i64,) = sqlx::query_as(
			"SELECT COUNT(*) FROM pragma_table_info('calendar_objects') WHERE name = 'exdate'",
		)
		.fetch_one(&mut *tx)
		.await?;
		if has_exdate.0 == 0 {
			sqlx::query("ALTER TABLE calendar_objects ADD COLUMN exdate TEXT")
				.execute(&mut *tx)
				.await?;
		}

		set_db_version(&mut tx, 20).await;
	}

	// Migration v21: index actions by (tn_id, subject, type).
	//
	// Speeds up community-INVT lookups (`type='INVT' AND subject=<community
	// id_tag>`) used by the leader's Invitations sub-tab and by the CONN
	// on_receive bypass that auto-accepts invitation-backed connections.
	if version < 21 {
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_actions_subject_type \
			 ON actions(tn_id, subject, type) WHERE subject IS NOT NULL",
		)
		.execute(&mut *tx)
		.await?;

		set_db_version(&mut tx, 21).await;
	}

	// Migration v22: backfill root_id for existing meta files.
	//
	// Meta database files ({parent_file_id}~meta) should have root_id pointing
	// to their parent file so they don't appear as standalone entries in listings.
	if version < 22 {
		sqlx::query(
			"UPDATE files SET root_id = SUBSTR(file_id, 1, LENGTH(file_id) - 5) \
			 WHERE file_id LIKE '%~meta' AND root_id IS NULL",
		)
		.execute(&mut *tx)
		.await?;

		set_db_version(&mut tx, 22).await;
	}

	// Migration v23: hidden flag for files (attachments, profile pictures)
	if version < 23 {
		sqlx::query("ALTER TABLE files ADD COLUMN hidden INTEGER DEFAULT 0")
			.execute(&mut *tx)
			.await?;

		// Backfill: mark files referenced as action attachments as hidden.
		// Attachments are stored as comma-separated file_ids, so we use a
		// recursive CTE to split each CSV value and match against files.
		sqlx::query(
			"WITH RECURSIVE split(tn_id, val, rest) AS ( \
				SELECT tn_id, \
					CASE WHEN INSTR(attachments, ',') > 0 \
						THEN TRIM(SUBSTR(attachments, 1, INSTR(attachments, ',') - 1)) \
						ELSE TRIM(attachments) END, \
					CASE WHEN INSTR(attachments, ',') > 0 \
						THEN SUBSTR(attachments, INSTR(attachments, ',') + 1) \
						ELSE NULL END \
				FROM actions WHERE attachments IS NOT NULL AND attachments != '' \
				UNION ALL \
				SELECT tn_id, \
					CASE WHEN INSTR(rest, ',') > 0 \
						THEN TRIM(SUBSTR(rest, 1, INSTR(rest, ',') - 1)) \
						ELSE TRIM(rest) END, \
					CASE WHEN INSTR(rest, ',') > 0 \
						THEN SUBSTR(rest, INSTR(rest, ',') + 1) \
						ELSE NULL END \
				FROM split WHERE rest IS NOT NULL \
			) \
			UPDATE files SET hidden = 1 \
			WHERE EXISTS ( \
				SELECT 1 FROM split \
				WHERE split.val = files.file_id \
					AND split.tn_id = files.tn_id \
					AND split.val != '' \
			)",
		)
		.execute(&mut *tx)
		.await?;

		sqlx::query("UPDATE files SET hidden = 1 WHERE preset = 'profile-picture'")
			.execute(&mut *tx)
			.await?;

		set_db_version(&mut tx, 23).await;
	}

	tx.commit().await?;

	Ok(())
}
// vim: ts=4
