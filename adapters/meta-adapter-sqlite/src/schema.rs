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

	// Current schema version - update this when adding new migrations
	const CURRENT_DB_VERSION: i64 = 9;

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
			parent_id text,				-- Folder hierarchy: references file_id of parent folder
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
			attachments json,
			reactions integer,
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

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS action_outbox_queue (
			tn_id integer NOT NULL,
			action_id text NOT NULL,
			id_tag text NOT NULL,
			next INTEGER,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(action_id, tn_id, id_tag)
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
			"CREATE TRIGGER IF NOT EXISTS action_outbox_queue_insert_at AFTER INSERT ON action_outbox_queue FOR EACH ROW \
			BEGIN UPDATE action_outbox_queue SET updated_at = unixepoch() WHERE action_id = NEW.action_id AND tn_id = NEW.tn_id AND id_tag = NEW.id_tag; END",
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
			"CREATE TRIGGER IF NOT EXISTS action_outbox_queue_updated_at AFTER UPDATE ON action_outbox_queue FOR EACH ROW \
			BEGIN UPDATE action_outbox_queue SET updated_at = unixepoch() WHERE action_id = NEW.action_id AND tn_id = NEW.tn_id AND id_tag = NEW.id_tag; END",
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

	// Fresh database: skip migrations (schema already has all columns)
	if version == 0 {
		// Create indexes that depend on columns added in migrations
		// For existing databases, these indexes are created in the respective migrations
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_actions_subject_role ON actions(subject, json_extract(x, '$.role')) WHERE type = 'SUBS'",
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

	// Future migrations:
	// if version < 10 { ... migration 10 ...; set_db_version(&mut tx, 10).await; }

	tx.commit().await?;

	Ok(())
}
// vim: ts=4
