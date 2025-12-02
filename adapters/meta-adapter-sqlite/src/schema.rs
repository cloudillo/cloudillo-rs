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

	let version = get_db_version(&mut tx).await;

	if version < 1 {
		// Version 1: Initial schema

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
			roles json,
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
			owner_tag text,
			preset text,
			content_type text,
			file_name text,
			tags json,
			x json,
			visibility char(1),			-- NULL: Direct (owner only), P: Public, V: Verified,
										-- 2: 2nd degree, F: Follower, C: Connected
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
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(tn_id, ref_id)
		)",
		)
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

		set_db_version(&mut tx, 1).await;
	}

	// Future migrations:
	// if version < 2 { ... migration 2 ...; set_db_version(&mut tx, 2).await; }

	tx.commit().await?;

	Ok(())
}
