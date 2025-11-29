//! Database schema initialization and migrations
//!
//! This module handles creating tables, indexes, and running migrations
//! to ensure the database schema is up to date.

use sqlx::SqlitePool;

/// Initialize the database schema with all required tables and indexes
pub(crate) async fn init_db(db: &SqlitePool) -> Result<(), sqlx::Error> {
	let mut tx = db.begin().await?;

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS globals (
			key text NOT NULL,
			value text,
			PRIMARY KEY(key)
	)",
	)
	.execute(&mut *tx)
	.await?;

	/***********/
	/* Init DB */
	/***********/

	// Tenants
	//*********
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS tenants (
		tn_id integer NOT NULL,
		id_tag text NOT NULL,
		type char(1),
		name text,
		profile_pic text,
		cover_pic text,
		x json,
		created_at datetime DEFAULT (unixepoch()),
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
		PRIMARY KEY(tn_id, name)
	)",
	)
	.execute(&mut *tx)
	.await?;

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS subscriptions (
		tn_id integer NOT NULL,
		subs_id integer NOT NULL,
		created_at datetime DEFAULT (unixepoch()),
		subscription json,
		PRIMARY KEY(subs_id)
	)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_subscriptions_tnid ON subscriptions(tn_id)")
		.execute(&mut *tx)
		.await?;

	// Profiles
	//**********
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
		created_at datetime DEFAULT (unixepoch()),
		synced_at datetime,
		etag text,
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
	//**********
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS tags (
		tn_id integer NOT NULL,
		tag text,
		perms json,
		PRIMARY KEY(tn_id, tag)
	)",
	)
	.execute(&mut *tx)
	.await?;

	// Files
	//*******
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS files (
		f_id integer NOT NULL,
		tn_id integer NOT NULL,
		file_id text,
		file_tp char(4),			-- 'BLOB', 'CRDT', 'RTDB' file type (storage type)
		status char(1),				-- 'M' - Mutable, 'A' - Active/immutable,
								-- 'P' - immutable under Processing, 'D' - Deleted
		owner_tag text,
		preset text,
		content_type text,
		file_name text,
		created_at datetime DEFAULT (unixepoch()),
		modified_at datetime,
		tags json,
		x json,
		visibility char(1),			-- NULL: Direct (owner only), P: Public, V: Verified,
								-- 2: 2nd degree, F: Follower, C: Connected
		PRIMARY KEY(f_id)
	)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_files_fileid ON files(file_id, tn_id)")
		.execute(&mut *tx)
		.await?;

	sqlx::query("CREATE TABLE IF NOT EXISTS file_variants (
		tn_id integer NOT NULL,
		f_id integer NOT NULL,
		variant_id text,
		variant text,				-- 'orig' - original, 'hd' - high density, 'sd' - small density, 'tn' - thumbnail, 'ic' - icon
		res_x integer,
		res_y integer,
		format text,
		size integer,
		available boolean,
		global boolean,				-- true: stored in global cache
		PRIMARY KEY(f_id, variant_id, tn_id)
	)").execute(&mut *tx).await?;
	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_file_variants_fileid ON file_variants(f_id, variant, tn_id)")
		.execute(&mut *tx).await?;

	// Refs
	//******
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS refs (
		tn_id integer NOT NULL,
		ref_id text NOT NULL,
		type text NOT NULL,
		description text,
		created_at datetime DEFAULT (unixepoch()),
		expires_at datetime,
		count integer,
		PRIMARY KEY(tn_id, ref_id)
	)",
	)
	.execute(&mut *tx)
	.await?;

	// Event store
	//*************
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS key_cache (
		id_tag text,
		key_id text,
		tn_id integer,
		expire integer,
		public_key text,
		PRIMARY KEY(id_tag, key_id)
	)",
	)
	.execute(&mut *tx)
	.await?;

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
		created_at datetime DEFAULT (unixepoch()),
		expires_at datetime,
		attachments json,
		reactions integer,
		comments integer,
		comments_read integer,
		visibility char(1)			-- NULL: Direct (owner only), P: Public, V: Verified,
								-- 2: 2nd degree, F: Follower, C: Connected
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
		next datetime,
		PRIMARY KEY(action_id, tn_id, id_tag)
	)",
	)
	.execute(&mut *tx)
	.await?;

	// Task scheduler
	//****************
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS tasks (
		task_id integer NOT NULL,
		tn_id integer NOT NULL,
		kind text NOT NULL,
		key text,
		status char(1),			-- 'P': pending, 'F': finished, 'E': error
		created_at datetime DEFAULT (unixepoch()),
		next_at datetime,
		retry text,
		cron text,
		input text,
		output text,
		error text,
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
		PRIMARY KEY(task_id, dep_id)
	) WITHOUT ROWID",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_task_dependencies_dep_id ON task_dependencies(dep_id)",
	)
	.execute(&mut *tx)
	.await?;

	// Phase 2 Migration: Action metadata enhancements
	let _ = sqlx::query("ALTER TABLE actions ADD COLUMN updated_at datetime DEFAULT NULL")
		.execute(&mut *tx)
		.await;

	// Update file_tp to have a default value if it's NULL
	let _ = sqlx::query("UPDATE files SET file_tp = 'BLOB' WHERE file_tp IS NULL")
		.execute(&mut *tx)
		.await;

	// Visibility column migration for files and actions
	// NULL = Direct (most restrictive), P = Public, V = Verified, 2 = 2nd degree, F = Follower, C = Connected
	let _ = sqlx::query("ALTER TABLE files ADD COLUMN visibility char(1)")
		.execute(&mut *tx)
		.await;
	let _ = sqlx::query("ALTER TABLE actions ADD COLUMN visibility char(1)")
		.execute(&mut *tx)
		.await;

	tx.commit().await?;

	Ok(())
}
