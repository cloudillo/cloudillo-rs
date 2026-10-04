// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Database schema initialization and migrations
//!
//! This module handles creating tables, indexes, and running migrations
//! to ensure the database schema is up to date.

use cloudillo_types::prelude::*;
use sqlx::{Row, Sqlite, SqlitePool, Transaction};

/// Add a column only if it is not already present. SQLite has no
/// `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`; a plain ALTER errors with
/// "duplicate column name" when the column exists. Migrations normally run only
/// on older DBs that lack the column, but a replay over a current base schema
/// (e.g. a migration test that rolls db_version back) would otherwise fail.
async fn add_column_if_missing(
	tx: &mut Transaction<'_, Sqlite>,
	table: &str,
	column: &str,
	decl: &str,
) -> Result<(), sqlx::Error> {
	// table/column/decl are internal constants (never user input), so the
	// dynamic SQL is safe — assert that for the sqlx injection lint.
	let cols = sqlx::query(sqlx::AssertSqlSafe(format!("PRAGMA table_info({table})")))
		.fetch_all(&mut **tx)
		.await?;
	let exists = cols.iter().any(|r| r.get::<String, _>("name") == column);
	if !exists {
		sqlx::query(sqlx::AssertSqlSafe(format!("ALTER TABLE {table} ADD COLUMN {column} {decl}")))
			.execute(&mut **tx)
			.await?;
	}
	Ok(())
}

async fn drop_column_if_exists(
	tx: &mut Transaction<'_, Sqlite>,
	table: &str,
	column: &str,
) -> Result<(), sqlx::Error> {
	// table/column are internal constants (never user input), so the dynamic SQL
	// is safe — assert that for the sqlx injection lint.
	let cols = sqlx::query(sqlx::AssertSqlSafe(format!("PRAGMA table_info({table})")))
		.fetch_all(&mut **tx)
		.await?;
	let exists = cols.iter().any(|r| r.get::<String, _>("name") == column);
	if exists {
		sqlx::query(sqlx::AssertSqlSafe(format!("ALTER TABLE {table} DROP COLUMN {column}")))
			.execute(&mut **tx)
			.await?;
	}
	Ok(())
}

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

/// Column list shared by every `search_docs` writer below.
pub(crate) const SEARCH_COLS: &str = "(tn_id, obj_tp, obj_id, part_id, part_kind, title, body, \
	 tags, content_type, upstream_tag, root_id, created_at, updated_at, fts_cl, obj_hash)";

/// The `DO UPDATE` clause shared by every upsert below. `part_id` is always `''`
/// for whole-object rows, so `idx_search_docs_key` makes `(tn_id, obj_tp,
/// obj_id)` the effective conflict target.
pub(crate) const SEARCH_UPSERT: &str = "ON CONFLICT(tn_id, obj_tp, obj_id, part_id) DO UPDATE SET \
	 part_kind = excluded.part_kind, title = excluded.title, body = excluded.body, \
	 tags = excluded.tags, content_type = excluded.content_type, \
	 upstream_tag = excluded.upstream_tag, root_id = excluded.root_id, \
	 created_at = excluded.created_at, \
	 updated_at = excluded.updated_at, fts_cl = excluded.fts_cl, \
	 obj_hash = excluded.obj_hash";

/// Set the database version in vars table
async fn set_db_version(tx: &mut Transaction<'_, Sqlite>, version: i64) {
	let _ = sqlx::query("INSERT OR REPLACE INTO vars (key, value) VALUES ('db_version', ?)")
		.bind(version.to_string())
		.execute(&mut **tx)
		.await;
}

/// The FTS5 virtual tables backing full-text search, and the triggers that
/// mirror `search_docs` into the external-content one.
///
/// The trigger strings carry no `CREATE TRIGGER` prefix so a future migration
/// that has to drop and recreate them can reuse these constants verbatim — FTS5
/// has no `ALTER TABLE ... ADD COLUMN`, so any column change to these tables is a
/// drop/recreate/repopulate.
///
/// Every statement lists all four `search_fts` columns. FTS5's `'delete'`
/// command needs the original value of each one, so an omission would silently
/// leave tombstones behind.
///
/// `tn_id` is a real indexed column, not metadata: a query pushes a `tn_id:<n>`
/// clause into the MATCH expression so FTS5 narrows to one tenant before ranking,
/// instead of matching the whole node's corpus and letting the `d.tn_id` join
/// condition trim it afterwards.
const SEARCH_FTS_DDL: &str = "CREATE VIRTUAL TABLE IF NOT EXISTS search_fts USING fts5(
		title, body, tags, tn_id,
		content='search_docs', content_rowid='s_id',
		tokenize=\"unicode61 remove_diacritics 2 tokenchars '#@'\"
	)";

const SEARCH_FTS_CL_DDL: &str = "CREATE VIRTUAL TABLE IF NOT EXISTS search_fts_cl USING fts5(
		title, body, tags, tn_id,
		content='', contentless_delete=1,
		tokenize=\"unicode61 remove_diacritics 2 tokenchars '#@'\"
	)";

const SEARCH_FTS_TRIGGERS: [&str; 3] = [
	"search_docs_ai AFTER INSERT ON search_docs \
	 WHEN new.fts_cl = 0 BEGIN \
	 INSERT INTO search_fts(rowid, title, body, tags, tn_id) \
	 VALUES (new.s_id, new.title, new.body, new.tags, new.tn_id); END",
	"search_docs_ad AFTER DELETE ON search_docs \
	 WHEN old.fts_cl = 0 BEGIN \
	 INSERT INTO search_fts(search_fts, rowid, title, body, tags, tn_id) \
	 VALUES ('delete', old.s_id, old.title, old.body, old.tags, old.tn_id); END",
	"search_docs_au AFTER UPDATE ON search_docs \
	 WHEN old.fts_cl = 0 AND new.fts_cl = 0 BEGIN \
	 INSERT INTO search_fts(search_fts, rowid, title, body, tags, tn_id) \
	 VALUES ('delete', old.s_id, old.title, old.body, old.tags, old.tn_id); \
	 INSERT INTO search_fts(rowid, title, body, tags, tn_id) \
	 VALUES (new.s_id, new.title, new.body, new.tags, new.tn_id); END",
];

/// Touches `entries.updated_at` on every change. No `CREATE TRIGGER` prefix, so the v58
/// migration can drop and recreate it around its own writes.
const ENTRIES_UPDATED_AT_TRIGGER: &str = "entries_updated_at AFTER UPDATE ON entries \
	FOR EACH ROW BEGIN UPDATE entries SET updated_at = unixepoch() WHERE e_id = NEW.e_id; END";

/// v58 managed backfill: the live actions' attachment items, one per row.
const SPLIT: &str = "WITH RECURSIVE split(tn_id, a_id, action_id, item, rest) AS ( \
	   SELECT tn_id, a_id, action_id, NULL, attachments || ',' FROM actions \
	    WHERE attachments IS NOT NULL AND attachments != '' \
	      AND action_id IS NOT NULL AND coalesce(status, 'A') != 'D' \
	   UNION ALL \
	   SELECT tn_id, a_id, action_id, substr(rest, 1, instr(rest, ',') - 1), \
	     substr(rest, instr(rest, ',') + 1) FROM split WHERE rest != '' \
	 ) ";
/// v58 managed backfill: split row `s` names entry `entries`' content (`f` its file).
const ITEM_MATCH: &str = "s.tn_id = entries.tn_id AND s.item IS NOT NULL AND s.item != '' \
	  AND ((s.item LIKE '@%' AND f.f_id = (SELECT COALESCE(o.merged_into, o.f_id) \
	        FROM files o WHERE o.tn_id = s.tn_id \
	        AND o.f_id = CAST(substr(s.item, 2) AS INTEGER))) \
	    OR (s.item NOT LIKE '@%' AND f.file_id = s.item))";

/// Migration 58 body: split the legacy `files` table into `entries` + `files`.
async fn migrate_v58_entries(tx: &mut Transaction<'_, Sqlite>) -> Result<(), sqlx::Error> {
	// The migration's own rewrites must keep each row's `updated_at`; recreated at the end.
	sqlx::query("DROP TRIGGER IF EXISTS entries_updated_at")
		.execute(&mut **tx)
		.await?;
	// SQLite refuses to drop an indexed column.
	sqlx::query("DROP INDEX IF EXISTS idx_files_parent").execute(&mut **tx).await?;

	// Placeholder entry_id (the content id, or `@<f_id>` while pending) is unique per
	// tenant; content rows get their random id below.
	sqlx::query(
		"INSERT INTO entries (e_id, tn_id, entry_id, f_id, status, owner_tag, upstream_tag, \
		   file_name, tags, visibility, hidden, parent_id, channel, created_at, updated_at, \
		   broken_at, broken_reason) \
		 SELECT f_id, tn_id, COALESCE(file_id, '@' || f_id), \
		   CASE WHEN file_tp = 'FLDR' THEN NULL ELSE f_id END, status, owner_tag, upstream_tag, \
		   file_name, tags, visibility, hidden, parent_id, channel, created_at, updated_at, \
		   broken_at, broken_reason \
		 FROM files",
	)
	.execute(&mut **tx)
	.await?;

	let content: Vec<i64> = sqlx::query_scalar("SELECT e_id FROM entries WHERE f_id IS NOT NULL")
		.fetch_all(&mut **tx)
		.await?;
	for e_id in content {
		let entry_id = cloudillo_types::utils::random_id()
			.map_err(|e| sqlx::Error::Protocol(format!("random_id: {e}")))?;
		sqlx::query("UPDATE entries SET entry_id = ? WHERE e_id = ?")
			.bind(entry_id)
			.bind(e_id)
			.execute(&mut **tx)
			.await?;
	}

	// Shares and file-to-file links name the entry now. Folder ids are unchanged.
	for col in ["resource", "subject"] {
		sqlx::query(sqlx::AssertSqlSafe(format!(
			"UPDATE share_entries SET {col}_id = \
			   (SELECT e.entry_id FROM files f JOIN entries e ON e.f_id = f.f_id \
			    WHERE f.tn_id = share_entries.tn_id AND f.file_id = share_entries.{col}_id) \
			 WHERE {col}_type = 'F' AND EXISTS \
			   (SELECT 1 FROM files f WHERE f.tn_id = share_entries.tn_id \
			    AND f.file_id = share_entries.{col}_id AND f.file_tp IS NOT 'FLDR')"
		)))
		.execute(&mut **tx)
		.await?;
	}
	sqlx::query(
		"UPDATE refs SET resource_id = \
		   (SELECT e.entry_id FROM files f JOIN entries e ON e.f_id = f.f_id \
		    WHERE f.tn_id = refs.tn_id AND f.file_id = refs.resource_id) \
		 WHERE type = 'share.file' AND EXISTS \
		   (SELECT 1 FROM files f WHERE f.tn_id = refs.tn_id AND f.file_id = refs.resource_id \
		    AND f.file_tp IS NOT 'FLDR')",
	)
	.execute(&mut **tx)
	.await?;

	// A remote folder is a reference like any other placement: a fresh entry id, the upstream's
	// folder id on `ref_file_id`, and every local pointer at the old id repointed. Its legacy
	// `files` row (`f_id` = the entry's `e_id`) still holds the content type.
	let remote_folders: Vec<(i64, i64, Box<str>)> = sqlx::query_as(
		"SELECT e_id, tn_id, entry_id FROM entries \
		 WHERE upstream_tag IS NOT NULL AND f_id IS NULL AND ref_file_id IS NULL",
	)
	.fetch_all(&mut **tx)
	.await?;
	for (e_id, tn_id, old_id) in remote_folders {
		let entry_id = cloudillo_types::utils::random_id()
			.map_err(|e| sqlx::Error::Protocol(format!("random_id: {e}")))?;
		sqlx::query(
			"UPDATE entries SET entry_id = ?1, ref_file_id = entry_id, ref_file_tp = 'FLDR', \
			   ref_content_type = (SELECT content_type FROM files WHERE f_id = ?2) \
			 WHERE e_id = ?2",
		)
		.bind(&entry_id)
		.bind(e_id)
		.execute(&mut **tx)
		.await?;
		for sql in [
			"UPDATE entries SET parent_id = ?1 WHERE tn_id = ?2 AND parent_id = ?3",
			"UPDATE share_entries SET resource_id = ?1 \
			 WHERE tn_id = ?2 AND resource_type = 'F' AND resource_id = ?3",
			"UPDATE share_entries SET subject_id = ?1 \
			 WHERE tn_id = ?2 AND subject_type = 'F' AND subject_id = ?3",
			"UPDATE refs SET resource_id = ?1 \
			 WHERE tn_id = ?2 AND type = 'share.file' AND resource_id = ?3",
		] {
			sqlx::query(sql)
				.bind(&entry_id)
				.bind(tn_id)
				.bind(old_id.as_ref())
				.execute(&mut **tx)
				.await?;
		}
	}

	// Folders are entries without a file.
	sqlx::query(
		"DELETE FROM file_variants WHERE f_id IN (SELECT f_id FROM files WHERE file_tp = 'FLDR')",
	)
	.execute(&mut **tx)
	.await?;
	sqlx::query("DELETE FROM files WHERE file_tp = 'FLDR'")
		.execute(&mut **tx)
		.await?;

	// Pins / Places / FSHR placements become references: the upstream content id and display
	// fields move onto the entry, and the entry never links a local `files` row again.
	sqlx::query(
		"UPDATE entries SET \
		   ref_file_id = (SELECT f.file_id FROM files f WHERE f.f_id = entries.f_id), \
		   ref_file_tp = (SELECT f.file_tp FROM files f WHERE f.f_id = entries.f_id), \
		   ref_content_type = (SELECT f.content_type FROM files f WHERE f.f_id = entries.f_id), \
		   ref_x = (SELECT f.x FROM files f WHERE f.f_id = entries.f_id), \
		   ref_preset = (SELECT f.preset FROM files f WHERE f.f_id = entries.f_id), \
		   f_id = NULL \
		 WHERE upstream_tag IS NOT NULL AND f_id IS NOT NULL",
	)
	.execute(&mut **tx)
	.await?;
	// A document part (`{root}~meta`) joins its root's drive, as a new one does.
	sqlx::query(
		"UPDATE entries SET channel = (SELECT r.channel FROM entries r \
		   JOIN files rf ON rf.f_id = r.f_id JOIN files pf ON pf.f_id = entries.f_id \
		   WHERE rf.tn_id = pf.tn_id AND rf.file_id = pf.root_id AND r.status <> 'D' \
		   ORDER BY r.e_id LIMIT 1) \
		 WHERE channel IS NULL AND f_id IN \
		   (SELECT f_id FROM files WHERE root_id IS NOT NULL AND file_id LIKE '%~meta')",
	)
	.execute(&mut **tx)
	.await?;
	// Legacy managed attachment entries get their owning action: the latest live action whose
	// attachments name the content (by id or `@<f_id>`); every other such action gets a copy of the
	// entry, so each lives and dies with its own action. One no live action names stays NULL, and
	// the file GC reaps it.
	sqlx::query(sqlx::AssertSqlSafe(format!(
		"{SPLIT} UPDATE entries SET action_id = ( \
		   SELECT s.action_id FROM split s JOIN files f ON f.f_id = entries.f_id \
		    WHERE {ITEM_MATCH} ORDER BY s.a_id DESC LIMIT 1) \
		 WHERE parent_id = ? AND action_id IS NULL AND f_id IS NOT NULL"
	)))
	.bind(cloudillo_types::meta_adapter::MANAGED_PARENT_ID)
	.execute(&mut **tx)
	.await?;
	let extra: Vec<(i64, Box<str>)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
		"{SPLIT} SELECT DISTINCT entries.e_id, s.action_id FROM entries \
		   JOIN files f ON f.f_id = entries.f_id JOIN split s ON {ITEM_MATCH} \
		 WHERE entries.parent_id = ? AND entries.action_id IS NOT s.action_id"
	)))
	.bind(cloudillo_types::meta_adapter::MANAGED_PARENT_ID)
	.fetch_all(&mut **tx)
	.await?;
	for (e_id, action_id) in extra {
		let entry_id = cloudillo_types::utils::random_id()
			.map_err(|e| sqlx::Error::Protocol(format!("random_id: {e}")))?;
		sqlx::query(
			"INSERT INTO entries (tn_id, entry_id, f_id, status, owner_tag, file_name, tags, \
			   visibility, hidden, parent_id, channel, action_id, created_at, updated_at) \
			 SELECT tn_id, ?, f_id, status, owner_tag, file_name, tags, visibility, hidden, \
			   parent_id, channel, ?, created_at, updated_at FROM entries WHERE e_id = ?",
		)
		.bind(entry_id)
		.bind(action_id.as_ref())
		.bind(e_id)
		.execute(&mut **tx)
		.await?;
	}
	// A reference's former row goes when it held nothing here. One with local variants (a Pin
	// that landed on local bytes) stays: the file GC reaps it once no entry wants it.
	sqlx::query(
		"DELETE FROM files WHERE NOT EXISTS (SELECT 1 FROM entries e WHERE e.f_id = files.f_id) \
		 AND NOT EXISTS (SELECT 1 FROM file_variants v WHERE v.f_id = files.f_id)",
	)
	.execute(&mut **tx)
	.await?;

	for col in [
		"status",
		"owner_tag",
		"upstream_tag",
		"file_name",
		"tags",
		"visibility",
		"hidden",
		"parent_id",
		"channel",
		"created_at",
		"broken_at",
		"broken_reason",
	] {
		drop_column_if_exists(tx, "files", col).await?;
	}
	sqlx::query(sqlx::AssertSqlSafe(format!(
		"CREATE TRIGGER IF NOT EXISTS {ENTRIES_UPDATED_AT_TRIGGER}"
	)))
	.execute(&mut **tx)
	.await?;
	Ok(())
}

/// Initialize the database schema with all required tables and indexes
pub(crate) async fn init_db(db: &SqlitePool) -> Result<(), sqlx::Error> {
	// Current schema version - update this when adding new migrations
	const CURRENT_DB_VERSION: i64 = 58;

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
			last_seen_at INTEGER,			-- Presence: stamped when the tenant's last ws-bus connection closes
			notify_email_direct_at INTEGER,			-- Offline-throttle watermark for the 'direct' group (MSG/CONN/FSHR)
			notify_email_engagement_at INTEGER,		-- Offline-throttle watermark for the 'engagement' group (CMNT/REACT)
			notify_email_social_at INTEGER,			-- Offline-throttle watermark for the 'social' group (FLLW/POST)
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

	// Per-profile settings. Unlike `settings` (tenant-wide, admin-only) each row is owned by
	// the profile named in `id_tag` — the first entity here whose owner is a member rather
	// than the tenant.
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS profile_settings (
			tn_id integer NOT NULL,
			id_tag text NOT NULL,
			name text NOT NULL,
			value text,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(tn_id, id_tag, name)
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
			follower boolean,
			connected boolean,
			roles text,
			trust char(1),					-- Per-profile trust preference: 'A' always, 'N' never, NULL ask
			synced_at INTEGER,
			etag text,
			feed_read_at INTEGER,			-- Reader's feed read-watermark for this context
			msg_read_at INTEGER,			-- Reader's DM read-watermark for this peer
			hidden_in_home INTEGER,			-- Composition: NULL = community shown in home feed (default), 1 = hidden
			hat_roles text,					-- My role map for this peer's members (peer_role:local_role,...)
			peer_hat_roles text,			-- Peer's role map for my members (advisory mirror)
			hats text,						-- My identities used at this peer, JSON array (empty string = as myself)
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

	// Files: pure content. Placement (folder, name, trash, visibility, …) lives on `entries`,
	// so one immutable BLOB can sit in several folders/rooms under the same `file_id`.
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS files (
			f_id integer NOT NULL,
			tn_id integer NOT NULL,
			file_id text,
			file_tp char(4),			-- 'BLOB', 'CRDT', 'RTDB' file type (storage type)
			preset text,
			content_type text,
			x json,						-- Content metadata, e.g. image dim [w,h]
			root_id text,				-- Document tree: access control root file_id
			merged_into integer,		-- Deduped pending upload: the surviving f_id
			accessed_at INTEGER,		-- Global: when anyone last accessed this file
			modified_at INTEGER,		-- Global: when anyone last modified this file
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(f_id)
		)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_files_fileid ON files(file_id, tn_id)")
		.execute(&mut *tx)
		.await?;

	// Entries: one placement of a file. Folders are entries without a file (`f_id` NULL).
	// Only BLOB files may have more than one entry.
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS entries (
			e_id integer NOT NULL,
			tn_id integer NOT NULL,
			entry_id text NOT NULL,		-- random_id(); a migrated folder keeps its old file_id
			f_id integer,				-- files.f_id; NULL => folder
			status char(1),				-- 'A' - Active, 'P' - Pending, 'D' - Deleted
			owner_tag text,				-- The profile with owner authority; NULL => the tenant
			upstream_tag text,			-- Where this placement's canonical copy lives; NULL => originates here
			file_name text,
			tags json,
			visibility char(1),			-- NULL: Direct (owner only), P: Public, V: Verified,
										-- 2: 2nd degree, F: Follower, C: Connected
			hidden INTEGER DEFAULT 0,
			parent_id text,				-- Folder hierarchy: entry_id of the parent folder
			channel text,				-- Absolute channel `@tenant~name`; NULL => open floor
			action_id text,				-- Managed attachment entry: the action that owns it
			-- Reference (`upstream_tag` set, `f_id` NULL): the upstream content, never held here
			ref_file_id text,
			ref_file_tp char(4),
			ref_content_type text,
			ref_x json,
			ref_preset text,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			broken_at INTEGER,			-- Tombstone written by the cross-context refresh endpoint
			broken_reason TEXT,			-- BrokenReason enum: 'deleted' | 'revoked'
			PRIMARY KEY(e_id)
		)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_entries_entryid ON entries(entry_id, tn_id)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_entries_parent ON entries(tn_id, parent_id)")
		.execute(&mut *tx)
		.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_entries_file ON entries(f_id) WHERE f_id IS NOT NULL",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_entries_channel ON entries(tn_id, channel) \
		 WHERE channel IS NOT NULL",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_entries_action ON entries(tn_id, action_id) \
		 WHERE action_id IS NOT NULL",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_entries_ref ON entries(tn_id, ref_file_id, upstream_tag) \
		 WHERE ref_file_id IS NOT NULL",
	)
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
			hat_tag text,					-- Community whose hat the issuer wore (signed `h` claim)
			channel text,					-- Absolute channel `@tenant~name`; NULL => open floor
			status char(1) DEFAULT 'P',		-- 'P' - Pending, 'A' - Active/finalized, 'D' - Deleted
			audience text,
			subject text,
			content json,
			expires_at INTEGER,
			attachments text,
			reactions text,
			comments integer DEFAULT 0,	-- total comment count, federated as STAT `c`
			comments_ts integer,		-- last-comment timestamp (epoch seconds), federated as STAT `ct`
			comments_read_at integer,	-- reader's comment read-watermark (epoch seconds)
			reposts integer,
			stat_at INTEGER,				-- Highest created_at of any STAT applied to reactions/comments
			visibility char(1) NOT NULL DEFAULT 'D',	-- D: Direct (owner only), P: Public, V: Verified,
														-- 2: 2nd degree, F: Follower, C: Connected
			flags text,						-- Action flags: R/r (reactions), C/c (comments), O/o (open)
			sub_level char(1),				-- Reader's W/T/M thread subscription level (NULL=none)
			x json,
			-- Dual-purpose: for status R (draft) / S (scheduled), holds the
			-- target publish instant (consumed by ActionCreatorTask + PATCH
			-- /actions). For status A (active/finalized) and onward, holds
			-- the actual creation time. See UpdateActionDataOptions::created_at.
			created_at INTEGER DEFAULT (unixepoch()),
			-- LOCAL ingestion time (epoch seconds), stamped at insert — NEVER the
			-- federated payload's created_at. The home feed sorts/watermarks by
			-- this so late-federated posts surface by arrival order. Migrated DBs
			-- can't get this DEFAULT (SQLite rejects a non-constant default on
			-- ALTER of a populated table), so create() stamps it explicitly via
			-- unixepoch(); see migration 36.
			received_at INTEGER DEFAULT (unixepoch()),
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
	// Backs thread comment listing + the `comments` (last-comment ts) recompute
	// done by CMNT:DEL and the v36 migration.
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_actions_parent_created ON actions(tn_id, parent_id, created_at)",
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
	// `created_at`/`updated_at` entered the descriptor above in the same commit that introduced
	// `db_version`, with no accompanying `ALTER TABLE` — and `CREATE TABLE IF NOT EXISTS` cannot
	// add a column to a table that already exists, so databases carried over from the
	// TypeScript-era schema still lack `created_at`. The index below reads it.
	//
	// Here and not in a versioned migration, for the reason already spelled out for
	// `sites`/`site_docs` further down: the descriptor block runs unconditionally and *before*
	// every migration, so this is the only placement where the column is guaranteed present by
	// the time the index is created.
	//
	// No `DEFAULT (unixepoch())`: SQLite rejects a non-constant default on `ADD COLUMN` once the
	// table has rows. The three writers in `action.rs` stamp it explicitly instead.
	add_column_if_missing(&mut tx, "action_tokens", "created_at", "INTEGER").await?;
	sqlx::query("UPDATE action_tokens SET created_at = unixepoch() WHERE created_at IS NULL")
		.execute(&mut *tx)
		.await?;
	// Backs `action::cleanup_orphaned_tokens`' daily sweep. Partial: only bundled rows whose
	// primary never verified are ever eligible, and they are a small minority of the table.
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_action_tokens_orphan \
		 ON action_tokens(created_at) WHERE ack IS NOT NULL",
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
			e_id INTEGER NOT NULL,		-- entries.e_id
			accessed_at INTEGER,
			modified_at INTEGER,
			pinned INTEGER DEFAULT 0,
			starred INTEGER DEFAULT 0,
			access_level CHAR(1),
			created_at INTEGER NOT NULL DEFAULT (unixepoch()),
			updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
			PRIMARY KEY (tn_id, id_tag, e_id)
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
			BEGIN UPDATE file_user_data SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND id_tag = NEW.id_tag AND e_id = NEW.e_id; END",
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
	sqlx::query(sqlx::AssertSqlSafe(format!(
		"CREATE TRIGGER IF NOT EXISTS {ENTRIES_UPDATED_AT_TRIGGER}"
	)))
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
		BEGIN UPDATE file_user_data SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND id_tag = NEW.id_tag AND e_id = NEW.e_id; END",
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

	// Document format manifests. `content_type` is the claim key: only one app may
	// register (and therefore index) a given document type per tenant.
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS doc_formats (
			tn_id integer NOT NULL,
			content_type text NOT NULL,
			publisher_tag text NOT NULL,
			app_name text NOT NULL,
			format_version integer,
			store_tp char(4),
			nav_param text,
			search json,
			x json,
			status char(1) DEFAULT 'A',
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(tn_id, content_type)
		)",
	)
	.execute(&mut *tx)
	.await?;

	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS doc_formats_insert_at AFTER INSERT ON doc_formats FOR EACH ROW \
		BEGIN UPDATE doc_formats SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND content_type = NEW.content_type; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS doc_formats_updated_at AFTER UPDATE ON doc_formats FOR EACH ROW \
		BEGIN UPDATE doc_formats SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND content_type = NEW.content_type; END",
	)
	.execute(&mut *tx)
	.await?;

	// Full-text search index. One row per searchable unit: a whole object
	// (part_id = '') or a deep sub-part of a document (part_id = the app's
	// deep-link key, e.g. a notillo page id).
	//
	// `part_id` is NOT NULL DEFAULT '' on purpose — SQLite treats NULLs as
	// distinct in a UNIQUE index, so a nullable column would silently permit
	// duplicate whole-object rows.
	//
	// There is deliberately NO `updated_at` trigger here: `updated_at` is set
	// explicitly by the writer. An AFTER UPDATE ... UPDATE trigger would
	// re-fire the FTS mirror triggers below.
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS search_docs (
			s_id integer PRIMARY KEY AUTOINCREMENT,
			tn_id integer NOT NULL,
			obj_tp char(1) NOT NULL,
			obj_id text NOT NULL,
			part_id text NOT NULL DEFAULT '',
			part_kind text,
			parent_part text,
			anchor_id text,
			title text,
			body text,
			tags text,
			content_type text,
			-- Where the indexed object comes from: `p.id_tag` for 'P', `a.issuer_tag`
			-- for 'A'. NULL for 'F'/'D' rows: provenance is per entry, read live from
			-- `entries.upstream_tag`. It is *not* the profile with owner authority.
			upstream_tag text,
			root_id text,
			created_at INTEGER,
			updated_at INTEGER,
			fts_cl integer NOT NULL DEFAULT 0,
			obj_hash text
		)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_search_docs_key \
		ON search_docs(tn_id, obj_tp, obj_id, part_id)",
	)
	.execute(&mut *tx)
	.await?;
	// FTS5 external-content table mirroring search_docs. External content (as
	// opposed to contentless) keeps snippet() working while storing the text
	// only once. `remove_diacritics 2` folds Unicode accents server-side;
	// `tokenchars '#@'` keeps #tag and @mention as single tokens.
	//
	// `tn_id` is indexed as a column so a query can push `tn_id:<n>` into the
	// MATCH expression and have FTS5 narrow to one tenant *before* ranking,
	// instead of matching the whole node's corpus and letting the `d.tn_id` join
	// condition cut it down afterwards. It comes last so the ordinals of the three
	// text columns — which the mirror triggers and `crate::search`'s inserts both
	// depend on — do not shift. External content maps columns by name and
	// `search_docs.tn_id` already exists, so the content table is unchanged.
	sqlx::query(SEARCH_FTS_DDL).execute(&mut *tx).await?;

	// Second FTS5 index, for tenants that turned `search.store_text` off. It is
	// *contentless* — no plain-text copy is kept anywhere, so `snippet()` cannot
	// work — but the body is still fully tokenized, so matching and `bm25()` are
	// identical to `search_fts`. Same four columns in the same order and the
	// same tokenizer, so the query builder and `escape_fts_query` work unchanged
	// against either table.
	//
	// `contentless_delete=1` (SQLite >= 3.43) is what makes deletion possible at
	// all without the original column values: it swaps the FTS5 `'delete'`
	// command — which requires them — for ordinary `DELETE`/`UPDATE` keyed on the
	// rowid. FTS5 rejects `'delete'` on such a table outright.
	//
	// A trigger cannot maintain this table: for a contentless row `search_docs.
	// body` is NULL by construction, so there would be no text to index. It is
	// written *only* by `crate::search`, which holds the extracted body.
	sqlx::query(SEARCH_FTS_CL_DDL).execute(&mut *tx).await?;

	// Mirror triggers — search_fts must never be written directly outside these.
	//
	// `fts_cl = 1` rows belong to `search_fts_cl` and are skipped here; the
	// adapter writes them. A row never changes mode in place — a `search.
	// store_text` flip is applied by a full reindex, which deletes and
	// re-inserts — so `old.fts_cl <> new.fts_cl` on the AU trigger is a bug, not
	// a supported path, and the guard deliberately does not try to migrate it.
	for stmt in SEARCH_FTS_TRIGGERS {
		sqlx::query(sqlx::AssertSqlSafe(format!("CREATE TRIGGER IF NOT EXISTS {stmt}")))
			.execute(&mut *tx)
			.await?;
	}

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

	// Channels: named rooms inside a tenant. Names are bare here (the tenant is tn_id);
	// entity `channel` columns carry the absolute `@tenant~name` form.
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS channels (
			tn_id integer NOT NULL,
			name text NOT NULL,
			title text,
			descr text,
			visibility char(1),			-- NULL: Direct (secret room), else VisibilityLevel char
			min_role text,				-- Bare ROLE_HIERARCHY name; NULL => public
			closed integer NOT NULL DEFAULT 0,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(tn_id, name)
		)",
	)
	.execute(&mut *tx)
	.await?;
	// Roster projection of signed SUBS/INVT; not the record of truth.
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS channel_members (
			tn_id integer NOT NULL,
			channel text NOT NULL,
			id_tag text NOT NULL,
			added_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(tn_id, channel, id_tag)
		)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_channel_members_user ON channel_members(tn_id, id_tag)",
	)
	.execute(&mut *tx)
	.await?;

	// Partner edges: a membership community's connected community peers, synced from its
	// `GET /api/partners` and from received PTNR actions. Feeds the connection map.
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS partner_edge (
			tn_id integer NOT NULL,
			community text NOT NULL,
			partner text NOT NULL,
			PRIMARY KEY(tn_id, community, partner)
		)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE INDEX IF NOT EXISTS idx_partner_edge_partner ON partner_edge(tn_id, partner)",
	)
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

	// Site builder
	//
	// `sites` is a per-tenant singleton: `tn_id` alone is the discriminator, so
	// `site_docs` carries no site reference. A table and not settings keys — the settings
	// store is typed scalar key/value, which fits no structured record.
	//
	// No `host` column: a tenant's site host is always its app domain, which
	// `build_domains_for_tenant` derives, so a stored copy would drift. Domain aliases
	// arrive as a `site_host (tn_id, host)` table, not as a scalar override — an override
	// would *replace* the app domain, silently taking the site off `<idTag>`.
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS sites (
			tn_id integer NOT NULL,
			status char(1) DEFAULT 'A',		-- 'A': active (served), 'D': disabled (configured but dark)
			nav text,						-- explicit main navigation, JSON array; NULL/empty = derive it
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(tn_id)
		)",
	)
	.execute(&mut *tx)
	.await?;

	// One row per document participating in the site.
	//
	// `UNIQUE (tn_id, mount_path)` is not optional. The primary key says a document
	// appears at most once in the site but nothing about the reverse; without the index
	// two documents can both claim '/blog' and longest-prefix resolution picks whichever
	// row the query returns first — different content per restart, with no error anywhere.
	// The publish endpoint checks it explicitly too, so the conflict is reported by
	// document name rather than as a raw constraint violation.
	//
	// Exactly two generations, both plain scalar columns. That keeps the GC reachability
	// query (`list_referenced_managed_fids`) a plain join, the shape of
	// `tenants.profile_pic`, instead of the `WITH RECURSIVE` CSV split
	// `actions.attachments` needs. It also makes retention free: on publish the displaced
	// generation loses its last reference and the GC reaps it.
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS site_docs (
			tn_id integer NOT NULL,
			doc_file_id text NOT NULL,			-- the Notillo document
			mount_path text NOT NULL,			-- configured: '/' for the root document, '/blog' for a mount
			published_mount_path text,			-- the path the served container was built for
			published_file_id text,				-- current container; NULL before the first publish
			previous_file_id text,				-- the one generation kept for rollback
			previous_mount_path text,			-- the path that generation was built for
			published_at INTEGER,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(tn_id, doc_file_id)
		)",
	)
	.execute(&mut *tx)
	.await?;
	// Here and not in a versioned migration, against the usual rule: the descriptor block
	// runs unconditionally and *before* every migration, and the statements below are part
	// of it and read `published_mount_path`. `CREATE TABLE IF NOT EXISTS` cannot add a
	// column to a table that exists, so this is the only placement where the columns are
	// guaranteed present by the time they are read. Seven no-op `PRAGMA table_info` checks
	// per start on two tiny tables.
	add_column_if_missing(&mut tx, "sites", "status", "char(1) DEFAULT 'A'").await?;
	add_column_if_missing(&mut tx, "sites", "nav", "text").await?;
	add_column_if_missing(&mut tx, "site_docs", "published_mount_path", "text").await?;
	add_column_if_missing(&mut tx, "site_docs", "published_file_id", "text").await?;
	add_column_if_missing(&mut tx, "site_docs", "previous_file_id", "text").await?;
	add_column_if_missing(&mut tx, "site_docs", "previous_mount_path", "text").await?;
	add_column_if_missing(&mut tx, "site_docs", "published_at", "INTEGER").await?;

	// The index below is unconditional and runs inside `init_db`'s single transaction for
	// existing databases too, and nothing enforced uniqueness before it existed. One
	// duplicate `(tn_id, mount_path)` anywhere on the node fails the statement, rolls the
	// transaction back and leaves the process unbootable for *every* tenant. So the losers
	// go first.
	//
	// Mirrors `cloudillo_types::site::published_path_drifted`, the one definition of the
	// tie-break, so the database and the live mount table cannot disagree about which row
	// stays: the row whose published path still equals its configured one, then the lowest
	// `doc_file_id`. (`IS NOT` rather than `<>` because an unpublished row's
	// `published_mount_path` is NULL, and NULL has to lose.) Loud, never silent — a removed
	// row is a document that stops serving.
	let shadowed = sqlx::query(
		"SELECT d.tn_id, d.doc_file_id, d.mount_path FROM site_docs d WHERE EXISTS ( \
			SELECT 1 FROM site_docs x \
			 WHERE x.tn_id = d.tn_id AND x.mount_path = d.mount_path \
			   AND x.doc_file_id <> d.doc_file_id \
			   AND ((x.published_mount_path IS NOT x.mount_path) \
					  < (d.published_mount_path IS NOT d.mount_path) \
				 OR ((x.published_mount_path IS NOT x.mount_path) \
					  = (d.published_mount_path IS NOT d.mount_path) \
					 AND x.doc_file_id < d.doc_file_id)))",
	)
	.fetch_all(&mut *tx)
	.await?;
	for row in &shadowed {
		let tn_id: i64 = row.get("tn_id");
		let doc_file_id: String = row.get("doc_file_id");
		let mount_path: String = row.get("mount_path");
		warn!(
			tn_id,
			%doc_file_id,
			%mount_path,
			"Two documents share one site mount path; removing the shadowed row"
		);
		sqlx::query("DELETE FROM site_docs WHERE tn_id=? AND doc_file_id=?")
			.bind(tn_id)
			.bind(&doc_file_id)
			.execute(&mut *tx)
			.await?;
	}

	sqlx::query(
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_site_docs_mount ON site_docs(tn_id, mount_path)",
	)
	.execute(&mut *tx)
	.await?;

	// The `updated_at` columns default to `unixepoch()`, so an insert-time trigger
	// only rewrites what the default just wrote — and its `UPDATE` then fires the
	// trigger below. Dropped here rather than in a versioned migration because the
	// statement is idempotent and these triggers only ever existed in unreleased
	// development databases.
	sqlx::query("DROP TRIGGER IF EXISTS sites_insert_at").execute(&mut *tx).await?;
	sqlx::query("DROP TRIGGER IF EXISTS entries_insert_at")
		.execute(&mut *tx)
		.await?;
	sqlx::query("DROP TRIGGER IF EXISTS site_docs_insert_at")
		.execute(&mut *tx)
		.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS sites_updated_at AFTER UPDATE ON sites FOR EACH ROW \
		BEGIN UPDATE sites SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS site_docs_updated_at AFTER UPDATE ON site_docs FOR EACH ROW \
		BEGIN UPDATE site_docs SET updated_at = unixepoch() \
		WHERE tn_id = NEW.tn_id AND doc_file_id = NEW.doc_file_id; END",
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
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_profiles_follower \
			 ON profiles(tn_id, id_tag) WHERE follower = 1",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_actions_sub_level \
			 ON actions(tn_id, sub_level) WHERE sub_level IS NOT NULL",
		)
		.execute(&mut *tx)
		.await?;
		// Backs the home feed's received_at ordering + keyset cursor (migration 36).
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_actions_received ON actions(tn_id, received_at, a_id)",
		)
		.execute(&mut *tx)
		.await?;
		// Channel-scoped feed pages, same ordering as idx_actions_received (migration 55).
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_actions_channel_received \
			 ON actions(tn_id, channel, received_at, a_id) WHERE channel IS NOT NULL",
		)
		.execute(&mut *tx)
		.await?;

		set_db_version(&mut tx, CURRENT_DB_VERSION).await;
		version = CURRENT_DB_VERSION;
	}

	// Whether `files` still carries the pre-v58 placement columns. Migrations that write
	// those columns run only then: a replay over the current schema (a test that rewinds
	// `db_version`) must not touch columns that now live on `entries`.
	let legacy_files: bool = sqlx::query_scalar::<_, i64>(
		"SELECT COUNT(*) FROM pragma_table_info('files') WHERE name = 'parent_id'",
	)
	.fetch_one(&mut *tx)
	.await? > 0;

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

	// Version 4: Folder hierarchy
	// (collections table also created here historically; dropped in v24)
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

	// Version 24: Drop unused collections table
	// The table was created in v4 but never wired up to any feature code.
	// DROP TABLE drops the associated indexes and triggers automatically.
	if version < 24 {
		sqlx::query("DROP TABLE IF EXISTS collections").execute(&mut *tx).await?;

		set_db_version(&mut tx, 24).await;
	}

	// Version 25: migrate actions.visibility NULL → 'D'.
	// Storage now uses 'D' for Direct uniformly; ActionView still maps 'D'
	// back to None at the SQL adapter boundary, so the wire/token format
	// is unchanged. NOT NULL is enforced for fresh DBs (CREATE TABLE) and
	// upheld by write-path discipline on existing DBs.
	if version < 25 {
		sqlx::query("UPDATE actions SET visibility = 'D' WHERE visibility IS NULL")
			.execute(&mut *tx)
			.await?;

		set_db_version(&mut tx, 25).await;
	}

	// Version 26: rename `federation.auto_approve` → `profile.auto_approve_actions`.
	// The new key has the same shape (Bool, scope Tenant, default false), so we
	// copy values forward before deleting the old rows. INSERT OR IGNORE keeps
	// any existing new-key value if both happen to be set.
	if version < 26 {
		sqlx::query(
			"INSERT OR IGNORE INTO settings (tn_id, name, value)
			 SELECT tn_id, 'profile.auto_approve_actions', value
			 FROM settings
			 WHERE name = 'federation.auto_approve'",
		)
		.execute(&mut *tx)
		.await?;

		sqlx::query("DELETE FROM settings WHERE name = 'federation.auto_approve'")
			.execute(&mut *tx)
			.await?;

		set_db_version(&mut tx, 26).await;
	}

	// Version 27: migrate legacy hidden=1 files into the managed folder so the
	// file GC can reap them. Only files with parent_id IS NULL are moved —
	// files already nested under a real folder or under __trash__ are left
	// alone to preserve user-visible structure.
	if version < 27 {
		sqlx::query(
			"UPDATE files SET parent_id = ?, hidden = 0
			  WHERE hidden = 1 AND parent_id IS NULL",
		)
		.bind(cloudillo_types::meta_adapter::MANAGED_PARENT_ID)
		.execute(&mut *tx)
		.await?;

		set_db_version(&mut tx, 27).await;
	}

	// Version 28: Hand (cross-context file refs) tombstone columns. Cross-tenant
	// rows whose source has been deleted or had access revoked are flagged here by
	// the refresh endpoint (`POST /api/files/{id}/refresh`); UI renders them as
	// tombstones.
	if version < 28 {
		sqlx::query("ALTER TABLE files ADD COLUMN broken_at INTEGER")
			.execute(&mut *tx)
			.await?;
		sqlx::query("ALTER TABLE files ADD COLUMN broken_reason TEXT")
			.execute(&mut *tx)
			.await?;

		set_db_version(&mut tx, 28).await;
	}

	// Version 29: per-user persisted access_level for cross-context rows. Written
	// by `POST /api/files/{id}/refresh` (and FSHR on_accept on the receiver side)
	// so subsequent list queries can return the source-reported access without
	// re-running the FSHR-fallback path in `get_access_level`.
	if version < 29 {
		sqlx::query("ALTER TABLE file_user_data ADD COLUMN access_level CHAR(1)")
			.execute(&mut *tx)
			.await?;

		set_db_version(&mut tx, 29).await;
	}

	// Version 30: backfill file_user_data.access_level from receiver-side FSHR
	// actions. v29 added the column but pre-existing accepted shares — created
	// before FSHR on_accept learned to seed — would have a NULL access_level
	// until the user manually refreshed each file. This migration matches each
	// receiver tenant's accepted FSHR action (audience = tenant id_tag, status
	// 'A', non-DEL) to its created file row and writes the cached perm char.
	// One-shot — runtime writes still funnel through `update_file_user_data` /
	// `refresh_file`, which take precedence on next reconciliation.
	//
	// Within each (tn_id, audience, subject) we keep the LATEST action —
	// ORDER BY created_at DESC, a_id DESC — so a recipient with multiple
	// accepted FSHRs for the same file (e.g. an initial READ later upgraded
	// to WRITE, or vice versa) gets the most recent grant. A plain JOIN
	// without ordering would pick an arbitrary row, potentially downgrading
	// a real grant.
	if version < 30 {
		sqlx::query(
			"INSERT INTO file_user_data (tn_id, id_tag, f_id, access_level, created_at, updated_at)
			 SELECT t.tn_id, t.id_tag, f.f_id,
			        CASE WHEN latest.sub_type = 'WRITE' THEN 'W'
			             WHEN latest.sub_type = 'COMMENT' THEN 'C'
			             ELSE 'R' END,
			        unixepoch(), unixepoch()
			 FROM (
			     SELECT a.tn_id, a.audience, a.subject, a.sub_type,
			            ROW_NUMBER() OVER (
			                PARTITION BY a.tn_id, a.audience, a.subject
			                ORDER BY a.created_at DESC, a.a_id DESC
			            ) AS rn
			     FROM actions a
			     WHERE a.type = 'FSHR'
			       AND a.subject IS NOT NULL
			       AND a.audience IS NOT NULL
			       AND (a.sub_type IS NULL OR a.sub_type != 'DEL')
			       AND (a.status IS NULL OR a.status = 'A')
			 ) latest
			 INNER JOIN tenants t ON latest.tn_id = t.tn_id AND latest.audience = t.id_tag
			 INNER JOIN files f ON f.tn_id = t.tn_id AND f.file_id = latest.subject
			 WHERE latest.rn = 1
			 ON CONFLICT (tn_id, id_tag, f_id) DO UPDATE SET
			    access_level = excluded.access_level,
			    updated_at = unixepoch()",
		)
		.execute(&mut *tx)
		.await?;

		set_db_version(&mut tx, 30).await;
	}

	if version < 31 {
		// ProfileStatus::Trusted removed; collapse legacy 'T' rows into
		// Active. Active is stored as NULL by convention (see parse_status).
		sqlx::query("UPDATE profiles SET status = NULL WHERE status = 'T'")
			.execute(&mut *tx)
			.await?;
		set_db_version(&mut tx, 31).await;
	}

	// Version 32: per-subject STAT watermark. Receivers gate inbound STAT
	// mirror updates on `created_at > stat_at` so a delayed/out-of-order
	// STAT cannot overwrite fresher counts already applied via direct REACT
	// or CMNT federation events. Existing rows start NULL — the first
	// inbound STAT after deployment accepts unconditionally.
	if version < 32 {
		sqlx::query("ALTER TABLE actions ADD COLUMN stat_at INTEGER")
			.execute(&mut *tx)
			.await?;
		set_db_version(&mut tx, 32).await;
	}

	if version < 33 {
		sqlx::query("ALTER TABLE actions ADD COLUMN reposts integer")
			.execute(&mut *tx)
			.await?;
		set_db_version(&mut tx, 33).await;
	}

	if version < 34 {
		sqlx::query("ALTER TABLE profiles ADD COLUMN follower boolean")
			.execute(&mut *tx)
			.await?;
		// Backfill the directional follower set from existing relationship actions.
		// A profile P (row keyed by P.id_tag) follows the local tenant iff P issued
		// an active FLLW to us, OR P is a *person* who issued an active CONN to us
		// (connection-implied follow is persons-only; communities are followed,
		// never follow). Mirrors the new hook rules so existing followers keep
		// receiving broadcasts after upgrade.
		sqlx::query(
			"UPDATE profiles SET follower = 1 \
			 WHERE EXISTS ( \
			     SELECT 1 FROM actions a \
			     WHERE a.tn_id = profiles.tn_id \
			       AND a.issuer_tag = profiles.id_tag \
			       AND a.status = 'A' \
			       AND (a.sub_type IS NULL OR a.sub_type != 'DEL') \
			       AND ( a.type = 'FLLW' \
			             OR (a.type = 'CONN' AND profiles.type = 'P') ) \
			 )",
		)
		.execute(&mut *tx)
		.await?;
		set_db_version(&mut tx, 34).await;
	}

	if version < 35 {
		// Partial index backing `list_follower_tags` (SELECT id_tag WHERE
		// tn_id=? AND follower=1), run on every broadcast. Without it the engine
		// range-scans all of the tenant's profiles via idx_profiles_tnid_idtag.
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_profiles_follower \
			 ON profiles(tn_id, id_tag) WHERE follower = 1",
		)
		.execute(&mut *tx)
		.await?;
		set_db_version(&mut tx, 35).await;
	}

	if version < 36 {
		// Unreleased "notifications, activity & content-availability" feature.
		// Idempotent: safe to re-run on a dev DB rolled back to db_version 35.
		// Comment stats split into: comments = live count (STAT `c`),
		// comments_ts = last-comment timestamp (STAT `ct`), comments_read_at =
		// reader watermark; legacy comments_read dropped.

		// --- new columns (all idempotent) ---
		add_column_if_missing(&mut tx, "profiles", "feed_read_at", "INTEGER").await?;
		add_column_if_missing(&mut tx, "profiles", "msg_read_at", "INTEGER").await?;
		add_column_if_missing(&mut tx, "profiles", "hidden_in_home", "INTEGER").await?;
		add_column_if_missing(&mut tx, "actions", "sub_level", "CHAR(1)").await?;
		add_column_if_missing(&mut tx, "actions", "comments_ts", "INTEGER").await?;
		add_column_if_missing(&mut tx, "actions", "comments_read_at", "INTEGER").await?;
		// No DEFAULT on the ALTER: SQLite rejects a non-constant default when adding
		// a column to a populated table. The INSERT path stamps received_at instead.
		add_column_if_missing(&mut tx, "actions", "received_at", "INTEGER").await?;
		add_column_if_missing(&mut tx, "tenants", "last_seen_at", "INTEGER").await?;
		add_column_if_missing(&mut tx, "tenants", "notify_email_direct_at", "INTEGER").await?;
		add_column_if_missing(&mut tx, "tenants", "notify_email_engagement_at", "INTEGER").await?;
		add_column_if_missing(&mut tx, "tenants", "notify_email_social_at", "INTEGER").await?;

		// --- indexes (also present in the base schema for fresh DBs) ---
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_actions_sub_level \
			 ON actions(tn_id, sub_level) WHERE sub_level IS NOT NULL",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_actions_parent_created ON actions(tn_id, parent_id, created_at)",
		)
		.execute(&mut *tx)
		.await?;
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_actions_received ON actions(tn_id, received_at, a_id)",
		)
		.execute(&mut *tx)
		.await?;

		// --- backfills / recompute ---
		// home feed sorts by local arrival; existing rows approximate with created_at.
		sqlx::query("UPDATE actions SET received_at = created_at WHERE received_at IS NULL")
			.execute(&mut *tx)
			.await?;
		// Seed the reader watermark for already-commented posts so they start "read"
		// (no unread-dot storm). Must run BEFORE the recompute. The IS NULL guard
		// makes a rolled-back re-run non-destructive to existing watermarks.
		sqlx::query(
			"UPDATE actions SET comments_read_at = unixepoch() \
			 WHERE comments_read_at IS NULL AND comments IS NOT NULL AND comments > 0",
		)
		.execute(&mut *tx)
		.await?;
		// Recompute count + timestamp from the live child CMNT rows. The EXISTS
		// predicate is robust regardless of what `comments` previously held (a stale
		// timestamp from a buggy dev build, or a real count): only rows with child
		// CMNTs are touched, and DEL/inactive children are excluded from both
		// aggregates.
		sqlx::query(
			"UPDATE actions SET
				comments = (
					SELECT COUNT(*) FROM actions c
					WHERE c.tn_id = actions.tn_id AND c.parent_id = actions.action_id
						AND c.type = 'CMNT' AND coalesce(c.sub_type,'') != 'DEL'
						AND coalesce(c.status,'A') = 'A'
				),
				comments_ts = (
					SELECT MAX(c.created_at) FROM actions c
					WHERE c.tn_id = actions.tn_id AND c.parent_id = actions.action_id
						AND c.type = 'CMNT' AND coalesce(c.sub_type,'') != 'DEL'
						AND coalesce(c.status,'A') = 'A'
				)
			WHERE EXISTS (
				SELECT 1 FROM actions c
				WHERE c.tn_id = actions.tn_id AND c.parent_id = actions.action_id
					AND c.type = 'CMNT'
			)",
		)
		.execute(&mut *tx)
		.await?;

		// Drop the obsolete legacy count column (reader-local, never federated).
		drop_column_if_exists(&mut tx, "actions", "comments_read").await?;

		set_db_version(&mut tx, 36).await;
	}

	if version < 37 {
		// Profile and cover pictures must be Public so guest-mode views can fetch
		// avatars without a token. Rows synced before the sync path started passing
		// Some('P') are stuck at 'D' (Direct), and that path never rewrites visibility
		// on an existing row, so only this migration can repair them. The `<> 'P'`
		// guard makes it idempotent, and it only ever loosens.
		// `updated_at` is stamped by the `files_updated_at` AFTER UPDATE trigger.
		if legacy_files {
			sqlx::query(
				"UPDATE files SET visibility = 'P' \
				 WHERE (visibility IS NULL OR visibility <> 'P') \
				   AND EXISTS (SELECT 1 FROM profiles p \
				               WHERE p.tn_id = files.tn_id AND p.profile_pic = files.file_id)",
			)
			.execute(&mut *tx)
			.await?;
			sqlx::query(
				"UPDATE files SET visibility = 'P' \
				 WHERE (visibility IS NULL OR visibility <> 'P') \
				   AND EXISTS (SELECT 1 FROM tenants t \
				               WHERE t.tn_id = files.tn_id \
				                 AND files.file_id IN (t.profile_pic, t.cover_pic))",
			)
			.execute(&mut *tx)
			.await?;
		}
		set_db_version(&mut tx, 37).await;
	}

	if version < 38 {
		// Full-text search: `doc_formats`, `search_docs`, both FTS5 virtual tables
		// and the three mirror triggers are all created by the `IF NOT EXISTS`
		// descriptor statements above, in their final shape — `SEARCH_FTS_DDL`,
		// `SEARCH_FTS_CL_DDL` and `SEARCH_FTS_TRIGGERS` already carry the `tn_id`
		// column, and `search_docs` already carries `fts_cl` and `obj_hash`. A
		// database below this version has no search tables at all, so there is
		// nothing to alter and this block only stamps the version.
		//
		// Backfilling existing files/actions/profiles is the `search-reindex`
		// scheduler task's job — keeping it out of the startup transaction.
		set_db_version(&mut tx, 38).await;
	}

	if version < 39 {
		// `doc_formats.version` held the registering app's release version as free
		// text: it bumped on unrelated releases, never when the index rules were
		// edited, and nothing compared two of them. Replaced by `format_version`,
		// the integer `MMMmmmppp` encoding of a *document format* version, which
		// `format::gate` orders registrations by.
		//
		// The old TEXT values are dropped rather than parsed: an app version is not
		// a document format version, so translating `'0.8.17'` would fabricate an
		// ordering. The gate reads NULL as "no ordering known". Nothing else ever
		// read this column, `doc_formats` has no index on it, and its triggers
		// reference only `tn_id`/`content_type`, so the DROP is safe.
		//
		// INTEGER, not TEXT: SQLite's TEXT affinity would coerce a bound i64 back to
		// text, and `doc_format::map_row` reads it with the panicking accessor.
		add_column_if_missing(&mut tx, "doc_formats", "format_version", "INTEGER").await?;
		drop_column_if_exists(&mut tx, "doc_formats", "version").await?;
		set_db_version(&mut tx, 39).await;
	}

	if version < 40 {
		// `idx_search_docs_obj (tn_id, obj_tp, obj_id)` was a strict left-prefix of
		// the UNIQUE `idx_search_docs_key (tn_id, obj_tp, obj_id, part_id)`, so the
		// planner could never choose it and it only cost a second b-tree write per
		// insert and delete.
		sqlx::query("DROP INDEX IF EXISTS idx_search_docs_obj")
			.execute(&mut *tx)
			.await?;
		set_db_version(&mut tx, 40).await;
	}

	if version < 47 {
		// `sites`, `site_docs`, the UNIQUE (tn_id, mount_path) index and both updated_at
		// trigger pairs are created by the `IF NOT EXISTS` descriptor statements above, in
		// their final shape — that block is unconditional and runs for existing databases too.
		//
		// 41..46 are skipped rather than absent: the site tables were built up over those six
		// steps, under the names `site`/`site_doc`, in unreleased development builds that
		// never reached a commit. The steps are gone and the numbers stay burnt.
		//
		// Nothing is left for this block but the stamp: the descriptor block above adds each
		// site column explicitly, because it reads them itself and runs ahead of every
		// migration, so nothing here has to assume a sub-47 database lacks the site tables.
		set_db_version(&mut tx, 47).await;
	}

	if version < 48 {
		// Rollback swaps the two container generations, and the mount path has to travel
		// with them: a row repathed, republished and then rolled back would otherwise name
		// the new prefix while serving a container built for the old one, and
		// `cache::mounts_from_docs` keys the live mount table on exactly that column.
		//
		// The descriptor block above carries the column for a fresh database, but
		// `CREATE TABLE IF NOT EXISTS` cannot add one to an existing table — hence the
		// ALTER. Older rows keep a NULL, which `rollback_doc` reads as "no path to restore".
		add_column_if_missing(&mut tx, "site_docs", "previous_mount_path", "text").await?;
		set_db_version(&mut tx, 48).await;
	}

	if version < 52 {
		// Ownership model cleanup: the two owner-ish columns held the inverse of what their
		// names said. `owner_tag` carried the *upstream* node (set only on cross-context
		// rows) and `creator_tag` carried the profile with owner authority. Migration 9
		// already put the right values in the right columns, so this is a pure rename —
		// no data movement. The order matters: the second rename's target collides with the
		// first's source, so `owner_tag` must vacate the name before `creator_tag` takes it.
		//
		// Guarded: unlike an additive ALTER, a RENAME is not replayable. A database whose
		// `db_version` was rewound over an already-renamed schema would otherwise hit
		// `duplicate column name: upstream_tag`. Keyed on `creator_tag`, which only a
		// pre-52 table has: `upstream_tag` has since moved to `entries` (v58).
		let legacy: i64 = sqlx::query_scalar(
			"SELECT COUNT(*) FROM pragma_table_info('files') WHERE name = 'creator_tag'",
		)
		.fetch_one(&mut *tx)
		.await?;
		if legacy > 0 {
			sqlx::query("ALTER TABLE files RENAME COLUMN owner_tag TO upstream_tag")
				.execute(&mut *tx)
				.await?;
			sqlx::query("ALTER TABLE files RENAME COLUMN creator_tag TO owner_tag")
				.execute(&mut *tx)
				.await?;
		}

		// `profile_settings` needs nothing here: it is a brand-new table, so the
		// unconditional `IF NOT EXISTS` descriptor block above already created it for
		// existing databases too.

		// `helpers::get_subscription_role` no longer falls back to `content.role` — that is
		// the action token's issuer-signed `c` claim, so a remote subscriber could name its
		// own role. Rows written before `x.role` existed carry the role only in `content`,
		// and without this backfill their holders silently drop to `Member`, losing
		// CONV:UPD, SUBS:DEL and INVT on conversations they administer.
		//
		// Self-issued rows only (`issuer_tag` == the tenant's own id_tag). That is exactly
		// the boundary the removal exists to draw: a *federated* SUBS's `content.role` was
		// written by the very party whose role it decides, and inbound processing strips
		// `x` (`process.rs`), so those rows must stay at the `Member` default. The CONV
		// creator's auto-SUBS (`native_hooks/conv.rs`) and the INVT-accept SUBS
		// (`native_hooks/invt.rs`) are both locally issued and so are reached.
		//
		// `json_valid` guards both extracts: `json_extract` raises on malformed JSON, which
		// would abort the whole migration transaction over one bad row.
		// A present `x.role` always wins — this only fills a missing one.
		sqlx::query(
			"UPDATE actions SET x = json_set(COALESCE(x, '{}'), '$.role', \
			   json_extract(content, '$.role')) \
			 WHERE type = 'SUBS' \
			   AND content IS NOT NULL AND json_valid(content) \
			   AND json_extract(content, '$.role') IN \
			       ('observer', 'member', 'moderator', 'admin') \
			   AND (x IS NULL OR json_valid(x)) \
			   AND json_extract(COALESCE(x, '{}'), '$.role') IS NULL \
			   AND lower(issuer_tag) = (SELECT lower(t.id_tag) FROM tenants t \
			                            WHERE t.tn_id = actions.tn_id)",
		)
		.execute(&mut *tx)
		.await?;

		// Belt and braces: `profile_settings_insert_at` exists nowhere in this tree, but a dev
		// database from an intermediate working state may still carry it. It only rewrote
		// `updated_at` to the value the column default had just set, and never fired on the
		// upsert path at all — SQLite runs UPDATE triggers, not INSERT triggers, for
		// `ON CONFLICT ... DO UPDATE`, which is how `setting::update_profile` writes.
		sqlx::query("DROP TRIGGER IF EXISTS profile_settings_insert_at")
			.execute(&mut *tx)
			.await?;
		set_db_version(&mut tx, 52).await;
	}

	if version < 53 {
		// `search_docs.owner_tag` never held an owner. The indexer fills it from the raw
		// `files.upstream_tag` (and from `p.id_tag` / `a.issuer_tag` for the other object
		// types), so after migration 52 renamed the `files` columns the search column was the
		// one carrying the *old* meaning of the name — `/api/search`'s `ownerTag` and
		// `/api/files`' `owner` would have named two different profiles for the same row.
		//
		// Guarded the same way as 52's rename: a RENAME is not replayable, so a database
		// whose `db_version` was rewound over an already-renamed schema must not hit
		// `duplicate column name`.
		let renamed: i64 = sqlx::query_scalar(
			"SELECT COUNT(*) FROM pragma_table_info('search_docs') WHERE name = 'upstream_tag'",
		)
		.fetch_one(&mut *tx)
		.await?;
		if renamed == 0 {
			sqlx::query("ALTER TABLE search_docs RENAME COLUMN owner_tag TO upstream_tag")
				.execute(&mut *tx)
				.await?;
		}
		set_db_version(&mut tx, 53).await;
	}

	if version < 54 {
		// Inter-community hats: per-peer role maps and the hat an action was signed under.
		add_column_if_missing(&mut tx, "profiles", "hat_roles", "text").await?;
		add_column_if_missing(&mut tx, "profiles", "peer_hat_roles", "text").await?;
		add_column_if_missing(&mut tx, "actions", "hat_tag", "text").await?;
		set_db_version(&mut tx, 54).await;
	}

	if version < 55 {
		// Channels: the channels/channel_members tables are created above; entities get a
		// `channel` column (NULL = open floor, no backfill).
		add_column_if_missing(&mut tx, "actions", "channel", "text").await?;
		if legacy_files {
			add_column_if_missing(&mut tx, "files", "channel", "text").await?;
		}
		add_column_if_missing(&mut tx, "search_docs", "channel", "text").await?;
		sqlx::query(
			"CREATE INDEX IF NOT EXISTS idx_actions_channel_received \
			 ON actions(tn_id, channel, received_at, a_id) WHERE channel IS NOT NULL",
		)
		.execute(&mut *tx)
		.await?;
		set_db_version(&mut tx, 55).await;
	}

	if version < 56 {
		// Non-blob files are created final, but `post_file` / `duplicate_file` used to leave
		// them at the 'P' default that only blob finalization clears. Any client-supplied
		// `file_tp` counts; NULL stays pending, since `create_file` reads a missing type as BLOB.
		if legacy_files {
			sqlx::query("UPDATE files SET status='A' WHERE status='P' AND file_tp<>'BLOB'")
				.execute(&mut *tx)
				.await?;
		}
		set_db_version(&mut tx, 56).await;
	}

	if version < 57 {
		// Hats: the viewer's remembered identities at a peer, as a JSON array.
		add_column_if_missing(&mut tx, "profiles", "hats", "text").await?;
		set_db_version(&mut tx, 57).await;
	}

	if version < 58 || legacy_files {
		// Also runs while `files` still has the placement columns: repairs a DB stamped v58 by
		// a pre-split dev build. Every step is idempotent.
		// Storage split: `files` keeps content, `entries` takes placement. 1:1 — every row
		// becomes one entry, and every non-folder row keeps its `files` row. `e_id` = old
		// `f_id`, so `file_user_data` rekeys by a column rename. Folders keep their old
		// `file_id` as `entry_id`, so every `parent_id` stays valid unchanged; content entries
		// get a fresh `random_id()`. Guarded like 52: replaying over the split schema is a no-op.
		// A pending upload deduped at finalize redirects its `@<f_id>` to the surviving content.
		add_column_if_missing(&mut tx, "files", "merged_into", "integer").await?;
		if legacy_files {
			migrate_v58_entries(&mut tx).await?;
		}
		// Search rows gate on the live `entries` / `actions` placement, never on a mirror.
		drop_column_if_exists(&mut tx, "search_docs", "visibility").await?;
		drop_column_if_exists(&mut tx, "search_docs", "channel").await?;
		set_db_version(&mut tx, 58).await;
	}

	// Unversioned and idempotent: a DB that reached v58 on a pre-rename build still has
	// `f_id`. e_id = old f_id, so the rename is the whole rekey; SQLite rewrites the PK and
	// the `file_user_data_*_at` trigger bodies along with it.
	let fud_legacy: i64 = sqlx::query_scalar(
		"SELECT COUNT(*) FROM pragma_table_info('file_user_data') WHERE name = 'f_id'",
	)
	.fetch_one(&mut *tx)
	.await?;
	if fud_legacy > 0 {
		sqlx::query("ALTER TABLE file_user_data RENAME COLUMN f_id TO e_id")
			.execute(&mut *tx)
			.await?;
	}

	tx.commit().await?;

	Ok(())
}

#[cfg(test)]
mod tests {
	use sqlx::sqlite::SqlitePoolOptions;

	// A DB stamped v58 by a build that split `files` but kept `file_user_data.f_id`.
	#[tokio::test]
	async fn fud_f_id_renamed_on_already_v58_db() {
		let db = SqlitePoolOptions::new()
			.max_connections(1)
			.connect("sqlite::memory:")
			.await
			.expect("connect");
		super::init_db(&db).await.expect("init");
		for sql in [
			"ALTER TABLE file_user_data RENAME COLUMN e_id TO f_id",
			"INSERT INTO file_user_data (tn_id, id_tag, f_id, starred) VALUES (1, 'bob', 7, 1)",
		] {
			sqlx::query(sql).execute(&db).await.expect("seed");
		}
		super::init_db(&db).await.expect("re-init");
		let ids: Vec<i64> = sqlx::query_scalar("SELECT e_id FROM file_user_data")
			.fetch_all(&db)
			.await
			.expect("e_id");
		assert_eq!(ids, vec![7]);
	}

	// Turns a freshly initialized `files` back into its pre-v58 shape.
	async fn add_legacy_files_columns(db: &sqlx::SqlitePool) {
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
			sqlx::query(sqlx::AssertSqlSafe(format!("ALTER TABLE files ADD COLUMN {col}")))
				.execute(db)
				.await
				.expect("legacy column");
		}
		// The legacy schema's `files` triggers would overwrite the seeded `updated_at`.
		for sql in ["DROP TRIGGER files_insert_at", "DROP TRIGGER files_updated_at"] {
			sqlx::query(sql).execute(db).await.expect("drop trigger");
		}
	}

	// A DB stamped v58 by a pre-split build: `files` still holds placement, `entries` is empty.
	#[tokio::test]
	async fn split_runs_on_v58_db_with_legacy_files() {
		let db = SqlitePoolOptions::new()
			.max_connections(1)
			.connect("sqlite::memory:")
			.await
			.expect("connect");
		super::init_db(&db).await.expect("init");
		add_legacy_files_columns(&db).await;
		sqlx::query(
			"INSERT INTO files (f_id, tn_id, file_id, file_tp, status, parent_id) \
			 VALUES (1, 1, 'f1~abc', 'BLOB', 'A', NULL), (2, 1, 'fold1', 'FLDR', 'A', NULL)",
		)
		.execute(&db)
		.await
		.expect("seed");
		super::init_db(&db).await.expect("re-init");
		let entries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entries")
			.fetch_one(&db)
			.await
			.expect("entries");
		assert_eq!(entries, 2);
		let files: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM files WHERE f_id = 1")
			.fetch_one(&db)
			.await
			.expect("files");
		assert_eq!(files, 1);
		let legacy: i64 = sqlx::query_scalar(
			"SELECT COUNT(*) FROM pragma_table_info('files') WHERE name = 'parent_id'",
		)
		.fetch_one(&db)
		.await
		.expect("pragma");
		assert_eq!(legacy, 0);
	}

	// v57 shape: share_entries and `share.file` refs name a file by its content `file_id`.
	// After v58 a file's links name its new entry; a folder's keep their id (= its entry_id).
	#[tokio::test]
	async fn v58_rewrites_file_shares_and_links_to_entry_ids() {
		let db = SqlitePoolOptions::new()
			.max_connections(1)
			.connect("sqlite::memory:")
			.await
			.expect("connect");
		super::init_db(&db).await.expect("init");
		add_legacy_files_columns(&db).await;
		for sql in [
			"INSERT INTO files (f_id, tn_id, file_id, file_tp, status, x, parent_id, updated_at) \
			 VALUES (1, 1, 'f1~abc', 'BLOB', 'A', '{\"dim\":[4,3]}', 'fold1', 1000), \
			 (2, 1, 'fold1', 'FLDR', 'A', NULL, NULL, 1000)",
			"INSERT INTO file_user_data (tn_id, id_tag, e_id, starred) \
			 VALUES (1, 'bob', 1, 1), (1, 'bob', 2, 1)",
			"INSERT INTO share_entries (tn_id, resource_type, resource_id, subject_type, \
			 subject_id, permission, created_by) \
			 VALUES (1, 'F', 'f1~abc', 'U', 'bob', 'R', 'me'), \
			 (1, 'F', 'fold1', 'U', 'bob', 'R', 'me')",
			"INSERT INTO refs (tn_id, ref_id, type, resource_id) \
			 VALUES (1, 'r1', 'share.file', 'f1~abc'), (1, 'r2', 'share.file', 'fold1')",
		] {
			sqlx::query(sql).execute(&db).await.expect("seed");
		}

		let mut tx = db.begin().await.expect("tx");
		super::migrate_v58_entries(&mut tx).await.expect("migrate");
		tx.commit().await.expect("commit");

		let file_entry: String = sqlx::query_scalar("SELECT entry_id FROM entries WHERE f_id = 1")
			.fetch_one(&db)
			.await
			.expect("file entry");
		assert_ne!(file_entry, "f1~abc");
		for (table, col) in [("share_entries", "id"), ("refs", "ref_id")] {
			let ids: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
				"SELECT resource_id FROM {table} ORDER BY {col}"
			)))
			.fetch_all(&db)
			.await
			.expect("ids");
			assert_eq!(ids, [file_entry.clone(), "fold1".to_string()], "{table}");
		}
		let parent: Option<String> =
			sqlx::query_scalar("SELECT parent_id FROM entries WHERE entry_id = ?")
				.bind(&file_entry)
				.fetch_one(&db)
				.await
				.expect("parent");
		assert_eq!(parent.as_deref(), Some("fold1"), "parent link survives");
		let starred: Vec<String> = sqlx::query_scalar(
			"SELECT e.entry_id FROM file_user_data u JOIN entries e ON e.e_id = u.e_id \
			 WHERE u.id_tag = 'bob' AND u.starred = 1 ORDER BY e.e_id",
		)
		.fetch_all(&db)
		.await
		.expect("stars");
		assert_eq!(starred, [file_entry.clone(), "fold1".to_string()], "stars follow the entry");
		let x: Option<String> = sqlx::query_scalar("SELECT x FROM files WHERE f_id = 1")
			.fetch_one(&db)
			.await
			.expect("x stays on files");
		assert_eq!(x.as_deref(), Some("{\"dim\":[4,3]}"));
		let stamps: Vec<i64> = sqlx::query_scalar("SELECT updated_at FROM entries ORDER BY e_id")
			.fetch_all(&db)
			.await
			.expect("updated_at");
		assert_eq!(stamps, [1000, 1000], "the migration keeps each entry's updated_at");
	}

	// Legacy managed attachment rows get the latest live action naming them (by id or `@<f_id>`);
	// one only a deleted action names stays unowned, for the file GC.
	#[tokio::test]
	async fn v58_backfills_managed_entry_action_id() {
		let db = SqlitePoolOptions::new()
			.max_connections(1)
			.connect("sqlite::memory:")
			.await
			.expect("connect");
		super::init_db(&db).await.expect("init");
		add_legacy_files_columns(&db).await;
		for sql in [
			"INSERT INTO files (f_id, tn_id, file_id, file_tp, status, parent_id) \
			 VALUES (1, 1, 'f1~live', 'BLOB', 'A', '__managed__'), \
			 (2, 1, 'f1~dead', 'BLOB', 'A', '__managed__'), \
			 (3, 1, 'f1~draft', 'BLOB', 'A', '__managed__')",
			"INSERT INTO actions (tn_id, action_id, type, issuer_tag, status, attachments) \
			 VALUES (1, 'a1~old', 'POST', 'me', 'A', 'f1~live'), \
			 (1, 'a1~new', 'POST', 'me', 'A', 'f1~live,@3'), \
			 (1, 'a1~gone', 'POST', 'me', 'D', 'f1~dead')",
		] {
			sqlx::query(sql).execute(&db).await.expect("seed");
		}

		let mut tx = db.begin().await.expect("tx");
		super::migrate_v58_entries(&mut tx).await.expect("migrate");
		tx.commit().await.expect("commit");

		// Each live action that names the content owns its own entry.
		let owners: Vec<(i64, Option<String>)> =
			sqlx::query_as("SELECT f_id, action_id FROM entries ORDER BY f_id, action_id")
				.fetch_all(&db)
				.await
				.expect("owners");
		assert_eq!(
			owners,
			[
				(1, Some("a1~new".into())),
				(1, Some("a1~old".into())),
				(2, None),
				(3, Some("a1~new".into())),
			]
		);
	}
}

// vim: ts=4
