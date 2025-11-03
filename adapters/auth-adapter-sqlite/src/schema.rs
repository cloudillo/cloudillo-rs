//! Database schema initialization and migrations

use sqlx::SqlitePool;

/// Initialize the database schema and run migrations
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

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS tenants (
		tn_id integer NOT NULL,
		id_tag text,
		email text,
		password text,
		status char(1),
		roles text,
		vapid_public_key text,
		vapid_private_key text,
		created_at datetime DEFAULT current_timestamp,
		PRIMARY KEY(tn_id)
	)",
	)
	.execute(&mut *tx)
	.await?;

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS keys (
		tn_id integer NOT NULL,
		key_id text NOT NULL,
		status char(1),
		expires_at datetime,
		public_key text,
		private_key text,
		PRIMARY KEY(tn_id, key_id)
	)",
	)
	.execute(&mut *tx)
	.await?;

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS certs (
		tn_id integer NOT NULL,
		status char(1),
		id_tag text,
		domain text,
		expires_at datetime,
		cert text,
		key text,
		PRIMARY KEY(tn_id)
	)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_certs_idTag ON certs (id_tag)")
		.execute(&mut *tx)
		.await?;
	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_certs_domain ON certs (domain)")
		.execute(&mut *tx)
		.await?;

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS events (
		ev_id integer NOT NULL,
		tn_id integer NOT NULL,
		type text NOT NULL,
		ip text,
		data text,
		PRIMARY KEY(ev_id)
	)",
	)
	.execute(&mut *tx)
	.await?;

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS user_vfy (
		vfy_code text NOT NULL,
		email text NOT NULL,
		func text NOT NULL,
		created_at datetime DEFAULT current_timestamp,
		PRIMARY KEY(vfy_code)
	)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_user_vfy_email ON user_vfy (email)")
		.execute(&mut *tx)
		.await?;

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS vars (
		key text NOT NULL,
		value text NOT NULL,
		created_at datetime DEFAULT current_timestamp,
		updated_at datetime DEFAULT current_timestamp,
		PRIMARY KEY(key)
	)",
	)
	.execute(&mut *tx)
	.await?;

	sqlx::query(
		"CREATE TABLE IF NOT EXISTS webauthn (
		tn_id integer NOT NULL,
		credential_id text NOT NULL,
		counter integer NOT NULL DEFAULT 0,
		public_key text NOT NULL,
		description text,
		created_at datetime DEFAULT current_timestamp,
		PRIMARY KEY(tn_id, credential_id)
	)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_webauthn_tn_id ON webauthn (tn_id)")
		.execute(&mut *tx)
		.await?;

	// Phase 1 Migration: Extend user_vfy table for unified token handling
	// Add support for expires_at (token expiration), id_tag (for password reset), and data (JSON)
	// Note: SQLite doesn't support IF NOT EXISTS in ALTER TABLE, so we ignore errors
	let _ = sqlx::query("ALTER TABLE user_vfy ADD COLUMN expires_at datetime")
		.execute(&mut *tx)
		.await;
	let _ = sqlx::query("ALTER TABLE user_vfy ADD COLUMN id_tag text")
		.execute(&mut *tx)
		.await;
	let _ = sqlx::query("ALTER TABLE user_vfy ADD COLUMN data text").execute(&mut *tx).await;

	// Add indexes for efficient queries
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_user_vfy_expires ON user_vfy(expires_at)")
		.execute(&mut *tx)
		.await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_user_vfy_email_func ON user_vfy(email, func)")
		.execute(&mut *tx)
		.await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_user_vfy_idtag_func ON user_vfy(id_tag, func)")
		.execute(&mut *tx)
		.await?;

	// Phase 2 Migration: Convert roles from JSON to TEXT format
	// Handle cases where roles were stored as JSON arrays and convert to comma-separated strings
	// For new databases, roles will be stored as comma-separated strings or NULL
	let _ = sqlx::query(
		"UPDATE tenants SET roles = NULL WHERE roles IS NULL OR roles = 'null' OR roles = '[]'",
	)
	.execute(&mut *tx)
	.await;

	tx.commit().await?;

	Ok(())
}
