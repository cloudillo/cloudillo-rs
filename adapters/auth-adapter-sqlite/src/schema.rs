//! Database schema initialization and migrations

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

// Current schema version - update this when adding new migrations
const CURRENT_DB_VERSION: i64 = 5;

/// Initialize the database schema and run migrations
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

	// Schema creation - safe to run every time (uses IF NOT EXISTS)

	// Tenants
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
			idp_api_key text,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(tn_id)
		)",
	)
	.execute(&mut *tx)
	.await?;

	// Keys
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS keys (
			tn_id integer NOT NULL,
			key_id text NOT NULL,
			status char(1),
			expires_at INTEGER,
			public_key text,
			private_key text,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(tn_id, key_id)
		)",
	)
	.execute(&mut *tx)
	.await?;

	// Certs
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS certs (
			tn_id integer NOT NULL,
			status char(1),
			id_tag text,
			domain text,
			expires_at INTEGER,
			cert text,
			key text,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
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

	// Events
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS events (
			ev_id integer NOT NULL,
			tn_id integer NOT NULL,
			type text NOT NULL,
			ip text,
			data text,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(ev_id)
		)",
	)
	.execute(&mut *tx)
	.await?;

	// User verification
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS user_vfy (
			vfy_code text NOT NULL,
			email text NOT NULL,
			func text NOT NULL,
			id_tag text,
			data text,
			expires_at INTEGER,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(vfy_code)
		)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_user_vfy_email ON user_vfy (email)")
		.execute(&mut *tx)
		.await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_user_vfy_expires ON user_vfy(expires_at)")
		.execute(&mut *tx)
		.await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_user_vfy_email_func ON user_vfy(email, func)")
		.execute(&mut *tx)
		.await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_user_vfy_idtag_func ON user_vfy(id_tag, func)")
		.execute(&mut *tx)
		.await?;

	// WebAuthn
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS webauthn (
			tn_id integer NOT NULL,
			credential_id text NOT NULL,
			counter integer NOT NULL DEFAULT 0,
			public_key text NOT NULL,
			description text,
			created_at INTEGER DEFAULT (unixepoch()),
			updated_at INTEGER DEFAULT (unixepoch()),
			PRIMARY KEY(tn_id, credential_id)
		)",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_webauthn_tn_id ON webauthn (tn_id)")
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
			"CREATE TRIGGER IF NOT EXISTS keys_insert_at AFTER INSERT ON keys FOR EACH ROW \
			BEGIN UPDATE keys SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND key_id = NEW.key_id; END",
		)
		.execute(&mut *tx)
		.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS certs_insert_at AFTER INSERT ON certs FOR EACH ROW \
			BEGIN UPDATE certs SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS events_insert_at AFTER INSERT ON events FOR EACH ROW \
			BEGIN UPDATE events SET updated_at = unixepoch() WHERE ev_id = NEW.ev_id; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS user_vfy_insert_at AFTER INSERT ON user_vfy FOR EACH ROW \
			BEGIN UPDATE user_vfy SET updated_at = unixepoch() WHERE vfy_code = NEW.vfy_code; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
			"CREATE TRIGGER IF NOT EXISTS webauthn_insert_at AFTER INSERT ON webauthn FOR EACH ROW \
			BEGIN UPDATE webauthn SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND credential_id = NEW.credential_id; END",
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
			"CREATE TRIGGER IF NOT EXISTS keys_updated_at AFTER UPDATE ON keys FOR EACH ROW \
			BEGIN UPDATE keys SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND key_id = NEW.key_id; END",
		)
		.execute(&mut *tx)
		.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS certs_updated_at AFTER UPDATE ON certs FOR EACH ROW \
			BEGIN UPDATE certs SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS events_updated_at AFTER UPDATE ON events FOR EACH ROW \
			BEGIN UPDATE events SET updated_at = unixepoch() WHERE ev_id = NEW.ev_id; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS user_vfy_updated_at AFTER UPDATE ON user_vfy FOR EACH ROW \
			BEGIN UPDATE user_vfy SET updated_at = unixepoch() WHERE vfy_code = NEW.vfy_code; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS webauthn_updated_at AFTER UPDATE ON webauthn FOR EACH ROW \
		BEGIN UPDATE webauthn SET updated_at = unixepoch() WHERE tn_id = NEW.tn_id AND credential_id = NEW.credential_id; END",
	)
	.execute(&mut *tx)
	.await?;

	// API Keys table
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS api_keys (
		key_id INTEGER PRIMARY KEY AUTOINCREMENT,
		tn_id INTEGER NOT NULL,
		key_prefix TEXT NOT NULL,
		key_hash TEXT NOT NULL,
		name TEXT,
		scopes TEXT,
		expires_at INTEGER,
		last_used_at INTEGER,
		created_at INTEGER DEFAULT (unixepoch()),
		updated_at INTEGER DEFAULT (unixepoch()),
		FOREIGN KEY (tn_id) REFERENCES tenants(tn_id) ON DELETE CASCADE
	)",
	)
	.execute(&mut *tx)
	.await?;

	// Indexes for api_keys
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_api_keys_tn_id ON api_keys (tn_id)")
		.execute(&mut *tx)
		.await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys (key_prefix)")
		.execute(&mut *tx)
		.await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_api_keys_expires ON api_keys (expires_at)")
		.execute(&mut *tx)
		.await?;

	// Triggers for api_keys
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS api_keys_insert_at AFTER INSERT ON api_keys FOR EACH ROW \
		BEGIN UPDATE api_keys SET updated_at = unixepoch() WHERE key_id = NEW.key_id; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS api_keys_updated_at AFTER UPDATE ON api_keys FOR EACH ROW \
		BEGIN UPDATE api_keys SET updated_at = unixepoch() WHERE key_id = NEW.key_id; END",
	)
	.execute(&mut *tx)
	.await?;

	// Proxy sites table
	sqlx::query(
		"CREATE TABLE IF NOT EXISTS proxy_sites (
		site_id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL,
		backend_url TEXT NOT NULL,
		status CHAR(1) NOT NULL DEFAULT 'A',
		proxy_type TEXT NOT NULL DEFAULT 'basic',
		cert TEXT,
		cert_key TEXT,
		cert_expires_at INTEGER,
		config TEXT,
		created_by INTEGER,
		created_at INTEGER DEFAULT (unixepoch()),
		updated_at INTEGER DEFAULT (unixepoch())
	)",
	)
	.execute(&mut *tx)
	.await?;

	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_sites_domain ON proxy_sites (domain)")
		.execute(&mut *tx)
		.await?;

	// Triggers for proxy_sites
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS proxy_sites_insert_at AFTER INSERT ON proxy_sites FOR EACH ROW \
		BEGIN UPDATE proxy_sites SET updated_at = unixepoch() WHERE site_id = NEW.site_id; END",
	)
	.execute(&mut *tx)
	.await?;
	sqlx::query(
		"CREATE TRIGGER IF NOT EXISTS proxy_sites_updated_at AFTER UPDATE ON proxy_sites FOR EACH ROW \
		BEGIN UPDATE proxy_sites SET updated_at = unixepoch() WHERE site_id = NEW.site_id; END",
	)
	.execute(&mut *tx)
	.await?;

	// Fresh database: skip migrations (schema already has all columns)
	if version == 0 {
		set_db_version(&mut tx, CURRENT_DB_VERSION).await;
		#[allow(unused_assignments)]
		{
			version = CURRENT_DB_VERSION;
		}
	}

	// Migrations for existing databases
	// Version 3: Add proxy_sites table (CREATE TABLE IF NOT EXISTS handles fresh DBs)
	// Note: We skip to version 4 because the CREATE TABLE above already includes
	// the proxy_type column that version 4 would add via ALTER TABLE
	if version > 0 && version < 3 {
		// Table was already created above with IF NOT EXISTS (including proxy_type), just bump version
		set_db_version(&mut tx, 4).await;
		version = 4;
	}

	// Version 4: Add proxy_type column to proxy_sites
	if version == 3 {
		sqlx::query("ALTER TABLE proxy_sites ADD COLUMN proxy_type TEXT NOT NULL DEFAULT 'basic'")
			.execute(&mut *tx)
			.await?;
		set_db_version(&mut tx, 4).await;
		version = 4;
	}

	// Version 5: Remove redundant 'P' (Pending) status from proxy sites
	if version == 4 {
		sqlx::query("UPDATE proxy_sites SET status = 'A' WHERE status = 'P'")
			.execute(&mut *tx)
			.await?;
		set_db_version(&mut tx, 5).await;
		#[allow(unused_assignments)]
		{
			version = 5;
		}
	}

	tx.commit().await?;

	Ok(())
}
