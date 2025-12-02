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

	let version = get_db_version(&mut tx).await;

	if version < 1 {
		// Version 1: Initial schema

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

		set_db_version(&mut tx, 1).await;
	}

	// Future migrations:
	// if version < 2 { ... migration 2 ...; set_db_version(&mut tx, 2).await; }

	tx.commit().await?;

	Ok(())
}
