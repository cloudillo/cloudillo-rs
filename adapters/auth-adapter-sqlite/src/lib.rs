#![allow(unused)]

use async_trait::async_trait;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use std::{fmt::Debug, sync::Arc, path::Path};
use sqlx::{sqlite::{self, SqlitePool, SqliteRow}, Row};

use cloudillo::{
	prelude::*,
	auth_adapter,
	meta_adapter,
	action::action,
	core::worker::WorkerPool,
	core::utils::random_id,
};

mod crypto;

/// # Helper functions
fn parse_str_list(s: &str) -> Box<[Box<str>]> {
	s.split(',')
		.map(|s| s.trim().to_owned().into_boxed_str())
		.filter(|s| !s.is_empty())
		.collect::<Vec<_>>()
		.into_boxed_slice()
}

/// Parse a comma-separated string into an Option of boxed array.
/// Returns None if the string is empty or only contains whitespace.
fn parse_str_list_optional(s: Option<&str>) -> Option<Box<[Box<str>]>> {
	s.and_then(|s| {
		let s = s.trim();
		if s.is_empty() {
			None
		} else {
			Some(parse_str_list(s))
		}
	})
}

fn inspect(err: &sqlx::Error) {
	warn!("DB: {:#?}", err);
}

pub fn map_res<T, F>(row: Result<SqliteRow, sqlx::Error>, f: F) -> ClResult<T>
where
	F: FnOnce(SqliteRow) -> Result<T, sqlx::Error>
{
	match row {
		Ok(row) => f(row).inspect_err(inspect).map_err(|_| Error::DbError),
		Err(sqlx::Error::RowNotFound) => Err(Error::NotFound),
		Err(err) => {
			inspect(&err);
			Err(Error::DbError)
		}
	}
}

pub async fn async_map_res<T, F>(row: Result<SqliteRow, sqlx::Error>, f: F) -> ClResult<T>
where
	F: AsyncFnOnce(SqliteRow) -> Result<T, sqlx::Error>
{
	match row {
		Ok(row) => f(row).await.inspect_err(inspect).map_err(|_| Error::DbError),
		Err(sqlx::Error::RowNotFound) => Err(Error::NotFound),
		Err(err) => {
			inspect(&err);
			Err(Error::DbError)
		}
	}
}

pub fn collect_res<T>(mut iter: impl Iterator<Item = Result<T, sqlx::Error>> + Unpin) -> ClResult<Vec<T>>
{
    let mut items = Vec::new();
    while let Some(item) = iter.next() {
        items.push(item.inspect_err(inspect).map_err(|_| Error::DbError)?);
    }
    Ok(items)
}


pub struct AuthAdapterSqlite {
	db: SqlitePool,
	worker: Arc<WorkerPool>,
	jwt_secret_str: String,
	jwt_secret: DecodingKey,
}

impl Debug for AuthAdapterSqlite {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("AuthAdapterSqlite").finish()
	}
}

impl AuthAdapterSqlite {
	pub async fn new(worker: Arc<WorkerPool>, path: impl AsRef<Path>) -> ClResult<Self> {
		let opts = sqlite::SqliteConnectOptions::new()
			.filename(path.as_ref())
			.create_if_missing(true)
			.journal_mode(sqlite::SqliteJournalMode::Wal);
		let db = sqlite::SqlitePoolOptions::new()
			.max_connections(5)
			.connect_with(opts)
			.await
			.inspect_err(|err| println!("DbError: {:#?}", err))
			.or(Err(Error::DbError))?;

		init_db(&db).await
			.inspect_err(|err| println!("DbError: {:#?}", err))
			.or(Err(Error::DbError))?;

		// Get or generate JWT secret
		let jwt_secret_str = Self::ensure_jwt_secret(&db).await?;
		let jwt_secret = DecodingKey::from_secret(jwt_secret_str.as_bytes());

		Ok(Self { worker, db, jwt_secret_str, jwt_secret })
	}

	/// Get or generate the JWT secret for HS256 signing
	async fn ensure_jwt_secret(db: &SqlitePool) -> ClResult<String> {
		// Try to read existing secret
		let res = sqlx::query("SELECT value FROM vars WHERE key = ?1")
			.bind("0:jwt_secret")
			.fetch_optional(db)
			.await
			.inspect_err(inspect)
			.or(Err(Error::DbError))?;

		if let Some(row) = res {
			return row.try_get("value").inspect_err(inspect).or(Err(Error::DbError));
		}

		// Generate new secret (32 random bytes, base64 encoded)
		use rand::RngCore;
		use base64::Engine;
		let mut secret_bytes = [0u8; 32];
		let mut rng = rand::rng();
		rng.fill_bytes(&mut secret_bytes);
		let secret_str = base64::engine::general_purpose::STANDARD.encode(&secret_bytes);

		// Store in database
		sqlx::query("INSERT OR REPLACE INTO vars (key, value) VALUES (?1, ?2)")
			.bind("0:jwt_secret")
			.bind(&secret_str)
			.execute(db)
			.await
			.inspect_err(inspect)
			.or(Err(Error::DbError))?;

		info!("Generated new JWT secret");
		Ok(secret_str)
	}
}


#[async_trait]
impl auth_adapter::AuthAdapter for AuthAdapterSqlite {
	async fn validate_token(&self, tn_id: TnId, id_tag: &str, token: &str) -> ClResult<auth_adapter::AuthCtx> {
		let token_data = decode::<auth_adapter::AccessToken<Box<str>>>(
			token,
			&self.jwt_secret,
			&Validation::new(Algorithm::HS256),
		).map_err(|_| Error::Unauthorized)?;

		Ok(auth_adapter::AuthCtx {
			tn_id,
			id_tag: Box::from(id_tag),
			roles: token_data.claims.r.unwrap_or("".into()).split(',').map(Box::from).collect(),
			scope: token_data.claims.scope,
		})
	}

	async fn read_id_tag(&self, tn_id: TnId) -> ClResult<Box<str>> {
		let res = sqlx::query(
			"SELECT id_tag FROM tenants WHERE tn_id = ?1"
		).bind(tn_id.0).fetch_one(&self.db).await.inspect_err(inspect);

		map_res(res, |row| row.try_get("id_tag"))
	}

	async fn read_tn_id(&self, id_tag: &str) -> ClResult<TnId> {
		let res = sqlx::query(
			"SELECT tn_id FROM tenants WHERE id_tag = ?1"
		).bind(id_tag).fetch_one(&self.db).await.inspect_err(inspect);

		map_res(res, |row| row.try_get("tn_id").map(|t| TnId(t)))
	}

	async fn read_tenant(&self, id_tag: &str) -> ClResult<auth_adapter::AuthProfile> {
		let res = sqlx::query(
			"SELECT tn_id, id_tag, roles FROM tenants WHERE id_tag = ?1"
		).bind(id_tag).fetch_one(&self.db).await;

		async_map_res(res, async |row| {
			let tn_id = TnId(row.try_get("tn_id")?);
			let roles: Option<Box<str>> = row.try_get("roles")?;
			Ok(auth_adapter::AuthProfile {
				id_tag: row.try_get("id_tag")?,
				roles: parse_str_list_optional(roles.as_deref()),
				keys: self.list_profile_keys(tn_id).await.unwrap_or(vec![]),
			})
		}).await
	}

	async fn create_tenant_registration(&self, email: &str) -> ClResult<()> {
		// Check if email is already registered as an active tenant
		let existing = sqlx::query(
			"SELECT email FROM tenants WHERE email = ?1 AND status = 'A'"
		)
		.bind(email)
		.fetch_optional(&self.db)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

		if existing.is_some() {
			return Err(Error::PermissionDenied); // Email already registered
		}

		// Generate verification code
		let vfy_code = random_id()?;

		// Store verification code (INSERT OR REPLACE to allow retries)
		sqlx::query(
			"INSERT OR REPLACE INTO user_vfy (vfy_code, email, func) VALUES (?1, ?2, 'register')"
		)
		.bind(&vfy_code)
		.bind(email)
		.execute(&self.db)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

		info!("Tenant registration initiated for email: {}", email);
		Ok(())
	}

	async fn create_tenant(&self, id_tag: &str, email: Option<&str>, vfy_code: Option<&str>) -> ClResult<TnId> {
		// If verification code is provided, validate it
		if let Some(vfy_code) = vfy_code {
			if let Some(email_addr) = email {
				// Query user_vfy table to validate code matches email
				let row = sqlx::query(
					"SELECT email FROM user_vfy WHERE vfy_code = ?1"
				).bind(vfy_code)
					.fetch_optional(&self.db)
					.await
					.inspect_err(inspect)
					.or(Err(Error::DbError))?;

				let Some(vfy_row) = row else {
					// Verification code not found
					return Err(Error::PermissionDenied);
				};

				let stored_email: String = vfy_row.try_get("email").inspect_err(inspect).or(Err(Error::DbError))?;
				if stored_email != email_addr {
					// Email mismatch - code belongs to different email
					return Err(Error::PermissionDenied);
				}

				// Validation passed - delete the verification code
				sqlx::query("DELETE FROM user_vfy WHERE vfy_code = ?1")
					.bind(vfy_code)
					.execute(&self.db)
					.await
					.inspect_err(inspect)
					.or(Err(Error::DbError))?;
			} else {
				// vfy_code provided but no email
				return Err(Error::PermissionDenied);
			}
		}

		let res = sqlx::query(
			"INSERT INTO tenants (id_tag, email, status) VALUES (?1, ?2, 'A') RETURNING tn_id"
		).bind(id_tag).bind(email)
			.fetch_one(&self.db).await;

		map_res(res, |row| row.try_get("tn_id").map(|t| TnId(t)))
	}

	async fn delete_tenant(&self, id_tag: &str) -> ClResult<()> {
		// Get the tenant ID first
		let res = sqlx::query("SELECT tn_id FROM tenants WHERE id_tag = ?1")
			.bind(id_tag)
			.fetch_optional(&self.db)
			.await
			.inspect_err(inspect)
			.or(Err(Error::DbError))?;

		let Some(row) = res else {
			return Err(Error::NotFound);
		};

		let tn_id: i32 = row.try_get("tn_id").inspect_err(inspect).or(Err(Error::DbError))?;

		// Begin transaction for atomic deletion
		let mut tx = self.db.begin().await.inspect_err(inspect).or(Err(Error::DbError))?;

		// Delete in order (respecting potential foreign key constraints)
		sqlx::query("DELETE FROM certs WHERE tn_id = ?1")
			.bind(tn_id)
			.execute(&mut *tx)
			.await
			.inspect_err(inspect)
			.or(Err(Error::DbError))?;

		sqlx::query("DELETE FROM keys WHERE tn_id = ?1")
			.bind(tn_id)
			.execute(&mut *tx)
			.await
			.inspect_err(inspect)
			.or(Err(Error::DbError))?;

		sqlx::query("DELETE FROM user_vfy WHERE email IN (SELECT email FROM tenants WHERE tn_id = ?1)")
			.bind(tn_id)
			.execute(&mut *tx)
			.await
			.inspect_err(inspect)
			.or(Err(Error::DbError))?;

		sqlx::query("DELETE FROM events WHERE tn_id = ?1")
			.bind(tn_id)
			.execute(&mut *tx)
			.await
			.inspect_err(inspect)
			.or(Err(Error::DbError))?;

		sqlx::query("DELETE FROM tenants WHERE tn_id = ?1")
			.bind(tn_id)
			.execute(&mut *tx)
			.await
			.inspect_err(inspect)
			.or(Err(Error::DbError))?;

		tx.commit().await.inspect_err(inspect).or(Err(Error::DbError))?;

		info!("Tenant deleted: {}", id_tag);
		Ok(())
	}

	// Password management
	async fn create_tenant_login(&self, id_tag: &str) -> ClResult<auth_adapter::AuthLogin> {
		let res = sqlx::query(
			"SELECT tn_id, id_tag, roles FROM tenants WHERE id_tag = ?1"
		).bind(id_tag).fetch_one(&self.db).await;

		match res {
			Err(err) => Err(Error::PermissionDenied),
			Ok(row) => {
				let tn_id = row.try_get("tn_id").map(|t| TnId(t)).or(Err(Error::DbError))?;
				let roles: Option<&str> = row.try_get("roles").or(Err(Error::DbError))?;

				//let token = crypto::generate_access_token(&self.worker, tn_id, roles.map(|s| s.into()), None, self.jwt_secret_str.clone().into()).await?;
				let access_token = auth_adapter::AccessToken {
					iss: Box::from(id_tag),
					sub: None,
					scope: None,
					r: roles.map(|s| Box::from(s)),
					exp: Timestamp::from_now(action::ACCESS_TOKEN_EXPIRY),
				};
				let token = crypto::generate_access_token(&self.worker, access_token, self.jwt_secret_str.clone().into()).await?;

				Ok(auth_adapter::AuthLogin {
					tn_id: row.try_get("tn_id").map(|t| TnId(t)).or(Err(Error::DbError))?,
					id_tag: Box::from(id_tag),
					roles: parse_str_list_optional(roles),
					token,
				})
			}
		}
	}

	async fn check_tenant_password(&self, id_tag: &str, password: Box<str>) -> ClResult<auth_adapter::AuthLogin> {
		let res = sqlx::query(
			"SELECT tn_id, id_tag, password, roles FROM tenants WHERE id_tag = ?1"
		).bind(id_tag).fetch_one(&self.db).await;

		match res {
			Err(err) => Err(Error::PermissionDenied),
			Ok(row) => {
				let tn_id: TnId = row.try_get("tn_id").map(|t| TnId(t)).or(Err(Error::DbError))?;
				let password_hash: Box<str> = row.try_get("password").or(Err(Error::DbError))?;
				let roles: Option<&str> = row.try_get("roles").or(Err(Error::DbError))?;

				crypto::check_password(&self.worker, password, password_hash).await?;
				//let token = crypto::generate_access_token(&self.worker, tn_id, roles.map(|s| s.into()), None, self.jwt_secret_str.clone().into()).await?;
				let access_token = auth_adapter::AccessToken {
					iss: Box::from(id_tag),
					sub: None,
					scope: None,
					r: roles.map(|s| Box::from(s)),
					exp: Timestamp::from_now(action::ACCESS_TOKEN_EXPIRY),
				};
				let token = crypto::generate_access_token(&self.worker, access_token, self.jwt_secret_str.clone().into()).await?;

				Ok(auth_adapter::AuthLogin {
					tn_id: row.try_get("tn_id").map(|t| TnId(t)).or(Err(Error::DbError))?,
					id_tag: Box::from(id_tag),
					roles: parse_str_list_optional(roles),
					token,
				})
			}
		}
	}

	async fn update_tenant_password(&self, id_tag: &str, password: Box<str>) -> ClResult<()> {
		let password_hash = crypto::generate_password_hash(&self.worker, password).await?;
		let res = sqlx::query(
			"UPDATE tenants SET password=?2 WHERE id_tag = ?1"
		).bind(id_tag).bind(password_hash).execute(&self.db).await;
		Ok(())
	}

	// Certificate management
	async fn create_cert(&self, cert_data: &auth_adapter::CertData) -> ClResult<()> {
		println!("create_cert {}", &cert_data.id_tag);
		sqlx::query(
			"INSERT OR REPLACE INTO certs (tn_id, id_tag, domain, expires_at, cert, key)
			VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
		).bind(cert_data.tn_id.0)
			.bind(&cert_data.id_tag)
			.bind(&cert_data.domain)
			.bind(cert_data.expires_at.0)
			.bind(&cert_data.cert)
			.bind(&cert_data.key)
			.execute(&self.db).await;

		Ok(())
	}

	async fn read_cert_by_tn_id(&self, tn_id: TnId) -> ClResult<auth_adapter::CertData> {
		let res = sqlx::query(
			"SELECT tn_id, id_tag, domain, cert, key, expires_at FROM certs WHERE tn_id = ?1"
		).bind(tn_id.0).fetch_one(&self.db).await;

		map_res(res, |row| Ok(auth_adapter::CertData {
			tn_id: TnId(row.try_get("tn_id")?),
			id_tag: row.try_get("id_tag")?,
			domain: row.try_get("domain")?,
			cert: row.try_get("cert")?,
			key: row.try_get("key")?,
			expires_at: Timestamp(row.try_get::<i64, _>("expires_at")?),
		}))
	}

	async fn read_cert_by_id_tag(&self, id_tag: &str) -> ClResult<auth_adapter::CertData> {
		let res = sqlx::query(
			"SELECT tn_id, id_tag, domain, cert, key, expires_at FROM certs WHERE id_tag = ?1"
		).bind(id_tag).fetch_one(&self.db).await;

		map_res(res, |row| Ok(auth_adapter::CertData {
			tn_id: TnId(row.try_get("tn_id")?),
			id_tag: row.try_get("id_tag")?,
			domain: row.try_get("domain")?,
			cert: row.try_get("cert")?,
			key: row.try_get("key")?,
			expires_at: Timestamp(row.try_get::<i64, _>("expires_at")?),
		}))
	}

	async fn read_cert_by_domain(&self, domain: &str) -> ClResult<auth_adapter::CertData> {
		let res = sqlx::query(
			"SELECT tn_id, id_tag, domain, cert, key, expires_at FROM certs WHERE domain = ?1"
		).bind(domain).fetch_one(&self.db).await;

		map_res(res, |row| Ok(auth_adapter::CertData {
			tn_id: TnId(row.try_get("tn_id")?),
			id_tag: row.try_get("id_tag")?,
			domain: row.try_get("domain")?,
			cert: row.try_get("cert")?,
			key: row.try_get("key")?,
			expires_at: Timestamp(row.try_get::<i64, _>("expires_at")?),
		}))
	}

	// Key management
	async fn list_profile_keys(&self, tn_id: TnId) -> ClResult<Vec<auth_adapter::AuthKey>> {
		let res = sqlx::query(
			"SELECT key_id, public_key, expires_at FROM keys WHERE tn_id = ?1"
		).bind(tn_id.0).fetch_all(&self.db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

		collect_res(res.iter().map(|row| Ok(auth_adapter::AuthKey {
			key_id: row.try_get::<Box<str>, _>("key_id")?,
			public_key: row.try_get::<Box<str>, _>("public_key")?,
			expires_at: row.try_get::<Option<i64>, _>("expires_at")?.map(Timestamp),
		})))
	}

	async fn read_profile_key(&self, tn_id: TnId, key_id: &str) -> ClResult<auth_adapter::AuthKey> {
		let res = sqlx::query(
			"SELECT key_id, public_key, expires_at FROM keys WHERE tn_id = ?1 AND key_id = ?2"
		)
		.bind(tn_id.0)
		.bind(key_id)
		.fetch_optional(&self.db)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

		let Some(row) = res else {
			return Err(Error::NotFound);
		};

		Ok(auth_adapter::AuthKey {
			key_id: row.try_get::<Box<str>, _>("key_id").inspect_err(inspect).or(Err(Error::DbError))?,
			public_key: row.try_get::<Box<str>, _>("public_key").inspect_err(inspect).or(Err(Error::DbError))?,
			expires_at: row.try_get::<Option<i64>, _>("expires_at").inspect_err(inspect).or(Err(Error::DbError))?.map(Timestamp),
		})
	}

	async fn create_profile_key(&self, tn_id: TnId, expires_at: Option<Timestamp>) -> ClResult<auth_adapter::AuthKey> {
		let now = time::OffsetDateTime::now_local().map_err(|_| Error::DbError)?;
		let key_id = format!("{:02}{:02}{:02}", now.year() - 2000, now.month() as u8, now.day());
		let keypair = crypto::generate_key(&self.worker).await.or(Err(Error::DbError))?;

		sqlx::query(
			"INSERT INTO keys (tn_id, key_id, private_key, public_key, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)"
		).bind(tn_id.0).bind(&key_id).bind(&keypair.private_key).bind(&keypair.public_key).bind(expires_at.map(|t| t.0)).execute(&self.db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

		Ok(auth_adapter::AuthKey {
			key_id: key_id.into(),
			public_key: keypair.public_key,
			expires_at,
		})
	}

	async fn create_access_token(&self, tn_id: TnId, data: &auth_adapter::AccessToken<&str>) -> ClResult<Box<str>> {
		let res = sqlx::query(
			"SELECT tn_id, id_tag, password, roles FROM tenants WHERE tn_id = ?"
		).bind(tn_id.0).fetch_one(&self.db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

		let roles: Option<&str> = res.try_get("roles").or(Err(Error::DbError))?;
		let id_tag: Box<str> = res.try_get("id_tag").or(Err(Error::DbError))?;

		let access_token = auth_adapter::AccessToken {
			iss: id_tag,
			sub: data.sub.map(|s| Box::from(s)),
			scope: data.scope.map(|s| Box::from(s)),
			r: roles.map(|s| Box::from(s)),
			exp: data.exp,
		};

		let token = crypto::generate_access_token(&self.worker, access_token, self.jwt_secret_str.clone().into()).await?;

		Ok(token)
	}

	async fn create_action_token(&self, tn_id: TnId, action: action::CreateAction) -> ClResult<Box<str>> {
		let res = sqlx::query("SELECT t.id_tag, k.key_id, k.private_key FROM tenants t
			JOIN keys k ON t.tn_id = k.tn_id
			WHERE t.tn_id=? ORDER BY k.key_id DESC LIMIT 1")
			.bind(tn_id.0).fetch_one(&self.db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;
		let id_tag: &str = res.try_get("id_tag").or(Err(Error::DbError))?;
		let key_id: Box<str> = res.try_get("key_id").or(Err(Error::DbError))?;
		let private_key: Box<str> = res.try_get("private_key").or(Err(Error::DbError))?;

		let mut typ = action.typ.to_string();
		if let Some(sub_typ) = &action.sub_typ {
			typ = typ + ":" + &sub_typ;
		}
		let action_data = auth_adapter::ActionToken {
			t: typ.into(),
			iss: id_tag.into(),
			k: key_id,
			p: action.parent_id,
			aud: action.audience_tag,
			c: action.content,
			a: action.attachments,
			sub: action.subject,
			exp: action.expires_at,
			iat: Timestamp::now(),
		};
		let token = crypto::generate_action_token(&self.worker, action_data, private_key).await?;

		Ok(token)
	}

	async fn create_proxy_token(&self, tn_id: TnId, id_tag: &str, roles: &[Box<str>]) -> ClResult<Box<str>> {
		// Fetch the latest key for this tenant
		let res = sqlx::query("SELECT key_id, private_key FROM keys WHERE tn_id = ? ORDER BY key_id DESC LIMIT 1")
			.bind(tn_id.0).fetch_one(&self.db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;
		let key_id: Box<str> = res.try_get("key_id").or(Err(Error::DbError))?;
		let private_key: Box<str> = res.try_get("private_key").or(Err(Error::DbError))?;

		// Create proxy token JWT with user's id_tag and roles
		// Proxy tokens allow this user to authenticate on behalf of the server in federation
		use jsonwebtoken::{encode, EncodingKey, Header};

		let now = Timestamp::now();
		let exp = Timestamp::from_now(86400); // 24 hours from now

		// Build payload as a serializable struct
		#[derive(serde::Serialize)]
		struct ProxyTokenPayload {
			iss: String,
			sub: String,
			aud: String,
			iat: u64,
			exp: u64,
			roles: Vec<String>,
		}

		let payload = ProxyTokenPayload {
			iss: id_tag.to_string(),
			sub: "federation".to_string(),
			aud: "federation".to_string(),
			iat: now.0 as u64,
			exp: exp.0 as u64,
			roles: roles.iter().map(|r| r.to_string()).collect(),
		};

		let key = EncodingKey::from_secret(private_key.as_bytes());
		let token = encode(&Header::default(), &payload, &key)
			.map_err(|_| Error::DbError)?;

		Ok(token.into())
	}

	async fn verify_access_token(&self, token: &str) -> ClResult<()> {
		// Decode and validate the JWT token (use AuthToken which has Deserialize)
		decode::<auth_adapter::AccessToken<Box<str>>>(
			token,
			&self.jwt_secret,
			&Validation::new(Algorithm::HS256),
		)
		.map_err(|_| Error::Unauthorized)?;

		Ok(())
	}

	// Vapid keys
	async fn read_vapid_key(&self, tn_id: TnId) -> ClResult<auth_adapter::KeyPair> {
		let res = sqlx::query(
			"SELECT vapid_public_key, vapid_private_key FROM tenants WHERE tn_id = ?1"
		)
		.bind(tn_id.0)
		.fetch_optional(&self.db)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

		let Some(row) = res else {
			return Err(Error::NotFound);
		};

		let public_key: Option<String> = row.try_get("vapid_public_key").or(Err(Error::DbError))?;
		let private_key: Option<String> = row.try_get("vapid_private_key").or(Err(Error::DbError))?;

		match (public_key, private_key) {
			(Some(pub_key), Some(priv_key)) => Ok(auth_adapter::KeyPair {
				public_key: pub_key.into(),
				private_key: priv_key.into(),
			}),
			_ => Err(Error::NotFound),
		}
	}

	async fn read_vapid_public_key(&self, tn_id: TnId) -> ClResult<Box<str>> {
		let res = sqlx::query(
			"SELECT vapid_public_key FROM tenants WHERE tn_id = ?1"
		)
		.bind(tn_id.0)
		.fetch_optional(&self.db)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

		let Some(row) = res else {
			return Err(Error::NotFound);
		};

		let public_key: Option<String> = row.try_get("vapid_public_key").or(Err(Error::DbError))?;
		public_key.map(|k| k.into()).ok_or(Error::NotFound)
	}

	async fn update_vapid_key(&self, tn_id: TnId, key: &auth_adapter::KeyPair) -> ClResult<()> {
		sqlx::query(
			"UPDATE tenants SET vapid_public_key = ?1, vapid_private_key = ?2 WHERE tn_id = ?3"
		)
		.bind(key.public_key.as_ref())
		.bind(key.private_key.as_ref())
		.bind(tn_id.0)
		.execute(&self.db)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

		Ok(())
	}

	// Variables
	async fn read_var(&self, tn_id: TnId, var: &str) -> ClResult<Box<str>> {
		let key = format!("{}:{}", tn_id.0, var);
		let res = sqlx::query(
			"SELECT value FROM vars WHERE key = ?1"
		).bind(&key).fetch_one(&self.db).await.inspect_err(inspect);

		map_res(res, |row| row.try_get("value"))
	}

	async fn update_var(&self, tn_id: TnId, var: &str, value: &str) -> ClResult<()> {
		let key = format!("{}:{}", tn_id.0, var);
		sqlx::query(
			"INSERT OR REPLACE INTO vars (key, value, updated_at) VALUES (?1, ?2, current_timestamp)"
		)
		.bind(&key)
		.bind(value)
		.execute(&self.db)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;
		Ok(())
	}

	// Webauthn
	async fn list_webauthn_credentials(&self, tn_id: TnId) -> ClResult<Box<[auth_adapter::Webauthn]>> {
		let res = sqlx::query(
			"SELECT credential_id, counter, public_key, description FROM webauthn WHERE tn_id = ?1"
		)
		.bind(tn_id.0)
		.fetch_all(&self.db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

		let credentials: Box<[auth_adapter::Webauthn]> = res.iter().map(|row| {
			Ok(auth_adapter::Webauthn {
				credential_id: Box::leak(row.try_get::<Box<str>, _>("credential_id").inspect_err(inspect).or(Err(Error::DbError))?) as &str,
				counter: row.try_get("counter").inspect_err(inspect).or(Err(Error::DbError))?,
				public_key: Box::leak(row.try_get::<Box<str>, _>("public_key").inspect_err(inspect).or(Err(Error::DbError))?) as &str,
				description: row.try_get::<Option<String>, _>("description").inspect_err(inspect).or(Err(Error::DbError))?.map(|s| Box::leak(s.into_boxed_str()) as &str),
			})
		}).collect::<ClResult<Vec<_>>>()?
		.into_boxed_slice();

		Ok(credentials)
	}

	async fn read_webauthn_credential(&self, tn_id: TnId, credential_id: &str) -> ClResult<auth_adapter::Webauthn> {
		let res = sqlx::query(
			"SELECT credential_id, counter, public_key, description FROM webauthn WHERE tn_id = ?1 AND credential_id = ?2"
		)
		.bind(tn_id.0)
		.bind(credential_id)
		.fetch_optional(&self.db)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

		let Some(row) = res else {
			return Err(Error::NotFound);
		};

		Ok(auth_adapter::Webauthn {
			credential_id: Box::leak(row.try_get::<Box<str>, _>("credential_id").inspect_err(inspect).or(Err(Error::DbError))?) as &str,
			counter: row.try_get("counter").inspect_err(inspect).or(Err(Error::DbError))?,
			public_key: Box::leak(row.try_get::<Box<str>, _>("public_key").inspect_err(inspect).or(Err(Error::DbError))?) as &str,
			description: row.try_get::<Option<String>, _>("description").inspect_err(inspect).or(Err(Error::DbError))?.map(|s| Box::leak(s.into_boxed_str()) as &str),
		})
	}

	async fn create_webauthn_credential(&self, tn_id: TnId, data: &auth_adapter::Webauthn) -> ClResult<()> {
		sqlx::query(
			"INSERT INTO webauthn (tn_id, credential_id, counter, public_key, description) VALUES (?1, ?2, ?3, ?4, ?5)"
		)
		.bind(tn_id.0)
		.bind(data.credential_id)
		.bind(data.counter)
		.bind(data.public_key)
		.bind(data.description)
		.execute(&self.db)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

		Ok(())
	}

	async fn update_webauthn_credential_counter(&self, tn_id: TnId, credential_id: &str, counter: u32) -> ClResult<()> {
		sqlx::query(
			"UPDATE webauthn SET counter = ?1 WHERE tn_id = ?2 AND credential_id = ?3"
		)
		.bind(counter)
		.bind(tn_id.0)
		.bind(credential_id)
		.execute(&self.db)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

		Ok(())
	}

	async fn delete_webauthn_credential(&self, tn_id: TnId, credential_id: &str) -> ClResult<()> {
		sqlx::query(
			"DELETE FROM webauthn WHERE tn_id = ?1 AND credential_id = ?2"
		)
		.bind(tn_id.0)
		.bind(credential_id)
		.execute(&self.db)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

		Ok(())
	}

	// Phase 1: Registration & Session Management
	async fn create_registration_verification(&self, email: &str) -> ClResult<Box<str>> {
		let vfy_code = random_id()?;
		// Set expiration to 24 hours from now (as unix timestamp)
		let expires_at = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs() + 86400; // 24 hours

		sqlx::query(
			"INSERT OR REPLACE INTO user_vfy (vfy_code, email, func, expires_at) VALUES (?1, ?2, 'register', ?3)"
		)
		.bind(&vfy_code)
		.bind(email)
		.bind(expires_at as i64)
		.execute(&self.db)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

		info!("Registration verification created for email: {}", email);
		Ok(vfy_code.into())
	}

	async fn validate_registration_verification(&self, email: &str, vfy_code: &str) -> ClResult<()> {
		let row = sqlx::query(
			"SELECT email FROM user_vfy WHERE vfy_code = ?1 AND email = ?2 AND func = 'register'"
		)
		.bind(vfy_code)
		.bind(email)
		.fetch_optional(&self.db)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

		if row.is_none() {
			return Err(Error::PermissionDenied);
		}

		// Delete the used verification code
		sqlx::query("DELETE FROM user_vfy WHERE vfy_code = ?1")
			.bind(vfy_code)
			.execute(&self.db)
			.await
			.inspect_err(inspect)
			.or(Err(Error::DbError))?;

		Ok(())
	}

	async fn invalidate_token(&self, _token: &str) -> ClResult<()> {
		// Note: SQLite doesn't natively support token blacklisting efficiently
		// For now, this is a no-op. In production, consider token expiration or separate blacklist table
		// This could be implemented with a token_blacklist table if needed
		Ok(())
	}

	async fn cleanup_expired_verifications(&self) -> ClResult<()> {
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs() as i64;

		sqlx::query(
			"DELETE FROM user_vfy WHERE expires_at IS NOT NULL AND expires_at < ?1"
		)
		.bind(now)
		.execute(&self.db)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

		info!("Cleaned up expired verification tokens");
		Ok(())
	}
}

async fn init_db(db: &SqlitePool) -> Result<(), sqlx::Error> {
	let mut tx = db.begin().await?;

	sqlx::query("CREATE TABLE IF NOT EXISTS globals (
			key text NOT NULL,
			value text,
			PRIMARY KEY(key)
	)").execute(&mut *tx).await?;

	sqlx::query("CREATE TABLE IF NOT EXISTS tenants (
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
	)").execute(&mut *tx).await?;

	sqlx::query("CREATE TABLE IF NOT EXISTS keys (
		tn_id integer NOT NULL,
		key_id text NOT NULL,
		status char(1),
		expires_at datetime,
		public_key text,
		private_key text,
		PRIMARY KEY(tn_id, key_id)
	)").execute(&mut *tx).await?;

	sqlx::query("CREATE TABLE IF NOT EXISTS certs (
		tn_id integer NOT NULL,
		status char(1),
		id_tag text,
		domain text,
		expires_at datetime,
		cert text,
		key text,
		PRIMARY KEY(tn_id)
	)").execute(&mut *tx).await?;
	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_certs_idTag ON certs (id_tag)")
		.execute(&mut *tx).await?;
	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_certs_domain ON certs (domain)"
		).execute(&mut *tx).await?;

	sqlx::query("CREATE TABLE IF NOT EXISTS events (
		ev_id integer NOT NULL,
		tn_id integer NOT NULL,
		type text NOT NULL,
		ip text,
		data text,
		PRIMARY KEY(ev_id)
	)").execute(&mut *tx).await?;

	sqlx::query("CREATE TABLE IF NOT EXISTS user_vfy (
		vfy_code text NOT NULL,
		email text NOT NULL,
		func text NOT NULL,
		created_at datetime DEFAULT current_timestamp,
		PRIMARY KEY(vfy_code)
	)").execute(&mut *tx).await?;
	sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_user_vfy_email ON user_vfy (email)")
		.execute(&mut *tx).await?;

	sqlx::query("CREATE TABLE IF NOT EXISTS vars (
		key text NOT NULL,
		value text NOT NULL,
		created_at datetime DEFAULT current_timestamp,
		updated_at datetime DEFAULT current_timestamp,
		PRIMARY KEY(key)
	)").execute(&mut *tx).await?;

	sqlx::query("CREATE TABLE IF NOT EXISTS webauthn (
		tn_id integer NOT NULL,
		credential_id text NOT NULL,
		counter integer NOT NULL DEFAULT 0,
		public_key text NOT NULL,
		description text,
		created_at datetime DEFAULT current_timestamp,
		PRIMARY KEY(tn_id, credential_id)
	)").execute(&mut *tx).await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_webauthn_tn_id ON webauthn (tn_id)")
		.execute(&mut *tx).await?;

	// Phase 1 Migration: Extend user_vfy table for unified token handling
	// Add support for expires_at (token expiration), id_tag (for password reset), and data (JSON)
	// Note: SQLite doesn't support IF NOT EXISTS in ALTER TABLE, so we ignore errors
	let _ = sqlx::query("ALTER TABLE user_vfy ADD COLUMN expires_at datetime")
		.execute(&mut *tx).await;
	let _ = sqlx::query("ALTER TABLE user_vfy ADD COLUMN id_tag text")
		.execute(&mut *tx).await;
	let _ = sqlx::query("ALTER TABLE user_vfy ADD COLUMN data text")
		.execute(&mut *tx).await;

	// Add indexes for efficient queries
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_user_vfy_expires ON user_vfy(expires_at)")
		.execute(&mut *tx).await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_user_vfy_email_func ON user_vfy(email, func)")
		.execute(&mut *tx).await?;
	sqlx::query("CREATE INDEX IF NOT EXISTS idx_user_vfy_idtag_func ON user_vfy(id_tag, func)")
		.execute(&mut *tx).await?;

	// Phase 2 Migration: Convert roles from JSON to TEXT format
	// Handle cases where roles were stored as JSON arrays and convert to comma-separated strings
	// For new databases, roles will be stored as comma-separated strings or NULL
	let _ = sqlx::query(
		"UPDATE tenants SET roles = NULL WHERE roles IS NULL OR roles = 'null' OR roles = '[]'"
	).execute(&mut *tx).await;

	tx.commit().await?;

	Ok(())
}

// vim: ts=4
