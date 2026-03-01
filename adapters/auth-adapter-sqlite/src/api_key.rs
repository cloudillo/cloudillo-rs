//! API Key management for the SQLite auth adapter

use sqlx::SqlitePool;
use std::sync::Arc;

use cloudillo_types::{
	auth_adapter::{ApiKeyInfo, ApiKeyValidation, CreateApiKeyOptions, CreatedApiKey},
	prelude::*,
	worker::WorkerPool,
};

use crate::crypto;

/// Row type for API key validation candidates
type ApiKeyCandidateRow = (i64, i32, String, Option<String>, Option<i64>, Option<String>);

/// Row type for API key info (key_id, key_prefix, name, scopes, expires_at, last_used_at, created_at)
type ApiKeyInfoRow = (i64, String, Option<String>, Option<String>, Option<i64>, Option<i64>, i64);

/// Create a new API key for a tenant
pub async fn create_api_key(
	db: &SqlitePool,
	worker: &Arc<WorkerPool>,
	tn_id: TnId,
	opts: CreateApiKeyOptions<'_>,
) -> ClResult<CreatedApiKey> {
	// Generate the key
	let (plaintext_key, key_prefix) = crypto::generate_api_key();

	// Hash the key for storage
	let key_hash = crypto::hash_api_key(worker, &plaintext_key).await?;

	// Insert into database
	let key_id = sqlx::query_scalar::<_, i64>(
		"INSERT INTO api_keys (tn_id, key_prefix, key_hash, name, scopes, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)
		RETURNING key_id",
	)
	.bind(tn_id.0)
	.bind(&key_prefix)
	.bind(key_hash.as_ref())
	.bind(opts.name)
	.bind(opts.scopes)
	.bind(opts.expires_at.map(|t| t.0))
	.fetch_one(db)
	.await
	.map_err(|e| {
		error!("Failed to insert API key: {}", e);
		Error::DbError
	})?;

	// Read back the created key info
	let info = read_api_key(db, tn_id, key_id).await?;

	Ok(CreatedApiKey { info, plaintext_key: plaintext_key.into() })
}

/// Validate an API key and return associated tenant info
pub async fn validate_api_key(
	db: &SqlitePool,
	worker: &Arc<WorkerPool>,
	key: &str,
) -> ClResult<ApiKeyValidation> {
	// Extract prefix from the key (cl_ + first 8 chars of random part)
	if !key.starts_with(crypto::API_KEY_PREFIX) {
		return Err(Error::Unauthorized);
	}

	let prefix_len = crypto::API_KEY_PREFIX.len() + 8;
	if key.len() < prefix_len {
		return Err(Error::Unauthorized);
	}
	let key_prefix = &key[..prefix_len];

	// Find API keys with matching prefix
	let candidates: Vec<ApiKeyCandidateRow> = sqlx::query_as(
		"SELECT ak.key_id, ak.tn_id, ak.key_hash, ak.scopes, ak.expires_at, t.roles
			FROM api_keys ak
			JOIN tenants t ON ak.tn_id = t.tn_id
			WHERE ak.key_prefix = ?",
	)
	.bind(key_prefix)
	.fetch_all(db)
	.await
	.map_err(|e| {
		error!("Failed to query API keys: {}", e);
		Error::DbError
	})?;

	if candidates.is_empty() {
		return Err(Error::Unauthorized);
	}

	// Try to verify against each candidate (usually just one due to unique prefix)
	for (key_id, tn_id, key_hash, scopes, expires_at, roles) in candidates {
		// Check expiration first (cheap check)
		if let Some(exp) = expires_at {
			let now = std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.map_err(|_| Error::Unauthorized)?
				.as_secs()
				.cast_signed();
			if exp < now {
				continue; // Expired, try next candidate
			}
		}

		// Verify the key hash (expensive check)
		if crypto::verify_api_key(worker, key, key_hash.into()).await.is_ok() {
			// Key is valid - update last_used_at
			let _ = sqlx::query("UPDATE api_keys SET last_used_at = unixepoch() WHERE key_id = ?")
				.bind(key_id)
				.execute(db)
				.await;

			// Get tenant id_tag
			let id_tag: String = sqlx::query_scalar("SELECT id_tag FROM tenants WHERE tn_id = ?")
				.bind(tn_id)
				.fetch_one(db)
				.await
				.map_err(|_| Error::Unauthorized)?;

			return Ok(ApiKeyValidation {
				tn_id: TnId(u32::try_from(tn_id).unwrap_or_default()),
				id_tag: id_tag.into(),
				key_id,
				scopes: scopes.map(Into::into),
				roles: roles.map(Into::into),
			});
		}
	}

	Err(Error::Unauthorized)
}

/// List API keys for a tenant (without exposing hashes)
pub async fn list_api_keys(db: &SqlitePool, tn_id: TnId) -> ClResult<Vec<ApiKeyInfo>> {
	let rows: Vec<ApiKeyInfoRow> = sqlx::query_as(
		"SELECT key_id, key_prefix, name, scopes, expires_at, last_used_at, created_at
			FROM api_keys
			WHERE tn_id = ?
			ORDER BY created_at DESC",
	)
	.bind(tn_id.0)
	.fetch_all(db)
	.await
	.map_err(|e| {
		error!("Failed to list API keys: {}", e);
		Error::DbError
	})?;

	Ok(rows
		.into_iter()
		.map(|(key_id, key_prefix, name, scopes, expires_at, last_used_at, created_at)| {
			ApiKeyInfo {
				key_id,
				key_prefix: key_prefix.into(),
				name: name.map(Into::into),
				scopes: scopes.map(Into::into),
				expires_at: expires_at.map(Timestamp),
				last_used_at: last_used_at.map(Timestamp),
				created_at: Timestamp(created_at),
			}
		})
		.collect())
}

/// Read a specific API key by ID
pub async fn read_api_key(db: &SqlitePool, tn_id: TnId, key_id: i64) -> ClResult<ApiKeyInfo> {
	let row: ApiKeyInfoRow = sqlx::query_as(
		"SELECT key_id, key_prefix, name, scopes, expires_at, last_used_at, created_at
			FROM api_keys
			WHERE tn_id = ? AND key_id = ?",
	)
	.bind(tn_id.0)
	.bind(key_id)
	.fetch_optional(db)
	.await
	.map_err(|e| {
		error!("Failed to read API key: {}", e);
		Error::DbError
	})?
	.ok_or(Error::NotFound)?;

	let (key_id, key_prefix, name, scopes, expires_at, last_used_at, created_at) = row;

	Ok(ApiKeyInfo {
		key_id,
		key_prefix: key_prefix.into(),
		name: name.map(Into::into),
		scopes: scopes.map(Into::into),
		expires_at: expires_at.map(Timestamp),
		last_used_at: last_used_at.map(Timestamp),
		created_at: Timestamp(created_at),
	})
}

/// Update an API key (name, scopes, expiration)
pub async fn update_api_key(
	db: &SqlitePool,
	tn_id: TnId,
	key_id: i64,
	name: Option<&str>,
	scopes: Option<&str>,
	expires_at: Option<Timestamp>,
) -> ClResult<ApiKeyInfo> {
	// Check that the key exists and belongs to this tenant
	let exists: Option<i64> =
		sqlx::query_scalar("SELECT key_id FROM api_keys WHERE tn_id = ? AND key_id = ?")
			.bind(tn_id.0)
			.bind(key_id)
			.fetch_optional(db)
			.await
			.map_err(|e| {
				error!("Failed to check API key existence: {}", e);
				Error::DbError
			})?;

	if exists.is_none() {
		return Err(Error::NotFound);
	}

	// Update the key
	sqlx::query(
		"UPDATE api_keys SET name = ?, scopes = ?, expires_at = ? WHERE tn_id = ? AND key_id = ?",
	)
	.bind(name)
	.bind(scopes)
	.bind(expires_at.map(|t| t.0))
	.bind(tn_id.0)
	.bind(key_id)
	.execute(db)
	.await
	.map_err(|e| {
		error!("Failed to update API key: {}", e);
		Error::DbError
	})?;

	// Read back the updated key
	read_api_key(db, tn_id, key_id).await
}

/// Delete an API key
pub async fn delete_api_key(db: &SqlitePool, tn_id: TnId, key_id: i64) -> ClResult<()> {
	let result = sqlx::query("DELETE FROM api_keys WHERE tn_id = ? AND key_id = ?")
		.bind(tn_id.0)
		.bind(key_id)
		.execute(db)
		.await
		.map_err(|e| {
			error!("Failed to delete API key: {}", e);
			Error::DbError
		})?;

	if result.rows_affected() == 0 {
		return Err(Error::NotFound);
	}

	Ok(())
}

/// Cleanup expired API keys
pub async fn cleanup_expired_api_keys(db: &SqlitePool) -> ClResult<u32> {
	let result = sqlx::query(
		"DELETE FROM api_keys WHERE expires_at IS NOT NULL AND expires_at < unixepoch()",
	)
	.execute(db)
	.await
	.map_err(|e| {
		error!("Failed to cleanup expired API keys: {}", e);
		Error::DbError
	})?;

	Ok(u32::try_from(result.rows_affected()).unwrap_or_default())
}

// vim: ts=4
