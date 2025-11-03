//! Email verification and token management

use sqlx::SqlitePool;

use crate::utils::*;
use cloudillo::{core::utils::random_id, prelude::*};

/// Create a registration verification token
pub(crate) async fn create_registration_verification(
	db: &SqlitePool,
	email: &str,
) -> ClResult<Box<str>> {
	let vfy_code = random_id()?;
	// Set expiration to 24 hours from now (as unix timestamp)
	let expires_at = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs()
		+ 86400; // 24 hours

	sqlx::query(
		"INSERT OR REPLACE INTO user_vfy (vfy_code, email, func, expires_at) VALUES (?1, ?2, 'register', ?3)"
	)
	.bind(&vfy_code)
	.bind(email)
	.bind(expires_at as i64)
	.execute(db)
	.await
	.inspect_err(inspect)
	.or(Err(Error::DbError))?;

	info!("Registration verification created for email: {}", email);
	Ok(vfy_code.into())
}

/// Validate a registration verification token
pub(crate) async fn validate_registration_verification(
	db: &SqlitePool,
	email: &str,
	vfy_code: &str,
) -> ClResult<()> {
	let row = sqlx::query(
		"SELECT email FROM user_vfy WHERE vfy_code = ?1 AND email = ?2 AND func = 'register'",
	)
	.bind(vfy_code)
	.bind(email)
	.fetch_optional(db)
	.await
	.inspect_err(inspect)
	.or(Err(Error::DbError))?;

	if row.is_none() {
		return Err(Error::PermissionDenied);
	}

	// Delete the used verification code
	sqlx::query("DELETE FROM user_vfy WHERE vfy_code = ?1")
		.bind(vfy_code)
		.execute(db)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

	Ok(())
}

/// Clean up expired verification tokens
pub(crate) async fn cleanup_expired_verifications(db: &SqlitePool) -> ClResult<()> {
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs() as i64;

	sqlx::query("DELETE FROM user_vfy WHERE expires_at IS NOT NULL AND expires_at < ?1")
		.bind(now)
		.execute(db)
		.await
		.inspect_err(inspect)
		.or(Err(Error::DbError))?;

	info!("Cleaned up expired verification tokens");
	Ok(())
}

/// Invalidate a token (no-op for now)
pub(crate) async fn invalidate_token(_token: &str) -> ClResult<()> {
	// Note: SQLite doesn't natively support token blacklisting efficiently
	// For now, this is a no-op. In production, consider token expiration or separate blacklist table
	// This could be implemented with a token_blacklist table if needed
	Ok(())
}
