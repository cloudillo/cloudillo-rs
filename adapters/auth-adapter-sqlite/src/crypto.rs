const TOKEN_EXPIRE: u64 = 8; /* hours */
const BCRYPT_COST: u32 = 10;

use p384::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use p384::{elliptic_curve::rand_core::OsRng, SecretKey};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::SecretKey as P256SecretKey;

use cloudillo_types::{
	auth_adapter::{AccessToken, ActionToken, KeyPair},
	prelude::*,
	worker,
};

fn generate_password_hash_sync(password: &str) -> ClResult<Box<str>> {
	let hash = bcrypt::hash(password, BCRYPT_COST).map_err(|_| Error::PermissionDenied)?;

	Ok(hash.into())
}

pub async fn generate_password_hash(
	worker: &worker::WorkerPool,
	password: &str,
) -> ClResult<Box<str>> {
	let password = password.to_string().into_boxed_str();
	worker.try_run_immed(move || generate_password_hash_sync(&password)).await
}

fn check_password_sync(password: &str, password_hash: &str) -> ClResult<()> {
	let res = bcrypt::verify(password, password_hash).map_err(|_| Error::PermissionDenied)?;
	if res {
		Ok(())
	} else {
		Err(Error::PermissionDenied)
	}
}

pub async fn check_password(
	worker: &worker::WorkerPool,
	password: &str,
	password_hash: Box<str>,
) -> ClResult<()> {
	let password = password.to_string().into_boxed_str();
	worker
		.try_run_immed(move || check_password_sync(&password, &password_hash))
		.await
}

fn generate_access_token_sync(
	access_token: &AccessToken<Box<str>>,
	jwt_secret: &str,
) -> ClResult<Box<str>> {
	let _expire = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map_err(|_| Error::PermissionDenied)?
		.as_secs()
		+ 3600 * TOKEN_EXPIRE;

	let token = jsonwebtoken::encode(
		&jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
		&access_token,
		&jsonwebtoken::EncodingKey::from_secret(jwt_secret.as_bytes()),
	)
	.map_err(|_| Error::PermissionDenied)?
	.into();

	Ok(token)
}

pub async fn generate_access_token(
	worker: &worker::WorkerPool,
	access_token: AccessToken<Box<str>>,
	jwt_secret: Box<str>,
) -> ClResult<Box<str>> {
	worker
		.try_run_immed(move || generate_access_token_sync(&access_token, &jwt_secret))
		.await
}

/// Generate a keypair (sync)
///
/// Must be run on a worker thread!
fn generate_key_sync() -> ClResult<KeyPair> {
	let private = SecretKey::random(&mut OsRng);
	let public = private.public_key();

	//let private_key = private.to_pkcs8_pem(LineEnding::LF).map_err(|_| Error::PermissionDenied)?;
	let private_key: Box<str> = private
		.to_pkcs8_pem(LineEnding::LF)
		.map_err(|_| Error::PermissionDenied)?
		.lines()
		.filter(|s| !s.starts_with('-'))
		.map(str::trim)
		.collect();
	let public_key: Box<str> = public
		.to_public_key_pem(LineEnding::LF)
		.map_err(|_| Error::PermissionDenied)?
		.lines()
		.filter(|s| !s.starts_with('-'))
		.map(str::trim)
		.collect();

	Ok(KeyPair { private_key, public_key })
}

/// Generate a keypair
pub async fn generate_key(worker: &worker::WorkerPool) -> ClResult<KeyPair> {
	worker.try_run_immed(generate_key_sync).await
}

/// Generate a P-256 keypair for VAPID (sync)
///
/// VAPID uses ES256 (P-256 curve). Returns:
/// - private_key: Raw 32-byte scalar, base64url encoded (compatible with TS version)
/// - public_key: 65-byte uncompressed point, base64url encoded (for Web Push API)
fn generate_vapid_key_sync() -> KeyPair {
	use p256::elliptic_curve::sec1::ToEncodedPoint;

	let private = P256SecretKey::random(&mut OsRng);
	let public = private.public_key();

	// Private key as raw scalar, base64url encoded (compatible with TypeScript version)
	let private_key: Box<str> = URL_SAFE_NO_PAD.encode(private.to_bytes()).into();

	// Public key as uncompressed point, base64url encoded (for Web Push API)
	let public_point = public.to_encoded_point(false);
	let public_key: Box<str> = URL_SAFE_NO_PAD.encode(public_point.as_bytes()).into();

	KeyPair { private_key, public_key }
}

/// Generate a P-256 keypair for VAPID
pub async fn generate_vapid_key(worker: &worker::WorkerPool) -> ClResult<KeyPair> {
	worker.try_run_immed(|| Ok(generate_vapid_key_sync())).await
}

/// API key prefix
pub const API_KEY_PREFIX: &str = "cl_";
/// Number of random bytes for API key (256 bits of entropy)
const API_KEY_RANDOM_BYTES: usize = 32;

/// Generate a new API key
///
/// Returns (full_key, prefix_for_display)
/// - full_key: The complete API key to give to the user (shown only once)
/// - key_prefix: First 8 chars after prefix for identification in logs/UI
pub fn generate_api_key() -> (String, String) {
	use rand::Rng;

	let mut random_bytes = [0u8; API_KEY_RANDOM_BYTES];
	rand::rng().fill_bytes(&mut random_bytes);

	let random_part = URL_SAFE_NO_PAD.encode(random_bytes);
	let full_key = format!("{}{}", API_KEY_PREFIX, random_part);
	// Key prefix: cl_ + first 8 chars of random part
	let key_prefix = format!("{}{}", API_KEY_PREFIX, &random_part[..8]);

	(full_key, key_prefix)
}

/// Hash an API key for storage (using bcrypt like passwords)
pub async fn hash_api_key(worker: &worker::WorkerPool, key: &str) -> ClResult<Box<str>> {
	generate_password_hash(worker, key).await
}

/// Verify an API key against its hash
pub async fn verify_api_key(
	worker: &worker::WorkerPool,
	key: &str,
	key_hash: Box<str>,
) -> ClResult<()> {
	check_password(worker, key, key_hash).await
}

fn generate_action_token_sync(action_data: &ActionToken, private_key: &str) -> ClResult<Box<str>> {
	let private_key_pem =
		format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----", private_key);
	let token = jsonwebtoken::encode(
		&jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES384),
		&action_data,
		&jsonwebtoken::EncodingKey::from_ec_pem(private_key_pem.as_bytes())
			.inspect_err(|err| error!("from_ec_pem err: {}", err))
			.map_err(|_| Error::PermissionDenied)?,
	)
	.inspect_err(|err| error!("encode err: {}", err))
	.map_err(|_| Error::PermissionDenied)?
	.into();

	Ok(token)
}

pub async fn generate_action_token(
	worker: &worker::WorkerPool,
	action_data: ActionToken,
	private_key: Box<str>,
) -> ClResult<Box<str>> {
	worker
		.try_run_immed(move || generate_action_token_sync(&action_data, &private_key))
		.await
}

// vim: ts=4
