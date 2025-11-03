const TOKEN_EXPIRE: u64 = 8; /* hours */
const BCRYPT_COST: u32 = 10;

use p384::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use p384::{elliptic_curve::rand_core::OsRng, SecretKey};

use cloudillo::{auth_adapter::*, core::worker, prelude::*};

fn generate_password_hash_sync(password: Box<str>) -> ClResult<Box<str>> {
	let hash = bcrypt::hash(password.as_ref(), BCRYPT_COST).map_err(|_| Error::PermissionDenied)?;

	Ok(hash.into())
}

pub async fn generate_password_hash(
	worker: &worker::WorkerPool,
	password: Box<str>,
) -> ClResult<Box<str>> {
	worker
		.run_immed(move || generate_password_hash_sync(password))
		.await
		.map_err(|_| Error::PermissionDenied)
}

fn check_password_sync(password: Box<str>, password_hash: Box<str>) -> ClResult<()> {
	let res =
		bcrypt::verify(password.as_ref(), &password_hash).map_err(|_| Error::PermissionDenied)?;
	if !res {
		Err(Error::PermissionDenied)
	} else {
		Ok(())
	}
}

pub async fn check_password(
	worker: &worker::WorkerPool,
	password: Box<str>,
	password_hash: Box<str>,
) -> ClResult<()> {
	worker
		.run_immed(move || check_password_sync(password, password_hash))
		.await
		.map_err(|_| Error::PermissionDenied)
}

fn generate_access_token_sync(
	access_token: AccessToken<Box<str>>,
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
		.run_immed(move || generate_access_token_sync(access_token, &jwt_secret))
		.await
		.map_err(|_| Error::PermissionDenied)
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
		.map(|s| if s.starts_with(char::is_alphanumeric) { s.trim() } else { "" })
		.collect();
	let public_key: Box<str> = public
		.to_public_key_pem(LineEnding::LF)
		.map_err(|_| Error::PermissionDenied)?
		.lines()
		.map(|s| if s.starts_with(char::is_alphanumeric) { s.trim() } else { "" })
		.collect();

	Ok(KeyPair { private_key, public_key })
}

/// Generate a keypair
pub async fn generate_key(worker: &worker::WorkerPool) -> ClResult<KeyPair> {
	worker.run_immed(generate_key_sync).await.map_err(|_| Error::PermissionDenied)
}

fn generate_action_token_sync(
	action_data: ActionToken,
	private_key: Box<str>,
) -> ClResult<Box<str>> {
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
		.run_immed(move || generate_action_token_sync(action_data, private_key))
		.await
		.map_err(|_| Error::PermissionDenied)
}

// vim: ts=4
