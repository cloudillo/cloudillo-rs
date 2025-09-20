const TOKEN_EXPIRE: u64 = 8; /* hours */
const BCRYPT_COST: u32 = 10;

use p384::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use p384::{SecretKey, elliptic_curve::rand_core::{CryptoRngCore, OsRng}};
use zeroize::Zeroizing;

use serde::{Serialize, Deserialize};

use cloudillo::{
	prelude::*,
	auth_adapter,
	core::worker,
};

pub fn generate_password_hash(password: &str) -> ClResult<Box<str>> {
	let hash = bcrypt::hash(password, BCRYPT_COST).map_err(|_| Error::PermissionDenied)?;

	Ok(hash.into())
}

pub fn check_password(password: Box<str>, password_hash: Box<str>) -> ClResult<()> {
	let res = bcrypt::verify(&*password, &password_hash).map_err(|_| Error::PermissionDenied)?;
	if (!res) { return Err(Error::PermissionDenied); }

	Ok(())
}

pub fn generate_access_token(tn_id: u32, roles: Option<&str>) -> ClResult<Box<str>> {
	let expire = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH).map_err(|_| Error::PermissionDenied)?
		.as_secs() + 3600 * TOKEN_EXPIRE;

	let token = jsonwebtoken::encode(
		&jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
		&auth_adapter::AuthToken::<&str> {
			sub: tn_id,
			exp: expire as u32,
			r: roles,
		},
		&jsonwebtoken::EncodingKey::from_secret("FIXME secret".as_bytes()),
	).map_err(|_| Error::PermissionDenied)?.into();

	Ok(token)
}

/*
fn generate_key_sync() -> ClResult<(Box<str>, Box<str>)> {
	// Create a new EC group for P-384
	let group = EcGroup::from_curve_name(Nid::SECP384R1).map_err(|_| Error::PermissionDenied)?;

	// Generate the keypair
	let keypair = EcKey::generate(&group).map_err(|_| Error::PermissionDenied)?;
	//for i in 0..1000 { EcKey::generate(&group)?; };

	// Convert private key to PEM
	let private_key_pem = keypair.private_key_to_pem().map_err(|_| Error::PermissionDenied)?;
	let private_key: String = String::from_utf8(private_key_pem).map_err(|_| Error::PermissionDenied)?
		.lines()
		.map(|s| if s.starts_with(char::is_alphanumeric) { s.trim() } else { "" })
		.collect();

	// Convert public key to PEM
	let public_key_pem = keypair.public_key_to_pem().map_err(|_| Error::PermissionDenied)?;
	let public_key: String = String::from_utf8(public_key_pem).map_err(|_| Error::PermissionDenied)?
		.lines()
		.map(|s| if s.starts_with(char::is_alphanumeric) { s.trim() } else { "" })
		.collect();

	Ok((private_key.into(), public_key.into()))
}
*/

fn generate_key_sync() -> ClResult<auth_adapter::KeyPair> {
	let private = SecretKey::random(&mut OsRng);
	let public = private.public_key();

	//let private_key = private.to_pkcs8_pem(LineEnding::LF).map_err(|_| Error::PermissionDenied)?;
	let private_key: Box<str> = private.to_pkcs8_pem(LineEnding::LF).map_err(|_| Error::PermissionDenied)?
		.lines()
		.map(|s| if s.starts_with(char::is_alphanumeric) { s.trim() } else { "" })
		.collect();
	let public_key: Box<str> = public.to_public_key_pem(LineEnding::LF).map_err(|_| Error::PermissionDenied)?
		.lines()
		.map(|s| if s.starts_with(char::is_alphanumeric) { s.trim() } else { "" })
		.collect();

	Ok(auth_adapter::KeyPair { private_key, public_key })
}

pub async fn generate_key(worker: &worker::WorkerPool) -> ClResult<auth_adapter::KeyPair> {
	worker.run(move || {
		generate_key_sync()
	}).await.map_err(|_| Error::PermissionDenied)
}

// vim: ts=4
