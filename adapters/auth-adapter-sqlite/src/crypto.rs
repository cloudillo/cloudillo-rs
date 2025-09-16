use bcrypt;
use jsonwebtoken;
//use openssl::{ec::{EcGroup, EcKey}, nid::Nid, pkey::Private, error::ErrorStack};
use p384::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use p384::{SecretKey, elliptic_curve::rand_core::{CryptoRngCore, OsRng}};
use zeroize::Zeroizing;

use serde::{Serialize, Deserialize};

use cloudillo::{auth_adapter, core::worker, Result, Error};

pub fn generate_password_hash(password: &str) -> Result<Box<str>> {
	let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|_| Error::PermissionDenied)?;

	Ok(hash.into())
	//bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|_| Error::PermissionDenied)?.into()
}

pub fn check_password(password: &str, password_hash: &str) -> Result<()> {
	//let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|_| Error::PermissionDenied)?;
	//println!("{} {} {:?}", password, hash, bcrypt::verify(password, password_hash).map_err(|_| Error::PermissionDenied));
	let res = bcrypt::verify(password, password_hash).map_err(|_| Error::PermissionDenied)?;
	if (!res) { return Err(Error::PermissionDenied); }

	Ok(())
}

/*
fn generate_key_sync() -> Result<(Box<str>, Box<str>)> {
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

pub struct KeyPair {
	//pub private_key: Zeroizing<String>,
	pub private_key: Box<str>,
	pub public_key: Box<str>,
}

fn generate_key_sync() -> Result<KeyPair> {
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

	Ok(KeyPair { private_key, public_key })
}

pub async fn generate_key(worker: &worker::WorkerPool) -> Result<KeyPair> {
	worker.run(move || {
		generate_key_sync()
	}).await.map_err(|_| Error::PermissionDenied)
}

// vim: ts=4
