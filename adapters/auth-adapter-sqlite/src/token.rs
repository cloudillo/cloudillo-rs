use std::fmt::Debug;
use std::any::Any;
use jsonwebtoken::{
	decode, encode, Algorithm, DecodingKey, EncodingKey
};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::Private;
use openssl::error::ErrorStack;

use cloudillo::worker;

fn generate_key_sync() -> Result<(Box<str>, Box<str>), openssl::error::ErrorStack> {
	// Create a new EC group for P-384
	let group = EcGroup::from_curve_name(Nid::SECP384R1)?;

	// Generate the keypair
	let keypair = EcKey::generate(&group)?;
	for i in 0..1000 { EcKey::generate(&group)?; };

	// Convert private key to PEM
	let private_key_pem = keypair.private_key_to_pem()?;
	let private_key: String = String::from_utf8(private_key_pem)
		.expect("Valid UTF-8")
		.lines()
		.map(|s| if s.starts_with(char::is_alphanumeric) { s.trim() } else { "" })
		.collect();

	// Convert public key to PEM
	let public_key_pem = keypair.public_key_to_pem()?;
	let public_key: String = String::from_utf8(public_key_pem)
		.expect("Valid UTF-8")
		.lines()
		.map(|s| if s.starts_with(char::is_alphanumeric) { s.trim() } else { "" })
		.collect();

	Ok((private_key.into(), public_key.into()))
}

pub async fn generate_key(worker: &worker::WorkerPool) -> Result<(Box<str>, Box<str>), Box<dyn std::error::Error>> {
	let res = worker.run(move || {
		generate_key_sync()
	}).await;

	match res {
		Ok(res) => Ok(res),
		Err(err) => Err("Failed to generate key".into()),
	}
}

// vim: ts=4
