use std::fmt::Debug;
use std::any::Any;
use jsonwebtoken::{
	decode, encode, Algorithm, DecodingKey, EncodingKey
};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::Private;
use openssl::error::ErrorStack;

use cloudillo::worker::{Task, run};

#[derive(Default, Debug)]
struct GenerateKeyTask {
    private_key: Option<Box<str>>,
    public_key: Option<Box<str>>
}

impl Task for GenerateKeyTask {
    fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
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

        self.private_key = Some(private_key.into());
        self.public_key = Some(public_key.into());
        Ok(())
    }
	fn into_any(self: Box<Self>) -> Box<dyn Any> { self }
}

pub async fn generate_key() -> Result<(Box<str>, Box<str>), Box<dyn std::error::Error>> {
    if let Ok(task) = run(Box::new(GenerateKeyTask::default())).await {
        Ok((task.private_key.unwrap().into(), task.public_key.unwrap().into()))
    } else {
        Err("Failed to generate key".into())
    }
}

// vim: ts=4
