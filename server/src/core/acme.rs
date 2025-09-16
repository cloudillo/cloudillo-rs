use std::{
	collections::HashMap,
	sync::Arc,
};
use axum::extract::{Path, State};
use axum::http::header::HeaderMap;
use instant_acme::{self as acme, Account};
use serde_json;
use rustls::crypto::{CryptoProvider, aws_lc_rs};
use rustls::sign::CertifiedKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use pem;
use x509_parser::{parse_x509_certificate, pem::Pem};

use crate::AppState;
use crate::auth_adapter;
use crate::error::{Error, Result};
use crate::types::{TnId, Timestamp};

#[derive(Debug)]
struct X509CertData {
	private_key_pem: Box<str>,
	certificate_pem: Box<str>,
	certified_key: Arc<CertifiedKey>,
	expires_at: Timestamp,
}

struct TenantCertData {
	id_tag: Box<str>,
	tn_id: TnId,
	app_domain: Option<Box<str>>,
	cert_data: X509CertData,
}

pub async fn init(state: Arc<AppState>, acme_email: &str, id_tag: &str, app_domain: Option<&str>) -> Result<()> {
	println!("ACME init {}", acme_email);

	let (account, credentials) = Account::builder().map_err(|_| Error::Unknown)?.create(
		&acme::NewAccount {
			contact: &[],
			terms_of_service_agreed: true,
			only_return_existing: false,
		},
		//acme::LetsEncrypt::Staging.url().to_owned(),
		acme::LetsEncrypt::Production.url().to_owned(),
		None,
	).await.map_err(|_| Error::Unknown)?;
	println!("ACME credentials {}", serde_json::to_string_pretty(&credentials).map_err(|_| Error::Unknown)?);

	renew_tenant(state, &account, id_tag, 1, app_domain).await.map_err(|_| Error::Unknown)?;

	Ok(())
}

pub async fn renew_tenant<'a>(state: Arc<AppState>, account: &'a acme::Account, id_tag: &'a str, tn_id: u32, app_domain: Option<&'a str>) -> Result<()> {
	let mut domains: Vec<String> = vec!["cl-o.".to_string() + &id_tag];
	if let Some(app_domain) = app_domain {
		domains.push(app_domain.to_string());
	} else {
		println!("cloudillo app domain: {}", &id_tag);
		domains.push(id_tag.into());
	}

	let cert = renew_domains(&state, &account, domains).await.map_err(|_| Error::Unknown)?;
	println!("ACME cert {}", &cert.expires_at);
	state.auth_adapter.create_cert(&auth_adapter::CertData {
		tn_id,
		id_tag: id_tag.into(),
		domain: app_domain.unwrap_or(&id_tag).into(),
		key: cert.private_key_pem.into(),
		cert: cert.certificate_pem.into(),
		expires_at: cert.expires_at,
	}).await?;
	
	Ok(())
}

//pub async fn renew_domains(state: &Arc<AppState>, account: &acme::Account, domains: impl Iterator<Item = &String>) -> std::result::Result<(), acme::Error> {
async fn renew_domains<'a>(state: &'a Arc<AppState>, account: &'a acme::Account, domains: Vec<String>) -> std::result::Result<X509CertData, Box<dyn std::error::Error + 'a>> {
	println!("ACME {:?}", &domains);
	let identifiers = domains.iter().map(|domain| acme::Identifier::Dns(domain.to_string())).collect::<Vec<_>>();

	let mut order = account.new_order(&acme::NewOrder::new(identifiers.as_slice())).await?;

	println!("ACME order {:#?}", order.state());

	if order.state().status == acme::OrderStatus::Pending {
		let mut authorizations = order.authorizations();
		while let Some(result) = authorizations.next().await {
			let mut authz = result?;
			match authz.status {
				acme::AuthorizationStatus::Pending => {}
				acme::AuthorizationStatus::Valid => continue,
				_ => todo!(),
			}

			let mut challenge = authz.challenge(acme::ChallengeType::Http01).ok_or(acme::Error::Str("no challenge"))?;
			let identifier = challenge.identifier().to_string().into_boxed_str();
			let token: Box<str> = challenge.key_authorization().as_str().into();
			println!("ACME challenge {} {}", identifier, token);
			state.acme_challenge_map.lock()?.insert(identifier, token);

			challenge.set_ready().await?;
		}

		println!("Start polling...");
		let status = order.poll_ready(&acme::RetryPolicy::default()).await?;

		if status != acme::OrderStatus::Ready {
			Err(acme::Error::Str("order not ready"))?;
		}

		println!("Finalizing...");
		let private_key_pem = order.finalize().await?;
		let cert_chain_pem = order.poll_certificate(&acme::RetryPolicy::default()).await?;
		println!("Got cert.");

		// Clean up ACME challenges
		for domain in domains.iter() {
			state.acme_challenge_map.lock()?.remove(&*domain.as_str());
		}

		let pem = &pem::parse(&cert_chain_pem).map_err(|_| Error::Unknown)?;
		let cert_der = pem.contents();
		let (_, parsed_cert) = parse_x509_certificate(&cert_der)?;
		let not_after = parsed_cert.validity().not_after;

		let certified_key = Arc::new(CertifiedKey::from_der(
			vec![CertificateDer::from_pem_slice(cert_chain_pem.as_bytes())?],
			PrivateKeyDer::from_pem_slice(&private_key_pem.as_bytes())?,
			CryptoProvider::get_default().ok_or(acme::Error::Str("no crypto provider"))?,
		)?);
		/*
		for domain in domains.iter() {
			state.cert_resolver.insert(domain.clone().into_boxed_str(), certified_key.clone());
		}
		*/

		let cert_data = X509CertData {
			private_key_pem: private_key_pem.to_string().into_boxed_str(),
			certificate_pem: cert_chain_pem.to_string().into_boxed_str(),
			certified_key,
			expires_at: not_after.timestamp() as Timestamp,
		};

		Ok(cert_data)
	} else {
		Err(Error::Unknown.into())
	}
}

pub async fn get_acme_challenge(
	State(state): State<Arc<AppState>>,
	//HeaderName(host): HeaderName,
	headers: HeaderMap,
) -> Result<Box<str>> {
	let domain = headers.get("host").ok_or(Error::Unknown)?.to_str().map_err(|_| Error::Unknown)?;
	println!("ACME challenge for domain {:?}", domain);

	if let Some(token) = state.acme_challenge_map.lock().map_err(|_| Error::Unknown)?.get(&*domain).clone() {
		println!("    -> {:?}", &token);
		Ok(token.clone())
	} else {
		println!("    -> not found");
		Err(Error::PermissionDenied)
	}
}

// vim: ts=4
