//! ACME subsystem. Handles automatic certificate management using Let's Encrypt.

use axum::extract::State;
use axum::http::header::HeaderMap;
use instant_acme::{self as acme, Account};
use pem;
use rustls::crypto::CryptoProvider;
use rustls::sign::CertifiedKey;
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use serde_json;
use std::sync::Arc;
use x509_parser::parse_x509_certificate;

use crate::auth_adapter;
use crate::prelude::*;

#[derive(Debug)]
struct X509CertData {
	private_key_pem: Box<str>,
	certificate_pem: Box<str>,
	expires_at: Timestamp,
}

pub async fn init(
	state: App,
	acme_email: &str,
	id_tag: &str,
	app_domain: Option<&str>,
) -> ClResult<()> {
	info!("ACME init {}", acme_email);

	let (account, credentials) = Account::builder()?
		.create(
			&acme::NewAccount {
				contact: &[],
				terms_of_service_agreed: true,
				only_return_existing: false,
			},
			//acme::LetsEncrypt::Staging.url().to_owned(),
			acme::LetsEncrypt::Production.url().to_owned(),
			None,
		)
		.await?;
	info!("ACME credentials {}", serde_json::to_string_pretty(&credentials)?);

	renew_tenant(state, &account, id_tag, 1, app_domain).await?;

	Ok(())
}

pub async fn renew_tenant<'a>(
	state: App,
	account: &'a acme::Account,
	id_tag: &'a str,
	tn_id: u32,
	app_domain: Option<&'a str>,
) -> ClResult<()> {
	let mut domains: Vec<String> = vec!["cl-o.".to_string() + id_tag];
	if let Some(app_domain) = app_domain {
		domains.push(app_domain.to_string());
	} else {
		info!("cloudillo app domain: {}", &id_tag);
		domains.push(id_tag.into());
	}

	let cert = renew_domains(&state, account, domains).await?;
	info!("ACME cert {}", &cert.expires_at);
	state
		.auth_adapter
		.create_cert(&auth_adapter::CertData {
			tn_id: TnId(tn_id),
			id_tag: id_tag.into(),
			domain: app_domain.unwrap_or(id_tag).into(),
			key: cert.private_key_pem,
			cert: cert.certificate_pem,
			expires_at: cert.expires_at,
		})
		.await?;

	Ok(())
}

//async fn renew_domains<'a>(state: &'a App, account: &'a acme::Account, domains: Vec<String>) -> Result<X509CertData, Box<dyn std::error::Error + 'a>> {
async fn renew_domains<'a>(
	state: &'a App,
	account: &'a acme::Account,
	domains: Vec<String>,
) -> ClResult<X509CertData> {
	info!("ACME {:?}", &domains);
	let identifiers = domains
		.iter()
		.map(|domain| acme::Identifier::Dns(domain.to_string()))
		.collect::<Vec<_>>();

	let mut order = account.new_order(&acme::NewOrder::new(identifiers.as_slice())).await?;

	info!("ACME order {:#?}", order.state());

	if order.state().status == acme::OrderStatus::Pending {
		let mut authorizations = order.authorizations();
		while let Some(result) = authorizations.next().await {
			let mut authz = result?;
			match authz.status {
				acme::AuthorizationStatus::Pending => {}
				acme::AuthorizationStatus::Valid => continue,
				status => {
					// Log unexpected status and continue - may be Deactivated, Expired, or Revoked
					warn!("Unexpected ACME authorization status: {:?}", status);
					continue;
				}
			}

			let mut challenge = authz
				.challenge(acme::ChallengeType::Http01)
				.ok_or(acme::Error::Str("no challenge"))?;
			let identifier = challenge.identifier().to_string().into_boxed_str();
			let token: Box<str> = challenge.key_authorization().as_str().into();
			info!("ACME challenge {} {}", identifier, token);
			state
				.acme_challenge_map
				.write()
				.map_err(|_| {
					Error::ServiceUnavailable("failed to access ACME challenge map".into())
				})?
				.insert(identifier, token);

			challenge.set_ready().await?;
		}

		info!("Start polling...");
		let status = order.poll_ready(&acme::RetryPolicy::default()).await?;

		if status != acme::OrderStatus::Ready {
			Err(acme::Error::Str("order not ready"))?;
		}

		info!("Finalizing...");
		let private_key_pem = order.finalize().await?;
		let cert_chain_pem = order.poll_certificate(&acme::RetryPolicy::default()).await?;
		info!("Got cert.");

		// Clean up ACME challenges
		for domain in domains.iter() {
			state
				.acme_challenge_map
				.write()
				.map_err(|_| {
					Error::ServiceUnavailable("failed to access ACME challenge map".into())
				})?
				.remove(domain.as_str());
		}

		let pem = &pem::parse(&cert_chain_pem)?;
		let cert_der = pem.contents();
		let (_, parsed_cert) = parse_x509_certificate(cert_der)?;
		let not_after = parsed_cert.validity().not_after;

		let certified_key = Arc::new(CertifiedKey::from_der(
			vec![CertificateDer::from_pem_slice(cert_chain_pem.as_bytes())?],
			PrivateKeyDer::from_pem_slice(private_key_pem.as_bytes())?,
			CryptoProvider::get_default().ok_or(acme::Error::Str("no crypto provider"))?,
		)?);
		for domain in domains.iter() {
			state
				.certs
				.write()
				.map_err(|_| Error::ServiceUnavailable("failed to access cert cache".into()))?
				.insert(domain.clone().into_boxed_str(), certified_key.clone());
		}

		let cert_data = X509CertData {
			private_key_pem: private_key_pem.to_string().into_boxed_str(),
			certificate_pem: cert_chain_pem.to_string().into_boxed_str(),
			expires_at: Timestamp(not_after.timestamp()),
		};

		Ok(cert_data)
	} else {
		Err(Error::ConfigError("ACME initialization failed".into()))
	}
}

pub async fn get_acme_challenge(
	State(state): State<App>,
	headers: HeaderMap,
) -> ClResult<Box<str>> {
	let domain = headers
		.get("host")
		.ok_or(Error::ValidationError("missing host header".into()))?
		.to_str()?;
	info!("ACME challenge for domain {:?}", domain);

	if let Some(token) = state
		.acme_challenge_map
		.read()
		.map_err(|_| Error::ServiceUnavailable("failed to access ACME challenge map".into()))?
		.get(domain)
	{
		println!("    -> {:?}", &token);
		Ok(token.clone())
	} else {
		println!("    -> not found");
		Err(Error::PermissionDenied)
	}
}

// vim: ts=4
