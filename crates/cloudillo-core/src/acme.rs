//! ACME subsystem. Handles automatic certificate management using Let's Encrypt.

use axum::extract::State;
use axum::http::header::HeaderMap;
use instant_acme::{self as acme, Account};
use rustls::crypto::CryptoProvider;
use rustls::sign::CertifiedKey;
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use x509_parser::parse_x509_certificate;

use crate::prelude::*;
use crate::scheduler::{Task, TaskId};
use cloudillo_types::auth_adapter;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

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

	// Look up the actual tenant ID instead of hardcoding to 1
	let tn_id = state.auth_adapter.read_tn_id(id_tag).await?;
	renew_tenant(state, &account, id_tag, tn_id.0, app_domain).await?;

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
		.map(|domain| acme::Identifier::Dns(domain.clone()))
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
				.insert(identifier.clone(), token);

			challenge.set_ready().await?;
		}

		info!("Start polling...");
		// Create a more patient retry policy for Let's Encrypt validation
		// Initial delay: 1s, backoff: 1.5x, timeout: 90s
		// This gives LE plenty of time to validate multiple domains
		let retry_policy = acme::RetryPolicy::new()
			.initial_delay(std::time::Duration::from_secs(1))
			.backoff(1.5)
			.timeout(std::time::Duration::from_secs(90));

		let status = order.poll_ready(&retry_policy).await?;

		if status != acme::OrderStatus::Ready {
			// Fetch authorization details to see validation errors
			let mut authorizations = order.authorizations();
			while let Some(result) = authorizations.next().await {
				if let Ok(authz) = result {
					for challenge in &authz.challenges {
						if challenge.r#type == acme::ChallengeType::Http01 {
							if let Some(ref err) = challenge.error {
								warn!(
									"ACME validation failed for {}: {}",
									authz.identifier(),
									err.detail.as_deref().unwrap_or("unknown error")
								);
							}
						}
					}
				}
			}
			Err(acme::Error::Str("order not ready"))?;
		}

		info!("Finalizing...");
		let private_key_pem = order.finalize().await?;
		// Use the same patient retry policy for certificate polling
		let cert_chain_pem = order.poll_certificate(&retry_policy).await?;
		info!("Got cert.");

		// Clean up ACME challenges
		for domain in &domains {
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
			CertificateDer::pem_slice_iter(cert_chain_pem.as_bytes())
				.filter_map(Result::ok)
				.collect(),
			PrivateKeyDer::from_pem_slice(private_key_pem.as_bytes())?,
			CryptoProvider::get_default().ok_or(acme::Error::Str("no crypto provider"))?,
		)?);
		for domain in &domains {
			state
				.certs
				.write()
				.map_err(|_| Error::ServiceUnavailable("failed to access cert cache".into()))?
				.insert(domain.clone().into_boxed_str(), certified_key.clone());
		}

		let cert_data = X509CertData {
			private_key_pem: private_key_pem.clone().into_boxed_str(),
			certificate_pem: cert_chain_pem.clone().into_boxed_str(),
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

/// Renew the TLS certificate for a single proxy site via ACME.
///
/// Creates an ACME account, generates the certificate, stores it in the auth adapter,
/// and invalidates the cert cache. This is called inline from proxy site creation
/// and manual renewal endpoints, as well as from the periodic `CertRenewalTask`.
pub async fn renew_proxy_site_cert(app: &App, site_id: i64, domain: &str) -> ClResult<()> {
	let (account, _credentials) = Account::builder()?
		.create(
			&acme::NewAccount {
				contact: &[],
				terms_of_service_agreed: true,
				only_return_existing: false,
			},
			acme::LetsEncrypt::Production.url().to_owned(),
			None,
		)
		.await?;

	let domains = vec![domain.to_string()];
	let cert = renew_domains(app, &account, domains).await?;

	app.auth_adapter
		.update_proxy_site_cert(
			site_id,
			&cert.certificate_pem,
			&cert.private_key_pem,
			cert.expires_at,
		)
		.await?;

	// Note: renew_domains() already inserts the fresh cert into app.certs cache,
	// so no cache invalidation needed here.

	info!(domain = %domain, "Proxy site certificate renewed successfully");
	Ok(())
}

// Certificate Renewal Task
// ========================

/// Certificate renewal task
///
/// Checks all tenants for missing or expiring certificates and renews them.
/// Scheduled to run hourly via cron: "0 * * * *"
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertRenewalTask {
	/// Number of days before expiration to trigger renewal (default: 30)
	pub renewal_days: u32,
	/// ACME email for account creation
	pub acme_email: String,
}

impl CertRenewalTask {
	/// Create new certificate renewal task
	pub fn new(acme_email: String, renewal_days: u32) -> Self {
		Self { renewal_days, acme_email }
	}
}

#[async_trait]
impl Task<App> for CertRenewalTask {
	fn kind() -> &'static str {
		"acme.cert_renewal"
	}

	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, context: &str) -> ClResult<Arc<dyn Task<App>>> {
		let task: CertRenewalTask = serde_json::from_str(context).map_err(|e| {
			Error::ValidationError(format!("Failed to deserialize cert renewal task: {}", e))
		})?;
		Ok(Arc::new(task))
	}

	fn serialize(&self) -> String {
		serde_json::to_string(self)
			.unwrap_or_else(|_| format!("acme.cert_renewal:{}", self.renewal_days))
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		info!("Running certificate renewal check (renewal threshold: {} days)", self.renewal_days);

		// Get list of tenants needing renewal
		let tenants = app.auth_adapter.list_tenants_needing_cert_renewal(self.renewal_days).await?;

		if tenants.is_empty() {
			info!("All tenant certificates are valid");
		}

		if !tenants.is_empty() {
			info!("Found {} tenant(s) needing certificate renewal", tenants.len());

			// Renew certificates for each tenant
			for (tn_id, id_tag) in tenants {
				info!("Renewing certificate for tenant: {} (tn_id={})", id_tag, tn_id.0);

				// Determine app_domain (only base tenant gets custom domain)
				let app_domain = if tn_id.0 == 1 {
					// For base tenant, check if there's a custom domain configured
					// TODO: Get this from app configuration/settings
					None
				} else {
					None
				};

				// Perform ACME renewal
				match init(app.clone(), &self.acme_email, &id_tag, app_domain).await {
					Ok(()) => {
						info!(tenant = %id_tag, "Certificate renewed successfully");
					}
					Err(e) => {
						error!(tenant = %id_tag, error = %e, "Failed to renew certificate");
						// Continue with other tenants even if one fails
					}
				}
			}
		}

		// Renew proxy site certificates
		let proxy_sites = app
			.auth_adapter
			.list_proxy_sites_needing_cert_renewal(self.renewal_days)
			.await?;

		if !proxy_sites.is_empty() {
			info!("Found {} proxy site(s) needing certificate renewal", proxy_sites.len());

			for site in proxy_sites {
				info!(
					"Renewing certificate for proxy site: {} (site_id={})",
					site.domain, site.site_id
				);

				if let Err(e) = renew_proxy_site_cert(app, site.site_id, &site.domain).await {
					error!(
						domain = %site.domain,
						error = %e,
						"Failed to renew proxy site certificate"
					);
				}
			}
		}

		info!("Certificate renewal check completed");
		Ok(())
	}
}

/// Register ACME-related tasks with the scheduler
///
/// Must be called during app initialization before the scheduler starts loading tasks
pub fn register_tasks(app: &App) -> ClResult<()> {
	app.scheduler.register::<CertRenewalTask>()?;
	Ok(())
}

// vim: ts=4
