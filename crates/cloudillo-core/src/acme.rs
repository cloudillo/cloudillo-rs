// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! ACME subsystem. Handles automatic certificate management using Let's Encrypt.

use axum::extract::State;
use axum::http::header::HeaderMap;
use instant_acme::{self as acme, Account};
use rustls::crypto::CryptoProvider;
use rustls::sign::CertifiedKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::sync::Arc;
use x509_parser::parse_x509_certificate;

use crate::dns::{DnsResolver, create_recursive_resolver, validate_domain_address};
use crate::prelude::*;
use crate::scheduler::{Task, TaskId};
use crate::{ScheduleEmailFn, ScheduleEmailParams};
use cloudillo_types::auth_adapter::{self, TenantCertRenewalRow};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
struct X509CertData {
	private_key_pem: Box<str>,
	certificate_pem: Box<str>,
	expires_at: Timestamp,
}

/// Vars-table key for the persisted ACME account credentials. Stored under
/// `TnId(0)` (global), matching the convention used for other server-wide
/// secrets like `0:jwt_secret`.
const ACME_ACCOUNT_VAR: &str = "acme_account";

/// Load the persisted ACME account, or create a new one and persist its
/// credentials on first use. Without persistence we'd hit Let's Encrypt's
/// per-IP account-creation rate limit on every renewal cycle and leak the
/// account key into the log on every call.
async fn get_or_create_acme_account(state: &App, acme_email: &str) -> ClResult<Account> {
	match state.auth_adapter.read_var(TnId(0), ACME_ACCOUNT_VAR).await {
		Ok(json) => {
			let credentials: acme::AccountCredentials = serde_json::from_str(&json)
				.map_err(|_| Error::Internal("corrupt ACME credentials in vars".into()))?;
			Ok(Account::builder()?.from_credentials(credentials).await?)
		}
		Err(Error::NotFound) => {
			info!("Creating new ACME account for {}", acme_email);
			let contact = format!("mailto:{}", acme_email);
			let (account, credentials) = Account::builder()?
				.create(
					&acme::NewAccount {
						contact: &[&contact],
						terms_of_service_agreed: true,
						only_return_existing: false,
					},
					acme::LetsEncrypt::Production.url().to_owned(),
					None,
				)
				.await?;
			let json = serde_json::to_string(&credentials)?;
			state.auth_adapter.update_var(TnId(0), ACME_ACCOUNT_VAR, &json).await?;
			Ok(account)
		}
		Err(e) => Err(e),
	}
}

pub async fn init(
	state: App,
	acme_email: &str,
	id_tag: &str,
	app_domain: Option<&str>,
) -> ClResult<()> {
	info!("ACME init {}", acme_email);
	let account = get_or_create_acme_account(&state, acme_email).await?;

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
			last_renewal_attempt_at: None,
			last_renewal_error: None,
			failure_count: 0,
			notified_at: None,
		})
		.await?;

	Ok(())
}

async fn renew_domains<'a>(
	state: &'a App,
	account: &'a acme::Account,
	domains: Vec<String>,
) -> ClResult<X509CertData> {
	// Track every identifier we actually inserted into acme_challenge_map so
	// we can remove the exact same keys on cleanup. The ACME server is free
	// to normalize identifiers (case, trailing dots) and using the input
	// `domains` list for removal could miss them.
	let mut inserted_identifiers: Vec<Box<str>> = Vec::new();
	let result = renew_domains_inner(state, account, &domains, &mut inserted_identifiers).await;

	// Always clean up challenges, on both success and failure paths.
	if let Ok(mut map) = state.acme_challenge_map.write() {
		for ident in &inserted_identifiers {
			map.remove(ident.as_ref());
		}
	} else {
		warn!("ACME: failed to access challenge map for cleanup");
	}

	result
}

async fn renew_domains_inner<'a>(
	state: &'a App,
	account: &'a acme::Account,
	domains: &'a [String],
	inserted_identifiers: &'a mut Vec<Box<str>>,
) -> ClResult<X509CertData> {
	info!("ACME {:?}", domains);
	let identifiers = domains
		.iter()
		.map(|domain| acme::Identifier::Dns(domain.clone()))
		.collect::<Vec<_>>();

	let mut order = account.new_order(&acme::NewOrder::new(identifiers.as_slice())).await?;

	info!("ACME order {:#?}", order.state());

	let initial_status = order.state().status;
	// `Pending` is the normal first-time path. `Ready` can happen when LE has
	// already validated authorizations on a recent retry — finalize directly.
	// Anything else (Valid/Invalid/Processing) is unexpected and should fail.
	match initial_status {
		acme::OrderStatus::Pending => {
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
				let identifier: Box<str> = challenge.identifier().to_string().into_boxed_str();
				let token: Box<str> = challenge.key_authorization().as_str().into();
				info!("ACME challenge {} {}", identifier, token);
				state
					.acme_challenge_map
					.write()
					.map_err(|_| {
						Error::ServiceUnavailable("failed to access ACME challenge map".into())
					})?
					.insert(identifier.clone(), token);
				inserted_identifiers.push(identifier);

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
							if challenge.r#type == acme::ChallengeType::Http01
								&& let Some(ref err) = challenge.error
							{
								warn!(
									"ACME validation failed for {}: {}",
									authz.identifier(),
									err.detail.as_deref().unwrap_or("unknown error")
								);
							}
						}
					}
				}
				Err(acme::Error::Str("order not ready"))?;
			}
		}
		acme::OrderStatus::Ready => {
			info!("ACME order already Ready - skipping authorization phase");
		}
		other => {
			warn!("Unexpected ACME order status on creation: {:?}", other);
			return Err(Error::ConfigError("ACME initialization failed".into()));
		}
	}

	let retry_policy = acme::RetryPolicy::new()
		.initial_delay(std::time::Duration::from_secs(1))
		.backoff(1.5)
		.timeout(std::time::Duration::from_secs(90));

	info!("Finalizing...");
	let private_key_pem = order.finalize().await?;
	let cert_chain_pem = order.poll_certificate(&retry_policy).await?;
	info!("Got cert.");

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
	for domain in domains {
		state
			.certs
			.write()
			.map_err(|_| Error::ServiceUnavailable("failed to access cert cache".into()))?
			.insert(domain.clone().into_boxed_str(), certified_key.clone());
	}

	let cert_data = X509CertData {
		private_key_pem: private_key_pem.into_boxed_str(),
		certificate_pem: cert_chain_pem.into_boxed_str(),
		expires_at: Timestamp(not_after.timestamp()),
	};

	Ok(cert_data)
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
		debug!("ACME challenge served for {}", domain);
		Ok(token.clone())
	} else {
		debug!("ACME challenge not found for {}", domain);
		Err(Error::PermissionDenied)
	}
}

/// Renew the TLS certificate for a single proxy site via ACME.
///
/// Loads the persisted ACME account (creating it on first use), generates the
/// certificate, stores it in the auth adapter, and invalidates the cert cache.
/// Called inline from proxy site creation and manual renewal endpoints, as
/// well as from the periodic `CertRenewalTask`.
pub async fn renew_proxy_site_cert(
	app: &App,
	acme_email: &str,
	site_id: i64,
	domain: &str,
) -> ClResult<()> {
	let account = get_or_create_acme_account(app, acme_email).await?;

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
		// Cannot fail: only String and u32 fields, no custom Serialize impl.
		// Fallback to "null" so build() fails loudly rather than creating a
		// corrupt task with default values.
		serde_json::to_string(self).unwrap_or_else(|_| "null".to_string())
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		info!("Running certificate renewal check (renewal threshold: {} days)", self.renewal_days);

		let tenants = app.auth_adapter.list_tenants_needing_cert_renewal(self.renewal_days).await?;
		let proxy_sites = app
			.auth_adapter
			.list_proxy_sites_needing_cert_renewal(self.renewal_days)
			.await?;

		if tenants.is_empty() && proxy_sites.is_empty() {
			info!("All certificates are valid");
			return Ok(());
		}

		// Single resolver for the whole batch — same pattern as register.rs
		let resolver = match create_recursive_resolver() {
			Ok(r) => r,
			Err(e) => {
				error!(error = %e, "Cannot create DNS resolver; skipping renewal run");
				return Ok(());
			}
		};

		if !tenants.is_empty() {
			info!("Found {} tenant(s) needing certificate renewal", tenants.len());
			for row in tenants {
				let app_domain: Option<&str> = None; // No custom domain support yet
				let domains = build_domains_for_tenant(&row.id_tag, app_domain);

				match check_domains_dns(&domains, &app.opts.local_address, &resolver).await {
					Ok(()) => {}
					Err(PreCheckError::Definitive(reason)) => {
						warn!(
							tn_id = %row.tn_id.0,
							id_tag = %row.id_tag,
							reason = %reason,
							"Skipping ACME renewal: DNS pre-check failed"
						);
						handle_renewal_failure(app, &row, &reason).await;
						continue;
					}
					Err(PreCheckError::Transient(reason)) => {
						warn!(
							tn_id = %row.tn_id.0,
							id_tag = %row.id_tag,
							reason = %reason,
							"Skipping ACME renewal this run: transient DNS resolver error \
							 (not counted as failure)"
						);
						continue;
					}
				}

				info!("Renewing certificate for tenant: {} (tn_id={})", row.id_tag, row.tn_id.0);
				match init(app.clone(), &self.acme_email, &row.id_tag, app_domain).await {
					Ok(()) => {
						info!(tn_id = %row.tn_id.0, id_tag = %row.id_tag,
							"Certificate renewed successfully");
						handle_renewal_success(app, &row, false).await;
					}
					Err(e) => {
						let reason = format!("acme: {}", e);
						error!(tn_id = %row.tn_id.0, id_tag = %row.id_tag, error = %reason,
							"Failed to renew certificate");
						handle_renewal_failure(app, &row, &reason).await;
					}
				}
			}
		}

		if !proxy_sites.is_empty() {
			info!("Found {} proxy site(s) needing certificate renewal", proxy_sites.len());

			for site in proxy_sites {
				let domains: Vec<String> = vec![site.domain.to_string()];
				match check_domains_dns(&domains, &app.opts.local_address, &resolver).await {
					Ok(()) => {}
					Err(PreCheckError::Definitive(reason)) => {
						warn!(
							domain = %site.domain,
							reason = %reason,
							"Skipping ACME renewal for proxy site: DNS pre-check failed"
						);
						continue;
					}
					Err(PreCheckError::Transient(reason)) => {
						warn!(
							domain = %site.domain,
							reason = %reason,
							"Skipping ACME renewal for proxy site this run: transient DNS \
							 resolver error"
						);
						continue;
					}
				}

				info!(
					"Renewing certificate for proxy site: {} (site_id={})",
					site.domain, site.site_id
				);

				if let Err(e) =
					renew_proxy_site_cert(app, &self.acme_email, site.site_id, &site.domain).await
				{
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

/// One-shot retry of `acme::init` for a single tenant, scheduled by bootstrap
/// when the at-registration ACME attempt fails. Coordinated with the daily
/// `CertRenewalTask` only by the in-task `read_cert_by_tn_id` short-circuit:
/// each retry checks first whether a cert was installed since it was queued,
/// and if so exits without contacting the ACME directory.
///
/// Three of these are typically queued at 2 / 5 / 15-minute delays. They
/// survive process restart (unlike the previous `tokio::spawn` approach), and
/// the per-key dedup in the scheduler stops repeated bootstrap-failure events
/// from stacking duplicate retries on top of each other.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcmeEarlyRetryTask {
	pub tn_id: TnId,
	pub acme_email: String,
	pub id_tag: String,
	pub app_domain: Option<String>,
}

#[async_trait]
impl Task<App> for AcmeEarlyRetryTask {
	fn kind() -> &'static str {
		"acme.early_retry"
	}

	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, context: &str) -> ClResult<Arc<dyn Task<App>>> {
		let task: AcmeEarlyRetryTask = serde_json::from_str(context).map_err(|e| {
			Error::ValidationError(format!("Failed to deserialize early retry task: {}", e))
		})?;
		Ok(Arc::new(task))
	}

	fn serialize(&self) -> String {
		// Same as CertRenewalTask::serialize — no fallible field types.
		serde_json::to_string(self).unwrap_or_else(|_| "null".to_string())
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		// `read_cert_by_tn_id` filters `cert IS NOT NULL AND key IS NOT NULL`,
		// so Ok(_) ⇒ cert installed (by an earlier retry or the daily renewal
		// task) and we should stop. Err(NotFound) ⇒ proceed.
		if app.auth_adapter.read_cert_by_tn_id(self.tn_id).await.is_ok() {
			info!(id_tag = %self.id_tag,
				"ACME early retry: cert already present, skipping");
			return Ok(());
		}
		info!(id_tag = %self.id_tag, "ACME early retry attempt");
		match init(app.clone(), &self.acme_email, &self.id_tag, self.app_domain.as_deref()).await {
			Ok(()) => {
				info!(id_tag = %self.id_tag, "ACME early retry succeeded");
				let row = TenantCertRenewalRow {
					tn_id: self.tn_id,
					id_tag: self.id_tag.clone().into(),
					expires_at: None,
					failure_count: 0,
					last_renewal_error: None,
					notified_at: None,
				};
				handle_renewal_success(app, &row, true).await;
				Ok(())
			}
			Err(e) => {
				warn!(error = %e, id_tag = %self.id_tag, "ACME early retry failed");
				// Surface the error so the scheduler records the failure, but
				// the other queued retries (separate tasks) still fire.
				Err(e)
			}
		}
	}
}

/// Register ACME-related tasks with the scheduler
///
/// Must be called during app initialization before the scheduler starts loading tasks
pub fn register_tasks(app: &App) -> ClResult<()> {
	app.scheduler.register::<CertRenewalTask>()?;
	app.scheduler.register::<AcmeEarlyRetryTask>()?;
	Ok(())
}

// ============================================================================
// DNS pre-check + renewal-failure tracking helpers
// ============================================================================

const RENEWAL_NOTIFY_LONG_INTERVAL_SECS: i64 = 7 * 86400;
const RENEWAL_NOTIFY_SHORT_INTERVAL_SECS: i64 = 86400;

/// Build the list of domains a tenant cert needs to cover. Mirrors the logic
/// in `renew_tenant`.
fn build_domains_for_tenant(id_tag: &str, app_domain: Option<&str>) -> Vec<String> {
	let mut domains = vec![format!("cl-o.{}", id_tag)];
	domains.push(app_domain.unwrap_or(id_tag).to_string());
	domains
}

/// Outcome of a DNS pre-check. Definitive failures (`"nodns"`, `"address"`)
/// are deterministic — the tenant's DNS is genuinely misconfigured — so they
/// escalate to suspension/notification. Transient failures (resolver network
/// errors, timeouts) are not the tenant's fault; the renewal is skipped this
/// run but failure_count / suspension state is left untouched so a flaky
/// resolver around expiry can't push a healthy tenant into Suspended.
enum PreCheckError {
	Definitive(String),
	Transient(String),
}

/// DNS pre-check for every domain in the list. Returns the error code
/// (`"nodns"` or `"address"`, matching `register.rs` conventions) on the
/// first definitive failure, or a transient error wrapping the underlying
/// resolver error. If `local_address` is empty (e.g., local dev), the check
/// is skipped — same as `register.rs` does.
async fn check_domains_dns(
	domains: &[String],
	local_address: &[Box<str>],
	resolver: &DnsResolver,
) -> Result<(), PreCheckError> {
	if local_address.is_empty() {
		return Ok(());
	}
	for domain in domains {
		match validate_domain_address(domain, local_address, resolver).await {
			Ok(_) => {}
			Err(Error::ValidationError(code)) => return Err(PreCheckError::Definitive(code)),
			Err(e) => return Err(PreCheckError::Transient(format!("{}", e))),
		}
	}
	Ok(())
}

pub async fn handle_renewal_success(
	app: &App,
	row: &TenantCertRenewalRow,
	is_first_issuance: bool,
) {
	if let Err(e) = app.auth_adapter.record_cert_renewal_success(row.tn_id).await {
		warn!(tn_id = %row.tn_id.0, id_tag = %row.id_tag, error = %e,
			"Failed to record renewal success");
	}
	// Only flip status back to active when this row was previously suspended
	// (i.e. its prior cert was past expiry). Calling `update_tenant_status('A')`
	// unconditionally would bump `tenants.updated_at` on every nightly run for
	// every healthy tenant.
	let is_currently_expired = row.expires_at.is_some_and(|t| t.0 < Timestamp::now().0);
	if is_currently_expired {
		if let Err(e) = app.auth_adapter.update_tenant_status(row.tn_id, 'A').await {
			warn!(tn_id = %row.tn_id.0, id_tag = %row.id_tag, error = %e,
				"Failed to clear suspended status after renewal");
		} else {
			info!(tn_id = %row.tn_id.0, id_tag = %row.id_tag,
				"Tenant un-suspended after successful cert renewal");
		}
	}

	// First-issuance hook: only fire when the caller passed
	// `is_first_issuance = true` (currently only the bootstrap synthetic-row
	// paths). The daily renewal task passes `false` here, so a row whose
	// `expires_at` is somehow NULL for a non-first reason will not re-fire
	// the hook.
	if is_first_issuance
		&& let Ok(hook) = app.ext::<crate::OnFirstCertIssuedFn>()
		&& let Err(e) = hook(app, row.tn_id, &row.id_tag).await
	{
		warn!(tn_id = %row.tn_id.0, id_tag = %row.id_tag, error = %e,
			"on_first_cert_issued hook failed");
	}
}

async fn handle_renewal_failure(app: &App, row: &TenantCertRenewalRow, reason: &str) {
	// Always record the failure so we have a counter, even on the
	// initial-bootstrap path (no cert yet). The adapter upserts the row.
	if let Err(e) = app.auth_adapter.record_cert_renewal_failure(row.tn_id, reason).await {
		warn!(tn_id = %row.tn_id.0, id_tag = %row.id_tag, error = %e,
			"Failed to record renewal failure");
	}

	let now = Timestamp::now().0;

	let (days_until_expiry, already_expired) = match row.expires_at {
		Some(expires_at) => {
			let days = (expires_at.0 - now) / 86400;
			(days, days <= 0)
		}
		// No cert yet — treat as already-expired for suspension/notify cadence.
		None => (0, true),
	};

	// Suspend the tenant once the cert is past expiry (or absent). Flipping an
	// already-suspended tenant to 'S' is a no-op; we never downgrade here.
	if already_expired && let Err(e) = app.auth_adapter.update_tenant_status(row.tn_id, 'S').await {
		warn!(tn_id = %row.tn_id.0, id_tag = %row.id_tag, error = %e,
			"Failed to mark tenant suspended");
	}

	let should_notify = should_notify(row, now, days_until_expiry);
	if !should_notify {
		return;
	}

	let expires_at = row.expires_at.unwrap_or(Timestamp(now));
	if let Err(e) = schedule_renewal_failure_email(
		app,
		row,
		reason,
		expires_at,
		days_until_expiry,
		already_expired,
	)
	.await
	{
		warn!(tn_id = %row.tn_id.0, id_tag = %row.id_tag, error = %e,
			"Failed to schedule renewal-failure email");
		return;
	}

	if let Err(e) = app.auth_adapter.record_cert_renewal_notification(row.tn_id).await {
		warn!(tn_id = %row.tn_id.0, id_tag = %row.id_tag, error = %e,
			"Failed to stamp notified_at");
	}
}

fn should_notify(row: &TenantCertRenewalRow, now: i64, days_until_expiry: i64) -> bool {
	// First failure (no notification recorded yet): always notify.
	let Some(last) = row.notified_at else {
		return true;
	};
	let interval = if days_until_expiry <= 7 {
		RENEWAL_NOTIFY_SHORT_INTERVAL_SECS
	} else {
		RENEWAL_NOTIFY_LONG_INTERVAL_SECS
	};
	now - last.0 >= interval
}

async fn schedule_renewal_failure_email(
	app: &App,
	row: &TenantCertRenewalRow,
	reason: &str,
	expires_at: Timestamp,
	days_until_expiry: i64,
	suspended: bool,
) -> ClResult<()> {
	let schedule_email = app.ext::<ScheduleEmailFn>()?;

	// Tenant email lives on AuthProfile.
	let profile = app.auth_adapter.read_tenant(&row.id_tag).await?;
	let Some(email) = profile.email else {
		warn!(tn_id = %row.tn_id.0, id_tag = %row.id_tag,
			"Cannot send renewal-failure email: tenant has no email on file");
		return Ok(());
	};

	// Pull the user's preferred language directly via the settings service —
	// we can't depend on cloudillo-email here.
	let lang = match app.settings.get(row.tn_id, "profile.lang").await {
		Ok(Some(crate::settings::SettingValue::String(s))) => Some(s),
		_ => None,
	};

	let base_id_tag = app.opts.base_id_tag.as_ref().map_or("cloudillo", AsRef::as_ref);
	let local_address_str =
		app.opts.local_address.iter().map(AsRef::as_ref).collect::<Vec<_>>().join(", ");
	let domain_for_display = format!("cl-o.{}", row.id_tag);

	let template_vars = serde_json::json!({
		"idTag": row.id_tag.as_ref(),
		"domain": domain_for_display,
		"daysUntilExpiry": days_until_expiry,
		"expiresAt": expires_at.to_iso_string(),
		"errorReason": reason,
		"suspended": suspended,
		"localAddress": local_address_str,
		"base_id_tag": base_id_tag,
		"instance_name": "Cloudillo",
	});

	let params = ScheduleEmailParams {
		to: email.to_string(),
		template_name: "cert_renewal_failed".to_string(),
		template_vars,
		lang,
		// Once-per-day key so we don't queue duplicate emails when the task
		// runs multiple times before sending (failure_count + day stamp).
		custom_key: Some(format!(
			"cert-renewal-failed:{}:{}",
			row.tn_id.0,
			Timestamp::now().0 / 86400
		)),
		from_name_override: Some(format!("Cloudillo | {}", base_id_tag.to_uppercase())),
	};

	schedule_email(app, row.tn_id, params).await
}

// vim: ts=4
