//! Bootstrap module for initial tenant setup and certificate management

use std::sync::Arc;

use crate::core::{acme, app::AppState};
use crate::meta_adapter::UpdateTenantData;
use crate::prelude::*;
use crate::utils::derive_name_from_id_tag;

/// Options for creating a complete tenant with all necessary setup
pub struct CreateCompleteTenantOptions<'a> {
	pub id_tag: &'a str,
	pub email: Option<&'a str>,
	pub password: Option<&'a str>,
	pub roles: Option<&'a [&'a str]>,
	pub display_name: Option<&'a str>,
	pub create_acme_cert: bool,
	pub acme_email: Option<&'a str>,
	pub app_domain: Option<&'a str>,
}

/// Create a complete tenant with all necessary setup
///
/// This function handles the complete tenant creation process including:
/// 1. Creating tenant in auth adapter
/// 2. Creating profile signing key
/// 3. Creating tenant in meta adapter
/// 4. Setting display name
/// 5. Optionally creating ACME certificate
///
/// This function is used by both bootstrap and registration flows
pub async fn create_complete_tenant(
	app: &Arc<AppState>,
	opts: CreateCompleteTenantOptions<'_>,
) -> ClResult<TnId> {
	let auth = &app.auth_adapter;
	let meta = &app.meta_adapter;

	info!("Creating complete tenant: {}", opts.id_tag);

	// Create tenant in auth adapter
	let tn_id = auth
		.create_tenant(
			opts.id_tag,
			crate::auth_adapter::CreateTenantData {
				vfy_code: None,
				email: opts.email,
				password: opts.password,
				roles: opts.roles,
			},
		)
		.await
		.map_err(|e| {
			warn!(
				error = %e,
				id_tag = %opts.id_tag,
				"Failed to create tenant in auth adapter"
			);
			e
		})?;

	info!(tn_id = ?tn_id, "Tenant created in auth adapter");

	// Create profile signing key
	auth.create_profile_key(tn_id, None).await.map_err(|e| {
		warn!(
			error = %e,
			id_tag = %opts.id_tag,
			tn_id = ?tn_id,
			"Failed to create profile key"
		);
		e
	})?;

	info!("Profile key created");

	// Create VAPID key for push notifications
	auth.create_vapid_key(tn_id).await.map_err(|e| {
		warn!(
			error = %e,
			id_tag = %opts.id_tag,
			tn_id = ?tn_id,
			"Failed to create VAPID key"
		);
		e
	})?;

	info!("VAPID key created");

	// Create tenant in meta adapter
	meta.create_tenant(tn_id, opts.id_tag).await.map_err(|e| {
		warn!(
			error = %e,
			id_tag = %opts.id_tag,
			tn_id = ?tn_id,
			"Failed to create tenant in meta adapter"
		);
		// Note: Cannot await cleanup here as we're in a non-async closure
		// The cleanup would need to be handled by the caller if needed
		e
	})?;

	info!("Tenant created in meta adapter");

	// Set display name (use provided or derive from id_tag with capitalization)
	let display_name = opts
		.display_name
		.map(|s| s.to_string())
		.unwrap_or_else(|| derive_name_from_id_tag(opts.id_tag));

	meta.update_tenant(
		tn_id,
		&UpdateTenantData { name: Patch::Value(display_name.clone()), ..Default::default() },
	)
	.await
	.map_err(|e| {
		warn!(
			error = %e,
			id_tag = %opts.id_tag,
			tn_id = ?tn_id,
			"Failed to update tenant display name"
		);
		e
	})?;

	info!(display_name = %display_name, "Tenant display name set");

	// Create ACME certificate if requested
	if opts.create_acme_cert {
		if let Some(acme_email) = opts.acme_email {
			info!("Creating ACME certificate for tenant");
			acme::init(app.clone(), acme_email, opts.id_tag, opts.app_domain)
				.await
				.map_err(|e| {
					warn!(
						error = %e,
						id_tag = %opts.id_tag,
						"Failed to create ACME certificate"
					);
					e
				})?;
			info!("ACME certificate created successfully");
		} else {
			warn!("ACME cert requested but no ACME email provided");
		}
	}

	info!(
		id_tag = %opts.id_tag,
		tn_id = ?tn_id,
		"Complete tenant creation finished successfully"
	);

	Ok(tn_id)
}

/// Bootstrap function that runs on application startup
///
/// This function:
/// 1. Checks if the base tenant (TnId(1)) exists
/// 2. If not, creates it using the provided configuration
/// 3. If ACME is configured, schedules certificate renewal tasks
pub async fn bootstrap(
	app: Arc<AppState>,
	opts: &crate::core::app::AppBuilderOpts,
) -> ClResult<()> {
	let auth = &app.auth_adapter;

	if true {
		let Some(base_id_tag) = opts.base_id_tag.as_ref() else {
			return Err(Error::Internal("FATAL: No base id tag provided".to_string()));
		};
		let id_tag = auth.read_id_tag(TnId(1)).await;
		debug!("Got id tag: {:?}", id_tag);

		if let Err(Error::NotFound) = id_tag {
			info!("======================================\nBootstrapping...\n======================================");
			let Some(base_password) = opts.base_password.clone() else {
				return Err(Error::Internal(
					"FATAL: No base password provided for bootstrap".to_string(),
				));
			};

			// Use the unified tenant creation function
			create_complete_tenant(
				&app,
				CreateCompleteTenantOptions {
					id_tag: base_id_tag,
					email: None,
					password: Some(&base_password),
					roles: Some(&["SADM"]),
					display_name: None, // Will be derived from id_tag
					create_acme_cert: opts.acme_email.is_some(),
					acme_email: opts.acme_email.as_deref(),
					app_domain: opts.base_app_domain.as_deref(),
				},
			)
			.await?;
		} else if let Some(ref acme_email) = opts.acme_email {
			// Schedule hourly certificate renewal task
			info!("Scheduling automatic certificate renewal task (runs hourly)");

			// TODO: Make renewal_days configurable via admin settings, default 30 days
			let renewal_days = 30;

			let renewal_task =
				Arc::new(acme::CertRenewalTask::new(acme_email.to_string(), renewal_days));

			// Schedule to run every hour at minute 0 using cron with a unique key for deduplication
			let app_clone = app.clone();
			let acme_email = acme_email.clone();
			tokio::spawn(async move {
				match app_clone
					.scheduler
					.task(renewal_task)
					.key("acme.cert_renewal") // Unique key prevents duplicates on restart
					.cron("0 0 * * *") // Every day
					.schedule()
					.await
				{
					Ok(task_id) => {
						info!("Certificate renewal task scheduled (task_id={})", task_id);
					}
					Err(e) => {
						error!(error = %e, "Failed to schedule certificate renewal task");
					}
				}

				// Also run renewal check immediately on startup in background
				info!("Running initial certificate check on startup...");
				match app_clone.auth_adapter.list_tenants_needing_cert_renewal(renewal_days).await {
					Ok(tenants) => {
						if tenants.is_empty() {
							info!("All tenant certificates are valid");
						} else {
							info!("Found {} tenant(s) needing certificate renewal", tenants.len());

							for (tn_id, id_tag) in tenants {
								info!(
									"Renewing certificate for tenant: {} (tn_id={})",
									id_tag, tn_id.0
								);

								let app_domain = if tn_id.0 == 1 {
									// TODO: Get from configuration
									None
								} else {
									None
								};

								match acme::init(
									app_clone.clone(),
									&acme_email,
									&id_tag,
									app_domain,
								)
								.await
								{
									Ok(_) => {
										info!(tenant = %id_tag, "Certificate renewed successfully");
									}
									Err(e) => {
										error!(tenant = %id_tag, error = %e, "Failed to renew certificate");
									}
								}
							}
						}
					}
					Err(e) => {
						warn!(error = %e, "Failed to check certificates on startup");
					}
				}
			});
		} else {
			info!("ACME not configured (no ACME_EMAIL), skipping certificate check");
		}
	}

	// Schedule profile refresh batch task
	// This runs every 5 minutes for debugging, change to "0 * * * *" (hourly) for production
	{
		let app_clone = app.clone();
		tokio::spawn(async move {
			let refresh_task = Arc::new(crate::profile::sync::ProfileRefreshBatchTask);
			match app_clone
				.scheduler
				.task(refresh_task)
				.key("profile.refresh_batch")
				.cron("*/5 * * * *") // Every 5 minutes for debugging
				.schedule()
				.await
			{
				Ok(task_id) => {
					info!("Profile refresh batch task scheduled (task_id={})", task_id);
				}
				Err(e) => {
					error!(error = %e, "Failed to schedule profile refresh batch task");
				}
			}
		});
	}

	Ok(())
}
// vim: ts=4
