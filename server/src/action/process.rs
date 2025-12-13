use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use itertools::Itertools;
use jsonwebtoken::{self as jwt, Algorithm, Validation};
use serde::de::DeserializeOwned;
use std::net::IpAddr;

use crate::{
	action::helpers,
	auth_adapter::ActionToken,
	core::rate_limit::{PenaltyReason, PowPenaltyReason, RateLimitApi},
	meta_adapter,
	prelude::*,
};

/// Decodes a JWT without verifying the signature
pub fn decode_jwt_no_verify<T: DeserializeOwned>(jwt: &str) -> ClResult<T> {
	let (_header, payload, _sig) = jwt.split('.').collect_tuple().ok_or(Error::Parse)?;
	let payload = URL_SAFE_NO_PAD.decode(payload.as_bytes()).map_err(|_| Error::Parse)?;
	let payload: T = serde_json::from_slice(&payload).map_err(|_| Error::Parse)?;

	Ok(payload)
}

/// Verify JWT signature with a public key
fn verify_jwt_signature(token: &str, public_key: &str) -> ClResult<ActionToken> {
	let public_key_pem =
		format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----", public_key);

	let mut validation = Validation::new(Algorithm::ES384);
	validation.validate_aud = false;
	validation.set_required_spec_claims(&["iss"]);

	let action: ActionToken = jwt::decode(
		token,
		&jwt::DecodingKey::from_ec_pem(public_key_pem.as_bytes())
			.inspect_err(|err| error!("from_ec_pem err: {}", err))?,
		&validation,
	)?
	.claims;

	Ok(action)
}

/// Verify an action token using 3-tier caching:
/// 1. Check failure cache (in-memory) - return early if cached failure
/// 2. Check SQLite key_cache - use if valid
/// 3. HTTP fetch - cache results (success to DB, failure to memory)
///
/// If client_ip is provided and verification fails, rate limiting penalties are applied.
pub async fn verify_action_token(
	app: &App,
	tn_id: TnId,
	token: &str,
	client_ip: Option<&IpAddr>,
) -> ClResult<ActionToken> {
	let action_not_validated: ActionToken = decode_jwt_no_verify(token)?;
	let issuer = &action_not_validated.iss;
	let key_id = &action_not_validated.k;

	info!("  from: {}, key: {}", issuer, key_id);

	// 1. Check failure cache - return early if we recently failed to fetch this key
	if let Some(failure) = app.key_fetch_cache.check_failure(issuer, key_id) {
		debug!(
			"Key fetch for {}:{} blocked by cache (retry in {} secs)",
			issuer,
			key_id,
			failure.seconds_until_retry()
		);
		return Err(Error::ServiceUnavailable(format!(
			"Key fetch temporarily blocked (retry in {} secs)",
			failure.seconds_until_retry()
		)));
	}

	// 2. Check SQLite key cache - use if we have a cached key
	match app.meta_adapter.read_profile_public_key(issuer, key_id).await {
		Ok((public_key, expires_at)) => {
			// Check if key is still valid (not expired)
			if expires_at > Timestamp::now() {
				info!("  using cached key (expires at {})", expires_at);
				match verify_jwt_signature(token, &public_key) {
					Ok(action) => {
						info!("  validated from cache {:?}", action);
						return Ok(action);
					}
					Err(e) => {
						// Signature verification failed - penalize
						if let Some(ip) = client_ip {
							if let Err(pen_err) = app.rate_limiter.penalize(
								ip,
								PenaltyReason::TokenVerificationFailure,
								1,
							) {
								warn!("Failed to record token penalty for {}: {}", ip, pen_err);
							}
						}
						warn!("  signature verification failed (cached key): {}", e);
						return Err(e);
					}
				}
			}
			// Key expired - continue to HTTP fetch
			debug!("  cached key expired at {}, fetching fresh", expires_at);
		}
		Err(Error::NotFound) => {
			// No cached key - continue to HTTP fetch
			debug!("  no cached key, fetching from remote");
		}
		Err(e) => {
			// Database error - log but continue to HTTP fetch
			warn!("  key cache read error: {}, fetching from remote", e);
		}
	}

	// 3. HTTP fetch from remote instance
	let fetch_result: ClResult<crate::types::ApiResponse<crate::profile::handler::Profile>> =
		app.request.get_noauth(tn_id, issuer, "/me").await;

	match fetch_result {
		Ok(api_response) => {
			let key_data = api_response.data;

			// Find the key we need
			let key = key_data.keys.iter().find(|k| k.key_id.as_ref() == key_id.as_ref());

			if let Some(key) = key {
				let public_key = &key.public_key;

				// Cache the key in SQLite for future use
				if let Err(e) =
					app.meta_adapter.add_profile_public_key(issuer, key_id, public_key).await
				{
					warn!("Failed to cache public key for {}:{}: {}", issuer, key_id, e);
				} else {
					debug!("Cached public key for {}:{}", issuer, key_id);
				}

				// Clear any previous failure entry
				app.key_fetch_cache.clear_failure(issuer, key_id);

				// Verify the signature
				info!("  validating...");
				match verify_jwt_signature(token, public_key) {
					Ok(action) => {
						info!("  validated {:?}", action);
						Ok(action)
					}
					Err(e) => {
						// Signature verification failed - penalize
						if let Some(ip) = client_ip {
							if let Err(pen_err) = app.rate_limiter.penalize(
								ip,
								PenaltyReason::TokenVerificationFailure,
								1,
							) {
								warn!("Failed to record token penalty for {}: {}", ip, pen_err);
							}
						}
						warn!("  signature verification failed: {}", e);
						Err(e)
					}
				}
			} else {
				// Key not found in response - cache this as a failure
				let err = Error::NotFound;
				app.key_fetch_cache.record_failure(issuer, key_id, &err);
				Err(Error::Unauthorized)
			}
		}
		Err(e) => {
			// HTTP fetch failed - cache the failure
			warn!("Key fetch failed for {}:{}: {}", issuer, key_id, e);
			app.key_fetch_cache.record_failure(issuer, key_id, &e);
			Err(e)
		}
	}
}

pub trait ActionType {
	fn allow_unknown() -> bool;
}

pub async fn process_inbound_action_token(
	app: &App,
	tn_id: TnId,
	action_id: &str,
	token: &str,
	is_sync: bool,
	client_address: Option<String>,
) -> ClResult<Option<serde_json::Value>> {
	let client_ip: Option<IpAddr> = client_address.as_ref().and_then(|addr| addr.parse().ok());

	// 1. Pre-verify PoW for CONN actions
	let action_preview: ActionToken = decode_jwt_no_verify(token)?;
	let is_conn_action = action_preview.t.starts_with("CONN");
	verify_pow_if_conn(app, is_conn_action, client_ip.as_ref(), token, &action_preview.iss)?;

	// 2. Verify action token
	let action =
		verify_and_handle_failure(app, tn_id, token, is_conn_action, client_ip.as_ref()).await?;

	// 3. Resolve definition (try full type, then base type)
	let (definition_type, definition) = resolve_definition(app, &action.t)?;

	// 4. Check permissions
	check_inbound_permissions(app, tn_id, &action, definition).await?;

	// 5. Store action in database
	store_inbound_action(
		app,
		tn_id,
		action_id,
		token,
		&action,
		definition,
		is_conn_action,
		client_ip.as_ref(),
	)
	.await;

	// 6. Process attachments (async only)
	if !is_sync {
		if let Some(ref attachments) = action.a {
			process_inbound_action_attachments(app, tn_id, &action.iss, attachments.clone())
				.await?;
		}
	}

	// 7. Execute DSL on_receive hook
	let hook_result = execute_on_receive_hook(
		app,
		tn_id,
		action_id,
		&action,
		definition_type,
		is_sync,
		client_address.clone(),
	)
	.await?;

	// 8. Auto-approve approvable actions from trusted sources (if enabled)
	if !is_sync {
		try_auto_approve(app, tn_id, action_id, &action, definition).await;
	}

	// 9. Forward action to connected WebSocket clients
	forward_inbound_action_to_websocket(app, tn_id, action_id, &action).await;

	Ok(hook_result)
}

/// Verify PoW for CONN actions before signature verification
fn verify_pow_if_conn(
	app: &App,
	is_conn_action: bool,
	client_ip: Option<&IpAddr>,
	token: &str,
	issuer: &str,
) -> ClResult<()> {
	if !is_conn_action {
		return Ok(());
	}

	if let Some(ip) = client_ip {
		if let Err(pow_err) = app.rate_limiter.verify_pow(ip, token) {
			debug!("CONN action from {} requires PoW: {:?}", issuer, pow_err);
			return Err(Error::PreconditionRequired(format!(
				"Proof of work required: {}",
				pow_err
			)));
		}
	}
	Ok(())
}

/// Verify action token, handling failures for CONN actions
async fn verify_and_handle_failure(
	app: &App,
	tn_id: TnId,
	token: &str,
	is_conn_action: bool,
	client_ip: Option<&IpAddr>,
) -> ClResult<ActionToken> {
	match verify_action_token(app, tn_id, token, client_ip).await {
		Ok(action) => Ok(action),
		Err(e) => {
			if is_conn_action {
				if let Some(ip) = client_ip {
					if let Err(pen_err) = app
						.rate_limiter
						.increment_pow_counter(ip, PowPenaltyReason::ConnSignatureFailure)
					{
						warn!("Failed to increment PoW counter for {}: {}", ip, pen_err);
					}
				}
			}
			Err(e)
		}
	}
}

/// Resolve action definition (try full type, then base type)
fn resolve_definition<'a>(
	app: &'a App,
	action_type: &'a str,
) -> ClResult<(&'a str, &'a crate::action::dsl::types::ActionDefinition)> {
	if let Some(def) = app.dsl_engine.get_definition(action_type) {
		return Ok((action_type, def));
	}

	// Try base type (before colon)
	let base_type = action_type.find(':').map(|pos| &action_type[..pos]).unwrap_or(action_type);
	if let Some(def) = app.dsl_engine.get_definition(base_type) {
		return Ok((base_type, def));
	}

	Err(Error::ValidationError(format!("Action type not supported: {}", action_type)))
}

/// Check permissions based on action type's allow_unknown setting
async fn check_inbound_permissions(
	app: &App,
	tn_id: TnId,
	action: &ActionToken,
	definition: &crate::action::dsl::types::ActionDefinition,
) -> ClResult<()> {
	if definition.behavior.allow_unknown.unwrap_or(false) {
		return Ok(());
	}

	let issuer_profile =
		if let Ok((_etag, profile)) = app.meta_adapter.read_profile(tn_id, &action.iss).await {
			Some(profile)
		} else {
			None
		};
	info!("  profile: {:?}", issuer_profile);

	let allowed = issuer_profile.as_ref().map(|p| p.following || p.connected).unwrap_or(false);

	if !allowed {
		warn!(
			issuer = %action.iss,
			action_type = %action.t,
			"Permission denied - sender not following/connected"
		);
		return Err(Error::PermissionDenied);
	}

	Ok(())
}

/// Store inbound action in database
#[allow(clippy::too_many_arguments)]
async fn store_inbound_action(
	app: &App,
	tn_id: TnId,
	action_id: &str,
	token: &str,
	action: &ActionToken,
	definition: &crate::action::dsl::types::ActionDefinition,
	is_conn_action: bool,
	client_ip: Option<&IpAddr>,
) {
	let (action_type, sub_type) = helpers::extract_type_and_subtype(&action.t);
	let sub_type_ref = sub_type.as_deref();

	let key = definition.key_pattern.as_deref().map(|pattern| {
		helpers::apply_key_pattern(
			pattern,
			&action_type,
			&action.iss,
			action.aud.as_deref(),
			action.p.as_deref(),
			action.sub.as_deref(),
		)
	});

	let content_str = helpers::serialize_content(action.c.as_ref());
	let visibility =
		helpers::inherit_visibility(app.meta_adapter.as_ref(), tn_id, None, action.p.as_deref())
			.await;

	let inbound_action = meta_adapter::Action {
		action_id,
		typ: &action_type,
		sub_typ: sub_type_ref,
		issuer_tag: &action.iss,
		parent_id: action.p.as_deref(),
		root_id: action.p.as_deref(),
		audience_tag: action.aud.as_deref(),
		content: content_str.as_deref(),
		attachments: action.a.as_ref().map(|v| v.iter().map(|s| s.as_ref()).collect()),
		subject: action.sub.as_deref(),
		created_at: action.iat,
		expires_at: action.exp,
		visibility,
	};

	match app.meta_adapter.create_action(tn_id, &inbound_action, key.as_deref()).await {
		Ok(_) => {
			info!("  stored inbound action {} in actions table", action_id);
			let update_opts = meta_adapter::UpdateActionDataOptions {
				status: crate::types::Patch::Value('A'),
				..Default::default()
			};
			if let Err(e) =
				app.meta_adapter.update_action_data(tn_id, action_id, &update_opts).await
			{
				warn!("  failed to set inbound action status to active: {}", e);
			}
		}
		Err(e) => {
			if is_conn_action {
				if let Some(ip) = client_ip {
					if let Err(pen_err) = app
						.rate_limiter
						.increment_pow_counter(ip, PowPenaltyReason::ConnDuplicatePending)
					{
						warn!("Failed to increment PoW counter for {}: {}", ip, pen_err);
					}
					debug!("CONN duplicate detected from {} - PoW counter incremented", action.iss);
				}
			}
			debug!("  failed to store inbound action: {} (may be duplicate)", e);
		}
	}

	if let Err(e) = app.meta_adapter.create_inbound_action(tn_id, action_id, token, None).await {
		debug!("  failed to store inbound action token: {} (may be duplicate)", e);
	}
}

/// Execute DSL on_receive hook
async fn execute_on_receive_hook(
	app: &App,
	tn_id: TnId,
	action_id: &str,
	action: &ActionToken,
	definition_type: &str,
	is_sync: bool,
	client_address: Option<String>,
) -> ClResult<Option<serde_json::Value>> {
	use crate::action::hooks::{HookContext, HookType};

	let (action_type, subtype) = helpers::extract_type_and_subtype(&action.t);

	let hook_context = HookContext::builder()
		.action_id(action_id)
		.action_type(action_type)
		.subtype(subtype)
		.issuer(&*action.iss)
		.audience(action.aud.as_ref().map(|s| s.to_string()))
		.parent(action.p.as_ref().map(|s| s.to_string()))
		.subject(action.sub.as_ref().map(|s| s.to_string()))
		.content(action.c.clone())
		.attachments(action.a.as_ref().map(|v| v.iter().map(|s| s.to_string()).collect()))
		.created_at(format!("{}", action.iat.0))
		.expires_at(action.exp.map(|ts| format!("{}", ts.0)))
		.tenant(
			tn_id.0 as i64,
			action.aud.as_ref().map(|s| s.to_string()).unwrap_or_default(),
			"person",
		)
		.inbound()
		.client_address(client_address)
		.build();

	if is_sync {
		let hook_result = app
			.dsl_engine
			.execute_hook_with_result(app, definition_type, HookType::OnReceive, hook_context)
			.await?;
		Ok(hook_result.return_value)
	} else {
		if let Err(e) = app
			.dsl_engine
			.execute_hook(app, definition_type, HookType::OnReceive, hook_context)
			.await
		{
			warn!(
				action_id = %action_id,
				action_type = %action.t,
				issuer = %action.iss,
				tenant_id = %tn_id.0,
				error = %e,
				"DSL on_receive hook failed"
			);
		}
		Ok(None)
	}
}

async fn process_inbound_action_attachments(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	attachments: Vec<Box<str>>,
) -> ClResult<()> {
	use crate::file::sync::sync_file_variants;

	for attachment in attachments {
		info!("  syncing attachment: {}", attachment);
		match sync_file_variants(app, tn_id, id_tag, &attachment, None, true).await {
			Ok(result) => {
				info!(
					"  attachment {} sync complete: {} synced, {} skipped, {} failed",
					attachment,
					result.synced_variants.len(),
					result.skipped_variants.len(),
					result.failed_variants.len()
				);
			}
			Err(e) => {
				warn!("  failed to sync attachment {}: {}", attachment, e);
			}
		}
	}

	Ok(())
}

/// Forward inbound action to connected WebSocket clients
async fn forward_inbound_action_to_websocket(
	app: &App,
	tn_id: TnId,
	action_id: &str,
	action: &crate::auth_adapter::ActionToken,
) {
	use crate::action::forward::{self, ForwardActionParams};

	let (action_type, subtype) = helpers::extract_type_and_subtype(&action.t);

	let attachments: Option<Vec<Box<str>>> = action.a.as_ref().map(|v| v.to_vec());

	let params = ForwardActionParams {
		action_id,
		issuer_tag: &action.iss,
		audience_tag: action.aud.as_deref(),
		action_type: &action_type,
		sub_type: subtype.as_deref(),
		content: action.c.as_ref(),
		attachments: attachments.as_deref(),
	};

	let result = forward::forward_inbound_action(app, tn_id, &params).await;

	if result.delivered {
		debug!(
			action_id = %action_id,
			action_type = %action.t,
			connections = %result.connection_count,
			"Inbound action forwarded to WebSocket clients"
		);
	} else if result.user_offline {
		debug!(
			action_id = %action_id,
			action_type = %action.t,
			audience = ?action.aud,
			"User offline - sending push notification"
		);
		// Send push notification for offline user
		send_push_notification(app, tn_id, action_id, action, &action_type, subtype.as_deref())
			.await;
	}
}

/// Send push notification for an action
async fn send_push_notification(
	app: &App,
	tn_id: TnId,
	action_id: &str,
	action: &crate::auth_adapter::ActionToken,
	action_type: &str,
	subtype: Option<&str>,
) {
	use crate::action::forward::{get_push_setting_key, should_push_notify};
	use crate::push::{send_to_tenant, NotificationPayload};

	// Check if this action type should trigger push notifications
	if !should_push_notify(action_type, subtype) {
		debug!(
			action_id = %action_id,
			action_type = %action_type,
			"Action type does not trigger push notifications"
		);
		return;
	}

	// Check if user has push notifications enabled for this action type
	let setting_key = get_push_setting_key(action_type);
	let push_enabled = app.settings.get_bool(tn_id, setting_key).await.unwrap_or(true);
	if !push_enabled {
		debug!(
			action_id = %action_id,
			action_type = %action_type,
			setting_key = %setting_key,
			"Push notifications disabled for this action type"
		);
		return;
	}

	// Also check master switch
	let master_enabled = app.settings.get_bool(tn_id, "notify.push").await.unwrap_or(true);
	if !master_enabled {
		debug!(
			action_id = %action_id,
			"Push notifications disabled (master switch)"
		);
		return;
	}

	// Build notification payload
	let title = match action_type {
		"MSG" => format!("Message from {}", action.iss),
		"CONN" => format!("Connection request from {}", action.iss),
		"FSHR" => format!("{} shared a file", action.iss),
		"CMNT" => format!("{} commented", action.iss),
		_ => format!("Notification from {}", action.iss),
	};

	let body = action
		.c
		.as_ref()
		.and_then(|c| c.as_str())
		.map(|s| s.chars().take(100).collect::<String>())
		.unwrap_or_default();

	let payload = NotificationPayload {
		title,
		body,
		path: Some(format!("/action/{}", action_id)),
		image: None,
		tag: Some(action_type.to_string()),
	};

	// Send to all subscriptions for this tenant
	match send_to_tenant(app, tn_id, &payload).await {
		Ok(count) => {
			info!(
				action_id = %action_id,
				action_type = %action_type,
				tn_id = %tn_id.0,
				sent_count = %count,
				"Push notification sent"
			);
		}
		Err(e) => {
			warn!(
				action_id = %action_id,
				action_type = %action_type,
				tn_id = %tn_id.0,
				error = %e,
				"Failed to send push notification"
			);
		}
	}
}

/// Try to auto-approve an approvable action from a trusted source
///
/// Conditions for auto-approve:
/// 1. Action type must be approvable (POST, MSG, REPOST)
/// 2. Action must be addressed to us (audience = our id_tag)
/// 3. Issuer must be different from us
/// 4. Issuer must be trusted (profile status 'T' or 'A')
/// 5. federation.auto_approve setting must be enabled
async fn try_auto_approve(
	app: &App,
	tn_id: TnId,
	action_id: &str,
	action: &crate::auth_adapter::ActionToken,
	definition: &crate::action::dsl::types::ActionDefinition,
) {
	use crate::action::status;
	use crate::action::task::{self, CreateAction};

	// 1. Check if action type is approvable
	if !definition.behavior.approvable.unwrap_or(false) {
		return;
	}

	// 2. Get our tenant's id_tag
	let tenant = match app.meta_adapter.read_tenant(tn_id).await {
		Ok(tenant) => tenant,
		Err(_) => {
			debug!("Auto-approve: Could not get tenant info");
			return;
		}
	};
	let our_id_tag = tenant.id_tag.as_ref();

	// 3. Check if action is addressed to us (audience = our id_tag)
	let audience = action.aud.as_deref();
	if audience != Some(our_id_tag) {
		debug!(
			action_id = %action_id,
			audience = ?audience,
			our_id_tag = %our_id_tag,
			"Auto-approve skipped: not addressed to us"
		);
		return;
	}

	// 4. Check issuer is not us
	if action.iss.as_ref() == our_id_tag {
		return;
	}

	// 5. Check if auto-approve setting is enabled
	let auto_approve_enabled =
		app.settings.get_bool(tn_id, "federation.auto_approve").await.unwrap_or(false);
	if !auto_approve_enabled {
		debug!(
			action_id = %action_id,
			"Auto-approve skipped: setting disabled"
		);
		return;
	}

	// 6. Check if issuer is trusted (connected = bidirectional connection established)
	let issuer_profile = match app.meta_adapter.read_profile(tn_id, &action.iss).await {
		Ok((_etag, profile)) => profile,
		Err(e) => {
			debug!(
				action_id = %action_id,
				issuer = %action.iss,
				error = %e,
				"Auto-approve skipped: issuer profile not found or error"
			);
			return;
		}
	};

	// Trust = bidirectional connection (CONN handshake completed)
	if !issuer_profile.connected {
		debug!(
			action_id = %action_id,
			issuer = %action.iss,
			connected = %issuer_profile.connected,
			"Auto-approve skipped: issuer not connected"
		);
		return;
	}

	// All conditions met - auto-approve by setting status and creating APRV
	info!(
		action_id = %action_id,
		issuer = %action.iss,
		action_type = %action.t,
		"Auto-approving action from trusted source"
	);

	// Update action status to 'A' (Active/Approved)
	let update_opts = crate::meta_adapter::UpdateActionDataOptions {
		status: crate::types::Patch::Value(status::ACTIVE),
		..Default::default()
	};
	if let Err(e) = app.meta_adapter.update_action_data(tn_id, action_id, &update_opts).await {
		warn!(
			action_id = %action_id,
			error = %e,
			"Auto-approve: Failed to update action status"
		);
		return;
	}

	// Create APRV action to signal approval to the issuer
	let aprv_action = CreateAction {
		typ: "APRV".into(),
		audience_tag: Some(action.iss.clone()),
		subject: Some(action_id.into()),
		..Default::default()
	};

	match task::create_action(app, tn_id, our_id_tag, aprv_action).await {
		Ok(_) => {
			info!(
				action_id = %action_id,
				issuer = %action.iss,
				"Auto-approve: APRV action created"
			);
		}
		Err(e) => {
			warn!(
				action_id = %action_id,
				error = %e,
				"Auto-approve: Failed to create APRV action"
			);
		}
	}
}

// vim: ts=4
