use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use itertools::Itertools;
use jsonwebtoken::{self as jwt, Algorithm, Validation};
use serde::de::DeserializeOwned;
use std::net::IpAddr;

use crate::{
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
		app.request.get_noauth(tn_id, issuer, "/me/keys").await;

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
	_action_id: &str,
	token: &str,
	is_sync: bool,
	client_address: Option<String>,
) -> ClResult<Option<serde_json::Value>> {
	// Parse client address for rate limiting
	let client_ip: Option<IpAddr> = client_address.as_ref().and_then(|addr| addr.parse().ok());

	// Pre-decode to check action type for PoW requirement (before signature verification)
	let action_preview: ActionToken = decode_jwt_no_verify(token)?;
	let is_conn_action = action_preview.t.starts_with("CONN");

	// For CONN actions, check PoW requirement BEFORE verification
	// Note: This check also happens in post_inbox handler for synchronous error response
	if is_conn_action {
		if let Some(ref ip) = client_ip {
			// Check PoW requirement
			if let Err(pow_err) = app.rate_limiter.verify_pow(ip, token) {
				debug!("CONN action from {} requires PoW: {:?}", action_preview.iss, pow_err);
				return Err(Error::PreconditionRequired(format!(
					"Proof of work required: {}",
					pow_err
				)));
			}
		}
	}

	// Verify the action token (with rate limiting on failure)
	let action = match verify_action_token(app, tn_id, token, client_ip.as_ref()).await {
		Ok(action) => action,
		Err(e) => {
			// For CONN actions, increment PoW counter on verification failure
			if is_conn_action {
				if let Some(ref ip) = client_ip {
					if let Err(pen_err) = app
						.rate_limiter
						.increment_pow_counter(ip, PowPenaltyReason::ConnSignatureFailure)
					{
						warn!("Failed to increment PoW counter for {}: {}", ip, pen_err);
					}
				}
			}
			return Err(e);
		}
	};

	// Check for definition: first try full type (e.g., "FLLW:DEL"), then fall back to base type ("FLLW")
	// This allows separate definitions for subtypes when the use case differs significantly
	let (definition_type, definition) = if let Some(def) = app.dsl_engine.get_definition(&action.t)
	{
		(action.t.as_ref(), def)
	} else {
		// Try base type (before colon)
		let base_type = action.t.find(':').map(|pos| &action.t[..pos]).unwrap_or(action.t.as_ref());
		if let Some(def) = app.dsl_engine.get_definition(base_type) {
			(base_type, def)
		} else {
			return Err(Error::ValidationError(format!("Action type not supported: {}", action.t)));
		}
	};

	// Check permissions based on action type's allow_unknown setting
	// Default to false if not specified (require following/connected)
	if !definition.behavior.allow_unknown.unwrap_or(false) {
		let issuer_profile =
			if let Ok((_etag, profile)) = app.meta_adapter.read_profile(tn_id, &action.iss).await {
				Some(profile)
			} else {
				None
			};
		info!("  profile: {:?}", issuer_profile);

		let mut allowed = false;
		if let Some(ref p) = issuer_profile {
			if p.following || p.connected {
				allowed = true;
			}
		}

		if !allowed {
			warn!(
				issuer = %action.iss,
				action_type = %action.t,
				"Permission denied - sender not following/connected"
			);
			return Err(Error::PermissionDenied);
		}

		if issuer_profile.is_none() {
			//profile::sync_profile(&app, tn_id, &action.iss).await?;
		}
	}

	// Store the inbound action in the database before running hooks
	// This ensures DSL operations like update_action can find the action
	{
		// Extract action type and subtype
		let (action_type, sub_type) = if let Some(colon_pos) = action.t.find(':') {
			let (t, st) = action.t.split_at(colon_pos);
			(t, Some(&st[1..]))
		} else {
			(action.t.as_ref(), None)
		};

		// Generate key from key_pattern if available
		let key = if let Some(pattern) = definition.key_pattern.as_deref() {
			let key = pattern
				.replace("{type}", action_type)
				.replace("{issuer}", &action.iss)
				.replace("{audience}", action.aud.as_deref().unwrap_or(""))
				.replace("{parent}", action.p.as_deref().unwrap_or(""))
				.replace("{subject}", action.sub.as_deref().unwrap_or(""));
			Some(key)
		} else {
			None
		};

		// Serialize content Value to string for storage (always JSON-encode)
		let content_str: Option<String> =
			action.c.as_ref().map(|v| serde_json::to_string(v).unwrap_or_default());

		// Inherit visibility from parent action if available
		let visibility = if let Some(parent_id) = action.p.as_deref() {
			match app.meta_adapter.get_action(tn_id, parent_id).await {
				Ok(Some(parent)) => parent.visibility,
				_ => None, // Parent not found locally or error - use default
			}
		} else {
			None
		};

		// Create action struct for storage
		let inbound_action = meta_adapter::Action {
			action_id: _action_id,
			typ: action_type,
			sub_typ: sub_type,
			issuer_tag: &action.iss,
			parent_id: action.p.as_deref(),
			root_id: action.p.as_deref(), // Use parent as root for now, could be improved
			audience_tag: action.aud.as_deref(),
			content: content_str.as_deref(),
			attachments: action.a.as_ref().map(|v| v.iter().map(|s| s.as_ref()).collect()),
			subject: action.sub.as_deref(),
			created_at: action.iat,
			expires_at: action.exp,
			visibility, // Inherit from parent if available
		};

		// Store in actions table (handles deduplication via key)
		match app.meta_adapter.create_action(tn_id, &inbound_action, key.as_deref()).await {
			Ok(_) => {
				info!("  stored inbound action {} in actions table", _action_id);
				// Set status to 'A' (active) for inbound actions - create_action defaults to 'P'
				let update_opts = meta_adapter::UpdateActionDataOptions {
					status: crate::types::Patch::Value('A'),
					..Default::default()
				};
				if let Err(e) =
					app.meta_adapter.update_action_data(tn_id, _action_id, &update_opts).await
				{
					warn!("  failed to set inbound action status to active: {}", e);
				}
			}
			Err(e) => {
				// For CONN actions, increment PoW counter on duplicate pending
				if is_conn_action {
					if let Some(ref ip) = client_ip {
						// Check if there's already a pending CONN from this issuer
						// (duplicate detection by key constraint failure)
						if let Err(pen_err) = app
							.rate_limiter
							.increment_pow_counter(ip, PowPenaltyReason::ConnDuplicatePending)
						{
							warn!("Failed to increment PoW counter for {}: {}", ip, pen_err);
						}
						debug!(
							"CONN duplicate detected from {} - PoW counter incremented",
							action.iss
						);
					}
				}
				// Log but don't fail - action might already exist (duplicate delivery)
				debug!("  failed to store inbound action: {} (may be duplicate)", e);
			}
		}

		// Store token in action_tokens table
		if let Err(e) = app.meta_adapter.create_inbound_action(tn_id, _action_id, token, None).await
		{
			debug!("  failed to store inbound action token: {} (may be duplicate)", e);
		}
	}

	// Skip attachment processing for synchronous requests
	if !is_sync {
		if let Some(ref attachments) = action.a {
			process_inbound_action_attachments(app, tn_id, &action.iss, attachments.clone())
				.await?;
		}
	}

	// Execute DSL on_receive hook
	use crate::action::hooks::{HookContext, HookType};
	use std::collections::HashMap;

	// Extract subtype from action type (e.g., "CONN:DEL" → type="CONN", subtype="DEL")
	let (action_type, subtype) = if let Some(colon_pos) = action.t.find(':') {
		let (t, st) = action.t.split_at(colon_pos);
		(t.to_string(), Some(st[1..].to_string()))
	} else {
		(action.t.to_string(), None)
	};

	let hook_context = HookContext {
		action_id: _action_id.to_string(),
		r#type: action_type,
		subtype,
		issuer: action.iss.to_string(),
		audience: action.aud.as_ref().map(|s| s.to_string()),
		parent: action.p.as_ref().map(|s| s.to_string()),
		subject: action.sub.as_ref().map(|s| s.to_string()),
		content: action.c.clone(),
		attachments: action.a.as_ref().map(|v| v.iter().map(|s| s.to_string()).collect()),
		created_at: format!("{}", action.iat.0), // Simple timestamp conversion
		expires_at: action.exp.map(|ts| format!("{}", ts.0)),
		tenant_id: tn_id.0 as i64,
		tenant_tag: action.aud.as_ref().map(|s| s.to_string()).unwrap_or_default(),
		tenant_type: "person".to_string(),
		is_inbound: true,
		is_outbound: false,
		client_address,
		vars: HashMap::new(),
	};

	if is_sync {
		// For synchronous processing, execute hook and return the result
		let hook_result = app
			.dsl_engine
			.execute_hook_with_result(app, definition_type, HookType::OnReceive, hook_context)
			.await?;

		Ok(hook_result.return_value)
	} else {
		// For asynchronous processing, execute hook without capturing result
		if let Err(e) = app
			.dsl_engine
			.execute_hook(app, definition_type, HookType::OnReceive, hook_context)
			.await
		{
			warn!(
				action_id = %_action_id,
				action_type = %action.t,
				issuer = %action.iss,
				tenant_id = %tn_id.0,
				error = %e,
				"DSL on_receive hook failed"
			);
			// Continue execution - hook errors shouldn't fail the action processing
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
		match sync_file_variants(app, tn_id, id_tag, &attachment, None).await {
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

// vim: ts=4
