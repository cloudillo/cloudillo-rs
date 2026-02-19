use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use itertools::Itertools;
use jsonwebtoken::{self as jwt, Algorithm, Validation};
use serde::de::DeserializeOwned;
use std::net::IpAddr;

use crate::{
	action::{
		helpers,
		post_store::{self, ProcessingContext},
	},
	auth_adapter::ActionToken,
	core::rate_limit::{PenaltyReason, PowPenaltyReason, RateLimitApi},
	meta_adapter::{self, AttachmentView},
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

	info!("→ VERIFY: from={} key={}", issuer, key_id);

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
				debug!("  using cached key (expires at {})", expires_at);
				match verify_jwt_signature(token, &public_key) {
					Ok(action) => {
						info!("← VERIFIED: type={} from={}", action.t, action.iss);
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
				match verify_jwt_signature(token, public_key) {
					Ok(action) => {
						info!("← VERIFIED: type={} from={}", action.t, action.iss);
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

/// Process an inbound action token
///
/// # Parameters
/// - `skip_permission_check`: If true, skip permission/relation checks (used for pre-approved related actions)
pub async fn process_inbound_action_token(
	app: &App,
	tn_id: TnId,
	action_id: &str,
	token: &str,
	is_sync: bool,
	client_address: Option<String>,
) -> ClResult<Option<serde_json::Value>> {
	let result = process_inbound_action_token_inner(
		app,
		tn_id,
		action_id,
		token,
		is_sync,
		client_address,
		false,
	)
	.await?;

	// Process any related actions that came with this action
	// (only for regular inbound actions, not for pre-approved/related ones to avoid recursion)
	process_related_actions(app, tn_id, action_id).await;

	Ok(result)
}

/// Process an inbound action token that is pre-approved (related action from APRV)
/// Skips permission checks since the action was already approved by the APRV issuer
pub async fn process_preapproved_action_token(
	app: &App,
	tn_id: TnId,
	action_id: &str,
	token: &str,
) -> ClResult<Option<serde_json::Value>> {
	process_inbound_action_token_inner(app, tn_id, action_id, token, false, None, true).await
}

async fn process_inbound_action_token_inner(
	app: &App,
	tn_id: TnId,
	action_id: &str,
	token: &str,
	is_sync: bool,
	client_address: Option<String>,
	skip_permission_check: bool,
) -> ClResult<Option<serde_json::Value>> {
	let client_ip: Option<IpAddr> = client_address.as_ref().and_then(|addr| addr.parse().ok());

	// 1. Pre-verify PoW for CONN actions
	let action_preview: ActionToken = decode_jwt_no_verify(token)?;
	let is_conn_action = action_preview.t.starts_with("CONN");
	verify_pow_if_conn(app, is_conn_action, client_ip.as_ref(), token, &action_preview.iss)?;

	// 2. Verify action token (signature verification - always required!)
	let action =
		verify_and_handle_failure(app, tn_id, token, is_conn_action, client_ip.as_ref()).await?;

	// 3. Resolve definition (try full type, then base type)
	let (_definition_type, definition) = resolve_definition(app, &action.t)?;

	// 4. Check permissions (skip for pre-approved related actions)
	if !skip_permission_check {
		check_inbound_permissions(app, tn_id, &action, definition).await?;
	} else {
		debug!(
			action_id = %action_id,
			action_type = %action.t,
			issuer = %action.iss,
			"Skipping permission check for pre-approved related action"
		);
	}

	// 5. Check subscription-based permissions (skip for pre-approved related actions)
	if !skip_permission_check {
		check_subscription_permissions(app, tn_id, &action, definition).await?;
	}

	// Check if this is an ephemeral action (forward only, don't persist)
	let is_ephemeral = definition.behavior.ephemeral.unwrap_or(false);

	if is_ephemeral {
		// Ephemeral actions: forward to WebSocket but don't persist
		debug!(
			action_id = %action_id,
			action_type = %action.t,
			issuer = %action.iss,
			"Processing ephemeral action (forward only, no persistence)"
		);
		forward_inbound_action_to_websocket(app, tn_id, action_id, &action).await;
		return Ok(None);
	}

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

	// 7. Unified post-store processing (hooks, WebSocket, fanout, auto-approve)
	let (action_type, sub_type) = helpers::extract_type_and_subtype(&action.t);
	let content_str = helpers::serialize_content(action.c.as_ref()).map(|s| s.into_boxed_str());
	let root_id =
		helpers::resolve_root_id(app.meta_adapter.as_ref(), tn_id, action.p.as_deref()).await;

	// Build owned Action for unified processing
	let action_for_processing = meta_adapter::Action {
		action_id: action_id.into(),
		typ: action_type.into_boxed_str(),
		sub_typ: sub_type.map(|s| s.into_boxed_str()),
		issuer_tag: action.iss.clone(),
		parent_id: action.p.clone(),
		root_id,
		audience_tag: action.aud.clone(),
		content: content_str,
		attachments: action.a.clone(),
		subject: action.sub.clone(),
		created_at: action.iat,
		expires_at: action.exp,
		visibility: helpers::inherit_visibility(
			app.meta_adapter.as_ref(),
			tn_id,
			None,
			action.p.as_deref(),
		)
		.await,
		flags: action.f.clone(),
		x: None,
	};

	// Convert attachments to AttachmentView (no dimensions for federated actions)
	let attachment_views: Option<Vec<AttachmentView>> = action.a.as_ref().map(|v| {
		v.iter()
			.map(|file_id| AttachmentView {
				file_id: file_id.clone(),
				dim: None,
				local_variants: None,
			})
			.collect()
	});

	let result = post_store::process_after_store(
		app,
		tn_id,
		&action_for_processing,
		attachment_views.as_deref(),
		ProcessingContext::Inbound { client_address, is_sync },
	)
	.await?;

	Ok(result.hook_result)
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
	debug!(
		"  profile: {} following={} connected={}",
		action.iss,
		issuer_profile.as_ref().map(|p| p.following).unwrap_or(false),
		issuer_profile.as_ref().map(|p| p.connected.is_connected()).unwrap_or(false)
	);

	let allowed = issuer_profile
		.as_ref()
		.map(|p| p.following || p.connected.is_connected())
		.unwrap_or(false);

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

/// Check subscription-based permissions for actions that require active subscriptions
/// This validates that:
/// 1. The action type requires subscription (via requires_subscription flag)
/// 2. The issuer has an active SUBS to the target action (or is the target's creator)
/// 3. The issuer's subscription role permits the action
async fn check_subscription_permissions(
	app: &App,
	tn_id: TnId,
	action: &ActionToken,
	definition: &crate::action::dsl::types::ActionDefinition,
) -> ClResult<()> {
	// Check if this action type requires subscription
	if !definition.behavior.requires_subscription.unwrap_or(false) {
		return Ok(());
	}

	// Get the target action (subject or parent)
	let target_id = action.sub.as_deref().or(action.p.as_deref());

	let Some(target_id) = target_id else {
		// No target to validate against
		return Ok(());
	};

	// Get the target action to check the issuer
	let target_action = app.meta_adapter.get_action(tn_id, target_id).await?;

	let Some(target_action) = target_action else {
		warn!(
			action_type = %action.t,
			target_id = %target_id,
			"Subscription check: target action not found"
		);
		return Err(Error::NotFound);
	};

	// If issuer is the target action's creator, they always have permission
	if action.iss.as_ref() == target_action.issuer.id_tag.as_ref() {
		debug!(
			issuer = %action.iss,
			target_id = %target_id,
			"Subscription check: issuer is target creator, permission granted"
		);
		return Ok(());
	}

	// Check for active subscription
	let subs_key = format!("SUBS:{}:{}", target_id, action.iss);
	let subscription = app.meta_adapter.get_action_by_key(tn_id, &subs_key).await?;

	let Some(subscription) = subscription else {
		// No subscription - check if there's one for the root action
		if let Some(root_id) = &target_action.root_id {
			let root_subs_key = format!("SUBS:{}:{}", root_id, action.iss);
			let root_subscription =
				app.meta_adapter.get_action_by_key(tn_id, &root_subs_key).await?;

			let Some(root_sub) = root_subscription else {
				warn!(
					issuer = %action.iss,
					target_id = %target_id,
					action_type = %action.t,
					"Permission denied - no active subscription"
				);
				return Err(Error::PermissionDenied);
			};
			// Found root subscription - use it for role checking
			return check_subscription_role_permission(action, &root_sub);
		}

		warn!(
			issuer = %action.iss,
			target_id = %target_id,
			action_type = %action.t,
			"Permission denied - no active subscription"
		);
		return Err(Error::PermissionDenied);
	};

	// Check role permissions
	check_subscription_role_permission(action, &subscription)
}

/// Check if the subscription's role permits the action
fn check_subscription_role_permission(
	action: &ActionToken,
	subscription: &meta_adapter::Action<Box<str>>,
) -> ClResult<()> {
	// Get role from x.role (with fallback to content.role for migration)
	let content_json = subscription
		.content
		.as_ref()
		.and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok());
	let user_role = helpers::get_subscription_role(subscription.x.as_ref(), content_json.as_ref());

	// Extract action type and subtype
	let (action_type, subtype) = helpers::extract_type_and_subtype(&action.t);
	let subtype_ref = subtype.as_deref();

	// Check role permission
	let required = helpers::SubscriptionRole::required_for_action(&action_type, subtype_ref);
	if user_role < required {
		warn!(
			issuer = %action.iss,
			action_type = %action.t,
			role = ?user_role,
			required = ?required,
			"Permission denied - insufficient role"
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

	// Resolve root_id from parent chain (not just parent_id)
	let root_id =
		helpers::resolve_root_id(app.meta_adapter.as_ref(), tn_id, action.p.as_deref()).await;

	let inbound_action = meta_adapter::Action {
		action_id,
		typ: &action_type,
		sub_typ: sub_type_ref,
		issuer_tag: &action.iss,
		parent_id: action.p.as_deref(),
		root_id: root_id.as_deref(),
		audience_tag: action.aud.as_deref(),
		content: content_str.as_deref(),
		attachments: action.a.as_ref().map(|v| v.iter().map(|s| s.as_ref()).collect()),
		subject: action.sub.as_deref(),
		created_at: action.iat,
		expires_at: action.exp,
		visibility,
		flags: action.f.as_deref(),
		x: None,
	};

	match app.meta_adapter.create_action(tn_id, &inbound_action, key.as_deref()).await {
		Ok(_) => {
			info!("← STORED: {}", action_id);
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

async fn process_inbound_action_attachments(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	attachments: Vec<Box<str>>,
) -> ClResult<()> {
	use crate::file::sync::sync_file_variants;

	let mut total_synced = 0;
	let mut total_skipped = 0;
	let mut total_failed = 0;

	for attachment in &attachments {
		debug!("  syncing attachment: {}", attachment);
		match sync_file_variants(app, tn_id, id_tag, attachment, None, true).await {
			Ok(result) => {
				total_synced += result.synced_variants.len();
				total_skipped += result.skipped_variants.len();
				total_failed += result.failed_variants.len();
			}
			Err(e) => {
				warn!("  failed to sync attachment {}: {}", attachment, e);
				total_failed += 1;
			}
		}
	}

	if !attachments.is_empty() {
		info!(
			"ATTACHMENTS: {} files - synced={} skipped={} failed={}",
			attachments.len(),
			total_synced,
			total_skipped,
			total_failed
		);
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
	use crate::meta_adapter::AttachmentView;

	let (action_type, subtype) = helpers::extract_type_and_subtype(&action.t);

	// Convert file IDs to AttachmentView (no dimensions for federated actions)
	let attachments: Option<Vec<AttachmentView>> = action.a.as_ref().map(|v| {
		v.iter()
			.map(|file_id| AttachmentView {
				file_id: file_id.clone(),
				dim: None,
				local_variants: None,
			})
			.collect()
	});

	let params = ForwardActionParams {
		action_id,
		temp_id: None,
		issuer_tag: &action.iss,
		audience_tag: action.aud.as_deref(),
		action_type: &action_type,
		sub_type: subtype.as_deref(),
		content: action.c.as_ref(),
		attachments: attachments.as_deref(),
		status: None,
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

/// Process related actions that came with any action
///
/// Related actions are stored in action_tokens with ack = main_action_id.
/// This verifies and stores them (skipping permission checks as they're pre-approved).
async fn process_related_actions(app: &App, tn_id: TnId, action_id: &str) {
	// Get related action tokens that were waiting for this action
	let related_tokens = match app.meta_adapter.get_related_action_tokens(tn_id, action_id).await {
		Ok(tokens) => tokens,
		Err(_) => return,
	};

	if related_tokens.is_empty() {
		return;
	}

	info!("Processing {} related actions for {}", related_tokens.len(), action_id);

	let mut success_count = 0;
	let mut fail_count = 0;

	for (related_action_id, related_token) in &related_tokens {
		debug!("Processing related action {}", related_action_id);

		match process_preapproved_action_token(app, tn_id, related_action_id, related_token).await {
			Ok(_) => {
				success_count += 1;
			}
			Err(e) => {
				fail_count += 1;
				warn!("Failed to process related action {}: {}", related_action_id, e);
			}
		}
	}

	if fail_count > 0 {
		info!("{} related actions processed, {} failed", success_count, fail_count);
	} else {
		debug!("{} related actions processed successfully", success_count);
	}
}

// vim: ts=4
