// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! WebAuthn (Passkey) authentication handlers

use axum::{
	Json,
	extract::{ConnectInfo, Path, State},
	http::StatusCode,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use webauthn_rs::prelude::*;

use cloudillo_core::Auth;
use cloudillo_core::extract::{IdTag, OptionalRequestId};
use cloudillo_core::rate_limit::{PenaltyReason, RateLimitApi};
use cloudillo_types::{auth_adapter, types::ApiResponse};

use crate::prelude::*;

use super::handler::return_login;

/// Challenge JWT expiry in seconds (2 minutes)
const CHALLENGE_EXPIRY_SECS: u64 = 120;

/// Challenge token claims for registration
#[derive(Debug, Serialize, Deserialize)]
struct RegChallengeToken {
	tn_id: u32,
	id_tag: String,
	state: String, // Serialized PasskeyRegistration
	exp: u64,
}

/// Challenge token claims for authentication
#[derive(Debug, Serialize, Deserialize)]
struct LoginChallengeToken {
	tn_id: u32,
	id_tag: String,
	state: String, // Serialized PasskeyAuthentication
	exp: u64,
	/// Single-use marker, see [`consume_challenge`].
	jti: String,
}

/// Login challenges spent by an accepted assertion, until they expire on their own.
///
/// WebAuthn requires a challenge be single-use, but the whole `PasskeyAuthentication`
/// state lives in the client-held JWT — without this record an accepted
/// `{token, response}` pair replays for the full [`CHALLENGE_EXPIRY_SECS`] window (the
/// signature-counter check does not catch it: the replayed JWT carries the old counter).
///
// ponytail: process-local, so a multi-process deployment would need this in the
// auth adapter's `vars` table or a shared cache instead. Memory within one TTL window is
// bounded only by the rate limiter on `GET /api/auth/wa/login/challenge`.
static SPENT_CHALLENGES: LazyLock<DashMap<String, Instant>> = LazyLock::new(DashMap::new);

/// Above this many live entries, drop the expired ones on the next insert. Rescanning past
/// the threshold is fine — `GET /api/auth/wa/login/challenge` is rate-limited, so the map
/// cannot get there often.
const SPENT_SWEEP_ABOVE: usize = 1024;

/// Record `jti` as spent; `Err` if it was already spent and not yet expired.
/// Called only once an assertion has verified; see [`post_login`].
fn consume_challenge(jti: &str) -> ClResult<()> {
	let now = Instant::now();
	// Entries are only useful until the challenge expires anyway; drop the dead ones rather
	// than grow without bound under a replay flood.
	if SPENT_CHALLENGES.len() > SPENT_SWEEP_ABOVE {
		SPENT_CHALLENGES.retain(|_, expires| now < *expires);
	}
	let expires = now + Duration::from_secs(CHALLENGE_EXPIRY_SECS);

	// One `entry`, not `get` then `insert`: those are two operations, and two concurrent
	// POSTs carrying the same accepted assertion both saw an absent key and both won. That
	// race IS the attack — an interceptor races the legitimate request rather than replaying
	// after it.
	//
	// A *stale* entry is not a replay: the challenge JWT carries the same TTL, so
	// `post_login`'s `exp` check already rejected it and "replayed" would be the wrong
	// verdict. Refresh it and admit. A live entry is refused *without* refreshing, so a
	// replay flood cannot keep a spent entry alive another full window.
	match SPENT_CHALLENGES.entry(jti.to_owned()) {
		Entry::Occupied(mut spent) => {
			if now < *spent.get() {
				warn!("WebAuthn challenge replayed");
				return Err(Error::Unauthorized);
			}
			spent.insert(expires);
		}
		Entry::Vacant(slot) => {
			slot.insert(expires);
		}
	}
	Ok(())
}

/// Fresh 128-bit single-use id for a login challenge.
fn new_jti() -> String {
	let bytes: [u8; 16] = rand::rng().random();
	URL_SAFE_NO_PAD.encode(bytes)
}

/// Build a Webauthn instance for the given tenant
fn build_webauthn(id_tag: &str) -> ClResult<Webauthn> {
	let rp_id = id_tag.to_string();
	let rp_origin = Url::parse(&format!("https://{}", id_tag))
		.map_err(|_| Error::Internal("invalid origin URL".into()))?;

	WebauthnBuilder::new(&rp_id, &rp_origin)
		.map_err(|e| {
			warn!("WebAuthn builder error: {:?}", e);
			Error::Internal("WebAuthn builder error".into())
		})?
		.rp_name(id_tag)
		.build()
		.map_err(|e| {
			warn!("WebAuthn build error: {:?}", e);
			Error::Internal("WebAuthn build error".into())
		})
}

/// Get current timestamp as seconds since epoch
fn now_secs() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs()
}

/// Create a challenge JWT token
fn create_challenge_jwt<T: Serialize>(claims: &T, secret: &str) -> ClResult<String> {
	jsonwebtoken::encode(
		&jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
		claims,
		&jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
	)
	.map_err(|e| {
		warn!("JWT encode error: {:?}", e);
		Error::Internal("JWT encode error".into())
	})
}

/// Decode and validate a challenge JWT token
fn decode_challenge_jwt<T: for<'de> Deserialize<'de>>(token: &str, secret: &str) -> ClResult<T> {
	let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
	let token_data = jsonwebtoken::decode::<T>(
		token,
		&jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
		&validation,
	)
	.map_err(|e| {
		warn!("JWT decode error: {:?}", e);
		Error::Unauthorized
	})?;

	Ok(token_data.claims)
}

/// Convert stored credentials to webauthn-rs Passkey format
///
/// The public_key field stores the full Passkey JSON serialization
fn stored_to_passkey(stored: &auth_adapter::Webauthn) -> ClResult<Passkey> {
	serde_json::from_str(&stored.public_key).map_err(|e| {
		warn!("Failed to deserialize Passkey: {:?}", e);
		Error::Internal("Failed to deserialize Passkey".into())
	})
}

// ============================================================================
// Response Types
// ============================================================================

/// Credential info for listing (without sensitive data)
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialInfo {
	credential_id: String,
	description: String,
}

/// Parse user-agent string to get a readable device/browser name
fn parse_user_agent(ua: &str) -> String {
	// Try to extract browser and OS info from user-agent
	let browser = if ua.contains("Firefox") {
		"Firefox"
	} else if ua.contains("Edg/") {
		"Edge"
	} else if ua.contains("Chrome") {
		"Chrome"
	} else if ua.contains("Safari") {
		"Safari"
	} else {
		"Browser"
	};

	let os = if ua.contains("Windows") {
		"Windows"
	} else if ua.contains("Mac OS") || ua.contains("Macintosh") {
		"macOS"
	} else if ua.contains("Linux") {
		"Linux"
	} else if ua.contains("Android") {
		"Android"
	} else if ua.contains("iPhone") || ua.contains("iPad") {
		"iOS"
	} else {
		"Unknown"
	};

	format!("{} on {}", browser, os)
}

/// Registration challenge response
/// Note: options is serialized as JSON Value to extract just the publicKey contents
/// which is what @simplewebauthn/browser expects
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegChallengeRes {
	options: serde_json::Value,
	token: String,
}

/// Login challenge response
/// Note: options is serialized as JSON Value to extract just the publicKey contents
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginChallengeRes {
	options: serde_json::Value,
	token: String,
}

// ============================================================================
// Request Types
// ============================================================================

/// Registration request body
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegReq {
	token: String,
	response: RegisterPublicKeyCredential,
	#[serde(default)]
	description: Option<String>,
}

/// Login request body
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginReq {
	token: String,
	response: PublicKeyCredential,
}

// ============================================================================
// Handlers
// ============================================================================

/// GET /api/auth/wa/reg - List WebAuthn credentials
pub async fn list_reg(
	State(app): State<App>,
	Auth(auth): Auth,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<CredentialInfo>>>)> {
	info!("Listing WebAuthn credentials for {}", auth.id_tag);

	let credentials = app.auth_adapter.list_webauthn_credentials(auth.tn_id).await?;

	let result: Vec<CredentialInfo> = credentials
		.iter()
		.map(|c| CredentialInfo {
			credential_id: c.credential_id.to_string(),
			description: c
				.description
				.as_deref()
				.map_or_else(|| "Passkey".to_string(), ToString::to_string),
		})
		.collect();

	Ok((StatusCode::OK, Json(ApiResponse::new(result))))
}

/// GET /api/auth/wa/reg/challenge - Get registration challenge
pub async fn get_reg_challenge(
	State(app): State<App>,
	IdTag(id_tag): IdTag,
	Auth(auth): Auth,
) -> ClResult<(StatusCode, Json<ApiResponse<RegChallengeRes>>)> {
	info!("Getting WebAuthn registration challenge for {}", auth.id_tag);

	// The RP is the *tenant*, not the caller: `post_login` builds it from the tenant's
	// id_tag, so enrolling under the caller's own domain would store a credential in
	// this tenant bound to an RP the enroller controls.
	let webauthn = build_webauthn(&id_tag)?;

	// Get existing credentials to exclude from registration
	let existing = app.auth_adapter.list_webauthn_credentials(auth.tn_id).await?;
	let exclude_credentials: Vec<CredentialID> = existing
		.iter()
		.filter_map(|c| URL_SAFE_NO_PAD.decode(c.credential_id.as_bytes()).ok())
		.map(CredentialID::from)
		.collect();

	// Create user unique ID from tn_id
	let user_id = Uuid::from_u128(u128::from(auth.tn_id.0));

	// Start passkey registration
	let (ccr, reg_state) = webauthn
		.start_passkey_registration(user_id, &id_tag, &id_tag, Some(exclude_credentials))
		.map_err(|e| {
			warn!("WebAuthn start_passkey_registration error: {:?}", e);
			Error::Internal("WebAuthn registration error".into())
		})?;

	// Serialize registration state
	let state_json = serde_json::to_string(&reg_state)
		.map_err(|_| Error::Internal("Failed to serialize registration state".into()))?;

	// Get JWT secret
	let jwt_secret = app.auth_adapter.read_var(TnId(0), "jwt_secret").await?;

	// Create challenge token
	let claims = RegChallengeToken {
		tn_id: auth.tn_id.0,
		id_tag: id_tag.to_string(),
		state: state_json,
		exp: now_secs() + CHALLENGE_EXPIRY_SECS,
	};
	let token = create_challenge_jwt(&claims, &jwt_secret)?;

	// Extract publicKey contents for @simplewebauthn/browser compatibility
	// webauthn-rs serializes as { publicKey: { ... } } but simplewebauthn expects just the inner object
	let ccr_json = serde_json::to_value(&ccr)
		.map_err(|_| Error::Internal("Failed to serialize challenge".into()))?;
	let options = ccr_json.get("publicKey").cloned().unwrap_or(ccr_json);

	Ok((StatusCode::OK, Json(ApiResponse::new(RegChallengeRes { options, token }))))
}

/// POST /api/auth/wa/reg - Register a new credential
pub async fn post_reg(
	State(app): State<App>,
	IdTag(id_tag): IdTag,
	Auth(auth): Auth,
	headers: axum::http::HeaderMap,
	Json(req): Json<RegReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<CredentialInfo>>)> {
	info!("Registering WebAuthn credential for {}", auth.id_tag);

	// Get JWT secret and decode challenge token
	let jwt_secret = app.auth_adapter.read_var(TnId(0), "jwt_secret").await?;
	let claims: RegChallengeToken = decode_challenge_jwt(&req.token, &jwt_secret)?;

	// Verify the token belongs to this user
	if claims.tn_id != auth.tn_id.0 {
		warn!("Token tn_id mismatch: {} != {}", claims.tn_id, auth.tn_id.0);
		return Err(Error::PermissionDenied);
	}

	// The challenge is signed with the server-wide HS256 secret, so bind it to this host
	// the way `post_login` does. The `tn_id` test above already implies it (tn_id ↔ id_tag
	// is 1:1), but the two gates must not be able to drift apart.
	if claims.id_tag.as_str() != id_tag.as_ref() {
		warn!(challenge = %claims.id_tag, host = %id_tag, "Registration challenge tenant mismatch");
		return Err(Error::PermissionDenied);
	}

	// Check expiry
	if claims.exp < now_secs() {
		warn!("Challenge token expired");
		return Err(Error::Unauthorized);
	}

	// Deserialize registration state
	let reg_state: PasskeyRegistration = serde_json::from_str(&claims.state).map_err(|e| {
		warn!("Failed to deserialize registration state: {:?}", e);
		Error::Internal("Invalid registration state".into())
	})?;

	// Build webauthn and finish registration — same RP as the challenge and as login.
	let webauthn = build_webauthn(&id_tag)?;
	let passkey = webauthn.finish_passkey_registration(&req.response, &reg_state).map_err(|e| {
		warn!("WebAuthn finish_passkey_registration error: {:?}", e);
		Error::PermissionDenied
	})?;

	// Extract credential ID (base64url encoded)
	let cred_id = URL_SAFE_NO_PAD.encode(passkey.cred_id());

	// Serialize the full Passkey for storage
	// This stores the COSE key, counter, and other credential data
	let passkey_json = serde_json::to_string(&passkey)
		.map_err(|_| Error::Internal("Failed to serialize passkey".into()))?;

	// Generate description from user-agent + timestamp if not provided
	let description = req.description.clone().unwrap_or_else(|| {
		let user_agent = headers
			.get(axum::http::header::USER_AGENT)
			.and_then(|v| v.to_str().ok())
			.unwrap_or("Unknown device");

		// Parse user-agent to get a readable device name
		let device_name = parse_user_agent(user_agent);
		let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC");
		format!("{} - {}", device_name, timestamp)
	});

	// Store the credential
	// Note: public_key field stores the full Passkey JSON
	let webauthn_data = auth_adapter::Webauthn {
		credential_id: cred_id.as_str().into(),
		counter: 0, // Initial counter, will be managed by Passkey internally
		public_key: passkey_json.as_str().into(),
		description: Some(description.as_str().into()),
	};
	app.auth_adapter.create_webauthn_credential(auth.tn_id, &webauthn_data).await?;

	info!("WebAuthn credential registered: {}", cred_id);

	Ok((
		StatusCode::CREATED,
		Json(ApiResponse::new(CredentialInfo { credential_id: cred_id, description })),
	))
}

/// DELETE /api/auth/wa/reg/{key_id} - Delete a credential
pub async fn delete_reg(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(key_id): Path<String>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	info!("Deleting WebAuthn credential {} for {}", key_id, auth.id_tag);

	app.auth_adapter.delete_webauthn_credential(auth.tn_id, &key_id).await?;

	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

/// The tenant's stored credentials that still deserialize into a usable [`Passkey`].
async fn valid_passkeys(app: &App, tn_id: TnId) -> Vec<Passkey> {
	let Ok(credentials) = app.auth_adapter.list_webauthn_credentials(tn_id).await else {
		return Vec::new();
	};
	credentials.iter().filter_map(|c| stored_to_passkey(c).ok()).collect()
}

/// Whether the tenant has at least one usable passkey — all `login-init` needs.
/// The challenge itself is minted separately by `GET /api/auth/wa/login/challenge`
/// at the moment the user clicks: `login-init` runs at page load, an unbounded
/// time earlier, so a challenge minted there would often already be expired.
pub async fn has_passkeys(app: &App, tn_id: TnId) -> bool {
	!valid_passkeys(app, tn_id).await.is_empty()
}

/// Try to create a login challenge, returning `None` instead of an error when no passkeys exist.
async fn try_login_challenge(app: &App, id_tag: &IdTag, tn_id: TnId) -> Option<LoginChallengeRes> {
	let passkeys = valid_passkeys(app, tn_id).await;

	if passkeys.is_empty() {
		warn!("No valid passkeys found for {}", id_tag.0);
		return None;
	}

	// Build webauthn and start authentication
	let webauthn = build_webauthn(&id_tag.0)
		.map_err(|e| warn!("WebAuthn build_webauthn error: {:?}", e))
		.ok()?;
	let (rcr, auth_state) = webauthn
		.start_passkey_authentication(&passkeys)
		.map_err(|e| {
			warn!("WebAuthn start_passkey_authentication error: {:?}", e);
		})
		.ok()?;

	// Serialize authentication state
	let state_json = serde_json::to_string(&auth_state)
		.map_err(|e| warn!("WebAuthn state serialization error: {:?}", e))
		.ok()?;

	// Get JWT secret
	let jwt_secret = app
		.auth_adapter
		.read_var(TnId(0), "jwt_secret")
		.await
		.map_err(|e| warn!("WebAuthn jwt_secret read error: {:?}", e))
		.ok()?;

	// Create challenge token
	let claims = LoginChallengeToken {
		tn_id: tn_id.0,
		id_tag: id_tag.0.to_string(),
		state: state_json,
		exp: now_secs() + CHALLENGE_EXPIRY_SECS,
		jti: new_jti(),
	};
	let token = create_challenge_jwt(&claims, &jwt_secret)
		.map_err(|e| warn!("WebAuthn challenge JWT creation error: {:?}", e))
		.ok()?;

	// Extract publicKey contents for @simplewebauthn/browser compatibility
	let rcr_json = serde_json::to_value(&rcr)
		.map_err(|e| warn!("WebAuthn rcr serialization error: {:?}", e))
		.ok()?;
	let options = rcr_json.get("publicKey").cloned().unwrap_or(rcr_json);

	Some(LoginChallengeRes { options, token })
}

/// GET /api/auth/wa/login/challenge - Get login challenge
pub async fn get_login_challenge(
	State(app): State<App>,
	id_tag: IdTag,
	tn_id: TnId,
) -> ClResult<(StatusCode, Json<ApiResponse<LoginChallengeRes>>)> {
	info!("Getting WebAuthn login challenge for {}", id_tag.0);

	let result = try_login_challenge(&app, &id_tag, tn_id).await.ok_or(Error::NotFound)?;

	Ok((StatusCode::OK, Json(ApiResponse::new(result))))
}

/// POST /api/auth/wa/login - Authenticate with WebAuthn
pub async fn post_login(
	State(app): State<App>,
	IdTag(host_id_tag): IdTag,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Json(req): Json<LoginReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<super::handler::Login>>)> {
	info!("Processing WebAuthn login");

	// Credential failures are penalized like a wrong password; server-side faults are not.
	let penalize = || {
		if let Err(e) = app.rate_limiter.penalize(&addr.ip(), PenaltyReason::AuthFailure, 1) {
			warn!("Failed to record auth penalty for {}: {}", addr.ip(), e);
		}
	};

	// Get JWT secret and decode challenge token
	let jwt_secret = app.auth_adapter.read_var(TnId(0), "jwt_secret").await?;
	let claims: LoginChallengeToken =
		decode_challenge_jwt(&req.token, &jwt_secret).inspect_err(|_| penalize())?;

	// Check expiry
	if claims.exp < now_secs() {
		warn!("Challenge token expired");
		penalize();
		return Err(Error::Unauthorized);
	}

	// The challenge is signed with the server-wide HS256 secret, so one minted at
	// tenant A's host would otherwise be accepted at any host on this server.
	if claims.id_tag.as_str() != host_id_tag.as_ref() {
		warn!(challenge = %claims.id_tag, host = %host_id_tag, "Challenge tenant mismatch");
		penalize();
		return Err(Error::Unauthorized);
	}

	// Deserialize authentication state
	let auth_state: PasskeyAuthentication = serde_json::from_str(&claims.state).map_err(|e| {
		warn!("Failed to deserialize authentication state: {:?}", e);
		Error::Internal("Invalid authentication state".into())
	})?;

	// Build webauthn and finish authentication
	let webauthn = build_webauthn(&claims.id_tag)?;
	let auth_result =
		webauthn
			.finish_passkey_authentication(&req.response, &auth_state)
			.map_err(|e| {
				warn!("WebAuthn finish_passkey_authentication error: {:?}", e);
				penalize();
				Error::PermissionDenied
			})?;

	// Spend the challenge now that an assertion has actually been accepted; see
	// `SPENT_CHALLENGES` for why the record is needed at all.
	//
	// Deliberately *after* verification, not before: a rejected assertion (a cancelled
	// prompt, the wrong authenticator, a dropped connection) never used the challenge, so
	// burning it there would force the client to refetch on every mistyped tap. There is
	// nothing to brute-force in the widened window — an acceptable assertion needs the
	// authenticator's private key — and `penalize()` plus the IP ban cover the attempts.
	consume_challenge(&claims.jti).inspect_err(|_| penalize())?;

	// Update the counter in the stored credential
	let cred_id = URL_SAFE_NO_PAD.encode(auth_result.cred_id());
	app.auth_adapter
		.update_webauthn_credential_counter(TnId(claims.tn_id), &cred_id, auth_result.counter())
		.await?;

	info!("WebAuthn authentication successful for {}", claims.id_tag);

	// Create login session
	let auth_login = app.auth_adapter.create_tenant_login(&claims.id_tag, &host_id_tag).await?;

	// Return login response using existing pattern
	let (status, json) = return_login(&app, auth_login).await?;
	Ok((status, Json(ApiResponse::new(json.0))))
}

#[cfg(test)]
mod tests {
	use super::{consume_challenge, new_jti};

	/// The property the record exists for: an accepted assertion's challenge cannot be
	/// spent twice. (`post_login` calls this only after verification succeeds, so a
	/// failed attempt never reaches here and its challenge stays usable.)
	#[test]
	fn a_spent_challenge_cannot_be_spent_again() {
		let jti = new_jti();
		assert!(consume_challenge(&jti).is_ok());
		assert!(consume_challenge(&jti).is_err());
	}

	#[test]
	fn distinct_challenges_are_independent() {
		let a = new_jti();
		let b = new_jti();
		assert_ne!(a, b);
		assert!(consume_challenge(&a).is_ok());
		assert!(consume_challenge(&b).is_ok());
	}

	/// The race the `entry` transaction closes: `get` then `insert` let two concurrent
	/// callers both observe an absent key and both win, which is how an interceptor
	/// beats the legitimate request rather than replaying after it.
	#[test]
	fn concurrent_callers_spend_a_challenge_exactly_once() {
		use std::sync::{Arc, Barrier};

		const THREADS: usize = 16;
		let jti = new_jti();
		let barrier = Arc::new(Barrier::new(THREADS));

		let winners: usize = std::thread::scope(|s| {
			let handles: Vec<_> = (0..THREADS)
				.map(|_| {
					let jti = jti.clone();
					let barrier = Arc::clone(&barrier);
					s.spawn(move || {
						barrier.wait();
						consume_challenge(&jti).is_ok()
					})
				})
				.collect();
			handles
				.into_iter()
				.map(|h| h.join().unwrap_or(false))
				.filter(|won| *won)
				.count()
		});

		assert_eq!(winners, 1, "a challenge must be spendable exactly once");
	}
}

// vim: ts=4
