//! WebAuthn (Passkey) authentication handlers

use axum::{
	extract::{Path, State},
	http::StatusCode,
	Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use url::Url;
use webauthn_rs::prelude::*;

use cloudillo_core::extract::IdTag;
use cloudillo_core::Auth;
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
	serde_json::from_str(stored.public_key).map_err(|e| {
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
#[derive(Serialize)]
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
				.map(|s| s.to_string())
				.unwrap_or_else(|| "Passkey".to_string()),
		})
		.collect();

	Ok((StatusCode::OK, Json(ApiResponse::new(result))))
}

/// GET /api/auth/wa/reg/challenge - Get registration challenge
pub async fn get_reg_challenge(
	State(app): State<App>,
	Auth(auth): Auth,
) -> ClResult<(StatusCode, Json<ApiResponse<RegChallengeRes>>)> {
	info!("Getting WebAuthn registration challenge for {}", auth.id_tag);

	let webauthn = build_webauthn(&auth.id_tag)?;

	// Get existing credentials to exclude from registration
	let existing = app.auth_adapter.list_webauthn_credentials(auth.tn_id).await?;
	let exclude_credentials: Vec<CredentialID> = existing
		.iter()
		.filter_map(|c| URL_SAFE_NO_PAD.decode(c.credential_id).ok())
		.map(CredentialID::from)
		.collect();

	// Create user unique ID from tn_id
	let user_id = Uuid::from_u128(auth.tn_id.0 as u128);

	// Start passkey registration
	let (ccr, reg_state) = webauthn
		.start_passkey_registration(user_id, &auth.id_tag, &auth.id_tag, Some(exclude_credentials))
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
		id_tag: auth.id_tag.to_string(),
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

	// Build webauthn and finish registration
	let webauthn = build_webauthn(&auth.id_tag)?;
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
		credential_id: &cred_id,
		counter: 0, // Initial counter, will be managed by Passkey internally
		public_key: &passkey_json,
		description: Some(&description),
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
) -> ClResult<StatusCode> {
	info!("Deleting WebAuthn credential {} for {}", key_id, auth.id_tag);

	app.auth_adapter.delete_webauthn_credential(auth.tn_id, &key_id).await?;

	Ok(StatusCode::NO_CONTENT)
}

/// GET /api/auth/wa/login/challenge - Get login challenge
pub async fn get_login_challenge(
	State(app): State<App>,
	id_tag: IdTag,
	tn_id: TnId,
) -> ClResult<(StatusCode, Json<ApiResponse<LoginChallengeRes>>)> {
	info!("Getting WebAuthn login challenge for {}", id_tag.0);

	// Get credentials for this tenant
	let credentials = app.auth_adapter.list_webauthn_credentials(tn_id).await?;
	if credentials.is_empty() {
		return Err(Error::NotFound);
	}

	// Convert to Passkey format
	let passkeys: Vec<Passkey> =
		credentials.iter().filter_map(|c| stored_to_passkey(c).ok()).collect();

	if passkeys.is_empty() {
		warn!("No valid passkeys found for {}", id_tag.0);
		return Err(Error::NotFound);
	}

	// Build webauthn and start authentication
	let webauthn = build_webauthn(&id_tag.0)?;
	let (rcr, auth_state) = webauthn.start_passkey_authentication(&passkeys).map_err(|e| {
		warn!("WebAuthn start_passkey_authentication error: {:?}", e);
		Error::Internal("WebAuthn authentication error".into())
	})?;

	// Serialize authentication state
	let state_json = serde_json::to_string(&auth_state)
		.map_err(|_| Error::Internal("Failed to serialize auth state".into()))?;

	// Get JWT secret
	let jwt_secret = app.auth_adapter.read_var(TnId(0), "jwt_secret").await?;

	// Create challenge token
	let claims = LoginChallengeToken {
		tn_id: tn_id.0,
		id_tag: id_tag.0.to_string(),
		state: state_json,
		exp: now_secs() + CHALLENGE_EXPIRY_SECS,
	};
	let token = create_challenge_jwt(&claims, &jwt_secret)?;

	// Extract publicKey contents for @simplewebauthn/browser compatibility
	let rcr_json = serde_json::to_value(&rcr)
		.map_err(|_| Error::Internal("Failed to serialize challenge".into()))?;
	let options = rcr_json.get("publicKey").cloned().unwrap_or(rcr_json);

	Ok((StatusCode::OK, Json(ApiResponse::new(LoginChallengeRes { options, token }))))
}

/// POST /api/auth/wa/login - Authenticate with WebAuthn
pub async fn post_login(
	State(app): State<App>,
	Json(req): Json<LoginReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<super::handler::Login>>)> {
	info!("Processing WebAuthn login");

	// Get JWT secret and decode challenge token
	let jwt_secret = app.auth_adapter.read_var(TnId(0), "jwt_secret").await?;
	let claims: LoginChallengeToken = decode_challenge_jwt(&req.token, &jwt_secret)?;

	// Check expiry
	if claims.exp < now_secs() {
		warn!("Challenge token expired");
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
				Error::PermissionDenied
			})?;

	// Update the counter in the stored credential
	let cred_id = URL_SAFE_NO_PAD.encode(auth_result.cred_id());
	app.auth_adapter
		.update_webauthn_credential_counter(TnId(claims.tn_id), &cred_id, auth_result.counter())
		.await?;

	info!("WebAuthn authentication successful for {}", claims.id_tag);

	// Create login session
	let auth_login = app.auth_adapter.create_tenant_login(&claims.id_tag).await?;

	// Return login response using existing pattern
	let (status, json) = return_login(&app, auth_login).await?;
	Ok((status, Json(ApiResponse::new(json.0))))
}

// vim: ts=4
