//! Web Push notification sending
//!
//! Implements RFC 8030 (HTTP/2 Push), RFC 8188 (Encrypted Content-Encoding),
//! RFC 8291 (Message Encryption for Web Push), and RFC 8292 (VAPID).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::prelude::*;
use cloudillo_types::meta_adapter::PushSubscriptionData;

/// Notification payload to send to the client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationPayload {
	/// Notification title
	pub title: String,
	/// Notification body text
	pub body: String,
	/// URL path to open when clicked (optional)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub path: Option<String>,
	/// Image URL (optional)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub image: Option<String>,
	/// Tag for grouping notifications (optional)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub tag: Option<String>,
}

/// Result of sending a push notification
#[derive(Debug)]
pub enum PushResult {
	/// Successfully sent
	Success,
	/// Subscription is no longer valid (should be deleted)
	SubscriptionGone,
	/// Temporary error (can retry)
	TemporaryError(String),
	/// Permanent error (don't retry)
	PermanentError(String),
}

/// Send a push notification to a subscription
///
/// # Arguments
/// * `app` - Application state (for HTTP client and VAPID keys)
/// * `tn_id` - Tenant ID (for VAPID keys)
/// * `subscription` - Push subscription data (endpoint and keys)
/// * `payload` - Notification payload
///
/// # Returns
/// * `PushResult` indicating success or failure type
pub async fn send_notification(
	app: &App,
	tn_id: TnId,
	subscription: &PushSubscriptionData,
	payload: &NotificationPayload,
) -> PushResult {
	// Get VAPID keys for this tenant
	let vapid_keys = match app.auth_adapter.read_vapid_key(tn_id).await {
		Ok(keys) => keys,
		Err(e) => {
			tracing::error!(tn_id = %tn_id.0, error = %e, "Failed to get VAPID keys");
			return PushResult::PermanentError(format!("VAPID key error: {}", e));
		}
	};

	// Serialize payload
	let payload_json = match serde_json::to_string(payload) {
		Ok(json) => json,
		Err(e) => return PushResult::PermanentError(format!("Payload serialization error: {}", e)),
	};

	// Encrypt the payload using ECE (Encrypted Content-Encoding)
	let encrypted =
		match encrypt_payload(&payload_json, &subscription.keys.p256dh, &subscription.keys.auth) {
			Ok(enc) => enc,
			Err(e) => return PushResult::PermanentError(format!("Encryption error: {}", e)),
		};

	// Get tenant id_tag for VAPID subject
	let id_tag = match app.auth_adapter.read_id_tag(tn_id).await {
		Ok(tag) => tag,
		Err(e) => {
			tracing::error!(tn_id = %tn_id.0, error = %e, "Failed to get tenant id_tag");
			return PushResult::PermanentError(format!("Tenant lookup error: {}", e));
		}
	};

	// Create VAPID JWT
	let vapid_jwt = match create_vapid_jwt(&subscription.endpoint, &id_tag, &vapid_keys.private_key)
	{
		Ok(jwt) => jwt,
		Err(e) => return PushResult::PermanentError(format!("VAPID JWT error: {}", e)),
	};

	// Send the HTTP/2 POST request
	send_push_request(
		&subscription.endpoint,
		&encrypted.body,
		&encrypted.salt,
		&encrypted.public_key,
		&vapid_jwt,
		&vapid_keys.public_key,
	)
	.await
}

/// Encrypted payload data
struct EncryptedPayload {
	body: Vec<u8>,
	salt: Vec<u8>,
	public_key: Vec<u8>,
}

/// Encrypt payload using ECE (RFC 8188, 8291)
fn encrypt_payload(
	payload: &str,
	p256dh_base64: &str,
	auth_base64: &str,
) -> Result<EncryptedPayload, String> {
	// Decode the subscription's public key and auth secret
	let p256dh = URL_SAFE_NO_PAD
		.decode(p256dh_base64)
		.map_err(|e| format!("Invalid p256dh: {}", e))?;
	let auth = URL_SAFE_NO_PAD
		.decode(auth_base64)
		.map_err(|e| format!("Invalid auth: {}", e))?;

	// Encrypt using ece crate with aes128gcm scheme
	// The ece::encrypt function takes: remote_public_key, auth_secret, plaintext
	let encrypted = ece::encrypt(&p256dh, &auth, payload.as_bytes())
		.map_err(|e| format!("ECE encryption failed: {:?}", e))?;

	// The encrypted result is already in aes128gcm format
	// Format: salt (16 bytes) || rs (4 bytes) || keyid_len (1 byte) || keyid || ciphertext
	let body = encrypted.to_vec();

	// Extract salt (first 16 bytes)
	let salt = body.get(0..16).ok_or("Encrypted data too short")?.to_vec();

	// The record size is at bytes 16-20, key ID length at byte 20
	let keyid_len = *body.get(20).ok_or("Missing keyid length")? as usize;
	let public_key = body.get(21..21 + keyid_len).ok_or("Missing public key")?.to_vec();

	Ok(EncryptedPayload { body, salt, public_key })
}

/// Create VAPID JWT (RFC 8292)
///
/// private_key_raw is the raw 32-byte P-256 scalar, base64url encoded
/// (compatible with TypeScript version storage format)
fn create_vapid_jwt(endpoint: &str, id_tag: &str, private_key_raw: &str) -> Result<String, String> {
	use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
	use p256::pkcs8::EncodePrivateKey;
	use p256::pkcs8::LineEnding;

	// Decode the raw private key scalar from base64url
	let private_key_bytes = URL_SAFE_NO_PAD
		.decode(private_key_raw)
		.map_err(|e| format!("Invalid base64url private key: {}", e))?;

	// Load the raw scalar into p256 SecretKey
	let secret_key = p256::SecretKey::from_bytes(private_key_bytes.as_slice().into())
		.map_err(|e| format!("Invalid P-256 private key: {:?}", e))?;

	// Convert to PEM format for jsonwebtoken
	let pem = secret_key
		.to_pkcs8_pem(LineEnding::LF)
		.map_err(|e| format!("Failed to encode private key: {:?}", e))?;

	// Parse endpoint to get the audience (origin)
	let url = url::Url::parse(endpoint).map_err(|e| format!("Invalid endpoint URL: {}", e))?;
	let audience = format!("{}://{}", url.scheme(), url.host_str().unwrap_or(""));

	// JWT claims for VAPID
	#[derive(Serialize)]
	struct VapidClaims {
		aud: String,
		exp: u64,
		sub: String,
	}

	let exp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs()
		+ 12 * 3600; // 12 hours

	let claims = VapidClaims { aud: audience, exp, sub: format!("mailto:admin@{}", id_tag) };

	// VAPID uses ES256 (P-256 curve, SHA-256)
	let encoding_key = EncodingKey::from_ec_pem(pem.as_bytes())
		.map_err(|e| format!("Invalid VAPID private key: {}", e))?;

	let header = Header::new(Algorithm::ES256);
	encode(&header, &claims, &encoding_key).map_err(|e| format!("JWT encoding failed: {}", e))
}

/// Send the encrypted push request
async fn send_push_request(
	endpoint: &str,
	body: &[u8],
	_salt: &[u8],
	_public_key: &[u8],
	vapid_jwt: &str,
	vapid_public_key: &str,
) -> PushResult {
	// Create HTTP/2 client for push service
	let connector = match HttpsConnectorBuilder::new()
		.with_native_roots()
		.map_err(|e| format!("TLS error: {}", e))
	{
		Ok(c) => c.https_only().enable_http2().build(),
		Err(e) => return PushResult::PermanentError(e),
	};

	let client: Client<_, Full<Bytes>> =
		Client::builder(TokioExecutor::new()).http2_only(true).build(connector);

	// Build the request
	// For aes128gcm, the body already contains salt and public key in the header
	let request = match hyper::Request::builder()
		.method(hyper::Method::POST)
		.uri(endpoint)
		.header("Content-Type", "application/octet-stream")
		.header("Content-Encoding", "aes128gcm")
		.header("TTL", "86400") // 24 hours
		.header(
			"Authorization",
			format!("vapid t={},k={}", vapid_jwt, vapid_public_key),
		)
		.body(Full::new(Bytes::copy_from_slice(body)))
	{
		Ok(req) => req,
		Err(e) => return PushResult::PermanentError(format!("Request build error: {}", e)),
	};

	// Send the request
	match client.request(request).await {
		Ok(response) => {
			let status = response.status();
			if status.is_success() {
				PushResult::Success
			} else if status == hyper::StatusCode::GONE || status == hyper::StatusCode::NOT_FOUND {
				// 404/410 = subscription no longer valid
				PushResult::SubscriptionGone
			} else if status.is_client_error() {
				// 4xx (except 404/410) = permanent error
				let body_bytes = response.into_body().collect().await.ok().map(|b| b.to_bytes());
				let body_str =
					body_bytes.as_ref().and_then(|b| std::str::from_utf8(b).ok()).unwrap_or("");
				PushResult::PermanentError(format!("HTTP {}: {}", status, body_str))
			} else {
				// 5xx = temporary error
				PushResult::TemporaryError(format!("HTTP {}", status))
			}
		}
		Err(e) => PushResult::TemporaryError(format!("Network error: {}", e)),
	}
}

/// Send notification to all subscriptions for a tenant
///
/// Returns the number of successfully sent notifications and removes invalid subscriptions.
pub async fn send_to_tenant(
	app: &App,
	tn_id: TnId,
	payload: &NotificationPayload,
) -> ClResult<usize> {
	let subscriptions = app.meta_adapter.list_push_subscriptions(tn_id).await?;
	let mut success_count = 0;

	for subscription in subscriptions {
		let result = send_notification(app, tn_id, &subscription.subscription, payload).await;

		match result {
			PushResult::Success => {
				success_count += 1;
				tracing::debug!(
					tn_id = %tn_id.0,
					subscription_id = %subscription.id,
					"Push notification sent successfully"
				);
			}
			PushResult::SubscriptionGone => {
				// Delete the invalid subscription
				tracing::info!(
					tn_id = %tn_id.0,
					subscription_id = %subscription.id,
					"Deleting invalid push subscription"
				);
				let _ = app.meta_adapter.delete_push_subscription(tn_id, subscription.id).await;
			}
			PushResult::TemporaryError(e) => {
				tracing::warn!(
					tn_id = %tn_id.0,
					subscription_id = %subscription.id,
					error = %e,
					"Temporary push notification error"
				);
			}
			PushResult::PermanentError(e) => {
				tracing::error!(
					tn_id = %tn_id.0,
					subscription_id = %subscription.id,
					error = %e,
					"Permanent push notification error"
				);
			}
		}
	}

	Ok(success_count)
}

// vim: ts=4
