//! Push notification HTTP handlers

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::prelude::*;
use cloudillo_core::extract::Auth;
use cloudillo_types::meta_adapter::{PushSubscriptionData, PushSubscriptionKeys};

/// Request body for creating a push subscription
#[derive(Debug, Deserialize)]
pub struct CreateSubscriptionRequest {
	/// The push subscription from the browser's Push API
	pub subscription: BrowserSubscription,
}

/// Browser's PushSubscription format
#[derive(Debug, Deserialize)]
pub struct BrowserSubscription {
	/// Push endpoint URL
	pub endpoint: String,
	/// Expiration time (Unix timestamp in ms, from browser)
	#[serde(rename = "expirationTime")]
	pub expiration_time: Option<i64>,
	/// Subscription keys
	pub keys: BrowserSubscriptionKeys,
}

/// Browser subscription keys format
#[derive(Debug, Deserialize)]
pub struct BrowserSubscriptionKeys {
	/// P-256 public key (base64url encoded)
	pub p256dh: String,
	/// Auth secret (base64url encoded)
	pub auth: String,
}

/// Response for successful subscription
#[derive(Debug, Serialize)]
pub struct SubscriptionResponse {
	/// The created subscription ID
	pub id: u64,
}

/// POST /api/notification/subscription
///
/// Registers a push notification subscription for the authenticated user.
/// The subscription will be stored and used to send push notifications when
/// the user is offline.
pub async fn post_subscription(
	State(app): State<App>,
	Auth(auth): Auth,
	Json(body): Json<CreateSubscriptionRequest>,
) -> Result<Json<SubscriptionResponse>, (StatusCode, String)> {
	tracing::info!(
		tn_id = %auth.tn_id.0,
		endpoint = %body.subscription.endpoint,
		"Registering push subscription"
	);

	// Convert browser subscription format to our storage format
	let subscription_data = PushSubscriptionData {
		endpoint: body.subscription.endpoint,
		// Browser sends expiration in milliseconds, convert to seconds if present
		expiration_time: body.subscription.expiration_time.map(|ms| ms / 1000),
		keys: PushSubscriptionKeys {
			p256dh: body.subscription.keys.p256dh,
			auth: body.subscription.keys.auth,
		},
	};

	// Store the subscription
	let id = app
		.meta_adapter
		.create_push_subscription(auth.tn_id, &subscription_data)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to create push subscription");
			(StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save subscription: {}", e))
		})?;

	tracing::debug!(
		tn_id = %auth.tn_id.0,
		subscription_id = %id,
		"Push subscription created"
	);

	Ok(Json(SubscriptionResponse { id }))
}

/// DELETE /api/notification/subscription/{id}
///
/// Removes a push notification subscription.
pub async fn delete_subscription(
	State(app): State<App>,
	Auth(auth): Auth,
	axum::extract::Path(subscription_id): axum::extract::Path<u64>,
) -> Result<StatusCode, (StatusCode, String)> {
	tracing::info!(
		tn_id = %auth.tn_id.0,
		subscription_id = %subscription_id,
		"Deleting push subscription"
	);

	app.meta_adapter
		.delete_push_subscription(auth.tn_id, subscription_id)
		.await
		.map_err(|e| {
			tracing::error!(error = %e, "Failed to delete push subscription");
			(StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete subscription: {}", e))
		})?;

	Ok(StatusCode::NO_CONTENT)
}

/// GET /api/notification/vapid-public-key
///
/// Returns the VAPID public key for this tenant.
/// Clients need this to subscribe to push notifications.
/// If VAPID keys don't exist yet, they will be auto-generated.
pub async fn get_vapid_public_key(
	State(app): State<App>,
	Auth(auth): Auth,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
	// Try to read existing VAPID public key
	let public_key = match app.auth_adapter.read_vapid_public_key(auth.tn_id).await {
		Ok(key) => key,
		Err(Error::NotFound) => {
			// VAPID key doesn't exist, create one
			tracing::info!(tn_id = %auth.tn_id.0, "Creating VAPID key on demand");
			let keypair = app.auth_adapter.create_vapid_key(auth.tn_id).await.map_err(|e| {
				tracing::error!(error = %e, "Failed to create VAPID key");
				(StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create VAPID key: {}", e))
			})?;
			keypair.public_key
		}
		Err(e) => {
			tracing::error!(error = %e, "Failed to read VAPID public key");
			return Err((
				StatusCode::INTERNAL_SERVER_ERROR,
				format!("Failed to get VAPID key: {}", e),
			));
		}
	};

	Ok(Json(serde_json::json!({
		"vapidPublicKey": public_key
	})))
}

// vim: ts=4
