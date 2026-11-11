// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Push notification HTTP handlers

use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};

use crate::prelude::*;
use cloudillo_core::extract::Auth;
use cloudillo_types::meta_adapter::{PushSubscriptionData, PushSubscriptionKeys};
use cloudillo_types::types::{ApiResponse, SHARED_TN};

/// Request body for creating a push subscription
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSubscriptionRequest {
	/// The push subscription from the browser's Push API
	pub subscription: BrowserSubscription,
}

/// Browser's PushSubscription format
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserSubscription {
	/// Push endpoint URL
	pub endpoint: String,
	/// Expiration time (Unix timestamp in ms, from browser)
	pub expiration_time: Option<i64>,
	/// Subscription keys
	pub keys: BrowserSubscriptionKeys,
}

/// Browser subscription keys format
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserSubscriptionKeys {
	/// P-256 public key (base64url encoded)
	pub p256dh: String,
	/// Auth secret (base64url encoded)
	pub auth: String,
}

/// Response for successful subscription
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionResponse {
	/// The created subscription ID
	pub id: String,
}

/// POST /api/notifications/subscriptions
///
/// Registers a push notification subscription for the authenticated user.
/// The subscription will be stored and used to send push notifications when
/// the user is offline.
pub async fn post_subscription(
	State(app): State<App>,
	Auth(auth): Auth,
	Json(body): Json<CreateSubscriptionRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<SubscriptionResponse>>)> {
	// Server-wide off switch (`notify.push_allowed`), above any tenant `notify.push` choice.
	if !app.settings.get_bool(SHARED_TN, "notify.push_allowed").await? {
		return Err(Error::PermissionDenied);
	}

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
		.await?;

	tracing::debug!(
		tn_id = %auth.tn_id.0,
		subscription_id = %id,
		"Push subscription created"
	);

	Ok((StatusCode::CREATED, Json(ApiResponse::new(SubscriptionResponse { id: id.to_string() }))))
}

/// DELETE /api/notifications/subscriptions/{id}
///
/// Removes a push notification subscription.
pub async fn delete_subscription(
	State(app): State<App>,
	Auth(auth): Auth,
	axum::extract::Path(subscription_id): axum::extract::Path<u64>,
) -> ClResult<StatusCode> {
	tracing::info!(
		tn_id = %auth.tn_id.0,
		subscription_id = %subscription_id,
		"Deleting push subscription"
	);

	app.meta_adapter.delete_push_subscription(auth.tn_id, subscription_id).await?;

	Ok(StatusCode::NO_CONTENT)
}

/// Response for the VAPID public key endpoint
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VapidPublicKeyResponse {
	pub vapid_public_key: String,
}

/// GET /api/notifications/vapid-key
///
/// Returns the VAPID public key for this tenant.
/// Clients need this to subscribe to push notifications.
/// If VAPID keys don't exist yet, they will be auto-generated.
pub async fn get_vapid_public_key(
	State(app): State<App>,
	Auth(auth): Auth,
) -> ClResult<Json<ApiResponse<VapidPublicKeyResponse>>> {
	// Try to read existing VAPID public key
	let public_key = match app.auth_adapter.read_vapid_public_key(auth.tn_id).await {
		Ok(key) => key,
		Err(Error::NotFound) => {
			// VAPID key doesn't exist, create one
			tracing::info!(tn_id = %auth.tn_id.0, "Creating VAPID key on demand");
			app.auth_adapter.create_vapid_key(auth.tn_id).await?.public_key
		}
		Err(e) => return Err(e),
	};

	Ok(Json(ApiResponse::new(VapidPublicKeyResponse { vapid_public_key: public_key.into() })))
}

// vim: ts=4
