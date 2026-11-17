// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Push notification HTTP handlers

use axum::{Json, extract::State, http::StatusCode};
use cloudillo_types::extract::JsonBody;
use serde::{Deserialize, Serialize};

use crate::prelude::*;
use crate::send::NotificationPayload;
use cloudillo_core::abac;
use cloudillo_core::extract::{Auth, IdTag};
use cloudillo_types::extract::Query;
use cloudillo_types::meta_adapter::{PushSubscriptionData, PushSubscriptionKeys};
use cloudillo_types::types::{ApiResponse, ApiTime, Capability, SHARED_TN, ScopeSet};

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
	JsonBody(body): JsonBody<CreateSubscriptionRequest>,
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
/// Removes a push notification subscription. A scoped caller (a device key) removes only its
/// own: it must prove possession by sending the row's endpoint URL in the
/// `cloudillo-push-endpoint` header; otherwise `NotFound`, revealing nothing.
pub async fn delete_subscription(
	State(app): State<App>,
	Auth(auth): Auth,
	headers: axum::http::HeaderMap,
	axum::extract::Path(subscription_id): axum::extract::Path<u64>,
) -> ClResult<StatusCode> {
	tracing::info!(
		tn_id = %auth.tn_id.0,
		subscription_id = %subscription_id,
		"Deleting push subscription"
	);

	if auth.scope.is_some() {
		let endpoint = headers
			.get("cloudillo-push-endpoint")
			.and_then(|v| v.to_str().ok())
			.ok_or(Error::NotFound)?;
		let owns = app
			.meta_adapter
			.list_push_subscriptions(auth.tn_id)
			.await?
			.iter()
			.any(|s| s.id == subscription_id && s.subscription.endpoint == endpoint);
		if !owns {
			return Err(Error::NotFound);
		}
	}

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

/// Query of `GET /api/notifications`
#[derive(Debug, Deserialize)]
pub struct ListNotificationsQuery {
	/// Return entries with `seq` greater than this (default 0)
	pub since: Option<u64>,
	/// Page size, clamped to 1..=100 (default 100)
	pub limit: Option<u32>,
}

/// One notification log entry: the pushed payload (with `seq`) plus its creation time
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationItem {
	#[serde(flatten)]
	pub payload: NotificationPayload,
	pub created_at: ApiTime,
}

/// Response of `GET /api/notifications`
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListNotificationsResponse {
	pub items: Vec<NotificationItem>,
	/// Highest `seq` fetched (unparseable rows included), or `since` when there are none
	pub last_seq: u64,
}

/// GET /api/notifications?since=<seq>&limit=<n>
///
/// The tenant's notification log after `since`, ascending — the catch-up path for clients
/// that may have missed pushes. Entries are the same payloads `send_to_tenant` pushed.
pub async fn list_notifications(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	Auth(auth): Auth,
	Query(q): Query<ListNotificationsQuery>,
) -> ClResult<Json<ApiResponse<ListNotificationsResponse>>> {
	// Unscoped: the account itself only — a community member holding `leader` passes
	// `require_leader` but must not read the log. Scoped: a key carrying `notifications:read`
	// (minted only by the owner, never via access-token; the key middleware binds it to this
	// tenant). Any other scope, malformed lists included, is refused.
	match auth.scope.as_deref() {
		None => abac::require_tenant_self(&auth, &tenant_id_tag, "notifications")?,
		Some(s) => {
			if !ScopeSet::parse(s).is_some_and(|set| set.has(Capability::NotificationsRead)) {
				return Err(Error::PermissionDenied);
			}
		}
	}
	let since = q.since.unwrap_or(0);
	let limit = q.limit.unwrap_or(100).clamp(1, 100);
	let entries = app.meta_adapter.list_notifications_since(tn_id, since, limit).await?;

	// Skipped rows still advance `last_seq`, so one bad row cannot wedge the client.
	let last_seq = entries.iter().map(|e| e.seq).max().unwrap_or(since);
	let mut items = Vec::with_capacity(entries.len());
	for entry in entries {
		let mut payload: NotificationPayload = match serde_json::from_str(&entry.payload) {
			Ok(p) => p,
			Err(error) => {
				warn!(?tn_id, seq = entry.seq, %error, "Skipping invalid notification");
				continue;
			}
		};
		payload.seq = Some(entry.seq);
		items.push(NotificationItem { payload, created_at: entry.created_at });
	}

	Ok(Json(ApiResponse::new(ListNotificationsResponse { items, last_seq })))
}

// vim: ts=4
