// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Admin certificate-status endpoint
//!
//! Surfaces ACME renewal state (expiry, last error, failure count, last
//! notification, tenant status) so admin / future banner UIs can show whether
//! the local TLS cert is healthy.

use axum::{Json, extract::State, http::StatusCode};
use cloudillo_types::types::ApiResponse;
use serde::Serialize;
use serde_with::skip_serializing_none;

use crate::prelude::*;

#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertStatusResponse {
	pub domain: String,
	pub expires_at: String,
	pub days_until_expiry: i64,
	pub last_renewal_attempt_at: Option<String>,
	pub last_renewal_error: Option<String>,
	pub failure_count: u32,
	pub notified_at: Option<String>,
	pub tenant_status: Option<String>,
}

/// GET /api/admin/cert-status — current ACME renewal state for the caller's tenant
#[axum::debug_handler]
pub async fn get_cert_status(
	State(app): State<App>,
	tn_id: TnId,
) -> ClResult<(StatusCode, Json<ApiResponse<CertStatusResponse>>)> {
	let cert = app.auth_adapter.read_cert_by_tn_id(tn_id).await?;

	let tenant_status = match app.auth_adapter.read_tenant(cert.id_tag.as_ref()).await {
		Ok(profile) => profile.status.map(|s| s.to_string()),
		Err(e) => {
			warn!(error = %e, tn_id = ?tn_id, "Failed to read tenant status for cert-status");
			None
		}
	};

	let now = Timestamp::now().0;
	let days_until_expiry = (cert.expires_at.0 - now) / 86400;

	let response = CertStatusResponse {
		domain: cert.domain.to_string(),
		expires_at: cert.expires_at.to_iso_string(),
		days_until_expiry,
		last_renewal_attempt_at: cert.last_renewal_attempt_at.map(|t| t.to_iso_string()),
		last_renewal_error: cert.last_renewal_error.map(|s| s.to_string()),
		failure_count: cert.failure_count,
		notified_at: cert.notified_at.map(|t| t.to_iso_string()),
		tenant_status,
	};

	Ok((StatusCode::OK, Json(ApiResponse::new(response))))
}

// vim: ts=4
