// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Admin email testing handlers

use axum::{
	Json,
	extract::State,
	http::StatusCode,
	response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use std::sync::Arc;

use cloudillo_core::extract::Auth;
use cloudillo_email::{EmailMessage, EmailModule};
use cloudillo_types::types::{ApiResponse, ErrorResponse};

use crate::prelude::*;

/// Request body for test email endpoint
#[derive(Debug, Clone, Deserialize)]
pub struct TestEmailRequest {
	/// Target email address to send the test email to
	pub to: String,
}

/// Response body for test email endpoint
#[derive(Debug, Clone, Serialize)]
pub struct TestEmailResponse {
	/// Whether the test email was sent successfully
	pub success: bool,
	/// Human-readable status message
	pub message: String,
}

/// POST /api/admin/email/test - Send a test email to verify email configuration
///
/// This endpoint allows administrators to verify that email settings are properly
/// configured by sending a test email to a specified address.
#[axum::debug_handler]
pub async fn send_test_email(
	State(app): State<App>,
	Auth(auth_ctx): Auth,
	Json(request): Json<TestEmailRequest>,
) -> ClResult<Response> {
	let tn_id = auth_ctx.tn_id;

	info!(
		tn_id = ?tn_id,
		to = %request.to,
		"POST /api/admin/email/test - Sending test email"
	);

	// Validate email format (basic check)
	if !request.to.contains('@') || !request.to.contains('.') {
		return Ok((
			StatusCode::BAD_REQUEST,
			Json(ErrorResponse::new(
				"INVALID_EMAIL_FORMAT".to_string(),
				"Invalid email address format. Email address must contain @ and .".to_string(),
			)),
		)
			.into_response());
	}

	// `EmailSender::send_test` intentionally bypasses the `email.enabled`
	// toggle (admins must be able to validate SMTP without flipping the
	// global on/off switch) and reports a missing SMTP host as
	// `SmtpCategory::NotConfigured`. We delegate to it directly instead of
	// pre-flight checks: the pre-flight reads used `.unwrap_or(_)` which
	// silently masked transient adapter errors, and the `email.enabled`
	// short-circuit was wrong for the test path anyway.

	// Get base_id_tag for sender name
	let base_id_tag = app.opts.base_id_tag.as_ref().map_or("cloudillo", AsRef::as_ref);

	// Create test email message
	let message = EmailMessage {
		to: request.to.clone(),
		subject: format!("Test Email from Cloudillo ({})", base_id_tag),
		text_body: format!(
			"This is a test email from your Cloudillo instance ({}).\n\n\
			If you received this email, your email configuration is working correctly.\n\n\
			-- Cloudillo",
			base_id_tag
		),
		html_body: Some(format!(
			"<html><body>\
			<h2>Test Email from Cloudillo</h2>\
			<p>This is a test email from your Cloudillo instance (<strong>{}</strong>).</p>\
			<p>If you received this email, your email configuration is working correctly.</p>\
			<hr>\
			<p style=\"color: #666;\">-- Cloudillo</p>\
			</body></html>",
			base_id_tag
		)),
		from_name_override: Some(format!("Cloudillo | {}", base_id_tag.to_uppercase())),
	};

	// Send immediately for direct feedback
	match app.ext::<Arc<EmailModule>>()?.send_test(tn_id, message).await {
		Ok(()) => {
			info!(
				tn_id = ?tn_id,
				to = %request.to,
				"Test email sent successfully"
			);
			Ok((
				StatusCode::OK,
				Json(ApiResponse::new(TestEmailResponse {
					success: true,
					message: format!("Test email sent to {}", request.to),
				})),
			)
				.into_response())
		}
		Err(diag) => {
			warn!(
				tn_id = ?tn_id,
				to = %request.to,
				category = ?diag.category,
				smtp_code = ?diag.smtp_code,
				raw = %diag.raw,
				"Failed to send test email"
			);
			// `SmtpDiagnostic` is `#[derive(Serialize)]` over plain
			// String/Option<String>/Option<u16>/enum, so this conversion
			// can't actually fail. Fallback kept defensively in case the
			// shape grows a fallible field later.
			let details = serde_json::to_value(&diag)
				.unwrap_or_else(|_| serde_json::json!({"category": "other"}));
			// `NotConfigured` is a configuration precondition, not a transient
			// SMTP delivery failure — surface it as 412 with a distinct error
			// code so the admin UI can prompt the user to set SMTP host.
			let (status, code) = match diag.category {
				cloudillo_email::SmtpCategory::NotConfigured => {
					(StatusCode::PRECONDITION_FAILED, "SMTP_NOT_CONFIGURED")
				}
				_ => (StatusCode::SERVICE_UNAVAILABLE, "SMTP_SEND_FAILED"),
			};
			Ok((
				status,
				Json(
					ErrorResponse::new(code.to_string(), diag.message.clone())
						.with_details(details),
				),
			)
				.into_response())
		}
	}
}

// vim: ts=4
