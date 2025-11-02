//! Registration and email verification handlers

use axum::{
	extract::{Json, State},
	http::StatusCode,
};
use serde_json::json;

use crate::{
	meta_adapter::{Profile, ProfileType},
	prelude::*,
	types::{RegisterRequest, RegisterVerifyRequest},
};

/// POST /auth/register - Register new user with email
pub async fn post_register(
	State(app): State<App>,
	Json(req): Json<RegisterRequest>,
) -> ClResult<(StatusCode, Json<serde_json::Value>)> {
	// Validate id_tag format
	if req.id_tag.is_empty() || req.id_tag.len() > 64 {
		return Err(Error::Unknown);
	}

	// Check if id_tag is already registered
	match app.auth_adapter.read_tn_id(&req.id_tag).await {
		Ok(_) => return Err(Error::PermissionDenied), // Already exists
		Err(Error::NotFound) => {}                    // Good, doesn't exist yet
		Err(e) => return Err(e),
	}

	// If email provided, generate verification token
	let verify_token = if let Some(email) = &req.email {
		// Check email format (simple validation)
		if !email.contains('@') {
			return Err(Error::Unknown);
		}

		// Create registration verification token
		let token = app.auth_adapter.create_registration_verification(email).await?;

		// Send verification email to user
		// In production, this would send a real email via SMTP
		// For now, we log the verification information
		let verification_link = format!("https://{}/auth/register-verify", &req.id_tag);

		info!("Registration verification initiated for email: {}", email);
		info!("Verification link (for manual testing): {}", verification_link);

		// Log the actual token for development/testing
		debug!("Verification token: {}", token);

		Some(token)
	} else {
		None
	};

	// Return registration response
	let response = json!({
		"id_tag": req.id_tag,
		"verify_token": verify_token,
		"message": if verify_token.is_some() {
			"Registration initiated. Check your email for verification code."
		} else {
			"Registration initiated. Use your id_tag to login."
		}
	});

	Ok((StatusCode::CREATED, Json(response)))
}

/// POST /auth/register-verify - Verify email and create account
pub async fn post_register_verify(
	State(app): State<App>,
	Json(req): Json<RegisterVerifyRequest>,
) -> ClResult<(StatusCode, Json<serde_json::Value>)> {
	// Validate request fields
	if req.id_tag.is_empty() || req.verify_token.is_empty() {
		return Err(Error::Unknown);
	}

	// Check if id_tag is already registered
	match app.auth_adapter.read_tn_id(&req.id_tag).await {
		Ok(_) => return Err(Error::PermissionDenied), // Already exists
		Err(Error::NotFound) => {}                    // Good, doesn't exist yet
		Err(e) => return Err(e),
	}

	// Create tenant with verification code
	// Note: The create_tenant method expects email + vfy_code to validate
	// We need to find the email associated with the verify token
	// For now, we'll create the tenant without the vfy_code
	// This will be improved when auth_adapter has a method to get email from token

	let tn_id = app
		.auth_adapter
		.create_tenant(&req.id_tag, None, Some(&req.verify_token))
		.await?;

	// Create initial profile
	let profile = Profile {
		id_tag: req.id_tag.as_str(),
		name: req.id_tag.as_str(),
		typ: ProfileType::Person,
		profile_pic: None,
		following: false,
		connected: false,
	};

	app.meta_adapter.create_profile(tn_id, &profile, "").await?;

	// Create initial access token
	let token = app.auth_adapter.create_tenant_login(&req.id_tag).await?;

	let response = json!({
		"id_tag": req.id_tag,
		"tn_id": tn_id.0,
		"access_token": token.token,
		"message": "Registration successful!"
	});

	Ok((StatusCode::CREATED, Json(response)))
}

// vim: ts=4
