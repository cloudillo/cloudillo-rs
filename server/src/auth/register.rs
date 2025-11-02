//! Registration and email verification handlers

use axum::{
	extract::{Json, State},
	http::StatusCode,
};
use serde_json::json;

use crate::{
	auth_adapter::CreateTenantData,
	meta_adapter::{Profile, ProfileType},
	prelude::*,
	types::{RegisterRequest, RegisterVerifyRequest, TnId},
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
		let verification_link = format!("https://{}/auth/register-verify", &req.id_tag);

		info!("Registration verification initiated for email: {}", email);
		info!("Verification link (for manual testing): {}", verification_link);
		debug!("Verification token: {}", token);

		// Queue verification email with template rendering
		// Note: This will fail silently if email is not configured (email.enabled = false)
		// Template will be rendered at execution time, not now
		let template_vars = serde_json::json!({
			"user_name": req.id_tag,
			"verification_token": token,
			"verification_link": verification_link,
			"instance_name": "Cloudillo",
		});

		match crate::email::EmailModule::schedule_email_task(
			&app.scheduler,
			&app.settings,
			TnId(0), // Use instance-level settings for registration emails
			email.to_string(),
			"Verify your email address".to_string(),
			"verification".to_string(),
			template_vars,
		)
		.await
		{
			Ok(_) => {
				info!("Verification email queued for {}", email);
			}
			Err(e) => {
				warn!("Failed to queue verification email: {}", e);
				// Don't fail registration if email queueing fails
			}
		}

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
	let tn_id = app
		.auth_adapter
		.create_tenant(
			&req.id_tag,
			CreateTenantData {
				vfy_code: Some(&req.verify_token),
				email: None,
				password: None,
				roles: None,
			},
		)
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
