//! Community profile creation handler

use axum::{
	extract::{Path, State},
	http::StatusCode,
	Json,
};

use crate::{
	action::task::{create_action, CreateAction},
	bootstrap::{create_complete_tenant, CreateCompleteTenantOptions},
	core::extract::Auth,
	idp::registration::{IdpRegContent, IdpRegResponse},
	meta_adapter::{
		Profile, ProfileConnectionStatus, ProfileType, UpdateProfileData, UpdateTenantData,
	},
	prelude::*,
	types::{ApiResponse, CommunityProfileResponse, CreateCommunityRequest},
	utils::derive_name_from_id_tag,
};

/// PUT /api/profiles/{id_tag} - Create a new community profile
pub async fn put_community_profile(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(id_tag): Path<String>,
	Json(req): Json<CreateCommunityRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<CommunityProfileResponse>>)> {
	let id_tag_lower = id_tag.to_lowercase();
	let creator_id_tag = &auth.id_tag;
	let creator_tn_id = auth.tn_id;

	info!(
		creator = %creator_id_tag,
		community = %id_tag_lower,
		typ = %req.typ,
		"Creating community profile"
	);

	// 1. Validate identity type
	if req.typ != "idp" && req.typ != "domain" {
		return Err(Error::ValidationError("Invalid identity type".into()));
	}

	// 3. Validate id_tag availability
	let providers = super::register::get_identity_providers(&app, TnId(1)).await;
	let validation = super::register::verify_register_data(
		&app,
		&req.typ,
		&id_tag_lower,
		req.app_domain.as_deref(),
		providers,
	)
	.await?;

	if !validation.id_tag_error.is_empty() {
		warn!(
			community = %id_tag_lower,
			error = %validation.id_tag_error,
			"Community id_tag validation failed"
		);
		return Err(Error::ValidationError(validation.id_tag_error));
	}

	// 3a. For IDP type, register with identity provider first
	let idp_api_key: Option<String> = if req.typ == "idp" {
		// Extract IDP domain from id_tag (e.g., "csapat.home.w9.hu" -> "home.w9.hu")
		let idp_domain = match id_tag_lower.find('.') {
			Some(pos) => &id_tag_lower[pos + 1..],
			None => return Err(Error::ValidationError("Invalid IDP id_tag format".into())),
		};

		// Build IDP:REG action content
		let address = if app.opts.local_address.is_empty() {
			None
		} else {
			Some(app.opts.local_address.iter().map(|s| s.as_ref()).collect::<Vec<_>>().join(","))
		};

		let reg_content = IdpRegContent {
			id_tag: id_tag_lower.clone(),
			email: None,                                    // Communities don't have email
			owner_id_tag: Some(creator_id_tag.to_string()), // Creator owns the community
			issuer: None,
			address,
			lang: None, // Communities don't have language preference
		};

		// Create IDP:REG action
		let action = CreateAction {
			typ: "IDP:REG".into(),
			sub_typ: None,
			parent_id: None,
			audience_tag: Some(idp_domain.to_string().into()),
			content: Some(serde_json::to_value(&reg_content)?),
			attachments: None,
			subject: None,
			expires_at: Some(Timestamp::now().add_seconds(86400 * 30)),
			visibility: None,
			flags: None,
			x: None,
		};

		// Generate and send token to IDP
		let action_token = app.auth_adapter.create_action_token(TnId(1), action).await?;

		#[derive(serde::Serialize)]
		struct InboxRequest {
			token: String,
		}

		info!(
			community = %id_tag_lower,
			idp_domain = %idp_domain,
			"Registering community with identity provider"
		);

		let idp_response: crate::types::ApiResponse<serde_json::Value> = app
			.request
			.post_public(
				idp_domain,
				"/inbox/sync",
				&InboxRequest { token: action_token.to_string() },
			)
			.await
			.map_err(|e| {
				warn!(error = %e, idp_domain = %idp_domain, "Failed to register community with IDP");
				Error::ValidationError("IDP registration failed".into())
			})?;

		// Parse response
		let idp_reg_result: IdpRegResponse = serde_json::from_value(idp_response.data)
			.map_err(|e| Error::Internal(format!("IDP response parsing failed: {}", e)))?;

		if !idp_reg_result.success {
			warn!(
				community = %id_tag_lower,
				message = %idp_reg_result.message,
				"IDP registration failed"
			);
			return Err(Error::ValidationError(idp_reg_result.message));
		}

		info!(
			community = %id_tag_lower,
			"Community registered with identity provider"
		);

		idp_reg_result.api_key
	} else {
		None
	};

	// 4. Create community tenant
	let display_name = req.name.clone().unwrap_or_else(|| derive_name_from_id_tag(&id_tag_lower));
	let community_tn_id = create_complete_tenant(
		&app,
		CreateCompleteTenantOptions {
			id_tag: &id_tag_lower,
			email: None,
			password: None,
			roles: None,
			display_name: Some(&display_name),
			create_acme_cert: app.opts.acme_email.is_some(),
			acme_email: app.opts.acme_email.as_deref(),
			app_domain: req.app_domain.as_deref(),
		},
	)
	.await?;

	info!(
		community = %id_tag_lower,
		tn_id = ?community_tn_id,
		"Community tenant created"
	);

	// 4a. Store IDP API key if we got one from registration
	if let Some(api_key) = &idp_api_key {
		info!(
			community = %id_tag_lower,
			"Storing IDP API key for community"
		);
		if let Err(e) = app.auth_adapter.update_idp_api_key(&id_tag_lower, api_key).await {
			warn!(error = %e, community = %id_tag_lower, "Failed to store IDP API key");
			// Continue - not critical for basic functionality
		}
	}

	// 5. Update tenant to Community type (and set profile_pic if provided)
	// Note: create_tenant already created a basic profile, update_tenant syncs changes
	app.meta_adapter
		.update_tenant(
			community_tn_id,
			&UpdateTenantData {
				typ: Patch::Value(ProfileType::Community),
				profile_pic: match &req.profile_pic {
					Some(pic) => Patch::Value(pic.clone()),
					None => Patch::Undefined,
				},
				..Default::default()
			},
		)
		.await?;

	// 5a. Enable auto-approve for incoming posts from connected users
	app.meta_adapter
		.update_setting(
			community_tn_id,
			"federation.auto_approve",
			Some(serde_json::Value::Bool(true)),
		)
		.await?;

	// 6. Create CONN: creator → community (in creator's tenant)
	info!(
		creator = %creator_id_tag,
		community = %id_tag_lower,
		"Creating CONN action from creator to community"
	);
	create_action(
		&app,
		creator_tn_id,
		creator_id_tag,
		CreateAction {
			typ: "CONN".into(),
			audience_tag: Some(id_tag_lower.clone().into()),
			..Default::default()
		},
	)
	.await?;

	// 7. Create CONN: community → creator (in community's tenant)
	// This triggers mutual detection and auto-accept
	info!(
		creator = %creator_id_tag,
		community = %id_tag_lower,
		"Creating CONN action from community to creator"
	);
	create_action(
		&app,
		community_tn_id,
		&id_tag_lower,
		CreateAction {
			typ: "CONN".into(),
			audience_tag: Some(creator_id_tag.to_string().into()),
			..Default::default()
		},
	)
	.await?;

	// 8. Get creator's profile name for the community's profile record
	let creator_name = match app.meta_adapter.get_profile_info(creator_tn_id, creator_id_tag).await
	{
		Ok(profile) => profile.name.to_string(),
		Err(_) => derive_name_from_id_tag(creator_id_tag),
	};

	// 9. Create creator's profile in community tenant with "leader" role
	let creator_profile = Profile {
		id_tag: creator_id_tag.as_ref(),
		name: creator_name.as_str(),
		typ: ProfileType::Person,
		profile_pic: None,
		following: true,
		connected: ProfileConnectionStatus::Connected,
	};
	app.meta_adapter.create_profile(community_tn_id, &creator_profile, "").await?;

	// Set leader role
	app.meta_adapter
		.update_profile(
			community_tn_id,
			creator_id_tag,
			&UpdateProfileData {
				roles: Patch::Value(Some(vec!["leader".to_string().into()])),
				connected: Patch::Value(ProfileConnectionStatus::Connected),
				following: Patch::Value(true),
				..Default::default()
			},
		)
		.await?;

	info!(
		creator = %creator_id_tag,
		community = %id_tag_lower,
		"Creator assigned leader role in community"
	);

	// 10. Return response
	let response = CommunityProfileResponse {
		id_tag: id_tag_lower,
		name: display_name,
		profile_type: "community".to_string(),
		profile_pic: req.profile_pic,
		created_at: Timestamp::now(),
	};

	Ok((StatusCode::CREATED, Json(ApiResponse::new(response))))
}

// vim: ts=4
