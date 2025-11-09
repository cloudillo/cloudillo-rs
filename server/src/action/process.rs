use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use itertools::Itertools;
use jsonwebtoken::{self as jwt, Algorithm, Validation};
use serde::{de::DeserializeOwned, Deserialize};

use crate::{auth_adapter::ActionToken, file::descriptor, prelude::*};

/// Decodes a JWT without verifying the signature
pub fn decode_jwt_no_verify<T: DeserializeOwned>(jwt: &str) -> ClResult<T> {
	let (_header, payload, _sig) = jwt.split('.').collect_tuple().ok_or(Error::Parse)?;
	let payload = URL_SAFE_NO_PAD.decode(payload.as_bytes()).map_err(|_| Error::Parse)?;
	let payload: T = serde_json::from_slice(&payload).map_err(|_| Error::Parse)?;

	Ok(payload)
}

pub async fn verify_action_token(app: &App, tn_id: TnId, token: &str) -> ClResult<ActionToken> {
	let action_not_validated: ActionToken = decode_jwt_no_verify(token)?;
	info!("  from: {}", action_not_validated.iss);

	let key_data: crate::profile::handler::Profile =
		app.request.get_noauth(tn_id, &action_not_validated.iss, "/me/keys").await?;
	let public_key: Option<Box<str>> =
		if let Some(key) = key_data.keys.iter().find(|k| k.key_id == action_not_validated.k) {
			let (public_key, _expires_at) = (key.public_key.clone(), key.expires_at);
			Some(public_key)
		} else {
			None
		};

	if let Some(public_key) = public_key {
		let public_key_pem =
			format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----", public_key);

		let mut validation = Validation::new(Algorithm::ES384);
		validation.validate_aud = false;
		validation.set_required_spec_claims(&["iss"]);
		info!("  validating...");

		let action: ActionToken = jwt::decode(
			token,
			&jwt::DecodingKey::from_ec_pem(public_key_pem.as_bytes())
				.inspect_err(|err| error!("from_ec_pem err: {}", err))?,
			&validation,
		)?
		.claims;
		info!("  validated {:?}", action);
		Ok(action)
	} else {
		Err(Error::Unauthorized)
	}
}

pub trait ActionType {
	fn allow_unknown() -> bool;
}

pub async fn process_inbound_action_token(
	app: &App,
	tn_id: TnId,
	_action_id: &str,
	token: &str,
) -> ClResult<()> {
	let action = verify_action_token(app, tn_id, token).await?;

	let issuer_profile =
		if let Ok((_etag, profile)) = app.meta_adapter.read_profile(tn_id, &action.iss).await {
			Some(profile)
		} else {
			None
		};
	info!("  profile: {:?}", issuer_profile);

	let mut allowed = false;
	// if opts.ack { allowed = true; }
	// Allow followers and connection requests

	if let Some(ref p) = issuer_profile {
		if p.following || p.connected {
			allowed = true;
		}
	}

	if !allowed {
		return Err(Error::PermissionDenied);
	}
	if issuer_profile.is_none() {
		//profile::sync_profile(&app, tn_id, &action.iss).await?;
	}

	if let Some(ref attachments) = action.a {
		process_inbound_action_attachments(app, tn_id, &action.iss, attachments.clone()).await?;
	}

	// Execute DSL on_receive hook if action type has one
	if app.dsl_engine.has_definition(&action.t) {
		use crate::action::hooks::{HookContext, HookType};
		use std::collections::HashMap;

		// Extract subtype from action type (e.g., "CONN:DEL" → type="CONN", subtype="DEL")
		let (action_type, subtype) = if let Some(colon_pos) = action.t.find(':') {
			let (t, st) = action.t.split_at(colon_pos);
			(t.to_string(), Some(st[1..].to_string()))
		} else {
			(action.t.to_string(), None)
		};

		let hook_context = HookContext {
			action_id: _action_id.to_string(),
			r#type: action_type,
			subtype,
			issuer: action.iss.to_string(),
			audience: action.aud.as_ref().map(|s| s.to_string()),
			parent: action.p.as_ref().map(|s| s.to_string()),
			subject: action.sub.as_ref().map(|s| s.to_string()),
			content: action.c.as_ref().and_then(|c| serde_json::from_str(c).ok()),
			attachments: action.a.as_ref().map(|v| v.iter().map(|s| s.to_string()).collect()),
			created_at: format!("{}", action.iat.0), // Simple timestamp conversion
			expires_at: action.exp.map(|ts| format!("{}", ts.0)),
			tenant_id: tn_id.0 as i64,
			tenant_tag: action.aud.as_ref().map(|s| s.to_string()).unwrap_or_default(),
			tenant_type: "person".to_string(),
			is_inbound: true,
			is_outbound: false,
			vars: HashMap::new(),
		};

		if let Err(e) = app
			.dsl_engine
			.execute_hook(app, &action.t, HookType::OnReceive, hook_context)
			.await
		{
			warn!(
				action_id = %_action_id,
				action_type = %action.t,
				issuer = %action.iss,
				tenant_id = %tn_id.0,
				error = %e,
				"DSL on_receive hook failed"
			);
			// Continue execution - hook errors shouldn't fail the action processing
		}
	}

	Ok(())
}

#[derive(Debug, Deserialize)]
struct Descriptor {
	file: Box<str>,
}

async fn process_inbound_action_attachments(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	attachments: Vec<Box<str>>,
) -> ClResult<()> {
	for attachment in attachments {
		info!("  syncing attachment: {}", attachment);
		if let Ok(descriptor) = app
			.request
			.get::<Descriptor>(tn_id, id_tag, format!("/file/{}/descriptor", attachment).as_str())
			.await
		{
			info!("  attachment descriptor: {:?}", descriptor.file);
			let variants = descriptor::parse_file_descriptor(&descriptor.file)?;
			info!("  attachment variants: {:?}", variants);
			for variant in variants {
				if app.blob_adapter.stat_blob(tn_id, variant.variant_id).await.is_none() {
					if variant.variant != "hd" {
						// FIXME settings
						info!("  downloading attachment: {}", variant.variant_id);

						let mut stream = app
							.request
							.get_stream(
								tn_id,
								id_tag,
								&format!("/file/variant/{}", variant.variant_id),
							)
							.await?;
						let _res = app
							.blob_adapter
							.create_blob_stream(tn_id, variant.variant_id, &mut stream)
							.await;
						info!("  attachment downloaded: {}", variant.variant_id);
					} else {
						info!("  skipping attachment: {} {}", variant.variant, variant.variant_id);
					}
				} else {
					info!(
						"  attachment already downloaded: {} {}",
						variant.variant, variant.variant_id
					);
				}
			}
		}
	}

	Ok(())
}

// vim: ts=4
