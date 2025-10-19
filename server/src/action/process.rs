use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use itertools::Itertools;
use jsonwebtoken::{self as jwt, Algorithm, Validation};
use serde::{Deserialize, de::DeserializeOwned};

use crate::{
	prelude::*,
	auth_adapter::ActionToken,
	file::file,
};

/// Decodes a JWT without verifying the signature
pub fn decode_jwt_no_verify<T: DeserializeOwned>(jwt: &str) -> ClResult<T> {
	let (_header, payload, _sig) = jwt.split('.').collect_tuple().ok_or(Error::Unknown)?;
	let payload = URL_SAFE_NO_PAD.decode(payload.as_bytes()).map_err(|_| Error::Unknown)?;
	let payload: T = serde_json::from_slice(&payload).map_err(|_| Error::Unknown)?;

	Ok(payload)
}

pub async fn verify_action_token(app: &App, token: &str) -> ClResult<ActionToken> {
	let action_not_validated: ActionToken = decode_jwt_no_verify(&token)?;
	info!("  from: {}", action_not_validated.iss);

	let key_data: crate::profile::handler::Profile = app.request.get_noauth(&action_not_validated.iss, "/me/keys").await?;
	let public_key: Option<Box<str>> = if let Some(key) = key_data.keys.iter().find(|k| k.key_id == action_not_validated.k) {
		let (public_key, _expires_at) = (key.public_key.clone(), key.expires_at);
		Some(public_key)
	} else {
		None
	};

	if let Some(public_key) = public_key {
		let public_key_pem = format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----", public_key);

		let mut validation = Validation::new(Algorithm::ES384);
		validation.validate_aud = false;
		validation.set_required_spec_claims(&["iss"]);
		info!("  validating...");

		let action: ActionToken = jwt::decode(
			&token,
			&jwt::DecodingKey::from_ec_pem(&public_key_pem.as_bytes()).inspect_err(|err| error!("from_ec_pem err: {}", err))?,
			&validation
		)?.claims;
		info!("  validated {:?}", action);
		Ok(action)
	} else {
		Err(Error::PermissionDenied)
	}
}

pub trait ActionType {
	fn allow_unknown() -> bool;
}

pub async fn process_inbound_action_token(app: &App, tn_id: TnId, _action_id: &str, token: &str) -> ClResult<()> {
	let action = verify_action_token(&app, &token).await?;

	let issuer_profile = if let Ok((_etag, profile)) = app.meta_adapter.read_profile(tn_id, &action.iss).await {
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

	if let Some(attachments) = action.a {
		process_inbound_action_attachments(&app, tn_id, &action.iss, attachments).await?;
	}

	Ok(())
}

#[derive(Debug, Deserialize)]
struct Descriptor {
	file: Box<str>,
}

async fn process_inbound_action_attachments(app: &App, tn_id: TnId, id_tag: &str, attachments: Vec<Box<str>>) -> ClResult<()> {
	for attachment in attachments {
		info!("  syncing attachment: {}", attachment);
		if let Ok(descriptor) = app.request.get::<Descriptor>(&id_tag, format!("/file/{}/descriptor", attachment).as_str()).await {
			info!("  attachment descriptor: {:?}", descriptor.file);
			let variants = file::parse_file_descriptor(&descriptor.file)?;
			info!("  attachment variants: {:?}", variants);
			for variant in variants {
				if app.blob_adapter.stat_blob(tn_id, &variant.variant_id).await.is_none() {
					if variant.variant != "hd" { // FIXME settings
						info!("  downloading attachment: {}", variant.variant_id);

						let mut stream = app.request.get_stream(&id_tag, &format!("/file/variant/{}", variant.variant_id)).await?;
						let _res = app.blob_adapter.create_blob_stream(tn_id, variant.variant_id, &mut stream).await;
						info!("  attachment downloaded: {}", variant.variant_id);
					} else {
						info!("  skipping attachment: {} {}", variant.variant, variant.variant_id);
					}
				} else {
					info!("  attachment already downloaded: {} {}", variant.variant, variant.variant_id);
				}
			}
		}
	}

	Ok(())
}

// vim: ts=4
