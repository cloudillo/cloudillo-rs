use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
//use jwt::SignWithKey;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

use crate::{
	prelude::*,
	App,
	core::request,
	auth_adapter,
	meta_adapter,
	types::{TnId, Timestamp, TimestampExt}
};

pub fn sha256_b64url(input: &str) -> Box<str> {
	let tm = std::time::SystemTime::now();
	let mut hasher = Sha256::new();
	hasher.update(input);
	let result = hasher.finalize();
	let result = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&result);
	info!("elapsed: {}ms", tm.elapsed().unwrap().as_millis());
	Box::from(result)
}

pub async fn create_action(state: &App, tn_id: TnId, id_tag: &str, action: meta_adapter::CreateAction) -> ClResult<Box<str>>{
	let action_token = state.auth_adapter.create_action_token(tn_id, action.clone()).await?;
	let action_id = sha256_b64url(&action_token);
	let action = meta_adapter::Action {
		action_id,
		issuer_tag: id_tag.into(),
		typ: action.typ.clone(),
		sub_typ: action.sub_typ.clone(),
		parent_id: action.parent_id.clone(),
		root_id: action.root_id.clone(),
		audience_tag: action.audience_tag.clone(),
		content: action.content.clone(),
		attachments: action.attachments.clone(),
		subject: action.subject.clone(),
		expires_at: action.expires_at.clone(),
		created_at: Timestamp::now(),
	};

	let key = Some("FIXME");
	state.meta_adapter.create_action(tn_id, &action, key).await?;

	// FIXME
	let mut map = std::collections::HashMap::new();
	map.insert("token", action_token);
	//state.request.post::<serde_json::Value>(&state, "/api/inbox", &map).await?;
	state.request.post::<serde_json::Value>(&state, "/api/inbox", &map).await?;
	// / FIXME

	Ok(action.action_id)
}

// vim: ts=4
