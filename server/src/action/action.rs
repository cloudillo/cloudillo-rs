use async_trait::async_trait;
use itertools::Itertools;
//use jsonwebtoken::{self as jwt, Algorithm, DecodingKey, EncodingKey, Validation};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::sync::Arc;

use crate::{
	prelude::*,
	action::process,
	file::file,
	core::hasher,
	core::request,
	core::scheduler::{Task, TaskId},
	auth_adapter,
	meta_adapter,
	types::now,
};

pub async fn create_action(app: &App, tn_id: TnId, id_tag: &str, action: meta_adapter::CreateAction) -> ClResult<Box<str>>{
	let attachments_to_wait = if let Some(attachments) = &action.attachments {
		attachments.iter().filter(|a| a.starts_with("@")).map(|a| format!("{},{}", tn_id, &a[1..]).into_boxed_str()).collect::<Vec<_>>()
	} else {
		Vec::new()
	};
	info!("Dependencies: {:?}", attachments_to_wait);
	let deps = app.meta_adapter.list_task_ids(file::FileIdGeneratorTask::kind(), &attachments_to_wait.into_boxed_slice()).await?;
	info!("Dependencies: {:?}", deps);

	let task = ActionCreatorTask::new(tn_id, Box::from(id_tag), action);
	let task_id = app.scheduler.add_with_deps(task, Some(deps)).await?;

	Ok(Box::from("FIXME"))
}

/// Action creator Task
#[derive(Debug, Serialize, Deserialize)]
pub struct ActionCreatorTask {
	tn_id: TnId,
	id_tag: Box<str>,
	action: meta_adapter::CreateAction,
}

impl ActionCreatorTask {
	pub fn new(tn_id: TnId, id_tag: Box<str>, action: meta_adapter::CreateAction) -> Arc<Self> {
		Arc::new(Self { tn_id, id_tag, action })
	}
}

#[async_trait]
impl Task<App> for ActionCreatorTask {
	fn kind() -> &'static str { "action.create" }
	fn kind_of(&self) -> &'static str { Self::kind() }

	fn build(id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		let task: ActionCreatorTask = serde_json::from_str(ctx)?;
		Ok(Arc::new(task))
	}

	fn serialize(&self) -> String {
		serde_json::to_string(self).unwrap()
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		info!("Running task action.create {:?} {:?}", self.tn_id, &self.action);
		let action_token = app.auth_adapter.create_action_token(self.tn_id, self.action.clone()).await?;
		let action_id = hasher::hash("a", action_token.as_bytes());

		let attachments: Option<Vec<Box<str>>> = if let Some(attachments) = &self.action.attachments {
			let mut attachment_vec: Vec<Box<str>> = Vec::new();
			for a in attachments {
				if a.starts_with("@") {
					let file_id = app.meta_adapter.get_file_id(self.tn_id, a[1..].parse()?).await?;
					attachment_vec.push(file_id.clone());
				} else {
					attachment_vec.push(a.clone());
				}
			}
			Some(attachment_vec)
		} else {
			None
		};

		let action = meta_adapter::Action {
			action_id,
			issuer_tag: self.id_tag.clone(),
			typ: self.action.typ.clone(),
			sub_typ: self.action.sub_typ.clone(),
			parent_id: self.action.parent_id.clone(),
			root_id: self.action.root_id.clone(),
			audience_tag: self.action.audience_tag.clone(),
			content: self.action.content.clone(),
			attachments,
			subject: self.action.subject.clone(),
			expires_at: self.action.expires_at.clone(),
			created_at: now(),
		};

		let key = Some(action.action_id.as_ref());
		app.meta_adapter.create_action(self.tn_id, &action, key).await?;

		// FIXME
		let mut map = std::collections::HashMap::new();
		map.insert("token", action_token);
		//app.request.post::<serde_json::Value>(&app, "/api/inbox", &map).await?;
		app.request.post::<serde_json::Value>(&self.id_tag, "/api/inbox", &map).await?;
		// / FIXME

		info!("Finished task action.create {}", action.action_id);
		Ok(())
	}
}

/// Action verifier generator Task
#[derive(Debug, Serialize, Deserialize)]
pub struct ActionVerifierTask {
	tn_id: TnId,
	token: Box<str>,
}

impl ActionVerifierTask {
	pub fn new(tn_id: TnId, token: Box<str>) -> Arc<Self> {
		Arc::new(Self { tn_id, token })
	}
}

#[async_trait]
impl Task<App> for ActionVerifierTask {
	fn kind() -> &'static str { "file.id-generator" }
	fn kind_of(&self) -> &'static str { Self::kind() }

	fn build(id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		let (tn_id, token) = ctx.split(',').collect_tuple().ok_or(Error::Unknown)?;
		let task = ActionVerifierTask::new(TnId(tn_id.parse()?), token.into());
		Ok(task)
	}

	fn serialize(&self) -> String {
		self.token.to_string()
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		let action_id = hasher::hash("a", self.token.as_bytes());
		info!("Running task action.verify {}", action_id);

		process::process_inbound_action_token(&app, self.tn_id, &action_id, &self.token).await?;

		/*
		let action_not_validated: auth_adapter::ActionToken = decode_jwt_no_verify(&self.token)?;
		info!("  from: {}", action_not_validated.iss);

		let key_data: crate::profile::handler::Profile = app.request.get(&action_not_validated.iss, "/me/keys").await?;
		info!("  keys: {:#?}", key_data.keys);
		let public_key: Option<Box<str>> = if let Some(key) = key_data.keys.iter().find(|k| k.key_id == action_not_validated.k) {
			let (public_key, expires_at) = (key.public_key.clone(), key.expires_at);
			Some(public_key)
		} else {
			None
		};

		if let Some(public_key) = public_key {
			let public_key_pem = format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----", public_key);

			let mut validation = Validation::new(Algorithm::ES384);
			validation.set_required_spec_claims(&["iss"]);

			let action: auth_adapter::ActionToken = jwt::decode(
				&self.token,
				&jwt::DecodingKey::from_ec_pem(&public_key_pem.as_bytes()).inspect_err(|err| error!("from_ec_pem err: {}", err))?,
				&validation
			)?.claims;


			info!("Finished task action.verify {}", action_id);
		} else {
			return Err(Error::NotFound);
		}
		*/
		info!("Finished task action.verify {}", action_id);
		Ok(())
	}
}

// vim: ts=4
