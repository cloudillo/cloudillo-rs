use async_trait::async_trait;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::sync::Arc;

use crate::{
	prelude::*,
	action::process,
	file::file,
	core::hasher,
	core::scheduler::{Task, TaskId},
	meta_adapter,
};

#[skip_serializing_none]
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CreateAction {
	#[serde(rename = "type")]
	pub typ: Box<str>,
	#[serde(rename = "subType")]
	pub sub_typ: Option<Box<str>>,
	#[serde(rename = "parentId")]
	pub parent_id: Option<Box<str>>,
	#[serde(rename = "rootId")]
	pub root_id: Option<Box<str>>,
	#[serde(rename = "audienceTag")]
	pub audience_tag: Option<Box<str>>,
	pub content: Option<Box<str>>,
	pub attachments: Option<Vec<Box<str>>>,
	pub subject: Option<Box<str>>,
	#[serde(rename = "expiresAt")]
	pub expires_at: Option<Timestamp>,
}

pub async fn create_action(app: &App, tn_id: TnId, id_tag: &str, action: CreateAction) -> ClResult<Box<str>>{
	let attachments_to_wait = if let Some(attachments) = &action.attachments {
		attachments.iter().filter(|a| a.starts_with("@")).map(|a| format!("{},{}", tn_id, &a[1..]).into_boxed_str()).collect::<Vec<_>>()
	} else {
		Vec::new()
	};
	info!("Dependencies: {:?}", attachments_to_wait);
	let deps = app.meta_adapter.list_task_ids(file::FileIdGeneratorTask::kind(), &attachments_to_wait.into_boxed_slice()).await?;
	info!("Dependencies: {:?}", deps);

	let task = ActionCreatorTask::new(tn_id, Box::from(id_tag), action);
	app.scheduler.add_with_deps(task, Some(deps)).await?;

	Ok(Box::from("FIXME"))
}

/// Action creator Task
#[derive(Debug, Serialize, Deserialize)]
pub struct ActionCreatorTask {
	tn_id: TnId,
	id_tag: Box<str>,
	action: CreateAction,
}

impl ActionCreatorTask {
	pub fn new(tn_id: TnId, id_tag: Box<str>, action: CreateAction) -> Arc<Self> {
		Arc::new(Self { tn_id, id_tag, action })
	}
}

#[async_trait]
impl Task<App> for ActionCreatorTask {
	fn kind() -> &'static str { "action.create" }
	fn kind_of(&self) -> &'static str { Self::kind() }

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
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
			action_id: action_id.as_ref(),
			issuer_tag: self.id_tag.as_ref(),
			typ: self.action.typ.as_ref(),
			sub_typ: self.action.sub_typ.as_deref(),
			parent_id: self.action.parent_id.as_deref(),
			root_id: self.action.root_id.as_deref(),
			audience_tag: self.action.audience_tag.as_deref(),
			content: self.action.content.as_deref(),
			attachments: attachments.as_ref().map(|v| v.iter().map(|a| a.as_ref()).collect()),
			subject: self.action.subject.as_deref(),
			expires_at: self.action.expires_at,
			created_at: Timestamp::now(),
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
	fn kind() -> &'static str { "action.verify" }
	fn kind_of(&self) -> &'static str { Self::kind() }

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
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

		info!("Finished task action.verify {}", action_id);
		Ok(())
	}
}

// vim: ts=4
