use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
	prelude::*,
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

	async fn run(&self, app: App) -> ClResult<()> {
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
		app.request.post::<serde_json::Value>(&app, "/api/inbox", &map).await?;
		// / FIXME

		info!("Finished task action.create {}", action.action_id);
		Ok(())
	}
}

// vim: ts=4
