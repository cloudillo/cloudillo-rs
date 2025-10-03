use async_trait::async_trait;
use base64::Engine;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::prelude::*;
use crate::App;
use crate::meta_adapter;
use crate::core::scheduler::{Task, TaskId};
use crate::types::TnId;

/// File ID generator Task
#[derive(Debug, Serialize, Deserialize)]
pub struct FileIdGeneratorTask {
	tn_id: TnId,
	f_id: u64,
}

impl FileIdGeneratorTask {
	pub fn new(tn_id: TnId, f_id: u64) -> Arc<Self> {
		Arc::new(Self { tn_id, f_id })
	}
}

#[async_trait]
impl Task<App> for FileIdGeneratorTask {
	fn kind() -> &'static str { "file.id-generator" }

	fn build(id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		let (tn_id, f_id) = ctx.split(',').collect_tuple().ok_or(Error::Unknown)?;
		let task = FileIdGeneratorTask::new(tn_id.parse()?, f_id.parse()?);
		Ok(task)
	}

	async fn run(&self, app: App) -> ClResult<()> {
		info!("Running task file.id-generator {}", self.f_id);
		let mut variants = app.meta_adapter.list_file_variants(self.tn_id, meta_adapter::FileId::FId(self.f_id), meta_adapter::FileVariantSelector::default()).await?;
		variants.sort();
		let descriptor = variants.iter().map(|v| format!("{};{};s={};r={}x{}", v.variant, v.variant_id, v.size, v.resolution.0, v.resolution.1)).join(",");

		let mut hasher = Sha256::new();
		hasher.update(descriptor.as_bytes());
		let file_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());

		info!("Finished task file.id-generator {} {}", descriptor, file_id);
		Ok(())
	}
}

// vim: ts=4
