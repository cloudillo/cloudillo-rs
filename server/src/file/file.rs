use async_trait::async_trait;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::prelude::*;
use crate::App;
use crate::meta_adapter;
use crate::core::{hasher::Hasher, scheduler::{Task, TaskId}};
use crate::types::TnId;
use crate::file::handler::GetFileVariantSelector;

/// Get file variant descriptor
pub fn get_file_descriptor(variants: &Vec<meta_adapter::FileVariant>) -> String {
	variants.iter().map(|v| format!("{}:{}:s={}:r={}x{}", v.variant, v.variant_id, v.size, v.resolution.0, v.resolution.1)).join(",")
}

/// Choose best variant
pub fn get_best_file_variant<'a>(variants: &'a Vec<meta_adapter::FileVariant>, selector: &'_ GetFileVariantSelector) -> ClResult<&'a meta_adapter::FileVariant> {
	info!("get_best_file_variant: {:?}", selector);
	let best = match selector.variant.as_deref() {
		Some("tn") => variants.iter().find(|v| *v.variant == *"tn")
			.or_else(|| variants.iter().find(|v| *v.variant == *"sd"))
			.or_else(|| variants.iter().find(|v| *v.variant == *"md"))
			.ok_or(Error::NotFound),
		Some("sd") => variants.iter().find(|v| *v.variant == *"sd")
			.or_else(|| variants.iter().find(|v| *v.variant == *"md"))
			.ok_or(Error::NotFound),
		Some("md") => variants.iter().find(|v| *v.variant == *"md")
			.or_else(|| variants.iter().find(|v| *v.variant == *"sd"))
			.ok_or(Error::NotFound),
		Some("hd") => variants.iter().find(|v| *v.variant == *"hd")
			.or_else(|| variants.iter().find(|v| *v.variant == *"md"))
			.or_else(|| variants.iter().find(|v| *v.variant == *"sd"))
			.ok_or(Error::NotFound),
		Some("xd") => variants.iter().find(|v| *v.variant == *"xd")
			.or_else(|| variants.iter().find(|v| *v.variant == *"hd"))
			.or_else(|| variants.iter().find(|v| *v.variant == *"md"))
			.or_else(|| variants.iter().find(|v| *v.variant == *"sd"))
			.ok_or(Error::NotFound),
		Some(_) => Err(Error::NotFound),
		None => Err(Error::NotFound)
	};
	info!("best variant: {:?} {:?}", best, variants);

	best
}

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
	fn kind_of(&self) -> &'static str { Self::kind() }

	fn build(id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		let (tn_id, f_id) = ctx.split(',').collect_tuple().ok_or(Error::Unknown)?;
		let task = FileIdGeneratorTask::new(tn_id.parse()?, f_id.parse()?);
		Ok(task)
	}

	fn serialize(&self) -> String {
		format!("{},{}", self.tn_id, self.f_id)
	}

	async fn run(&self, app: App) -> ClResult<()> {
		info!("Running task file.id-generator {}", self.f_id);
		let mut variants = app.meta_adapter.list_file_variants(self.tn_id, meta_adapter::FileId::FId(self.f_id)).await?;
		variants.sort();
		let descriptor = get_file_descriptor(&variants);

		let mut hasher = Hasher::new();
		hasher.update(descriptor.as_bytes());
		let file_id = hasher.finalize();
		app.meta_adapter.update_file_id(self.tn_id, self.f_id, &file_id).await?;

		info!("Finished task file.id-generator {} {}", descriptor, file_id);
		Ok(())
	}
}

// vim: ts=4
