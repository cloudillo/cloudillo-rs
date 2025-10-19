use async_trait::async_trait;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, sync::Arc};

use crate::prelude::*;
use crate::meta_adapter;
use crate::core::{hasher::Hasher, scheduler::{Task, TaskId}};
use crate::types::TnId;
use crate::file::handler::GetFileVariantSelector;

/// Get file variant descriptor
pub fn get_file_descriptor<S: AsRef<str> + Debug + Eq>(variants: &Vec<meta_adapter::FileVariant<S>>) -> String {
	"d1~".to_owned() + &variants.iter().map(|v| format!("{}:{}:f={}:s={}:r={}x{}", v.variant.as_ref(), v.variant_id.as_ref(), v.format.as_ref(), v.size, v.resolution.0, v.resolution.1)).join(",")
}

pub fn parse_file_descriptor(descriptor: &str) -> ClResult<Vec<meta_adapter::FileVariant<&str>>> {
	if descriptor.starts_with("d1~") {
		let variants: ClResult<Vec<meta_adapter::FileVariant<&str>>> = descriptor[3..].split(',').map(|v| {
			let v_vec: Vec<&str> = v.split(':').collect();
			if v_vec.len() < 2 { Err(Error::Parse)?; }
			let (variant, variant_id) = (v_vec[0], v_vec[1]);
			let mut resolution: Option<(u32, u32)> = None;
			let mut format: Option<&str> = Some("AVIF");
			let mut size: Option<u64> = None;

			for v in v_vec[2..].iter() {
				if v.starts_with("f=") {
					format = Some(&v[2..]);
				} else if v.starts_with("s=") {
					size = Some(v[2..].parse().ok().ok_or(Error::Parse)?);
				} else if v.starts_with("r=") {
					let res_str: (&str, &str) = v[2..].split('x').collect_tuple().ok_or(Error::Parse)?;
					resolution = Some((res_str.0.parse()?, res_str.1.parse()?));
				}
			}
			if let (Some(resolution), Some(format), Some(size)) = (resolution, format, size) {
				Ok(meta_adapter::FileVariant {
					variant: variant,
					variant_id: variant_id,
					resolution,
					format: format,
					size,
					available: false,
				})
			} else {
				error!("resolution: {:?}, format: {:?}, size: {:?}", resolution, format, size);
				Err(Error::Parse)
			}
		}).collect();
		variants
	} else {
		Err(Error::Parse)
	}
}

/// Choose best variant
pub fn get_best_file_variant<'a, S: AsRef<str> + Debug + Eq>(variants: &'a Vec<meta_adapter::FileVariant<S>>, selector: &'_ GetFileVariantSelector) -> ClResult<&'a meta_adapter::FileVariant<S>> {
	info!("get_best_file_variant: {:?}", selector);
	let best = match selector.variant.as_deref() {
		Some("tn") => variants.iter().find(|v| v.variant.as_ref() == "tn")
			.or_else(|| variants.iter().find(|v| v.variant.as_ref() == "sd"))
			.or_else(|| variants.iter().find(|v| v.variant.as_ref() == "md"))
			.ok_or(Error::NotFound),
		Some("sd") => variants.iter().find(|v| v.variant.as_ref() == "sd")
			.or_else(|| variants.iter().find(|v| v.variant.as_ref() == "md"))
			.ok_or(Error::NotFound),
		Some("md") => variants.iter().find(|v| v.variant.as_ref() == "md")
			.or_else(|| variants.iter().find(|v| v.variant.as_ref() == "sd"))
			.ok_or(Error::NotFound),
		Some("hd") => variants.iter().find(|v| v.variant.as_ref() == "hd")
			.or_else(|| variants.iter().find(|v| v.variant.as_ref() == "md"))
			.or_else(|| variants.iter().find(|v| v.variant.as_ref() == "sd"))
			.ok_or(Error::NotFound),
		Some("xd") => variants.iter().find(|v| v.variant.as_ref() == "xd")
			.or_else(|| variants.iter().find(|v| v.variant.as_ref() == "hd"))
			.or_else(|| variants.iter().find(|v| v.variant.as_ref() == "md"))
			.or_else(|| variants.iter().find(|v| v.variant.as_ref() == "sd"))
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
	fn kind() -> &'static str { "file.id-generate" }
	fn kind_of(&self) -> &'static str { Self::kind() }

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		let (tn_id, f_id) = ctx.split(',').collect_tuple().ok_or(Error::Unknown)?;
		let task = FileIdGeneratorTask::new(TnId(tn_id.parse()?), f_id.parse()?);
		Ok(task)
	}

	fn serialize(&self) -> String {
		format!("{},{}", self.tn_id, self.f_id)
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		info!("Running task file.id-generate {}", self.f_id);
		let mut variants = app.meta_adapter.list_file_variants(self.tn_id, meta_adapter::FileId::FId(self.f_id)).await?;
		variants.sort();
		let descriptor = get_file_descriptor(&variants);

		let mut hasher = Hasher::new();
		hasher.update(descriptor.as_bytes());
		let file_id = hasher.finalize("f");
		app.meta_adapter.update_file_id(self.tn_id, self.f_id, &file_id).await?;

		info!("Finished task file.id-generate {} {}", descriptor, file_id);
		Ok(())
	}
}

// vim: ts=4
