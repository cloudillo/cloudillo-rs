use async_trait::async_trait;
use image::ImageReader;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{io::Cursor, path::Path, sync::Arc};

use crate::prelude::*;
use crate::App;
use crate::meta_adapter;
use crate::blob_adapter;
use crate::core::scheduler::{Task, TaskId};
use crate::file::store;
use crate::types::TnId;

// Sync image resizer
fn resize_image_sync<'a>(orig_buf: impl AsRef<[u8]> + 'a, resize: (u32, u32)) -> Result<Box<[u8]>, image::error::ImageError> {
	let now = std::time::Instant::now();
	let original = ImageReader::new(Cursor::new(&orig_buf.as_ref()))
		.with_guessed_format()?
		.decode()?;
	debug!("decoded [{:.2}ms]", now.elapsed().as_millis());

	let now = std::time::Instant::now();
	let resized = original.resize(resize.0, resize.1, image::imageops::FilterType::Lanczos3);
	debug!("resized [{:.2}ms]", now.elapsed().as_millis());

	let mut output = Cursor::new(Vec::new());
	let now = std::time::Instant::now();

	let encoder = image::codecs::avif::AvifEncoder::new_with_speed_quality(&mut output, 4, 80).with_num_threads(Some(1));
	resized.write_with_encoder(encoder)?;
	debug!("written [{:.2}ms]", now.elapsed().as_millis());
	Ok(output.into_inner().into())
}

pub async fn resize_image(app: App, orig_buf: Vec<u8>, resize: (u32, u32)) -> Result<Box<[u8]>, image::error::ImageError> {
	app.worker.run_immed(move || {
		info!("Resizing image");
		resize_image_sync(orig_buf, resize)
	}).await
}

/// Image resizer Task
#[derive(Debug, Serialize, Deserialize)]
pub struct ImageResizerTask {
	tn_id: TnId,
	f_id: u64,
	variant: Box<str>,
	path: Box<Path>,
	res: (u32, u32),
}

impl ImageResizerTask {
	pub fn new(tn_id: TnId, f_id: u64, path: impl Into<Box<Path>>, variant: impl Into<Box<str>>, res: (u32, u32)) -> Arc<Self> {
		Arc::new(Self { tn_id, f_id, path: path.into(), variant: variant.into(), res })
	}
}

#[async_trait]
impl Task<App> for ImageResizerTask {
	fn kind() -> &'static str { "image.resize" }

	fn build(id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		let (tn_id, f_id, variant, x_res, y_res, path) = ctx.split(',').collect_tuple().ok_or(Error::Unknown)?;
		let task = ImageResizerTask::new(tn_id.parse()?, f_id.parse()?, Box::from(Path::new(path)), variant, (x_res.parse()?, y_res.parse()?));
		Ok(task)
	}

	async fn run(&self, app: App) -> ClResult<()> {
		info!("Running task image.resize {:?} {:?}", self.path, self.res);
		let bytes = tokio::fs::read(self.path.clone()).await?;
		let res = self.res;
		let resized = app.worker.run(move || {
			resize_image_sync(bytes, res)
		}).await?;
		info!("Finished task image.resize {:?} {}", self.path, resized.len());
		let variant_id = store::create_blob_buf(&app, self.tn_id, &resized, blob_adapter::CreateBlobOptions::default()).await?;
		app.meta_adapter.create_file_variant(self.tn_id, self.f_id, variant_id, meta_adapter::CreateFileVariant {
			variant: self.variant.clone(),
			format: "AVIF".into(),
			resolution: res,
			size: resized.len() as u64,
		}).await?;
		Ok(())
	}
}

// vim: ts=4
