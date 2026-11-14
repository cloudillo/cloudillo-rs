// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! PDF processing tasks for thumbnail generation and metadata extraction.
//!
//! Uses external tools for PDF processing:
//! - pdftoppm (from poppler-utils) for thumbnail generation
//! - pdfinfo (from poppler-utils) for page count extraction

use async_trait::async_trait;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use crate::prelude::*;
use crate::{image, store};
use cloudillo_core::scheduler::{Task, TaskId};
use cloudillo_types::blob_adapter;
use cloudillo_types::meta_adapter;

/// PDF metadata extracted from pdfinfo
#[derive(Debug, Clone)]
pub struct PdfInfo {
	pub page_count: u32,
}

/// Get PDF page count using pdfinfo
pub fn get_pdf_info(input: &Path) -> ClResult<PdfInfo> {
	let output = Command::new("pdfinfo")
		.env_remove("SECRET_KEY")
		.arg(input.to_str().ok_or(Error::Internal("invalid path".into()))?)
		.output()
		.map_err(|e| Error::Internal(format!("pdfinfo failed: {}", e)))?;

	if !output.status.success() {
		let stderr = String::from_utf8_lossy(&output.stderr);
		return Err(Error::Internal(format!("pdfinfo failed: {}", stderr)));
	}

	let stdout = String::from_utf8_lossy(&output.stdout);
	let page_count = stdout
		.lines()
		.find(|line| line.starts_with("Pages:"))
		.and_then(|line| line.split_whitespace().nth(1))
		.and_then(|s| s.parse().ok())
		.unwrap_or(1);

	Ok(PdfInfo { page_count })
}

/// Generate thumbnail from first page of PDF using pdftoppm
pub fn generate_pdf_thumbnail(input: &Path, output: &Path, dpi: u32) -> ClResult<()> {
	// pdftoppm outputs to filename-1.png for first page
	let output_base = output
		.with_extension("")
		.to_str()
		.ok_or(Error::Internal("invalid output path".into()))?
		.to_string();

	let status = Command::new("pdftoppm")
		.env_remove("SECRET_KEY")
		.args([
			"-png",
			"-f",
			"1", // First page
			"-l",
			"1", // Last page (same as first = only first page)
			"-r",
			&dpi.to_string(),
			"-singlefile",
			input.to_str().ok_or(Error::Internal("invalid input path".into()))?,
			&output_base,
		])
		.status()
		.map_err(|e| Error::Internal(format!("pdftoppm failed: {}", e)))?;

	if !status.success() {
		return Err(Error::Internal("pdftoppm thumbnail generation failed".into()));
	}

	Ok(())
}

/// Result of PDF thumbnail generation
#[derive(Debug)]
pub struct PdfThumbnailResult {
	pub page_count: u32,
	pub variant_id: String,
}

/// Generate PDF thumbnail synchronously during upload.
///
/// Extracts PDF info, renders first page, resizes to webp, stores blob + variant.
pub async fn generate_pdf_thumbnail_variant(
	app: &App,
	tn_id: TnId,
	f_id: u64,
	input_path: &Path,
	thumbnail_size: u32,
) -> ClResult<PdfThumbnailResult> {
	// Create temp file for thumbnail in app's tmp_dir. The `.png` has to be there:
	// `generate_pdf_thumbnail` hands `pdftoppm` the path with the extension stripped,
	// and `-png` puts it back.
	let thumb_path = crate::scratch::scratch_path(&app.opts.tmp_dir, "pdf_thumb", ".png")?;

	// Get PDF info and generate thumbnail in worker thread
	let input_path_owned = input_path.to_path_buf();
	let thumb_path_clone = thumb_path.clone();

	let pdf_info = app
		.worker
		.try_run(move || {
			let info = get_pdf_info(&input_path_owned)?;
			generate_pdf_thumbnail(&input_path_owned, &thumb_path_clone, 150)?;
			Ok::<_, Error>(info)
		})
		.await?;

	info!("Extracted PDF info: {} pages from {:?}", pdf_info.page_count, input_path);

	// Read the generated thumbnail PNG and resize it
	let thumb_bytes = tokio::fs::read(&thumb_path).await?;
	let _ = tokio::fs::remove_file(&thumb_path).await;

	let resize_result = image::resize_image(
		app.clone(),
		thumb_bytes,
		image::ImageFormat::Webp,
		(thumbnail_size, thumbnail_size),
	)
	.await
	.map_err(|e| Error::Internal(format!("thumbnail resize failed: {}", e)))?;

	info!(
		"PDF thumbnail {:?} → {}x{} ({}bytes), {} pages",
		input_path,
		resize_result.width,
		resize_result.height,
		resize_result.bytes.len(),
		pdf_info.page_count
	);

	// Create blob from thumbnail
	let variant_id = store::create_blob_buf(
		app,
		tn_id,
		&resize_result.bytes,
		blob_adapter::CreateBlobOptions::default(),
	)
	.await?;

	// Store thumbnail variant metadata
	app.meta_adapter
		.create_file_variant(
			tn_id,
			f_id,
			meta_adapter::FileVariant {
				variant_id: &variant_id,
				variant: "vis.tn",
				format: "webp",
				resolution: (resize_result.width, resize_result.height),
				size: resize_result.bytes.len() as u64,
				available: true,
				global: false,
				duration: None,
				bitrate: None,
				page_count: Some(pdf_info.page_count),
			},
		)
		.await?;

	Ok(PdfThumbnailResult { page_count: pdf_info.page_count, variant_id: variant_id.to_string() })
}

/// PDF processor task - generates thumbnail and extracts metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct PdfProcessorTask {
	tn_id: TnId,
	f_id: u64,
	input_path: Box<Path>,
	thumbnail_size: u32,
}

impl PdfProcessorTask {
	// Pre-JSON input of rows queued before the upgrade; drop at 1.0.
	fn build_legacy(ctx: &str) -> ClResult<Self> {
		let (tn_id, f_id, thumbnail_size, path) =
			ctx.split(',').collect_tuple().ok_or(Error::Parse)?;
		Ok(Self {
			tn_id: TnId(tn_id.parse()?),
			f_id: f_id.parse()?,
			input_path: Box::from(Path::new(path)),
			thumbnail_size: thumbnail_size.parse()?,
		})
	}
}

#[async_trait]
impl Task<App> for PdfProcessorTask {
	fn kind() -> &'static str {
		"pdf.process"
	}
	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		let task = if ctx.trim_start().starts_with('{') {
			serde_json::from_str::<Self>(ctx)?
		} else {
			Self::build_legacy(ctx)?
		};
		Ok(Arc::new(task))
	}

	fn serialize(&self) -> ClResult<String> {
		Ok(serde_json::to_string(self)?)
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		info!(
			"Running task pdf.process {:?} thumbnail_size={}",
			self.input_path, self.thumbnail_size
		);

		generate_pdf_thumbnail_variant(
			app,
			self.tn_id,
			self.f_id,
			&self.input_path,
			self.thumbnail_size,
		)
		.await?;

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_pdf_processor_serialize_deserialize() {
		let task = PdfProcessorTask {
			tn_id: TnId(1),
			f_id: 42,
			input_path: Path::new("/tmp/test.pdf").into(),
			thumbnail_size: 256,
		};

		let serialized = Task::<App>::serialize(&task).unwrap();
		assert!(serialized.starts_with('{'));
		assert!(serialized.contains("\"thumbnail_size\":256"));

		let decoded: PdfProcessorTask = serde_json::from_str(&serialized).unwrap();
		assert_eq!(decoded.tn_id, task.tn_id);
		assert_eq!(decoded.f_id, task.f_id);
		assert_eq!(decoded.input_path, task.input_path);
		assert_eq!(decoded.thumbnail_size, task.thumbnail_size);

		let rebuilt = PdfProcessorTask::build(0, &serialized).unwrap();
		assert_eq!(rebuilt.kind_of(), "pdf.process");
	}

	#[test]
	fn test_pdf_processor_build_legacy() {
		let ctx = "1,42,256,/tmp/test.pdf";
		assert_eq!(PdfProcessorTask::build(0, ctx).unwrap().kind_of(), "pdf.process");

		let task = PdfProcessorTask::build_legacy(ctx).unwrap();
		assert_eq!(task.tn_id, TnId(1));
		assert_eq!(task.f_id, 42);
		assert_eq!(&*task.input_path, Path::new("/tmp/test.pdf"));
		assert_eq!(task.thumbnail_size, 256);
	}
}

// vim: ts=4
