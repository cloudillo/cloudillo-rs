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

/// Check if PDF tools are available
pub fn is_available() -> bool {
	let pdfinfo = Command::new("pdfinfo")
		.arg("--version")
		.output()
		.map(|o| o.status.success())
		.unwrap_or(false);

	let pdftoppm = Command::new("pdftoppm")
		.arg("-v")
		.output()
		.map(|o| o.status.success())
		.unwrap_or(false);

	pdfinfo && pdftoppm
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
	pub fn new(
		tn_id: TnId,
		f_id: u64,
		input_path: impl Into<Box<Path>>,
		thumbnail_size: u32,
	) -> Arc<Self> {
		Arc::new(Self { tn_id, f_id, input_path: input_path.into(), thumbnail_size })
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
		let (tn_id, f_id, thumbnail_size, path) =
			ctx.split(',').collect_tuple().ok_or(Error::Parse)?;
		let task = PdfProcessorTask::new(
			TnId(tn_id.parse()?),
			f_id.parse()?,
			Box::from(Path::new(path)),
			thumbnail_size.parse()?,
		);
		Ok(task)
	}

	fn serialize(&self) -> String {
		format!(
			"{},{},{},{}",
			self.tn_id,
			self.f_id,
			self.thumbnail_size,
			self.input_path.to_string_lossy()
		)
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		info!(
			"Running task pdf.process {:?} thumbnail_size={}",
			self.input_path, self.thumbnail_size
		);

		// Create temp file for thumbnail in app's tmp_dir
		let thumb_name = format!("pdf_thumb_{}.png", self.f_id);
		let thumb_path = app.opts.tmp_dir.join(&thumb_name);

		// Get PDF info and generate thumbnail in worker thread
		let input_path = self.input_path.clone();
		let thumb_path_clone = thumb_path.clone();

		let pdf_info = app
			.worker
			.try_run(move || {
				// Get page count
				let info = get_pdf_info(&input_path)?;

				// Generate thumbnail at 150 DPI (good balance of quality vs size)
				generate_pdf_thumbnail(&input_path, &thumb_path_clone, 150)?;

				Ok::<_, Error>(info)
			})
			.await?;

		info!("Extracted PDF info: {} pages from {:?}", pdf_info.page_count, self.input_path);

		// Read the generated thumbnail PNG and resize it
		let thumb_bytes = tokio::fs::read(&thumb_path).await?;

		// Clean up temp thumbnail file
		let _ = tokio::fs::remove_file(&thumb_path).await;

		// Resize to final thumbnail size using image module
		let thumbnail_size = self.thumbnail_size;
		let resize_result = image::resize_image(
			app.clone(),
			thumb_bytes,
			image::ImageFormat::Webp,
			(thumbnail_size, thumbnail_size),
		)
		.await
		.map_err(|e| Error::Internal(format!("thumbnail resize failed: {}", e)))?;

		info!(
			"Finished task pdf.process {:?} → {}x{} ({}bytes), {} pages",
			self.input_path,
			resize_result.width,
			resize_result.height,
			resize_result.bytes.len(),
			pdf_info.page_count
		);

		// Create blob from thumbnail
		let variant_id = store::create_blob_buf(
			app,
			self.tn_id,
			&resize_result.bytes,
			blob_adapter::CreateBlobOptions::default(),
		)
		.await?;

		// Store thumbnail variant metadata
		app.meta_adapter
			.create_file_variant(
				self.tn_id,
				self.f_id,
				meta_adapter::FileVariant {
					variant_id: &variant_id,
					variant: "vis.tn",
					format: "webp",
					resolution: (resize_result.width, resize_result.height),
					size: resize_result.bytes.len() as u64,
					available: true,
					duration: None,
					bitrate: None,
					page_count: Some(pdf_info.page_count),
				},
			)
			.await?;

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_pdf_tools_availability() {
		// This test will pass if poppler-utils is installed
		let available = is_available();
		println!("PDF tools available: {}", available);
	}

	#[test]
	fn test_pdf_processor_serialize_deserialize() {
		let task = PdfProcessorTask::new(TnId(1), 42, Path::new("/tmp/test.pdf"), 256);

		let serialized = Task::<App>::serialize(task.as_ref());
		assert!(serialized.contains("1,42,256"));

		let rebuilt = PdfProcessorTask::build(0, &serialized).unwrap();
		assert_eq!(rebuilt.kind_of(), "pdf.process");
	}
}

// vim: ts=4
