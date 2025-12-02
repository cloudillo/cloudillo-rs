//! Audio processing tasks for extraction and transcoding.
//!
//! Uses FFmpeg via shell commands for audio processing:
//! - AudioExtractorTask: Extract/transcode audio to a specific quality tier

use async_trait::async_trait;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc};

use crate::blob_adapter;
use crate::core::scheduler::{Task, TaskId};
use crate::file::{ffmpeg, store};
use crate::meta_adapter;
use crate::prelude::*;
use crate::types::TnId;

/// Audio extractor task - extracts audio from video or transcodes audio to a specific quality tier
#[derive(Debug, Serialize, Deserialize)]
pub struct AudioExtractorTask {
	tn_id: TnId,
	f_id: u64,
	variant: Box<str>,
	input_path: Box<Path>,
	bitrate: u32,
}

impl AudioExtractorTask {
	pub fn new(
		tn_id: TnId,
		f_id: u64,
		input_path: impl Into<Box<Path>>,
		variant: impl Into<Box<str>>,
		bitrate: u32,
	) -> Arc<Self> {
		Arc::new(Self {
			tn_id,
			f_id,
			input_path: input_path.into(),
			variant: variant.into(),
			bitrate,
		})
	}
}

#[async_trait]
impl Task<App> for AudioExtractorTask {
	fn kind() -> &'static str {
		"audio.extract"
	}
	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		let (tn_id, f_id, variant, bitrate, path) =
			ctx.split(',').collect_tuple().ok_or(Error::Parse)?;
		let task = AudioExtractorTask::new(
			TnId(tn_id.parse()?),
			f_id.parse()?,
			Box::from(Path::new(path)),
			variant,
			bitrate.parse()?,
		);
		Ok(task)
	}

	fn serialize(&self) -> String {
		format!(
			"{},{},{},{},{}",
			self.tn_id,
			self.f_id,
			self.variant,
			self.bitrate,
			self.input_path.to_string_lossy()
		)
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		info!(
			"Running task audio.extract {:?} {} bitrate={}k",
			self.input_path, self.variant, self.bitrate
		);

		// Create temp file for output in app's tmp_dir
		let output_name = format!("audio_{}_{}.opus", self.f_id, self.variant.replace('.', "_"));
		let output_path = app.opts.tmp_dir.join(&output_name);

		// Run audio extraction in worker thread (CPU-intensive)
		let input_path = self.input_path.clone();
		let output_path_clone = output_path.clone();
		let bitrate = self.bitrate;

		let duration = app
			.worker
			.run(move || {
				let opts = ffmpeg::AudioExtractOpts {
					bitrate,
					codec: "libopus".to_string(),
					format: "opus".to_string(),
				};

				let duration =
					ffmpeg::FFmpeg::extract_audio(&input_path, &output_path_clone, &opts)?;
				Ok::<_, Error>(duration)
			})
			.await?;

		info!("Finished task audio.extract {:?} → dur={:.2}s", self.input_path, duration);

		// Read output and create blob
		let bytes = tokio::fs::read(&output_path).await?;
		let variant_id = store::create_blob_buf(
			app,
			self.tn_id,
			&bytes,
			blob_adapter::CreateBlobOptions::default(),
		)
		.await?;

		// Clean up temp file
		let _ = tokio::fs::remove_file(&output_path).await;

		// Store variant metadata
		app.meta_adapter
			.create_file_variant(
				self.tn_id,
				self.f_id,
				meta_adapter::FileVariant {
					variant_id: &variant_id,
					variant: &self.variant,
					format: "opus",
					resolution: (0, 0), // Audio has no resolution
					size: bytes.len() as u64,
					available: true,
					duration: Some(duration),
					bitrate: Some(self.bitrate),
					page_count: None,
				},
			)
			.await?;

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::core::scheduler::Task;

	#[test]
	fn test_audio_extractor_serialize_deserialize() {
		let task = AudioExtractorTask::new(TnId(1), 42, Path::new("/tmp/test.mp4"), "aud.md", 128);

		let serialized = Task::<App>::serialize(task.as_ref());
		assert!(serialized.contains("1,42,aud.md,128"));

		let rebuilt = AudioExtractorTask::build(0, &serialized).unwrap();
		assert_eq!(rebuilt.kind_of(), "audio.extract");
	}
}

// vim: ts=4
