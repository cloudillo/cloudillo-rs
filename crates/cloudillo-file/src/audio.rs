// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Audio processing tasks for extraction and transcoding.
//!
//! Uses FFmpeg via shell commands for audio processing:
//! - AudioExtractorTask: Extract/transcode audio to a specific quality tier

use async_trait::async_trait;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc};

use crate::prelude::*;
use crate::{ffmpeg, store};
use cloudillo_core::scheduler::{Task, TaskId};
use cloudillo_types::blob_adapter;
use cloudillo_types::meta_adapter;

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

	// Pre-JSON input of rows queued before the upgrade; drop at 1.0.
	fn build_legacy(ctx: &str) -> ClResult<Self> {
		let (tn_id, f_id, variant, bitrate, path) =
			ctx.split(',').collect_tuple().ok_or(Error::Parse)?;
		Ok(Self {
			tn_id: TnId(tn_id.parse()?),
			f_id: f_id.parse()?,
			input_path: Box::from(Path::new(path)),
			variant: variant.into(),
			bitrate: bitrate.parse()?,
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
			"Running task audio.extract {:?} {} bitrate={}k",
			self.input_path, self.variant, self.bitrate
		);

		// Create temp file for output in app's tmp_dir. The `.opus` is not decoration:
		// ffmpeg picks the muxer from it.
		let output_path = crate::scratch::scratch_path(&app.opts.tmp_dir, "audio", ".opus")?;

		// Run audio extraction in worker thread (CPU-intensive)
		let input_path = self.input_path.clone();
		let output_path_clone = output_path.clone();
		let bitrate = self.bitrate;

		let duration = app
			.worker
			.try_run_slow(move || {
				let opts = ffmpeg::AudioExtractOpts { bitrate, codec: "libopus".to_string() };

				let duration =
					ffmpeg::FFmpeg::extract_audio(&input_path, &output_path_clone, &opts)?;
				Ok::<_, Error>(duration)
			})
			.await?;

		info!("Finished task audio.extract {:?} → dur={:.2}s", self.input_path, duration);

		// Get file size before creating blob
		let file_size = tokio::fs::metadata(&output_path).await?.len();

		// Create blob from file (streams + hashes off the worker thread)
		let variant_id = store::create_blob_from_file(
			app,
			self.tn_id,
			&output_path,
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
					resolution: (0, 0),
					size: file_size,
					available: true,
					global: false,
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

	#[test]
	fn test_audio_extractor_serialize_deserialize() {
		let task = AudioExtractorTask::new(TnId(1), 42, Path::new("/tmp/test.mp4"), "aud.md", 128);

		let serialized = Task::<App>::serialize(task.as_ref()).unwrap();
		assert!(serialized.starts_with('{'));
		assert!(serialized.contains("\"variant\":\"aud.md\""));

		let decoded: AudioExtractorTask = serde_json::from_str(&serialized).unwrap();
		assert_eq!(decoded.tn_id, task.tn_id);
		assert_eq!(decoded.f_id, task.f_id);
		assert_eq!(decoded.variant, task.variant);
		assert_eq!(decoded.input_path, task.input_path);
		assert_eq!(decoded.bitrate, task.bitrate);

		let rebuilt = AudioExtractorTask::build(0, &serialized).unwrap();
		assert_eq!(rebuilt.kind_of(), "audio.extract");
	}

	#[test]
	fn test_audio_extractor_build_legacy() {
		let ctx = "1,42,aud.md,128,/tmp/test.mp4";
		assert_eq!(AudioExtractorTask::build(0, ctx).unwrap().kind_of(), "audio.extract");

		let task = AudioExtractorTask::build_legacy(ctx).unwrap();
		assert_eq!(task.tn_id, TnId(1));
		assert_eq!(task.f_id, 42);
		assert_eq!(&*task.variant, "aud.md");
		assert_eq!(&*task.input_path, Path::new("/tmp/test.mp4"));
		assert_eq!(task.bitrate, 128);
	}
}

// vim: ts=4
