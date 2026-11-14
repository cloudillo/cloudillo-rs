// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Video processing tasks for transcoding.
//!
//! Uses FFmpeg via shell commands for video processing:
//! - VideoTranscoderTask: Transcode video to different quality tiers
//!
//! Note: Thumbnail extraction is now done synchronously during upload in handler.rs

use async_trait::async_trait;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc};

use crate::prelude::*;
use crate::{ffmpeg, store};
use cloudillo_core::scheduler::{Task, TaskId};
use cloudillo_types::blob_adapter;
use cloudillo_types::meta_adapter;

/// Video transcoder task - transcodes video to a specific quality tier
#[derive(Debug, Serialize, Deserialize)]
pub struct VideoTranscoderTask {
	tn_id: TnId,
	f_id: u64,
	variant: Box<str>,
	input_path: Box<Path>,
	max_dim: u32,
	bitrate: u32,
}

impl VideoTranscoderTask {
	pub fn new(
		tn_id: TnId,
		f_id: u64,
		input_path: impl Into<Box<Path>>,
		variant: impl Into<Box<str>>,
		max_dim: u32,
		bitrate: u32,
	) -> Arc<Self> {
		Arc::new(Self {
			tn_id,
			f_id,
			input_path: input_path.into(),
			variant: variant.into(),
			max_dim,
			bitrate,
		})
	}

	// Pre-JSON input of rows queued before the upgrade; drop at 1.0.
	fn build_legacy(ctx: &str) -> ClResult<Self> {
		let (tn_id, f_id, variant, max_dim, bitrate, path) =
			ctx.split(',').collect_tuple().ok_or(Error::Parse)?;
		Ok(Self {
			tn_id: TnId(tn_id.parse()?),
			f_id: f_id.parse()?,
			input_path: Box::from(Path::new(path)),
			variant: variant.into(),
			max_dim: max_dim.parse()?,
			bitrate: bitrate.parse()?,
		})
	}
}

#[async_trait]
impl Task<App> for VideoTranscoderTask {
	fn kind() -> &'static str {
		"video.transcode"
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
			"Running task video.transcode {:?} {} max_dim={} bitrate={}k",
			self.input_path, self.variant, self.max_dim, self.bitrate
		);

		// Create temp file for output in app's tmp_dir. The `.mp4` is not decoration:
		// ffmpeg picks the muxer from it.
		let output_path = crate::scratch::scratch_path(&app.opts.tmp_dir, "transcode", ".mp4")?;

		// Run transcoding in worker thread (CPU-intensive)
		let input_path = self.input_path.clone();
		let output_path_clone = output_path.clone();
		let max_dim = self.max_dim;
		let bitrate = self.bitrate;

		let (resolution, duration) = app
			.worker
			.try_run_slow(move || {
				let opts = ffmpeg::VideoTranscodeOpts {
					max_dim,
					bitrate,
					codec: "libx264".to_string(),
					preset: "medium".to_string(),
				};

				let resolution =
					ffmpeg::FFmpeg::transcode_video(&input_path, &output_path_clone, &opts)?;

				// Get duration from output
				let info = ffmpeg::FFmpeg::probe(&output_path_clone)?;
				Ok::<_, Error>((resolution, info.duration))
			})
			.await?;

		info!(
			"Finished task video.transcode {:?} → {}x{} dur={:.2}s",
			self.input_path, resolution.0, resolution.1, duration
		);

		// Get file size before creating blob
		let file_size = tokio::fs::metadata(&output_path).await?.len();

		// Create blob from file (streams + hashes off the tokio worker thread)
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
					format: "mp4",
					resolution,
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
	fn test_video_transcoder_serialize_deserialize() {
		let task =
			VideoTranscoderTask::new(TnId(1), 42, Path::new("/tmp/test.mp4"), "vid.hd", 1080, 5000);

		let serialized = Task::<App>::serialize(task.as_ref()).unwrap();
		assert!(serialized.starts_with('{'));
		assert!(serialized.contains("\"variant\":\"vid.hd\""));

		let decoded: VideoTranscoderTask = serde_json::from_str(&serialized).unwrap();
		assert_eq!(decoded.tn_id, task.tn_id);
		assert_eq!(decoded.f_id, task.f_id);
		assert_eq!(decoded.variant, task.variant);
		assert_eq!(decoded.input_path, task.input_path);
		assert_eq!(decoded.max_dim, task.max_dim);
		assert_eq!(decoded.bitrate, task.bitrate);

		let rebuilt = VideoTranscoderTask::build(0, &serialized).unwrap();
		assert_eq!(rebuilt.kind_of(), "video.transcode");
	}

	#[test]
	fn test_video_transcoder_build_legacy() {
		let ctx = "1,42,vid.hd,1080,5000,/tmp/test.mp4";
		assert_eq!(VideoTranscoderTask::build(0, ctx).unwrap().kind_of(), "video.transcode");

		let task = VideoTranscoderTask::build_legacy(ctx).unwrap();
		assert_eq!(task.tn_id, TnId(1));
		assert_eq!(task.f_id, 42);
		assert_eq!(&*task.variant, "vid.hd");
		assert_eq!(&*task.input_path, Path::new("/tmp/test.mp4"));
		assert_eq!(task.max_dim, 1080);
		assert_eq!(task.bitrate, 5000);
	}
}

// vim: ts=4
