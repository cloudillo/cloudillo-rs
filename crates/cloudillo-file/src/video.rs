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
		let (tn_id, f_id, variant, max_dim, bitrate, path) =
			ctx.split(',').collect_tuple().ok_or(Error::Parse)?;
		let task = VideoTranscoderTask::new(
			TnId(tn_id.parse()?),
			f_id.parse()?,
			Box::from(Path::new(path)),
			variant,
			max_dim.parse()?,
			bitrate.parse()?,
		);
		Ok(task)
	}

	fn serialize(&self) -> String {
		format!(
			"{},{},{},{},{},{}",
			self.tn_id,
			self.f_id,
			self.variant,
			self.max_dim,
			self.bitrate,
			self.input_path.to_string_lossy()
		)
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		info!(
			"Running task video.transcode {:?} {} max_dim={} bitrate={}k",
			self.input_path, self.variant, self.max_dim, self.bitrate
		);

		// Create temp file for output in app's tmp_dir
		let output_name = format!("transcode_{}_{}.mp4", self.f_id, self.variant.replace('.', "_"));
		let output_path = app.opts.tmp_dir.join(&output_name);

		// Run transcoding in worker thread (CPU-intensive)
		let input_path = self.input_path.clone();
		let output_path_clone = output_path.clone();
		let max_dim = self.max_dim;
		let bitrate = self.bitrate;

		let (resolution, duration) = app
			.worker
			.try_run(move || {
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
					format: "mp4",
					resolution,
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

	#[test]
	fn test_video_transcoder_serialize_deserialize() {
		let task =
			VideoTranscoderTask::new(TnId(1), 42, Path::new("/tmp/test.mp4"), "vid.hd", 1080, 5000);

		let serialized = Task::<App>::serialize(task.as_ref());
		assert!(serialized.contains("1,42,vid.hd,1080,5000"));

		let rebuilt = VideoTranscoderTask::build(0, &serialized).unwrap();
		assert_eq!(rebuilt.kind_of(), "video.transcode");
	}
}

// vim: ts=4
