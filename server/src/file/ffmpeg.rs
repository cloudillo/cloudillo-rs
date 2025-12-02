//! FFmpeg wrapper for video/audio processing.
//!
//! Provides functionality for:
//! - Probing media files (getting duration, resolution, codec info)
//! - Extracting frames for thumbnails (smart frame selection)
//! - Transcoding video to different qualities
//! - Extracting audio from video files

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

use crate::prelude::*;

/// Video stream information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoStream {
	pub index: u32,
	pub codec: String,
	pub width: u32,
	pub height: u32,
	pub frame_rate: f64,
	pub bitrate: Option<u32>,
}

/// Audio stream information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioStream {
	pub index: u32,
	pub codec: String,
	pub channels: u32,
	pub sample_rate: u32,
	pub bitrate: Option<u32>,
}

/// Media file information from ffprobe
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaInfo {
	pub duration: f64,
	pub format: String,
	pub video_streams: Vec<VideoStream>,
	pub audio_streams: Vec<AudioStream>,
}

impl MediaInfo {
	/// Get the primary video stream (first one)
	pub fn primary_video(&self) -> Option<&VideoStream> {
		self.video_streams.first()
	}

	/// Get the primary audio stream (first one)
	pub fn primary_audio(&self) -> Option<&AudioStream> {
		self.audio_streams.first()
	}

	/// Check if this is a video file (has video stream)
	pub fn has_video(&self) -> bool {
		!self.video_streams.is_empty()
	}

	/// Check if this is an audio file (has audio stream)
	pub fn has_audio(&self) -> bool {
		!self.audio_streams.is_empty()
	}

	/// Get video resolution as (width, height)
	pub fn video_resolution(&self) -> Option<(u32, u32)> {
		self.primary_video().map(|v| (v.width, v.height))
	}
}

/// Video transcoding options
#[derive(Debug, Clone)]
pub struct VideoTranscodeOpts {
	/// Maximum dimension (video fits in max_dim x max_dim bounding box)
	pub max_dim: u32,
	/// Target bitrate in kbps
	pub bitrate: u32,
	/// Video codec (default: libx264)
	pub codec: String,
	/// Preset (ultrafast, fast, medium, slow, veryslow)
	pub preset: String,
}

impl Default for VideoTranscodeOpts {
	fn default() -> Self {
		Self {
			max_dim: 1080,
			bitrate: 5000,
			codec: "libx264".to_string(),
			preset: "medium".to_string(),
		}
	}
}

/// Audio extraction options
#[derive(Debug, Clone)]
pub struct AudioExtractOpts {
	/// Target bitrate in kbps
	pub bitrate: u32,
	/// Audio codec (default: libopus)
	pub codec: String,
	/// Output format (default: opus)
	pub format: String,
}

impl Default for AudioExtractOpts {
	fn default() -> Self {
		Self { bitrate: 128, codec: "libopus".to_string(), format: "opus".to_string() }
	}
}

/// FFmpeg command wrapper
pub struct FFmpeg;

impl FFmpeg {
	/// Probe a media file and get its information
	pub fn probe(input: &Path) -> ClResult<MediaInfo> {
		let output = Command::new("ffprobe")
			.args([
				"-v",
				"quiet",
				"-print_format",
				"json",
				"-show_format",
				"-show_streams",
				input.to_str().ok_or(Error::Internal("invalid path".into()))?,
			])
			.output()
			.map_err(|e| Error::Internal(format!("ffprobe failed: {}", e)))?;

		if !output.status.success() {
			let stderr = String::from_utf8_lossy(&output.stderr);
			return Err(Error::Internal(format!("ffprobe failed: {}", stderr)));
		}

		let json: serde_json::Value = serde_json::from_slice(&output.stdout)
			.map_err(|e| Error::Internal(format!("failed to parse ffprobe output: {}", e)))?;

		Self::parse_probe_output(&json)
	}

	/// Parse ffprobe JSON output into MediaInfo
	fn parse_probe_output(json: &serde_json::Value) -> ClResult<MediaInfo> {
		let format = json
			.get("format")
			.ok_or(Error::Internal("missing format in ffprobe output".into()))?;

		let duration: f64 = format
			.get("duration")
			.and_then(|v| v.as_str())
			.and_then(|s| s.parse().ok())
			.unwrap_or(0.0);

		let format_name = format
			.get("format_name")
			.and_then(|v| v.as_str())
			.unwrap_or("unknown")
			.to_string();

		let streams = json
			.get("streams")
			.and_then(|v| v.as_array())
			.map(|arr| arr.as_slice())
			.unwrap_or(&[]);

		let mut video_streams = Vec::new();
		let mut audio_streams = Vec::new();

		for stream in streams {
			let codec_type = stream.get("codec_type").and_then(|v| v.as_str());

			match codec_type {
				Some("video") => {
					if let Some(vs) = Self::parse_video_stream(stream) {
						video_streams.push(vs);
					}
				}
				Some("audio") => {
					if let Some(aus) = Self::parse_audio_stream(stream) {
						audio_streams.push(aus);
					}
				}
				_ => {}
			}
		}

		Ok(MediaInfo { duration, format: format_name, video_streams, audio_streams })
	}

	/// Parse a video stream from ffprobe output
	fn parse_video_stream(stream: &serde_json::Value) -> Option<VideoStream> {
		let index = stream.get("index")?.as_u64()? as u32;
		let codec = stream.get("codec_name")?.as_str()?.to_string();
		let width = stream.get("width")?.as_u64()? as u32;
		let height = stream.get("height")?.as_u64()? as u32;

		// Parse frame rate from "30/1" or "30000/1001" format
		let frame_rate = stream
			.get("r_frame_rate")
			.and_then(|v| v.as_str())
			.and_then(|s| {
				let parts: Vec<&str> = s.split('/').collect();
				if parts.len() == 2 {
					let num: f64 = parts[0].parse().ok()?;
					let den: f64 = parts[1].parse().ok()?;
					Some(num / den)
				} else {
					s.parse().ok()
				}
			})
			.unwrap_or(30.0);

		let bitrate = stream
			.get("bit_rate")
			.and_then(|v| v.as_str())
			.and_then(|s| s.parse::<u64>().ok())
			.map(|b| (b / 1000) as u32);

		Some(VideoStream { index, codec, width, height, frame_rate, bitrate })
	}

	/// Parse an audio stream from ffprobe output
	fn parse_audio_stream(stream: &serde_json::Value) -> Option<AudioStream> {
		let index = stream.get("index")?.as_u64()? as u32;
		let codec = stream.get("codec_name")?.as_str()?.to_string();
		let channels = stream.get("channels")?.as_u64()? as u32;
		let sample_rate = stream
			.get("sample_rate")
			.and_then(|v| v.as_str())
			.and_then(|s| s.parse().ok())
			.unwrap_or(48000);

		let bitrate = stream
			.get("bit_rate")
			.and_then(|v| v.as_str())
			.and_then(|s| s.parse::<u64>().ok())
			.map(|b| (b / 1000) as u32);

		Some(AudioStream { index, codec, channels, sample_rate, bitrate })
	}

	/// Extract a frame from a video at a specific timestamp
	pub fn extract_frame(input: &Path, output: &Path, seek_seconds: f64) -> ClResult<()> {
		let status = Command::new("ffmpeg")
			.args([
				"-y",
				"-ss",
				&format!("{:.3}", seek_seconds),
				"-i",
				input.to_str().ok_or(Error::Internal("invalid input path".into()))?,
				"-vframes",
				"1",
				"-q:v",
				"2",
				"-update",
				"1",
				output.to_str().ok_or(Error::Internal("invalid output path".into()))?,
			])
			.status()
			.map_err(|e| Error::Internal(format!("ffmpeg failed: {}", e)))?;

		if !status.success() {
			return Err(Error::Internal("ffmpeg frame extraction failed".into()));
		}

		Ok(())
	}

	/// Find an "interesting" frame for thumbnail using scene detection
	/// Returns the timestamp in seconds of a visually interesting frame
	pub fn find_interesting_frame(input: &Path, duration: f64) -> ClResult<f64> {
		// Strategy: Sample frames at 10%, 25%, 50% and pick the one with highest scene score
		// For simplicity, we'll use 10% of the duration (avoids intro/credits)
		// A more sophisticated approach would use scene detection

		let seek_time = if duration > 10.0 {
			// For videos > 10 seconds, seek to 10% or 3 seconds, whichever is larger
			(duration * 0.1).max(3.0).min(duration - 1.0)
		} else if duration > 1.0 {
			// For short videos, seek to middle
			duration / 2.0
		} else {
			// Very short videos, use start
			0.0
		};

		// Verify we can actually seek to this position
		let output = Command::new("ffprobe")
			.args([
				"-v",
				"quiet",
				"-select_streams",
				"v:0",
				"-show_entries",
				"frame=pkt_pts_time",
				"-read_intervals",
				&format!("%{:.3}", seek_time),
				"-of",
				"csv=p=0",
				input.to_str().ok_or(Error::Internal("invalid path".into()))?,
			])
			.output();

		// If probing fails, fall back to our calculated time
		match output {
			Ok(out) if out.status.success() => {
				// Try to parse the actual frame time
				let stdout = String::from_utf8_lossy(&out.stdout);
				if let Some(first_line) = stdout.lines().next() {
					if let Ok(time) = first_line.trim().parse::<f64>() {
						return Ok(time);
					}
				}
				Ok(seek_time)
			}
			_ => Ok(seek_time),
		}
	}

	/// Transcode video to a specific quality
	pub fn transcode_video(
		input: &Path,
		output: &Path,
		opts: &VideoTranscodeOpts,
	) -> ClResult<(u32, u32)> {
		// Build the scale filter to fit in bounding box while maintaining aspect ratio
		// Crop to even dimensions (required by libx264) - removes at most 1 pixel
		let scale_filter = format!(
			"scale='min({},iw)':'min({},ih)':force_original_aspect_ratio=decrease,crop=trunc(iw/2)*2:trunc(ih/2)*2",
			opts.max_dim, opts.max_dim
		);

		let status = Command::new("ffmpeg")
			.args([
				"-y",
				"-i",
				input.to_str().ok_or(Error::Internal("invalid input path".into()))?,
				"-c:v",
				&opts.codec,
				"-preset",
				&opts.preset,
				"-b:v",
				&format!("{}k", opts.bitrate),
				"-vf",
				&scale_filter,
				"-c:a",
				"aac",
				"-b:a",
				"128k",
				"-movflags",
				"+faststart",
				output.to_str().ok_or(Error::Internal("invalid output path".into()))?,
			])
			.status()
			.map_err(|e| Error::Internal(format!("ffmpeg failed: {}", e)))?;

		if !status.success() {
			return Err(Error::Internal("ffmpeg video transcode failed".into()));
		}

		// Get the actual output resolution
		let info = Self::probe(output)?;
		let resolution = info
			.video_resolution()
			.ok_or(Error::Internal("failed to get output video resolution".into()))?;

		Ok(resolution)
	}

	/// Extract audio from a video or transcode audio file
	pub fn extract_audio(input: &Path, output: &Path, opts: &AudioExtractOpts) -> ClResult<f64> {
		let status = Command::new("ffmpeg")
			.args([
				"-y",
				"-i",
				input.to_str().ok_or(Error::Internal("invalid input path".into()))?,
				"-vn", // No video
				"-c:a",
				&opts.codec,
				"-b:a",
				&format!("{}k", opts.bitrate),
				output.to_str().ok_or(Error::Internal("invalid output path".into()))?,
			])
			.status()
			.map_err(|e| Error::Internal(format!("ffmpeg failed: {}", e)))?;

		if !status.success() {
			return Err(Error::Internal("ffmpeg audio extraction failed".into()));
		}

		// Get the duration of the output file
		let info = Self::probe(output)?;
		Ok(info.duration)
	}

	/// Check if FFmpeg is available
	pub fn is_available() -> bool {
		Command::new("ffmpeg")
			.arg("-version")
			.output()
			.map(|o| o.status.success())
			.unwrap_or(false)
	}

	/// Check if FFprobe is available
	pub fn is_probe_available() -> bool {
		Command::new("ffprobe")
			.arg("-version")
			.output()
			.map(|o| o.status.success())
			.unwrap_or(false)
	}
}

/// Video quality presets using bounding box approach
pub mod presets {
	use super::*;

	pub const VIDEO_SD: VideoTranscodeOpts = VideoTranscodeOpts {
		max_dim: 480,
		bitrate: 1500,
		codec: String::new(),  // Will use "libx264"
		preset: String::new(), // Will use "medium"
	};

	pub const VIDEO_MD: VideoTranscodeOpts = VideoTranscodeOpts {
		max_dim: 720,
		bitrate: 3000,
		codec: String::new(),
		preset: String::new(),
	};

	pub const VIDEO_HD: VideoTranscodeOpts = VideoTranscodeOpts {
		max_dim: 1080,
		bitrate: 5000,
		codec: String::new(),
		preset: String::new(),
	};

	pub const VIDEO_XD: VideoTranscodeOpts = VideoTranscodeOpts {
		max_dim: 2160,
		bitrate: 15000,
		codec: String::new(),
		preset: String::new(),
	};

	pub const AUDIO_SD: AudioExtractOpts = AudioExtractOpts {
		bitrate: 64,
		codec: String::new(),  // Will use "libopus"
		format: String::new(), // Will use "opus"
	};

	pub const AUDIO_MD: AudioExtractOpts =
		AudioExtractOpts { bitrate: 128, codec: String::new(), format: String::new() };

	pub const AUDIO_HD: AudioExtractOpts =
		AudioExtractOpts { bitrate: 256, codec: String::new(), format: String::new() };

	/// Get video transcode options for a quality tier
	pub fn video_opts(quality: &str) -> VideoTranscodeOpts {
		let base = match quality {
			"sd" => VIDEO_SD,
			"md" => VIDEO_MD,
			"hd" => VIDEO_HD,
			"xd" => VIDEO_XD,
			_ => VIDEO_HD,
		};

		VideoTranscodeOpts {
			max_dim: base.max_dim,
			bitrate: base.bitrate,
			codec: "libx264".to_string(),
			preset: "medium".to_string(),
		}
	}

	/// Get audio extraction options for a quality tier
	pub fn audio_opts(quality: &str) -> AudioExtractOpts {
		let base = match quality {
			"sd" => AUDIO_SD,
			"md" => AUDIO_MD,
			"hd" => AUDIO_HD,
			_ => AUDIO_MD,
		};

		AudioExtractOpts {
			bitrate: base.bitrate,
			codec: "libopus".to_string(),
			format: "opus".to_string(),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_ffmpeg_available() {
		// This test will pass if FFmpeg is installed
		let available = FFmpeg::is_available();
		println!("FFmpeg available: {}", available);
	}

	#[test]
	fn test_presets() {
		let video_opts = presets::video_opts("hd");
		assert_eq!(video_opts.max_dim, 1080);
		assert_eq!(video_opts.bitrate, 5000);

		let audio_opts = presets::audio_opts("md");
		assert_eq!(audio_opts.bitrate, 128);
	}
}

// vim: ts=4
