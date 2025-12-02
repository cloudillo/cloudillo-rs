//! File processing presets for different use cases.
//!
//! Presets define which variants to generate for different media types
//! and use cases (e.g., "default", "podcast", "archive").

use serde::{Deserialize, Serialize};

use super::variant::VariantClass;

/// File processing preset configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePreset {
	/// Preset name (e.g., "default", "podcast", "archive")
	pub name: String,
	/// Allowed media classes for upload (e.g., [Visual, Video, Audio])
	pub allowed_media_classes: Vec<VariantClass>,
	/// Image/visual variants to generate (e.g., ["vis.tn", "vis.sd", "vis.md", "vis.hd"])
	pub image_variants: Vec<String>,
	/// Video variants to generate (e.g., ["vid.sd", "vid.md", "vid.hd"])
	pub video_variants: Vec<String>,
	/// Audio variants to generate (e.g., ["aud.md"])
	pub audio_variants: Vec<String>,
	/// Extract audio track from video files
	pub extract_audio: bool,
	/// Generate thumbnail for video/audio/document files
	pub generate_thumbnail: bool,
	/// Maximum variant to generate (caps generation at this level)
	pub max_variant: Option<String>,
}

impl Default for FilePreset {
	fn default() -> Self {
		Self {
			name: "default".to_string(),
			allowed_media_classes: vec![
				VariantClass::Visual,
				VariantClass::Video,
				VariantClass::Audio,
				VariantClass::Document,
			],
			image_variants: vec![
				"vis.tn".into(),
				"vis.sd".into(),
				"vis.md".into(),
				"vis.hd".into(),
			],
			video_variants: vec!["vid.sd".into(), "vid.md".into(), "vid.hd".into()],
			audio_variants: vec!["aud.md".into()],
			extract_audio: false,
			generate_thumbnail: true,
			max_variant: Some("vid.hd".into()),
		}
	}
}

/// Built-in presets
pub mod presets {
	use super::{FilePreset, VariantClass};

	/// Default preset - balanced quality and storage
	pub fn default() -> FilePreset {
		FilePreset::default()
	}

	/// Podcast preset - prioritizes audio extraction and quality
	pub fn podcast() -> FilePreset {
		FilePreset {
			name: "podcast".to_string(),
			allowed_media_classes: vec![VariantClass::Audio, VariantClass::Video],
			image_variants: vec!["vis.tn".into()], // Just thumbnail for audio-focused
			video_variants: vec!["vid.sd".into()],
			audio_variants: vec!["aud.sd".into(), "aud.md".into(), "aud.hd".into()],
			extract_audio: true,
			generate_thumbnail: true,
			max_variant: Some("vid.sd".into()),
		}
	}

	/// Archive preset - keep original only, minimal processing (allows all types including raw)
	pub fn archive() -> FilePreset {
		FilePreset {
			name: "archive".to_string(),
			allowed_media_classes: vec![
				VariantClass::Visual,
				VariantClass::Video,
				VariantClass::Audio,
				VariantClass::Document,
				VariantClass::Raw,
			],
			image_variants: vec!["vis.tn".into()], // Minimal processing
			video_variants: vec![],
			audio_variants: vec![],
			extract_audio: false,
			generate_thumbnail: true,
			max_variant: None, // Keep original only
		}
	}

	/// High quality preset - maximum quality variants
	pub fn high_quality() -> FilePreset {
		FilePreset {
			name: "high_quality".to_string(),
			allowed_media_classes: vec![
				VariantClass::Visual,
				VariantClass::Video,
				VariantClass::Audio,
			],
			image_variants: vec![
				"vis.tn".into(),
				"vis.sd".into(),
				"vis.md".into(),
				"vis.hd".into(),
				"vis.xd".into(),
			],
			video_variants: vec![
				"vid.sd".into(),
				"vid.md".into(),
				"vid.hd".into(),
				"vid.xd".into(),
			],
			audio_variants: vec!["aud.md".into(), "aud.hd".into()],
			extract_audio: false,
			generate_thumbnail: true,
			max_variant: Some("vid.xd".into()),
		}
	}

	/// Mobile preset - optimized for mobile devices and bandwidth
	pub fn mobile() -> FilePreset {
		FilePreset {
			name: "mobile".to_string(),
			allowed_media_classes: vec![
				VariantClass::Visual,
				VariantClass::Video,
				VariantClass::Audio,
			],
			image_variants: vec!["vis.tn".into(), "vis.sd".into(), "vis.md".into()],
			video_variants: vec!["vid.sd".into(), "vid.md".into()],
			audio_variants: vec!["aud.sd".into()],
			extract_audio: false,
			generate_thumbnail: true,
			max_variant: Some("vid.md".into()),
		}
	}

	/// Video preset - video-focused, no separate audio track extraction
	pub fn video() -> FilePreset {
		FilePreset {
			name: "video".to_string(),
			allowed_media_classes: vec![VariantClass::Video],
			image_variants: vec!["vis.sd".into(), "vis.md".into(), "vis.hd".into()], // Match video tiers
			video_variants: vec!["vid.sd".into(), "vid.md".into(), "vid.hd".into()],
			audio_variants: vec![], // No separate audio variants
			extract_audio: false,   // Don't extract audio track
			generate_thumbnail: true,
			max_variant: Some("vid.hd".into()),
		}
	}

	/// Get preset by name
	pub fn get(name: &str) -> Option<FilePreset> {
		match name {
			"default" => Some(default()),
			"podcast" => Some(podcast()),
			"archive" => Some(archive()),
			"high_quality" => Some(high_quality()),
			"mobile" => Some(mobile()),
			"video" => Some(video()),
			_ => None,
		}
	}

	/// List all available preset names
	pub fn list() -> Vec<&'static str> {
		vec!["default", "podcast", "archive", "high_quality", "mobile", "video"]
	}
}

/// Video quality tier with associated settings
#[derive(Debug, Clone, Copy)]
pub struct VideoQualityTier {
	pub name: &'static str,
	pub max_dim: u32,
	pub bitrate: u32,
}

/// Audio quality tier with associated settings
#[derive(Debug, Clone, Copy)]
pub struct AudioQualityTier {
	pub name: &'static str,
	pub bitrate: u32,
}

/// Image quality tier with associated settings
#[derive(Debug, Clone, Copy)]
pub struct ImageQualityTier {
	pub name: &'static str,
	pub max_dim: u32,
}

/// Video quality tiers
pub const VIDEO_TIERS: &[VideoQualityTier] = &[
	VideoQualityTier { name: "vid.sd", max_dim: 720, bitrate: 1500 },
	VideoQualityTier { name: "vid.md", max_dim: 1280, bitrate: 3000 },
	VideoQualityTier { name: "vid.hd", max_dim: 1920, bitrate: 5000 },
	VideoQualityTier { name: "vid.xd", max_dim: 3840, bitrate: 15000 },
];

/// Audio quality tiers
pub const AUDIO_TIERS: &[AudioQualityTier] = &[
	AudioQualityTier { name: "aud.sd", bitrate: 64 },
	AudioQualityTier { name: "aud.md", bitrate: 128 },
	AudioQualityTier { name: "aud.hd", bitrate: 256 },
];

/// Image quality tiers
pub const IMAGE_TIERS: &[ImageQualityTier] = &[
	ImageQualityTier { name: "vis.tn", max_dim: 256 },
	ImageQualityTier { name: "vis.sd", max_dim: 720 },
	ImageQualityTier { name: "vis.md", max_dim: 1280 },
	ImageQualityTier { name: "vis.hd", max_dim: 1920 },
	ImageQualityTier { name: "vis.xd", max_dim: 3840 },
];

/// Get video tier by variant name
pub fn get_video_tier(variant: &str) -> Option<&'static VideoQualityTier> {
	VIDEO_TIERS.iter().find(|t| t.name == variant)
}

/// Get audio tier by variant name
pub fn get_audio_tier(variant: &str) -> Option<&'static AudioQualityTier> {
	AUDIO_TIERS.iter().find(|t| t.name == variant)
}

/// Get image tier by variant name
pub fn get_image_tier(variant: &str) -> Option<&'static ImageQualityTier> {
	IMAGE_TIERS.iter().find(|t| t.name == variant)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_default_preset() {
		let preset = presets::default();
		assert_eq!(preset.name, "default");
		assert!(preset.video_variants.contains(&"vid.hd".to_string()));
		assert!(preset.generate_thumbnail);
	}

	#[test]
	fn test_podcast_preset() {
		let preset = presets::podcast();
		assert_eq!(preset.name, "podcast");
		assert!(preset.extract_audio);
		assert!(preset.audio_variants.contains(&"aud.hd".to_string()));
	}

	#[test]
	fn test_get_preset() {
		assert!(presets::get("default").is_some());
		assert!(presets::get("podcast").is_some());
		assert!(presets::get("nonexistent").is_none());
	}

	#[test]
	fn test_video_tiers() {
		let tier = get_video_tier("vid.hd");
		assert!(tier.is_some());
		let tier = tier.unwrap();
		assert_eq!(tier.max_dim, 1920);
		assert_eq!(tier.bitrate, 5000);
	}

	#[test]
	fn test_audio_tiers() {
		let tier = get_audio_tier("aud.md");
		assert!(tier.is_some());
		let tier = tier.unwrap();
		assert_eq!(tier.bitrate, 128);
	}

	#[test]
	fn test_image_tiers() {
		let tier = get_image_tier("vis.hd");
		assert!(tier.is_some());
		let tier = tier.unwrap();
		assert_eq!(tier.max_dim, 1920);
	}
}

// vim: ts=4
