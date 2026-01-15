//! Variant classes and quality tiers for multi-media file processing.
//!
//! Implements a two-level hierarchy: `class.quality` (e.g., `vis.sd`, `aud.hd`, `vid.md`)

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Variant class - the media type category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VariantClass {
	/// Visual - images (jpeg, png, webp, avif)
	Visual,
	/// Video - video files (mp4/h264)
	Video,
	/// Audio - audio tracks (opus)
	Audio,
	/// Document - PDF documents
	Document,
	/// Raw - original unprocessed file
	Raw,
}

impl VariantClass {
	/// Get the short string representation (e.g., "vis", "vid", "aud")
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::Visual => "vis",
			Self::Video => "vid",
			Self::Audio => "aud",
			Self::Document => "doc",
			Self::Raw => "raw",
		}
	}

	/// Parse from short string representation
	pub fn from_str_opt(s: &str) -> Option<Self> {
		match s {
			"vis" => Some(Self::Visual),
			"vid" => Some(Self::Video),
			"aud" => Some(Self::Audio),
			"doc" => Some(Self::Document),
			"raw" => Some(Self::Raw),
			_ => None,
		}
	}

	/// Determine variant class from content-type MIME string
	pub fn from_content_type(content_type: &str) -> Option<Self> {
		match content_type {
			// Image (including SVG)
			"image/jpeg" | "image/png" | "image/webp" | "image/avif" | "image/gif"
			| "image/svg+xml" => Some(Self::Visual),
			// Video
			"video/mp4" | "video/quicktime" | "video/webm" | "video/x-msvideo"
			| "video/x-matroska" => Some(Self::Video),
			// Audio
			"audio/mpeg" | "audio/wav" | "audio/ogg" | "audio/flac" | "audio/aac"
			| "audio/webm" => Some(Self::Audio),
			// Document
			"application/pdf" => Some(Self::Document),
			// Unknown - don't return Raw automatically, let caller decide
			_ => None,
		}
	}
}

impl fmt::Display for VariantClass {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.as_str())
	}
}

impl FromStr for VariantClass {
	type Err = ();

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Self::from_str_opt(s).ok_or(())
	}
}

/// Variant quality tier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VariantQuality {
	/// Profile - special variant for profile pictures (fallback to thumbnail)
	Profile,
	/// Thumbnail - tiny preview (128px for images, static frame for video)
	Thumbnail,
	/// Small/Standard Definition - 720px images, 480p video, 64kbps audio
	Small,
	/// Medium Definition - 1280px images, 720p video, 128kbps audio
	Medium,
	/// High Definition - 1920px images, 1080p video, 256kbps audio
	High,
	/// Extra/Extreme Definition - 3840px images, 4K video
	Extra,
	/// Original - unprocessed source file
	Original,
}

impl VariantQuality {
	/// Get the short string representation (e.g., "tn", "sd", "md")
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::Profile => "pf",
			Self::Thumbnail => "tn",
			Self::Small => "sd",
			Self::Medium => "md",
			Self::High => "hd",
			Self::Extra => "xd",
			Self::Original => "orig",
		}
	}

	/// Parse from short string representation
	pub fn from_str_opt(s: &str) -> Option<Self> {
		match s {
			"pf" => Some(Self::Profile),
			"tn" => Some(Self::Thumbnail),
			"sd" => Some(Self::Small),
			"md" => Some(Self::Medium),
			"hd" => Some(Self::High),
			"xd" => Some(Self::Extra),
			"orig" => Some(Self::Original),
			_ => None,
		}
	}

	/// Get the bounding box size for this quality tier (for images/video)
	pub fn bounding_box(&self) -> Option<u32> {
		match self {
			Self::Profile => Some(80),
			Self::Thumbnail => Some(128),
			Self::Small => Some(720),
			Self::Medium => Some(1280),
			Self::High => Some(1920),
			Self::Extra => Some(3840),
			Self::Original => None,
		}
	}

	/// Get the audio bitrate in kbps for this quality tier
	pub fn audio_bitrate(&self) -> Option<u32> {
		match self {
			Self::Profile => None,
			Self::Thumbnail => None,
			Self::Small => Some(64),
			Self::Medium => Some(128),
			Self::High => Some(256),
			Self::Extra => Some(320),
			Self::Original => None,
		}
	}

	/// Get the video bitrate in kbps for this quality tier
	pub fn video_bitrate(&self) -> Option<u32> {
		match self {
			Self::Profile => None,
			Self::Thumbnail => None,
			Self::Small => Some(1500),
			Self::Medium => Some(3000),
			Self::High => Some(5000),
			Self::Extra => Some(15000),
			Self::Original => None,
		}
	}

	/// List of standard quality tiers in ascending order (excluding special variants)
	pub const STANDARD_TIERS: &'static [VariantQuality] =
		&[Self::Thumbnail, Self::Small, Self::Medium, Self::High, Self::Extra];
}

impl fmt::Display for VariantQuality {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.as_str())
	}
}

impl FromStr for VariantQuality {
	type Err = ();

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Self::from_str_opt(s).ok_or(())
	}
}

/// A complete variant specification combining class and quality
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Variant {
	pub class: VariantClass,
	pub quality: VariantQuality,
}

impl Variant {
	/// Create a new variant
	pub fn new(class: VariantClass, quality: VariantQuality) -> Self {
		Self { class, quality }
	}

	/// Parse from string in format "class.quality" (e.g., "vis.sd")
	/// Special case: "orig" has no class prefix and uses Raw class internally
	/// Also supports legacy single-level format (e.g., "sd") which defaults to Visual class
	pub fn parse(s: &str) -> Option<Self> {
		// Special case: "orig" is always stored without class prefix
		if s == "orig" {
			return Some(Self { class: VariantClass::Raw, quality: VariantQuality::Original });
		}

		if let Some((class_str, quality_str)) = s.split_once('.') {
			// New two-level format: "vis.sd"
			let class = VariantClass::from_str_opt(class_str)?;
			let quality = VariantQuality::from_str_opt(quality_str)?;
			Some(Self { class, quality })
		} else {
			// Legacy single-level format: "sd" → defaults to Visual
			let quality = VariantQuality::from_str_opt(s)?;
			Some(Self { class: VariantClass::Visual, quality })
		}
	}

	/// Check if this is a legacy (single-level) variant name
	/// Note: "orig" is NOT legacy - it's the canonical format for originals
	pub fn is_legacy_format(s: &str) -> bool {
		s != "orig" && !s.contains('.') && VariantQuality::from_str_opt(s).is_some()
	}

	/// Convert legacy variant name to new format
	/// "sd" → "vis.sd", "tn" → "vis.tn"
	pub fn upgrade_legacy(s: &str) -> Option<String> {
		if Self::is_legacy_format(s) {
			Some(format!("{}.{}", VariantClass::Visual, s))
		} else {
			None
		}
	}

	// Common variant constants
	pub const VIS_TN: Self =
		Self { class: VariantClass::Visual, quality: VariantQuality::Thumbnail };
	pub const VIS_SD: Self = Self { class: VariantClass::Visual, quality: VariantQuality::Small };
	pub const VIS_MD: Self = Self { class: VariantClass::Visual, quality: VariantQuality::Medium };
	pub const VIS_HD: Self = Self { class: VariantClass::Visual, quality: VariantQuality::High };
	pub const VIS_XD: Self = Self { class: VariantClass::Visual, quality: VariantQuality::Extra };
	pub const VIS_ORIG: Self =
		Self { class: VariantClass::Visual, quality: VariantQuality::Original };
	pub const VIS_PF: Self = Self { class: VariantClass::Visual, quality: VariantQuality::Profile };

	pub const VID_SD: Self = Self { class: VariantClass::Video, quality: VariantQuality::Small };
	pub const VID_MD: Self = Self { class: VariantClass::Video, quality: VariantQuality::Medium };
	pub const VID_HD: Self = Self { class: VariantClass::Video, quality: VariantQuality::High };
	pub const VID_XD: Self = Self { class: VariantClass::Video, quality: VariantQuality::Extra };

	pub const AUD_SD: Self = Self { class: VariantClass::Audio, quality: VariantQuality::Small };
	pub const AUD_MD: Self = Self { class: VariantClass::Audio, quality: VariantQuality::Medium };
	pub const AUD_HD: Self = Self { class: VariantClass::Audio, quality: VariantQuality::High };

	pub const DOC_ORIG: Self =
		Self { class: VariantClass::Document, quality: VariantQuality::Original };

	pub const RAW_ORIG: Self = Self { class: VariantClass::Raw, quality: VariantQuality::Original };
}

impl fmt::Display for Variant {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		// Special case: "orig" is always displayed without class prefix
		if self.quality == VariantQuality::Original {
			write!(f, "orig")
		} else {
			write!(f, "{}.{}", self.class, self.quality)
		}
	}
}

impl FromStr for Variant {
	type Err = ();

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Self::parse(s).ok_or(())
	}
}

/// Parse quality tier from variant name or quality string.
/// Handles both "hd" (quality only) and "vis.hd" (class.quality) formats.
pub fn parse_quality(s: &str) -> Option<VariantQuality> {
	if let Some(v) = Variant::parse(s) {
		Some(v.quality)
	} else {
		VariantQuality::from_str_opt(s)
	}
}

/// Get the fallback chain for a given variant (within the same class)
pub fn get_fallback_chain(variant: &Variant) -> Vec<Variant> {
	let class = variant.class;
	match variant.quality {
		VariantQuality::Thumbnail => vec![],
		VariantQuality::Small => vec![
			Variant::new(class, VariantQuality::Medium),
			Variant::new(class, VariantQuality::Thumbnail),
		],
		VariantQuality::Medium => vec![
			Variant::new(class, VariantQuality::Small),
			Variant::new(class, VariantQuality::Thumbnail),
		],
		VariantQuality::High => vec![
			Variant::new(class, VariantQuality::Medium),
			Variant::new(class, VariantQuality::Small),
			Variant::new(class, VariantQuality::Thumbnail),
		],
		VariantQuality::Extra => vec![
			Variant::new(class, VariantQuality::High),
			Variant::new(class, VariantQuality::Medium),
			Variant::new(class, VariantQuality::Small),
			Variant::new(class, VariantQuality::Thumbnail),
		],
		VariantQuality::Original => vec![
			Variant::new(class, VariantQuality::Extra),
			Variant::new(class, VariantQuality::High),
			Variant::new(class, VariantQuality::Medium),
			Variant::new(class, VariantQuality::Small),
			Variant::new(class, VariantQuality::Thumbnail),
		],
		VariantQuality::Profile => vec![Variant::new(class, VariantQuality::Thumbnail)],
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_variant_class_parsing() {
		assert_eq!(VariantClass::from_str_opt("vis"), Some(VariantClass::Visual));
		assert_eq!(VariantClass::from_str_opt("vid"), Some(VariantClass::Video));
		assert_eq!(VariantClass::from_str_opt("aud"), Some(VariantClass::Audio));
		assert_eq!(VariantClass::from_str_opt("doc"), Some(VariantClass::Document));
		assert_eq!(VariantClass::from_str_opt("raw"), Some(VariantClass::Raw));
		assert_eq!(VariantClass::from_str_opt("invalid"), None);
	}

	#[test]
	fn test_variant_quality_parsing() {
		assert_eq!(VariantQuality::from_str_opt("tn"), Some(VariantQuality::Thumbnail));
		assert_eq!(VariantQuality::from_str_opt("sd"), Some(VariantQuality::Small));
		assert_eq!(VariantQuality::from_str_opt("md"), Some(VariantQuality::Medium));
		assert_eq!(VariantQuality::from_str_opt("hd"), Some(VariantQuality::High));
		assert_eq!(VariantQuality::from_str_opt("xd"), Some(VariantQuality::Extra));
		assert_eq!(VariantQuality::from_str_opt("orig"), Some(VariantQuality::Original));
		assert_eq!(VariantQuality::from_str_opt("pf"), Some(VariantQuality::Profile));
		assert_eq!(VariantQuality::from_str_opt("invalid"), None);
	}

	#[test]
	fn test_variant_parsing_new_format() {
		let v = Variant::parse("vis.sd").unwrap();
		assert_eq!(v.class, VariantClass::Visual);
		assert_eq!(v.quality, VariantQuality::Small);

		let v = Variant::parse("vid.hd").unwrap();
		assert_eq!(v.class, VariantClass::Video);
		assert_eq!(v.quality, VariantQuality::High);

		let v = Variant::parse("aud.md").unwrap();
		assert_eq!(v.class, VariantClass::Audio);
		assert_eq!(v.quality, VariantQuality::Medium);
	}

	#[test]
	fn test_variant_parsing_legacy_format() {
		// Legacy format should default to Visual class
		let v = Variant::parse("sd").unwrap();
		assert_eq!(v.class, VariantClass::Visual);
		assert_eq!(v.quality, VariantQuality::Small);

		let v = Variant::parse("tn").unwrap();
		assert_eq!(v.class, VariantClass::Visual);
		assert_eq!(v.quality, VariantQuality::Thumbnail);
	}

	#[test]
	fn test_variant_display() {
		assert_eq!(Variant::VIS_SD.to_string(), "vis.sd");
		assert_eq!(Variant::VID_HD.to_string(), "vid.hd");
		assert_eq!(Variant::AUD_MD.to_string(), "aud.md");
		// Original variants always display as just "orig" regardless of class
		assert_eq!(Variant::VIS_ORIG.to_string(), "orig");
		assert_eq!(Variant::RAW_ORIG.to_string(), "orig");
	}

	#[test]
	fn test_is_legacy_format() {
		assert!(Variant::is_legacy_format("sd"));
		assert!(Variant::is_legacy_format("tn"));
		assert!(Variant::is_legacy_format("hd"));
		assert!(!Variant::is_legacy_format("vis.sd"));
		assert!(!Variant::is_legacy_format("invalid"));
		// "orig" is NOT legacy - it's the canonical format for originals
		assert!(!Variant::is_legacy_format("orig"));
	}

	#[test]
	fn test_upgrade_legacy() {
		assert_eq!(Variant::upgrade_legacy("sd"), Some("vis.sd".to_string()));
		assert_eq!(Variant::upgrade_legacy("tn"), Some("vis.tn".to_string()));
		assert_eq!(Variant::upgrade_legacy("vis.sd"), None);
		// "orig" should NOT be upgraded - it's already canonical
		assert_eq!(Variant::upgrade_legacy("orig"), None);
	}

	#[test]
	fn test_orig_special_case() {
		// "orig" parses to Raw class with Original quality
		let v = Variant::parse("orig").unwrap();
		assert_eq!(v.class, VariantClass::Raw);
		assert_eq!(v.quality, VariantQuality::Original);

		// Display always outputs just "orig"
		assert_eq!(v.to_string(), "orig");

		// Any variant with Original quality displays as "orig"
		let vis_orig = Variant::new(VariantClass::Visual, VariantQuality::Original);
		assert_eq!(vis_orig.to_string(), "orig");
	}

	#[test]
	fn test_bounding_box() {
		assert_eq!(VariantQuality::Thumbnail.bounding_box(), Some(128));
		assert_eq!(VariantQuality::Small.bounding_box(), Some(720));
		assert_eq!(VariantQuality::Medium.bounding_box(), Some(1280));
		assert_eq!(VariantQuality::High.bounding_box(), Some(1920));
		assert_eq!(VariantQuality::Extra.bounding_box(), Some(3840));
		assert_eq!(VariantQuality::Original.bounding_box(), None);
	}

	#[test]
	fn test_fallback_chain() {
		let chain = get_fallback_chain(&Variant::VIS_HD);
		assert_eq!(chain.len(), 3);
		assert_eq!(chain[0], Variant::VIS_MD);
		assert_eq!(chain[1], Variant::VIS_SD);
		assert_eq!(chain[2], Variant::VIS_TN);
	}
}

// vim: ts=4
