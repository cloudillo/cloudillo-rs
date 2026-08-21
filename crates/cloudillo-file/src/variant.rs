// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

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
	pub fn as_str(self) -> &'static str {
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

	/// Whether receivers should fetch the `orig` blob bytes when syncing a
	/// file of this class.
	///
	/// Media classes (Visual / Video / Audio) keep `orig` as metadata-only on
	/// receivers: the original is large, may not even be stored at the source
	/// (`file.store_original_*` defaults to false), and the generated variants
	/// (`tn`/`sd`/`md`/`hd`/`xd`) are what gets distributed.
	///
	/// Non-media classes carry their payload in `orig`, so receivers must
	/// fetch it (Document = PDF, Raw = unprocessed binary).
	///
	/// Default is "sync orig"; media classes opt out. New classes added in
	/// the future inherit the default unless they explicitly opt out here.
	pub fn sync_orig(self) -> bool {
		match self {
			Self::Visual | Self::Video | Self::Audio => false,
			Self::Document | Self::Raw => true,
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
	pub fn as_str(self) -> &'static str {
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
	if let Some(v) = Variant::parse(s) { Some(v.quality) } else { VariantQuality::from_str_opt(s) }
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
		assert_eq!(Variant::parse("vis.sd").unwrap().to_string(), "vis.sd");
		assert_eq!(Variant::parse("vid.hd").unwrap().to_string(), "vid.hd");
		assert_eq!(Variant::parse("aud.md").unwrap().to_string(), "aud.md");
		// Original variants always display as just "orig" regardless of class
		assert_eq!(Variant::parse("orig").unwrap().to_string(), "orig");
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
		let vis_orig = Variant { class: VariantClass::Visual, quality: VariantQuality::Original };
		assert_eq!(vis_orig.to_string(), "orig");
	}
}

// vim: ts=4
