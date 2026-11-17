// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! File processing presets and upload profiles.
//!
//! A *profile* (`orig`, `preview`, `standard`, `high`, `compact`, or a tenant-defined one in
//! the `file.profiles` setting) accepts every media class and says how much processing each
//! class gets. A *purpose preset* (`profile-picture`, `cover`, `thumbnail-only`, `apkg`,
//! `site`) is a fixed system-internal recipe. Both resolve into a [`FilePreset`].

use serde::{Deserialize, Serialize};

use crate::image::ImageFormat;
use crate::prelude::*;
use crate::variant::VariantClass;

/// File processing preset configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePreset {
	/// Preset or profile name (e.g., "standard", "cover")
	pub name: String,
	/// Allowed media classes for upload (e.g., [Visual, Video, Audio])
	pub allowed_media_classes: Vec<VariantClass>,
	/// Image/visual variants to generate (e.g., `["vis.tn", "vis.sd", "vis.md", "vis.hd"]`)
	pub image_variants: Vec<String>,
	/// Video variants to generate (e.g., `["vid.sd", "vid.md", "vid.hd"]`)
	pub video_variants: Vec<String>,
	/// Audio variants to generate (e.g., `["aud.md"]`)
	pub audio_variants: Vec<String>,
	/// Extract audio track from video files
	pub extract_audio: bool,
	/// Generate thumbnail for video/audio/document files
	pub generate_thumbnail: bool,
	/// Maximum variant to generate (caps generation at this level)
	pub max_variant: Option<String>,
	/// Variant to create synchronously for immediate thumbnail response (e.g., "vis.pf" or "vis.tn")
	pub thumbnail_variant: Option<String>,
	/// Store original blob (file_variant record is always created, but blob storage is optional)
	pub store_original: bool,
}

/// Purpose presets (system-internal, not tenant-configurable)
pub mod presets {
	use super::{FilePreset, VariantClass};

	/// Profile picture preset - includes vis.pf variant for small profile thumbnails
	pub fn profile_picture() -> FilePreset {
		FilePreset {
			name: "profile-picture".to_string(),
			allowed_media_classes: vec![VariantClass::Visual],
			image_variants: vec![
				"vis.pf".into(),
				"vis.tn".into(),
				"vis.sd".into(),
				"vis.md".into(),
				"vis.hd".into(),
			],
			video_variants: vec![],
			audio_variants: vec![],
			extract_audio: false,
			generate_thumbnail: false, // vis.pf serves as thumbnail
			max_variant: Some("vis.hd".into()),
			thumbnail_variant: Some("vis.pf".into()),
			store_original: false, // Generated variants are sufficient
		}
	}

	/// Cover image preset - standard image variants without vis.pf
	pub fn cover() -> FilePreset {
		FilePreset {
			name: "cover".to_string(),
			allowed_media_classes: vec![VariantClass::Visual],
			image_variants: vec![
				"vis.tn".into(),
				"vis.sd".into(),
				"vis.md".into(),
				"vis.hd".into(),
			],
			video_variants: vec![],
			audio_variants: vec![],
			extract_audio: false,
			generate_thumbnail: false, // vis.tn serves as thumbnail
			max_variant: Some("vis.hd".into()),
			thumbnail_variant: Some("vis.tn".into()),
			store_original: false, // Generated variants are sufficient
		}
	}

	/// Thumbnail-only preset - generate only a thumbnail, don't store original
	pub fn thumbnail_only() -> FilePreset {
		FilePreset {
			name: "thumbnail-only".to_string(),
			allowed_media_classes: vec![VariantClass::Visual],
			image_variants: vec![],
			video_variants: vec![],
			audio_variants: vec![],
			extract_audio: false,
			generate_thumbnail: true,
			max_variant: None,
			thumbnail_variant: Some("vis.tn".into()),
			store_original: false,
		}
	}

	/// App package preset - stores zip package as-is, extracts icon as vis.pf
	pub fn apkg() -> FilePreset {
		FilePreset {
			name: "apkg".to_string(),
			allowed_media_classes: vec![VariantClass::Raw],
			image_variants: vec!["vis.pf".into()],
			video_variants: vec![],
			audio_variants: vec![],
			extract_audio: false,
			generate_thumbnail: false,
			max_variant: None,
			thumbnail_variant: Some("vis.pf".into()),
			store_original: true,
		}
	}

	/// Site container preset - stores the published zip as-is, nothing derived
	///
	/// Modelled on [`apkg`], minus the icon: there is no image to extract.
	/// `store_original` is the whole preset — the zip is read back entry-by-entry through
	/// the container index, so any re-encoding would break the stored offsets.
	///
	/// Stored as-is, but not unchecked: every HTML entry is walked by
	/// [`crate::site_html::validate_site_container`] first, and a fragment outside the
	/// allowlist fails the whole upload. Validating rather than rewriting keeps "as-is"
	/// true.
	pub fn site() -> FilePreset {
		FilePreset {
			name: "site".to_string(),
			allowed_media_classes: vec![VariantClass::Raw],
			image_variants: vec![],
			video_variants: vec![],
			audio_variants: vec![],
			extract_audio: false,
			generate_thumbnail: false,
			max_variant: None,
			thumbnail_variant: None,
			store_original: true,
		}
	}

	/// Get purpose preset by name
	pub fn get(name: &str) -> Option<FilePreset> {
		match name {
			"profile-picture" => Some(profile_picture()),
			"cover" => Some(cover()),
			"thumbnail-only" => Some(thumbnail_only()),
			"apkg" => Some(apkg()),
			"site" => Some(site()),
			_ => None,
		}
	}
}

/// Upload profile: how much processing each media class gets.
///
/// Levels are bare tier names (`"hd"`), `None` = no variants for that class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
	/// Store the original blob
	pub orig: bool,
	/// Visual level: tn, sd, md, hd, xd
	pub vis: Option<String>,
	/// Video level: sd, md, hd, xd
	pub vid: Option<String>,
	/// Audio level: sd, md, hd
	pub aud: Option<String>,
	/// Generate a `vis.tn` thumbnail
	pub thumb: bool,
	/// Extract the audio track from video
	pub extract_audio: bool,
}

/// Visual level ladder, lowest first
pub const VIS_LADDER: &[&str] = &["tn", "sd", "md", "hd", "xd"];
/// Video level ladder, lowest first
pub const VID_LADDER: &[&str] = &["sd", "md", "hd", "xd"];
/// Audio level ladder, lowest first
pub const AUD_LADDER: &[&str] = &["sd", "md", "hd"];

/// Profile name stored for federated sync mirrors; never a valid profile name.
pub const RESERVED_SYNC: &str = "sync";

/// Fallback profile for stored names that no longer resolve
pub const DEFAULT_PROFILE: &str = "standard";

fn profile(orig: bool, vis: Option<&str>, vid: Option<&str>, aud: Option<&str>) -> Profile {
	Profile {
		orig,
		vis: vis.map(String::from),
		vid: vid.map(String::from),
		aud: aud.map(String::from),
		thumb: vis.is_some(),
		extract_audio: false,
	}
}

/// Built-in profiles (code defaults; tenants override them field-wise in `file.profiles`)
pub fn builtin_profiles() -> [(&'static str, Profile); 5] {
	[
		("orig", profile(true, None, None, None)),
		("preview", profile(true, Some("tn"), None, None)),
		("standard", standard_profile()),
		("high", profile(true, Some("xd"), Some("xd"), Some("hd"))),
		("compact", profile(false, Some("md"), Some("md"), Some("sd"))),
	]
}

fn builtin_profile(name: &str) -> Option<Profile> {
	builtin_profiles().into_iter().find(|(n, _)| *n == name).map(|(_, p)| p)
}

fn standard_profile() -> Profile {
	profile(true, Some("hd"), Some("hd"), Some("md"))
}

/// Expand a level into the variant list for its class.
///
/// vis/vid: every rung up to the level. aud: from `md` upward, `sd` only when the level is `sd`.
fn expand(class: &str, ladder: &[&str], level: Option<&str>) -> Vec<String> {
	let Some(idx) = level.and_then(|l| ladder.iter().position(|r| *r == l)) else {
		return Vec::new();
	};
	let start = usize::from(class == "aud" && idx > 0);
	let rungs = if class == "aud" && idx == 0 { &ladder[..1] } else { &ladder[start..=idx] };
	rungs.iter().map(|r| format!("{class}.{r}")).collect()
}

/// Turn a profile into the runtime processing descriptor
pub fn profile_to_preset(name: &str, p: &Profile) -> FilePreset {
	FilePreset {
		name: name.to_string(),
		allowed_media_classes: vec![
			VariantClass::Visual,
			VariantClass::Video,
			VariantClass::Audio,
			VariantClass::Document,
			VariantClass::Raw,
		],
		image_variants: expand("vis", VIS_LADDER, p.vis.as_deref()),
		video_variants: expand("vid", VID_LADDER, p.vid.as_deref()),
		audio_variants: expand("aud", AUD_LADDER, p.aud.as_deref()),
		extract_audio: p.extract_audio,
		generate_thumbnail: p.thumb,
		max_variant: p.vid.as_deref().map(|l| format!("vid.{l}")),
		thumbnail_variant: p.thumb.then(|| "vis.tn".to_string()),
		store_original: p.orig,
	}
}

/// Syntax of a profile name: lowercase, digits, `-`; 1-32 bytes. Also checks names of profiles
/// that live on another tenant (`rfile:` keys).
pub fn check_name_syntax(name: &str) -> ClResult<()> {
	let valid_chars =
		name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
	if name.is_empty() || name.len() > 32 || !valid_chars {
		return Err(Error::ValidationError(format!("invalid profile name '{name}'")));
	}
	Ok(())
}

fn check_name(name: &str) -> ClResult<()> {
	check_name_syntax(name)?;
	if name == RESERVED_SYNC || presets::get(name).is_some() {
		return Err(Error::ValidationError(format!("profile name '{name}' is reserved")));
	}
	Ok(())
}

fn check_level(name: &str, class: &str, ladder: &[&str], level: Option<&str>) -> ClResult<()> {
	match level {
		Some(l) if !ladder.contains(&l) => {
			Err(Error::ValidationError(format!("profile '{name}': unknown {class} level '{l}'")))
		}
		_ => Ok(()),
	}
}

/// Parse one `file.profiles` entry, merged field-wise over the built-in of the same name
/// (or over `standard` for a custom name).
fn parse_profile(name: &str, entry: &serde_json::Value) -> ClResult<Profile> {
	check_name(name)?;
	let Some(fields) = entry.as_object() else {
		return Err(Error::ValidationError(format!("profile '{name}' must be an object")));
	};
	let base = builtin_profile(name).unwrap_or_else(standard_profile);
	let mut merged = serde_json::to_value(base)
		.map_err(|e| Error::ValidationError(format!("profile '{name}': {e}")))?;
	if let Some(obj) = merged.as_object_mut() {
		obj.extend(fields.clone());
	}
	let p: Profile = serde_json::from_value(merged)
		.map_err(|e| Error::ValidationError(format!("profile '{name}': {e}")))?;
	check_level(name, "vis", VIS_LADDER, p.vis.as_deref())?;
	check_level(name, "vid", VID_LADDER, p.vid.as_deref())?;
	check_level(name, "aud", AUD_LADDER, p.aud.as_deref())?;
	Ok(p)
}

/// Validate a whole `file.profiles` value (the settings validator)
pub fn validate_profiles(value: &serde_json::Value) -> ClResult<()> {
	let Some(map) = value.as_object() else {
		return Err(Error::ValidationError("file.profiles must be an object".into()));
	};
	for (name, entry) in map {
		parse_profile(name, entry)?;
	}
	Ok(())
}

/// Find a profile by name: tenant entry merged over its base, else the built-in.
fn find_profile(overrides: &serde_json::Value, name: &str) -> ClResult<Option<Profile>> {
	match overrides.get(name) {
		Some(entry) => parse_profile(name, entry).map(Some),
		None => Ok(builtin_profile(name)),
	}
}

/// Resolve a preset or profile name for an upload.
///
/// Purpose preset → profile (tenant `file.profiles` merged over built-in, or custom) →
/// `InvalidField` (400).
pub async fn resolve(app: &App, tn_id: TnId, name: &str) -> ClResult<FilePreset> {
	if let Some(p) = presets::get(name) {
		return Ok(p);
	}
	let overrides = app.settings.get_json(tn_id, "file.profiles").await?;
	match find_profile(&overrides, name)? {
		Some(p) => Ok(profile_to_preset(name, &p)),
		None => Err(Error::InvalidField {
			field: "preset",
			message: "unknown preset or profile".into(),
		}),
	}
}

/// Resolve a stored name (which may have been deleted since); falls back to `standard`.
pub async fn resolve_stored(app: &App, tn_id: TnId, name: Option<&str>) -> FilePreset {
	if let Some(n) = name
		&& let Ok(p) = resolve(app, tn_id, n).await
	{
		return p;
	}
	profile_to_preset(DEFAULT_PROFILE, &standard_profile())
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
	/// Optional format override (None = use setting, Some = override)
	pub format: Option<ImageFormat>,
}

/// Video quality tiers: sd=720p, md=1280p, hd=1080p, xd=4K. Bitrates in kbps.
pub const VIDEO_TIERS: &[VideoQualityTier] = &[
	VideoQualityTier { name: "vid.sd", max_dim: 720, bitrate: 1500 },
	VideoQualityTier { name: "vid.md", max_dim: 1280, bitrate: 3000 },
	VideoQualityTier { name: "vid.hd", max_dim: 1920, bitrate: 5000 },
	VideoQualityTier { name: "vid.xd", max_dim: 3840, bitrate: 15000 },
];

/// Audio quality tiers: sd=64kbps, md=128kbps, hd=256kbps.
pub const AUDIO_TIERS: &[AudioQualityTier] = &[
	AudioQualityTier { name: "aud.sd", bitrate: 64 },
	AudioQualityTier { name: "aud.md", bitrate: 128 },
	AudioQualityTier { name: "aud.hd", bitrate: 256 },
];

/// Image quality tiers: pf=80px profile icon (always AVIF), tn=256px thumbnail,
/// sd/md/hd/xd scale from 720px to 4K. Format follows settings unless overridden.
pub const IMAGE_TIERS: &[ImageQualityTier] = &[
	ImageQualityTier { name: "vis.pf", max_dim: 80, format: Some(ImageFormat::Avif) },
	ImageQualityTier { name: "vis.tn", max_dim: 256, format: None },
	ImageQualityTier { name: "vis.sd", max_dim: 720, format: None },
	ImageQualityTier { name: "vis.md", max_dim: 1280, format: None },
	ImageQualityTier { name: "vis.hd", max_dim: 1920, format: None },
	ImageQualityTier { name: "vis.xd", max_dim: 3840, format: None },
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
	use serde_json::json;

	fn builtin(name: &str) -> FilePreset {
		profile_to_preset(name, &find_profile(&json!({}), name).unwrap().unwrap())
	}

	fn v(items: &[&str]) -> Vec<String> {
		items.iter().map(|s| (*s).to_string()).collect()
	}

	#[test]
	fn test_every_builtin_resolves() {
		for (name, _) in builtin_profiles() {
			let p = builtin(name);
			assert_eq!(p.name, name);
			assert_eq!(p.allowed_media_classes.len(), 5);
			assert!(p.allowed_media_classes.contains(&VariantClass::Raw));
		}
	}

	#[test]
	fn test_standard_equals_old_file_preset() {
		let p = builtin("standard");
		assert_eq!(p.image_variants, v(&["vis.tn", "vis.sd", "vis.md", "vis.hd"]));
		assert_eq!(p.video_variants, v(&["vid.sd", "vid.md", "vid.hd"]));
		assert_eq!(p.audio_variants, v(&["aud.md"]));
		assert_eq!(p.max_variant.as_deref(), Some("vid.hd"));
		assert_eq!(p.thumbnail_variant.as_deref(), Some("vis.tn"));
		assert!(p.generate_thumbnail);
		assert!(p.store_original);
		assert!(!p.extract_audio);
	}

	#[test]
	fn test_high_and_compact_audio() {
		assert_eq!(builtin("high").audio_variants, v(&["aud.md", "aud.hd"]));
		let compact = builtin("compact");
		assert_eq!(compact.audio_variants, v(&["aud.sd"]));
		assert!(!compact.store_original);
	}

	#[test]
	fn test_orig_and_preview() {
		let orig = builtin("orig");
		assert!(orig.image_variants.is_empty() && orig.video_variants.is_empty());
		assert!(orig.audio_variants.is_empty());
		assert!(orig.thumbnail_variant.is_none() && !orig.generate_thumbnail);
		assert!(orig.max_variant.is_none() && orig.store_original);
		let preview = builtin("preview");
		assert_eq!(preview.image_variants, v(&["vis.tn"]));
		assert!(preview.max_variant.is_none() && preview.generate_thumbnail);
	}

	#[test]
	fn test_merge_override() {
		let overrides = json!({
			"standard": { "vis": "xd", "aud": null },
			"podcast": { "extractAudio": true },
		});
		let p = find_profile(&overrides, "standard").unwrap().unwrap();
		assert_eq!(p.vis.as_deref(), Some("xd"));
		assert_eq!(p.vid.as_deref(), Some("hd"));
		assert!(p.aud.is_none());
		let custom = find_profile(&overrides, "podcast").unwrap().unwrap();
		assert!(custom.extract_audio);
		assert_eq!(custom.vid.as_deref(), Some("hd"));
		assert!(validate_profiles(&overrides).is_ok());
		assert!(find_profile(&overrides, "nonexistent").unwrap().is_none());
	}

	#[test]
	fn test_validator_rejects() {
		assert!(validate_profiles(&json!({ "sync": {} })).is_err());
		assert!(validate_profiles(&json!({ "cover": {} })).is_err());
		assert!(validate_profiles(&json!({ "Bad_Name": {} })).is_err());
		assert!(check_name(&"a".repeat(33)).is_err());
		assert!(validate_profiles(&json!({ "x": { "vid": "tn" } })).is_err());
		assert!(validate_profiles(&json!({ "x": { "aud": "xd" } })).is_err());
		assert!(validate_profiles(&json!({ "x": 1 })).is_err());
		assert!(validate_profiles(&json!([])).is_err());
		// Unknown fields are tolerated (compat W1/A1).
		assert!(validate_profiles(&json!({ "x": { "bogus": true } })).is_ok());
		assert!(validate_profiles(&json!({})).is_ok());
	}

	#[test]
	fn test_purpose_presets() {
		assert!(presets::get("cover").is_some());
		assert!(presets::get("standard").is_none());
		assert!(presets::get("default").is_none());
		assert!(builtin_profile("sync").is_none());
	}

	/// `resolve` needs an `App`; this replays its lookup order without one.
	#[test]
	fn test_unknown_and_sync_unresolvable() {
		for name in ["bogus", "sync", "default", "orig-only"] {
			assert!(presets::get(name).is_none(), "{name}");
			assert!(matches!(find_profile(&json!({}), name), Ok(None)), "{name}");
		}
		assert!(find_profile(&json!({ "sync": {} }), "sync").is_err());
	}

	#[test]
	fn test_thumbnail_only_preset() {
		let preset = presets::thumbnail_only();
		assert_eq!(preset.name, "thumbnail-only");
		assert!(preset.image_variants.is_empty());
		assert!(!preset.store_original);
		assert_eq!(preset.thumbnail_variant.as_deref(), Some("vis.tn"));
		assert!(preset.generate_thumbnail);
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
