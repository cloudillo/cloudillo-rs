//! File descriptor generation and parsing.
//!
//! Supports two descriptor formats:
//! - d1~ (legacy): variant separator is `,`, ID separator is `~`
//! - d2, (new): variant separator is `;`, ID separator is `,`
//!
//! Format examples:
//! d1~tn:b1~abc123:f=webp:s=2048:r=128x128,sd:b1~def456:f=webp:s=10240:r=720x720
//! d2,vis.tn:b1,abc123:f=webp:s=2048:r=128x128;vis.sd:b1,def456:f=webp:s=10240:r=720x720:dur=120.5:br=5000

use async_trait::async_trait;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, sync::Arc};

use crate::core::{
	hasher::Hasher,
	scheduler::{Task, TaskId},
};
use crate::file::handler::GetFileVariantSelector;
use crate::file::variant::{Variant, VariantClass};
use crate::meta_adapter;
use crate::prelude::*;
use crate::types::TnId;

/// Descriptor format version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorVersion {
	/// Legacy format: d1~, variant separator `,`, ID separator `~`
	V1,
	/// New format: d2,, variant separator `;`, ID separator `,`
	V2,
}

impl DescriptorVersion {
	/// Get the prefix for this version
	pub fn prefix(&self) -> &'static str {
		match self {
			Self::V1 => "d1~",
			Self::V2 => "d2,",
		}
	}

	/// Get the variant separator for this version
	pub fn variant_separator(&self) -> char {
		match self {
			Self::V1 => ',',
			Self::V2 => ';',
		}
	}

	/// Get the ID separator for this version (prefix~hash or prefix,hash)
	pub fn id_separator(&self) -> char {
		match self {
			Self::V1 => '~',
			Self::V2 => ',',
		}
	}
}

/// Generate file descriptor in the new d2 format
pub fn get_file_descriptor<S: AsRef<str> + Debug + Eq>(
	variants: &[meta_adapter::FileVariant<S>],
) -> String {
	get_file_descriptor_versioned(variants, DescriptorVersion::V2)
}

/// Generate file descriptor with explicit version
pub fn get_file_descriptor_versioned<S: AsRef<str> + Debug + Eq>(
	variants: &[meta_adapter::FileVariant<S>],
	version: DescriptorVersion,
) -> String {
	let sep = version.variant_separator();
	let id_sep = version.id_separator();

	// Note: variant_id keeps its original format (b1~hash) - we don't change the ~ separator
	// The d2, prefix differentiates descriptors from hashed IDs
	let _ = id_sep; // Unused but kept for API consistency

	version.prefix().to_owned()
		+ &variants
			.iter()
			.map(|v| {
				let mut parts = format!(
					"{}:{}:f={}:s={}:r={}x{}",
					v.variant.as_ref(),
					v.variant_id.as_ref(),
					v.format.as_ref(),
					v.size,
					v.resolution.0,
					v.resolution.1
				);

				// Add optional properties
				if let Some(dur) = v.duration {
					parts.push_str(&format!(":dur={}", dur));
				}
				if let Some(br) = v.bitrate {
					parts.push_str(&format!(":br={}", br));
				}
				if let Some(pg) = v.page_count {
					parts.push_str(&format!(":pg={}", pg));
				}

				parts
			})
			.join(&sep.to_string())
}

/// Parse a single variant entry from descriptor
fn parse_variant_entry(
	entry: &str,
	_id_separator: char,
) -> ClResult<meta_adapter::FileVariant<&str>> {
	let v_vec: Vec<&str> = entry.split(':').collect();
	if v_vec.len() < 2 {
		return Err(Error::Parse);
	}

	let variant = v_vec[0];
	let variant_id = v_vec[1];

	let mut resolution: Option<(u32, u32)> = None;
	let mut format: Option<&str> = Some("avif");
	let mut size: Option<u64> = None;
	let mut duration: Option<f64> = None;
	let mut bitrate: Option<u32> = None;
	let mut page_count: Option<u32> = None;

	for prop in v_vec[2..].iter() {
		if let Some(val) = prop.strip_prefix("f=") {
			format = Some(val);
		} else if let Some(val) = prop.strip_prefix("s=") {
			size = Some(val.parse().map_err(|_| Error::Parse)?);
		} else if let Some(val) = prop.strip_prefix("r=") {
			let res_str: (&str, &str) = val.split('x').collect_tuple().ok_or(Error::Parse)?;
			resolution = Some((res_str.0.parse()?, res_str.1.parse()?));
		} else if let Some(val) = prop.strip_prefix("dur=") {
			duration = Some(val.parse().map_err(|_| Error::Parse)?);
		} else if let Some(val) = prop.strip_prefix("br=") {
			bitrate = Some(val.parse().map_err(|_| Error::Parse)?);
		} else if let Some(val) = prop.strip_prefix("pg=") {
			page_count = Some(val.parse().map_err(|_| Error::Parse)?);
		}
		// Ignore unknown properties for forward compatibility
	}

	if let (Some(resolution), Some(format), Some(size)) = (resolution, format, size) {
		Ok(meta_adapter::FileVariant {
			variant,
			variant_id,
			resolution,
			format,
			size,
			available: false,
			duration,
			bitrate,
			page_count,
		})
	} else {
		error!(
			"Invalid variant entry - resolution: {:?}, format: {:?}, size: {:?}",
			resolution, format, size
		);
		Err(Error::Parse)
	}
}

/// Parse file descriptor (supports both d1 and d2 formats)
pub fn parse_file_descriptor(descriptor: &str) -> ClResult<Vec<meta_adapter::FileVariant<&str>>> {
	if let Some(body) = descriptor.strip_prefix("d2,") {
		// New format: d2, with ; variant separator and , ID separator
		body.split(';')
			.filter(|s| !s.is_empty())
			.map(|entry| parse_variant_entry(entry, ','))
			.collect()
	} else if let Some(body) = descriptor.strip_prefix("d1~") {
		// Legacy format: d1~ with , variant separator and ~ ID separator
		body.split(',')
			.filter(|s| !s.is_empty())
			.map(|entry| parse_variant_entry(entry, '~'))
			.collect()
	} else {
		Err(Error::Parse)
	}
}

/// Normalize variant name for comparison
/// Handles both legacy (sd) and new (vis.sd) formats
fn normalize_variant_name(name: &str) -> &str {
	// If it's a two-level name, extract just the quality part for legacy comparison
	if let Some((_class, quality)) = name.split_once('.') {
		quality
	} else {
		name
	}
}

/// Check if a variant matches the requested variant (supports both formats)
fn variant_matches(variant: &str, requested: &str) -> bool {
	// Direct match
	if variant == requested {
		return true;
	}

	// Legacy format match: "sd" matches "vis.sd"
	if let Some(parsed) = Variant::parse(variant) {
		if parsed.quality.as_str() == requested {
			return true;
		}
	}

	// New format match: "vis.sd" matches when requesting "sd"
	if normalize_variant_name(variant) == requested {
		return true;
	}

	false
}

/// Find variant by name in a list (supports both legacy and new formats)
fn find_variant<'a, S: AsRef<str> + Debug>(
	variants: &[&'a meta_adapter::FileVariant<S>],
	name: &str,
) -> Option<&'a meta_adapter::FileVariant<S>> {
	variants.iter().find(|v| variant_matches(v.variant.as_ref(), name)).copied()
}

/// Choose best variant with optional class filter
pub fn get_best_file_variant<'a, S: AsRef<str> + Debug + Eq>(
	variants: &'a [meta_adapter::FileVariant<S>],
	selector: &'_ GetFileVariantSelector,
) -> ClResult<&'a meta_adapter::FileVariant<S>> {
	debug!("get_best_file_variant: {:?}", selector);

	// Parse the requested variant to see if it has a class prefix
	let (requested_class, requested_quality) = if let Some(ref variant_str) = selector.variant {
		if let Some(parsed) = Variant::parse(variant_str) {
			(Some(parsed.class), parsed.quality.as_str())
		} else {
			(None, variant_str.as_str())
		}
	} else {
		(None, "tn") // Default to thumbnail
	};

	// Filter variants by class if specified
	let class_filtered: Vec<_> = if let Some(class) = requested_class {
		variants
			.iter()
			.filter(|v| {
				if let Some(parsed) = Variant::parse(v.variant.as_ref()) {
					parsed.class == class
				} else {
					// Legacy variants are assumed to be Visual
					class == VariantClass::Visual
				}
			})
			.collect()
	} else {
		variants.iter().collect()
	};

	let best = match requested_quality {
		"tn" => find_variant(&class_filtered, "tn")
			.or_else(|| find_variant(&class_filtered, "pf"))
			.ok_or(Error::NotFound),
		"sd" => find_variant(&class_filtered, "sd")
			.or_else(|| find_variant(&class_filtered, "md"))
			.or_else(|| find_variant(&class_filtered, "tn"))
			.or_else(|| find_variant(&class_filtered, "pf"))
			.ok_or(Error::NotFound),
		"md" => find_variant(&class_filtered, "md")
			.or_else(|| find_variant(&class_filtered, "sd"))
			.or_else(|| find_variant(&class_filtered, "tn"))
			.ok_or(Error::NotFound),
		"hd" => find_variant(&class_filtered, "hd")
			.or_else(|| find_variant(&class_filtered, "md"))
			.or_else(|| find_variant(&class_filtered, "sd"))
			.or_else(|| find_variant(&class_filtered, "tn"))
			.ok_or(Error::NotFound),
		"xd" => find_variant(&class_filtered, "xd")
			.or_else(|| find_variant(&class_filtered, "hd"))
			.or_else(|| find_variant(&class_filtered, "md"))
			.or_else(|| find_variant(&class_filtered, "sd"))
			.or_else(|| find_variant(&class_filtered, "tn"))
			.ok_or(Error::NotFound),
		"pf" => find_variant(&class_filtered, "pf")
			.or_else(|| find_variant(&class_filtered, "tn"))
			.ok_or(Error::NotFound),
		"orig" => find_variant(&class_filtered, "orig")
			.or_else(|| find_variant(&class_filtered, "xd"))
			.or_else(|| find_variant(&class_filtered, "hd"))
			.ok_or(Error::NotFound),
		_ => Err(Error::NotFound),
	};

	debug!("best variant: {:?}", best);
	best
}

/// File ID generator Task
#[derive(Debug, Serialize, Deserialize)]
pub struct FileIdGeneratorTask {
	tn_id: TnId,
	f_id: u64,
}

impl FileIdGeneratorTask {
	pub fn new(tn_id: TnId, f_id: u64) -> Arc<Self> {
		Arc::new(Self { tn_id, f_id })
	}
}

#[async_trait]
impl Task<App> for FileIdGeneratorTask {
	fn kind() -> &'static str {
		"file.id-generate"
	}
	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		let (tn_id, f_id) = ctx
			.split(',')
			.collect_tuple()
			.ok_or(Error::Internal("invalid FileIdGenerator context format".into()))?;
		let task = FileIdGeneratorTask::new(TnId(tn_id.parse()?), f_id.parse()?);
		Ok(task)
	}

	fn serialize(&self) -> String {
		format!("{},{}", self.tn_id, self.f_id)
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		info!("Running task file.id-generate {}", self.f_id);
		let mut variants = app
			.meta_adapter
			.list_file_variants(self.tn_id, meta_adapter::FileId::FId(self.f_id))
			.await?;
		variants.sort();
		let descriptor = get_file_descriptor(&variants);

		let mut hasher = Hasher::new();
		hasher.update(descriptor.as_bytes());
		let file_id = hasher.finalize("f");

		// Finalize the file - sets file_id and transitions status from 'P' to 'A' atomically
		app.meta_adapter.finalize_file(self.tn_id, self.f_id, &file_id).await?;

		info!("Finished task file.id-generate {} → {}", descriptor, file_id);
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_parse_d1_descriptor() {
		let desc = "d1~tn:b1~abc123:f=webp:s=2048:r=128x128,sd:b1~def456:f=webp:s=10240:r=720x720";
		let variants = parse_file_descriptor(desc).unwrap();

		assert_eq!(variants.len(), 2);
		assert_eq!(variants[0].variant, "tn");
		assert_eq!(variants[0].variant_id, "b1~abc123");
		assert_eq!(variants[0].format, "webp");
		assert_eq!(variants[0].size, 2048);
		assert_eq!(variants[0].resolution, (128, 128));

		assert_eq!(variants[1].variant, "sd");
		assert_eq!(variants[1].variant_id, "b1~def456");
	}

	#[test]
	fn test_parse_d2_descriptor() {
		// Note: variant_ids keep the ~ separator (b1~hash), only descriptor prefix uses comma (d2,)
		let desc = "d2,vis.tn:b1~abc123:f=webp:s=2048:r=128x128;vis.sd:b1~def456:f=webp:s=10240:r=720x720:dur=120.5:br=5000";
		let variants = parse_file_descriptor(desc).unwrap();

		assert_eq!(variants.len(), 2);
		assert_eq!(variants[0].variant, "vis.tn");
		assert_eq!(variants[0].variant_id, "b1~abc123");
		assert_eq!(variants[0].format, "webp");
		assert_eq!(variants[0].size, 2048);
		assert_eq!(variants[0].resolution, (128, 128));
		assert_eq!(variants[0].duration, None);

		assert_eq!(variants[1].variant, "vis.sd");
		assert_eq!(variants[1].variant_id, "b1~def456");
		assert_eq!(variants[1].duration, Some(120.5));
		assert_eq!(variants[1].bitrate, Some(5000));
	}

	#[test]
	fn test_generate_d2_descriptor() {
		let variants = vec![
			meta_adapter::FileVariant {
				variant: "vis.tn",
				variant_id: "b1~abc123",
				format: "webp",
				size: 2048,
				resolution: (128, 128),
				available: true,
				duration: None,
				bitrate: None,
				page_count: None,
			},
			meta_adapter::FileVariant {
				variant: "vid.hd",
				variant_id: "b1~def456",
				format: "mp4",
				size: 51200,
				resolution: (1920, 1080),
				available: true,
				duration: Some(120.5),
				bitrate: Some(5000),
				page_count: None,
			},
		];

		let desc = get_file_descriptor(&variants);
		assert!(desc.starts_with("d2,"));
		// variant_ids keep their ~ separator
		assert!(desc.contains("vis.tn:b1~abc123"));
		assert!(desc.contains("vid.hd:b1~def456"));
		assert!(desc.contains(":dur=120.5"));
		assert!(desc.contains(":br=5000"));
		// Variants are separated by ;
		assert!(desc.contains(";vid.hd"));
	}

	#[test]
	fn test_variant_matches() {
		// Direct match
		assert!(variant_matches("sd", "sd"));
		assert!(variant_matches("vis.sd", "vis.sd"));

		// Legacy to new format match
		assert!(variant_matches("vis.sd", "sd"));
		assert!(variant_matches("vid.hd", "hd"));

		// No match
		assert!(!variant_matches("vis.sd", "hd"));
		assert!(!variant_matches("sd", "hd"));
	}
}

// vim: ts=4
