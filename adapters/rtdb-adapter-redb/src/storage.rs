// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

use cloudillo_types::error::ClResult;
use cloudillo_types::rtdb_adapter::{ChangeEvent, SubscriptionScope};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

/// Document storage table
pub const TABLE_DOCUMENTS: redb::TableDefinition<&str, &str> = redb::TableDefinition::new("docs");

/// Index storage table
pub const TABLE_INDEXES: redb::TableDefinition<&str, &str> = redb::TableDefinition::new("idxs");

/// Metadata storage table
pub const TABLE_METADATA: redb::TableDefinition<&str, &str> = redb::TableDefinition::new("meta");

/// `meta` key holding the file's schema version. Unprefixed, so shared-file tenant purges
/// (which delete `"{tn}/..."`) keep it.
pub const SCHEMA_VERSION_KEY: &str = "schema_version";

/// File schema version this binary reads and writes (stored as its decimal string)
pub const SCHEMA_VERSION: u32 = 1;

/// Refuse a file written by a newer schema; stamp an unversioned (new or pre-versioning) one.
pub fn ensure_schema_version(
	meta: &mut redb::Table<&str, &str>,
) -> Result<(), crate::error::Error> {
	use crate::error::{Error, from_redb_error};
	use redb::ReadableTable;

	let stored = meta
		.get(SCHEMA_VERSION_KEY)
		.map_err(from_redb_error)?
		.map(|v| v.value().to_string());
	let Some(stored) = stored else {
		meta.insert(SCHEMA_VERSION_KEY, SCHEMA_VERSION.to_string().as_str())
			.map_err(from_redb_error)?;
		return Ok(());
	};
	let msg = match stored.parse::<u32>() {
		Ok(v) if v <= SCHEMA_VERSION => return Ok(()),
		Ok(v) => format!(
			"rtdb redb file schema v{v} is newer than this binary (v{SCHEMA_VERSION}); \
			restore a backup or upgrade"
		),
		Err(_) => format!("rtdb redb file has an unreadable schema_version {stored:?}"),
	};
	tracing::error!("{}", msg);
	Err(Error::StorageError(msg))
}

/// Get current Unix timestamp
pub fn now_timestamp() -> u64 {
	SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Convert a JSON value to a sortable string for indexing
pub fn value_to_string(value: &Value) -> String {
	match value {
		Value::String(s) => s.clone(),
		Value::Number(n) => n.to_string(),
		Value::Bool(b) => b.to_string(),
		Value::Null => "null".to_string(),
		_ => serde_json::to_string(value).unwrap_or_default(),
	}
}

/// Convert a JSON value to index strings, expanding arrays into per-element entries.
///
/// - Arrays: one string per scalar element (nested arrays/objects skipped)
/// - Scalars: single-element Vec
/// - Empty arrays: empty Vec (no phantom entries)
pub fn values_to_index_strings(value: &Value) -> Vec<String> {
	match value {
		Value::Array(arr) => arr
			.iter()
			.filter(|v| !v.is_array() && !v.is_object())
			.map(value_to_string)
			.collect(),
		other => vec![value_to_string(other)],
	}
}

/// Check if an event matches a subscription path (prefix match with boundary check)
pub fn event_matches_path(event: &ChangeEvent, subscription_path: &str) -> bool {
	let event_path = event.path();

	// Exact match
	if event_path == subscription_path {
		return true;
	}

	// Prefix match (event is child of subscription)
	if event_path.starts_with(subscription_path) {
		// Ensure it's a path boundary
		if event_path.as_bytes().get(subscription_path.len()) == Some(&b'/') {
			return true;
		}
	}

	false
}

/// Does this event belong to a subscription on `subscription_path` at `scope`?
///
/// `Children` deliberately excludes an event at the subscription path itself: that is
/// the collection's own document, not one of its documents. `Subtree` keeps the
/// pre-scope behaviour, which included both it and every descendant at any depth.
pub fn event_matches_scope(
	event: &ChangeEvent,
	subscription_path: &str,
	scope: SubscriptionScope,
) -> bool {
	match scope {
		SubscriptionScope::Document => event.path() == subscription_path,
		SubscriptionScope::Children => match event.path().strip_prefix(subscription_path) {
			Some(rest) => rest.starts_with('/') && !rest[1..].contains('/'),
			None => false,
		},
		SubscriptionScope::Subtree => event_matches_path(event, subscription_path),
	}
}

/// Parse path into collection and doc_id
pub fn parse_path(path: &str) -> ClResult<(String, String)> {
	let parts: Vec<&str> = path.rsplitn(2, '/').collect();

	if parts.len() != 2 {
		return Err(crate::Error::InvalidPath(format!("Invalid path: {}", path)).into());
	}

	Ok((parts[1].to_string(), parts[0].to_string()))
}

/// Inject the `id` field into a document if it doesn't already have one.
///
/// Documents are stored without an `id` field (the key is the source of truth),
/// so this must be called at read time to ensure the `id` is present.
pub fn inject_doc_id(doc: &mut Value, doc_id: &str) {
	if let Value::Object(obj) = doc {
		obj.entry("id").or_insert_with(|| Value::String(doc_id.to_string()));
	}
}

/// Generate a random document ID using cloudillo's utility function
pub fn generate_doc_id() -> ClResult<String> {
	cloudillo_types::utils::random_id()
}

// Tests for this module have been moved to tests/storage_tests.rs
// to follow standard test organization patterns.
// See TESTS.md for information about test structure.

// vim: ts=4
