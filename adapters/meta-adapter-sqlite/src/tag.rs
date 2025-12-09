//! File tagging system
//!
//! Manages tags associated with files for organization and categorization.

use std::collections::HashMap;

use sqlx::{Row, SqlitePool};

use cloudillo::prelude::*;

/// List all tags with optional prefix filtering and counts
///
/// When `with_counts` is true, counts are calculated by iterating through all files
/// and counting occurrences of each tag in the comma-separated tags column.
pub(crate) async fn list(
	db: &SqlitePool,
	tn_id: TnId,
	prefix: Option<&str>,
	with_counts: bool,
	limit: Option<u32>,
) -> ClResult<Vec<TagInfo>> {
	if with_counts {
		// Get all files with tags to count occurrences
		let rows = sqlx::query(
			"SELECT tags FROM files WHERE tn_id = ? AND tags IS NOT NULL AND tags != ''",
		)
		.bind(tn_id.0)
		.fetch_all(db)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

		// Count tag occurrences
		let mut tag_counts: HashMap<String, u32> = HashMap::new();
		for row in &rows {
			let tags_str: String = row.get("tags");
			for tag in tags_str.split(',') {
				let tag = tag.trim();
				if !tag.is_empty() {
					// Apply prefix filter if specified
					if let Some(p) = prefix {
						if !tag.starts_with(p) {
							continue;
						}
					}
					*tag_counts.entry(tag.to_string()).or_insert(0) += 1;
				}
			}
		}

		// Convert to Vec and sort by count (descending), then by tag name
		let mut tags: Vec<TagInfo> = tag_counts
			.into_iter()
			.map(|(tag, count)| TagInfo { tag, count: Some(count) })
			.collect();

		tags.sort_by(|a, b| {
			b.count.unwrap_or(0).cmp(&a.count.unwrap_or(0)).then_with(|| a.tag.cmp(&b.tag))
		});

		// Apply limit
		if let Some(lim) = limit {
			tags.truncate(lim as usize);
		}

		Ok(tags)
	} else {
		// Original behavior: just return tag names without counts
		let rows = if let Some(p) = prefix {
			sqlx::query(
				"SELECT DISTINCT tag FROM tags WHERE tn_id = ? AND tag LIKE ? || '%' ORDER BY tag",
			)
			.bind(tn_id.0)
			.bind(p)
			.fetch_all(db)
			.await
			.inspect_err(|err| warn!("DB: {:#?}", err))
			.map_err(|_| Error::DbError)?
		} else {
			sqlx::query("SELECT DISTINCT tag FROM tags WHERE tn_id = ? ORDER BY tag")
				.bind(tn_id.0)
				.fetch_all(db)
				.await
				.inspect_err(|err| warn!("DB: {:#?}", err))
				.map_err(|_| Error::DbError)?
		};

		let mut tags: Vec<TagInfo> = rows
			.iter()
			.map(|row| {
				let tag: String = row.get("tag");
				TagInfo { tag, count: None }
			})
			.collect();

		// Apply limit
		if let Some(lim) = limit {
			tags.truncate(lim as usize);
		}

		Ok(tags)
	}
}

/// Add a tag to a file
pub(crate) async fn add(
	db: &SqlitePool,
	tn_id: TnId,
	file_id: &str,
	tag: &str,
) -> ClResult<Vec<String>> {
	// Fetch current tags
	let row = sqlx::query("SELECT tags FROM files WHERE tn_id = ? AND file_id = ?")
		.bind(tn_id.0)
		.bind(file_id)
		.fetch_optional(db)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	if row.is_none() {
		return Err(Error::NotFound);
	}

	let row = row.unwrap();
	let tags_str: Option<String> = row.get("tags");
	let mut tags: Vec<String> = tags_str
		.map(|s| s.split(',').map(|t| t.to_string()).collect())
		.unwrap_or_default();

	// Add tag if not already present
	if !tags.contains(&tag.to_string()) {
		tags.push(tag.to_string());
	}

	// Update file tags
	let tags_str = tags.join(",");
	sqlx::query("UPDATE files SET tags = ? WHERE tn_id = ? AND file_id = ?")
		.bind(&tags_str)
		.bind(tn_id.0)
		.bind(file_id)
		.execute(db)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	// Ensure tag exists in global tags table
	sqlx::query("INSERT OR IGNORE INTO tags (tn_id, tag) VALUES (?, ?)")
		.bind(tn_id.0)
		.bind(tag)
		.execute(db)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	Ok(tags)
}

/// Remove a tag from a file
pub(crate) async fn remove(
	db: &SqlitePool,
	tn_id: TnId,
	file_id: &str,
	tag: &str,
) -> ClResult<Vec<String>> {
	// Fetch current tags
	let row = sqlx::query("SELECT tags FROM files WHERE tn_id = ? AND file_id = ?")
		.bind(tn_id.0)
		.bind(file_id)
		.fetch_optional(db)
		.await
		.inspect_err(|err| warn!("DB: {:#?}", err))
		.map_err(|_| Error::DbError)?;

	if row.is_none() {
		return Err(Error::NotFound);
	}

	let row = row.unwrap();
	let tags_str: Option<String> = row.get("tags");
	let mut tags: Vec<String> = tags_str
		.map(|s| s.split(',').map(|t| t.to_string()).collect())
		.unwrap_or_default();

	// Remove tag
	tags.retain(|t| t != tag);

	// Update file tags (or set to NULL if empty)
	if tags.is_empty() {
		sqlx::query("UPDATE files SET tags = NULL WHERE tn_id = ? AND file_id = ?")
			.bind(tn_id.0)
			.bind(file_id)
			.execute(db)
			.await
			.inspect_err(|err| warn!("DB: {:#?}", err))
			.map_err(|_| Error::DbError)?;
	} else {
		let tags_str = tags.join(",");
		sqlx::query("UPDATE files SET tags = ? WHERE tn_id = ? AND file_id = ?")
			.bind(&tags_str)
			.bind(tn_id.0)
			.bind(file_id)
			.execute(db)
			.await
			.inspect_err(|err| warn!("DB: {:#?}", err))
			.map_err(|_| Error::DbError)?;
	}

	Ok(tags)
}
