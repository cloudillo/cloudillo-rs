//! File management and variant handling

use sqlx::{Row, SqlitePool};

use crate::utils::*;
use cloudillo::meta_adapter::*;
use cloudillo::prelude::*;

/// Get file_id by numeric f_id
pub(crate) async fn get_id(db: &SqlitePool, tn_id: TnId, f_id: u64) -> ClResult<Box<str>> {
	let res = sqlx::query("SELECT file_id FROM files WHERE tn_id=? AND f_id=?")
		.bind(tn_id.0)
		.bind(f_id as i64)
		.fetch_one(db)
		.await;

	map_res(res, |row| row.try_get("file_id"))
}

/// List files with filtering and pagination
pub(crate) async fn list(
	db: &SqlitePool,
	tn_id: TnId,
	opts: &ListFileOptions,
) -> ClResult<Vec<FileView>> {
	// Check if we need user-specific data (JOIN with file_user_data)
	let has_user = opts.user_id_tag.is_some();
	let needs_user_join = has_user
		&& (opts.pinned.is_some()
			|| opts.starred.is_some()
			|| matches!(opts.sort.as_deref(), Some("recent" | "modified")));

	let mut query = sqlx::QueryBuilder::new(
		"SELECT f.f_id, f.file_id, f.parent_id, f.file_name, f.file_tp, f.created_at, f.accessed_at, f.modified_at, f.status, f.tags, f.owner_tag, f.preset, f.content_type, f.visibility, f.x,
		        COALESCE(p.id_tag, f.owner_tag) as id_tag, COALESCE(p.name, f.owner_tag) as name, p.type, p.profile_pic",
	);

	// Add user data columns if user is authenticated
	if has_user {
		query.push(", fud.accessed_at as fud_accessed_at, fud.modified_at as fud_modified_at, fud.pinned as fud_pinned, fud.starred as fud_starred");
	}

	query.push(
		" FROM files f
		 LEFT JOIN profiles p ON p.tn_id=f.tn_id AND p.id_tag=f.owner_tag",
	);

	// Add file_user_data JOIN if needed for filtering/sorting or to include user data
	if has_user {
		if needs_user_join && (opts.pinned == Some(true) || opts.starred == Some(true)) {
			// INNER JOIN when filtering by pinned/starred (must have the data)
			query.push(" INNER JOIN file_user_data fud ON fud.tn_id=f.tn_id AND fud.f_id=f.f_id AND fud.id_tag=");
		} else {
			// LEFT JOIN to include user data when available
			query.push(" LEFT JOIN file_user_data fud ON fud.tn_id=f.tn_id AND fud.f_id=f.f_id AND fud.id_tag=");
		}
		query.push_bind(opts.user_id_tag.as_deref().unwrap_or(""));
	}

	query.push(" WHERE f.tn_id=");
	query.push_bind(tn_id.0);

	if let Some(file_id) = &opts.file_id {
		query.push(" AND f.file_id=").push_bind(file_id.as_str());
	}

	// Filter by parent folder
	if let Some(parent_id) = &opts.parent_id {
		if parent_id == "__root__" {
			// Explicit root: files with no parent (not in any folder, not in trash)
			query.push(" AND f.parent_id IS NULL");
		} else {
			// Specific folder (including "__trash__" for trash contents)
			query.push(" AND f.parent_id=").push_bind(parent_id.as_str());
		}
	}
	// Note: If parent_id is not specified, return all files (for search, etc.)

	if let Some(tag) = &opts.tag {
		query.push(" AND f.tags LIKE ").push_bind(format!("%{}%", tag));
	}

	if let Some(preset) = &opts.preset {
		query.push(" AND f.preset=").push_bind(preset.as_str());
	}

	if let Some(file_type) = &opts.file_type {
		// Support comma-separated multiple types (e.g., "CRDT,RTDB")
		let types: Vec<&str> = file_type.split(',').map(|s| s.trim()).collect();
		if types.len() == 1 {
			query.push(" AND f.file_tp=").push_bind(types[0]);
		} else {
			query.push(" AND f.file_tp IN (");
			let mut separated = query.separated(", ");
			for t in types {
				separated.push_bind(t);
			}
			separated.push_unseparated(")");
		}
	}

	// Filter by content type (MIME type pattern, e.g., "image/*" or "image/*,video/*")
	if let Some(content_type) = &opts.content_type {
		let patterns: Vec<&str> = content_type.split(',').map(|s| s.trim()).collect();
		if patterns.len() == 1 {
			// Convert wildcard pattern to SQL LIKE pattern (e.g., "image/*" -> "image/%")
			let pattern = patterns[0].replace('*', "%");
			query.push(" AND f.content_type LIKE ").push_bind(pattern);
		} else {
			// Multiple patterns - use OR conditions
			query.push(" AND (");
			for (i, p) in patterns.iter().enumerate() {
				if i > 0 {
					query.push(" OR ");
				}
				let pattern = p.replace('*', "%");
				query.push("f.content_type LIKE ").push_bind(pattern);
			}
			query.push(")");
		}
	}

	// Filter by status - if no status specified, exclude deleted files by default
	if let Some(status) = opts.status {
		let status_char = match status {
			FileStatus::Active => "A",
			FileStatus::Pending => "P",
			FileStatus::Deleted => "D",
		};
		query.push(" AND f.status=").push_bind(status_char);
	} else {
		// By default, exclude deleted files
		query.push(" AND f.status != 'D'");
	}

	// Filter by pinned/starred (user-specific)
	if opts.pinned == Some(true) {
		query.push(" AND fud.pinned = 1");
	}
	if opts.starred == Some(true) {
		query.push(" AND fud.starred = 1");
	}

	// Determine sort order
	let sort_field = opts.sort.as_deref().unwrap_or("created");
	let sort_dir = match opts.sort_dir.as_deref() {
		Some("asc") => "ASC",
		Some("desc") => "DESC",
		_ => match sort_field {
			"name" => "ASC",
			_ => "DESC", // Default DESC for date-based sorts
		},
	};
	let is_desc = sort_dir == "DESC";

	// Parse cursor for keyset pagination
	if let Some(cursor_str) = &opts.cursor {
		if let Some(cursor) = cloudillo::types::CursorData::decode(cursor_str) {
			// Look up internal f_id from cursor's external file_id
			let cursor_f_id: Option<i64> =
				sqlx::query_scalar("SELECT f_id FROM files WHERE tn_id=? AND file_id=?")
					.bind(tn_id.0)
					.bind(&cursor.id)
					.fetch_optional(db)
					.await
					.ok()
					.flatten();

			if let Some(cursor_f_id) = cursor_f_id {
				// Add keyset pagination WHERE clause based on sort field
				// For DESC: (sort_field, f_id) < (cursor_value, cursor_f_id)
				// For ASC: (sort_field, f_id) > (cursor_value, cursor_f_id)
				// Note: push_bind() adds bind placeholders, don't use ? in push() strings
				let comparison = if is_desc { "<" } else { ">" };

				match sort_field {
					"recent" if has_user => {
						if let Some(ts) = cursor.timestamp() {
							query.push(format!(
								" AND ((fud.accessed_at IS NULL AND f.f_id {} ",
								comparison
							));
							query.push_bind(cursor_f_id);
							query.push(format!(
								") OR (fud.accessed_at IS NOT NULL AND (fud.accessed_at, f.f_id) {} (",
								comparison
							));
							query.push_bind(ts);
							query.push(", ");
							query.push_bind(cursor_f_id);
							query.push(")))");
						}
					}
					"modified" if has_user => {
						if let Some(ts) = cursor.timestamp() {
							query.push(format!(
								" AND ((fud.modified_at IS NULL AND f.f_id {} ",
								comparison
							));
							query.push_bind(cursor_f_id);
							query.push(format!(
								") OR (fud.modified_at IS NOT NULL AND (fud.modified_at, f.f_id) {} (",
								comparison
							));
							query.push_bind(ts);
							query.push(", ");
							query.push_bind(cursor_f_id);
							query.push(")))");
						}
					}
					"name" => {
						if let Some(name) = cursor.string_value() {
							query.push(format!(" AND (f.file_name, f.f_id) {} (", comparison));
							query.push_bind(name.to_string());
							query.push(", ");
							query.push_bind(cursor_f_id);
							query.push(")");
						}
					}
					_ => {
						// "created" or default
						if let Some(ts) = cursor.timestamp() {
							query.push(format!(" AND (f.created_at, f.f_id) {} (", comparison));
							query.push_bind(ts);
							query.push(", ");
							query.push_bind(cursor_f_id);
							query.push(")");
						}
					}
				}
			}
		}
	}

	match sort_field {
		"recent" if has_user => {
			// Sort by user's access time (NULLs last for DESC, NULLs first for ASC)
			query.push(format!(
				" ORDER BY CASE WHEN fud.accessed_at IS NULL THEN {} ELSE {} END, fud.accessed_at {}, f.f_id {}",
				if is_desc { 1 } else { 0 },
				if is_desc { 0 } else { 1 },
				sort_dir, sort_dir
			));
		}
		"modified" if has_user => {
			// Sort by user's modification time (NULLs last for DESC, NULLs first for ASC)
			query.push(format!(
				" ORDER BY CASE WHEN fud.modified_at IS NULL THEN {} ELSE {} END, fud.modified_at {}, f.f_id {}",
				if is_desc { 1 } else { 0 },
				if is_desc { 0 } else { 1 },
				sort_dir, sort_dir
			));
		}
		"name" => {
			query.push(format!(" ORDER BY f.file_name {}, f.f_id {}", sort_dir, sort_dir));
		}
		_ => {
			// Default (including "created"): sort by file creation time
			query.push(format!(" ORDER BY f.created_at {}, f.f_id {}", sort_dir, sort_dir));
		}
	}

	// Fetch limit+1 to determine hasMore
	// Note: SQLite doesn't allow bound parameters in LIMIT clause, so we use format!
	let limit = opts.limit.unwrap_or(30) as i64;
	query.push(format!(" LIMIT {}", limit + 1));

	debug!("SQL: {}", query.sql());

	let res = query
		.build()
		.fetch_all(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	collect_res(res.iter().map(|row| {
		let status = match row.try_get("status")? {
			"A" => FileStatus::Active,
			"P" => FileStatus::Pending,
			"D" => FileStatus::Deleted,
			_ => return Err(sqlx::Error::RowNotFound),
		};

		let tags_str: Option<Box<str>> = row.try_get("tags")?;
		let tags = tags_str.map(|s| parse_str_list(&s).to_vec());

		// Build owner profile info if owner_tag exists
		let owner = if let (Ok(id_tag), Ok(name)) =
			(row.try_get::<Box<str>, _>("id_tag"), row.try_get::<Box<str>, _>("name"))
		{
			let typ = match row.try_get::<&str, _>("type").ok() {
				Some("P") => ProfileType::Person,
				Some("C") => ProfileType::Community,
				_ => ProfileType::Person, // Default fallback
			};

			Some(ProfileInfo { id_tag, name, typ, profile_pic: row.try_get("profile_pic").ok() })
		} else {
			None
		};

		let visibility: Option<String> = row.try_get("visibility").ok();
		let visibility = visibility.and_then(|s| s.chars().next());

		// Use @{f_id} as fallback when file_id is NULL (for pending files)
		let f_id: i64 = row.try_get("f_id")?;
		let file_id: Option<Box<str>> = row.try_get("file_id").ok().flatten();
		let file_id = file_id.unwrap_or_else(|| format!("@{}", f_id).into());

		// Build user data if available
		let user_data = if has_user {
			let accessed_at: Option<i64> = row.try_get("fud_accessed_at").ok().flatten();
			let modified_at: Option<i64> = row.try_get("fud_modified_at").ok().flatten();
			let pinned: Option<i64> = row.try_get("fud_pinned").ok().flatten();
			let starred: Option<i64> = row.try_get("fud_starred").ok().flatten();

			// Only include user_data if there's at least some data
			if accessed_at.is_some()
				|| modified_at.is_some()
				|| pinned.is_some()
				|| starred.is_some()
			{
				Some(FileUserData {
					accessed_at: accessed_at.map(Timestamp),
					modified_at: modified_at.map(Timestamp),
					pinned: pinned.unwrap_or(0) != 0,
					starred: starred.unwrap_or(0) != 0,
				})
			} else {
				None
			}
		} else {
			None
		};

		// Global file activity timestamps
		let accessed_at: Option<i64> = row.try_get("accessed_at").ok().flatten();
		let modified_at: Option<i64> = row.try_get("modified_at").ok().flatten();

		// Parse x field as JSON
		let x: Option<serde_json::Value> = row.try_get("x").ok().flatten();

		Ok(FileView {
			file_id,
			parent_id: row.try_get("parent_id").ok(),
			owner,
			preset: row.try_get("preset")?,
			content_type: row.try_get("content_type")?,
			file_name: row.try_get("file_name")?,
			file_tp: row.try_get("file_tp")?,
			created_at: row.try_get("created_at").map(Timestamp)?,
			accessed_at: accessed_at.map(Timestamp),
			modified_at: modified_at.map(Timestamp),
			status,
			tags,
			visibility,
			access_level: None, // Computed later by filter_files_by_visibility
			user_data,
			x,
		})
	}))
}

/// List file variants for a file
pub(crate) async fn list_variants(
	db: &SqlitePool,
	tn_id: TnId,
	file_id: FileId<&str>,
) -> ClResult<Vec<FileVariant<Box<str>>>> {
	let res = match file_id {
		FileId::FId(f_id) => sqlx::query(
			"SELECT variant_id, variant, res_x, res_y, format, size, available, duration, bitrate, page_count
			FROM file_variants WHERE tn_id=? AND f_id=?",
		)
		.bind(tn_id.0)
		.bind(f_id as i64)
		.fetch_all(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?,
		FileId::FileId(file_id) => {
			if let Some(f_id_str) = file_id.strip_prefix("@") {
				let f_id = f_id_str
					.parse::<i64>()
					.map_err(|_| Error::ValidationError("invalid f_id".into()))?;
				sqlx::query(
					"SELECT variant_id, variant, res_x, res_y, format, size, available, duration, bitrate, page_count
					FROM file_variants WHERE tn_id=? AND f_id=?",
				)
				.bind(tn_id.0)
				.bind(f_id)
				.fetch_all(db)
				.await
				.inspect_err(inspect)
				.map_err(|_| Error::DbError)?
			} else {
				sqlx::query("SELECT fv.variant_id, fv.variant, fv.res_x, fv.res_y, fv.format, fv.size, fv.available, fv.duration, fv.bitrate, fv.page_count
					FROM files f
					JOIN file_variants fv ON fv.tn_id=f.tn_id AND fv.f_id=f.f_id
					WHERE f.tn_id=? AND f.file_id=?")
					.bind(tn_id.0).bind(file_id)
					.fetch_all(db).await.inspect_err(inspect).map_err(|_| Error::DbError)?
			}
		}
	};

	collect_res(res.iter().map(|row| {
		let res_x = row.try_get("res_x")?;
		let res_y = row.try_get("res_y")?;
		Ok(FileVariant {
			variant_id: row.try_get("variant_id")?,
			variant: row.try_get("variant")?,
			resolution: (res_x, res_y),
			format: row.try_get("format")?,
			size: row.try_get("size")?,
			available: row.try_get("available")?,
			duration: row.try_get::<Option<f64>, _>("duration").ok().flatten(),
			bitrate: row.try_get::<Option<i64>, _>("bitrate").ok().flatten().map(|v| v as u32),
			page_count: row
				.try_get::<Option<i64>, _>("page_count")
				.ok()
				.flatten()
				.map(|v| v as u32),
		})
	}))
}

/// List available (locally present) variant names for a file by file_id
pub(crate) async fn list_available_variants(
	db: &SqlitePool,
	tn_id: TnId,
	file_id: &str,
) -> ClResult<Vec<Box<str>>> {
	let res = sqlx::query(
		"SELECT fv.variant
		 FROM files f
		 JOIN file_variants fv ON fv.tn_id=f.tn_id AND fv.f_id=f.f_id
		 WHERE f.tn_id=? AND f.file_id=? AND fv.available=1",
	)
	.bind(tn_id.0)
	.bind(file_id)
	.fetch_all(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

	collect_res(res.iter().map(|row| row.try_get("variant")))
}

/// List available (locally present) variant names for a file by f_id
pub(crate) async fn list_available_variants_by_fid(
	db: &SqlitePool,
	tn_id: TnId,
	f_id: i64,
) -> ClResult<Vec<Box<str>>> {
	let res = sqlx::query(
		"SELECT fv.variant
		 FROM file_variants fv
		 WHERE fv.tn_id=? AND fv.f_id=? AND fv.available=1",
	)
	.bind(tn_id.0)
	.bind(f_id)
	.fetch_all(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

	collect_res(res.iter().map(|row| row.try_get("variant")))
}

/// Read a single file variant by ID
pub(crate) async fn read_variant(
	db: &SqlitePool,
	tn_id: TnId,
	variant_id: &str,
) -> ClResult<FileVariant<Box<str>>> {
	debug!("read_variant: tn_id={}, variant_id={}", tn_id.0, variant_id);
	let res = sqlx::query(
		"SELECT variant_id, variant, res_x, res_y, format, size, available, duration, bitrate, page_count
			FROM file_variants WHERE tn_id=? AND variant_id=?",
	)
	.bind(tn_id.0)
	.bind(variant_id)
	.fetch_one(db)
	.await;
	debug!("read_variant result: {:?}", res.is_ok());

	map_res(res, |row| {
		let res_x = row.try_get("res_x")?;
		let res_y = row.try_get("res_y")?;
		Ok(FileVariant {
			variant_id: row.try_get("variant_id")?,
			variant: row.try_get("variant")?,
			resolution: (res_x, res_y),
			format: row.try_get("format")?,
			size: row.try_get("size")?,
			available: row.try_get("available")?,
			duration: row.try_get::<Option<f64>, _>("duration").ok().flatten(),
			bitrate: row.try_get::<Option<i64>, _>("bitrate").ok().flatten().map(|v| v as u32),
			page_count: row
				.try_get::<Option<i64>, _>("page_count")
				.ok()
				.flatten()
				.map(|v| v as u32),
		})
	})
}

/// Look up the file_id for a given variant_id
pub(crate) async fn read_file_id_by_variant(
	db: &SqlitePool,
	tn_id: TnId,
	variant_id: &str,
) -> ClResult<Box<str>> {
	let res = sqlx::query(
		"SELECT f.file_id
			FROM files f
			JOIN file_variants fv ON f.tn_id=fv.tn_id AND f.f_id=fv.f_id
			WHERE fv.tn_id=? AND fv.variant_id=?",
	)
	.bind(tn_id.0)
	.bind(variant_id)
	.fetch_one(db)
	.await;

	map_res(res, |row| row.try_get("file_id"))
}

/// Look up the internal f_id for a given file_id
pub(crate) async fn read_f_id_by_file_id(
	db: &SqlitePool,
	tn_id: TnId,
	file_id: &str,
) -> ClResult<u64> {
	let res = sqlx::query("SELECT f_id FROM files WHERE tn_id=? AND file_id=?")
		.bind(tn_id.0)
		.bind(file_id)
		.fetch_one(db)
		.await;

	map_res(res, |row| {
		let f_id: i64 = row.try_get("f_id")?;
		Ok(f_id as u64)
	})
}

/// Create a new file record
pub(crate) async fn create(
	db: &SqlitePool,
	tn_id: TnId,
	opts: CreateFile,
) -> ClResult<FileId<Box<str>>> {
	// Only check for existing file if we have preset and orig_variant_id (normal file creation)
	// For shared files (FSHR), these are None so we skip the dedup check
	if let (Some(preset), Some(orig_variant_id)) = (&opts.preset, &opts.orig_variant_id) {
		let file_id_exists: Option<Box<str>> = sqlx::query(
			"SELECT min(f.file_id) FROM file_variants fv
			JOIN files f ON f.tn_id=fv.tn_id AND f.f_id=fv.f_id AND f.preset=? AND f.file_id IS NOT NULL
			WHERE fv.tn_id=? AND fv.variant_id=? AND fv.variant='orig'",
		)
		.bind(preset)
		.bind(tn_id.0)
		.bind(orig_variant_id)
		.fetch_one(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?
		.get(0);

		if let Some(file_id) = file_id_exists {
			return Ok(FileId::FileId(file_id));
		}
	}

	// Use provided status or default to 'P' (Pending)
	let status = match opts.status {
		Some(FileStatus::Active) => "A",
		Some(FileStatus::Pending) => "P",
		Some(FileStatus::Deleted) => "D",
		None => "P",
	};
	let created_at =
		if let Some(created_at) = opts.created_at { created_at } else { Timestamp::now() };
	let file_tp = opts.file_tp.as_deref().unwrap_or("BLOB"); // Default to BLOB if not specified
	let visibility = opts.visibility.map(|c| c.to_string());

	// For shared files (with explicit file_id), check if already exists (idempotent)
	if let Some(ref file_id) = opts.file_id {
		let existing: Option<i64> =
			sqlx::query_scalar("SELECT f_id FROM files WHERE tn_id=? AND file_id=?")
				.bind(tn_id.0)
				.bind(file_id)
				.fetch_optional(db)
				.await
				.inspect_err(inspect)
				.map_err(|_| Error::DbError)?;

		if let Some(f_id) = existing {
			return Ok(FileId::FId(f_id as u64));
		}
	}

	let res = sqlx::query("INSERT INTO files (tn_id, file_id, parent_id, status, owner_tag, preset, content_type, file_name, file_tp, created_at, tags, x, visibility) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING f_id")
		.bind(tn_id.0).bind(opts.file_id).bind(opts.parent_id).bind(status).bind(opts.owner_tag).bind(opts.preset).bind(opts.content_type).bind(opts.file_name).bind(file_tp).bind(created_at.0).bind(opts.tags.map(|tags| tags.join(","))).bind(opts.x).bind(visibility)
		.fetch_one(db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

	Ok(FileId::FId(res.get(0)))
}

/// Create a file variant
/// Note: Only works for pending files (status='P') to preserve content-based ID integrity
pub(crate) async fn create_variant<'a>(
	db: &SqlitePool,
	tn_id: TnId,
	f_id: u64,
	opts: FileVariant<&'a str>,
) -> ClResult<&'a str> {
	let mut tx = db.begin().await.map_err(|_| Error::DbError)?;
	let _res = sqlx::query("SELECT f_id FROM files WHERE tn_id=? AND f_id=? AND status='P'")
		.bind(tn_id.0)
		.bind(f_id as i64)
		.fetch_one(&mut *tx)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	let _res = sqlx::query("INSERT OR IGNORE INTO file_variants (tn_id, f_id, variant_id, variant, res_x, res_y, format, size, available, duration, bitrate, page_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
		.bind(tn_id.0).bind(f_id as i64).bind(opts.variant_id).bind(opts.variant).bind(opts.resolution.0).bind(opts.resolution.1).bind(opts.format).bind(opts.size as i64).bind(opts.available).bind(opts.duration).bind(opts.bitrate.map(|b| b as i64)).bind(opts.page_count.map(|p| p as i64))
		.execute(&mut *tx).await.inspect_err(inspect).map_err(|_| Error::DbError)?;
	tx.commit().await.map_err(|_| Error::DbError)?;

	Ok(opts.variant_id)
}

/// Update file_id for a pending file (idempotent - succeeds if already set to same value)
pub(crate) async fn update_id(
	db: &SqlitePool,
	tn_id: TnId,
	f_id: u64,
	file_id: &str,
) -> ClResult<()> {
	// First check if file exists and what its current file_id is
	let existing = sqlx::query("SELECT file_id FROM files WHERE tn_id=? AND f_id=?")
		.bind(tn_id.0)
		.bind(f_id as i64)
		.fetch_optional(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	match existing {
		None => {
			// File doesn't exist at all
			return Err(Error::NotFound);
		}
		Some(row) => {
			let existing_file_id: Option<String> = row.try_get("file_id").ok().flatten();

			if let Some(existing_id) = existing_file_id {
				// Already has a file_id - check if it matches
				if existing_id == file_id {
					// Idempotent success - already set to the correct value
					return Ok(());
				} else {
					// Different file_id - this is a conflict
					let msg = format!(
						"Attempted to update f_id={} to file_id={} but already set to {}",
						f_id, file_id, existing_id
					);
					error!("{}", msg);
					return Err(Error::Conflict(msg));
				}
			}
			// file_id is NULL - proceed with update
		}
	}

	// Update file_id for pending files
	let res = sqlx::query("UPDATE files SET file_id=? WHERE tn_id=? AND f_id=? AND status='P'")
		.bind(file_id)
		.bind(tn_id.0)
		.bind(f_id as i64)
		.execute(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	if res.rows_affected() == 0 {
		// Race condition - someone else just set it between our check and update.
		// Re-check what value was set (idempotent verification)
		let current = sqlx::query("SELECT file_id FROM files WHERE tn_id=? AND f_id=?")
			.bind(tn_id.0)
			.bind(f_id as i64)
			.fetch_optional(db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		if let Some(row) = current {
			if let Some(existing_id) = row.try_get::<Option<String>, _>("file_id").ok().flatten() {
				if existing_id == file_id {
					// Race condition resolved - correct value was set
					return Ok(());
				} else {
					// Different value - this is a real conflict
					let msg = format!(
						"Race condition: f_id={} was set to {} instead of {}",
						f_id, existing_id, file_id
					);
					error!("{}", msg);
					return Err(Error::Conflict(msg));
				}
			}
		}
		// Still NULL somehow - return error
		return Err(Error::Internal("Unexpected state during file_id update".into()));
	}

	Ok(())
}

/// Finalize a pending file - sets file_id and transitions status from 'P' to 'A' atomically
pub(crate) async fn finalize_file(
	db: &SqlitePool,
	tn_id: TnId,
	f_id: u64,
	file_id: &str,
) -> ClResult<()> {
	// First check if file exists and what its current state is
	let existing = sqlx::query("SELECT file_id, status FROM files WHERE tn_id=? AND f_id=?")
		.bind(tn_id.0)
		.bind(f_id as i64)
		.fetch_optional(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	match existing {
		None => {
			// File doesn't exist at all
			return Err(Error::NotFound);
		}
		Some(row) => {
			let existing_file_id: Option<String> = row.try_get("file_id").ok().flatten();
			let status: String = row.try_get("status").map_err(|_| Error::DbError)?;

			if let Some(existing_id) = existing_file_id {
				// Already has a file_id - check if it matches
				if existing_id == file_id && status == "A" {
					// Idempotent success - already finalized with correct value
					return Ok(());
				} else if existing_id == file_id && status == "P" {
					// Has correct file_id but status not updated - fix it
					sqlx::query("UPDATE files SET status='A' WHERE tn_id=? AND f_id=?")
						.bind(tn_id.0)
						.bind(f_id as i64)
						.execute(db)
						.await
						.inspect_err(inspect)
						.map_err(|_| Error::DbError)?;
					return Ok(());
				} else if existing_id != file_id {
					// Different file_id - this is a conflict
					let msg = format!(
						"Attempted to finalize f_id={} to file_id={} but already set to {}",
						f_id, file_id, existing_id
					);
					error!("{}", msg);
					return Err(Error::Conflict(msg));
				}
			}
			// file_id is NULL - proceed with finalization
		}
	}

	// Set file_id and status='A' atomically for pending files
	let res = sqlx::query(
		"UPDATE files SET file_id=?, status='A' WHERE tn_id=? AND f_id=? AND status='P'",
	)
	.bind(file_id)
	.bind(tn_id.0)
	.bind(f_id as i64)
	.execute(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

	if res.rows_affected() == 0 {
		// Race condition - someone else just set it between our check and update.
		// Re-check what value was set (idempotent verification)
		let current = sqlx::query("SELECT file_id, status FROM files WHERE tn_id=? AND f_id=?")
			.bind(tn_id.0)
			.bind(f_id as i64)
			.fetch_optional(db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		if let Some(row) = current {
			if let Some(existing_id) = row.try_get::<Option<String>, _>("file_id").ok().flatten() {
				let status: String = row.try_get("status").map_err(|_| Error::DbError)?;
				if existing_id == file_id && status == "A" {
					// Race condition resolved - correct value and status were set
					return Ok(());
				} else if existing_id == file_id && status == "P" {
					// Has correct file_id but status not updated - fix it
					sqlx::query("UPDATE files SET status='A' WHERE tn_id=? AND f_id=?")
						.bind(tn_id.0)
						.bind(f_id as i64)
						.execute(db)
						.await
						.inspect_err(inspect)
						.map_err(|_| Error::DbError)?;
					return Ok(());
				} else {
					// Different value - this is a real conflict
					let msg = format!(
						"Race condition: f_id={} was set to {} instead of {}",
						f_id, existing_id, file_id
					);
					error!("{}", msg);
					return Err(Error::Conflict(msg));
				}
			}
		}
		// Still NULL somehow - return error
		return Err(Error::Internal("Unexpected state during file finalization".into()));
	}

	info!("Finalized file f_id={} → file_id={}, status='A'", f_id, file_id);
	Ok(())
}

/// Update file metadata (name, parent folder, visibility, status)
pub(crate) async fn update_data(
	db: &SqlitePool,
	tn_id: TnId,
	file_id: &str,
	opts: &UpdateFileOptions,
) -> ClResult<()> {
	use cloudillo::types::Patch;

	// Build dynamic UPDATE query based on which fields are set
	let mut set_clauses = Vec::new();

	if !opts.file_name.is_undefined() {
		set_clauses.push("file_name = ?");
	}
	if !opts.parent_id.is_undefined() {
		set_clauses.push("parent_id = ?");
	}
	if !opts.visibility.is_undefined() {
		set_clauses.push("visibility = ?");
	}
	if !opts.status.is_undefined() {
		set_clauses.push("status = ?");
	}

	if set_clauses.is_empty() {
		return Ok(()); // Nothing to update
	}

	// Handle @-prefixed integer IDs vs content-addressable IDs
	let (where_clause, file_id_bind): (&str, &str) =
		if let Some(f_id_str) = file_id.strip_prefix("@") {
			("f_id", f_id_str)
		} else {
			("file_id", file_id)
		};

	let sql = format!(
		"UPDATE files SET {} WHERE tn_id = ? AND {} = ?",
		set_clauses.join(", "),
		where_clause
	);

	let mut query = sqlx::query(&sql);

	// Bind values in the same order as set_clauses
	if !opts.file_name.is_undefined() {
		let val: Option<&str> = match &opts.file_name {
			Patch::Null => None,
			Patch::Value(v) => Some(v.as_str()),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}
	if !opts.parent_id.is_undefined() {
		let val: Option<&str> = match &opts.parent_id {
			Patch::Null => None,
			Patch::Value(v) => Some(v.as_str()),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}
	if !opts.visibility.is_undefined() {
		let val: Option<String> = match &opts.visibility {
			Patch::Null => None,
			Patch::Value(c) => Some(c.to_string()),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}
	if !opts.status.is_undefined() {
		let val: Option<String> = match &opts.status {
			Patch::Null => None,
			Patch::Value(c) => Some(c.to_string()),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}

	// Bind WHERE clause params
	query = query.bind(tn_id.0).bind(file_id_bind);

	query.execute(db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

	Ok(())
}

/// Read a file by ID (supports both @-prefixed f_id and content-addressable file_id)
pub(crate) async fn read(
	db: &SqlitePool,
	tn_id: TnId,
	file_id: &str,
) -> ClResult<Option<FileView>> {
	// Handle @-prefixed integer IDs vs content-addressable IDs
	let row = if let Some(f_id_str) = file_id.strip_prefix("@") {
		// Integer ID - parse and query by f_id
		let f_id = f_id_str
			.parse::<i64>()
			.map_err(|_| Error::ValidationError("invalid f_id".into()))?;
		sqlx::query(
			"SELECT f.file_id, f.parent_id, f.file_name, f.file_tp, f.created_at, f.accessed_at, f.modified_at, f.status, f.tags, f.owner_tag, f.preset, f.content_type, f.visibility, f.x,
			        COALESCE(p.id_tag, f.owner_tag) as id_tag, COALESCE(p.name, f.owner_tag) as name, p.type, p.profile_pic
			 FROM files f
			 LEFT JOIN profiles p ON p.tn_id=f.tn_id AND p.id_tag=f.owner_tag
			 WHERE f.tn_id=? AND f.f_id=?"
		)
		.bind(tn_id.0)
		.bind(f_id)
		.fetch_optional(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?
	} else {
		// Content-addressable ID - query by file_id
		sqlx::query(
			"SELECT f.file_id, f.parent_id, f.file_name, f.file_tp, f.created_at, f.accessed_at, f.modified_at, f.status, f.tags, f.owner_tag, f.preset, f.content_type, f.visibility, f.x,
			        COALESCE(p.id_tag, f.owner_tag) as id_tag, COALESCE(p.name, f.owner_tag) as name, p.type, p.profile_pic
			 FROM files f
			 LEFT JOIN profiles p ON p.tn_id=f.tn_id AND p.id_tag=f.owner_tag
			 WHERE f.tn_id=? AND f.file_id=?"
		)
		.bind(tn_id.0)
		.bind(file_id)
		.fetch_optional(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?
	};

	match row {
		None => Ok(None),
		Some(row) => {
			let status = match row.try_get("status").map_err(|_| Error::DbError)? {
				"A" => FileStatus::Active,
				"P" => FileStatus::Pending,
				"D" => FileStatus::Deleted,
				_ => return Err(Error::DbError),
			};

			let tags_str: Option<Box<str>> = row.try_get("tags").ok();
			let tags = tags_str.map(|s| parse_str_list(&s).to_vec());

			// Build owner profile info if owner_tag exists
			let owner = if let (Ok(id_tag), Ok(name)) =
				(row.try_get::<Box<str>, _>("id_tag"), row.try_get::<Box<str>, _>("name"))
			{
				let typ = match row.try_get::<&str, _>("type").ok() {
					Some("P") => ProfileType::Person,
					Some("C") => ProfileType::Community,
					_ => ProfileType::Person, // Default fallback
				};

				Some(ProfileInfo {
					id_tag,
					name,
					typ,
					profile_pic: row.try_get("profile_pic").ok(),
				})
			} else {
				None
			};

			let visibility: Option<String> = row.try_get("visibility").ok();
			let visibility = visibility.and_then(|s| s.chars().next());

			// Global file activity timestamps
			let accessed_at: Option<i64> = row.try_get("accessed_at").ok().flatten();
			let modified_at: Option<i64> = row.try_get("modified_at").ok().flatten();

			// Parse x field as JSON
			let x: Option<serde_json::Value> = row.try_get("x").ok().flatten();

			Ok(Some(FileView {
				file_id: row.try_get("file_id").map_err(|_| Error::DbError)?,
				parent_id: row.try_get("parent_id").ok(),
				owner,
				preset: row.try_get("preset").ok(),
				content_type: row.try_get("content_type").ok(),
				file_name: row.try_get("file_name").map_err(|_| Error::DbError)?,
				file_tp: row.try_get("file_tp").ok(),
				created_at: row
					.try_get::<i64, _>("created_at")
					.map(Timestamp)
					.map_err(|_| Error::DbError)?,
				accessed_at: accessed_at.map(Timestamp),
				modified_at: modified_at.map(Timestamp),
				status,
				tags,
				visibility,
				access_level: None, // Computed later by filter_files_by_visibility
				user_data: None,    // Not fetched in single-file read
				x,
			}))
		}
	}
}

/// Delete a file (set status to 'D')
pub(crate) async fn delete(db: &SqlitePool, tn_id: TnId, file_id: &str) -> ClResult<()> {
	// Set status to 'D' (deleted)
	sqlx::query("UPDATE files SET status = 'D' WHERE tn_id = ? AND file_id = ?")
		.bind(tn_id.0)
		.bind(file_id)
		.execute(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	Ok(())
}
