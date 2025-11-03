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
	opts: ListFileOptions,
) -> ClResult<Vec<FileView>> {
	let mut query = sqlx::QueryBuilder::new(
		"SELECT f.file_id, f.file_name, f.created_at, f.status, f.tags, f.owner_tag, f.preset, f.content_type,
		        p.id_tag, p.name, p.type, p.profile_pic
		 FROM files f
		 LEFT JOIN profiles p ON p.tn_id=f.tn_id AND p.id_tag=f.owner_tag
		 WHERE f.tn_id="
	);
	query.push_bind(tn_id.0);

	if let Some(file_id) = &opts.file_id {
		query.push(" AND f.file_id=").push_bind(file_id.as_ref());
	}

	if let Some(tag) = &opts.tag {
		query.push(" AND f.tags LIKE ").push_bind(format!("%{}%", tag));
	}

	if let Some(preset) = &opts.preset {
		query.push(" AND f.preset=").push_bind(preset.as_ref());
	}

	if let Some(file_type) = &opts.file_type {
		query.push(" AND f.file_tp=").push_bind(file_type.as_ref());
	}

	if let Some(status) = opts.status {
		let status_char = match status {
			FileStatus::Immutable => "I",
			FileStatus::Mutable => "M",
			FileStatus::Pending => "P",
			FileStatus::Deleted => "D",
		};
		query.push(" AND f.status=").push_bind(status_char);
	}

	query.push(" ORDER BY f.created_at DESC LIMIT ");
	query.push_bind(opts._limit.unwrap_or(100) as i64);

	let res = query
		.build()
		.fetch_all(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	collect_res(res.iter().map(|row| {
		let status = match row.try_get("status")? {
			"I" => FileStatus::Immutable,
			"M" => FileStatus::Mutable,
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

		Ok(FileView {
			file_id: row.try_get("file_id")?,
			owner,
			preset: row.try_get("preset")?,
			content_type: row.try_get("content_type")?,
			file_name: row.try_get("file_name")?,
			created_at: row.try_get("created_at").map(Timestamp)?,
			status,
			tags,
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
			"SELECT variant_id, variant, res_x, res_y, format, size, available
			FROM file_variants WHERE tn_id=? AND f_id=?",
		)
		.bind(tn_id.0)
		.bind(f_id as i64)
		.fetch_all(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?,
		FileId::FileId(file_id) => {
			if let Some(f_id) = file_id.strip_prefix("@") {
				sqlx::query(
					"SELECT variant_id, variant, res_x, res_y, format, size, available
					FROM file_variants WHERE tn_id=? AND f_id=?",
				)
				.bind(tn_id.0)
				.bind(f_id)
				.fetch_all(db)
				.await
				.inspect_err(inspect)
				.map_err(|_| Error::DbError)?
			} else {
				sqlx::query("SELECT fv.variant_id, fv.variant, fv.res_x, fv.res_y, fv.format, fv.size, fv.available
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
		})
	}))
}

/// Read a single file variant by ID
pub(crate) async fn read_variant(
	db: &SqlitePool,
	tn_id: TnId,
	variant_id: &str,
) -> ClResult<FileVariant<Box<str>>> {
	let res = sqlx::query(
		"SELECT variant_id, variant, res_x, res_y, format, size, available
			FROM file_variants WHERE tn_id=? AND variant_id=?",
	)
	.bind(tn_id.0)
	.bind(variant_id)
	.fetch_one(db)
	.await;

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
		})
	})
}

/// Create a new file record
pub(crate) async fn create(
	db: &SqlitePool,
	tn_id: TnId,
	opts: CreateFile,
) -> ClResult<FileId<Box<str>>> {
	let file_id_exists = sqlx::query(
		"SELECT min(f.file_id) FROM file_variants fv
		JOIN files f ON f.tn_id=fv.tn_id AND f.f_id=fv.f_id AND f.preset=? AND f.file_id IS NOT NULL
		WHERE fv.tn_id=? AND fv.variant_id=? AND fv.variant='orig'",
	)
	.bind(&opts.preset)
	.bind(tn_id.0)
	.bind(&opts.orig_variant_id)
	.fetch_one(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?
	.get(0);

	if let Some(file_id) = file_id_exists {
		return Ok(FileId::FileId(file_id));
	}

	let status = "P";
	let created_at =
		if let Some(created_at) = opts.created_at { created_at } else { Timestamp::now() };
	let file_tp = opts.file_tp.unwrap_or_else(|| "BLOB".into()); // Default to BLOB if not specified
	let res = sqlx::query("INSERT OR IGNORE INTO files (tn_id, file_id, status, owner_tag, preset, content_type, file_name, file_tp, created_at, tags, x) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING f_id")
		.bind(tn_id.0).bind(opts.file_id).bind(status).bind(opts.owner_tag).bind(opts.preset).bind(opts.content_type).bind(opts.file_name).bind(file_tp.as_ref()).bind(created_at.0).bind(opts.tags.map(|tags| tags.join(","))).bind(opts.x)
		.fetch_one(db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

	Ok(FileId::FId(res.get(0)))
}

/// Create a file variant
pub(crate) async fn create_variant<'a>(
	db: &SqlitePool,
	tn_id: TnId,
	f_id: u64,
	opts: FileVariant<&'a str>,
) -> ClResult<&'a str> {
	let mut tx = db.begin().await.map_err(|_| Error::DbError)?;
	let _res = sqlx::query("SELECT f_id FROM files WHERE tn_id=? AND f_id=? AND file_id IS NULL")
		.bind(tn_id.0)
		.bind(f_id as i64)
		.fetch_one(&mut *tx)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	let _res = sqlx::query("INSERT OR IGNORE INTO file_variants (tn_id, f_id, variant_id, variant, res_x, res_y, format, size) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
		.bind(tn_id.0).bind(f_id as i64).bind(opts.variant_id).bind(opts.variant).bind(opts.resolution.0).bind(opts.resolution.1).bind(opts.format).bind(opts.size as i64)
		.execute(&mut *tx).await.inspect_err(inspect).map_err(|_| Error::DbError)?;
	tx.commit().await.map_err(|_| Error::DbError)?;

	Ok(opts.variant_id)
}

/// Update file_id for a pending file
pub(crate) async fn update_id(
	db: &SqlitePool,
	tn_id: TnId,
	f_id: u64,
	file_id: &str,
) -> ClResult<()> {
	let res =
		sqlx::query("UPDATE files SET file_id=? WHERE tn_id=? AND f_id=? AND file_id IS NULL")
			.bind(file_id)
			.bind(tn_id.0)
			.bind(f_id as i64)
			.execute(db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;
	if res.rows_affected() == 0 {
		return Err(Error::NotFound);
	}

	Ok(())
}

/// Update file name
pub(crate) async fn update_name(
	db: &SqlitePool,
	tn_id: TnId,
	file_id: &str,
	file_name: &str,
) -> ClResult<()> {
	sqlx::query("UPDATE files SET file_name = ? WHERE tn_id = ? AND file_id = ?")
		.bind(file_name)
		.bind(tn_id.0)
		.bind(file_id)
		.execute(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	Ok(())
}

/// Read a file by ID
pub(crate) async fn read(
	_db: &SqlitePool,
	_tn_id: TnId,
	_file_id: &str,
) -> ClResult<Option<FileView>> {
	// Simplified implementation - just return None for now
	Ok(None)
}

/// Delete (soft delete) a file
pub(crate) async fn delete(db: &SqlitePool, tn_id: TnId, file_id: &str) -> ClResult<()> {
	// Soft delete file
	sqlx::query("UPDATE files SET deleted_at = unixepoch() WHERE tn_id = ? AND file_id = ?")
		.bind(tn_id.0)
		.bind(file_id)
		.execute(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	Ok(())
}

/// Decrement file reference count
pub(crate) async fn decrement_ref(db: &SqlitePool, tn_id: TnId, file_id: &str) -> ClResult<()> {
	// Decrement reference count
	sqlx::query(
		"UPDATE files SET ref_count = MAX(0, ref_count - 1) WHERE tn_id = ? AND file_id = ?",
	)
	.bind(tn_id.0)
	.bind(file_id)
	.execute(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

	Ok(())
}
