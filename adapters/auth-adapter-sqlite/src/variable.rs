//! Tenant variable storage

use sqlx::{Row, SqlitePool};

use crate::utils::*;
use cloudillo_types::prelude::*;

/// Read a tenant variable
pub(crate) async fn read_var(db: &SqlitePool, tn_id: TnId, var: &str) -> ClResult<Box<str>> {
	let key = format!("{}:{}", tn_id.0, var);
	let res = sqlx::query("SELECT value FROM vars WHERE key = ?1")
		.bind(&key)
		.fetch_one(db)
		.await
		.inspect_err(inspect);

	map_res(res, |row| row.try_get("value"))
}

/// Update a tenant variable
pub(crate) async fn update_var(
	db: &SqlitePool,
	tn_id: TnId,
	var: &str,
	value: &str,
) -> ClResult<()> {
	let key = format!("{}:{}", tn_id.0, var);
	sqlx::query(
		"INSERT OR REPLACE INTO vars (key, value, updated_at) VALUES (?1, ?2, current_timestamp)",
	)
	.bind(&key)
	.bind(value)
	.execute(db)
	.await
	.inspect_err(inspect)
	.or(Err(Error::DbError))?;
	Ok(())
}
