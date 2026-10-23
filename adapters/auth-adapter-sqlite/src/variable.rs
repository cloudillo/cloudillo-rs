// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Tenant variable storage

use sqlx::{Row, SqlitePool};

use crate::VAR_VALUE;
use crate::utils::{Db, inspect, map_res};
use cloudillo_types::{
	prelude::*,
	secret_box::{self, SecretBox},
};

/// Vars holding secrets: stored encrypted when a `SECRET_KEY` is configured.
/// The `vars` entry of `secret_columns()` in `lib.rs` is built from this list.
pub(crate) const SECRET_VARS: &[&str] = &["jwt_secret", "acme_account"];

/// Associated data of a secret `vars.value`, by its full key (`{tn_id}:{var}`)
pub(crate) fn var_aad(key: &str) -> String {
	secret_box::aad(VAR_VALUE.0, VAR_VALUE.1, key)
}

/// Read a tenant variable
pub(crate) async fn read_var(
	db: &SqlitePool,
	sb: &SecretBox,
	tn_id: TnId,
	var: &str,
) -> ClResult<Box<str>> {
	let key = format!("{}:{}", tn_id.0, var);
	let res = sqlx::query("SELECT value FROM vars WHERE key = ?1")
		.bind(&key)
		.fetch_one(db)
		.await
		.inspect_err(inspect);

	let value: Box<str> = map_res(res, |row| row.try_get("value"))?;
	if SECRET_VARS.contains(&var) {
		Ok(sb.decrypt(&value, &var_aad(&key))?.into())
	} else {
		Ok(value)
	}
}

/// Update a tenant variable
pub(crate) async fn update_var(
	db: &SqlitePool,
	sb: &SecretBox,
	tn_id: TnId,
	var: &str,
	value: &str,
) -> ClResult<()> {
	let key = format!("{}:{}", tn_id.0, var);
	let sealed;
	let value = if SECRET_VARS.contains(&var) {
		sealed = sb.encrypt(value, &var_aad(&key))?;
		sealed.as_str()
	} else {
		value
	};
	sqlx::query(
		"INSERT OR REPLACE INTO vars (key, value, updated_at) VALUES (?1, ?2, current_timestamp)",
	)
	.bind(&key)
	.bind(value)
	.execute(db)
	.await
	.db()?;
	Ok(())
}
