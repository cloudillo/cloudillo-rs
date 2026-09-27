// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Channel database operations: named rooms inside a tenant and their rosters.
//!
//! Names are bare here (the tenant is `tn_id`); entity `channel` columns carry the
//! absolute `@tenant~name` form. `channel_members` is a projection of signed SUBS/INVT.

use cloudillo_types::{
	meta_adapter::{Channel, UpdateChannelData},
	prelude::*,
};
use sqlx::{Row, SqlitePool};

use crate::utils::{Db, push_patch};

const CHANNEL_COLS: &str =
	"name, title, descr, visibility, min_role, closed, created_at, updated_at";

fn row_to_channel(row: &sqlx::sqlite::SqliteRow) -> Channel {
	Channel {
		name: row.get::<String, _>("name").into(),
		title: row.get::<Option<String>, _>("title").map(Into::into),
		descr: row.get::<Option<String>, _>("descr").map(Into::into),
		visibility: row.get::<Option<String>, _>("visibility").and_then(|s| s.chars().next()),
		min_role: row.get::<Option<String>, _>("min_role").map(Into::into),
		closed: row.get::<i64, _>("closed") != 0,
		created_at: Timestamp(row.get::<i64, _>("created_at")),
		updated_at: Timestamp(row.get::<i64, _>("updated_at")),
	}
}

pub async fn list_channels(db: &SqlitePool, tn_id: TnId) -> ClResult<Vec<Channel>> {
	let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
		"SELECT {CHANNEL_COLS} FROM channels WHERE tn_id = ? ORDER BY name"
	)))
	.bind(tn_id.0)
	.fetch_all(db)
	.await
	.db()?;
	Ok(rows.iter().map(row_to_channel).collect())
}

pub async fn read_channel(db: &SqlitePool, tn_id: TnId, name: &str) -> ClResult<Channel> {
	let row = sqlx::query(sqlx::AssertSqlSafe(format!(
		"SELECT {CHANNEL_COLS} FROM channels WHERE tn_id = ? AND name = ?"
	)))
	.bind(tn_id.0)
	.bind(name)
	.fetch_optional(db)
	.await
	.db()?;
	row.as_ref().map(row_to_channel).ok_or(Error::NotFound)
}

pub async fn create_channel(db: &SqlitePool, tn_id: TnId, channel: &Channel) -> ClResult<()> {
	let res = sqlx::query(
		"INSERT INTO channels (tn_id, name, title, descr, visibility, min_role, closed) \
		 VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(tn_id, name) DO NOTHING",
	)
	.bind(tn_id.0)
	.bind(channel.name.as_ref())
	.bind(channel.title.as_deref())
	.bind(channel.descr.as_deref())
	.bind(channel.visibility.map(|c| c.to_string()))
	.bind(channel.min_role.as_deref())
	.bind(i32::from(channel.closed))
	.execute(db)
	.await
	.db()?;

	if res.rows_affected() == 0 {
		return Err(Error::Conflict(format!("channel '{}' already exists", channel.name)));
	}
	Ok(())
}

pub async fn update_channel(
	db: &SqlitePool,
	tn_id: TnId,
	name: &str,
	patch: &UpdateChannelData,
) -> ClResult<()> {
	let mut query = sqlx::QueryBuilder::new("UPDATE channels SET ");
	let mut has_updates = false;
	has_updates = push_patch!(query, has_updates, "title", &patch.title);
	has_updates = push_patch!(query, has_updates, "descr", &patch.descr);
	has_updates =
		push_patch!(query, has_updates, "visibility", &patch.visibility, |c| c.to_string());
	has_updates = push_patch!(query, has_updates, "min_role", &patch.min_role);
	// `closed` is NOT NULL: a Null patch reopens the room.
	if let Some(closed) = match patch.closed {
		Patch::Undefined => None,
		Patch::Null => Some(false),
		Patch::Value(b) => Some(b),
	} {
		if has_updates {
			query.push(", ");
		}
		query.push("closed=").push_bind(i32::from(closed));
		has_updates = true;
	}

	if !has_updates {
		return Ok(());
	}

	query.push(", updated_at = unixepoch()");
	query.push(" WHERE tn_id = ").push_bind(tn_id.0);
	query.push(" AND name = ").push_bind(name);

	let res = query.build().execute(db).await.db()?;

	if res.rows_affected() == 0 {
		return Err(Error::NotFound);
	}
	Ok(())
}

/// Deletes the channel and its roster. Entity `channel` columns stay stamped.
pub async fn delete_channel(db: &SqlitePool, tn_id: TnId, name: &str) -> ClResult<()> {
	let mut tx = db.begin().await.db()?;
	sqlx::query("DELETE FROM channel_members WHERE tn_id = ? AND channel = ?")
		.bind(tn_id.0)
		.bind(name)
		.execute(&mut *tx)
		.await
		.db()?;
	let res = sqlx::query("DELETE FROM channels WHERE tn_id = ? AND name = ?")
		.bind(tn_id.0)
		.bind(name)
		.execute(&mut *tx)
		.await
		.db()?;
	tx.commit().await.db()?;

	if res.rows_affected() == 0 {
		return Err(Error::NotFound);
	}
	Ok(())
}

pub async fn list_channel_members(
	db: &SqlitePool,
	tn_id: TnId,
	name: &str,
) -> ClResult<Vec<Box<str>>> {
	let tags: Vec<String> = sqlx::query_scalar(
		"SELECT id_tag FROM channel_members WHERE tn_id = ? AND channel = ? ORDER BY id_tag",
	)
	.bind(tn_id.0)
	.bind(name)
	.fetch_all(db)
	.await
	.db()?;
	Ok(tags.into_iter().map(Into::into).collect())
}

pub async fn add_channel_member(
	db: &SqlitePool,
	tn_id: TnId,
	name: &str,
	id_tag: &str,
) -> ClResult<()> {
	sqlx::query(
		"INSERT INTO channel_members (tn_id, channel, id_tag) VALUES (?, ?, ?) \
		 ON CONFLICT(tn_id, channel, id_tag) DO NOTHING",
	)
	.bind(tn_id.0)
	.bind(name)
	.bind(id_tag)
	.execute(db)
	.await
	.db()?;
	Ok(())
}

pub async fn remove_channel_member(
	db: &SqlitePool,
	tn_id: TnId,
	name: &str,
	id_tag: &str,
) -> ClResult<()> {
	sqlx::query("DELETE FROM channel_members WHERE tn_id = ? AND channel = ? AND id_tag = ?")
		.bind(tn_id.0)
		.bind(name)
		.bind(id_tag)
		.execute(db)
		.await
		.db()?;
	Ok(())
}

pub async fn list_member_channels(
	db: &SqlitePool,
	tn_id: TnId,
	id_tag: &str,
) -> ClResult<Vec<Box<str>>> {
	let names: Vec<String> =
		sqlx::query_scalar("SELECT channel FROM channel_members WHERE tn_id = ? AND id_tag = ?")
			.bind(tn_id.0)
			.bind(id_tag)
			.fetch_all(db)
			.await
			.db()?;
	Ok(names.into_iter().map(Into::into).collect())
}

// vim: ts=4
