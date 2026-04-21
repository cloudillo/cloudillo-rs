// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Calendar and calendar-object database operations (CalDAV + JSON REST).
//!
//! Mirrors `contact.rs`: the `calendar_objects` table keeps the authoritative VCALENDAR blob
//! and a projected set of indexed columns (summary, dtstart, dtend, rrule, ...). The blob
//! round-trips unchanged; the projection powers list / time-range / `calendar-query` without
//! having to reparse text.
//!
//! Soft deletes (via `deleted_at`) leave tombstones so CalDAV `sync-collection` can tell
//! clients about removed objects.

use cloudillo_types::{
	meta_adapter::{
		Calendar, CalendarObject, CalendarObjectExtracted, CalendarObjectSyncEntry,
		CalendarObjectView, CreateCalendarData, ListCalendarObjectOptions, UpdateCalendarData,
	},
	prelude::*,
};
use sqlx::{Row, SqlitePool};

use crate::utils::{escape_like, push_patch};

// Calendars //
//***********//

pub async fn create_calendar(
	db: &SqlitePool,
	tn_id: TnId,
	input: &CreateCalendarData,
) -> ClResult<Calendar> {
	let components = input.components.as_deref().unwrap_or("VEVENT,VTODO");
	let row = sqlx::query(
		"INSERT INTO calendars (tn_id, name, description, color, timezone, components, ctag) \
		 VALUES (?, ?, ?, ?, ?, ?, lower(hex(randomblob(8)))) \
		 RETURNING cal_id, name, description, color, timezone, components, ctag, \
			created_at, updated_at",
	)
	.bind(tn_id.0)
	.bind(&input.name)
	.bind(input.description.as_deref())
	.bind(input.color.as_deref())
	.bind(input.timezone.as_deref())
	.bind(components)
	.fetch_one(db)
	.await
	.map_err(|e| {
		if let sqlx::Error::Database(dbe) = &e
			&& dbe.is_unique_violation()
		{
			return Error::Conflict(format!("Calendar '{}' already exists", input.name));
		}
		error!("DB: {e}");
		Error::DbError
	})?;

	Ok(row_to_calendar(&row))
}

pub async fn list_calendars(db: &SqlitePool, tn_id: TnId) -> ClResult<Vec<Calendar>> {
	let rows = sqlx::query(
		"SELECT cal_id, name, description, color, timezone, components, ctag, \
			created_at, updated_at \
		 FROM calendars WHERE tn_id = ? ORDER BY created_at ASC",
	)
	.bind(tn_id.0)
	.fetch_all(db)
	.await
	.inspect_err(|e| error!("DB: {e}"))
	.or(Err(Error::DbError))?;

	Ok(rows.iter().map(row_to_calendar).collect())
}

pub async fn get_calendar(db: &SqlitePool, tn_id: TnId, cal_id: u64) -> ClResult<Option<Calendar>> {
	let row = sqlx::query(
		"SELECT cal_id, name, description, color, timezone, components, ctag, \
			created_at, updated_at \
		 FROM calendars WHERE tn_id = ? AND cal_id = ?",
	)
	.bind(tn_id.0)
	.bind(cal_id.cast_signed())
	.fetch_optional(db)
	.await
	.inspect_err(|e| error!("DB: {e}"))
	.or(Err(Error::DbError))?;

	Ok(row.as_ref().map(row_to_calendar))
}

pub async fn get_calendar_by_name(
	db: &SqlitePool,
	tn_id: TnId,
	name: &str,
) -> ClResult<Option<Calendar>> {
	let row = sqlx::query(
		"SELECT cal_id, name, description, color, timezone, components, ctag, \
			created_at, updated_at \
		 FROM calendars WHERE tn_id = ? AND name = ?",
	)
	.bind(tn_id.0)
	.bind(name)
	.fetch_optional(db)
	.await
	.inspect_err(|e| error!("DB: {e}"))
	.or(Err(Error::DbError))?;

	Ok(row.as_ref().map(row_to_calendar))
}

pub async fn update_calendar(
	db: &SqlitePool,
	tn_id: TnId,
	cal_id: u64,
	patch: &UpdateCalendarData,
) -> ClResult<()> {
	let mut query = sqlx::QueryBuilder::new("UPDATE calendars SET ");
	let mut has_updates = false;
	has_updates = push_patch!(query, has_updates, "name", &patch.name);
	has_updates = push_patch!(query, has_updates, "description", &patch.description);
	has_updates = push_patch!(query, has_updates, "color", &patch.color);
	has_updates = push_patch!(query, has_updates, "timezone", &patch.timezone);
	has_updates = push_patch!(query, has_updates, "components", &patch.components);

	if !has_updates {
		return Ok(());
	}

	query.push(" WHERE tn_id = ").push_bind(tn_id.0);
	query.push(" AND cal_id = ").push_bind(cal_id.cast_signed());

	let res = query
		.build()
		.execute(db)
		.await
		.inspect_err(|e| error!("DB: {e}"))
		.or(Err(Error::DbError))?;

	if res.rows_affected() == 0 {
		return Err(Error::NotFound);
	}
	Ok(())
}

pub async fn delete_calendar(db: &SqlitePool, tn_id: TnId, cal_id: u64) -> ClResult<()> {
	let mut tx = db.begin().await.or(Err(Error::DbError))?;
	sqlx::query("DELETE FROM calendar_objects WHERE tn_id = ? AND cal_id = ?")
		.bind(tn_id.0)
		.bind(cal_id.cast_signed())
		.execute(&mut *tx)
		.await
		.inspect_err(|e| error!("DB: {e}"))
		.or(Err(Error::DbError))?;
	let res = sqlx::query("DELETE FROM calendars WHERE tn_id = ? AND cal_id = ?")
		.bind(tn_id.0)
		.bind(cal_id.cast_signed())
		.execute(&mut *tx)
		.await
		.inspect_err(|e| error!("DB: {e}"))
		.or(Err(Error::DbError))?;
	tx.commit().await.or(Err(Error::DbError))?;

	if res.rows_affected() == 0 {
		return Err(Error::NotFound);
	}
	Ok(())
}

fn row_to_calendar(row: &sqlx::sqlite::SqliteRow) -> Calendar {
	Calendar {
		cal_id: row.get::<i64, _>("cal_id").cast_unsigned(),
		name: row.get::<String, _>("name").into(),
		description: row.get::<Option<String>, _>("description").map(Into::into),
		color: row.get::<Option<String>, _>("color").map(Into::into),
		timezone: row.get::<Option<String>, _>("timezone").map(Into::into),
		components: row.get::<String, _>("components").into(),
		ctag: row.get::<String, _>("ctag").into(),
		created_at: Timestamp(row.get::<i64, _>("created_at")),
		updated_at: Timestamp(row.get::<i64, _>("updated_at")),
	}
}

// Calendar objects //
//******************//

/// Column list for SELECT — keeps the three row→struct mappings below in sync.
const OBJECT_COLS: &str = "co_id, cal_id, uid, etag, component, summary, location, description, \
	dtstart, dtend, all_day, status, priority, organizer, rrule, exdate, recurrence_id, sequence, \
	created_at, updated_at";

/// Decode the `exdate` CSV column (unix-second timestamps) into a `Vec<Timestamp>`.
fn parse_exdate_csv(raw: Option<&str>) -> Vec<Timestamp> {
	let Some(raw) = raw else { return Vec::new() };
	raw.split(',')
		.filter_map(|s| s.trim().parse::<i64>().ok())
		.map(Timestamp)
		.collect()
}

/// Encode `Vec<Timestamp>` as comma-separated unix seconds for the `exdate` column.
fn format_exdate_csv(ts: &[Timestamp]) -> Option<String> {
	if ts.is_empty() {
		None
	} else {
		Some(ts.iter().map(|t| t.0.to_string()).collect::<Vec<_>>().join(","))
	}
}

fn read_extracted(row: &sqlx::sqlite::SqliteRow) -> CalendarObjectExtracted {
	CalendarObjectExtracted {
		component: row.get::<String, _>("component").into(),
		summary: row.get::<Option<String>, _>("summary").map(Into::into),
		location: row.get::<Option<String>, _>("location").map(Into::into),
		description: row.get::<Option<String>, _>("description").map(Into::into),
		dtstart: row.get::<Option<i64>, _>("dtstart").map(Timestamp),
		dtend: row.get::<Option<i64>, _>("dtend").map(Timestamp),
		all_day: row.get::<i64, _>("all_day") != 0,
		status: row.get::<Option<String>, _>("status").map(Into::into),
		priority: row.get::<Option<i64>, _>("priority").and_then(|p| u8::try_from(p).ok()),
		organizer: row.get::<Option<String>, _>("organizer").map(Into::into),
		rrule: row.get::<Option<String>, _>("rrule").map(Into::into),
		exdate: parse_exdate_csv(row.get::<Option<String>, _>("exdate").as_deref()),
		recurrence_id: row.get::<Option<i64>, _>("recurrence_id").map(Timestamp),
		sequence: row.get::<i64, _>("sequence"),
	}
}

fn row_to_view(row: &sqlx::sqlite::SqliteRow) -> CalendarObjectView {
	CalendarObjectView {
		co_id: row.get::<i64, _>("co_id").cast_unsigned(),
		cal_id: row.get::<i64, _>("cal_id").cast_unsigned(),
		uid: row.get::<String, _>("uid").into(),
		etag: row.get::<String, _>("etag").into(),
		extracted: read_extracted(row),
		created_at: Timestamp(row.get::<i64, _>("created_at")),
		updated_at: Timestamp(row.get::<i64, _>("updated_at")),
	}
}

fn row_to_object(row: &sqlx::sqlite::SqliteRow) -> CalendarObject {
	CalendarObject {
		co_id: row.get::<i64, _>("co_id").cast_unsigned(),
		cal_id: row.get::<i64, _>("cal_id").cast_unsigned(),
		uid: row.get::<String, _>("uid").into(),
		etag: row.get::<String, _>("etag").into(),
		ical: row.get::<String, _>("ical").into(),
		extracted: read_extracted(row),
		created_at: Timestamp(row.get::<i64, _>("created_at")),
		updated_at: Timestamp(row.get::<i64, _>("updated_at")),
	}
}

pub async fn list_calendar_objects(
	db: &SqlitePool,
	tn_id: TnId,
	cal_id: u64,
	opts: &ListCalendarObjectOptions,
) -> ClResult<Vec<CalendarObjectView>> {
	let mut query = sqlx::QueryBuilder::new("SELECT ");
	query.push(OBJECT_COLS);
	query.push(" FROM calendar_objects WHERE tn_id = ").push_bind(tn_id.0);
	query.push(" AND cal_id = ").push_bind(cal_id.cast_signed());
	query.push(" AND deleted_at IS NULL");
	if !opts.include_exceptions {
		query.push(" AND recurrence_id IS NULL");
	}

	if let Some(comp) = opts.component.as_deref()
		&& !comp.is_empty()
	{
		query.push(" AND component = ").push_bind(comp.to_string());
	}

	if let Some(q) = opts.q.as_deref()
		&& !q.is_empty()
	{
		let pattern = format!("%{}%", escape_like(q));
		query.push(" AND (summary LIKE ");
		query.push_bind(pattern.clone());
		query.push(" ESCAPE '\\' OR location LIKE ");
		query.push_bind(pattern.clone());
		query.push(" ESCAPE '\\' OR description LIKE ");
		query.push_bind(pattern);
		query.push(" ESCAPE '\\')");
	}

	// Time-range superset: any object whose master dtstart ≤ end AND
	// (rrule IS NOT NULL OR dtend IS NULL OR dtend ≥ start).
	if let Some(end) = opts.end {
		query.push(" AND (dtstart IS NULL OR dtstart <= ").push_bind(end.0);
		query.push(")");
	}
	if let Some(start) = opts.start {
		query
			.push(" AND (rrule IS NOT NULL OR dtend IS NULL OR dtend >= ")
			.push_bind(start.0);
		query.push(")");
	}

	if let Some(cursor) = opts.cursor.as_deref() {
		let co_id: i64 =
			cursor.parse().map_err(|_| Error::ValidationError("Invalid cursor".into()))?;
		query.push(" AND co_id > ").push_bind(co_id);
	}

	query.push(" ORDER BY co_id ASC");
	let limit = opts.limit.unwrap_or(200).min(1000);
	query.push(" LIMIT ").push_bind(i64::from(limit) + 1);

	let rows = query
		.build()
		.fetch_all(db)
		.await
		.inspect_err(|e| error!("DB: {e}"))
		.or(Err(Error::DbError))?;

	Ok(rows.iter().map(row_to_view).collect())
}

pub async fn get_calendar_object(
	db: &SqlitePool,
	tn_id: TnId,
	cal_id: u64,
	uid: &str,
) -> ClResult<Option<CalendarObject>> {
	let row = sqlx::query(&format!(
		"SELECT {OBJECT_COLS}, ical FROM calendar_objects \
		 WHERE tn_id = ? AND cal_id = ? AND uid = ? AND recurrence_id IS NULL \
		 AND deleted_at IS NULL",
	))
	.bind(tn_id.0)
	.bind(cal_id.cast_signed())
	.bind(uid)
	.fetch_optional(db)
	.await
	.inspect_err(|e| error!("DB: {e}"))
	.or(Err(Error::DbError))?;

	Ok(row.as_ref().map(row_to_object))
}

pub async fn get_calendar_object_override(
	db: &SqlitePool,
	tn_id: TnId,
	cal_id: u64,
	uid: &str,
	recurrence_id: Timestamp,
) -> ClResult<Option<CalendarObject>> {
	let row = sqlx::query(&format!(
		"SELECT {OBJECT_COLS}, ical FROM calendar_objects \
		 WHERE tn_id = ? AND cal_id = ? AND uid = ? AND recurrence_id = ? \
		 AND deleted_at IS NULL",
	))
	.bind(tn_id.0)
	.bind(cal_id.cast_signed())
	.bind(uid)
	.bind(recurrence_id.0)
	.fetch_optional(db)
	.await
	.inspect_err(|e| error!("DB: {e}"))
	.or(Err(Error::DbError))?;

	Ok(row.as_ref().map(row_to_object))
}

pub async fn list_calendar_object_overrides(
	db: &SqlitePool,
	tn_id: TnId,
	cal_id: u64,
	uid: &str,
) -> ClResult<Vec<CalendarObject>> {
	let rows = sqlx::query(&format!(
		"SELECT {OBJECT_COLS}, ical FROM calendar_objects \
		 WHERE tn_id = ? AND cal_id = ? AND uid = ? AND recurrence_id IS NOT NULL \
		 AND deleted_at IS NULL ORDER BY recurrence_id ASC",
	))
	.bind(tn_id.0)
	.bind(cal_id.cast_signed())
	.bind(uid)
	.fetch_all(db)
	.await
	.inspect_err(|e| error!("DB: {e}"))
	.or(Err(Error::DbError))?;

	Ok(rows.iter().map(row_to_object).collect())
}

pub async fn delete_calendar_object_override(
	db: &SqlitePool,
	tn_id: TnId,
	cal_id: u64,
	uid: &str,
	recurrence_id: Timestamp,
) -> ClResult<()> {
	let mut tx = db.begin().await.or(Err(Error::DbError))?;

	let res = sqlx::query(
		"UPDATE calendar_objects SET deleted_at = unixepoch() \
		 WHERE tn_id = ? AND cal_id = ? AND uid = ? AND recurrence_id = ? \
		 AND deleted_at IS NULL",
	)
	.bind(tn_id.0)
	.bind(cal_id.cast_signed())
	.bind(uid)
	.bind(recurrence_id.0)
	.execute(&mut *tx)
	.await
	.inspect_err(|e| error!("DB: {e}"))
	.or(Err(Error::DbError))?;

	if res.rows_affected() == 0 {
		return Err(Error::NotFound);
	}

	sqlx::query(
		"UPDATE calendars SET ctag = lower(hex(randomblob(8))) \
		 WHERE tn_id = ? AND cal_id = ?",
	)
	.bind(tn_id.0)
	.bind(cal_id.cast_signed())
	.execute(&mut *tx)
	.await
	.inspect_err(|e| error!("DB: {e}"))
	.or(Err(Error::DbError))?;

	tx.commit().await.or(Err(Error::DbError))?;
	Ok(())
}

/// Shared INSERT prefix for `upsert_calendar_object` — the two call sites (master /
/// override) differ only in the `ON CONFLICT` target, which is appended per branch.
const UPSERT_INSERT_PREFIX: &str = "INSERT INTO calendar_objects (tn_id, cal_id, uid, component, etag, ical, \
		summary, location, description, dtstart, dtend, all_day, status, priority, \
		organizer, rrule, exdate, recurrence_id, sequence, deleted_at) \
	 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL) ";

const UPSERT_UPDATE_SET: &str = "DO UPDATE SET \
		component = excluded.component, \
		etag = excluded.etag, \
		ical = excluded.ical, \
		summary = excluded.summary, \
		location = excluded.location, \
		description = excluded.description, \
		dtstart = excluded.dtstart, \
		dtend = excluded.dtend, \
		all_day = excluded.all_day, \
		status = excluded.status, \
		priority = excluded.priority, \
		organizer = excluded.organizer, \
		rrule = excluded.rrule, \
		exdate = excluded.exdate, \
		sequence = excluded.sequence, \
		deleted_at = NULL";

pub async fn upsert_calendar_object(
	db: &SqlitePool,
	tn_id: TnId,
	cal_id: u64,
	uid: &str,
	ical: &str,
	etag: &str,
	extracted: &CalendarObjectExtracted,
) -> ClResult<Box<str>> {
	let mut tx = db.begin().await.or(Err(Error::DbError))?;

	// Masters (recurrence_id NULL) and overrides (recurrence_id set) have distinct
	// partial unique indexes — SQLite's NULL-distinct rule means a single conflict
	// target can't cover both. Pick the right one for this write.
	let sql = if extracted.recurrence_id.is_none() {
		format!(
			"{UPSERT_INSERT_PREFIX}ON CONFLICT(tn_id, cal_id, uid) \
			 WHERE recurrence_id IS NULL AND deleted_at IS NULL {UPSERT_UPDATE_SET}"
		)
	} else {
		format!(
			"{UPSERT_INSERT_PREFIX}ON CONFLICT(tn_id, cal_id, uid, recurrence_id) \
			 WHERE recurrence_id IS NOT NULL AND deleted_at IS NULL {UPSERT_UPDATE_SET}"
		)
	};
	sqlx::query(&sql)
		.bind(tn_id.0)
		.bind(cal_id.cast_signed())
		.bind(uid)
		.bind(extracted.component.as_ref())
		.bind(etag)
		.bind(ical)
		.bind(extracted.summary.as_deref())
		.bind(extracted.location.as_deref())
		.bind(extracted.description.as_deref())
		.bind(extracted.dtstart.map(|t| t.0))
		.bind(extracted.dtend.map(|t| t.0))
		.bind(i64::from(extracted.all_day))
		.bind(extracted.status.as_deref())
		.bind(extracted.priority.map(i64::from))
		.bind(extracted.organizer.as_deref())
		.bind(extracted.rrule.as_deref())
		.bind(format_exdate_csv(&extracted.exdate))
		.bind(extracted.recurrence_id.map(|t| t.0))
		.bind(extracted.sequence)
		.execute(&mut *tx)
		.await
		.inspect_err(|e| error!("DB: {e}"))
		.or(Err(Error::DbError))?;

	sqlx::query(
		"UPDATE calendars SET ctag = lower(hex(randomblob(8))) \
		 WHERE tn_id = ? AND cal_id = ?",
	)
	.bind(tn_id.0)
	.bind(cal_id.cast_signed())
	.execute(&mut *tx)
	.await
	.inspect_err(|e| error!("DB: {e}"))
	.or(Err(Error::DbError))?;

	let stored_etag: String = sqlx::query_scalar(
		"SELECT etag FROM calendar_objects \
		 WHERE tn_id = ? AND cal_id = ? AND uid = ? AND recurrence_id IS ?",
	)
	.bind(tn_id.0)
	.bind(cal_id.cast_signed())
	.bind(uid)
	.bind(extracted.recurrence_id.map(|t| t.0))
	.fetch_one(&mut *tx)
	.await
	.inspect_err(|e| error!("DB: {e}"))
	.or(Err(Error::DbError))?;

	tx.commit().await.or(Err(Error::DbError))?;

	Ok(stored_etag.into_boxed_str())
}

pub async fn delete_calendar_object(
	db: &SqlitePool,
	tn_id: TnId,
	cal_id: u64,
	uid: &str,
) -> ClResult<()> {
	let mut tx = db.begin().await.or(Err(Error::DbError))?;

	let res = sqlx::query(
		"UPDATE calendar_objects SET deleted_at = unixepoch() \
		 WHERE tn_id = ? AND cal_id = ? AND uid = ? AND deleted_at IS NULL",
	)
	.bind(tn_id.0)
	.bind(cal_id.cast_signed())
	.bind(uid)
	.execute(&mut *tx)
	.await
	.inspect_err(|e| error!("DB: {e}"))
	.or(Err(Error::DbError))?;

	if res.rows_affected() == 0 {
		return Err(Error::NotFound);
	}

	sqlx::query(
		"UPDATE calendars SET ctag = lower(hex(randomblob(8))) \
		 WHERE tn_id = ? AND cal_id = ?",
	)
	.bind(tn_id.0)
	.bind(cal_id.cast_signed())
	.execute(&mut *tx)
	.await
	.inspect_err(|e| error!("DB: {e}"))
	.or(Err(Error::DbError))?;

	tx.commit().await.or(Err(Error::DbError))?;
	Ok(())
}

pub async fn get_calendar_objects_by_uids(
	db: &SqlitePool,
	tn_id: TnId,
	cal_id: u64,
	uids: &[&str],
) -> ClResult<Vec<CalendarObject>> {
	if uids.is_empty() {
		return Ok(Vec::new());
	}

	let mut query = sqlx::QueryBuilder::new("SELECT ");
	query.push(OBJECT_COLS);
	query.push(", ical FROM calendar_objects WHERE tn_id = ").push_bind(tn_id.0);
	query.push(" AND cal_id = ").push_bind(cal_id.cast_signed());
	query.push(" AND deleted_at IS NULL AND recurrence_id IS NULL AND uid IN (");
	for (i, uid) in uids.iter().enumerate() {
		if i > 0 {
			query.push(", ");
		}
		query.push_bind(*uid);
	}
	query.push(")");

	let rows = query
		.build()
		.fetch_all(db)
		.await
		.inspect_err(|e| error!("DB: {e}"))
		.or(Err(Error::DbError))?;

	Ok(rows.iter().map(row_to_object).collect())
}

/// List changes since the given sync token. See `contact::list_contacts_since` — same
/// inclusive `>=` semantics.
pub async fn list_calendar_objects_since(
	db: &SqlitePool,
	tn_id: TnId,
	cal_id: u64,
	since: Option<Timestamp>,
	limit: Option<u32>,
) -> ClResult<Vec<CalendarObjectSyncEntry>> {
	let mut query = sqlx::QueryBuilder::new(
		"SELECT uid, etag, deleted_at, updated_at FROM calendar_objects \
			 WHERE tn_id = ",
	);
	query.push_bind(tn_id.0);
	query.push(" AND cal_id = ").push_bind(cal_id.cast_signed());
	query.push(" AND recurrence_id IS NULL");
	if let Some(ts) = since {
		query.push(" AND updated_at >= ").push_bind(ts.0);
	} else {
		query.push(" AND deleted_at IS NULL");
	}
	query.push(" ORDER BY updated_at ASC, co_id ASC");
	if let Some(n) = limit {
		query.push(" LIMIT ").push_bind(i64::from(n));
	}

	let rows = query
		.build()
		.fetch_all(db)
		.await
		.inspect_err(|e| error!("DB: {e}"))
		.or(Err(Error::DbError))?;

	Ok(rows
		.into_iter()
		.map(|row| CalendarObjectSyncEntry {
			uid: row.get::<String, _>("uid").into(),
			etag: row.get::<String, _>("etag").into(),
			deleted: row.get::<Option<i64>, _>("deleted_at").is_some(),
			updated_at: Timestamp(row.get::<i64, _>("updated_at")),
		})
		.collect())
}

pub async fn query_calendar_objects_in_range(
	db: &SqlitePool,
	tn_id: TnId,
	cal_id: u64,
	component: Option<&str>,
	start: Option<Timestamp>,
	end: Option<Timestamp>,
) -> ClResult<Vec<CalendarObject>> {
	let mut query = sqlx::QueryBuilder::new("SELECT ");
	query.push(OBJECT_COLS);
	query.push(", ical FROM calendar_objects WHERE tn_id = ").push_bind(tn_id.0);
	query.push(" AND cal_id = ").push_bind(cal_id.cast_signed());
	query.push(" AND deleted_at IS NULL AND recurrence_id IS NULL");

	if let Some(comp) = component
		&& !comp.is_empty()
	{
		query.push(" AND component = ").push_bind(comp.to_string());
	}
	if let Some(end) = end {
		query.push(" AND (dtstart IS NULL OR dtstart <= ").push_bind(end.0);
		query.push(")");
	}
	if let Some(start) = start {
		query
			.push(" AND (rrule IS NOT NULL OR dtend IS NULL OR dtend >= ")
			.push_bind(start.0);
		query.push(")");
	}

	query.push(" ORDER BY dtstart ASC, co_id ASC");

	let rows = query
		.build()
		.fetch_all(db)
		.await
		.inspect_err(|e| error!("DB: {e}"))
		.or(Err(Error::DbError))?;

	Ok(rows.iter().map(row_to_object).collect())
}

// vim: ts=4
