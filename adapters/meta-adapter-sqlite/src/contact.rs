// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Address book and contact database operations (CardDAV + JSON REST).
//!
//! The `contacts` table keeps both the authoritative vCard blob and a projected set of
//! indexed columns (fn_name, emails, tels, ...). The vCard round-trips unchanged; the
//! projection powers list/search and CardDAV REPORTs without having to reparse text.
//!
//! Soft deletes (via `deleted_at`) leave tombstones so CardDAV `sync-collection` can tell
//! clients about removed cards.

use cloudillo_types::{
	meta_adapter::{
		AddressBook, Contact, ContactExtracted, ContactSyncEntry, ContactView, ListContactOptions,
		UpdateAddressBookData,
	},
	prelude::*,
};
use sqlx::{Row, SqlitePool};

use crate::utils::{escape_like, push_patch};

// Address Books //
//***************//

pub async fn create_address_book(
	db: &SqlitePool,
	tn_id: TnId,
	name: &str,
	description: Option<&str>,
) -> ClResult<AddressBook> {
	let row = sqlx::query(
		"INSERT INTO address_books (tn_id, name, description, ctag) \
		 VALUES (?, ?, ?, lower(hex(randomblob(8)))) \
		 RETURNING ab_id, name, description, ctag, created_at, updated_at",
	)
	.bind(tn_id.0)
	.bind(name)
	.bind(description)
	.fetch_one(db)
	.await
	.map_err(|e| {
		if let sqlx::Error::Database(dbe) = &e
			&& dbe.is_unique_violation()
		{
			return Error::Conflict(format!("Address book '{name}' already exists"));
		}
		error!("DB: {e}");
		Error::DbError
	})?;

	Ok(AddressBook {
		ab_id: row.get::<i64, _>("ab_id").cast_unsigned(),
		name: row.get::<String, _>("name").into(),
		description: row.get::<Option<String>, _>("description").map(Into::into),
		ctag: row.get::<String, _>("ctag").into(),
		created_at: Timestamp(row.get::<i64, _>("created_at")),
		updated_at: Timestamp(row.get::<i64, _>("updated_at")),
	})
}

pub async fn list_address_books(db: &SqlitePool, tn_id: TnId) -> ClResult<Vec<AddressBook>> {
	let rows = sqlx::query(
		"SELECT ab_id, name, description, ctag, created_at, updated_at \
		 FROM address_books WHERE tn_id = ? ORDER BY created_at ASC",
	)
	.bind(tn_id.0)
	.fetch_all(db)
	.await
	.inspect_err(|e| error!("DB: {e}"))
	.or(Err(Error::DbError))?;

	Ok(rows
		.into_iter()
		.map(|row| AddressBook {
			ab_id: row.get::<i64, _>("ab_id").cast_unsigned(),
			name: row.get::<String, _>("name").into(),
			description: row.get::<Option<String>, _>("description").map(Into::into),
			ctag: row.get::<String, _>("ctag").into(),
			created_at: Timestamp(row.get::<i64, _>("created_at")),
			updated_at: Timestamp(row.get::<i64, _>("updated_at")),
		})
		.collect())
}

pub async fn get_address_book(
	db: &SqlitePool,
	tn_id: TnId,
	ab_id: u64,
) -> ClResult<Option<AddressBook>> {
	let row = sqlx::query(
		"SELECT ab_id, name, description, ctag, created_at, updated_at \
		 FROM address_books WHERE tn_id = ? AND ab_id = ?",
	)
	.bind(tn_id.0)
	.bind(ab_id.cast_signed())
	.fetch_optional(db)
	.await
	.inspect_err(|e| error!("DB: {e}"))
	.or(Err(Error::DbError))?;

	Ok(row.map(|row| AddressBook {
		ab_id: row.get::<i64, _>("ab_id").cast_unsigned(),
		name: row.get::<String, _>("name").into(),
		description: row.get::<Option<String>, _>("description").map(Into::into),
		ctag: row.get::<String, _>("ctag").into(),
		created_at: Timestamp(row.get::<i64, _>("created_at")),
		updated_at: Timestamp(row.get::<i64, _>("updated_at")),
	}))
}

pub async fn get_address_book_by_name(
	db: &SqlitePool,
	tn_id: TnId,
	name: &str,
) -> ClResult<Option<AddressBook>> {
	let row = sqlx::query(
		"SELECT ab_id, name, description, ctag, created_at, updated_at \
		 FROM address_books WHERE tn_id = ? AND name = ?",
	)
	.bind(tn_id.0)
	.bind(name)
	.fetch_optional(db)
	.await
	.inspect_err(|e| error!("DB: {e}"))
	.or(Err(Error::DbError))?;

	Ok(row.map(|row| AddressBook {
		ab_id: row.get::<i64, _>("ab_id").cast_unsigned(),
		name: row.get::<String, _>("name").into(),
		description: row.get::<Option<String>, _>("description").map(Into::into),
		ctag: row.get::<String, _>("ctag").into(),
		created_at: Timestamp(row.get::<i64, _>("created_at")),
		updated_at: Timestamp(row.get::<i64, _>("updated_at")),
	}))
}

pub async fn update_address_book(
	db: &SqlitePool,
	tn_id: TnId,
	ab_id: u64,
	patch: &UpdateAddressBookData,
) -> ClResult<()> {
	let mut query = sqlx::QueryBuilder::new("UPDATE address_books SET ");
	let mut has_updates = false;
	has_updates = push_patch!(query, has_updates, "name", &patch.name);
	has_updates = push_patch!(query, has_updates, "description", &patch.description);

	if !has_updates {
		return Ok(());
	}

	query.push(" WHERE tn_id = ").push_bind(tn_id.0);
	query.push(" AND ab_id = ").push_bind(ab_id.cast_signed());

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

pub async fn delete_address_book(db: &SqlitePool, tn_id: TnId, ab_id: u64) -> ClResult<()> {
	let mut tx = db.begin().await.or(Err(Error::DbError))?;
	sqlx::query("DELETE FROM contacts WHERE tn_id = ? AND ab_id = ?")
		.bind(tn_id.0)
		.bind(ab_id.cast_signed())
		.execute(&mut *tx)
		.await
		.inspect_err(|e| error!("DB: {e}"))
		.or(Err(Error::DbError))?;
	let res = sqlx::query("DELETE FROM address_books WHERE tn_id = ? AND ab_id = ?")
		.bind(tn_id.0)
		.bind(ab_id.cast_signed())
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

// Contacts //
//**********//

/// Column list for SELECT — keeps the three row→struct mappings below in sync.
const CONTACT_COLS: &str = "c_id, ab_id, uid, etag, fn_name, given_name, family_name, email, emails, tel, tels, \
	 org, title, note, photo_uri, profile_id_tag, created_at, updated_at";

fn read_extracted(row: &sqlx::sqlite::SqliteRow) -> ContactExtracted {
	ContactExtracted {
		fn_name: row.get::<Option<String>, _>("fn_name").map(Into::into),
		given_name: row.get::<Option<String>, _>("given_name").map(Into::into),
		family_name: row.get::<Option<String>, _>("family_name").map(Into::into),
		email: row.get::<Option<String>, _>("email").map(Into::into),
		emails: row.get::<Option<String>, _>("emails").map(Into::into),
		tel: row.get::<Option<String>, _>("tel").map(Into::into),
		tels: row.get::<Option<String>, _>("tels").map(Into::into),
		org: row.get::<Option<String>, _>("org").map(Into::into),
		title: row.get::<Option<String>, _>("title").map(Into::into),
		note: row.get::<Option<String>, _>("note").map(Into::into),
		photo_uri: row.get::<Option<String>, _>("photo_uri").map(Into::into),
		profile_id_tag: row.get::<Option<String>, _>("profile_id_tag").map(Into::into),
	}
}

fn row_to_view(row: &sqlx::sqlite::SqliteRow) -> ContactView {
	ContactView {
		c_id: row.get::<i64, _>("c_id").cast_unsigned(),
		ab_id: row.get::<i64, _>("ab_id").cast_unsigned(),
		uid: row.get::<String, _>("uid").into(),
		etag: row.get::<String, _>("etag").into(),
		extracted: read_extracted(row),
		created_at: Timestamp(row.get::<i64, _>("created_at")),
		updated_at: Timestamp(row.get::<i64, _>("updated_at")),
	}
}

fn row_to_contact(row: &sqlx::sqlite::SqliteRow) -> Contact {
	Contact {
		c_id: row.get::<i64, _>("c_id").cast_unsigned(),
		ab_id: row.get::<i64, _>("ab_id").cast_unsigned(),
		uid: row.get::<String, _>("uid").into(),
		etag: row.get::<String, _>("etag").into(),
		vcard: row.get::<String, _>("vcard").into(),
		extracted: read_extracted(row),
		created_at: Timestamp(row.get::<i64, _>("created_at")),
		updated_at: Timestamp(row.get::<i64, _>("updated_at")),
	}
}

pub async fn list_contacts(
	db: &SqlitePool,
	tn_id: TnId,
	ab_id: Option<u64>,
	opts: &ListContactOptions,
) -> ClResult<Vec<ContactView>> {
	let mut query = sqlx::QueryBuilder::new("SELECT ");
	query.push(CONTACT_COLS);
	query.push(" FROM contacts WHERE tn_id = ").push_bind(tn_id.0);
	if let Some(id) = ab_id {
		query.push(" AND ab_id = ").push_bind(id.cast_signed());
	}
	query.push(" AND deleted_at IS NULL");

	if let Some(q) = opts.q.as_deref()
		&& !q.is_empty()
	{
		let pattern = format!("%{}%", escape_like(q));
		query.push(" AND (fn_name LIKE ");
		query.push_bind(pattern.clone());
		query.push(" ESCAPE '\\' OR emails LIKE ");
		query.push_bind(pattern.clone());
		query.push(" ESCAPE '\\' OR tels LIKE ");
		query.push_bind(pattern);
		query.push(" ESCAPE '\\')");
	}

	if ab_id.is_some() {
		// Single-book mode: cursor by c_id, ordered by c_id.
		if let Some(cursor) = opts.cursor.as_deref() {
			let c_id: i64 =
				cursor.parse().map_err(|_| Error::ValidationError("Invalid cursor".into()))?;
			query.push(" AND c_id > ").push_bind(c_id);
		}
		query.push(" ORDER BY c_id ASC");
	} else {
		// All-books mode: name-sorted with keyset pagination on (fn_name, c_id).
		if let Some(cursor) = opts.cursor.as_deref() {
			let c_id: i64 =
				cursor.parse().map_err(|_| Error::ValidationError("Invalid cursor".into()))?;
			query.push(" AND (COALESCE(fn_name, '') > COALESCE((");
			query.push("SELECT COALESCE(fn_name, '') FROM contacts WHERE c_id = ");
			query.push_bind(c_id);
			query.push("), '') OR (COALESCE(fn_name, '') = COALESCE((");
			query.push("SELECT COALESCE(fn_name, '') FROM contacts WHERE c_id = ");
			query.push_bind(c_id);
			query.push("), '') AND c_id > ");
			query.push_bind(c_id);
			query.push("))");
		}
		query.push(" ORDER BY COALESCE(fn_name, '') ASC, c_id ASC");
	}

	// Fetch limit+1 so the handler can tell real "there's more" from exact-fit pages.
	let limit = opts.limit.unwrap_or(100).min(500);
	query.push(" LIMIT ").push_bind(i64::from(limit) + 1);

	let rows = query
		.build()
		.fetch_all(db)
		.await
		.inspect_err(|e| error!("DB: {e}"))
		.or(Err(Error::DbError))?;

	Ok(rows.iter().map(row_to_view).collect())
}

pub async fn get_contact(
	db: &SqlitePool,
	tn_id: TnId,
	ab_id: u64,
	uid: &str,
) -> ClResult<Option<Contact>> {
	let row = sqlx::query(&format!(
		"SELECT {CONTACT_COLS}, vcard FROM contacts \
		 WHERE tn_id = ? AND ab_id = ? AND uid = ? AND deleted_at IS NULL",
	))
	.bind(tn_id.0)
	.bind(ab_id.cast_signed())
	.bind(uid)
	.fetch_optional(db)
	.await
	.inspect_err(|e| error!("DB: {e}"))
	.or(Err(Error::DbError))?;

	Ok(row.as_ref().map(row_to_contact))
}

#[allow(clippy::too_many_arguments)]
pub async fn upsert_contact(
	db: &SqlitePool,
	tn_id: TnId,
	ab_id: u64,
	uid: &str,
	vcard: &str,
	etag: &str,
	extracted: &ContactExtracted,
) -> ClResult<Box<str>> {
	let mut tx = db.begin().await.or(Err(Error::DbError))?;

	sqlx::query(
		"INSERT INTO contacts (tn_id, ab_id, uid, etag, vcard, \
			fn_name, given_name, family_name, email, emails, tel, tels, \
			org, title, note, photo_uri, profile_id_tag, deleted_at) \
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL) \
		 ON CONFLICT(tn_id, ab_id, uid) DO UPDATE SET \
			etag = excluded.etag, \
			vcard = excluded.vcard, \
			fn_name = excluded.fn_name, \
			given_name = excluded.given_name, \
			family_name = excluded.family_name, \
			email = excluded.email, \
			emails = excluded.emails, \
			tel = excluded.tel, \
			tels = excluded.tels, \
			org = excluded.org, \
			title = excluded.title, \
			note = excluded.note, \
			photo_uri = excluded.photo_uri, \
			profile_id_tag = excluded.profile_id_tag, \
			deleted_at = NULL",
	)
	.bind(tn_id.0)
	.bind(ab_id.cast_signed())
	.bind(uid)
	.bind(etag)
	.bind(vcard)
	.bind(extracted.fn_name.as_deref())
	.bind(extracted.given_name.as_deref())
	.bind(extracted.family_name.as_deref())
	.bind(extracted.email.as_deref())
	.bind(extracted.emails.as_deref())
	.bind(extracted.tel.as_deref())
	.bind(extracted.tels.as_deref())
	.bind(extracted.org.as_deref())
	.bind(extracted.title.as_deref())
	.bind(extracted.note.as_deref())
	.bind(extracted.photo_uri.as_deref())
	.bind(extracted.profile_id_tag.as_deref())
	.execute(&mut *tx)
	.await
	.inspect_err(|e| error!("DB: {e}"))
	.or(Err(Error::DbError))?;

	sqlx::query(
		"UPDATE address_books SET ctag = lower(hex(randomblob(8))) \
		 WHERE tn_id = ? AND ab_id = ?",
	)
	.bind(tn_id.0)
	.bind(ab_id.cast_signed())
	.execute(&mut *tx)
	.await
	.inspect_err(|e| error!("DB: {e}"))
	.or(Err(Error::DbError))?;

	let stored_etag: String = sqlx::query_scalar(
		"SELECT etag FROM contacts \
		 WHERE tn_id = ? AND ab_id = ? AND uid = ?",
	)
	.bind(tn_id.0)
	.bind(ab_id.cast_signed())
	.bind(uid)
	.fetch_one(&mut *tx)
	.await
	.inspect_err(|e| error!("DB: {e}"))
	.or(Err(Error::DbError))?;

	tx.commit().await.or(Err(Error::DbError))?;

	Ok(stored_etag.into_boxed_str())
}

pub async fn delete_contact(db: &SqlitePool, tn_id: TnId, ab_id: u64, uid: &str) -> ClResult<()> {
	let mut tx = db.begin().await.or(Err(Error::DbError))?;

	let res = sqlx::query(
		"UPDATE contacts SET deleted_at = unixepoch() \
		 WHERE tn_id = ? AND ab_id = ? AND uid = ? AND deleted_at IS NULL",
	)
	.bind(tn_id.0)
	.bind(ab_id.cast_signed())
	.bind(uid)
	.execute(&mut *tx)
	.await
	.inspect_err(|e| error!("DB: {e}"))
	.or(Err(Error::DbError))?;

	if res.rows_affected() == 0 {
		return Err(Error::NotFound);
	}

	sqlx::query(
		"UPDATE address_books SET ctag = lower(hex(randomblob(8))) \
		 WHERE tn_id = ? AND ab_id = ?",
	)
	.bind(tn_id.0)
	.bind(ab_id.cast_signed())
	.execute(&mut *tx)
	.await
	.inspect_err(|e| error!("DB: {e}"))
	.or(Err(Error::DbError))?;

	tx.commit().await.or(Err(Error::DbError))?;
	Ok(())
}

pub async fn get_contacts_by_uids(
	db: &SqlitePool,
	tn_id: TnId,
	ab_id: u64,
	uids: &[&str],
) -> ClResult<Vec<Contact>> {
	if uids.is_empty() {
		return Ok(Vec::new());
	}

	let mut query = sqlx::QueryBuilder::new("SELECT ");
	query.push(CONTACT_COLS);
	query.push(", vcard FROM contacts WHERE tn_id = ").push_bind(tn_id.0);
	query.push(" AND ab_id = ").push_bind(ab_id.cast_signed());
	query.push(" AND deleted_at IS NULL AND uid IN (");
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

	Ok(rows.iter().map(row_to_contact).collect())
}

/// List changes since the given sync token.
///
/// Uses `updated_at >= since` (inclusive) rather than `>`: timestamps have second
/// granularity, so a strict `>` would miss any write that landed in the same second as
/// the encoded token. The boundary rows from the previous sync get re-sent; CardDAV
/// clients dedupe them by etag at negligible cost, and this is the simplest way to
/// guarantee no mutation is ever silently skipped without changing the token format.
pub async fn list_contacts_since(
	db: &SqlitePool,
	tn_id: TnId,
	ab_id: u64,
	since: Option<Timestamp>,
	limit: Option<u32>,
) -> ClResult<Vec<ContactSyncEntry>> {
	let mut query = sqlx::QueryBuilder::new(
		"SELECT uid, etag, deleted_at, updated_at FROM contacts \
			 WHERE tn_id = ",
	);
	query.push_bind(tn_id.0);
	query.push(" AND ab_id = ").push_bind(ab_id.cast_signed());
	if let Some(ts) = since {
		query.push(" AND updated_at >= ").push_bind(ts.0);
	} else {
		// Full sync: skip tombstones — a client that has never synced doesn't need them.
		query.push(" AND deleted_at IS NULL");
	}
	// Tiebreaker on c_id keeps ordering deterministic when multiple rows share a second.
	query.push(" ORDER BY updated_at ASC, c_id ASC");
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
		.map(|row| ContactSyncEntry {
			uid: row.get::<String, _>("uid").into(),
			etag: row.get::<String, _>("etag").into(),
			deleted: row.get::<Option<i64>, _>("deleted_at").is_some(),
			updated_at: Timestamp(row.get::<i64, _>("updated_at")),
		})
		.collect())
}

pub async fn list_contacts_by_profile(
	db: &SqlitePool,
	tn_id: TnId,
	profile_id_tag: &str,
) -> ClResult<Vec<Contact>> {
	let rows = sqlx::query(&format!(
		"SELECT {CONTACT_COLS}, vcard FROM contacts \
		 WHERE tn_id = ? AND profile_id_tag = ? AND deleted_at IS NULL",
	))
	.bind(tn_id.0)
	.bind(profile_id_tag)
	.fetch_all(db)
	.await
	.inspect_err(|e| error!("DB: {e}"))
	.or(Err(Error::DbError))?;

	Ok(rows.iter().map(row_to_contact).collect())
}

// vim: ts=4
