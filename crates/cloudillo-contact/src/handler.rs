// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! JSON REST handlers for address books and contacts.
//!
//! Structured-only shape: clients send/receive typed JSON; the server is the sole authority
//! on vCard generation and field extraction. Custom vCard properties from external CardDAV
//! clients round-trip through the stored blob but don't surface here.

use axum::{
	Json,
	extract::{Path, Query, State},
	http::StatusCode,
};
use uuid::Uuid;

use cloudillo_core::{
	IdTag,
	extract::{Auth, OptionalRequestId},
	prelude::*,
};
use cloudillo_types::{
	meta_adapter::{ListContactOptions, Profile, UpdateAddressBookData},
	types::ApiResponse,
};

use crate::{
	profile_overlay::{build_overlay, merge_profile_into_input, resolve_profile},
	types::{
		AddressBookCreate, AddressBookOutput, AddressBookPatch, ContactInput, ContactListItem,
		ContactOutput, ContactPatch, ImportConflictMode, ImportContactsError, ImportContactsQuery,
		ImportContactsResult, ListContactsQuery, ProfileOverlay,
	},
	vcard,
};

// Shared helpers
//****************

fn ab_to_output(ab: &cloudillo_types::meta_adapter::AddressBook) -> AddressBookOutput {
	AddressBookOutput {
		ab_id: ab.ab_id,
		name: ab.name.to_string(),
		description: ab.description.as_deref().map(str::to_string),
		ctag: ab.ctag.to_string(),
		created_at: ab.created_at,
		updated_at: ab.updated_at,
	}
}

/// Resolve profiles for a batch of contacts in one query, returning `None` overlays for
/// any that aren't locally known. Uses `read_profile` per distinct id_tag — for v1 this
/// is fine (address books are typically small); a later batched `read_profiles` would be
/// a simple optimization.
async fn resolve_overlays(
	app: &App,
	tn_id: TnId,
	id_tags: impl IntoIterator<Item = &str>,
) -> ClResult<std::collections::HashMap<String, ProfileOverlay>> {
	let mut map = std::collections::HashMap::new();
	let mut seen = std::collections::HashSet::new();
	for id_tag in id_tags {
		if !seen.insert(id_tag.to_string()) {
			continue;
		}
		if let Some(profile) = resolve_profile(app, tn_id, id_tag).await? {
			map.insert(id_tag.to_string(), build_overlay(&profile));
		}
	}
	Ok(map)
}

fn contact_row_to_output(
	row: &cloudillo_types::meta_adapter::Contact,
	overlays: &std::collections::HashMap<String, ProfileOverlay>,
) -> ContactOutput {
	// Re-parse the stored vCard to recover emails[]/phones[] structure for the JSON response.
	// Projected columns alone lose the per-entry TYPE/PREF parameters, so we need the blob.
	let (parsed, parse_error) = if let Some((p, _, warnings)) = vcard::parse(&row.vcard) {
		let joined = if warnings.is_empty() { None } else { Some(warnings.join("; ")) };
		(p, joined)
	} else {
		error!(
			c_id = row.c_id,
			ab_id = row.ab_id,
			uid = %row.uid,
			"stored vCard blob is unparseable — persisted corruption, returning empty projection",
		);
		(crate::types::ContactInput::default(), Some("unparseable stored vCard".to_string()))
	};
	let profile_id_tag = row.extracted.profile_id_tag.as_deref().map(str::to_string);
	let profile = profile_id_tag.as_deref().and_then(|tag| overlays.get(tag).cloned());

	// Photo URL may need to be derived from profile overlay when the stored blob lacks one.
	let mut photo = row.extracted.photo_uri.as_deref().map(str::to_string);
	if photo.is_none()
		&& let Some(ov) = &profile
	{
		photo.clone_from(&ov.profile_pic);
	}

	let mut formatted_name = row.extracted.fn_name.as_deref().map(str::to_string);
	if formatted_name.as_deref().is_none_or(str::is_empty)
		&& let Some(ov) = &profile
	{
		formatted_name.clone_from(&ov.name);
	}

	ContactOutput {
		c_id: row.c_id,
		ab_id: row.ab_id,
		uid: row.uid.to_string(),
		etag: row.etag.to_string(),
		formatted_name,
		n: parsed.n,
		emails: parsed.emails,
		phones: parsed.phones,
		org: row.extracted.org.as_deref().map(str::to_string),
		title: row.extracted.title.as_deref().map(str::to_string),
		note: row.extracted.note.as_deref().map(str::to_string),
		photo,
		profile_id_tag,
		profile,
		parse_error,
		created_at: row.created_at,
		updated_at: row.updated_at,
	}
}

fn contact_view_to_list_item(
	row: &cloudillo_types::meta_adapter::ContactView,
	overlays: &std::collections::HashMap<String, ProfileOverlay>,
) -> ContactListItem {
	let profile_id_tag = row.extracted.profile_id_tag.as_deref().map(str::to_string);
	let profile = profile_id_tag.as_deref().and_then(|tag| overlays.get(tag).cloned());

	let mut photo = row.extracted.photo_uri.as_deref().map(str::to_string);
	if photo.is_none()
		&& let Some(ov) = &profile
	{
		photo.clone_from(&ov.profile_pic);
	}

	let mut formatted_name = row.extracted.fn_name.as_deref().map(str::to_string);
	if formatted_name.as_deref().is_none_or(str::is_empty)
		&& let Some(ov) = &profile
	{
		formatted_name.clone_from(&ov.name);
	}

	ContactListItem {
		c_id: row.c_id,
		ab_id: row.ab_id,
		uid: row.uid.to_string(),
		etag: row.etag.to_string(),
		formatted_name,
		email: row.extracted.email.as_deref().map(str::to_string),
		tel: row.extracted.tel.as_deref().map(str::to_string),
		org: row.extracted.org.as_deref().map(str::to_string),
		photo,
		profile_id_tag,
		profile,
		updated_at: row.updated_at,
	}
}

/// Apply a `ContactPatch` to a full `ContactInput` (already hydrated from storage).
fn apply_contact_patch(into: &mut ContactInput, patch: ContactPatch) {
	match patch.formatted_name {
		Patch::Undefined => {}
		Patch::Null => into.formatted_name = None,
		Patch::Value(v) => into.formatted_name = Some(v),
	}
	match patch.n {
		Patch::Undefined => {}
		Patch::Null => into.n = None,
		Patch::Value(v) => into.n = Some(v),
	}
	match patch.emails {
		Patch::Undefined => {}
		Patch::Null => into.emails.clear(),
		Patch::Value(v) => into.emails = v,
	}
	match patch.phones {
		Patch::Undefined => {}
		Patch::Null => into.phones.clear(),
		Patch::Value(v) => into.phones = v,
	}
	match patch.org {
		Patch::Undefined => {}
		Patch::Null => into.org = None,
		Patch::Value(v) => into.org = Some(v),
	}
	match patch.title {
		Patch::Undefined => {}
		Patch::Null => into.title = None,
		Patch::Value(v) => into.title = Some(v),
	}
	match patch.note {
		Patch::Undefined => {}
		Patch::Null => into.note = None,
		Patch::Value(v) => into.note = Some(v),
	}
	match patch.photo {
		Patch::Undefined => {}
		Patch::Null => into.photo = None,
		Patch::Value(v) => into.photo = Some(v),
	}
	match patch.profile_id_tag {
		Patch::Undefined => {}
		Patch::Null => into.profile_id_tag = None,
		Patch::Value(v) => into.profile_id_tag = Some(v),
	}
}

/// Hydrate a stored contact's full `ContactInput` from its vCard blob (for PATCH merge).
/// Returns `Error::Internal` when the stored blob does not parse — merging patch input
/// against an empty base would silently clear every field on the row.
fn stored_to_input(stored: &cloudillo_types::meta_adapter::Contact) -> ClResult<ContactInput> {
	let (mut parsed, _, _) = vcard::parse(&stored.vcard).ok_or_else(|| {
		error!(
			c_id = stored.c_id,
			ab_id = stored.ab_id,
			uid = %stored.uid,
			"stored vCard blob is unparseable",
		);
		Error::Internal("stored vCard blob is unparseable".into())
	})?;
	parsed.uid = Some(stored.uid.to_string());
	Ok(parsed)
}

/// Shared write path: merges profile data, generates vCard, upserts, returns the fresh row.
async fn write_contact(
	app: &App,
	tn_id: TnId,
	ab_id: u64,
	mut input: ContactInput,
) -> ClResult<ContactOutput> {
	// Ensure UID is set.
	let uid = match input.uid.clone() {
		Some(u) if !u.is_empty() => u,
		_ => {
			let u = format!("urn:uuid:{}", Uuid::new_v4());
			input.uid = Some(u.clone());
			u
		}
	};

	// Resolve linked profile (if any) and apply smart merge for empty fields.
	let linked_profile: Option<Profile<Box<str>>> = match input.profile_id_tag.as_deref() {
		Some(tag) if !tag.is_empty() => resolve_profile(app, tn_id, tag).await?,
		_ => None,
	};
	merge_profile_into_input(&mut input, linked_profile.as_ref());

	// Generate vCard, compute etag, build extracted projection.
	let now_iso = format_rev(Timestamp::now());
	let vcard_text = vcard::generate(&input, Some(&now_iso));
	let etag = vcard::etag_of(&vcard_text);
	let extracted = vcard::extract_from_input(&input);

	app.meta_adapter
		.upsert_contact(tn_id, ab_id, &uid, &vcard_text, &etag, &extracted)
		.await?;

	let stored = app.meta_adapter.get_contact(tn_id, ab_id, &uid).await?.ok_or(Error::NotFound)?;

	// Build overlay map (at most one entry) for the response.
	let mut overlays = std::collections::HashMap::new();
	if let Some(profile) = linked_profile {
		overlays.insert(profile.id_tag.to_string(), build_overlay(&profile));
	}

	Ok(contact_row_to_output(&stored, &overlays))
}

// Timestamp formatting helper — vCard REV wants compact basic ISO 8601 (yyyymmddThhmmssZ).
fn format_rev(ts: Timestamp) -> String {
	chrono::DateTime::from_timestamp(ts.0, 0).map_or_else(
		|| "19700101T000000Z".to_string(),
		|dt| dt.format("%Y%m%dT%H%M%SZ").to_string(),
	)
}

// Handlers
//**********

// Address books
//***************

pub async fn list_address_books(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<AddressBookOutput>>>)> {
	let books = app.meta_adapter.list_address_books(tn_id).await?;
	let out: Vec<AddressBookOutput> = books.iter().map(ab_to_output).collect();
	let mut resp = ApiResponse::new(out);
	if let Some(id) = req_id {
		resp = resp.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(resp)))
}

/// Names flow into the CardDAV collection URI and DAV response XML, so a newline or slash
/// can corrupt headers or split the URL. Cap at 128 bytes to keep URLs reasonable.
fn validate_ab_name(name: &str) -> ClResult<()> {
	if name.is_empty() {
		return Err(Error::ValidationError("name required".into()));
	}
	if name.len() > 128 {
		return Err(Error::ValidationError("name too long".into()));
	}
	if name.chars().any(|c| c.is_control() || c == '/' || c == '\\') {
		return Err(Error::ValidationError("name contains invalid character".into()));
	}
	Ok(())
}

pub async fn create_address_book(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(body): Json<AddressBookCreate>,
) -> ClResult<(StatusCode, Json<ApiResponse<AddressBookOutput>>)> {
	let name = body.name.trim();
	validate_ab_name(name)?;
	let ab = app
		.meta_adapter
		.create_address_book(tn_id, name, body.description.as_deref())
		.await?;
	let mut resp = ApiResponse::new(ab_to_output(&ab));
	if let Some(id) = req_id {
		resp = resp.with_req_id(id);
	}
	Ok((StatusCode::CREATED, Json(resp)))
}

pub async fn patch_address_book(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Path(ab_id): Path<u64>,
	Json(patch): Json<AddressBookPatch>,
) -> ClResult<(StatusCode, Json<ApiResponse<AddressBookOutput>>)> {
	let name = match &patch.name {
		Patch::Value(v) => Patch::Value(v.trim().to_string()),
		Patch::Null => Patch::Null,
		Patch::Undefined => Patch::Undefined,
	};
	if let Patch::Value(v) = &name {
		validate_ab_name(v)?;
	}
	let update = UpdateAddressBookData { name, description: patch.description };
	app.meta_adapter.update_address_book(tn_id, ab_id, &update).await?;
	let ab = app.meta_adapter.get_address_book(tn_id, ab_id).await?.ok_or(Error::NotFound)?;
	let mut resp = ApiResponse::new(ab_to_output(&ab));
	if let Some(id) = req_id {
		resp = resp.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(resp)))
}

pub async fn delete_address_book(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	Path(ab_id): Path<u64>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	app.meta_adapter.delete_address_book(tn_id, ab_id).await?;
	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

// Contacts
//**********

pub async fn list_contacts(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Path(ab_id): Path<u64>,
	Query(query): Query<ListContactsQuery>,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<ContactListItem>>>)> {
	let opts = ListContactOptions { q: query.q, cursor: query.cursor, limit: query.limit };
	let mut rows = app.meta_adapter.list_contacts(tn_id, ab_id, &opts).await?;

	// Adapter over-fetches by 1 so we can distinguish "exact-fit page" from "more rows".
	let requested = opts.limit.unwrap_or(100).min(500) as usize;
	let has_more = rows.len() > requested;
	if has_more {
		rows.truncate(requested);
	}

	let profile_tags: Vec<String> = rows
		.iter()
		.filter_map(|r| r.extracted.profile_id_tag.as_deref().map(str::to_string))
		.collect();
	let overlays = resolve_overlays(&app, tn_id, profile_tags.iter().map(String::as_str)).await?;

	let items: Vec<ContactListItem> =
		rows.iter().map(|row| contact_view_to_list_item(row, &overlays)).collect();

	let next_cursor = if has_more { items.last().map(|last| last.c_id.to_string()) } else { None };

	let mut resp = ApiResponse::with_cursor_pagination(items, next_cursor, has_more);
	if let Some(id) = req_id {
		resp = resp.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(resp)))
}

pub async fn get_contact(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Path((ab_id, uid)): Path<(u64, String)>,
) -> ClResult<(StatusCode, Json<ApiResponse<ContactOutput>>)> {
	let stored = app.meta_adapter.get_contact(tn_id, ab_id, &uid).await?.ok_or(Error::NotFound)?;

	let overlays =
		resolve_overlays(&app, tn_id, stored.extracted.profile_id_tag.as_deref()).await?;
	let out = contact_row_to_output(&stored, &overlays);

	let mut resp = ApiResponse::new(out);
	if let Some(id) = req_id {
		resp = resp.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(resp)))
}

pub async fn create_contact(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Path(ab_id): Path<u64>,
	Json(body): Json<ContactInput>,
) -> ClResult<(StatusCode, Json<ApiResponse<ContactOutput>>)> {
	// Address book must exist.
	app.meta_adapter.get_address_book(tn_id, ab_id).await?.ok_or(Error::NotFound)?;
	let out = write_contact(&app, tn_id, ab_id, body).await?;
	let mut resp = ApiResponse::new(out);
	if let Some(id) = req_id {
		resp = resp.with_req_id(id);
	}
	Ok((StatusCode::CREATED, Json(resp)))
}

pub async fn put_contact(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Path((ab_id, uid)): Path<(u64, String)>,
	Json(mut body): Json<ContactInput>,
) -> ClResult<(StatusCode, Json<ApiResponse<ContactOutput>>)> {
	app.meta_adapter.get_address_book(tn_id, ab_id).await?.ok_or(Error::NotFound)?;
	body.uid = Some(uid);
	let out = write_contact(&app, tn_id, ab_id, body).await?;
	let mut resp = ApiResponse::new(out);
	if let Some(id) = req_id {
		resp = resp.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(resp)))
}

pub async fn patch_contact(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Path((ab_id, uid)): Path<(u64, String)>,
	Json(patch): Json<ContactPatch>,
) -> ClResult<(StatusCode, Json<ApiResponse<ContactOutput>>)> {
	let stored = app.meta_adapter.get_contact(tn_id, ab_id, &uid).await?.ok_or(Error::NotFound)?;

	let mut merged = stored_to_input(&stored)?;
	apply_contact_patch(&mut merged, patch);
	merged.uid = Some(stored.uid.to_string());

	let out = write_contact(&app, tn_id, ab_id, merged).await?;
	let mut resp = ApiResponse::new(out);
	if let Some(id) = req_id {
		resp = resp.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(resp)))
}

pub async fn delete_contact(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	Path((ab_id, uid)): Path<(u64, String)>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	app.meta_adapter.delete_contact(tn_id, ab_id, &uid).await?;
	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

/// POST /api/address-books/{ab_id}/import?conflict=skip|replace|add
///
/// Body: `text/vcard` containing one or more `BEGIN:VCARD ... END:VCARD` blocks.
/// Returns a per-card result summary with any parse/write failures.
///
/// Conflict modes (matched by vCard UID against existing rows in the address book):
/// - `skip` (default) — keep the existing contact, count it under `skipped`.
/// - `replace` — overwrite the existing contact (same UID), count under `updated`.
/// - `add` — drop the incoming UID and mint a fresh one so the card lands as a new
///   contact alongside the existing one. Useful when the user wants every card from
///   the file to land regardless of UID collisions.
#[allow(clippy::too_many_arguments)]
pub async fn import_contacts(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Path(ab_id): Path<u64>,
	Query(query): Query<ImportContactsQuery>,
	body: String,
) -> ClResult<(StatusCode, Json<ApiResponse<ImportContactsResult>>)> {
	app.meta_adapter.get_address_book(tn_id, ab_id).await?.ok_or(Error::NotFound)?;

	let mode = query.conflict.unwrap_or_default();
	let cards = vcard::split_cards(&body);
	let mut result = ImportContactsResult {
		total: u32::try_from(cards.len()).unwrap_or(u32::MAX),
		..Default::default()
	};

	// Parse every card once up-front so the existence check can see all candidate UIDs
	// and we only hit the DB with a single batch lookup instead of a per-card roundtrip.
	let parsed: Vec<Option<crate::types::ContactInput>> =
		cards.iter().map(|card| vcard::parse(card).map(|(input, _, _)| input)).collect();
	let candidate_uids: Vec<String> = parsed
		.iter()
		.filter_map(|p| p.as_ref()?.uid.clone())
		.filter(|u| !u.is_empty())
		.collect();
	let existing: std::collections::HashSet<String> = if candidate_uids.is_empty() {
		std::collections::HashSet::new()
	} else {
		let refs: Vec<&str> = candidate_uids.iter().map(String::as_str).collect();
		app.meta_adapter
			.get_contacts_by_uids(tn_id, ab_id, &refs)
			.await?
			.into_iter()
			.map(|c| c.uid.to_string())
			.collect()
	};

	for (i, parsed_slot) in parsed.into_iter().enumerate() {
		let idx = u32::try_from(i).unwrap_or(u32::MAX);
		let Some(mut input) = parsed_slot else {
			result.errors.push(ImportContactsError {
				index: idx,
				uid: None,
				message: "could not parse vCard block".into(),
			});
			continue;
		};

		let incoming_uid = input.uid.clone();
		let exists = incoming_uid
			.as_deref()
			.is_some_and(|uid| !uid.is_empty() && existing.contains(uid));

		match (exists, mode) {
			(true, ImportConflictMode::Skip) => {
				result.skipped += 1;
				continue;
			}
			(_, ImportConflictMode::Add) => {
				// Force a new UID so the card lands as a fresh contact even on collision.
				input.uid = None;
			}
			// Replace, or non-collision Skip/Replace, fall through to write_contact (upsert).
			_ => {}
		}

		match write_contact(&app, tn_id, ab_id, input).await {
			Ok(_) => {
				if exists && mode == ImportConflictMode::Replace {
					result.updated += 1;
				} else {
					result.imported += 1;
				}
			}
			Err(e) => result.errors.push(ImportContactsError {
				index: idx,
				uid: incoming_uid,
				message: e.to_string(),
			}),
		}
	}

	let mut resp = ApiResponse::new(result);
	if let Some(id) = req_id {
		resp = resp.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(resp)))
}

// vim: ts=4
