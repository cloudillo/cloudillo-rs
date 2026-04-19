// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! JSON REST API types for contacts and address books.
//!
//! The shape is structured-only: server owns vCard generation and field extraction;
//! clients never see raw vCard text. Custom vCard properties sent by external CardDAV
//! clients are preserved in the stored blob but invisible to JSON responses.

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use cloudillo_core::prelude::*;
use cloudillo_types::types::serialize_timestamp_iso;

// Structured sub-types
//**********************

/// vCard N (structured name) property.
#[skip_serializing_none]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactName {
	pub given: Option<String>,
	pub family: Option<String>,
	pub additional: Option<String>,
	pub prefix: Option<String>,
	pub suffix: Option<String>,
}

/// A value with TYPE and PREF parameters — covers EMAIL, TEL, URL, etc.
#[skip_serializing_none]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypedValue {
	pub value: String,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub r#type: Vec<String>,
	pub pref: Option<u8>,
}

// Profile overlay
//*****************

/// Live profile data returned alongside a contact that has `profileIdTag` set.
/// Fetched per-request from the tenant's `profiles` table; never written into storage.
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileOverlay {
	pub id_tag: String,
	pub name: Option<String>,
	pub r#type: Option<String>,
	pub profile_pic: Option<String>,
	pub connected: Option<bool>,
	pub following: Option<bool>,
}

// Write types (input — POST/PUT/PATCH bodies)
//*********************************************

/// Body for `POST /api/address-books/{abId}/contacts` (create) and
/// `PUT  /api/address-books/{abId}/contacts/{uid}` (replace).
///
/// Field absence means "leave empty"; no merge semantics on full replace.
#[skip_serializing_none]
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactInput {
	pub uid: Option<String>,
	#[serde(rename = "fn")]
	pub formatted_name: Option<String>,
	pub n: Option<ContactName>,
	#[serde(default)]
	pub emails: Vec<TypedValue>,
	#[serde(default)]
	pub phones: Vec<TypedValue>,
	pub org: Option<String>,
	pub title: Option<String>,
	pub note: Option<String>,
	pub photo: Option<String>,
	pub profile_id_tag: Option<String>,
}

/// Body for `PATCH /api/address-books/{abId}/contacts/{uid}`.
/// Each field uses `Patch<T>` so clients can distinguish "leave alone" from "clear".
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactPatch {
	#[serde(default, rename = "fn")]
	pub formatted_name: Patch<String>,
	#[serde(default)]
	pub n: Patch<ContactName>,
	#[serde(default)]
	pub emails: Patch<Vec<TypedValue>>,
	#[serde(default)]
	pub phones: Patch<Vec<TypedValue>>,
	#[serde(default)]
	pub org: Patch<String>,
	#[serde(default)]
	pub title: Patch<String>,
	#[serde(default)]
	pub note: Patch<String>,
	#[serde(default)]
	pub photo: Patch<String>,
	#[serde(default)]
	pub profile_id_tag: Patch<String>,
}

// Read types (output — response bodies)
//***************************************

/// Full contact response including server-side metadata and optional live profile overlay.
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactOutput {
	pub c_id: u64,
	pub ab_id: u64,
	pub uid: String,
	pub etag: String,
	#[serde(rename = "fn")]
	pub formatted_name: Option<String>,
	pub n: Option<ContactName>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub emails: Vec<TypedValue>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub phones: Vec<TypedValue>,
	pub org: Option<String>,
	pub title: Option<String>,
	pub note: Option<String>,
	pub photo: Option<String>,
	pub profile_id_tag: Option<String>,
	/// Live profile data merged from the `profiles` table (only present when linked and known).
	pub profile: Option<ProfileOverlay>,
	/// Set when the stored vCard blob could not be parsed. Clients should render
	/// "record unreadable" rather than treating an empty projection as authoritative.
	pub parse_error: Option<String>,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub updated_at: Timestamp,
}

/// Summary row for list endpoints (omits emails[]/phones[] detail to keep list responses small).
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactListItem {
	pub c_id: u64,
	pub ab_id: u64,
	pub uid: String,
	pub etag: String,
	#[serde(rename = "fn")]
	pub formatted_name: Option<String>,
	pub email: Option<String>,
	pub tel: Option<String>,
	pub org: Option<String>,
	pub photo: Option<String>,
	pub profile_id_tag: Option<String>,
	pub profile: Option<ProfileOverlay>,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub updated_at: Timestamp,
}

// Address book
//**************

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressBookOutput {
	pub ab_id: u64,
	pub name: String,
	pub description: Option<String>,
	pub ctag: String,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub updated_at: Timestamp,
}

#[skip_serializing_none]
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressBookCreate {
	pub name: String,
	pub description: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressBookPatch {
	#[serde(default)]
	pub name: Patch<String>,
	#[serde(default)]
	pub description: Patch<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListContactsQuery {
	pub q: Option<String>,
	pub cursor: Option<String>,
	pub limit: Option<u32>,
}

// Import
//********

/// How to handle a vCard whose UID matches an existing contact in the address book.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ImportConflictMode {
	/// Keep the existing contact unchanged (safe default).
	#[default]
	Skip,
	/// Replace the existing contact with the imported card (CardDAV-style).
	Replace,
	/// Always create a new contact, regenerating the UID so duplicates land side-by-side.
	Add,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportContactsQuery {
	#[serde(default)]
	pub conflict: Option<ImportConflictMode>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportContactsError {
	/// 0-based index of the card in the source file (counting valid BEGIN:VCARD blocks only).
	pub index: u32,
	pub uid: Option<String>,
	pub message: String,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportContactsResult {
	/// Number of vCard blocks the parser found in the input (including unparseable ones).
	pub total: u32,
	/// New contacts created.
	pub imported: u32,
	/// Existing contacts overwritten (only with conflict=replace).
	pub updated: u32,
	/// Existing contacts left unchanged (only with conflict=skip).
	pub skipped: u32,
	/// Per-card parse / write failures.
	pub errors: Vec<ImportContactsError>,
}

// vim: ts=4
