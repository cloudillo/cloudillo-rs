// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! JSON REST API types for calendars and calendar objects (events + tasks).
//!
//! The shape is structured-only: server owns iCalendar generation and field extraction;
//! clients never see raw iCalendar text. Custom properties sent by external CalDAV clients
//! are preserved in the stored blob but invisible to JSON responses.

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use cloudillo_core::prelude::*;
use cloudillo_types::types::serialize_timestamp_iso;

// Structured sub-types
//**********************

/// An attendee / organizer reference. CalDAV stores these as CAL-ADDRESS URIs (typically
/// `mailto:…` or a Cloudillo profile URL).
#[skip_serializing_none]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attendee {
	pub address: String,
	pub cn: Option<String>,
	/// PARTSTAT parameter: ACCEPTED / DECLINED / TENTATIVE / NEEDS-ACTION / DELEGATED.
	pub partstat: Option<String>,
	/// ROLE parameter: CHAIR / REQ-PARTICIPANT / OPT-PARTICIPANT / NON-PARTICIPANT.
	pub role: Option<String>,
	/// RSVP=TRUE requested.
	pub rsvp: Option<bool>,
}

/// A VALARM component reminder. Trigger is stored as the raw RFC 5545 value (`-PT15M`,
/// absolute date-time, etc.) so anything a client sent round-trips unchanged.
#[skip_serializing_none]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Alarm {
	/// ACTION: AUDIO / DISPLAY / EMAIL.
	pub action: Option<String>,
	pub trigger: Option<String>,
	pub description: Option<String>,
}

// Calendar collection
//*********************

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CalendarOutput {
	pub cal_id: u64,
	pub name: String,
	pub description: Option<String>,
	pub color: Option<String>,
	pub timezone: Option<String>,
	/// CSV of supported components, e.g. `"VEVENT,VTODO"`.
	pub components: String,
	pub ctag: String,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub updated_at: Timestamp,
}

#[skip_serializing_none]
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CalendarCreate {
	pub name: String,
	pub description: Option<String>,
	pub color: Option<String>,
	pub timezone: Option<String>,
	pub components: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CalendarPatch {
	#[serde(default)]
	pub name: Patch<String>,
	#[serde(default)]
	pub description: Patch<String>,
	#[serde(default)]
	pub color: Patch<String>,
	#[serde(default)]
	pub timezone: Patch<String>,
	#[serde(default)]
	pub components: Patch<Vec<String>>,
}

// Calendar object (write)
//*************************

/// Body for `POST /api/calendars/{calId}/objects` (create) and `PUT …/{uid}` (replace).
/// One of `event` / `todo` must be populated to indicate the component type.
#[skip_serializing_none]
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CalendarObjectInput {
	pub uid: Option<String>,
	/// `RECURRENCE-ID` (ISO-8601) when writing a recurrence-override VEVENT. `None` for
	/// the master. Exception endpoints force this from the URL path.
	pub recurrence_id: Option<String>,
	pub event: Option<EventInput>,
	pub todo: Option<TodoInput>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventInput {
	pub summary: Option<String>,
	pub description: Option<String>,
	pub location: Option<String>,
	/// DTSTART as ISO-8601. `all_day` distinguishes `VALUE=DATE` from `VALUE=DATE-TIME`.
	pub dtstart: Option<String>,
	pub dtend: Option<String>,
	#[serde(default)]
	pub all_day: bool,
	pub rrule: Option<String>,
	/// `EXDATE` exclusions on the master (ISO-8601 list). Occurrences matching these are
	/// skipped client-side. Ignored on override rows.
	#[serde(default)]
	pub exdate: Vec<String>,
	pub status: Option<String>,
	pub organizer: Option<String>,
	#[serde(default)]
	pub attendees: Vec<Attendee>,
	#[serde(default)]
	pub categories: Vec<String>,
	#[serde(default)]
	pub alarms: Vec<Alarm>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TodoInput {
	pub summary: Option<String>,
	pub description: Option<String>,
	/// DTSTART, if the task has a planned start.
	pub dtstart: Option<String>,
	/// DUE as ISO-8601.
	pub due: Option<String>,
	pub completed: Option<String>,
	pub priority: Option<u8>,
	pub status: Option<String>,
	pub rrule: Option<String>,
	#[serde(default)]
	pub categories: Vec<String>,
	#[serde(default)]
	pub alarms: Vec<Alarm>,
}

// Calendar object (patch)
//*************************

/// Body for `PATCH /api/calendars/{calId}/objects/{uid}`.
///
/// Same field set as [`CalendarObjectInput`] but with JSON-absence semantics:
/// fields the client omits stay at their current stored value. That's why every
/// collection / bool is wrapped in `Option` — `None` means "no change", `Some(_)`
/// means "replace with this value (including empty)".
#[skip_serializing_none]
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CalendarObjectPatch {
	pub event: Option<EventPatch>,
	pub todo: Option<TodoPatch>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventPatch {
	pub summary: Option<String>,
	pub description: Option<String>,
	pub location: Option<String>,
	pub dtstart: Option<String>,
	pub dtend: Option<String>,
	pub all_day: Option<bool>,
	pub rrule: Option<String>,
	/// Replace the master's `EXDATE` list. Use `Some(Vec::new())` to clear.
	pub exdate: Option<Vec<String>>,
	pub status: Option<String>,
	pub organizer: Option<String>,
	pub attendees: Option<Vec<Attendee>>,
	pub categories: Option<Vec<String>>,
	pub alarms: Option<Vec<Alarm>>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TodoPatch {
	pub summary: Option<String>,
	pub description: Option<String>,
	pub dtstart: Option<String>,
	pub due: Option<String>,
	pub completed: Option<String>,
	pub priority: Option<u8>,
	pub status: Option<String>,
	pub rrule: Option<String>,
	pub categories: Option<Vec<String>>,
	pub alarms: Option<Vec<Alarm>>,
}

// Calendar object (read)
//************************

/// Unified response shape covering both VEVENT and VTODO. `component` tells clients which
/// subtype's fields are meaningful.
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CalendarObjectOutput {
	pub co_id: u64,
	pub cal_id: u64,
	pub uid: String,
	pub etag: String,
	/// `VEVENT` or `VTODO`.
	pub component: String,
	pub summary: Option<String>,
	pub description: Option<String>,
	pub location: Option<String>,
	pub dtstart: Option<String>,
	pub dtend: Option<String>,
	#[serde(default, skip_serializing_if = "std::ops::Not::not")]
	pub all_day: bool,
	pub status: Option<String>,
	pub priority: Option<u8>,
	pub organizer: Option<String>,
	pub rrule: Option<String>,
	/// `RECURRENCE-ID` (ISO-8601) for override rows; `None` on the master.
	pub recurrence_id: Option<String>,
	/// `EXDATE` list (ISO-8601) on the master; `None` on override rows or when absent.
	pub exdate: Option<Vec<String>>,
	/// Present when the stored iCalendar blob could not be parsed.
	pub parse_error: Option<String>,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub updated_at: Timestamp,
}

/// Summary row for list endpoints.
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CalendarObjectListItem {
	pub co_id: u64,
	pub cal_id: u64,
	pub uid: String,
	pub etag: String,
	pub component: String,
	pub summary: Option<String>,
	pub location: Option<String>,
	pub dtstart: Option<String>,
	pub dtend: Option<String>,
	#[serde(default, skip_serializing_if = "std::ops::Not::not")]
	pub all_day: bool,
	pub status: Option<String>,
	pub rrule: Option<String>,
	/// `RECURRENCE-ID` (ISO-8601) for override rows; `None` on masters.
	pub recurrence_id: Option<String>,
	/// `EXDATE` list (ISO-8601) on masters; `None` when absent.
	pub exdate: Option<Vec<String>>,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub updated_at: Timestamp,
}

// Recurring-series split
//*************************

/// Body for `POST /api/calendars/{calId}/objects/{uid}/split`.
///
/// Atomically forks a recurring series at `split_at`:
///   1. Apply `master_patch` to the existing master (typically truncating its RRULE
///      with UNTIL just before `split_at`).
///   2. Soft-delete every recurrence-override row whose RECURRENCE-ID is ≥ `split_at`.
///   3. Create a new master from `tail` (with its own server-minted UID) that carries
///      the edited fields from the split point onward.
///
/// All three steps run inside a single DB transaction. A failure at any step rolls the
/// whole operation back, so the client never observes a half-split series.
#[skip_serializing_none]
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitSeriesRequest {
	/// RECURRENCE-ID of the first occurrence that belongs to the new tail series
	/// (ISO-8601). Overrides at or after this timestamp are dropped.
	pub split_at: String,
	/// Patch applied to the existing master before the split. Clients typically set
	/// `event.rrule` to a client-computed UNTIL-bounded rule so the master stops
	/// producing occurrences at or after `split_at`.
	#[serde(default)]
	pub master_patch: CalendarObjectPatch,
	/// Full `CalendarObjectInput` for the new tail master. `uid` is ignored — the
	/// server always mints a fresh UID so the tail is independently addressable.
	pub tail: CalendarObjectInput,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitSeriesResponse {
	/// The updated master (post-patch). Clients should adopt this etag.
	pub master: CalendarObjectOutput,
	/// The newly-created tail master. Its `uid` is the one to address future edits at.
	pub tail: CalendarObjectOutput,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListObjectsQuery {
	/// Restrict to `VEVENT` or `VTODO`.
	pub component: Option<String>,
	pub q: Option<String>,
	/// Time-range start as ISO-8601.
	pub start: Option<String>,
	/// Time-range end as ISO-8601.
	pub end: Option<String>,
	pub cursor: Option<String>,
	pub limit: Option<u32>,
	/// When true, the response includes recurrence-override rows (each with a `RECURRENCE-ID`)
	/// alongside the master. Clients that expand recurrence locally need these to overlay
	/// the right occurrences.
	#[serde(default)]
	pub include_exceptions: bool,
}

// vim: ts=4
