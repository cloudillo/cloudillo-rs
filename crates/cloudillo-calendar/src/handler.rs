// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! JSON REST handlers for calendars and calendar objects.
//!
//! Structured-only shape: clients send/receive typed JSON; the server is the sole authority
//! on iCalendar generation and field extraction. Custom properties from external CalDAV
//! clients round-trip through the stored blob but don't surface here.

use axum::{
	Json,
	extract::{Path, Query, State},
	http::StatusCode,
};
use cloudillo_core::{
	IdTag,
	extract::{Auth, OptionalRequestId},
	prelude::*,
};
use cloudillo_types::{
	meta_adapter::{
		Calendar, CalendarObject, CalendarObjectExtracted, CalendarObjectView, CalendarObjectWrite,
		CreateCalendarData, ListCalendarObjectOptions, UpdateCalendarData,
	},
	types::ApiResponse,
	utils::random_id,
};

use crate::{
	ical,
	types::{
		CalendarCreate, CalendarObjectInput, CalendarObjectListItem, CalendarObjectOutput,
		CalendarObjectPatch, CalendarOutput, CalendarPatch, EventInput, EventPatch,
		ListObjectsQuery, SplitSeriesRequest, SplitSeriesResponse, TodoInput, TodoPatch,
	},
};

// Shared helpers
//****************

fn cal_to_output(cal: &Calendar) -> CalendarOutput {
	CalendarOutput {
		cal_id: cal.cal_id,
		name: cal.name.to_string(),
		description: cal.description.as_deref().map(str::to_string),
		color: cal.color.as_deref().map(str::to_string),
		timezone: cal.timezone.as_deref().map(str::to_string),
		components: cal.components.to_string(),
		ctag: cal.ctag.to_string(),
		created_at: cal.created_at,
		updated_at: cal.updated_at,
	}
}

fn object_to_output(row: &CalendarObject) -> CalendarObjectOutput {
	let parse_error = match ical::parse(&row.ical) {
		Some((_, _, warnings)) if !warnings.is_empty() => Some(warnings.join("; ")),
		Some(_) => None,
		None => Some("unparseable stored iCalendar".into()),
	};
	let exdate_iso: Vec<String> = row
		.extracted
		.exdate
		.iter()
		.map(|ts| ical::ts_to_iso(*ts, row.extracted.all_day))
		.collect();
	CalendarObjectOutput {
		co_id: row.co_id,
		cal_id: row.cal_id,
		uid: row.uid.to_string(),
		etag: row.etag.to_string(),
		component: row.extracted.component.to_string(),
		summary: row.extracted.summary.as_deref().map(str::to_string),
		description: row.extracted.description.as_deref().map(str::to_string),
		location: row.extracted.location.as_deref().map(str::to_string),
		dtstart: row.extracted.dtstart.map(|ts| ical::ts_to_iso(ts, row.extracted.all_day)),
		dtend: row.extracted.dtend.map(|ts| ical::ts_to_iso(ts, row.extracted.all_day)),
		all_day: row.extracted.all_day,
		status: row.extracted.status.as_deref().map(str::to_string),
		priority: row.extracted.priority,
		organizer: row.extracted.organizer.as_deref().map(str::to_string),
		rrule: row.extracted.rrule.as_deref().map(str::to_string),
		recurrence_id: row
			.extracted
			.recurrence_id
			.map(|ts| ical::ts_to_iso(ts, row.extracted.all_day)),
		exdate: if exdate_iso.is_empty() { None } else { Some(exdate_iso) },
		parse_error,
		created_at: row.created_at,
		updated_at: row.updated_at,
	}
}

fn view_to_list_item(row: &CalendarObjectView) -> CalendarObjectListItem {
	let exdate_iso: Vec<String> = row
		.extracted
		.exdate
		.iter()
		.map(|ts| ical::ts_to_iso(*ts, row.extracted.all_day))
		.collect();
	CalendarObjectListItem {
		co_id: row.co_id,
		cal_id: row.cal_id,
		uid: row.uid.to_string(),
		etag: row.etag.to_string(),
		component: row.extracted.component.to_string(),
		summary: row.extracted.summary.as_deref().map(str::to_string),
		location: row.extracted.location.as_deref().map(str::to_string),
		dtstart: row.extracted.dtstart.map(|ts| ical::ts_to_iso(ts, row.extracted.all_day)),
		dtend: row.extracted.dtend.map(|ts| ical::ts_to_iso(ts, row.extracted.all_day)),
		all_day: row.extracted.all_day,
		status: row.extracted.status.as_deref().map(str::to_string),
		rrule: row.extracted.rrule.as_deref().map(str::to_string),
		recurrence_id: row
			.extracted
			.recurrence_id
			.map(|ts| ical::ts_to_iso(ts, row.extracted.all_day)),
		exdate: if exdate_iso.is_empty() { None } else { Some(exdate_iso) },
		updated_at: row.updated_at,
	}
}

/// Names flow into the CalDAV collection URI, so a newline or slash would corrupt headers
/// or split the URL. Cap at 128 bytes to keep URLs reasonable.
fn validate_cal_name(name: &str) -> ClResult<()> {
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

fn parse_iso_ts(v: &str) -> Option<Timestamp> {
	// Delegate to chrono for the general case.
	chrono::DateTime::parse_from_rfc3339(v)
		.ok()
		.map(|dt| Timestamp(dt.timestamp()))
		.or_else(|| {
			// Allow bare `YYYY-MM-DD` too.
			chrono::NaiveDate::parse_from_str(v, "%Y-%m-%d")
				.ok()
				.and_then(|d| d.and_hms_opt(0, 0, 0))
				.map(|ndt| Timestamp(ndt.and_utc().timestamp()))
		})
}

// Calendar collection handlers
//******************************

pub async fn list_calendars(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<CalendarOutput>>>)> {
	let cals = app.meta_adapter.list_calendars(tn_id).await?;
	let out: Vec<CalendarOutput> = cals.iter().map(cal_to_output).collect();
	let mut resp = ApiResponse::new(out);
	if let Some(id) = req_id {
		resp = resp.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(resp)))
}

pub async fn create_calendar(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(body): Json<CalendarCreate>,
) -> ClResult<(StatusCode, Json<ApiResponse<CalendarOutput>>)> {
	let name = body.name.trim();
	validate_cal_name(name)?;
	let components = body.components.map(|v| v.join(","));
	let input = CreateCalendarData {
		name: name.to_string(),
		description: body.description,
		color: body.color,
		timezone: body.timezone,
		components,
	};
	let cal = app.meta_adapter.create_calendar(tn_id, &input).await?;
	let mut resp = ApiResponse::new(cal_to_output(&cal));
	if let Some(id) = req_id {
		resp = resp.with_req_id(id);
	}
	Ok((StatusCode::CREATED, Json(resp)))
}

pub async fn get_calendar(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Path(cal_id): Path<u64>,
) -> ClResult<(StatusCode, Json<ApiResponse<CalendarOutput>>)> {
	let cal = app.meta_adapter.get_calendar(tn_id, cal_id).await?.ok_or(Error::NotFound)?;
	let mut resp = ApiResponse::new(cal_to_output(&cal));
	if let Some(id) = req_id {
		resp = resp.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(resp)))
}

pub async fn patch_calendar(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Path(cal_id): Path<u64>,
	Json(patch): Json<CalendarPatch>,
) -> ClResult<(StatusCode, Json<ApiResponse<CalendarOutput>>)> {
	let name = match &patch.name {
		Patch::Value(v) => Patch::Value(v.trim().to_string()),
		Patch::Null => Patch::Null,
		Patch::Undefined => Patch::Undefined,
	};
	if let Patch::Value(v) = &name {
		validate_cal_name(v)?;
	}
	let components = match patch.components {
		Patch::Value(list) => Patch::Value(list.join(",")),
		Patch::Null => Patch::Null,
		Patch::Undefined => Patch::Undefined,
	};
	let update = UpdateCalendarData {
		name,
		description: patch.description,
		color: patch.color,
		timezone: patch.timezone,
		components,
	};
	app.meta_adapter.update_calendar(tn_id, cal_id, &update).await?;
	let cal = app.meta_adapter.get_calendar(tn_id, cal_id).await?.ok_or(Error::NotFound)?;
	let mut resp = ApiResponse::new(cal_to_output(&cal));
	if let Some(id) = req_id {
		resp = resp.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(resp)))
}

pub async fn delete_calendar(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	Path(cal_id): Path<u64>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	app.meta_adapter.delete_calendar(tn_id, cal_id).await?;
	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

// Calendar object handlers
//**************************

pub async fn list_objects(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Path(cal_id): Path<u64>,
	Query(query): Query<ListObjectsQuery>,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<CalendarObjectListItem>>>)> {
	let opts = ListCalendarObjectOptions {
		component: query.component,
		q: query.q,
		start: query.start.as_deref().and_then(parse_iso_ts),
		end: query.end.as_deref().and_then(parse_iso_ts),
		cursor: query.cursor,
		limit: query.limit,
		include_exceptions: query.include_exceptions,
	};
	let mut rows = app.meta_adapter.list_calendar_objects(tn_id, cal_id, &opts).await?;

	// Adapter over-fetches by 1 to distinguish exact-fit from "more rows".
	let requested = usize::try_from(opts.limit.unwrap_or(200).min(1000)).unwrap_or(200);
	let has_more = rows.len() > requested;
	if has_more {
		rows.truncate(requested);
	}

	let items: Vec<CalendarObjectListItem> = rows.iter().map(view_to_list_item).collect();
	let next_cursor = if has_more { items.last().map(|last| last.co_id.to_string()) } else { None };

	let mut resp = ApiResponse::with_cursor_pagination(items, next_cursor, has_more);
	if let Some(id) = req_id {
		resp = resp.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(resp)))
}

pub async fn get_object(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Path((cal_id, uid)): Path<(u64, String)>,
) -> ClResult<(StatusCode, Json<ApiResponse<CalendarObjectOutput>>)> {
	let stored = app
		.meta_adapter
		.get_calendar_object(tn_id, cal_id, &uid)
		.await?
		.ok_or(Error::NotFound)?;
	let mut resp = ApiResponse::new(object_to_output(&stored));
	if let Some(id) = req_id {
		resp = resp.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(resp)))
}

async fn write_object(
	app: &App,
	tn_id: TnId,
	cal_id: u64,
	mut input: CalendarObjectInput,
) -> ClResult<CalendarObjectOutput> {
	if input.event.is_none() && input.todo.is_none() {
		return Err(Error::ValidationError("event or todo required".into()));
	}
	// Client-supplied UIDs (typical for CalDAV PUT from Apple Calendar, Thunderbird,
	// DAVx⁵ etc.) round-trip verbatim. Server-minted UIDs use the standard 24-char
	// base62 short id — no need for UUID verbosity on the server-create path.
	let uid = match input.uid.clone() {
		Some(u) if !u.is_empty() => u,
		_ => {
			let u = random_id()?;
			input.uid = Some(u.clone());
			u
		}
	};

	let (ical_text, etag, extracted) = render_object(&input)?;

	app.meta_adapter
		.upsert_calendar_object(tn_id, cal_id, &uid, &ical_text, &etag, &extracted)
		.await?;

	let stored = app
		.meta_adapter
		.get_calendar_object(tn_id, cal_id, &uid)
		.await?
		.ok_or(Error::NotFound)?;
	Ok(object_to_output(&stored))
}

pub async fn create_object(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Path(cal_id): Path<u64>,
	Json(body): Json<CalendarObjectInput>,
) -> ClResult<(StatusCode, Json<ApiResponse<CalendarObjectOutput>>)> {
	app.meta_adapter.get_calendar(tn_id, cal_id).await?.ok_or(Error::NotFound)?;
	let out = write_object(&app, tn_id, cal_id, body).await?;
	let mut resp = ApiResponse::new(out);
	if let Some(id) = req_id {
		resp = resp.with_req_id(id);
	}
	Ok((StatusCode::CREATED, Json(resp)))
}

pub async fn put_object(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Path((cal_id, uid)): Path<(u64, String)>,
	Json(mut body): Json<CalendarObjectInput>,
) -> ClResult<(StatusCode, Json<ApiResponse<CalendarObjectOutput>>)> {
	app.meta_adapter.get_calendar(tn_id, cal_id).await?.ok_or(Error::NotFound)?;
	body.uid = Some(uid);
	let out = write_object(&app, tn_id, cal_id, body).await?;
	let mut resp = ApiResponse::new(out);
	if let Some(id) = req_id {
		resp = resp.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(resp)))
}

/// Apply an `EventPatch` onto an existing `EventInput` in place.
///
/// Scalar fields replace when `Some(_)`, keep when `None`. Collection fields (`attendees`,
/// `categories`, `alarms`) replace when `Some(_)` (including empty vec) and keep when
/// `None` — the Option wrapper is how the PATCH body distinguishes "client omitted this
/// field" from "client wants this list cleared".
fn apply_event_patch(target: &mut EventInput, patch: EventPatch) {
	if let Some(v) = patch.summary {
		target.summary = Some(v);
	}
	if let Some(v) = patch.description {
		target.description = Some(v);
	}
	if let Some(v) = patch.location {
		target.location = Some(v);
	}
	if let Some(v) = patch.dtstart {
		target.dtstart = Some(v);
	}
	if let Some(v) = patch.dtend {
		target.dtend = Some(v);
	}
	if let Some(v) = patch.all_day {
		target.all_day = v;
	}
	if let Some(v) = patch.rrule {
		target.rrule = Some(v);
	}
	if let Some(v) = patch.exdate {
		target.exdate = v;
	}
	if let Some(v) = patch.status {
		target.status = Some(v);
	}
	if let Some(v) = patch.organizer {
		target.organizer = Some(v);
	}
	if let Some(v) = patch.attendees {
		target.attendees = v;
	}
	if let Some(v) = patch.categories {
		target.categories = v;
	}
	if let Some(v) = patch.alarms {
		target.alarms = v;
	}
}

fn apply_todo_patch(target: &mut TodoInput, patch: TodoPatch) {
	if let Some(v) = patch.summary {
		target.summary = Some(v);
	}
	if let Some(v) = patch.description {
		target.description = Some(v);
	}
	if let Some(v) = patch.dtstart {
		target.dtstart = Some(v);
	}
	if let Some(v) = patch.due {
		target.due = Some(v);
	}
	if let Some(v) = patch.completed {
		target.completed = Some(v);
	}
	if let Some(v) = patch.priority {
		target.priority = Some(v);
	}
	if let Some(v) = patch.status {
		target.status = Some(v);
	}
	if let Some(v) = patch.rrule {
		target.rrule = Some(v);
	}
	if let Some(v) = patch.categories {
		target.categories = v;
	}
	if let Some(v) = patch.alarms {
		target.alarms = v;
	}
}

pub async fn patch_object(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Path((cal_id, uid)): Path<(u64, String)>,
	Json(patch): Json<CalendarObjectPatch>,
) -> ClResult<(StatusCode, Json<ApiResponse<CalendarObjectOutput>>)> {
	app.meta_adapter.get_calendar(tn_id, cal_id).await?.ok_or(Error::NotFound)?;

	// Decode the stored blob to its full input shape so unspecified fields survive the
	// regenerate step (the projection parser used by `get_object` drops attendees /
	// alarms / categories).
	let stored = app
		.meta_adapter
		.get_calendar_object(tn_id, cal_id, &uid)
		.await?
		.ok_or(Error::NotFound)?;
	let (mut merged, _warnings) = ical::parse_to_input(&stored.ical)
		.ok_or_else(|| Error::Internal("stored iCalendar not parseable".into()))?;
	merged.uid = Some(uid.clone());

	// The patch routes to whichever sub-component the stored object has. If the client
	// sends `event` for a VTODO (or vice versa), that's a client error — treat as a
	// validation failure rather than silently upgrading the component type.
	match (&merged.event, &merged.todo, patch.event, patch.todo) {
		(Some(_), _, Some(ev), None) => {
			let target = merged.event.as_mut().ok_or(Error::Internal("event missing".into()))?;
			apply_event_patch(target, ev);
		}
		(_, Some(_), None, Some(td)) => {
			let target = merged.todo.as_mut().ok_or(Error::Internal("todo missing".into()))?;
			apply_todo_patch(target, td);
		}
		(_, _, None, None) => {
			// Empty patch is a no-op at the component level, but we still regenerate so
			// the etag bumps and CalDAV sync tokens advance — matches what PUT does on
			// an unchanged body.
		}
		_ => {
			return Err(Error::ValidationError(
				"patch component does not match stored object".into(),
			));
		}
	}

	let out = write_object(&app, tn_id, cal_id, merged).await?;
	let mut resp = ApiResponse::new(out);
	if let Some(id) = req_id {
		resp = resp.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(resp)))
}

pub async fn delete_object(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	Path((cal_id, uid)): Path<(u64, String)>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	app.meta_adapter.delete_calendar_object(tn_id, cal_id, &uid).await?;
	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

/// Regenerate iCalendar + extracted projection for an input. Mirrors the second half of
/// [`write_object`] but returns the pieces instead of writing — the split path needs
/// to hand these to the adapter's transactional writer.
fn render_object(
	input: &CalendarObjectInput,
) -> ClResult<(String, String, CalendarObjectExtracted)> {
	let ical_text = ical::generate(input);
	let etag = ical::etag_of(&ical_text);
	let (extracted, _, _) = ical::parse(&ical_text).ok_or_else(|| {
		error!("failed to re-parse own generated iCalendar");
		Error::Internal("iCalendar generation produced unparseable output".into())
	})?;
	Ok((ical_text, etag, extracted))
}

/// `POST /api/calendars/{cal_id}/objects/{uid}/split` — atomically fork a recurring
/// series. Replaces the previous three-round-trip client dance (PATCH master, DELETE
/// overrides, POST tail) whose intermediate failures could leave the series half-split
/// on the server. Here all three mutations commit together or not at all.
pub async fn split_series(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Path((cal_id, uid)): Path<(u64, String)>,
	Json(body): Json<SplitSeriesRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<SplitSeriesResponse>>)> {
	app.meta_adapter.get_calendar(tn_id, cal_id).await?.ok_or(Error::NotFound)?;

	let split_at = parse_iso_ts(&body.split_at)
		.ok_or_else(|| Error::ValidationError("invalid splitAt".into()))?;

	// Load and decode the existing master. Must exist and must actually be recurring —
	// splitting a non-recurring object is a client mistake we reject with 400 rather
	// than silently creating a duplicate.
	let stored = app
		.meta_adapter
		.get_calendar_object(tn_id, cal_id, &uid)
		.await?
		.ok_or(Error::NotFound)?;
	if stored.extracted.rrule.is_none() {
		return Err(Error::ValidationError("object is not a recurring series".into()));
	}
	let (mut merged, _warnings) = ical::parse_to_input(&stored.ical)
		.ok_or_else(|| Error::Internal("stored iCalendar not parseable".into()))?;
	merged.uid = Some(uid.clone());

	// Apply the master patch. Semantics mirror `patch_object`: component type is
	// fixed by what's stored; a mismatched patch body is a validation error.
	match (&merged.event, &merged.todo, body.master_patch.event, body.master_patch.todo) {
		(Some(_), _, Some(ev), None) => {
			let target = merged.event.as_mut().ok_or(Error::Internal("event missing".into()))?;
			apply_event_patch(target, ev);
		}
		(_, Some(_), None, Some(td)) => {
			let target = merged.todo.as_mut().ok_or(Error::Internal("todo missing".into()))?;
			apply_todo_patch(target, td);
		}
		(_, _, None, None) => {}
		_ => {
			return Err(Error::ValidationError(
				"master patch component does not match stored object".into(),
			));
		}
	}

	// Tail must describe a component; force a fresh server-minted UID so the new
	// series is independently addressable and can't collide with the master.
	let mut tail_input = body.tail;
	if tail_input.event.is_none() && tail_input.todo.is_none() {
		return Err(Error::ValidationError("tail event or todo required".into()));
	}
	let tail_uid = random_id()?;
	tail_input.uid = Some(tail_uid.clone());
	tail_input.recurrence_id = None;

	let (master_ical, master_etag, master_extracted) = render_object(&merged)?;
	let (tail_ical, tail_etag, tail_extracted) = render_object(&tail_input)?;

	app.meta_adapter
		.split_calendar_object_series(
			tn_id,
			cal_id,
			CalendarObjectWrite {
				uid: &uid,
				ical: &master_ical,
				etag: &master_etag,
				extracted: &master_extracted,
			},
			CalendarObjectWrite {
				uid: &tail_uid,
				ical: &tail_ical,
				etag: &tail_etag,
				extracted: &tail_extracted,
			},
			split_at,
		)
		.await?;

	let master_row = app
		.meta_adapter
		.get_calendar_object(tn_id, cal_id, &uid)
		.await?
		.ok_or_else(|| Error::Internal("master missing after split".into()))?;
	let tail_row = app
		.meta_adapter
		.get_calendar_object(tn_id, cal_id, &tail_uid)
		.await?
		.ok_or_else(|| Error::Internal("tail missing after split".into()))?;

	let mut resp = ApiResponse::new(SplitSeriesResponse {
		master: object_to_output(&master_row),
		tail: object_to_output(&tail_row),
	});
	if let Some(id) = req_id {
		resp = resp.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(resp)))
}

// Recurrence-override handlers
//******************************
//
// Exceptions (VEVENTs with `RECURRENCE-ID` matching a master's occurrence) are stored
// as separate rows keyed by `(uid, recurrence_id)`. The master row (`recurrence_id IS NULL`)
// is untouched by these endpoints — editing one occurrence of a recurring series creates
// or patches an exception row; the series-level RRULE only changes via the master routes.

pub async fn list_exceptions(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Path((cal_id, uid)): Path<(u64, String)>,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<CalendarObjectOutput>>>)> {
	app.meta_adapter.get_calendar(tn_id, cal_id).await?.ok_or(Error::NotFound)?;
	let rows = app.meta_adapter.list_calendar_object_overrides(tn_id, cal_id, &uid).await?;
	let out: Vec<CalendarObjectOutput> = rows.iter().map(object_to_output).collect();
	let mut resp = ApiResponse::new(out);
	if let Some(id) = req_id {
		resp = resp.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(resp)))
}

pub async fn get_exception(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Path((cal_id, uid, rid)): Path<(u64, String, String)>,
) -> ClResult<(StatusCode, Json<ApiResponse<CalendarObjectOutput>>)> {
	let ts =
		parse_iso_ts(&rid).ok_or_else(|| Error::ValidationError("invalid recurrence_id".into()))?;
	let row = app
		.meta_adapter
		.get_calendar_object_override(tn_id, cal_id, &uid, ts)
		.await?
		.ok_or(Error::NotFound)?;
	let mut resp = ApiResponse::new(object_to_output(&row));
	if let Some(id) = req_id {
		resp = resp.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(resp)))
}

/// Create or replace a recurrence override. Treat as PUT: the body is a full
/// `CalendarObjectInput` for the override VEVENT. `recurrence_id` is forced from the URL
/// path so the client can't store a mismatched value.
pub async fn put_exception(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Path((cal_id, uid, rid)): Path<(u64, String, String)>,
	Json(mut body): Json<CalendarObjectInput>,
) -> ClResult<(StatusCode, Json<ApiResponse<CalendarObjectOutput>>)> {
	// Master must already exist — overrides need a series to attach to.
	app.meta_adapter
		.get_calendar_object(tn_id, cal_id, &uid)
		.await?
		.ok_or(Error::NotFound)?;
	parse_iso_ts(&rid).ok_or_else(|| Error::ValidationError("invalid recurrence_id".into()))?;
	body.uid = Some(uid);
	body.recurrence_id = Some(rid);
	let out = write_object(&app, tn_id, cal_id, body).await?;
	let mut resp = ApiResponse::new(out);
	if let Some(id) = req_id {
		resp = resp.with_req_id(id);
	}
	Ok((StatusCode::CREATED, Json(resp)))
}

pub async fn patch_exception(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Path((cal_id, uid, rid)): Path<(u64, String, String)>,
	Json(patch): Json<CalendarObjectPatch>,
) -> ClResult<(StatusCode, Json<ApiResponse<CalendarObjectOutput>>)> {
	let ts =
		parse_iso_ts(&rid).ok_or_else(|| Error::ValidationError("invalid recurrence_id".into()))?;
	app.meta_adapter.get_calendar(tn_id, cal_id).await?.ok_or(Error::NotFound)?;
	let stored = app
		.meta_adapter
		.get_calendar_object_override(tn_id, cal_id, &uid, ts)
		.await?
		.ok_or(Error::NotFound)?;
	let (mut merged, _warnings) = ical::parse_to_input(&stored.ical)
		.ok_or_else(|| Error::Internal("stored iCalendar not parseable".into()))?;
	merged.uid = Some(uid.clone());
	merged.recurrence_id = Some(rid);

	match (&merged.event, &merged.todo, patch.event, patch.todo) {
		(Some(_), _, Some(ev), None) => {
			let target = merged.event.as_mut().ok_or(Error::Internal("event missing".into()))?;
			apply_event_patch(target, ev);
		}
		(_, Some(_), None, Some(td)) => {
			let target = merged.todo.as_mut().ok_or(Error::Internal("todo missing".into()))?;
			apply_todo_patch(target, td);
		}
		(_, _, None, None) => {}
		_ => {
			return Err(Error::ValidationError(
				"patch component does not match stored object".into(),
			));
		}
	}

	let out = write_object(&app, tn_id, cal_id, merged).await?;
	let mut resp = ApiResponse::new(out);
	if let Some(id) = req_id {
		resp = resp.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(resp)))
}

pub async fn delete_exception(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(_id_tag): IdTag,
	Auth(_auth): Auth,
	Path((cal_id, uid, rid)): Path<(u64, String, String)>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	let ts =
		parse_iso_ts(&rid).ok_or_else(|| Error::ValidationError("invalid recurrence_id".into()))?;
	app.meta_adapter
		.delete_calendar_object_override(tn_id, cal_id, &uid, ts)
		.await?;
	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

// Tests
//*******

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
	use super::*;
	use crate::types::{Alarm, Attendee};

	/// Full-fidelity round-trip: generate a VCALENDAR from an EventInput that includes
	/// description, attendees, and alarms; then parse it back and confirm everything
	/// the patch-merge path relies on survives.
	#[test]
	fn parse_to_input_preserves_full_event() {
		let original = CalendarObjectInput {
			uid: Some("full-1".into()),
			recurrence_id: None,
			event: Some(EventInput {
				summary: Some("Team sync".into()),
				description: Some("Quarterly planning. Bring notes.".into()),
				location: Some("Room A".into()),
				dtstart: Some("2026-05-10T09:00:00Z".into()),
				dtend: Some("2026-05-10T10:00:00Z".into()),
				all_day: false,
				rrule: None,
				exdate: vec![],
				status: Some("CONFIRMED".into()),
				organizer: Some("mailto:alice@example.org".into()),
				attendees: vec![
					Attendee {
						address: "mailto:bob@example.org".into(),
						cn: Some("Bob".into()),
						partstat: Some("ACCEPTED".into()),
						role: Some("REQ-PARTICIPANT".into()),
						rsvp: Some(true),
					},
					Attendee {
						address: "mailto:carol@example.org".into(),
						cn: Some("Carol".into()),
						partstat: Some("NEEDS-ACTION".into()),
						role: None,
						rsvp: None,
					},
				],
				categories: vec!["work".into(), "planning".into()],
				alarms: vec![Alarm {
					action: Some("DISPLAY".into()),
					trigger: Some("-PT15M".into()),
					description: Some("Reminder".into()),
				}],
			}),
			todo: None,
		};

		let ical_text = ical::generate(&original);
		let (parsed, _warnings) = ical::parse_to_input(&ical_text).expect("parse_to_input failed");
		let ev = parsed.event.expect("missing event");
		assert_eq!(parsed.uid.as_deref(), Some("full-1"));
		assert_eq!(ev.summary.as_deref(), Some("Team sync"));
		assert_eq!(ev.description.as_deref(), Some("Quarterly planning. Bring notes."));
		assert_eq!(ev.location.as_deref(), Some("Room A"));
		assert_eq!(ev.dtstart.as_deref(), Some("2026-05-10T09:00:00Z"));
		assert_eq!(ev.dtend.as_deref(), Some("2026-05-10T10:00:00Z"));
		assert_eq!(ev.status.as_deref(), Some("CONFIRMED"));
		assert_eq!(ev.attendees.len(), 2);
		assert_eq!(ev.attendees[0].address, "mailto:bob@example.org");
		assert_eq!(ev.attendees[0].cn.as_deref(), Some("Bob"));
		assert_eq!(ev.attendees[0].partstat.as_deref(), Some("ACCEPTED"));
		assert_eq!(ev.attendees[0].rsvp, Some(true));
		assert_eq!(ev.categories, vec!["work".to_string(), "planning".into()]);
		assert_eq!(ev.alarms.len(), 1);
		assert_eq!(ev.alarms[0].action.as_deref(), Some("DISPLAY"));
		assert_eq!(ev.alarms[0].trigger.as_deref(), Some("-PT15M"));
		assert_eq!(ev.alarms[0].description.as_deref(), Some("Reminder"));
	}

	/// The core PATCH invariant: sending only dtstart/dtend must leave description,
	/// attendees, and alarms at their stored values.
	#[test]
	fn patch_event_dtstart_dtend_preserves_other_fields() {
		// Simulate the stored VCALENDAR the server would have for this event.
		let stored_ical = ical::generate(&CalendarObjectInput {
			uid: Some("resize-me".into()),
			recurrence_id: None,
			event: Some(EventInput {
				summary: Some("Design review".into()),
				description: Some("Review the new onboarding flow.".into()),
				location: Some("Zoom".into()),
				dtstart: Some("2026-04-23T20:00:00Z".into()),
				dtend: Some("2026-04-23T22:00:00Z".into()),
				all_day: false,
				rrule: None,
				exdate: vec![],
				status: Some("CONFIRMED".into()),
				organizer: Some("mailto:dana@example.org".into()),
				attendees: vec![Attendee {
					address: "mailto:eve@example.org".into(),
					cn: Some("Eve".into()),
					partstat: Some("ACCEPTED".into()),
					role: Some("REQ-PARTICIPANT".into()),
					rsvp: Some(true),
				}],
				categories: vec!["work".into()],
				alarms: vec![Alarm {
					action: Some("DISPLAY".into()),
					trigger: Some("-PT10M".into()),
					description: Some("Heads up".into()),
				}],
			}),
			todo: None,
		});

		// Decode to full input, same as patch_object does.
		let (mut merged, _) = ical::parse_to_input(&stored_ical).unwrap();

		// Patch: only new dtend (resize) — matches the frontend drag-resize case.
		let patch =
			EventPatch { dtend: Some("2026-04-23T08:24:00Z".into()), ..EventPatch::default() };
		apply_event_patch(merged.event.as_mut().unwrap(), patch);

		let ev = merged.event.as_ref().unwrap();
		assert_eq!(ev.dtstart.as_deref(), Some("2026-04-23T20:00:00Z"));
		assert_eq!(ev.dtend.as_deref(), Some("2026-04-23T08:24:00Z"));
		assert_eq!(ev.description.as_deref(), Some("Review the new onboarding flow."));
		assert_eq!(ev.location.as_deref(), Some("Zoom"));
		assert_eq!(ev.summary.as_deref(), Some("Design review"));
		assert_eq!(ev.attendees.len(), 1);
		assert_eq!(ev.attendees[0].address, "mailto:eve@example.org");
		assert_eq!(ev.alarms.len(), 1);
		assert_eq!(ev.alarms[0].trigger.as_deref(), Some("-PT10M"));
		assert_eq!(ev.categories, vec!["work".to_string()]);

		// And confirm the round-trip through generate → parse_to_input still carries
		// those fields — this is what the real handler produces on the wire.
		let regenerated = ical::generate(&merged);
		let (reparsed, _) = ical::parse_to_input(&regenerated).unwrap();
		let ev2 = reparsed.event.unwrap();
		assert_eq!(ev2.dtend.as_deref(), Some("2026-04-23T08:24:00Z"));
		assert_eq!(ev2.description.as_deref(), Some("Review the new onboarding flow."));
		assert_eq!(ev2.attendees.len(), 1);
		assert_eq!(ev2.alarms.len(), 1);
	}

	/// Empty-vec patch means "clear this list" — distinct from `None` which means
	/// "keep existing". This is the main reason the patch types wrap collections in
	/// `Option<Vec<_>>` rather than defaulting to `Vec::new`.
	#[test]
	fn patch_event_empty_vec_clears_list() {
		let mut target = EventInput {
			attendees: vec![Attendee { address: "mailto:x@y".into(), ..Attendee::default() }],
			categories: vec!["a".into()],
			alarms: vec![Alarm { action: Some("DISPLAY".into()), ..Alarm::default() }],
			..EventInput::default()
		};
		let patch = EventPatch {
			attendees: Some(Vec::new()),
			categories: Some(Vec::new()),
			alarms: Some(Vec::new()),
			..EventPatch::default()
		};
		apply_event_patch(&mut target, patch);
		assert!(target.attendees.is_empty());
		assert!(target.categories.is_empty());
		assert!(target.alarms.is_empty());
	}

	#[test]
	fn patch_todo_priority_only_preserves_description() {
		let stored_ical = ical::generate(&CalendarObjectInput {
			uid: Some("todo-1".into()),
			recurrence_id: None,
			event: None,
			todo: Some(TodoInput {
				summary: Some("Buy milk".into()),
				description: Some("2% fat, 2L.".into()),
				dtstart: None,
				due: Some("2026-04-25T00:00:00Z".into()),
				completed: None,
				priority: Some(5),
				status: Some("NEEDS-ACTION".into()),
				rrule: None,
				categories: vec!["errands".into()],
				alarms: vec![],
			}),
		});
		let (mut merged, _) = ical::parse_to_input(&stored_ical).unwrap();
		apply_todo_patch(
			merged.todo.as_mut().unwrap(),
			TodoPatch { priority: Some(1), ..TodoPatch::default() },
		);
		let td = merged.todo.as_ref().unwrap();
		assert_eq!(td.priority, Some(1));
		assert_eq!(td.summary.as_deref(), Some("Buy milk"));
		assert_eq!(td.description.as_deref(), Some("2% fat, 2L."));
		assert_eq!(td.due.as_deref(), Some("2026-04-25T00:00:00Z"));
		assert_eq!(td.categories, vec!["errands".to_string()]);
	}
}

// vim: ts=4
