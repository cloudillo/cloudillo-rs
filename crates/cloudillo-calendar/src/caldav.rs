// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! CalDAV endpoints — PROPFIND, REPORT, and resource GET/PUT/DELETE.
//!
//! Wiring (see `crates/cloudillo/src/routes.rs`):
//!
//! ```text
//! GET   /.well-known/caldav                          → 301 → /dav/principal/
//! ANY   /dav/calendars/                              → home-set PROPFIND
//! ANY   /dav/calendars/{cal_name}/                   → collection PROPFIND / REPORT
//! ANY   /dav/calendars/{cal_name}/{resource}         → .ics GET / PUT / DELETE
//! ```
//!
//! Auth: `cloudillo_dav::dav_basic_auth` applied as a layer on the `/dav/...` router. All
//! methods share the same handler and dispatch on `request.method()`.

use std::fmt::Write as _;

use axum::{
	body::{Body, to_bytes},
	extract::{Path, Request, State},
	http::{Method, Response, StatusCode, header},
};

use cloudillo_core::{IdTag, extract::Auth, prelude::*};
use cloudillo_dav::{
	MultiResponse, PropName, PropStat, Propfind, Report, escape_xml, etag_header, plain_error,
	render_multistatus, unquote_etag, urldecode_path, urlencode_path,
};
use cloudillo_types::meta_adapter::ListCalendarObjectOptions;

use crate::{ical, types::CalendarObjectInput};

const PRINCIPAL_PATH: &str = "/dav/principal/";
const CALENDARS_PATH: &str = "/dav/calendars/";
const DAV_NS: &str = cloudillo_dav::NS_DAV;
const CALDAV_NS: &str = cloudillo_dav::NS_CALDAV;
const CALSERVER_NS: &str = cloudillo_dav::NS_CALSERVER;

const MAX_BODY_BYTES: usize = 1024 * 1024;
/// Ceiling on how many rows one `sync-collection` REPORT can return. Mirrors the CardDAV
/// constant in `cloudillo-contact`; keeps responses bounded even when the client requests
/// more.
const MAX_SYNC_PAGE: u32 = 1_000;

/// Matches the CardDAV module's constant — discovery clients (DAVx5 etc.) decide which
/// protocols to probe from the `DAV:` response header, so every DAV response advertises
/// both `addressbook` and `calendar-access` to avoid one protocol masking the other.
const DAV_CAPABILITIES: &str = "1, 2, 3, addressbook, calendar-access";

// Helpers
//*********

fn xml_response(status: StatusCode, body: String) -> Response<Body> {
	Response::builder()
		.status(status)
		.header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
		.header("DAV", DAV_CAPABILITIES)
		.body(Body::from(body))
		.unwrap_or_else(|_| plain_error(StatusCode::INTERNAL_SERVER_ERROR, "xml build failed"))
}

fn ok_empty() -> Response<Body> {
	Response::builder()
		.status(StatusCode::OK)
		.header("DAV", DAV_CAPABILITIES)
		.header("Allow", "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, REPORT")
		.body(Body::empty())
		.unwrap_or_else(|_| Response::new(Body::empty()))
}

fn encode_sync_token(ts: i64) -> String {
	format!("urn:cloudillo:sync:{ts}")
}

fn decode_sync_token(token: &str) -> Option<i64> {
	token.strip_prefix("urn:cloudillo:sync:").and_then(|s| s.parse().ok())
}

fn has_prop(props: &[PropName], ns: &str, local: &str) -> bool {
	props.iter().any(|p| p.is(ns, local))
}

fn matches_prop(pf: &Propfind, ns: &str, local: &str) -> bool {
	match pf {
		Propfind::AllProp | Propfind::PropName => true,
		Propfind::Prop(list) => has_prop(list, ns, local),
	}
}

fn depth(req: &Request<Body>) -> u8 {
	match req.headers().get("Depth").and_then(|h| h.to_str().ok()) {
		Some("1") => 1,
		Some("infinity") => u8::MAX,
		_ => 0,
	}
}

/// Read the request body as UTF-8. RFC 5545 §3.1 mandates UTF-8 for iCalendar bodies.
async fn read_body(req: Request<Body>) -> Result<String, Response<Body>> {
	let bytes = to_bytes(req.into_body(), MAX_BODY_BYTES).await.map_err(|e| {
		warn!("CalDAV body read failed (likely > {} bytes): {:?}", MAX_BODY_BYTES, e);
		plain_error(StatusCode::PAYLOAD_TOO_LARGE, "request body too large")
	})?;
	String::from_utf8(bytes.to_vec())
		.map_err(|_| plain_error(StatusCode::BAD_REQUEST, "request body must be UTF-8"))
}

// .well-known/caldav redirect
//*****************************

pub async fn well_known(req: Request<Body>) -> Response<Body> {
	let Some(id_tag) = req.extensions().get::<IdTag>() else {
		warn!("well-known: IdTag not present in request extensions");
		return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "host not resolved");
	};
	let location = format!("https://cl-o.{}{}", id_tag.0, PRINCIPAL_PATH);

	Response::builder()
		.status(StatusCode::MOVED_PERMANENTLY)
		.header(header::LOCATION, location)
		.body(Body::empty())
		.unwrap_or_else(|e| {
			warn!("well-known: redirect builder failed: {e:?}");
			Response::new(Body::empty())
		})
}

// Home set — lists calendars
//****************************

pub async fn handle_home(
	State(app): State<App>,
	Auth(auth): Auth,
	req: Request<Body>,
) -> Response<Body> {
	let method = req.method().clone();
	let tn_id = auth.tn_id;

	if method == Method::OPTIONS {
		return ok_empty();
	}
	if method.as_str() != "PROPFIND" {
		return plain_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
	}

	let d = depth(&req);
	let body = match read_body(req).await {
		Ok(b) => b,
		Err(r) => return r,
	};
	let pf = cloudillo_dav::propfind::parse(&body);

	let mut responses: Vec<MultiResponse> = Vec::new();
	responses.push(home_self_response(&pf));

	if d >= 1 {
		let cals = match app.meta_adapter.list_calendars(tn_id).await {
			Ok(c) => c,
			Err(e) => {
				warn!("CalDAV home list failed: {:?}", e);
				return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "db error");
			}
		};
		for cal in &cals {
			responses.push(collection_response(&pf, cal));
		}
	}

	xml_response(StatusCode::MULTI_STATUS, render_multistatus(&responses, None))
}

fn home_self_response(pf: &Propfind) -> MultiResponse {
	let want = |ns: &str, local: &str| matches_prop(pf, ns, local);
	let mut props = String::new();
	if want(DAV_NS, "resourcetype") {
		props.push_str("<d:resourcetype><d:collection/></d:resourcetype>");
	}
	if want(DAV_NS, "displayname") {
		props.push_str("<d:displayname>Calendars</d:displayname>");
	}
	MultiResponse::new(CALENDARS_PATH).with_propstat(PropStat::ok(props))
}

fn collection_href(name: &str) -> String {
	format!("{}{}/", CALENDARS_PATH, urlencode_path(name))
}

fn collection_response(
	pf: &Propfind,
	cal: &cloudillo_types::meta_adapter::Calendar,
) -> MultiResponse {
	let href = collection_href(&cal.name);
	let want = |ns: &str, local: &str| matches_prop(pf, ns, local);
	let mut props = String::new();

	if want(DAV_NS, "resourcetype") {
		props.push_str("<d:resourcetype><d:collection/><cal:calendar/></d:resourcetype>");
	}
	if want(DAV_NS, "displayname") {
		let _ = write!(&mut props, "<d:displayname>{}</d:displayname>", escape_xml(&cal.name));
	}
	if want(CALDAV_NS, "calendar-description")
		&& let Some(desc) = cal.description.as_deref()
	{
		let _ = write!(
			&mut props,
			"<cal:calendar-description>{}</cal:calendar-description>",
			escape_xml(desc),
		);
	}
	if want(CALSERVER_NS, "calendar-color")
		&& let Some(color) = cal.color.as_deref()
	{
		let _ = write!(&mut props, "<cs:calendar-color>{}</cs:calendar-color>", escape_xml(color));
	}
	if want(CALDAV_NS, "calendar-timezone")
		&& let Some(tz) = cal.timezone.as_deref()
	{
		let _ = write!(
			&mut props,
			"<cal:calendar-timezone>{}</cal:calendar-timezone>",
			escape_xml(tz),
		);
	}
	if want(CALDAV_NS, "supported-calendar-component-set") {
		props.push_str("<cal:supported-calendar-component-set>");
		for comp in cal.components.split(',').map(str::trim).filter(|s| !s.is_empty()) {
			let _ = write!(&mut props, "<cal:comp name=\"{}\"/>", escape_xml(comp));
		}
		props.push_str("</cal:supported-calendar-component-set>");
	}
	if want(CALDAV_NS, "supported-calendar-data") {
		props.push_str(
			"<cal:supported-calendar-data>\
				<cal:calendar-data content-type=\"text/calendar\" version=\"2.0\"/>\
			</cal:supported-calendar-data>",
		);
	}
	if want(CALDAV_NS, "max-resource-size") {
		props.push_str("<cal:max-resource-size>1048576</cal:max-resource-size>");
	}
	if want(DAV_NS, "supported-report-set") {
		props.push_str(
			"<d:supported-report-set>\
				<d:supported-report><d:report><cal:calendar-multiget/></d:report></d:supported-report>\
				<d:supported-report><d:report><cal:calendar-query/></d:report></d:supported-report>\
				<d:supported-report><d:report><d:sync-collection/></d:report></d:supported-report>\
			</d:supported-report-set>",
		);
	}
	if want(CALSERVER_NS, "getctag") {
		let _ = write!(&mut props, "<cs:getctag>{}</cs:getctag>", escape_xml(&cal.ctag));
	}
	if want(DAV_NS, "sync-token") {
		let _ = write!(
			&mut props,
			"<d:sync-token>{}</d:sync-token>",
			escape_xml(&encode_sync_token(cal.updated_at.0)),
		);
	}

	MultiResponse::new(href).with_propstat(PropStat::ok(props))
}

// Collection (single calendar) — PROPFIND / REPORT
//***************************************************

pub async fn handle_collection(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(cal_name_raw): Path<String>,
	req: Request<Body>,
) -> Response<Body> {
	let method = req.method().clone();
	let tn_id = auth.tn_id;
	let Some(cal_name) = urldecode_path(&cal_name_raw) else {
		return plain_error(StatusCode::BAD_REQUEST, "invalid URL encoding");
	};

	if method == Method::OPTIONS {
		return ok_empty();
	}

	let cal = match app.meta_adapter.get_calendar_by_name(tn_id, &cal_name).await {
		Ok(Some(c)) => c,
		Ok(None) => return plain_error(StatusCode::NOT_FOUND, "no such calendar"),
		Err(e) => {
			warn!("CalDAV collection lookup failed: {:?}", e);
			return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "db error");
		}
	};

	match method.as_str() {
		"PROPFIND" => propfind_collection(&app, tn_id, cal, req).await,
		"REPORT" => report_collection(&app, tn_id, cal, req).await,
		"MKCOL" | "MKCALENDAR" => plain_error(StatusCode::METHOD_NOT_ALLOWED, "already exists"),
		_ => plain_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
	}
}

async fn propfind_collection(
	app: &App,
	tn_id: TnId,
	cal: cloudillo_types::meta_adapter::Calendar,
	req: Request<Body>,
) -> Response<Body> {
	let d = depth(&req);
	let body = match read_body(req).await {
		Ok(b) => b,
		Err(r) => return r,
	};
	let pf = cloudillo_dav::propfind::parse(&body);

	let mut responses: Vec<MultiResponse> = Vec::new();
	responses.push(collection_response(&pf, &cal));

	if d >= 1 {
		let rows = match app
			.meta_adapter
			.list_calendar_objects(tn_id, cal.cal_id, &ListCalendarObjectOptions::default())
			.await
		{
			Ok(r) => r,
			Err(e) => {
				warn!("CalDAV list_calendar_objects failed: {:?}", e);
				return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "db error");
			}
		};
		for row in &rows {
			let href = format!(
				"{}{}",
				collection_href(&cal.name),
				urlencode_path(&format!("{}.ics", row.uid)),
			);
			responses.push(resource_response(&pf, &href, &row.etag, None));
		}
	}

	xml_response(StatusCode::MULTI_STATUS, render_multistatus(&responses, None))
}

fn resource_response(
	pf: &Propfind,
	href: &str,
	etag: &str,
	ical_body: Option<&str>,
) -> MultiResponse {
	let want = |ns: &str, local: &str| matches_prop(pf, ns, local);
	let mut props = String::new();
	if want(DAV_NS, "resourcetype") {
		props.push_str("<d:resourcetype/>");
	}
	if want(DAV_NS, "getetag") {
		let _ = write!(&mut props, "<d:getetag>{}</d:getetag>", escape_xml(&etag_header(etag)));
	}
	if want(DAV_NS, "getcontenttype") {
		props.push_str(
			"<d:getcontenttype>text/calendar; charset=utf-8; component=vevent</d:getcontenttype>",
		);
	}
	if want(CALDAV_NS, "calendar-data")
		&& let Some(body) = ical_body
	{
		let _ = write!(&mut props, "<cal:calendar-data>{}</cal:calendar-data>", escape_xml(body));
	}
	MultiResponse::new(href).with_propstat(PropStat::ok(props))
}

async fn report_collection(
	app: &App,
	tn_id: TnId,
	cal: cloudillo_types::meta_adapter::Calendar,
	req: Request<Body>,
) -> Response<Body> {
	let body = match read_body(req).await {
		Ok(b) => b,
		Err(r) => return r,
	};
	match cloudillo_dav::report::parse(&body) {
		Report::CalendarMultiget(r) => {
			let uids: Vec<String> = r
				.hrefs
				.iter()
				.filter_map(|h| {
					let last = h.rsplit('/').next()?;
					let decoded = urldecode_path(last)?;
					decoded.strip_suffix(".ics").map(str::to_string)
				})
				.collect();
			let uid_refs: Vec<&str> = uids.iter().map(String::as_str).collect();

			let rows = match app
				.meta_adapter
				.get_calendar_objects_by_uids(tn_id, cal.cal_id, &uid_refs)
				.await
			{
				Ok(r) => r,
				Err(e) => {
					warn!("CalDAV multiget lookup failed: {:?}", e);
					return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "db error");
				}
			};
			let found: std::collections::HashMap<
				String,
				&cloudillo_types::meta_adapter::CalendarObject,
			> = rows.iter().map(|r| (r.uid.to_string(), r)).collect();

			let pf = Propfind::Prop(r.props);
			let mut responses: Vec<MultiResponse> = Vec::new();
			for href in &r.hrefs {
				let last = href.rsplit('/').next().unwrap_or("");
				let uid =
					urldecode_path(last).and_then(|s| s.strip_suffix(".ics").map(str::to_string));
				match uid.and_then(|u| found.get(&u).copied()) {
					Some(row) => {
						responses.push(resource_response(&pf, href, &row.etag, Some(&row.ical)));
					}
					None => responses.push(MultiResponse::new(href).with_status(404)),
				}
			}
			xml_response(StatusCode::MULTI_STATUS, render_multistatus(&responses, None))
		}
		Report::CalendarQuery(r) => {
			// Superset semantics: feed the time range to the adapter and let the client
			// do precise filtering. No RRULE expansion here.
			let start =
				r.time_range.as_ref().and_then(|(s, _)| s.as_deref()).and_then(parse_caldav_dt);
			let end =
				r.time_range.as_ref().and_then(|(_, e)| e.as_deref()).and_then(parse_caldav_dt);
			let rows = match app
				.meta_adapter
				.query_calendar_objects_in_range(
					tn_id,
					cal.cal_id,
					r.component.as_deref(),
					start,
					end,
				)
				.await
			{
				Ok(r) => r,
				Err(e) => {
					warn!("CalDAV calendar-query failed: {:?}", e);
					return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "db error");
				}
			};

			let pf = Propfind::Prop(r.props);
			let mut responses: Vec<MultiResponse> = Vec::new();
			for row in &rows {
				let href = format!(
					"{}{}",
					collection_href(&cal.name),
					urlencode_path(&format!("{}.ics", row.uid)),
				);
				responses.push(resource_response(&pf, &href, &row.etag, Some(&row.ical)));
			}
			xml_response(StatusCode::MULTI_STATUS, render_multistatus(&responses, None))
		}
		Report::SyncCollection(r) => {
			let since = r.sync_token.as_deref().and_then(decode_sync_token).map(Timestamp);
			let effective_limit = r.limit.map_or(MAX_SYNC_PAGE, |n| n.min(MAX_SYNC_PAGE));
			let entries = match app
				.meta_adapter
				.list_calendar_objects_since(tn_id, cal.cal_id, since, Some(effective_limit))
				.await
			{
				Ok(e) => e,
				Err(e) => {
					warn!("CalDAV sync-collection failed: {:?}", e);
					return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "db error");
				}
			};
			let truncated = u32::try_from(entries.len()).unwrap_or(u32::MAX) >= effective_limit;
			let max_ts = entries.iter().map(|e| e.updated_at.0).max().unwrap_or(0);
			let token_ts = if truncated { max_ts } else { max_ts.max(cal.updated_at.0) };
			let new_token = encode_sync_token(token_ts);

			let pf = Propfind::Prop(r.props);
			let mut responses: Vec<MultiResponse> = Vec::new();
			for entry in &entries {
				let href = format!(
					"{}{}",
					collection_href(&cal.name),
					urlencode_path(&format!("{}.ics", entry.uid)),
				);
				if entry.deleted {
					responses.push(MultiResponse::new(href).with_status(404));
				} else {
					responses.push(resource_response(&pf, &href, &entry.etag, None));
				}
			}
			xml_response(StatusCode::MULTI_STATUS, render_multistatus(&responses, Some(&new_token)))
		}
		_ => plain_error(StatusCode::BAD_REQUEST, "unsupported report"),
	}
}

/// Parse a CalDAV `time-range` attribute — iCalendar basic format `YYYYMMDDTHHMMSSZ` or
/// `YYYYMMDD`. Returns `None` on malformed input (caller treats as "unbounded side").
fn parse_caldav_dt(value: &str) -> Option<Timestamp> {
	// Reuse the ical parser's single-datetime parser by wrapping in a small adapter.
	// We only use it for index filtering, so naive UTC is fine — the handler is explicit
	// that it returns a superset and clients filter precisely.
	let trimmed = value.trim();
	if trimmed.len() == 8 && trimmed.chars().all(|c| c.is_ascii_digit()) {
		return date_to_unix(trimmed).map(Timestamp);
	}
	if trimmed.len() >= 15 {
		let y: i32 = trimmed.get(0..4)?.parse().ok()?;
		let m: u32 = trimmed.get(4..6)?.parse().ok()?;
		let d: u32 = trimmed.get(6..8)?.parse().ok()?;
		let hh: u32 = trimmed.get(9..11)?.parse().ok()?;
		let mm: u32 = trimmed.get(11..13)?.parse().ok()?;
		let ss: u32 = trimmed.get(13..15)?.parse().ok()?;
		let date_secs = chrono::NaiveDate::from_ymd_opt(y, m, d)?
			.and_hms_opt(hh, mm, ss)?
			.and_utc()
			.timestamp();
		return Some(Timestamp(date_secs));
	}
	None
}

fn date_to_unix(s: &str) -> Option<i64> {
	let y: i32 = s.get(0..4)?.parse().ok()?;
	let m: u32 = s.get(4..6)?.parse().ok()?;
	let d: u32 = s.get(6..8)?.parse().ok()?;
	chrono::NaiveDate::from_ymd_opt(y, m, d)
		.and_then(|dt| dt.and_hms_opt(0, 0, 0))
		.map(|ndt| ndt.and_utc().timestamp())
}

// Individual resource (.ics) — GET / PUT / DELETE / HEAD / OPTIONS
//*******************************************************************

pub async fn handle_resource(
	State(app): State<App>,
	Auth(auth): Auth,
	Path((cal_name_raw, resource_raw)): Path<(String, String)>,
	req: Request<Body>,
) -> Response<Body> {
	let method = req.method().clone();
	let tn_id = auth.tn_id;
	let (Some(cal_name), Some(resource)) =
		(urldecode_path(&cal_name_raw), urldecode_path(&resource_raw))
	else {
		return plain_error(StatusCode::BAD_REQUEST, "invalid URL encoding");
	};

	if method == Method::OPTIONS {
		return ok_empty();
	}

	let Some(uid) = resource.strip_suffix(".ics") else {
		return plain_error(StatusCode::NOT_FOUND, "only .ics resources are supported");
	};

	let cal = match app.meta_adapter.get_calendar_by_name(tn_id, &cal_name).await {
		Ok(Some(c)) => c,
		Ok(None) => return plain_error(StatusCode::NOT_FOUND, "no such calendar"),
		Err(e) => {
			warn!("CalDAV resource cal lookup failed: {:?}", e);
			return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "db error");
		}
	};

	match method.as_str() {
		"GET" | "HEAD" => get_resource(&app, tn_id, cal.cal_id, uid, method == Method::HEAD).await,
		"PUT" => put_resource(&app, tn_id, cal.cal_id, uid, req).await,
		"DELETE" => delete_resource(&app, tn_id, cal.cal_id, uid).await,
		_ => plain_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
	}
}

async fn get_resource(
	app: &App,
	tn_id: TnId,
	cal_id: u64,
	uid: &str,
	head_only: bool,
) -> Response<Body> {
	let row = match app.meta_adapter.get_calendar_object(tn_id, cal_id, uid).await {
		Ok(Some(r)) => r,
		Ok(None) => return plain_error(StatusCode::NOT_FOUND, "not found"),
		Err(e) => {
			warn!("CalDAV get failed: {:?}", e);
			return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "db error");
		}
	};

	let body = if head_only { Body::empty() } else { Body::from(row.ical.to_string()) };
	Response::builder()
		.status(StatusCode::OK)
		.header(header::CONTENT_TYPE, "text/calendar; charset=utf-8")
		.header(header::ETAG, etag_header(&row.etag))
		.header("DAV", DAV_CAPABILITIES)
		.body(body)
		.unwrap_or_else(|_| Response::new(Body::empty()))
}

async fn put_resource(
	app: &App,
	tn_id: TnId,
	cal_id: u64,
	uid: &str,
	req: Request<Body>,
) -> Response<Body> {
	let if_match = req.headers().get("If-Match").and_then(|h| h.to_str().ok()).map(str::to_string);
	let if_none_match = req
		.headers()
		.get("If-None-Match")
		.and_then(|h| h.to_str().ok())
		.map(str::to_string);

	let ical_text = match read_body(req).await {
		Ok(s) => s,
		Err(r) => return r,
	};

	let existing = match app.meta_adapter.get_calendar_object(tn_id, cal_id, uid).await {
		Ok(e) => e,
		Err(e) => {
			warn!("CalDAV put: lookup failed: {:?}", e);
			return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "db error");
		}
	};

	if let Some(inm) = if_none_match.as_deref()
		&& inm.trim() == "*"
		&& existing.is_some()
	{
		return plain_error(StatusCode::PRECONDITION_FAILED, "resource already exists");
	}
	if let Some(im) = if_match.as_deref()
		&& let Some(ref cur) = existing
		&& unquote_etag(im) != unquote_etag(cur.etag.as_ref())
	{
		return plain_error(StatusCode::PRECONDITION_FAILED, "etag mismatch");
	}

	// Store the client-supplied iCalendar blob verbatim on the master row — round-trip
	// fidelity matters for VALARM / VTIMEZONE / X-* properties we don't model. Recurrence
	// overrides (additional VEVENTs with RECURRENCE-ID under the same UID) get their own
	// rows with generated per-override blobs so REST endpoints can list and edit them.
	let Some((extracted, parsed_uid, _warnings)) = ical::parse(&ical_text) else {
		return plain_error(StatusCode::BAD_REQUEST, "malformed iCalendar");
	};

	// Pin UID from the URL — mismatches fragment state across endpoints.
	let effective_uid = parsed_uid.unwrap_or_else(|| uid.to_string());
	if effective_uid != uid {
		return plain_error(
			StatusCode::CONFLICT,
			&format!("UID in iCalendar ({effective_uid}) does not match URL UID ({uid})"),
		);
	}

	let etag = ical::etag_of(&ical_text);

	if let Err(e) = app
		.meta_adapter
		.upsert_calendar_object(tn_id, cal_id, uid, &ical_text, &etag, &extracted)
		.await
	{
		warn!("CalDAV put: upsert failed: {:?}", e);
		return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "db error");
	}

	// Second pass: write one row per override VEVENT. Each override gets a standalone
	// single-VEVENT VCALENDAR blob (loses external VTIMEZONE references, but the override's
	// DTSTART is stored as unix-seconds, so that's only a cosmetic loss for GETs of the
	// override in isolation — the master's blob still carries the full context).
	let (all_inputs, _) = ical::parse_all_to_inputs(&ical_text);
	for input in all_inputs {
		if input.recurrence_id.is_none() {
			continue;
		}
		if input.uid.as_deref() != Some(uid) && input.uid.is_some() {
			continue;
		}
		let override_blob =
			ical::generate(&CalendarObjectInput { uid: Some(uid.to_string()), ..input });
		let override_etag = ical::etag_of(&override_blob);
		let Some((override_extracted, _, _)) = ical::parse(&override_blob) else {
			continue;
		};
		if let Err(e) = app
			.meta_adapter
			.upsert_calendar_object(
				tn_id,
				cal_id,
				uid,
				&override_blob,
				&override_etag,
				&override_extracted,
			)
			.await
		{
			warn!("CalDAV put: override upsert failed: {:?}", e);
		}
	}

	let status = if existing.is_some() { StatusCode::NO_CONTENT } else { StatusCode::CREATED };
	Response::builder()
		.status(status)
		.header(header::ETAG, etag_header(&etag))
		.header("DAV", DAV_CAPABILITIES)
		.body(Body::empty())
		.unwrap_or_else(|_| Response::new(Body::empty()))
}

async fn delete_resource(app: &App, tn_id: TnId, cal_id: u64, uid: &str) -> Response<Body> {
	match app.meta_adapter.delete_calendar_object(tn_id, cal_id, uid).await {
		Ok(()) => Response::builder()
			.status(StatusCode::NO_CONTENT)
			.header("DAV", DAV_CAPABILITIES)
			.body(Body::empty())
			.unwrap_or_else(|_| Response::new(Body::empty())),
		Err(Error::NotFound) => plain_error(StatusCode::NOT_FOUND, "not found"),
		Err(e) => {
			warn!("CalDAV delete failed: {:?}", e);
			plain_error(StatusCode::INTERNAL_SERVER_ERROR, "db error")
		}
	}
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
	use super::*;

	#[test]
	fn sync_token_roundtrip() {
		let t = encode_sync_token(1_700_000_000);
		assert_eq!(decode_sync_token(&t), Some(1_700_000_000));
		assert_eq!(decode_sync_token("urn:cloudillo:sync:abc"), None);
	}

	#[test]
	fn parse_caldav_dt_handles_basic_and_date() {
		assert!(parse_caldav_dt("20260401T000000Z").is_some());
		assert!(parse_caldav_dt("20260401").is_some());
		assert!(parse_caldav_dt("garbage").is_none());
	}
}

// vim: ts=4
