// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Narrow iCalendar 2.0 (RFC 5545) parser and generator — only what we need.
//!
//! **Parse** (external CalDAV client PUTs a VCALENDAR): walk top-level components and extract
//! the master VEVENT or VTODO fields (UID, SUMMARY, DTSTART, DTEND/DUE, RRULE, ORGANIZER,
//! STATUS, PRIORITY, SEQUENCE, RECURRENCE-ID) into the index projection. Unknown components
//! and properties are ignored here — they still round-trip through the stored blob untouched.
//!
//! **Generate** (web client sent structured JSON): build a canonical VCALENDAR blob from an
//! [`CalendarObjectInput`] (containing either an event or a todo).
//!
//! This is NOT a general-purpose iCalendar library — no timezone resolution, no RRULE
//! expansion. DTSTART values with an opaque `TZID` are stored naïvely as UTC; this is good
//! enough for the deliberately-loose `calendar-query` time-range filter, and clients expand
//! recurrence locally.

use cloudillo_dav::content_line::{
	RawLine, get_param, parse_line, unescape_text, unfold, write_line,
};

use cloudillo_core::prelude::*;
use cloudillo_types::meta_adapter::CalendarObjectExtracted;

use crate::types::{Alarm, Attendee, CalendarObjectInput, EventInput, TodoInput};

pub use cloudillo_dav::content_line::etag_of;

// Date/time
//***********

/// Parse an iCalendar DATE-TIME or DATE into (unix seconds, is_all_day).
/// Recognised forms:
/// - `YYYYMMDDTHHMMSSZ` — UTC
/// - `YYYYMMDDTHHMMSS`  — local / TZID; we treat as naïve UTC for indexing purposes
/// - `YYYYMMDD`         — all-day; stored as UTC midnight
fn parse_dt(value: &str, is_date: bool) -> Option<(i64, bool)> {
	let v = value.trim();
	let y: i32 = v.get(0..4)?.parse().ok()?;
	let m: u32 = v.get(4..6)?.parse().ok()?;
	let d: u32 = v.get(6..8)?.parse().ok()?;
	if is_date || (v.len() == 8 && v.chars().all(|c| c.is_ascii_digit())) {
		return Some((date_to_unix(y, m, d)?, true));
	}
	if v.len() >= 15 {
		// v[8] is 'T'
		let hh: u32 = v.get(9..11)?.parse().ok()?;
		let mm: u32 = v.get(11..13)?.parse().ok()?;
		let ss: u32 = v.get(13..15)?.parse().ok()?;
		// ponytail: leap seconds clamp to :59 (≤1s index error) rather than rolling
		// into the next minute; switch to real rollover only if a client complains.
		let dt = chrono::NaiveDate::from_ymd_opt(y, m, d)?.and_hms_opt(hh, mm, ss.min(59))?;
		return Some((dt.and_utc().timestamp(), false));
	}
	None
}

/// Convert a Gregorian date to Unix seconds (midnight UTC). Proleptic; invalid
/// calendar dates (Feb 30, month 13, ...) return None rather than rolling over.
fn date_to_unix(y: i32, m: u32, d: u32) -> Option<i64> {
	chrono::NaiveDate::from_ymd_opt(y, m, d)?
		.and_hms_opt(0, 0, 0)
		.map(|dt| dt.and_utc().timestamp())
}

fn emit_dt(ts: Timestamp, all_day: bool) -> String {
	let dt = chrono::DateTime::from_timestamp(ts.0, 0).unwrap_or_else(|| {
		warn!("ical: timestamp {} out of range; emitting the epoch", ts.0);
		chrono::DateTime::<chrono::Utc>::UNIX_EPOCH
	});
	if all_day { dt.format("%Y%m%d").to_string() } else { dt.format("%Y%m%dT%H%M%SZ").to_string() }
}

// Public parse
//**************

/// Parse a VCALENDAR blob. Returns the master VEVENT/VTODO projection plus any warnings.
/// Returns `None` if the blob has no recognisable component.
pub fn parse(ical: &str) -> Option<(CalendarObjectExtracted, Option<String>, Vec<String>)> {
	let mut warnings: Vec<String> = Vec::new();
	let mut stack: Vec<String> = Vec::new();
	let mut primary: Option<ComponentAccum> = None;
	let mut current: Option<ComponentAccum> = None;

	for line in unfold(ical) {
		let trimmed_line = line.trim();
		if trimmed_line.is_empty() {
			continue;
		}
		let Some(raw) = parse_line(&line, false) else {
			warnings.push(format!("malformed line: {trimmed_line:.80}"));
			continue;
		};
		match raw.name.as_str() {
			"BEGIN" => {
				let comp = raw.value.to_ascii_uppercase();
				stack.push(comp.clone());
				if current.is_none() && (comp == "VEVENT" || comp == "VTODO") {
					current = Some(ComponentAccum::new(comp));
				}
			}
			"END" => {
				let comp = raw.value.to_ascii_uppercase();
				if stack.last().map(String::as_str) == Some(comp.as_str()) {
					stack.pop();
				} else {
					warnings.push(format!("unbalanced END:{comp}"));
				}
				if let Some(done) = current.take_if(|c| c.kind == comp) {
					// Prefer the master (recurrence_id = None) over any override we see first.
					if done.recurrence_id.is_none() || primary.is_none() {
						primary = Some(done);
					} else if let Some(p) = primary.as_mut()
						&& p.recurrence_id.is_some()
					{
						// Already holding an override; master is still preferred when it comes.
						*p = done;
					}
				}
			}
			_ if current.is_some() => {
				if let Some(acc) = current.as_mut() {
					acc.ingest(&raw, &mut warnings);
				}
			}
			_ => {}
		}
	}

	let accum = primary?;
	let uid = accum.uid.clone();
	Some((accum.into_extracted(), uid, warnings))
}

/// Full-fidelity decoder that maps the master VEVENT/VTODO of a stored VCALENDAR blob
/// back to the JSON shape we accept from clients — including ATTENDEE, CATEGORIES, and
/// nested VALARM components that the projection parser in [`parse`] discards. Used by
/// the PATCH handler to merge partial updates without dropping unspecified fields.
///
/// Returns `None` if the blob has no recognisable master component.
pub fn parse_to_input(ical: &str) -> Option<(CalendarObjectInput, Vec<String>)> {
	let mut warnings: Vec<String> = Vec::new();
	let mut stack: Vec<String> = Vec::new();
	let mut primary: Option<FullComponent> = None;
	let mut current: Option<FullComponent> = None;
	let mut current_alarm: Option<Alarm> = None;

	for line in unfold(ical) {
		let trimmed_line = line.trim();
		if trimmed_line.is_empty() {
			continue;
		}
		let Some(raw) = parse_line(&line, false) else {
			warnings.push(format!("malformed line: {trimmed_line:.80}"));
			continue;
		};
		match raw.name.as_str() {
			"BEGIN" => {
				let comp = raw.value.to_ascii_uppercase();
				stack.push(comp.clone());
				if current.is_none() && (comp == "VEVENT" || comp == "VTODO") {
					current = Some(FullComponent::new(comp));
				} else if current.is_some() && comp == "VALARM" && current_alarm.is_none() {
					current_alarm = Some(Alarm::default());
				}
			}
			"END" => {
				let comp = raw.value.to_ascii_uppercase();
				if stack.last().map(String::as_str) == Some(comp.as_str()) {
					stack.pop();
				} else {
					warnings.push(format!("unbalanced END:{comp}"));
				}
				if comp == "VALARM"
					&& let Some(alarm) = current_alarm.take()
					&& let Some(c) = current.as_mut()
				{
					c.alarms.push(alarm);
				}
				if let Some(done) = current.take_if(|c| c.kind == comp) {
					if done.recurrence_id.is_none() || primary.is_none() {
						primary = Some(done);
					} else if let Some(p) = primary.as_mut()
						&& p.recurrence_id.is_some()
					{
						*p = done;
					}
				}
			}
			_ if current_alarm.is_some() => {
				if let Some(alarm) = current_alarm.as_mut() {
					alarm.ingest(&raw);
				}
			}
			_ if current.is_some() => {
				if let Some(acc) = current.as_mut() {
					acc.ingest(&raw);
				}
			}
			_ => {}
		}
	}

	let component = primary?;
	let uid = component.uid.clone();
	let input = component.into_input();
	Some((CalendarObjectInput { uid, ..input }, warnings))
}

/// Decode every VEVENT/VTODO in a VCALENDAR blob to a structured input. The master
/// (`recurrence_id == None`) comes first when present; recurrence overrides follow in
/// file order. Used by the CalDAV PUT path so that an .ics file carrying a master
/// plus per-occurrence overrides round-trips into separate DB rows.
pub fn parse_all_to_inputs(ical: &str) -> (Vec<CalendarObjectInput>, Vec<String>) {
	let mut warnings: Vec<String> = Vec::new();
	let mut stack: Vec<String> = Vec::new();
	let mut components: Vec<FullComponent> = Vec::new();
	let mut current: Option<FullComponent> = None;
	let mut current_alarm: Option<Alarm> = None;

	for line in unfold(ical) {
		let trimmed_line = line.trim();
		if trimmed_line.is_empty() {
			continue;
		}
		let Some(raw) = parse_line(&line, false) else {
			warnings.push(format!("malformed line: {trimmed_line:.80}"));
			continue;
		};
		match raw.name.as_str() {
			"BEGIN" => {
				let comp = raw.value.to_ascii_uppercase();
				stack.push(comp.clone());
				if current.is_none() && (comp == "VEVENT" || comp == "VTODO") {
					current = Some(FullComponent::new(comp));
				} else if current.is_some() && comp == "VALARM" && current_alarm.is_none() {
					current_alarm = Some(Alarm::default());
				}
			}
			"END" => {
				let comp = raw.value.to_ascii_uppercase();
				if stack.last().map(String::as_str) == Some(comp.as_str()) {
					stack.pop();
				} else {
					warnings.push(format!("unbalanced END:{comp}"));
				}
				if comp == "VALARM"
					&& let Some(alarm) = current_alarm.take()
					&& let Some(c) = current.as_mut()
				{
					c.alarms.push(alarm);
				}
				if let Some(done) = current.take_if(|c| c.kind == comp) {
					components.push(done);
				}
			}
			_ if current_alarm.is_some() => {
				if let Some(alarm) = current_alarm.as_mut() {
					alarm.ingest(&raw);
				}
			}
			_ if current.is_some() => {
				if let Some(acc) = current.as_mut() {
					acc.ingest(&raw);
				}
			}
			_ => {}
		}
	}

	// Master first; overrides preserve source order.
	components.sort_by_key(|c| i64::from(c.recurrence_id.is_some()));

	let inputs: Vec<CalendarObjectInput> = components
		.into_iter()
		.map(|c| {
			let uid = c.uid.clone();
			let input = c.into_input();
			CalendarObjectInput { uid, ..input }
		})
		.collect();
	(inputs, warnings)
}

struct FullComponent {
	kind: String,
	uid: Option<String>,
	summary: Option<String>,
	description: Option<String>,
	location: Option<String>,
	// Raw parsed values — converted to ISO-8601 only on output so we can distinguish
	// "all-day date" from "datetime".
	dtstart: Option<(i64, bool)>,
	dtend: Option<(i64, bool)>,
	completed: Option<(i64, bool)>,
	rrule: Option<String>,
	exdate: Vec<(i64, bool)>,
	status: Option<String>,
	organizer: Option<String>,
	priority: Option<u8>,
	attendees: Vec<Attendee>,
	categories: Vec<String>,
	alarms: Vec<Alarm>,
	recurrence_id: Option<i64>,
}

impl FullComponent {
	fn new(kind: String) -> Self {
		Self {
			kind,
			uid: None,
			summary: None,
			description: None,
			location: None,
			dtstart: None,
			dtend: None,
			completed: None,
			rrule: None,
			exdate: Vec::new(),
			status: None,
			organizer: None,
			priority: None,
			attendees: Vec::new(),
			categories: Vec::new(),
			alarms: Vec::new(),
			recurrence_id: None,
		}
	}

	fn ingest(&mut self, raw: &RawLine) {
		match raw.name.as_str() {
			"UID" => self.uid = Some(unescape_text(&raw.value)),
			"SUMMARY" => self.summary = Some(unescape_text(&raw.value)),
			"LOCATION" => self.location = Some(unescape_text(&raw.value)),
			"DESCRIPTION" => self.description = Some(unescape_text(&raw.value)),
			"STATUS" => self.status = Some(raw.value.trim().to_ascii_uppercase()),
			"PRIORITY" => self.priority = raw.value.trim().parse().ok(),
			"ORGANIZER" => self.organizer = Some(unescape_text(&raw.value)),
			"RRULE" => self.rrule = Some(raw.value.trim().to_string()),
			"DTSTART" => {
				let is_date =
					get_param(&raw.params, "VALUE").is_some_and(|v| v.eq_ignore_ascii_case("DATE"));
				self.dtstart = parse_dt(&raw.value, is_date);
			}
			"DTEND" | "DUE" => {
				let is_date =
					get_param(&raw.params, "VALUE").is_some_and(|v| v.eq_ignore_ascii_case("DATE"));
				self.dtend = parse_dt(&raw.value, is_date);
			}
			"COMPLETED" => {
				let is_date =
					get_param(&raw.params, "VALUE").is_some_and(|v| v.eq_ignore_ascii_case("DATE"));
				self.completed = parse_dt(&raw.value, is_date);
			}
			"EXDATE" => {
				let is_date =
					get_param(&raw.params, "VALUE").is_some_and(|v| v.eq_ignore_ascii_case("DATE"));
				for piece in raw.value.split(',') {
					let v = piece.trim();
					if v.is_empty() {
						continue;
					}
					if let Some(parsed) = parse_dt(v, is_date) {
						self.exdate.push(parsed);
					}
				}
			}
			"RECURRENCE-ID" => {
				let is_date =
					get_param(&raw.params, "VALUE").is_some_and(|v| v.eq_ignore_ascii_case("DATE"));
				self.recurrence_id = parse_dt(&raw.value, is_date).map(|(ts, _)| ts);
			}
			"ATTENDEE" => {
				self.attendees.push(Attendee {
					address: unescape_text(&raw.value),
					cn: get_param(&raw.params, "CN").map(str::to_string),
					partstat: get_param(&raw.params, "PARTSTAT").map(str::to_string),
					role: get_param(&raw.params, "ROLE").map(str::to_string),
					rsvp: get_param(&raw.params, "RSVP").map(|v| v.eq_ignore_ascii_case("TRUE")),
				});
			}
			"CATEGORIES" => {
				// CATEGORIES is a comma-separated list per RFC 5545; escape_text escapes
				// embedded commas, so splitting on unescaped commas is safe here.
				let decoded = unescape_text(&raw.value);
				self.categories.extend(
					decoded.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from),
				);
			}
			_ => {}
		}
	}

	fn into_input(self) -> CalendarObjectInput {
		let all_day = self.dtstart.is_some_and(|(_, d)| d);
		let dtstart_iso = self.dtstart.map(|(ts, d)| ts_to_iso(Timestamp(ts), d));
		let dtend_iso = self.dtend.map(|(ts, d)| ts_to_iso(Timestamp(ts), d));
		let completed_iso = self.completed.map(|(ts, d)| ts_to_iso(Timestamp(ts), d));
		let exdate_iso: Vec<String> =
			self.exdate.iter().map(|(ts, d)| ts_to_iso(Timestamp(*ts), *d)).collect();
		let recurrence_id_iso = self.recurrence_id.map(|ts| ts_to_iso(Timestamp(ts), all_day));
		let uid = self.uid;
		match self.kind.as_str() {
			"VEVENT" => CalendarObjectInput {
				uid,
				recurrence_id: recurrence_id_iso,
				event: Some(EventInput {
					summary: self.summary,
					description: self.description,
					location: self.location,
					dtstart: dtstart_iso,
					dtend: dtend_iso,
					all_day,
					rrule: self.rrule,
					exdate: exdate_iso,
					status: self.status,
					organizer: self.organizer,
					attendees: self.attendees,
					categories: self.categories,
					alarms: self.alarms,
				}),
				todo: None,
			},
			"VTODO" => CalendarObjectInput {
				uid,
				recurrence_id: recurrence_id_iso,
				event: None,
				todo: Some(TodoInput {
					summary: self.summary,
					description: self.description,
					dtstart: dtstart_iso,
					due: dtend_iso,
					completed: completed_iso,
					priority: self.priority,
					status: self.status,
					rrule: self.rrule,
					categories: self.categories,
					alarms: self.alarms,
				}),
			},
			_ => CalendarObjectInput { uid, recurrence_id: None, event: None, todo: None },
		}
	}
}

impl Alarm {
	fn ingest(&mut self, raw: &RawLine) {
		match raw.name.as_str() {
			"ACTION" => self.action = Some(raw.value.trim().to_ascii_uppercase()),
			"TRIGGER" => self.trigger = Some(raw.value.trim().to_string()),
			"DESCRIPTION" => self.description = Some(unescape_text(&raw.value)),
			_ => {}
		}
	}
}

struct ComponentAccum {
	kind: String,
	uid: Option<String>,
	summary: Option<String>,
	location: Option<String>,
	description: Option<String>,
	dtstart: Option<(i64, bool)>,
	dtend: Option<(i64, bool)>,
	status: Option<String>,
	priority: Option<u8>,
	organizer: Option<String>,
	rrule: Option<String>,
	exdate: Vec<i64>,
	recurrence_id: Option<i64>,
	sequence: i64,
}

impl ComponentAccum {
	fn new(kind: String) -> Self {
		Self {
			kind,
			uid: None,
			summary: None,
			location: None,
			description: None,
			dtstart: None,
			dtend: None,
			status: None,
			priority: None,
			organizer: None,
			rrule: None,
			exdate: Vec::new(),
			recurrence_id: None,
			sequence: 0,
		}
	}

	fn ingest(&mut self, raw: &RawLine, _warnings: &mut Vec<String>) {
		match raw.name.as_str() {
			"UID" => self.uid = Some(unescape_text(&raw.value)),
			"SUMMARY" => self.summary = Some(unescape_text(&raw.value)),
			"LOCATION" => self.location = Some(unescape_text(&raw.value)),
			"DESCRIPTION" => self.description = Some(unescape_text(&raw.value)),
			"STATUS" => self.status = Some(raw.value.trim().to_ascii_uppercase()),
			"PRIORITY" => self.priority = raw.value.trim().parse().ok(),
			"ORGANIZER" => self.organizer = Some(unescape_text(&raw.value)),
			"RRULE" => self.rrule = Some(raw.value.trim().to_string()),
			"SEQUENCE" => {
				if let Ok(n) = raw.value.trim().parse::<i64>() {
					self.sequence = n;
				}
			}
			"DTSTART" => {
				let is_date =
					get_param(&raw.params, "VALUE").is_some_and(|v| v.eq_ignore_ascii_case("DATE"));
				self.dtstart = parse_dt(&raw.value, is_date);
			}
			"DTEND" | "DUE" => {
				let is_date =
					get_param(&raw.params, "VALUE").is_some_and(|v| v.eq_ignore_ascii_case("DATE"));
				self.dtend = parse_dt(&raw.value, is_date);
			}
			"EXDATE" => {
				let is_date =
					get_param(&raw.params, "VALUE").is_some_and(|v| v.eq_ignore_ascii_case("DATE"));
				for piece in raw.value.split(',') {
					let v = piece.trim();
					if v.is_empty() {
						continue;
					}
					if let Some((ts, _)) = parse_dt(v, is_date) {
						self.exdate.push(ts);
					}
				}
			}
			"RECURRENCE-ID" => {
				let is_date =
					get_param(&raw.params, "VALUE").is_some_and(|v| v.eq_ignore_ascii_case("DATE"));
				self.recurrence_id = parse_dt(&raw.value, is_date).map(|(ts, _)| ts);
			}
			_ => {}
		}
	}

	fn into_extracted(self) -> CalendarObjectExtracted {
		let (dtstart_ts, all_day) = self.dtstart.map_or((None, false), |(t, d)| (Some(t), d));
		let dtend_ts = self.dtend.map(|(t, _)| t);
		CalendarObjectExtracted {
			component: self.kind.into_boxed_str(),
			summary: self.summary.map(String::into_boxed_str),
			location: self.location.map(String::into_boxed_str),
			description: self.description.map(String::into_boxed_str),
			dtstart: dtstart_ts.map(Timestamp),
			dtend: dtend_ts.map(Timestamp),
			all_day,
			status: self.status.map(String::into_boxed_str),
			priority: self.priority,
			organizer: self.organizer.map(String::into_boxed_str),
			rrule: self.rrule.map(String::into_boxed_str),
			exdate: self.exdate.into_iter().map(Timestamp).collect(),
			recurrence_id: self.recurrence_id.map(Timestamp),
			sequence: self.sequence,
		}
	}
}

// Generation
//************

/// Parse an ISO-8601 datetime from REST JSON (`YYYY-MM-DDTHH:MM:SS(Z|±HH:MM)?`) or a bare
/// date (`YYYY-MM-DD`). Returns (unix seconds, is_date). Timezone offsets are applied;
/// floating datetimes (no offset) are treated as UTC.
fn parse_iso(value: &str) -> Option<(i64, bool)> {
	let v = value.trim();
	if v.len() == 10 && v.as_bytes().get(4) == Some(&b'-') && v.as_bytes().get(7) == Some(&b'-') {
		let d = chrono::NaiveDate::parse_from_str(v, "%Y-%m-%d").ok()?;
		return Some((d.and_hms_opt(0, 0, 0)?.and_utc().timestamp(), true));
	}
	if v.len() < 19 {
		return None;
	}
	// RFC 3339 with offset, else a floating local time treated as UTC.
	let ts = if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(v) {
		dt.timestamp()
	} else if let Ok(dt) = chrono::DateTime::parse_from_str(v, "%Y-%m-%dT%H:%M:%S%.f%z") {
		dt.timestamp()
	} else {
		chrono::NaiveDateTime::parse_from_str(v.get(..19)?, "%Y-%m-%dT%H:%M:%S")
			.ok()?
			.and_utc()
			.timestamp()
	};
	Some((ts, false))
}

/// Generate a canonical VCALENDAR blob from structured input. `uid` is taken from
/// `input.uid`; callers mint one before calling if needed.
pub fn generate(input: &CalendarObjectInput) -> String {
	let mut out = String::with_capacity(512);
	out.push_str("BEGIN:VCALENDAR\r\n");
	out.push_str("VERSION:2.0\r\n");
	out.push_str("PRODID:-//Cloudillo//Calendar//EN\r\n");
	out.push_str("CALSCALE:GREGORIAN\r\n");

	if let Some(ev) = &input.event {
		write_event(&mut out, input.uid.as_deref(), input.recurrence_id.as_deref(), ev);
	} else if let Some(td) = &input.todo {
		write_todo(&mut out, input.uid.as_deref(), input.recurrence_id.as_deref(), td);
	}

	out.push_str("END:VCALENDAR\r\n");
	out
}

fn write_event(out: &mut String, uid: Option<&str>, recurrence_id: Option<&str>, ev: &EventInput) {
	out.push_str("BEGIN:VEVENT\r\n");
	if let Some(uid) = uid {
		write_line(out, "UID", &[], uid, false);
	}
	write_dtstamp(out);
	if let Some(rid) = recurrence_id {
		write_dt(out, "RECURRENCE-ID", rid, ev.all_day);
	}
	if let Some(s) = ev.summary.as_deref() {
		write_line(out, "SUMMARY", &[], s, false);
	}
	if let Some(s) = ev.location.as_deref() {
		write_line(out, "LOCATION", &[], s, false);
	}
	if let Some(s) = ev.description.as_deref() {
		write_line(out, "DESCRIPTION", &[], s, false);
	}
	if let Some(dt) = ev.dtstart.as_deref() {
		write_dt(out, "DTSTART", dt, ev.all_day);
	}
	if let Some(dt) = ev.dtend.as_deref() {
		write_dt(out, "DTEND", dt, ev.all_day);
	}
	if let Some(s) = ev.rrule.as_deref() {
		write_line(out, "RRULE", &[], s, true);
	}
	for ex in &ev.exdate {
		write_dt(out, "EXDATE", ex, ev.all_day);
	}
	if let Some(s) = ev.status.as_deref() {
		write_line(out, "STATUS", &[], s, true);
	}
	if let Some(s) = ev.organizer.as_deref() {
		write_line(out, "ORGANIZER", &[], s, true);
	}
	for att in &ev.attendees {
		let mut params: Vec<(&str, String)> = Vec::new();
		if let Some(cn) = &att.cn {
			params.push(("CN", cn.clone()));
		}
		if let Some(ps) = &att.partstat {
			params.push(("PARTSTAT", ps.clone()));
		}
		if let Some(r) = &att.role {
			params.push(("ROLE", r.clone()));
		}
		if let Some(rs) = att.rsvp {
			params.push(("RSVP", if rs { "TRUE".into() } else { "FALSE".into() }));
		}
		let prefs: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
		write_line(out, "ATTENDEE", &prefs, &att.address, true);
	}
	if !ev.categories.is_empty() {
		write_line(out, "CATEGORIES", &[], &ev.categories.join(","), true);
	}
	for alarm in &ev.alarms {
		write_alarm(out, alarm);
	}
	out.push_str("END:VEVENT\r\n");
}

fn write_todo(out: &mut String, uid: Option<&str>, recurrence_id: Option<&str>, td: &TodoInput) {
	out.push_str("BEGIN:VTODO\r\n");
	if let Some(uid) = uid {
		write_line(out, "UID", &[], uid, false);
	}
	write_dtstamp(out);
	if let Some(rid) = recurrence_id {
		write_dt(out, "RECURRENCE-ID", rid, false);
	}
	if let Some(s) = td.summary.as_deref() {
		write_line(out, "SUMMARY", &[], s, false);
	}
	if let Some(s) = td.description.as_deref() {
		write_line(out, "DESCRIPTION", &[], s, false);
	}
	if let Some(dt) = td.dtstart.as_deref() {
		write_dt(out, "DTSTART", dt, false);
	}
	if let Some(dt) = td.due.as_deref() {
		write_dt(out, "DUE", dt, false);
	}
	if let Some(dt) = td.completed.as_deref() {
		write_dt(out, "COMPLETED", dt, false);
	}
	if let Some(p) = td.priority {
		write_line(out, "PRIORITY", &[], &p.to_string(), true);
	}
	if let Some(s) = td.status.as_deref() {
		write_line(out, "STATUS", &[], s, true);
	}
	if let Some(s) = td.rrule.as_deref() {
		write_line(out, "RRULE", &[], s, true);
	}
	if !td.categories.is_empty() {
		write_line(out, "CATEGORIES", &[], &td.categories.join(","), true);
	}
	for alarm in &td.alarms {
		write_alarm(out, alarm);
	}
	out.push_str("END:VTODO\r\n");
}

fn write_alarm(out: &mut String, alarm: &Alarm) {
	out.push_str("BEGIN:VALARM\r\n");
	if let Some(a) = alarm.action.as_deref() {
		write_line(out, "ACTION", &[], a, true);
	}
	if let Some(t) = alarm.trigger.as_deref() {
		write_line(out, "TRIGGER", &[], t, true);
	}
	if let Some(d) = alarm.description.as_deref() {
		write_line(out, "DESCRIPTION", &[], d, false);
	}
	out.push_str("END:VALARM\r\n");
}

fn write_dt(out: &mut String, name: &str, iso: &str, all_day: bool) {
	let Some((ts, is_date)) = parse_iso(iso) else {
		// Fall back to raw verbatim — preserves client intent even if we can't canonicalise.
		write_line(out, name, &[], iso, true);
		return;
	};
	let final_all_day = all_day || is_date;
	let formatted = emit_dt(Timestamp(ts), final_all_day);
	let params: &[(&str, &str)] = if final_all_day { &[("VALUE", "DATE")] } else { &[] };
	write_line(out, name, params, &formatted, true);
}

fn write_dtstamp(out: &mut String) {
	let secs = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map_or(0, |d| {
			i64::try_from(d.as_secs()).unwrap_or_else(|_| {
				warn!("ical: system time past i64; clamping DTSTAMP");
				i64::MAX
			})
		});
	let stamp = emit_dt(Timestamp(secs), false);
	write_line(out, "DTSTAMP", &[], &stamp, true);
}

/// Format a unix timestamp back to ISO-8601 for REST JSON responses.
pub fn ts_to_iso(ts: Timestamp, all_day: bool) -> String {
	let dt = chrono::DateTime::from_timestamp(ts.0, 0).unwrap_or_else(|| {
		warn!("ical: timestamp {} out of range; emitting the epoch", ts.0);
		chrono::DateTime::<chrono::Utc>::UNIX_EPOCH
	});
	if all_day {
		dt.format("%Y-%m-%d").to_string()
	} else {
		dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
	}
}

// Tests
//*******

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
	use super::*;

	#[test]
	fn parse_simple_vevent() {
		let ical = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\n\
			BEGIN:VEVENT\r\nUID:test-123\r\nSUMMARY:Lunch\r\nLOCATION:Cafe\r\n\
			DTSTART:20260419T120000Z\r\nDTEND:20260419T130000Z\r\nSEQUENCE:1\r\n\
			END:VEVENT\r\nEND:VCALENDAR\r\n";
		let (extracted, uid, _) = parse(ical).unwrap();
		assert_eq!(uid.as_deref(), Some("test-123"));
		assert_eq!(extracted.component.as_ref(), "VEVENT");
		assert_eq!(extracted.summary.as_deref(), Some("Lunch"));
		assert_eq!(extracted.location.as_deref(), Some("Cafe"));
		assert!(!extracted.all_day);
		assert!(extracted.dtstart.is_some());
		assert!(extracted.dtend.is_some());
		assert!(extracted.dtend.unwrap().0 > extracted.dtstart.unwrap().0);
		assert_eq!(extracted.sequence, 1);
	}

	#[test]
	fn parse_all_day_event() {
		let ical = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:x\r\n\
			SUMMARY:Holiday\r\nDTSTART;VALUE=DATE:20260419\r\nDTEND;VALUE=DATE:20260420\r\n\
			END:VEVENT\r\nEND:VCALENDAR\r\n";
		let (extracted, _, _) = parse(ical).unwrap();
		assert!(extracted.all_day);
		assert!(extracted.dtstart.is_some());
	}

	#[test]
	fn parse_vtodo() {
		let ical = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VTODO\r\nUID:task-1\r\n\
			SUMMARY:Buy milk\r\nDUE;VALUE=DATE:20260420\r\nPRIORITY:3\r\n\
			STATUS:NEEDS-ACTION\r\nEND:VTODO\r\nEND:VCALENDAR\r\n";
		let (extracted, uid, _) = parse(ical).unwrap();
		assert_eq!(uid.as_deref(), Some("task-1"));
		assert_eq!(extracted.component.as_ref(), "VTODO");
		assert_eq!(extracted.priority, Some(3));
		assert_eq!(extracted.status.as_deref(), Some("NEEDS-ACTION"));
		assert!(extracted.dtend.is_some()); // DUE maps to dtend
	}

	#[test]
	fn parse_recurring_event_with_override() {
		let ical = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n\
			BEGIN:VEVENT\r\nUID:r1\r\nSUMMARY:Daily\r\nDTSTART:20260101T090000Z\r\n\
			RRULE:FREQ=DAILY;COUNT=5\r\nEND:VEVENT\r\n\
			BEGIN:VEVENT\r\nUID:r1\r\nSUMMARY:Daily (override)\r\n\
			DTSTART:20260103T100000Z\r\nRECURRENCE-ID:20260103T090000Z\r\n\
			END:VEVENT\r\nEND:VCALENDAR\r\n";
		let (extracted, _, _) = parse(ical).unwrap();
		// Master (no RECURRENCE-ID) should win over the override.
		assert_eq!(extracted.summary.as_deref(), Some("Daily"));
		assert!(extracted.rrule.is_some());
		assert!(extracted.recurrence_id.is_none());
	}

	#[test]
	fn roundtrip_event() {
		let input = CalendarObjectInput {
			uid: Some("gen-1".into()),
			recurrence_id: None,
			event: Some(EventInput {
				summary: Some("Gen Test".into()),
				dtstart: Some("2026-05-01T09:00:00Z".into()),
				dtend: Some("2026-05-01T10:00:00Z".into()),
				..EventInput::default()
			}),
			todo: None,
		};
		let generated = generate(&input);
		assert!(generated.contains("BEGIN:VCALENDAR"));
		assert!(generated.contains("BEGIN:VEVENT"));
		assert!(generated.contains("UID:gen-1"));
		assert!(generated.contains("SUMMARY:Gen Test"));
		let (extracted, uid, _) = parse(&generated).unwrap();
		assert_eq!(uid.as_deref(), Some("gen-1"));
		assert_eq!(extracted.summary.as_deref(), Some("Gen Test"));
	}

	#[test]
	fn etag_stable_for_same_input() {
		let a = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n";
		assert_eq!(etag_of(a), etag_of(a));
		assert_eq!(etag_of(a).len(), 16);
	}

	#[test]
	fn fold_and_escape() {
		let mut out = String::new();
		write_line(&mut out, "X", &[], "hello,world\nbye;ok", false);
		assert!(out.starts_with("X:hello\\,world\\nbye\\;ok"));
	}

	#[test]
	fn date_to_unix_matches_epoch() {
		assert_eq!(date_to_unix(1970, 1, 1), Some(0));
		// 2026-04-19 is 56*365 + 14 (leap days) + 31+28+31+18 = 20562 days.
		assert_eq!(date_to_unix(2026, 4, 19), Some(20_562 * 86400));
	}

	#[test]
	fn iso_parse_tz_offset() {
		assert_eq!(
			parse_iso("2026-05-01T09:00:00Z"),
			Some((date_to_unix(2026, 5, 1).unwrap() + 9 * 3600, false))
		);
		assert_eq!(
			parse_iso("2026-05-01T09:00:00+02:00"),
			Some((date_to_unix(2026, 5, 1).unwrap() + 7 * 3600, false))
		);
		// Basic (colon-less) offset form, as emitted by some clients.
		assert_eq!(
			parse_iso("2026-05-01T09:00:00+0200"),
			Some((date_to_unix(2026, 5, 1).unwrap() + 7 * 3600, false))
		);
		// Fractional seconds must not cost the offset.
		assert_eq!(
			parse_iso("2026-05-01T09:00:00.123+0200"),
			Some((date_to_unix(2026, 5, 1).unwrap() + 7 * 3600, false))
		);
		assert_eq!(
			parse_iso("2026-05-01T09:00:00.123+02:00"),
			Some((date_to_unix(2026, 5, 1).unwrap() + 7 * 3600, false))
		);
	}

	#[test]
	fn iso_multibyte_boundary_does_not_panic() {
		// 20 bytes; byte 19 falls inside the two-byte 'e\u{301}' sequence.
		assert_eq!(parse_iso("aaaaaaaaaaaaaaaaaa\u{e9}"), None);
	}

	#[test]
	fn parse_dt_keeps_leap_second() {
		assert!(parse_dt("20260630T235960Z", false).is_some());
	}

	#[test]
	fn emit_dt_uses_z() {
		let s = emit_dt(Timestamp(date_to_unix(2026, 4, 19).unwrap() + 12 * 3600), false);
		assert_eq!(s, "20260419T120000Z");
	}

	#[test]
	fn date_to_unix_rejects_invalid_days() {
		assert_eq!(date_to_unix(2026, 2, 30), None);
		assert_eq!(date_to_unix(2026, 4, 31), None);
		assert_eq!(date_to_unix(2026, 6, 31), None);
		assert_eq!(date_to_unix(2026, 9, 31), None);
		assert_eq!(date_to_unix(2026, 11, 31), None);
		// Non-leap year: Feb 29 is invalid
		assert_eq!(date_to_unix(2025, 2, 29), None);
		// Leap year (div by 4): Feb 29 is valid
		assert!(date_to_unix(2024, 2, 29).is_some());
		// Century non-leap year: Feb 29 invalid
		assert_eq!(date_to_unix(2100, 2, 29), None);
		// 400-year leap: Feb 29 valid
		assert!(date_to_unix(2000, 2, 29).is_some());
	}

	#[test]
	fn parse_dt_rejects_invalid_days() {
		assert_eq!(parse_dt("20260230", true), None);
		assert_eq!(parse_dt("20260431", true), None);
		assert_eq!(parse_dt("20250229", true), None);
		assert!(parse_dt("20240229", true).is_some());
	}
}

// vim: ts=4
