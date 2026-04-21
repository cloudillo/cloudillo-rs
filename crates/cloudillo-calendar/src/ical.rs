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

use sha2::{Digest, Sha256};

use cloudillo_core::prelude::*;
use cloudillo_types::meta_adapter::CalendarObjectExtracted;

use crate::types::{Alarm, Attendee, CalendarObjectInput, EventInput, TodoInput};

const MAX_LINE_LEN: usize = 75;

/// Canonical ETag for an iCalendar blob — first 8 bytes of SHA-256, lowercase hex.
pub fn etag_of(ical: &str) -> String {
	let digest = Sha256::digest(ical.as_bytes());
	let mut s = String::with_capacity(16);
	for b in &digest[..8] {
		use std::fmt::Write as _;
		let _ = write!(&mut s, "{b:02x}");
	}
	s
}

// Parsing
//*********

#[derive(Debug)]
struct RawLine {
	name: String,
	params: Vec<(String, String)>,
	value: String,
}

/// Join continuation lines (CRLF + SPACE/TAB) and split into logical lines.
fn unfold(input: &str) -> Vec<String> {
	let mut out: Vec<String> = Vec::new();
	for raw in input.split('\n') {
		let line = raw.strip_suffix('\r').unwrap_or(raw);
		if let Some(first) = line.chars().next()
			&& (first == ' ' || first == '\t')
			&& let Some(last) = out.last_mut()
		{
			last.push_str(&line[1..]);
			continue;
		}
		out.push(line.to_string());
	}
	out
}

fn parse_line(line: &str) -> Option<RawLine> {
	// Name and params are separated from value by the first unquoted ':'.
	let mut in_quote = false;
	let mut colon_idx = None;
	for (i, c) in line.char_indices() {
		match c {
			'"' => in_quote = !in_quote,
			':' if !in_quote => {
				colon_idx = Some(i);
				break;
			}
			_ => {}
		}
	}
	let colon_idx = colon_idx?;
	let head = &line[..colon_idx];
	let value = line[colon_idx + 1..].to_string();

	let mut parts = split_params(head);
	let name_full = parts.remove(0);
	let params = parts
		.into_iter()
		.filter_map(|p| {
			let (k, v) = p.split_once('=')?;
			Some((k.to_ascii_uppercase(), strip_quotes(v).to_string()))
		})
		.collect();

	Some(RawLine { name: name_full.to_ascii_uppercase(), params, value })
}

fn split_params(head: &str) -> Vec<String> {
	let mut parts = Vec::new();
	let mut buf = String::new();
	let mut in_quote = false;
	for c in head.chars() {
		match c {
			'"' => {
				in_quote = !in_quote;
				buf.push(c);
			}
			';' if !in_quote => {
				parts.push(buf.clone());
				buf.clear();
			}
			_ => buf.push(c),
		}
	}
	parts.push(buf);
	parts
}

fn strip_quotes(s: &str) -> &str {
	s.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(s)
}

fn unescape_text(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	let mut iter = s.chars();
	while let Some(c) = iter.next() {
		if c == '\\' {
			match iter.next() {
				Some('n' | 'N') => out.push('\n'),
				Some(other) => out.push(other),
				None => out.push('\\'),
			}
		} else {
			out.push(c);
		}
	}
	out
}

fn get_param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
	params.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

// Date/time
//***********

/// Parse an iCalendar DATE-TIME or DATE into (unix seconds, is_all_day).
/// Recognised forms:
/// - `YYYYMMDDTHHMMSSZ` — UTC
/// - `YYYYMMDDTHHMMSS`  — local / TZID; we treat as naïve UTC for indexing purposes
/// - `YYYYMMDD`         — all-day; stored as UTC midnight
fn parse_dt(value: &str, is_date: bool) -> Option<(i64, bool)> {
	let v = value.trim();
	if is_date || (v.len() == 8 && v.chars().all(|c| c.is_ascii_digit())) {
		let y: i32 = v.get(0..4)?.parse().ok()?;
		let m: u32 = v.get(4..6)?.parse().ok()?;
		let d: u32 = v.get(6..8)?.parse().ok()?;
		let ts = date_to_unix(y, m, d)?;
		return Some((ts, true));
	}
	if v.len() >= 15 {
		let y: i32 = v.get(0..4)?.parse().ok()?;
		let m: u32 = v.get(4..6)?.parse().ok()?;
		let d: u32 = v.get(6..8)?.parse().ok()?;
		// v[8] is 'T'
		let hh: u32 = v.get(9..11)?.parse().ok()?;
		let mm: u32 = v.get(11..13)?.parse().ok()?;
		let ss: u32 = v.get(13..15)?.parse().ok()?;
		let ts = date_to_unix(y, m, d)?;
		let ts = ts + i64::from(hh) * 3600 + i64::from(mm) * 60 + i64::from(ss);
		return Some((ts, false));
	}
	None
}

/// Convert a Gregorian date to Unix seconds (midnight UTC). Proleptic; matches chrono.
fn date_to_unix(y: i32, m: u32, d: u32) -> Option<i64> {
	if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
		return None;
	}
	// Reject days beyond the actual month length so Feb 30 / Apr 31 don't silently
	// roll forward into the next month via the Hinnant algorithm.
	let leap = y.rem_euclid(4) == 0 && (y.rem_euclid(100) != 0 || y.rem_euclid(400) == 0);
	let max_day: u32 = match m {
		1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
		4 | 6 | 9 | 11 => 30,
		2 if leap => 29,
		2 => 28,
		_ => return None,
	};
	if d > max_day {
		return None;
	}
	// Howard Hinnant's date algorithm — matches RFC 5545's proleptic Gregorian calendar.
	let y = i64::from(if m <= 2 { y - 1 } else { y });
	let era = y.div_euclid(400);
	let yoe = y.rem_euclid(400);
	let m_i = i64::from(m);
	let d_i = i64::from(d);
	let doy = (153 * (if m_i > 2 { m_i - 3 } else { m_i + 9 }) + 2) / 5 + d_i - 1;
	let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	let days_since_epoch = era * 146_097 + doe - 719_468;
	Some(days_since_epoch * 86400)
}

fn emit_dt(ts: Timestamp, all_day: bool) -> String {
	// Inverse of `date_to_unix` + time-of-day split. Emits UTC (Z) for datetimes, plain
	// date for all-day. Matches what clients sent us on the happy path.
	let total = ts.0;
	let days = total.div_euclid(86400);
	let sod = total.rem_euclid(86400);
	let (y, m, d) = unix_days_to_ymd(days);
	if all_day {
		format!("{y:04}{m:02}{d:02}")
	} else {
		let hh = sod / 3600;
		let mm = (sod % 3600) / 60;
		let ss = sod % 60;
		format!("{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z")
	}
}

fn unix_days_to_ymd(days: i64) -> (i32, u32, u32) {
	// Inverse of date_to_unix's day computation.
	let z = days + 719_468;
	let era = z.div_euclid(146_097);
	let doe = z.rem_euclid(146_097);
	let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let d = doy - (153 * mp + 2) / 5 + 1;
	let m = if mp < 10 { mp + 3 } else { mp - 9 };
	let y = yoe + era * 400 + i64::from(m <= 2);
	// Month (1..=12) and day (1..=31) always fit in u32. Year within 0..=9999 for formatting;
	// clamp anything wilder.
	let m32 = u32::try_from(m).unwrap_or(0);
	let d32 = u32::try_from(d).unwrap_or(0);
	let y32 = i32::try_from(y).unwrap_or(0);
	(y32, m32, d32)
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
		let Some(raw) = parse_line(&line) else {
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
		let Some(raw) = parse_line(&line) else {
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
		let Some(raw) = parse_line(&line) else {
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

fn escape_text(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for c in s.chars() {
		match c {
			'\\' => out.push_str("\\\\"),
			'\n' => out.push_str("\\n"),
			',' => out.push_str("\\,"),
			';' => out.push_str("\\;"),
			_ => out.push(c),
		}
	}
	out
}

fn fold_line(out: &mut String, line: &str) {
	let bytes = line.as_bytes();
	if bytes.len() <= MAX_LINE_LEN {
		out.push_str(line);
		out.push_str("\r\n");
		return;
	}
	let mut i = 0;
	while i < bytes.len() {
		let end = (i + MAX_LINE_LEN).min(bytes.len());
		let mut safe_end = end;
		while safe_end > i && !line.is_char_boundary(safe_end) {
			safe_end -= 1;
		}
		if i > 0 {
			out.push(' ');
		}
		out.push_str(&line[i..safe_end]);
		out.push_str("\r\n");
		i = safe_end;
	}
}

fn sanitize_for_line(s: &str) -> String {
	s.chars().filter(|c| !matches!(c, '\r' | '\n')).collect()
}

fn write_line(out: &mut String, name: &str, params: &[(&str, &str)], value: &str, verbatim: bool) {
	let encoded = if verbatim { sanitize_for_line(value) } else { escape_text(value) };
	let mut line = String::with_capacity(name.len() + encoded.len() + 8);
	line.push_str(name);
	for (k, v) in params {
		line.push(';');
		line.push_str(k);
		line.push('=');
		let cleaned: String = v.chars().filter(|c| *c != '"' && !c.is_control()).collect();
		if cleaned.contains([',', ';', ':']) {
			line.push('"');
			line.push_str(&cleaned);
			line.push('"');
		} else {
			line.push_str(&cleaned);
		}
	}
	line.push(':');
	line.push_str(&encoded);
	fold_line(out, &line);
}

/// Parse an ISO-8601 datetime from REST JSON (`YYYY-MM-DDTHH:MM:SS(Z|±HH:MM)?`) or a bare
/// date (`YYYY-MM-DD`). Returns (unix seconds, is_date). Timezone offsets are applied;
/// floating datetimes (no offset) are treated as UTC.
fn parse_iso(value: &str) -> Option<(i64, bool)> {
	let v = value.trim();
	if v.len() == 10 && v.as_bytes().get(4) == Some(&b'-') && v.as_bytes().get(7) == Some(&b'-') {
		let y: i32 = v.get(0..4)?.parse().ok()?;
		let m: u32 = v.get(5..7)?.parse().ok()?;
		let d: u32 = v.get(8..10)?.parse().ok()?;
		return Some((date_to_unix(y, m, d)?, true));
	}
	if v.len() < 19 {
		return None;
	}
	let y: i32 = v.get(0..4)?.parse().ok()?;
	let m: u32 = v.get(5..7)?.parse().ok()?;
	let d: u32 = v.get(8..10)?.parse().ok()?;
	let hh: u32 = v.get(11..13)?.parse().ok()?;
	let mm: u32 = v.get(14..16)?.parse().ok()?;
	let ss: u32 = v.get(17..19)?.parse().ok()?;
	let base = date_to_unix(y, m, d)? + i64::from(hh) * 3600 + i64::from(mm) * 60 + i64::from(ss);
	let tz_part = v.get(19..).unwrap_or("");
	let offset_secs = parse_tz_offset(tz_part).unwrap_or(0);
	Some((base - offset_secs, false))
}

fn parse_tz_offset(s: &str) -> Option<i64> {
	let s = s.trim_start_matches('.').trim_start_matches(|c: char| c.is_ascii_digit());
	if s.is_empty() || s == "Z" {
		return Some(0);
	}
	let sign = match s.as_bytes().first() {
		Some(b'+') => 1_i64,
		Some(b'-') => -1_i64,
		_ => return None,
	};
	let rest = &s[1..];
	let (hh, mm) = if let Some((h, m)) = rest.split_once(':') {
		(h, m)
	} else if rest.len() == 4 {
		(&rest[..2], &rest[2..])
	} else {
		return None;
	};
	let h: i64 = hh.parse().ok()?;
	let m: i64 = mm.parse().ok()?;
	Some(sign * (h * 3600 + m * 60))
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
	let days = ts.0.div_euclid(86400);
	let sod = ts.0.rem_euclid(86400);
	let (y, m, d) = unix_days_to_ymd(days);
	if all_day {
		format!("{y:04}-{m:02}-{d:02}")
	} else {
		let hh = sod / 3600;
		let mm = (sod % 3600) / 60;
		let ss = sod % 60;
		format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
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
