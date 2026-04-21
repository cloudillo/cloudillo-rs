// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Parse REPORT request bodies (RFC 6352 §8, RFC 6578 §3, RFC 4791 §7).
//!
//! We handle the reports mainstream clients actually use:
//! - `{urn:ietf:params:xml:ns:carddav}addressbook-multiget` — "give me these specific hrefs"
//! - `{urn:ietf:params:xml:ns:caldav}calendar-multiget`  — same, for CalDAV
//! - `{urn:ietf:params:xml:ns:caldav}calendar-query`     — component + time-range filter
//! - `{DAV:}sync-collection` — "what changed since my last sync-token?"
//!
//! `addressbook-query` (server-side filtering) is not implemented; macOS / DAVx5 / iOS all
//! function fine without it. For calendar-query we parse only the top-level comp-filter and
//! time-range — deeper prop-filters collapse to "return superset" which is RFC-compliant
//! and lets the client do the precise filtering locally.

use quick_xml::{Reader, events::Event};
use tracing::warn;

use crate::{
	consts::{NS_CALDAV, NS_CARDDAV, NS_DAV},
	propfind::PropName,
};

/// Upper bound we ever accept on `<D:limit><D:nresults>` — larger values are dropped at
/// parse time so downstream handlers don't need to re-validate. The handler still applies
/// its own hard cap on the DB query.
pub const MAX_SYNC_LIMIT: u32 = 10_000;

/// A parsed REPORT request. Errors (malformed XML, unsupported report) collapse to `Unknown`.
#[derive(Debug, Clone, Default)]
pub enum Report {
	#[default]
	Unknown,
	AddressbookMultiget(MultigetReport),
	CalendarMultiget(MultigetReport),
	CalendarQuery(CalendarQueryReport),
	SyncCollection(SyncCollectionReport),
}

#[derive(Debug, Clone, Default)]
pub struct MultigetReport {
	pub props: Vec<PropName>,
	/// Raw hrefs from the request — the handler resolves them to UIDs.
	pub hrefs: Vec<String>,
}

/// Parsed `{urn:ietf:params:xml:ns:caldav}calendar-query` (RFC 4791 §7.8).
///
/// We extract only the pieces we use for the deliberately-loose "superset" semantics:
/// - `props`: which properties the client wants back
/// - `component`: the name of the inner-most `<comp-filter>` below VCALENDAR (VEVENT / VTODO)
/// - `time_range`: the `start` / `end` attributes from any nested `<time-range>` element
#[derive(Debug, Clone, Default)]
pub struct CalendarQueryReport {
	pub props: Vec<PropName>,
	pub component: Option<String>,
	/// `(start, end)` in iCalendar basic format (`YYYYMMDDTHHMMSSZ`).
	pub time_range: Option<(Option<String>, Option<String>)>,
}

#[derive(Debug, Clone, Default)]
pub struct SyncCollectionReport {
	pub props: Vec<PropName>,
	/// Client's last sync token; empty means initial sync.
	pub sync_token: Option<String>,
	/// Client's requested page size, clamped to `[1, MAX_SYNC_LIMIT]`. `None` = no client
	/// preference; the handler still applies its own hard cap.
	pub limit: Option<u32>,
}

pub fn parse(body: &str) -> Report {
	if crate::propfind_util::has_doctype_or_entity(body) {
		return Report::Unknown;
	}

	let mut reader = Reader::from_str(body);
	reader.config_mut().trim_text(true);

	// Track namespace scope plus the resolved (ns, local) name of every open element so End
	// events can match their opening Start by name, not position. Without this, the End of a
	// nested child would flip flags meant for its parent.
	let mut ns_stack: Vec<Vec<(String, String)>> = vec![vec![(String::new(), String::new())]];
	let mut element_stack: Vec<(String, String)> = Vec::new();
	let mut root_kind: Option<ReportKind> = None;
	// Depths at which each state flag's opening element sits; Some(n) means we're inside an
	// element opened when element_stack.len() was n. None means not inside.
	let mut prop_depth: Option<usize> = None;
	let mut href_depth: Option<usize> = None;
	let mut sync_token_depth: Option<usize> = None;
	let mut limit_depth: Option<usize> = None;
	let mut nresults_depth: Option<usize> = None;
	let mut current_text = String::new();
	// Set when a text node's XML-entity unescape fails. We continue reading events (so the
	// parser's own state stays consistent) but collapse the report to `Unknown` at the end
	// rather than trusting partially-recovered data.
	let mut had_unescape_error = false;

	let mut multiget = MultigetReport::default();
	let mut calendar_multiget = MultigetReport::default();
	let mut sync_coll = SyncCollectionReport::default();
	let mut cal_query = CalendarQueryReport::default();
	// Track the deepest comp-filter name we've seen so far (VCALENDAR → VEVENT → ...).
	let mut cal_query_comp_depth: Option<usize> = None;

	loop {
		match reader.read_event() {
			Ok(Event::Start(e)) => {
				super::propfind_util::push_ns_scope(&mut ns_stack, &e);
				let (ns, local) = super::propfind_util::resolve_name(&ns_stack, e.name().as_ref());
				element_stack.push((ns.clone(), local.clone()));

				if root_kind.is_none() {
					match (ns.as_str(), local.as_str()) {
						(NS_CARDDAV, "addressbook-multiget") => {
							root_kind = Some(ReportKind::AddressbookMultiget);
						}
						(NS_CALDAV, "calendar-multiget") => {
							root_kind = Some(ReportKind::CalendarMultiget);
						}
						(NS_CALDAV, "calendar-query") => {
							root_kind = Some(ReportKind::CalendarQuery);
						}
						(NS_DAV, "sync-collection") => {
							root_kind = Some(ReportKind::SyncCollection);
						}
						_ => {}
					}
					continue;
				}

				let depth = element_stack.len();
				let parent_is_prop = prop_depth == Some(depth - 1);
				match root_kind {
					Some(ReportKind::AddressbookMultiget) => match (ns.as_str(), local.as_str()) {
						(NS_DAV, "prop") if prop_depth.is_none() => prop_depth = Some(depth),
						(NS_DAV, "href") if href_depth.is_none() => {
							href_depth = Some(depth);
							current_text.clear();
						}
						_ if parent_is_prop => multiget.props.push(PropName::new(ns, local)),
						_ => {}
					},
					Some(ReportKind::CalendarMultiget) => match (ns.as_str(), local.as_str()) {
						(NS_DAV, "prop") if prop_depth.is_none() => prop_depth = Some(depth),
						(NS_DAV, "href") if href_depth.is_none() => {
							href_depth = Some(depth);
							current_text.clear();
						}
						_ if parent_is_prop => {
							calendar_multiget.props.push(PropName::new(ns, local));
						}
						_ => {}
					},
					Some(ReportKind::CalendarQuery) => {
						if ns == NS_DAV && local == "prop" && prop_depth.is_none() {
							prop_depth = Some(depth);
						} else if parent_is_prop {
							cal_query.props.push(PropName::new(ns, local));
						} else if ns == NS_CALDAV && local == "comp-filter" {
							// Read `name="…"`; keep the deepest (inner-most) one. VCALENDAR is
							// the outer filter; VEVENT/VTODO lives inside it.
							if let Some(name) = read_name_attr(&e) {
								let name_upper = name.to_ascii_uppercase();
								let is_deeper = cal_query_comp_depth.is_none_or(|d| depth > d);
								if is_deeper && name_upper != "VCALENDAR" {
									cal_query.component = Some(name_upper);
									cal_query_comp_depth = Some(depth);
								}
							}
						}
					}
					Some(ReportKind::SyncCollection) => match (ns.as_str(), local.as_str()) {
						(NS_DAV, "prop") if prop_depth.is_none() => prop_depth = Some(depth),
						(NS_DAV, "sync-token") if sync_token_depth.is_none() => {
							sync_token_depth = Some(depth);
							current_text.clear();
						}
						(NS_DAV, "limit") if limit_depth.is_none() => limit_depth = Some(depth),
						(NS_DAV, "nresults")
							if limit_depth.is_some() && nresults_depth.is_none() =>
						{
							nresults_depth = Some(depth);
							current_text.clear();
						}
						_ if parent_is_prop => sync_coll.props.push(PropName::new(ns, local)),
						_ => {}
					},
					_ => {}
				}
			}
			Ok(Event::Empty(e)) => {
				super::propfind_util::push_ns_scope(&mut ns_stack, &e);
				let (ns, local) = super::propfind_util::resolve_name(&ns_stack, e.name().as_ref());
				let parent_is_prop = prop_depth == Some(element_stack.len());
				if parent_is_prop {
					match root_kind {
						Some(ReportKind::AddressbookMultiget) => {
							multiget.props.push(PropName::new(ns, local));
						}
						Some(ReportKind::CalendarMultiget) => {
							calendar_multiget.props.push(PropName::new(ns, local));
						}
						Some(ReportKind::CalendarQuery) => {
							cal_query.props.push(PropName::new(ns, local));
						}
						Some(ReportKind::SyncCollection) => {
							sync_coll.props.push(PropName::new(ns, local));
						}
						_ => {}
					}
				} else if matches!(root_kind, Some(ReportKind::SyncCollection))
					&& ns == NS_DAV && local == "sync-token"
				{
					// Explicit empty <sync-token/> → initial sync.
					sync_coll.sync_token = None;
				} else if matches!(root_kind, Some(ReportKind::CalendarQuery))
					&& ns == NS_CALDAV
					&& local == "time-range"
				{
					let start = read_attr(&e, b"start");
					let end = read_attr(&e, b"end");
					cal_query.time_range = Some((start, end));
				} else if matches!(root_kind, Some(ReportKind::CalendarQuery))
					&& ns == NS_CALDAV
					&& local == "comp-filter"
				{
					// Self-closing <comp-filter name="VEVENT"/> — no inner time-range, but we
					// still want to capture the component name.
					if let Some(name) = read_name_attr(&e) {
						let name_upper = name.to_ascii_uppercase();
						let depth = element_stack.len() + 1;
						let is_deeper = cal_query_comp_depth.is_none_or(|d| depth > d);
						if is_deeper && name_upper != "VCALENDAR" {
							cal_query.component = Some(name_upper);
							cal_query_comp_depth = Some(depth);
						}
					}
				}
				ns_stack.pop();
			}
			Ok(Event::Text(t))
				if href_depth.is_some()
					|| sync_token_depth.is_some()
					|| nresults_depth.is_some() =>
			{
				match t.unescape() {
					Ok(s) => current_text.push_str(&s),
					Err(e) => {
						warn!("REPORT body has malformed XML entity: {e}");
						had_unescape_error = true;
					}
				}
			}
			Ok(Event::End(_)) => {
				ns_stack.pop();
				let _closed = element_stack.pop();
				let depth = element_stack.len();
				// A flag closes when we pop out past the depth where it opened. Using
				// equality (not strict inequality) is fine because End pops first and the
				// opening element sat at depth == Some(_depth+1) before the pop.
				if prop_depth.is_some_and(|d| d > depth) {
					prop_depth = None;
				}
				if href_depth.is_some_and(|d| d > depth) {
					href_depth = None;
					let s = std::mem::take(&mut current_text);
					// Empty / whitespace-only <href/> is meaningless; dropping it avoids
					// emitting empty <D:href></D:href> rows in the multistatus response.
					if !s.trim().is_empty() {
						match root_kind {
							Some(ReportKind::CalendarMultiget) => {
								calendar_multiget.hrefs.push(s);
							}
							_ => multiget.hrefs.push(s),
						}
					}
				}
				if sync_token_depth.is_some_and(|d| d > depth) {
					sync_token_depth = None;
					let s = std::mem::take(&mut current_text);
					sync_coll.sync_token = if s.is_empty() { None } else { Some(s) };
				}
				if nresults_depth.is_some_and(|d| d > depth) {
					nresults_depth = None;
					sync_coll.limit = current_text
						.trim()
						.parse::<u32>()
						.ok()
						.filter(|&n| n > 0 && n <= MAX_SYNC_LIMIT);
					current_text.clear();
				}
				if limit_depth.is_some_and(|d| d > depth) {
					limit_depth = None;
				}
			}
			Ok(Event::Eof) | Err(_) => break,
			_ => {}
		}
	}

	if had_unescape_error {
		return Report::Unknown;
	}
	match root_kind {
		Some(ReportKind::AddressbookMultiget) => Report::AddressbookMultiget(multiget),
		Some(ReportKind::CalendarMultiget) => Report::CalendarMultiget(calendar_multiget),
		Some(ReportKind::CalendarQuery) => Report::CalendarQuery(cal_query),
		Some(ReportKind::SyncCollection) => Report::SyncCollection(sync_coll),
		None => Report::Unknown,
	}
}

fn read_attr(e: &quick_xml::events::BytesStart<'_>, key: &[u8]) -> Option<String> {
	for attr in e.attributes().flatten() {
		if attr.key.as_ref() == key {
			return std::str::from_utf8(&attr.value).ok().map(str::to_string);
		}
	}
	None
}

fn read_name_attr(e: &quick_xml::events::BytesStart<'_>) -> Option<String> {
	read_attr(e, b"name")
}

#[derive(Debug, Clone, Copy)]
enum ReportKind {
	AddressbookMultiget,
	CalendarMultiget,
	CalendarQuery,
	SyncCollection,
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
	use super::*;

	#[test]
	fn parse_addressbook_multiget() {
		let body = r#"<?xml version="1.0" encoding="utf-8"?>
			<c:addressbook-multiget xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">
				<d:prop>
					<d:getetag/>
					<c:address-data/>
				</d:prop>
				<d:href>/dav/addressbooks/Contacts/abc.vcf</d:href>
				<d:href>/dav/addressbooks/Contacts/def.vcf</d:href>
			</c:addressbook-multiget>"#;
		let Report::AddressbookMultiget(r) = parse(body) else {
			panic!("expected addressbook-multiget");
		};
		assert_eq!(r.hrefs.len(), 2);
		assert!(r.hrefs.iter().any(|h| h.ends_with("abc.vcf")));
		assert!(r.props.iter().any(|p| p.is(NS_DAV, "getetag")));
		assert!(r.props.iter().any(|p| p.is(NS_CARDDAV, "address-data")));
	}

	#[test]
	fn parse_sync_collection_initial() {
		let body = r#"<?xml version="1.0" encoding="utf-8"?>
			<d:sync-collection xmlns:d="DAV:">
				<d:sync-token/>
				<d:sync-level>1</d:sync-level>
				<d:prop><d:getetag/></d:prop>
			</d:sync-collection>"#;
		let Report::SyncCollection(r) = parse(body) else {
			panic!("expected sync-collection");
		};
		assert_eq!(r.sync_token, None);
		assert_eq!(r.limit, None);
		assert!(r.props.iter().any(|p| p.is(NS_DAV, "getetag")));
	}

	#[test]
	fn sync_collection_clamps_limit() {
		let body = format!(
			r#"<?xml version="1.0" encoding="utf-8"?>
			<d:sync-collection xmlns:d="DAV:">
				<d:sync-token/>
				<d:limit><d:nresults>{}</d:nresults></d:limit>
				<d:prop><d:getetag/></d:prop>
			</d:sync-collection>"#,
			u64::from(MAX_SYNC_LIMIT) + 1,
		);
		let Report::SyncCollection(r) = parse(&body) else {
			panic!("expected sync-collection");
		};
		assert_eq!(r.limit, None, "limits above MAX_SYNC_LIMIT must be dropped");

		let body = r#"<?xml version="1.0" encoding="utf-8"?>
			<d:sync-collection xmlns:d="DAV:">
				<d:sync-token/>
				<d:limit><d:nresults>0</d:nresults></d:limit>
			</d:sync-collection>"#;
		let Report::SyncCollection(r) = parse(body) else {
			panic!("expected sync-collection");
		};
		assert_eq!(r.limit, None, "zero limits must be dropped");

		let body = r#"<?xml version="1.0" encoding="utf-8"?>
			<d:sync-collection xmlns:d="DAV:">
				<d:sync-token/>
				<d:limit><d:nresults>250</d:nresults></d:limit>
			</d:sync-collection>"#;
		let Report::SyncCollection(r) = parse(body) else {
			panic!("expected sync-collection");
		};
		assert_eq!(r.limit, Some(250));
	}

	#[test]
	fn empty_hrefs_are_skipped() {
		// Empty <href/> (both self-closed and <href></href>) must not reach the handler.
		let body = r#"<?xml version="1.0" encoding="utf-8"?>
			<c:addressbook-multiget xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">
				<d:prop><d:getetag/></d:prop>
				<d:href>/dav/addressbooks/Contacts/abc.vcf</d:href>
				<d:href></d:href>
				<d:href>   </d:href>
			</c:addressbook-multiget>"#;
		let Report::AddressbookMultiget(r) = parse(body) else {
			panic!("expected addressbook-multiget");
		};
		assert_eq!(r.hrefs, vec!["/dav/addressbooks/Contacts/abc.vcf".to_string()]);
	}

	#[test]
	fn parse_sync_collection_with_token() {
		let body = r#"<?xml version="1.0" encoding="utf-8"?>
			<d:sync-collection xmlns:d="DAV:">
				<d:sync-token>http://cloudillo.example/sync/1700000000</d:sync-token>
				<d:prop><d:getetag/></d:prop>
			</d:sync-collection>"#;
		let Report::SyncCollection(r) = parse(body) else {
			panic!("expected sync-collection");
		};
		assert_eq!(r.sync_token.as_deref(), Some("http://cloudillo.example/sync/1700000000"));
	}

	#[test]
	fn doctype_is_rejected_as_unknown() {
		// Entity-bearing bodies must be rejected before the XML parser sees them.
		let body = r#"<?xml version="1.0"?>
			<!DOCTYPE addressbook-multiget [<!ENTITY x "aaaaaaaaaaaa">]>
			<c:addressbook-multiget xmlns:c="urn:ietf:params:xml:ns:carddav"/>"#;
		assert!(matches!(parse(body), Report::Unknown));
	}

	#[test]
	fn prop_with_nested_child_still_collects_siblings() {
		// Nested elements inside a <prop> must not close the in-prop state via their End tag.
		let body = r#"<?xml version="1.0" encoding="utf-8"?>
			<c:addressbook-multiget xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">
				<d:prop>
					<d:getetag/>
					<d:custom><d:inner/></d:custom>
					<c:address-data/>
				</d:prop>
				<d:href>/dav/ab/a.vcf</d:href>
			</c:addressbook-multiget>"#;
		let Report::AddressbookMultiget(r) = parse(body) else {
			panic!("expected addressbook-multiget");
		};
		assert!(r.props.iter().any(|p| p.is(NS_DAV, "getetag")));
		assert!(r.props.iter().any(|p| p.is(NS_DAV, "custom")));
		assert!(r.props.iter().any(|p| p.is(NS_CARDDAV, "address-data")));
		assert!(!r.props.iter().any(|p| p.is(NS_DAV, "inner")));
		assert_eq!(r.hrefs, vec!["/dav/ab/a.vcf".to_string()]);
	}

	#[test]
	fn parse_calendar_multiget() {
		let body = r#"<?xml version="1.0" encoding="utf-8"?>
			<c:calendar-multiget xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
				<d:prop>
					<d:getetag/>
					<c:calendar-data/>
				</d:prop>
				<d:href>/dav/calendars/Default/abc.ics</d:href>
				<d:href>/dav/calendars/Default/def.ics</d:href>
			</c:calendar-multiget>"#;
		let Report::CalendarMultiget(r) = parse(body) else {
			panic!("expected calendar-multiget");
		};
		assert_eq!(r.hrefs.len(), 2);
		assert!(r.hrefs.iter().any(|h| h.ends_with("abc.ics")));
		assert!(r.props.iter().any(|p| p.is(NS_DAV, "getetag")));
		assert!(r.props.iter().any(|p| p.is(NS_CALDAV, "calendar-data")));
	}

	#[test]
	fn parse_calendar_query_with_time_range() {
		let body = r#"<?xml version="1.0" encoding="utf-8"?>
			<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
				<d:prop>
					<d:getetag/>
					<c:calendar-data/>
				</d:prop>
				<c:filter>
					<c:comp-filter name="VCALENDAR">
						<c:comp-filter name="VEVENT">
							<c:time-range start="20260401T000000Z" end="20260501T000000Z"/>
						</c:comp-filter>
					</c:comp-filter>
				</c:filter>
			</c:calendar-query>"#;
		let Report::CalendarQuery(r) = parse(body) else {
			panic!("expected calendar-query");
		};
		assert_eq!(r.component.as_deref(), Some("VEVENT"));
		assert_eq!(
			r.time_range,
			Some((Some("20260401T000000Z".into()), Some("20260501T000000Z".into())))
		);
		assert!(r.props.iter().any(|p| p.is(NS_DAV, "getetag")));
	}

	#[test]
	fn parse_calendar_query_without_time_range() {
		let body = r#"<?xml version="1.0" encoding="utf-8"?>
			<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
				<d:prop><d:getetag/></d:prop>
				<c:filter>
					<c:comp-filter name="VCALENDAR">
						<c:comp-filter name="VTODO"/>
					</c:comp-filter>
				</c:filter>
			</c:calendar-query>"#;
		let Report::CalendarQuery(r) = parse(body) else {
			panic!("expected calendar-query");
		};
		assert_eq!(r.component.as_deref(), Some("VTODO"));
		assert_eq!(r.time_range, None);
	}

	#[test]
	fn unknown_report_collapses_gracefully() {
		let body = r#"<?xml version="1.0" encoding="utf-8"?>
			<d:some-other-report xmlns:d="DAV:"/>"#;
		assert!(matches!(parse(body), Report::Unknown));
	}
}

// vim: ts=4
