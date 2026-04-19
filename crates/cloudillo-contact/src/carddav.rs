// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! CardDAV endpoints — PROPFIND, REPORT, and resource GET/PUT/DELETE.
//!
//! Wiring (see `crates/cloudillo/src/routes.rs`):
//!
//! ```text
//! GET   /.well-known/carddav                         → 301 → /dav/principal/
//! ANY   /dav/principal/                              → principal PROPFIND
//! ANY   /dav/addressbooks/                           → home-set PROPFIND
//! ANY   /dav/addressbooks/{ab_name}/                 → collection PROPFIND / REPORT
//! ANY   /dav/addressbooks/{ab_name}/{resource}       → .vcf GET / PUT / DELETE
//! ```
//!
//! Auth: `cloudillo_dav::dav_basic_auth` applied as a layer on the `/dav/...` router.
//! All methods share the same handler and dispatch on `request.method()`.

use std::fmt::Write as _;

use axum::{
	body::{Body, to_bytes},
	extract::{Path, Request, State},
	http::{Method, Response, StatusCode, header},
};

use cloudillo_core::{IdTag, extract::Auth, prelude::*};
use cloudillo_dav::{
	MultiResponse, PropName, PropStat, Propfind, Report, escape_xml, render_multistatus,
};
use cloudillo_types::meta_adapter::ListContactOptions;

use crate::{
	profile_overlay::{merge_profile_into_input, resolve_profile},
	vcard,
};

// URL prefixes — kept in sync with route registrations in `cloudillo/src/routes.rs`.
const PRINCIPAL_PATH: &str = "/dav/principal/";
const ADDRESSBOOKS_PATH: &str = "/dav/addressbooks/";
const DAV_NS: &str = cloudillo_dav::NS_DAV;
const CARDDAV_NS: &str = cloudillo_dav::NS_CARDDAV;
const CALSERVER_NS: &str = cloudillo_dav::NS_CALSERVER;

// Body size limit for DAV XML / vCard requests (1 MiB is more than enough for any vCard).
const MAX_BODY_BYTES: usize = 1024 * 1024;

// Server-side ceiling on sync-collection page size. Clients may request a smaller limit;
// they cannot force a larger one. When a response is truncated, the returned sync-token
// advances to the last row we sent and clients repeat the request to fetch the rest.
const MAX_SYNC_PAGE: u32 = 1_000;

// Helpers
//*********

fn etag_header(etag: &str) -> String {
	format!("\"{etag}\"")
}

fn xml_response(status: StatusCode, body: String) -> Response<Body> {
	Response::builder()
		.status(status)
		.header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
		.header("DAV", "1, 2, 3, addressbook")
		.body(Body::from(body))
		.unwrap_or_else(|_| plain_error(StatusCode::INTERNAL_SERVER_ERROR, "xml build failed"))
}

fn plain_error(status: StatusCode, msg: &'static str) -> Response<Body> {
	Response::builder().status(status).body(Body::from(msg)).unwrap_or_else(|_| {
		let mut r = Response::new(Body::from(msg));
		*r.status_mut() = status;
		r
	})
}

fn ok_empty() -> Response<Body> {
	use axum::http::HeaderValue;
	// Direct construction (no fallible builder) so headers can never be silently dropped.
	let mut resp = Response::new(Body::empty());
	resp.headers_mut()
		.insert("dav", HeaderValue::from_static("1, 2, 3, addressbook"));
	resp.headers_mut().insert(
		"allow",
		HeaderValue::from_static("OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, REPORT, MKCOL"),
	);
	resp
}

/// Encode a sync token from a unix timestamp. Opaque to clients but stable.
fn encode_sync_token(ts: i64) -> String {
	format!("urn:cloudillo:sync:{ts}")
}

fn decode_sync_token(token: &str) -> Option<i64> {
	token.strip_prefix("urn:cloudillo:sync:").and_then(|s| s.parse().ok())
}

fn has_prop(props: &[PropName], ns: &str, local: &str) -> bool {
	props.iter().any(|p| p.is(ns, local))
}

fn depth(req: &Request<Body>) -> u8 {
	match req.headers().get("Depth").and_then(|h| h.to_str().ok()) {
		Some("1") => 1,
		Some("infinity") => u8::MAX,
		_ => 0,
	}
}

/// Read the request body as UTF-8. RFC 6350 §3.1 and RFC 6352 §6.3 require vCard/CardDAV
/// bodies to be UTF-8; malformed bytes are rejected rather than silently repaired so we
/// never persist a corrupted vCard and serve it back to clients.
async fn read_body(req: Request<Body>) -> Result<String, Response<Body>> {
	let bytes = to_bytes(req.into_body(), MAX_BODY_BYTES).await.map_err(|e| {
		warn!("CardDAV body read failed (likely > {} bytes): {:?}", MAX_BODY_BYTES, e);
		plain_error(StatusCode::PAYLOAD_TOO_LARGE, "request body too large")
	})?;
	String::from_utf8(bytes.to_vec())
		.map_err(|_| plain_error(StatusCode::BAD_REQUEST, "request body must be UTF-8"))
}

// .well-known/carddav redirect
//******************************
//
// Mounted on both services so discovery works whichever domain a CardDAV client probes:
//   - On the API service (Host = `cl-o.{idTag}`)
//   - On the App service (Host = `{idTag}`)
//
// Always emits an absolute URL to the API domain (`https://cl-o.{idTag}/dav/principal/`)
// sourced from the `IdTag` extension that the webserver injected from the authority. This
// is robust to HTTP/2 (where the authority arrives as the `:authority` pseudo-header, not a
// `Host` header) and unambiguous for the client regardless of which domain it probed.

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

// Principal
//***********

pub async fn handle_principal(
	State(app): State<App>,
	Auth(auth): Auth,
	IdTag(id_tag): IdTag,
	req: Request<Body>,
) -> Response<Body> {
	let method = req.method().clone();
	let _ = (&app, &auth, &id_tag);

	if method == Method::OPTIONS {
		return ok_empty();
	}
	if method.as_str() != "PROPFIND" {
		return plain_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
	}

	let body = match read_body(req).await {
		Ok(b) => b,
		Err(r) => return r,
	};
	let pf = cloudillo_dav::propfind::parse(&body);

	let principal_href = PRINCIPAL_PATH;
	let home_href = ADDRESSBOOKS_PATH;
	let display = format!("{}", id_tag);

	let mut props = String::new();
	let want = |ns: &str, local: &str| -> bool {
		match &pf {
			Propfind::AllProp | Propfind::PropName => true,
			Propfind::Prop(list) => has_prop(list, ns, local),
		}
	};

	if want(DAV_NS, "resourcetype") {
		props.push_str("<d:resourcetype><d:principal/></d:resourcetype>");
	}
	if want(DAV_NS, "displayname") {
		let _ = write!(&mut props, "<d:displayname>{}</d:displayname>", escape_xml(&display));
	}
	if want(DAV_NS, "current-user-principal") {
		let _ = write!(
			&mut props,
			"<d:current-user-principal><d:href>{}</d:href></d:current-user-principal>",
			escape_xml(principal_href),
		);
	}
	if want(DAV_NS, "principal-URL") {
		let _ = write!(
			&mut props,
			"<d:principal-URL><d:href>{}</d:href></d:principal-URL>",
			escape_xml(principal_href),
		);
	}
	if want(CARDDAV_NS, "addressbook-home-set") {
		let _ = write!(
			&mut props,
			"<c:addressbook-home-set><d:href>{}</d:href></c:addressbook-home-set>",
			escape_xml(home_href),
		);
	}

	let resp = MultiResponse::new(principal_href).with_propstat(PropStat::ok(props));
	xml_response(StatusCode::MULTI_STATUS, render_multistatus(&[resp], None))
}

// Home set — lists address books
//********************************

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

	// The home-set collection itself.
	responses.push(home_self_response(&pf));

	// Child address books (depth >= 1).
	if d >= 1 {
		let books = match app.meta_adapter.list_address_books(tn_id).await {
			Ok(b) => b,
			Err(e) => {
				warn!("CardDAV home list failed: {:?}", e);
				return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "db error");
			}
		};
		for ab in &books {
			responses.push(collection_response(&pf, ab));
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
		props.push_str("<d:displayname>Address Books</d:displayname>");
	}
	MultiResponse::new(ADDRESSBOOKS_PATH).with_propstat(PropStat::ok(props))
}

fn collection_href(name: &str) -> String {
	format!("{}{}/", ADDRESSBOOKS_PATH, urlencode_path(name))
}

fn collection_response(
	pf: &Propfind,
	ab: &cloudillo_types::meta_adapter::AddressBook,
) -> MultiResponse {
	let href = collection_href(&ab.name);
	let want = |ns: &str, local: &str| matches_prop(pf, ns, local);
	let mut props = String::new();

	if want(DAV_NS, "resourcetype") {
		props.push_str("<d:resourcetype><d:collection/><c:addressbook/></d:resourcetype>");
	}
	if want(DAV_NS, "displayname") {
		let _ = write!(&mut props, "<d:displayname>{}</d:displayname>", escape_xml(&ab.name));
	}
	if want(CARDDAV_NS, "addressbook-description")
		&& let Some(desc) = ab.description.as_deref()
	{
		let _ = write!(
			&mut props,
			"<c:addressbook-description>{}</c:addressbook-description>",
			escape_xml(desc),
		);
	}
	if want(CARDDAV_NS, "supported-address-data") {
		props.push_str(
			"<c:supported-address-data>\
				<c:address-data-type content-type=\"text/vcard\" version=\"4.0\"/>\
				<c:address-data-type content-type=\"text/vcard\" version=\"3.0\"/>\
			</c:supported-address-data>",
		);
	}
	if want(CARDDAV_NS, "max-resource-size") {
		props.push_str("<c:max-resource-size>1048576</c:max-resource-size>");
	}
	if want(DAV_NS, "supported-report-set") {
		props.push_str(
			"<d:supported-report-set>\
				<d:supported-report><d:report><c:addressbook-multiget/></d:report></d:supported-report>\
				<d:supported-report><d:report><d:sync-collection/></d:report></d:supported-report>\
			</d:supported-report-set>",
		);
	}
	if want(CALSERVER_NS, "getctag") {
		let _ = write!(&mut props, "<cs:getctag>{}</cs:getctag>", escape_xml(&ab.ctag));
	}
	if want(DAV_NS, "sync-token") {
		let _ = write!(
			&mut props,
			"<d:sync-token>{}</d:sync-token>",
			escape_xml(&encode_sync_token(ab.updated_at.0)),
		);
	}

	MultiResponse::new(href).with_propstat(PropStat::ok(props))
}

fn matches_prop(pf: &Propfind, ns: &str, local: &str) -> bool {
	match pf {
		Propfind::AllProp | Propfind::PropName => true,
		Propfind::Prop(list) => has_prop(list, ns, local),
	}
}

/// URL-encode a path segment (names may contain spaces or punctuation).
pub(crate) fn urlencode_path(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for b in s.bytes() {
		if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
			out.push(b as char);
		} else {
			let _ = write!(&mut out, "%{:02X}", b);
		}
	}
	out
}

/// Strip the surrounding double quotes from an ETag header value per RFC 7232 §2.3, so
/// comparisons are always against the opaque-tag bytes themselves.
fn unquote_etag(s: &str) -> &str {
	let t = s.trim();
	t.strip_prefix('"').and_then(|x| x.strip_suffix('"')).unwrap_or(t)
}

/// URL-decode a path segment from the wire. Returns `None` when the input contains a
/// malformed percent-escape or the decoded bytes are not valid UTF-8; callers should
/// respond 400 Bad Request rather than silently passing the undecoded text downstream.
fn urldecode_path(s: &str) -> Option<String> {
	let bytes = s.as_bytes();
	let mut out = Vec::with_capacity(bytes.len());
	let mut i = 0;
	while i < bytes.len() {
		if bytes[i] == b'%' {
			if i + 2 >= bytes.len() {
				return None;
			}
			let hi = u8::try_from((bytes[i + 1] as char).to_digit(16)?).ok()?;
			let lo = u8::try_from((bytes[i + 2] as char).to_digit(16)?).ok()?;
			out.push((hi << 4) | lo);
			i += 3;
			continue;
		}
		out.push(bytes[i]);
		i += 1;
	}
	String::from_utf8(out).ok()
}

// Collection (single address book) — PROPFIND / REPORT / MKCOL
//**************************************************************

pub async fn handle_collection(
	State(app): State<App>,
	Auth(auth): Auth,
	Path(ab_name_raw): Path<String>,
	req: Request<Body>,
) -> Response<Body> {
	let method = req.method().clone();
	let tn_id = auth.tn_id;
	let Some(ab_name) = urldecode_path(&ab_name_raw) else {
		return plain_error(StatusCode::BAD_REQUEST, "invalid URL encoding");
	};

	if method == Method::OPTIONS {
		return ok_empty();
	}

	let ab = match app.meta_adapter.get_address_book_by_name(tn_id, &ab_name).await {
		Ok(Some(ab)) => ab,
		Ok(None) => return plain_error(StatusCode::NOT_FOUND, "no such address book"),
		Err(e) => {
			warn!("CardDAV collection lookup failed: {:?}", e);
			return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "db error");
		}
	};

	match method.as_str() {
		"PROPFIND" => propfind_collection(&app, tn_id, ab, req).await,
		"REPORT" => report_collection(&app, tn_id, ab, req).await,
		"MKCOL" => plain_error(StatusCode::METHOD_NOT_ALLOWED, "already exists"),
		_ => plain_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
	}
}

async fn propfind_collection(
	app: &App,
	tn_id: TnId,
	ab: cloudillo_types::meta_adapter::AddressBook,
	req: Request<Body>,
) -> Response<Body> {
	let d = depth(&req);
	let body = match read_body(req).await {
		Ok(b) => b,
		Err(r) => return r,
	};
	let pf = cloudillo_dav::propfind::parse(&body);

	let mut responses: Vec<MultiResponse> = Vec::new();
	responses.push(collection_response(&pf, &ab));

	if d >= 1 {
		let rows = match app
			.meta_adapter
			.list_contacts(tn_id, ab.ab_id, &ListContactOptions::default())
			.await
		{
			Ok(r) => r,
			Err(e) => {
				warn!("CardDAV list_contacts failed: {:?}", e);
				return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "db error");
			}
		};
		for row in &rows {
			let href = format!(
				"{}{}",
				collection_href(&ab.name),
				urlencode_path(&format!("{}.vcf", row.uid)),
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
	vcard_body: Option<&str>,
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
		props.push_str("<d:getcontenttype>text/vcard; charset=utf-8</d:getcontenttype>");
	}
	if want(CARDDAV_NS, "address-data")
		&& let Some(body) = vcard_body
	{
		let _ = write!(&mut props, "<c:address-data>{}</c:address-data>", escape_xml(body));
	}
	MultiResponse::new(href).with_propstat(PropStat::ok(props))
}

async fn report_collection(
	app: &App,
	tn_id: TnId,
	ab: cloudillo_types::meta_adapter::AddressBook,
	req: Request<Body>,
) -> Response<Body> {
	let body = match read_body(req).await {
		Ok(b) => b,
		Err(r) => return r,
	};
	match cloudillo_dav::report::parse(&body) {
		Report::AddressbookMultiget(r) => {
			let uids: Vec<String> = r
				.hrefs
				.iter()
				.filter_map(|h| {
					// Expect hrefs like /dav/addressbooks/{ab}/{uid}.vcf.
					// Silently skip undecodable hrefs here — the per-href loop below
					// will render them as 404 in the multistatus response.
					let last = h.rsplit('/').next()?;
					let decoded = urldecode_path(last)?;
					decoded.strip_suffix(".vcf").map(str::to_string)
				})
				.collect();
			let uid_refs: Vec<&str> = uids.iter().map(String::as_str).collect();

			let rows = match app.meta_adapter.get_contacts_by_uids(tn_id, ab.ab_id, &uid_refs).await
			{
				Ok(r) => r,
				Err(e) => {
					warn!("CardDAV multiget lookup failed: {:?}", e);
					return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "db error");
				}
			};
			let found: std::collections::HashMap<String, &cloudillo_types::meta_adapter::Contact> =
				rows.iter().map(|r| (r.uid.to_string(), r)).collect();
			// UID is unique per address book in the DB; a collision here would mean a
			// schema violation silently dropping rows from the response.
			debug_assert!(
				found.len() == rows.len(),
				"duplicate UID in address book ab_id={}",
				ab.ab_id
			);

			let pf = Propfind::Prop(r.props);
			let mut responses: Vec<MultiResponse> = Vec::new();
			for href in &r.hrefs {
				let last = href.rsplit('/').next().unwrap_or("");
				let uid =
					urldecode_path(last).and_then(|s| s.strip_suffix(".vcf").map(str::to_string));
				match uid.and_then(|u| found.get(&u).copied()) {
					Some(row) => {
						responses.push(resource_response(&pf, href, &row.etag, Some(&row.vcard)));
					}
					None => responses.push(MultiResponse::new(href).with_status(404)),
				}
			}
			xml_response(StatusCode::MULTI_STATUS, render_multistatus(&responses, None))
		}
		Report::SyncCollection(r) => {
			let since = r.sync_token.as_deref().and_then(decode_sync_token).map(Timestamp);
			// Effective page size: honour the client's limit up to our ceiling, and default
			// to the ceiling when the client didn't ask for one.
			let effective_limit = r.limit.map_or(MAX_SYNC_PAGE, |n| n.min(MAX_SYNC_PAGE));
			let entries = match app
				.meta_adapter
				.list_contacts_since(tn_id, ab.ab_id, since, Some(effective_limit))
				.await
			{
				Ok(e) => e,
				Err(e) => {
					warn!("CardDAV sync-collection failed: {:?}", e);
					return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "db error");
				}
			};
			// If we hit the cap, the response is a partial page: advance the token to the
			// last row's timestamp so a follow-up request picks up from there. Otherwise
			// use the address book's updated_at as the floor so empty syncs still produce
			// a monotonic token.
			//
			// Known limitation: the sync token encodes only `updated_at` (seconds). If more
			// than `MAX_SYNC_PAGE` rows share the same second (e.g. bulk import), each page
			// will start at the same timestamp and the client loops. Fix requires extending
			// the token to include a `(updated_at, c_id)` tiebreaker — out of scope here.
			let truncated = u32::try_from(entries.len()).unwrap_or(u32::MAX) >= effective_limit;
			if truncated {
				let min_ts = entries.iter().map(|e| e.updated_at.0).min().unwrap_or(0);
				let max_ts = entries.iter().map(|e| e.updated_at.0).max().unwrap_or(0);
				if min_ts == max_ts {
					warn!(
						ab_id = ab.ab_id,
						rows = entries.len(),
						"sync-collection page cap hit with all rows sharing one timestamp — \
						 client may loop; consider widening MAX_SYNC_PAGE or extending the token",
					);
				}
			}
			let max_ts = entries.iter().map(|e| e.updated_at.0).max().unwrap_or(0);
			let token_ts = if truncated { max_ts } else { max_ts.max(ab.updated_at.0) };
			let new_token = encode_sync_token(token_ts);

			let pf = Propfind::Prop(r.props);
			let mut responses: Vec<MultiResponse> = Vec::new();
			for entry in &entries {
				let href = format!(
					"{}{}",
					collection_href(&ab.name),
					urlencode_path(&format!("{}.vcf", entry.uid)),
				);
				if entry.deleted {
					responses.push(MultiResponse::new(href).with_status(404));
				} else {
					responses.push(resource_response(&pf, &href, &entry.etag, None));
				}
			}
			xml_response(StatusCode::MULTI_STATUS, render_multistatus(&responses, Some(&new_token)))
		}
		Report::Unknown => plain_error(StatusCode::BAD_REQUEST, "unsupported report"),
	}
}

// Individual resource (.vcf) — GET / PUT / DELETE / HEAD / OPTIONS
//*******************************************************************

pub async fn handle_resource(
	State(app): State<App>,
	Auth(auth): Auth,
	Path((ab_name_raw, resource_raw)): Path<(String, String)>,
	req: Request<Body>,
) -> Response<Body> {
	let method = req.method().clone();
	let tn_id = auth.tn_id;
	let (Some(ab_name), Some(resource)) =
		(urldecode_path(&ab_name_raw), urldecode_path(&resource_raw))
	else {
		return plain_error(StatusCode::BAD_REQUEST, "invalid URL encoding");
	};

	if method == Method::OPTIONS {
		return ok_empty();
	}

	let Some(uid) = resource.strip_suffix(".vcf") else {
		return plain_error(StatusCode::NOT_FOUND, "only .vcf resources are supported");
	};

	let ab = match app.meta_adapter.get_address_book_by_name(tn_id, &ab_name).await {
		Ok(Some(ab)) => ab,
		Ok(None) => return plain_error(StatusCode::NOT_FOUND, "no such address book"),
		Err(e) => {
			warn!("CardDAV resource ab lookup failed: {:?}", e);
			return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "db error");
		}
	};

	match method.as_str() {
		"GET" | "HEAD" => get_resource(&app, tn_id, ab.ab_id, uid, method == Method::HEAD).await,
		"PUT" => put_resource(&app, tn_id, ab.ab_id, uid, req).await,
		"DELETE" => delete_resource(&app, tn_id, ab.ab_id, uid).await,
		_ => plain_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
	}
}

async fn get_resource(
	app: &App,
	tn_id: TnId,
	ab_id: u64,
	uid: &str,
	head_only: bool,
) -> Response<Body> {
	let row = match app.meta_adapter.get_contact(tn_id, ab_id, uid).await {
		Ok(Some(r)) => r,
		Ok(None) => return plain_error(StatusCode::NOT_FOUND, "not found"),
		Err(e) => {
			warn!("CardDAV get failed: {:?}", e);
			return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "db error");
		}
	};

	let body = if head_only { Body::empty() } else { Body::from(row.vcard.to_string()) };
	Response::builder()
		.status(StatusCode::OK)
		.header(header::CONTENT_TYPE, "text/vcard; charset=utf-8")
		.header(header::ETAG, etag_header(&row.etag))
		.header("DAV", "1, 2, 3, addressbook")
		.body(body)
		.unwrap_or_else(|_| Response::new(Body::empty()))
}

async fn put_resource(
	app: &App,
	tn_id: TnId,
	ab_id: u64,
	uid: &str,
	req: Request<Body>,
) -> Response<Body> {
	// If-Match / If-None-Match precondition headers (for lost-update protection).
	let if_match = req.headers().get("If-Match").and_then(|h| h.to_str().ok()).map(str::to_string);
	let if_none_match = req
		.headers()
		.get("If-None-Match")
		.and_then(|h| h.to_str().ok())
		.map(str::to_string);

	let vcard_text = match read_body(req).await {
		Ok(s) => s,
		Err(r) => return r,
	};

	// Look up existing contact for precondition checks.
	let existing = match app.meta_adapter.get_contact(tn_id, ab_id, uid).await {
		Ok(e) => e,
		Err(e) => {
			warn!("CardDAV put: lookup failed: {:?}", e);
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

	// Parse vCard → structured form (preserves profile link + projected fields).
	let Some((mut input, _, _)) = vcard::parse(&vcard_text) else {
		return plain_error(StatusCode::BAD_REQUEST, "malformed vcard");
	};

	// Pin UID from the URL — mismatches would fragment state across endpoints.
	input.uid = Some(uid.to_string());

	// Apply smart profile merge before generating the canonical vCard.
	let linked_profile = match input.profile_id_tag.as_deref() {
		Some(tag) if !tag.is_empty() => match resolve_profile(app, tn_id, tag).await {
			Ok(p) => p,
			Err(e) => {
				warn!("CardDAV put: profile resolve failed: {:?}", e);
				None
			}
		},
		_ => None,
	};
	merge_profile_into_input(&mut input, linked_profile.as_ref());

	// Regenerate a canonical vCard so both code paths (REST and CardDAV) produce the same
	// stored blob given the same input.
	let canonical = vcard::generate(&input, None);
	let etag = vcard::etag_of(&canonical);
	let extracted = vcard::extract_from_input(&input);

	if let Err(e) = app
		.meta_adapter
		.upsert_contact(tn_id, ab_id, uid, &canonical, &etag, &extracted)
		.await
	{
		warn!("CardDAV put: upsert failed: {:?}", e);
		return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "db error");
	}

	let status = if existing.is_some() { StatusCode::NO_CONTENT } else { StatusCode::CREATED };
	Response::builder()
		.status(status)
		.header(header::ETAG, etag_header(&etag))
		.header("DAV", "1, 2, 3, addressbook")
		.body(Body::empty())
		.unwrap_or_else(|_| Response::new(Body::empty()))
}

async fn delete_resource(app: &App, tn_id: TnId, ab_id: u64, uid: &str) -> Response<Body> {
	match app.meta_adapter.delete_contact(tn_id, ab_id, uid).await {
		Ok(()) => Response::builder()
			.status(StatusCode::NO_CONTENT)
			.header("DAV", "1, 2, 3, addressbook")
			.body(Body::empty())
			.unwrap_or_else(|_| Response::new(Body::empty())),
		Err(Error::NotFound) => plain_error(StatusCode::NOT_FOUND, "not found"),
		Err(e) => {
			warn!("CardDAV delete failed: {:?}", e);
			plain_error(StatusCode::INTERNAL_SERVER_ERROR, "db error")
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn urlencode_roundtrip() {
		assert_eq!(urlencode_path("Work Contacts"), "Work%20Contacts");
		assert_eq!(urldecode_path("Work%20Contacts").as_deref(), Some("Work Contacts"));
		let mixed = "Szilárd+Doe";
		let enc = urlencode_path(mixed);
		assert_eq!(urldecode_path(&enc).as_deref(), Some(mixed));
	}

	#[test]
	fn urldecode_rejects_invalid_utf8() {
		// %FF alone is not a valid UTF-8 start byte — must be rejected, not silently
		// passed through.
		assert!(urldecode_path("bad%FFname").is_none());
	}

	#[test]
	fn unquote_etag_handles_quotes_and_whitespace() {
		assert_eq!(unquote_etag("\"abc\""), "abc");
		assert_eq!(unquote_etag("  \"abc\"  "), "abc");
		assert_eq!(unquote_etag("abc"), "abc");
		assert_eq!(unquote_etag("\"\""), "");
	}

	#[test]
	fn sync_token_roundtrip() {
		let t = encode_sync_token(1_700_000_000);
		assert_eq!(decode_sync_token(&t), Some(1_700_000_000));
		assert_eq!(decode_sync_token("urn:cloudillo:sync:abc"), None);
		assert_eq!(decode_sync_token("something-else"), None);
	}
}

// vim: ts=4
