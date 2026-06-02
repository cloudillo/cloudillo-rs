// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

use std::collections::{HashMap, HashSet};

use axum::{
	Json,
	body::Body,
	extract::State,
	http::{HeaderMap, StatusCode, header},
	response::Response,
};

use crate::prelude::*;
use cloudillo_core::IdTag;
use cloudillo_core::extract::{OptionalAuth, OptionalRequestId};
use cloudillo_core::profile_visibility::{CommunityRole, RequesterTier, SectionVisibility};
use cloudillo_types::meta_adapter::ProfileType;
use cloudillo_types::types::{ApiResponse, AppDomainRes, Profile, ProfileBase};

/// Wire-format string for a `ProfileType`. Shared between the full and base
/// `/api/me` handlers so they can't drift.
fn profile_type_str(t: ProfileType) -> &'static str {
	match t {
		ProfileType::Person => "person",
		ProfileType::Community => "community",
	}
}

/// Suffix appended to a section field name to mark its required visibility.
const VIS_SUFFIX: &str = ".vis";

/// Filter the tenant `x` map according to the caller's tier.
///
/// Sections are gated by `<field>.vis` markers. Sections without a marker are
/// treated as public (matches today's behaviour). Unknown marker values
/// (`SectionVisibility::parse` returns `None`) are treated as hidden — fail
/// closed.
///
/// When a section is hidden we strip:
/// - the `<field>` entry itself (if present),
/// - the `<field>.vis` marker (so anonymous callers see no hint),
/// - the `<field>` entry from the comma-separated `sections` list (dropped
///   entirely if the list becomes empty).
fn filter_sections(x: HashMap<Box<str>, Box<str>>, tier: RequesterTier) -> HashMap<String, String> {
	let mut hidden: HashSet<String> = HashSet::new();
	for (k, v) in &x {
		let Some(field) = k.strip_suffix(VIS_SUFFIX) else {
			continue;
		};
		// `RequesterTier::can_view` is the single source of truth for owner
		// short-circuits and tier comparisons; don't duplicate the logic here.
		let visible = match SectionVisibility::parse(v) {
			Some(req) => tier.can_view(req),
			None => tier.is_owner,
		};
		if !visible {
			hidden.insert(field.to_string());
		}
	}

	let mut out: HashMap<String, String> = HashMap::with_capacity(x.len());
	for (k, v) in x {
		let key = k.to_string();
		// Filter the comma-separated `sections` list before the hidden-key
		// check, so that even if a meta-marker accidentally inserted the
		// literal "sections" into `hidden`, we still produce a correctly
		// filtered list rather than dropping the entry entirely.
		if key == "sections" {
			let kept: Vec<&str> = v
				.split(',')
				.map(str::trim)
				.filter(|s| !s.is_empty() && !hidden.contains(*s))
				.collect();
			if kept.is_empty() {
				continue;
			}
			out.insert(key, kept.join(","));
			continue;
		}
		if hidden.contains(&key) {
			continue;
		}
		if let Some(field) = key.strip_suffix(VIS_SUFFIX)
			&& hidden.contains(field)
		{
			continue;
		}
		out.insert(key, v.to_string());
	}
	out
}

/// Format a hash as a strong ETag per RFC 7232 §2.3 — the surrounding quotes
/// are mandatory. Kept byte-identical to `cloudillo_dav::http::etag_header` so
/// behavior can't drift (inlined rather than taking a `cloudillo-dav` dep).
fn etag_header(etag: &str) -> String {
	format!("\"{etag}\"")
}

/// Strip the surrounding double quotes from an ETag header value per RFC 7232
/// §2.3, so comparisons are always against the opaque-tag bytes themselves.
/// Kept byte-identical to `cloudillo_dav::http::unquote_etag`.
fn unquote_etag(s: &str) -> &str {
	let t = s.trim();
	t.strip_prefix('"').and_then(|x| x.strip_suffix('"')).unwrap_or(t)
}

/// Compute a stable, content-derived ETag for a serialized `ProfileBase`.
///
/// Uses SHA-256 (the platform's existing content-hash primitive, via the `sha2`
/// crate) truncated to 64 bits and base64url-encoded — the same `URL_SAFE_NO_PAD`
/// alphabet the content-addressing `Hasher` uses (`cloudillo_types::hasher`), and
/// safe to embed verbatim in an ETag value. SHA-256 has a fixed, specified output
/// identical across Rust versions, platforms, and restarts, so a follower's
/// `If-None-Match` keeps matching as long as the content is unchanged — unlike
/// `std::hash::DefaultHasher`, which is deterministic today but carries no
/// cross-version stability guarantee. Because `ProfileBase` carries `name`,
/// `type`, `profile_pic`, **and** `keys`, the digest changes on any of them —
/// including signing-key rotation — with no extra inputs.
fn compute_etag(bytes: &[u8]) -> String {
	use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
	use sha2::{Digest, Sha256};
	let digest = Sha256::digest(bytes);
	URL_SAFE_NO_PAD.encode(&digest[..8])
}

/// `GET /api/me` — terse self-profile for federation peers.
///
/// Intentionally does not consult `OptionalAuth`: peers fetch this
/// unauthenticated, so the response shape must not depend on caller identity
/// (no tier filtering, no `x` map, no `cover_pic`). Owner-rendering UI
/// clients should call `/api/me/full` to get `x` and `cover_pic` with tier
/// filtering applied. Do not add an auth extractor here — that would
/// re-introduce the leakage `ProfileBase` was added to avoid.
///
/// Serves a content-derived `ETag` from an in-memory `ProfileMeCache` so the
/// frequent follower polls answer `304 Not Modified` without a meta-adapter
/// read. The cache stores only the ETag; the `ProfileBase` body is rebuilt on
/// every `200` and re-wrapped in a fresh `ApiResponse` carrying the current
/// `reqId`. The ETag is computed over the serialized `ProfileBase`, so a `304`
/// is consistent with the body a `200` would have produced.
pub async fn get_tenant_profile_base(
	State(app): State<App>,
	IdTag(id_tag): IdTag,
	OptionalRequestId(req_id): OptionalRequestId,
	headers: HeaderMap,
) -> ClResult<Response> {
	let auth_profile = app.auth_adapter.read_tenant(&id_tag).await?;
	let tn_id = auth_profile.tn_id;

	let if_none_match = headers
		.get(header::IF_NONE_MATCH)
		.and_then(|v| v.to_str().ok())
		.map(|s| unquote_etag(s).to_string());

	// Fast path: cached etag matches the conditional request → 304, no meta read.
	if let Some(ref inm) = if_none_match
		&& let Some(cached) = app.profile_me.get(tn_id)
		&& inm.as_str() == &*cached
	{
		// Sliding expiry: a hot tenant under constant polling stays warm instead
		// of expiring every TTL and paying a full auth + meta rebuild.
		app.profile_me.touch(tn_id);
		return Response::builder()
			.status(StatusCode::NOT_MODIFIED)
			.header(header::ETAG, etag_header(&cached))
			.body(Body::empty())
			.map_err(|e| Error::Internal(format!("failed to build 304 response: {}", e)));
	}

	let tenant_meta = app.meta_adapter.read_tenant(tn_id).await?;
	let profile = ProfileBase {
		id_tag: auth_profile.id_tag.to_string(),
		name: tenant_meta.name.to_string(),
		r#type: profile_type_str(tenant_meta.typ).to_string(),
		profile_pic: tenant_meta.profile_pic.map(|s| s.to_string()),
		keys: auth_profile.keys,
	};
	let body = serde_json::to_vec(&profile)?;
	let etag = compute_etag(&body);
	app.profile_me.insert(tn_id, etag.clone().into());

	// Cold/expired cache but content unchanged → still 304.
	if if_none_match.as_deref() == Some(etag.as_str()) {
		return Response::builder()
			.status(StatusCode::NOT_MODIFIED)
			.header(header::ETAG, etag_header(&etag))
			.body(Body::empty())
			.map_err(|e| Error::Internal(format!("failed to build 304 response: {}", e)));
	}

	let mut response = ApiResponse::new(profile);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}
	let json = serde_json::to_vec(&response)?;
	Response::builder()
		.status(StatusCode::OK)
		.header(header::CONTENT_TYPE, "application/json")
		.header(header::ETAG, etag_header(&etag))
		.body(Body::from(json))
		.map_err(|e| Error::Internal(format!("failed to build 200 response: {}", e)))
}

/// Public: returns the tenant's app/web domain (the cert `domain`) so clients on
/// the API host can build links to the tenant's web UI (e.g. `/s/<refId>` share
/// links). Unauthenticated — the app domain is public. Falls back to the idTag if
/// no cert row exists yet (e.g. local/dev without ACME), so it always returns 200.
pub async fn get_tenant_app_domain(
	State(app): State<App>,
	IdTag(id_tag): IdTag,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<AppDomainRes>>)> {
	let app_domain = match app.auth_adapter.read_cert_by_id_tag(&id_tag).await {
		Ok(cert) => cert.domain.to_string(),
		Err(_) => id_tag.to_string(),
	};
	let mut response = ApiResponse::new(AppDomainRes { app_domain });
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}
	Ok((StatusCode::OK, Json(response)))
}

pub async fn get_tenant_profile(
	State(app): State<App>,
	IdTag(id_tag): IdTag,
	OptionalAuth(auth): OptionalAuth,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Profile>>)> {
	let auth_profile = app.auth_adapter.read_tenant(&id_tag).await?;
	let tn_id = auth_profile.tn_id;
	let tenant_meta = app.meta_adapter.read_tenant(tn_id).await?;

	let is_owner = auth.as_ref().is_some_and(|a| a.id_tag.as_ref() == &*id_tag);
	let is_authenticated = auth.is_some();
	let max_role = auth
		.as_ref()
		.and_then(|a| a.roles.iter().filter_map(|r| CommunityRole::parse(r)).max());

	let (follows_tenant, connected_to_tenant) = if is_owner || !is_authenticated {
		(false, false)
	} else if let Some(a) = auth.as_ref() {
		let caller = a.id_tag.as_ref();
		let map = app.meta_adapter.get_relationships(tn_id, &[caller]).await?;
		let (f, c) = map.get(caller).copied().unwrap_or((false, false));
		(f, c)
	} else {
		(false, false)
	};

	let tier =
		RequesterTier { is_owner, is_authenticated, follows_tenant, connected_to_tenant, max_role };

	let x_map = filter_sections(tenant_meta.x, tier);

	let profile = Profile {
		id_tag: auth_profile.id_tag.to_string(),
		name: tenant_meta.name.to_string(),
		r#type: profile_type_str(tenant_meta.typ).to_string(),
		profile_pic: tenant_meta.profile_pic.map(|s| s.to_string()),
		cover_pic: tenant_meta.cover_pic.map(|s| s.to_string()),
		keys: auth_profile.keys,
		x: if x_map.is_empty() { None } else { Some(x_map) },
	};

	let mut response = ApiResponse::new(profile);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::OK, Json(response)))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn input() -> HashMap<Box<str>, Box<str>> {
		let mut x: HashMap<Box<str>, Box<str>> = HashMap::new();
		x.insert("links.vis".into(), "contributor".into());
		x.insert("sections".into(), "about,links".into());
		x.insert("links".into(), "{\"github\":\"x\"}".into());
		x.insert("about".into(), "hi".into());
		x
	}

	fn anon() -> RequesterTier {
		RequesterTier::anonymous()
	}

	fn auth_no_role() -> RequesterTier {
		RequesterTier { is_authenticated: true, ..RequesterTier::anonymous() }
	}

	fn auth_role(r: CommunityRole) -> RequesterTier {
		RequesterTier { is_authenticated: true, max_role: Some(r), ..RequesterTier::anonymous() }
	}

	fn owner() -> RequesterTier {
		RequesterTier { is_owner: true, ..RequesterTier::anonymous() }
	}

	#[test]
	fn anonymous_loses_gated_section_and_hint() {
		let out = filter_sections(input(), anon());
		assert_eq!(out.get("about").map(String::as_str), Some("hi"));
		assert_eq!(out.get("sections").map(String::as_str), Some("about"));
		assert!(!out.contains_key("links"));
		assert!(!out.contains_key("links.vis"));
	}

	#[test]
	fn authenticated_no_role_blocked() {
		let out = filter_sections(input(), auth_no_role());
		assert!(!out.contains_key("links"));
		assert!(!out.contains_key("links.vis"));
		assert_eq!(out.get("sections").map(String::as_str), Some("about"));
	}

	#[test]
	fn contributor_sees_all_entries_unchanged() {
		let out = filter_sections(input(), auth_role(CommunityRole::Contributor));
		assert!(out.contains_key("links"));
		assert_eq!(out.get("links.vis").map(String::as_str), Some("contributor"));
		assert!(out.contains_key("about"));
		let sections = out.get("sections").map_or("", String::as_str);
		let mut parts: Vec<&str> = sections.split(',').collect();
		parts.sort_unstable();
		assert_eq!(parts, vec!["about", "links"]);
	}

	#[test]
	fn supporter_below_contributor_is_blocked() {
		let out = filter_sections(input(), auth_role(CommunityRole::Supporter));
		assert!(!out.contains_key("links"));
		assert!(!out.contains_key("links.vis"));
		assert_eq!(out.get("sections").map(String::as_str), Some("about"));
	}

	#[test]
	fn owner_sees_everything() {
		let out = filter_sections(input(), owner());
		assert!(out.contains_key("links"));
		assert!(out.contains_key("links.vis"));
		assert!(out.contains_key("about"));
	}

	#[test]
	fn unknown_vis_label_hides_for_non_owner() {
		let mut x: HashMap<Box<str>, Box<str>> = HashMap::new();
		x.insert("secrets.vis".into(), "banana".into());
		x.insert("secrets".into(), "shh".into());
		x.insert("about".into(), "hi".into());

		let out = filter_sections(x.clone(), auth_role(CommunityRole::Leader));
		assert!(!out.contains_key("secrets"));
		assert!(!out.contains_key("secrets.vis"));
		assert!(out.contains_key("about"));

		let out_owner = filter_sections(x, owner());
		assert!(out_owner.contains_key("secrets"));
		assert!(out_owner.contains_key("secrets.vis"));
	}

	#[test]
	fn vis_marker_without_section_data_is_still_stripped() {
		let mut x: HashMap<Box<str>, Box<str>> = HashMap::new();
		x.insert("links.vis".into(), "contributor".into());
		x.insert("about".into(), "hi".into());

		let out = filter_sections(x, anon());
		assert!(!out.contains_key("links.vis"));
		assert!(out.contains_key("about"));
	}

	#[test]
	fn sections_dropped_entirely_when_all_hidden() {
		let mut x: HashMap<Box<str>, Box<str>> = HashMap::new();
		x.insert("links.vis".into(), "contributor".into());
		x.insert("sections".into(), "links".into());
		x.insert("links".into(), "{}".into());

		let out = filter_sections(x, anon());
		assert!(!out.contains_key("sections"));
		assert!(!out.contains_key("links"));
		assert!(!out.contains_key("links.vis"));
	}

	#[test]
	fn sections_with_whitespace_is_trimmed() {
		let mut x: HashMap<Box<str>, Box<str>> = HashMap::new();
		x.insert("links.vis".into(), "contributor".into());
		x.insert("sections".into(), " about , links , bio ".into());
		x.insert("links".into(), "{}".into());
		x.insert("about".into(), "a".into());
		x.insert("bio".into(), "b".into());

		let out = filter_sections(x, anon());
		let sections = out.get("sections").map_or("", String::as_str);
		let parts: Vec<&str> = sections.split(',').collect();
		assert!(parts.contains(&"about"));
		assert!(parts.contains(&"bio"));
		assert!(!parts.contains(&"links"));
	}
}

// vim: ts=4
