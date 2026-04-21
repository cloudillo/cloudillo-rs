// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! HTTP Basic auth middleware that accepts a scoped API token as the "password".
//!
//! CardDAV clients cache the password indefinitely (often in plaintext on disk), so we must
//! never accept the user's real login credentials here. Instead, the user generates an API
//! key via `POST /api/auth/api-keys` with `"scopes": "carddav:read"` or
//! `"scopes": "carddav:read,carddav:write"` (comma-separated) and pastes the returned token
//! into their DAV client as the password.
//!
//! The middleware:
//! 1. Reads `Authorization: Basic base64(anything:token)`
//! 2. Ignores the username field — DAV clients use it inconsistently, and the token is
//!    already a self-identifying credential. The token alone is authoritative.
//! 3. Validates the token via `auth_adapter.validate_api_key(token)`
//! 4. Verifies the key's tenant matches the Host-derived tenant (per the bearer-auth pattern
//!    in `cloudillo_core::middleware::require_auth`) — prevents using a token issued for
//!    one tenant against another tenant's `cl-o.*` domain on a multi-tenant server.
//! 5. Checks the required scope for the HTTP method.
//! 6. Injects `Auth(AuthCtx)` into the request extensions, matching the bearer-token path.

use axum::{
	body::Body,
	extract::State,
	http::{HeaderValue, Method, Request, Response, StatusCode, header},
	middleware::Next,
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};

use cloudillo_core::{App, extract::Auth};
use cloudillo_types::{auth_adapter::AuthCtx, extract::IdTag, prelude::*};

/// Returns `true` iff `scopes` (comma-separated) contains an exact-match token for `needed`.
/// Whitespace around each token is trimmed.
pub fn has_scope(scopes: &str, needed: &str) -> bool {
	scopes.split(',').map(str::trim).any(|s| s == needed)
}

/// What the token must satisfy. `AllOf` requires every scope (the read+write pattern);
/// `AnyOf` is used for the shared principal path where either `carddav:read` OR `caldav:read`
/// lets a DAV client discover collection URIs.
#[derive(Debug, Clone)]
enum Required {
	AllOf(&'static [&'static str]),
	AnyOf(&'static [&'static str]),
}

impl Required {
	fn satisfied_by(&self, scopes: &str) -> bool {
		match self {
			Self::AllOf(needed) => needed.iter().all(|s| has_scope(scopes, s)),
			Self::AnyOf(needed) => needed.iter().any(|s| has_scope(scopes, s)),
		}
	}

	fn as_slice(&self) -> &'static [&'static str] {
		match self {
			Self::AllOf(s) | Self::AnyOf(s) => s,
		}
	}
}

/// Derive the scope prefix from the URL path. `None` = shared DAV path (principal discovery
/// or `.well-known`) that accepts any DAV read scope.
fn resource_scope_prefix(path: &str) -> Option<&'static str> {
	if path.starts_with("/dav/calendars/") {
		Some("caldav")
	} else if path.starts_with("/dav/addressbooks/") {
		Some("carddav")
	} else {
		None
	}
}

/// Returns the scope(s) required for a given request. PROPFIND / REPORT / MKCOL aren't in
/// `axum::http::Method`'s canonical set but flow through as ext methods, so we match on
/// method name strings. Write methods imply read; the principal path is any-of.
fn required_scopes(method: &Method, path: &str) -> Required {
	let is_read = matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS" | "PROPFIND" | "REPORT");
	match (resource_scope_prefix(path), is_read) {
		(Some("caldav"), true) => Required::AllOf(&["caldav:read"]),
		(Some("caldav"), false) => Required::AllOf(&["caldav:read", "caldav:write"]),
		// Everything else with an explicit prefix: default to carddav (matches the pre-CalDAV
		// status quo for any path like `/dav/addressbooks/...`).
		(Some(_), true) => Required::AllOf(&["carddav:read"]),
		(Some(_), false) => Required::AllOf(&["carddav:read", "carddav:write"]),
		(None, true) => Required::AnyOf(&["carddav:read", "caldav:read"]),
		(None, false) => Required::AnyOf(&["carddav:write", "caldav:write"]),
	}
}

fn unauthorized() -> Response<Body> {
	let mut resp = Response::new(Body::from("Unauthorized"));
	*resp.status_mut() = StatusCode::UNAUTHORIZED;
	resp.headers_mut().insert(
		header::WWW_AUTHENTICATE,
		HeaderValue::from_static(r#"Basic realm="Cloudillo DAV""#),
	);
	resp
}

fn forbidden() -> Response<Body> {
	let mut resp = Response::new(Body::from("Forbidden: token lacks required scope"));
	*resp.status_mut() = StatusCode::FORBIDDEN;
	resp
}

/// Middleware body: validates the Basic-auth API token, checks scopes, and injects
/// `Auth(AuthCtx)` into extensions so downstream extractors work unchanged.
pub async fn dav_basic_auth(
	State(app): State<App>,
	mut req: Request<Body>,
	next: Next,
) -> Response<Body> {
	// Extract Authorization header.
	let Some(auth_header) = req.headers().get(header::AUTHORIZATION).and_then(|h| h.to_str().ok())
	else {
		return unauthorized();
	};
	let Some(b64) = auth_header.strip_prefix("Basic ").map(str::trim) else {
		return unauthorized();
	};

	// Decode "anything:password". We ignore the username — DAV clients use it inconsistently
	// (some put idTag, some put the user's email, some put their OS account name) and the
	// token alone is a self-identifying credential. Tenant binding is enforced below.
	let Ok(decoded) = B64.decode(b64) else {
		return unauthorized();
	};
	let Ok(pair) = std::str::from_utf8(&decoded) else {
		return unauthorized();
	};
	let Some((_user, password)) = pair.split_once(':') else {
		return unauthorized();
	};
	if password.is_empty() {
		return unauthorized();
	}

	// Validate the API token.
	let Ok(validation) = app.auth_adapter.validate_api_key(password).await else {
		warn!("DAV: API key validation failed");
		return unauthorized();
	};

	// Tenant binding: the token's tenant must match the Host-derived tenant. Without this,
	// a token issued on a multi-tenant server for user Bob would work against user Alice's
	// `cl-o.alice/dav/...` URL — the client-facing principal would say Alice, but the data
	// access would silently operate on Bob's tenant.
	let Some(host_id_tag) = req.extensions().get::<IdTag>().cloned() else {
		warn!("DAV: IdTag not present in request extensions (webserver misconfigured?)");
		return unauthorized();
	};
	let Ok(host_tn_id) = app.auth_adapter.read_tn_id(&host_id_tag.0).await else {
		warn!("DAV: unknown tenant for Host '{}'", host_id_tag.0);
		return unauthorized();
	};
	if validation.tn_id != host_tn_id {
		warn!(
			"DAV: token tenant {:?} doesn't match Host tenant {:?} (host idTag '{}')",
			validation.tn_id, host_tn_id, host_id_tag.0
		);
		return unauthorized();
	}

	// Scope check — path-aware so the same middleware covers CardDAV + CalDAV + principal.
	let scopes = validation.scopes.as_deref().unwrap_or("");
	let needed = required_scopes(req.method(), req.uri().path());
	if !needed.satisfied_by(scopes) {
		warn!(
			"DAV: token for {} lacks required scope(s) {:?} (has: {:?})",
			validation.id_tag,
			needed.as_slice(),
			scopes
		);
		return forbidden();
	}

	// Build the same AuthCtx as the bearer-token middleware.
	let ctx = AuthCtx {
		tn_id: validation.tn_id,
		id_tag: validation.id_tag,
		roles: validation
			.roles
			.map(|r| r.split(',').map(Box::from).collect())
			.unwrap_or_default(),
		scope: validation.scopes,
	};
	req.extensions_mut().insert(Auth(ctx));

	next.run(req).await
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn has_scope_exact_match_only() {
		assert!(has_scope("carddav:read", "carddav:read"));
		assert!(has_scope("carddav:read,carddav:write", "carddav:read"));
		assert!(has_scope("carddav:read, carddav:write", "carddav:write"));
		assert!(has_scope("other,carddav:write", "carddav:write"));
		assert!(!has_scope("carddav:reader", "carddav:read"));
		assert!(!has_scope("", "carddav:read"));
		assert!(!has_scope("carddav", "carddav:read"));
		// Space-separation is NOT accepted — use commas.
		assert!(!has_scope("carddav:read carddav:write", "carddav:read"));
	}

	#[test]
	fn required_scopes_carddav_path() {
		let get = required_scopes(&Method::GET, "/dav/addressbooks/Contacts/");
		assert_eq!(get.as_slice(), &["carddav:read"]);
		assert!(get.satisfied_by("carddav:read"));

		let put = required_scopes(&Method::PUT, "/dav/addressbooks/Contacts/abc.vcf");
		assert_eq!(put.as_slice(), &["carddav:read", "carddav:write"]);
		assert!(put.satisfied_by("carddav:read,carddav:write"));
		assert!(!put.satisfied_by("carddav:read"));

		let propfind =
			required_scopes(&Method::from_bytes(b"PROPFIND").unwrap(), "/dav/addressbooks/");
		assert_eq!(propfind.as_slice(), &["carddav:read"]);
	}

	#[test]
	fn required_scopes_caldav_path() {
		let get = required_scopes(&Method::GET, "/dav/calendars/Default/");
		assert_eq!(get.as_slice(), &["caldav:read"]);

		let put = required_scopes(&Method::PUT, "/dav/calendars/Default/abc.ics");
		assert_eq!(put.as_slice(), &["caldav:read", "caldav:write"]);
		assert!(put.satisfied_by("caldav:read,caldav:write"));

		// A carddav-only token must NOT be accepted on a calendars path.
		assert!(!put.satisfied_by("carddav:read,carddav:write"));
	}

	#[test]
	fn required_scopes_principal_accepts_either() {
		let get = required_scopes(&Method::GET, "/dav/principal/");
		assert!(matches!(get, Required::AnyOf(_)));
		// Either scope on its own discovers principal + home-sets.
		assert!(get.satisfied_by("carddav:read"));
		assert!(get.satisfied_by("caldav:read"));
		assert!(!get.satisfied_by("other:read"));
	}
}

// vim: ts=4
