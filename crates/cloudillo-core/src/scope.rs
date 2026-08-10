// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Central, fail-closed scope enforcement for scoped credentials.
//!
//! Two unrelated credential families carry a `scope` string:
//!
//! - **Delegated tokens** — share links (`file:{file_id}:{R|C|W}`) and app
//!   publishing (`apkg:publish`), parsed by
//!   [`cloudillo_types::types::TokenScope`].
//! - **Capability scopes** — the comma-separated `carddav:*` / `caldav:*` list a
//!   user types into the `scopes` field of `POST /api/auth/api-keys`.
//!
//! [`scope_permits`] is the single decision point for both, called from
//! `crate::middleware::require_auth` on every protected request.

use axum::http::Method;
use cloudillo_types::types::TokenScope;

/// Returns `true` iff `scopes` (comma-separated) contains an exact-match token for `needed`.
/// Whitespace around each token is trimmed.
pub fn has_scope(scopes: &str, needed: &str) -> bool {
	scopes.split(',').map(str::trim).any(|s| s == needed)
}

/// REST equivalents of the `/dav/*` surface that `cloudillo_dav::auth::dav_basic_auth`
/// guards, so one `carddav:*` / `caldav:*` key means the same thing on both.
const CARDDAV_PREFIXES: &[&str] = &["/api/address-books", "/api/contacts"];
const CALDAV_PREFIXES: &[&str] = &["/api/calendars"];

/// Whether `path` is the `prefix` collection itself or a resource inside it.
/// Segment-aware: `/api/contacts` matches `/api/contacts` and `/api/contacts/x`,
/// but not `/api/contacts-export`.
fn path_in_family(path: &str, prefix: &str) -> bool {
	path == prefix || path.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/'))
}

fn is_read_method(method: &Method) -> bool {
	matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Whether the capability list `scopes` covers `method` for a `prefix`-family
/// path. Write methods imply read, mirroring `cloudillo_dav::auth::required_scopes`.
fn capability_permits(scopes: &str, method: &Method, prefix: &str) -> bool {
	let read = format!("{prefix}:read");
	if !has_scope(scopes, &read) {
		return false;
	}
	is_read_method(method) || has_scope(scopes, &format!("{prefix}:write"))
}

/// Whether a credential carrying `scope` may perform `method` on `path`.
///
/// **Fails closed**: an unrecognised scope string grants nothing, anywhere. Tenant
/// API keys are minted with the full tenant-owner role set regardless of their
/// `scopes` column, so "unrecognised" must never degrade to "unrestricted".
///
/// `None` means an unscoped credential — unrestricted here, gated by roles/ABAC
/// instead. `validate_api_key` normalises a blank `scopes` column to `None`; a blank
/// string arriving anyway is a capability list with no capabilities, and grants nothing.
pub fn scope_permits(scope: Option<&str>, method: &Method, path: &str) -> bool {
	let Some(scope) = scope else {
		return true;
	};

	match TokenScope::parse(scope) {
		Some(TokenScope::File { .. }) => {
			path.starts_with("/api/files/")
				|| path == "/api/files"
				// Document-scoped full-text search: an app (or share-link guest)
				// searching inside the one document it was handed; the handler
				// confines results to that document's tree and to file/document
				// rows. `/api/doc-formats` is deliberately NOT here — registering
				// index rules is shell-mediated, out of reach of app credentials.
				|| path == "/api/search"
				|| path.starts_with("/ws/rtdb/")
				|| path.starts_with("/ws/crdt/")
				// Reachable for the `?via=` cross-document re-scoping branch, which takes
				// a scoped bearer; the bare branch rejects scoped tokens in the handler.
				|| path == "/api/auth/access-token"
		}
		// Deliberately narrow: only what app publishing needs, to limit the blast
		// radius of a compromised token.
		Some(TokenScope::ApkgPublish) => {
			path.starts_with("/api/files/apkg/")
				|| (path == "/api/actions" && method == Method::POST)
				|| path.starts_with("/api/apps")
		}
		// Not a delegated token — treat it as a capability list.
		None => {
			if CARDDAV_PREFIXES.iter().any(|p| path_in_family(path, p)) {
				capability_permits(scope, method, "carddav")
			} else if CALDAV_PREFIXES.iter().any(|p| path_in_family(path, p)) {
				capability_permits(scope, method, "caldav")
			} else {
				false
			}
		}
	}
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
	fn unscoped_is_unrestricted() {
		for path in ["/api/files/x", "/api/idp/identities", "/api/settings/foo", "/api/anything"] {
			assert!(scope_permits(None, &Method::GET, path));
			assert!(scope_permits(None, &Method::POST, path));
		}
	}

	#[test]
	fn blank_scope_string_grants_nothing() {
		// `validate_api_key` normalises blank to `None` upstream, so a blank string
		// arriving here is a capability list with no capabilities, not "unrestricted".
		for path in ["/api/files/x", "/api/address-books", "/api/idp/identities", "/api/anything"] {
			assert!(!scope_permits(Some(""), &Method::GET, path));
			assert!(!scope_permits(Some("  "), &Method::POST, path));
		}
	}

	#[test]
	fn file_scope_stays_on_the_file_surface() {
		let s = Some("file:f1~abc:W");
		assert!(scope_permits(s, &Method::GET, "/api/files/x"));
		assert!(scope_permits(s, &Method::GET, "/api/files"));
		assert!(scope_permits(s, &Method::GET, "/ws/crdt/f1~abc"));
		// Must stay reachable for `?via=`; rejecting the bare branch is the handler's job.
		assert!(scope_permits(s, &Method::POST, "/api/auth/access-token"));
		// In-document search: the handler confines results to the scoped tree.
		assert!(scope_permits(s, &Method::GET, "/api/search"));
		// ...but the whitelist is an exact match, so the sibling rebuild route
		// (owner/leader only) is not delegable to a file-scoped token.
		assert!(!scope_permits(s, &Method::POST, "/api/search/reindex"));

		assert!(!scope_permits(s, &Method::POST, "/api/idp/identities"));
		assert!(!scope_permits(s, &Method::PUT, "/api/settings/foo"));
		assert!(!scope_permits(s, &Method::GET, "/api/auth/proxy-token"));
		// Claiming a document type is never delegable to an app's own token.
		assert!(!scope_permits(s, &Method::GET, "/api/doc-formats"));
		assert!(!scope_permits(s, &Method::PUT, "/api/doc-formats/cloudillo%2Fnotillo"));
	}

	#[test]
	fn apkg_scope_stays_on_the_publish_surface() {
		let s = Some("apkg:publish");
		assert!(scope_permits(s, &Method::POST, "/api/files/apkg/upload"));
		assert!(scope_permits(s, &Method::POST, "/api/actions"));
		assert!(!scope_permits(s, &Method::GET, "/api/actions"));
		assert!(scope_permits(s, &Method::GET, "/api/apps/installed"));
		assert!(!scope_permits(s, &Method::POST, "/api/idp/identities"));
	}

	#[test]
	fn carddav_read_is_read_only_and_carddav_only() {
		let s = Some("carddav:read");
		assert!(scope_permits(s, &Method::GET, "/api/address-books"));
		assert!(scope_permits(s, &Method::GET, "/api/contacts"));
		assert!(!scope_permits(s, &Method::POST, "/api/address-books"));
		assert!(!scope_permits(s, &Method::GET, "/api/calendars"));

		// A DAV-scoped key must not reach tenant management APIs.
		assert!(!scope_permits(s, &Method::POST, "/api/idp/identities"));
		assert!(!scope_permits(s, &Method::PUT, "/api/settings/idp.enabled"));
		assert!(!scope_permits(s, &Method::GET, "/api/auth/api-keys"));
	}

	#[test]
	fn carddav_write_permits_mutations() {
		// A capability-scoped key must still reach its own surface.
		let s = Some("carddav:read,carddav:write");
		assert!(scope_permits(s, &Method::GET, "/api/address-books"));
		assert!(scope_permits(s, &Method::POST, "/api/address-books"));
		assert!(scope_permits(s, &Method::PUT, "/api/address-books/ab1/contacts/u1"));
		assert!(!scope_permits(s, &Method::POST, "/api/calendars"));
		assert!(!scope_permits(s, &Method::POST, "/api/idp/identities"));
	}

	#[test]
	fn caldav_scope_stays_on_the_calendar_surface() {
		let s = Some("caldav:read");
		assert!(scope_permits(s, &Method::GET, "/api/calendars/x/objects"));
		assert!(!scope_permits(s, &Method::POST, "/api/calendars/x/objects"));
		assert!(!scope_permits(s, &Method::GET, "/api/address-books"));
	}

	#[test]
	fn prefix_matching_is_segment_aware() {
		let s = Some("carddav:read");
		// The collection itself and resources inside it.
		assert!(scope_permits(s, &Method::GET, "/api/contacts"));
		assert!(scope_permits(s, &Method::GET, "/api/contacts/x"));
		// A sibling route that merely shares a textual prefix is not in the family.
		assert!(!scope_permits(s, &Method::GET, "/api/contacts-export"));
		assert!(!scope_permits(s, &Method::GET, "/api/address-books-admin"));
	}

	#[test]
	fn unrecognised_scope_grants_nothing() {
		for s in ["admin", "nonsense", "carddav", "read"] {
			for path in [
				"/api/address-books",
				"/api/calendars",
				"/api/contacts",
				"/api/files/x",
				"/api/idp/identities",
				"/api/settings/foo",
				"/",
			] {
				assert!(!scope_permits(Some(s), &Method::GET, path), "{s} on {path}");
				assert!(!scope_permits(Some(s), &Method::POST, path), "{s} on {path}");
			}
		}
	}
}

// vim: ts=4
