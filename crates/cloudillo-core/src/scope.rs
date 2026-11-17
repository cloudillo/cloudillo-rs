// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Central, fail-closed scope enforcement for scoped credentials.
//!
//! A `scope` string is a comma-separated list, parsed by
//! [`cloudillo_types::types::ScopeSet`], mixing two kinds of entry:
//!
//! - **At most one delegated entry** — share links (`file:{file_id}:{R|C|W}`), app
//!   publishing (`apkg:publish`) or a remote-context key (`rfile:{id_tag}:{root}:{R|W}`),
//!   parsed by [`cloudillo_types::types::TokenScope`].
//! - **Any number of capabilities** — `carddav:*`, `caldav:*`, `notifications:read`,
//!   `notifications:push`, as typed into the `scopes` field of `POST /api/auth/api-keys`.
//!
//! [`scope_permits`] is the single decision point, called from
//! `crate::middleware::require_auth` on every protected request. It ORs the entries;
//! a malformed list grants nothing.

use axum::http::Method;
use cloudillo_types::types::{Capability, ScopeSet, TokenScope};

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

/// One non-empty path segment (no `/`), for `{id}`-style route parameters.
fn one_segment(s: &str) -> bool {
	!s.is_empty() && !s.contains('/')
}

/// Whether `set` covers `method` for a DAV-family path whose capabilities are `read` /
/// `write`. Write methods need both, mirroring `cloudillo_dav::auth::required_scopes`.
fn capability_permits(
	set: &ScopeSet,
	method: &Method,
	read: Capability,
	write: Capability,
) -> bool {
	set.has(read) && (is_read_method(method) || set.has(write))
}

/// Whether the delegated entry `scope` reaches `method` on `path`.
fn delegated_permits(scope: &TokenScope, method: &Method, path: &str) -> bool {
	match scope {
		TokenScope::File { .. } => file_surface(method, path),
		// The file surface plus room discovery: `/api/channels` sits behind `optional_auth`,
		// which would downgrade a refused scope to anonymous. The handlers narrow.
		TokenScope::Drive { .. } => {
			file_surface(method, path) || (method == Method::GET && path == "/api/channels")
		}
		// Deliberately narrow: only what app publishing needs, to limit the blast
		// radius of a compromised token. Installing or removing apps is the leader's
		// (`require_leader`), not the publisher's.
		TokenScope::ApkgPublish => {
			path == "/api/uploads/apkg" || (path == "/api/actions" && method == Method::POST)
		}
		// Grants nothing locally: the key only brokers a scoped token from its bound context.
		TokenScope::RemoteFile { .. } => method == Method::POST && path == "/api/auth/proxy-token",
	}
}

/// The routes a file or drive scope reaches.
fn file_surface(method: &Method, path: &str) -> bool {
	path.starts_with("/api/files/")
		|| path == "/api/files"
		|| path.starts_with("/api/uploads/")
		|| path.starts_with("/api/variants/")
		// Document-scoped full-text search: an app (or share-link guest)
		// searching inside the one document it was handed; the handler
		// confines results to that document's tree and to file/document
		// rows. `/api/doc-formats` is deliberately NOT here — registering
		// index rules is shell-mediated, out of reach of app credentials.
		|| path == "/api/search"
		// Changes feed: the handler confines a scoped caller to its scope root folder.
		|| (path == "/api/file-changes" && method == Method::GET)
		|| path.starts_with("/ws/rtdb/")
		|| path.starts_with("/ws/crdt/")
		// Tenant `filesChanged` hints; `ws_file_changes_admission` narrows to scoped API keys.
		|| path == "/ws/file-changes"
		// Reachable for the `via` cross-document re-scoping branch, which takes
		// a scoped bearer; the bare branch rejects scoped tokens in the handler.
		|| path == "/api/auth/access-token"
}

/// Whether a credential carrying `scope` may perform `method` on `path`.
///
/// The entries are ORed: the delegated entry's surface, each capability's DAV family,
/// `notifications:read` → exactly `GET /api/notifications`, and `notifications:push` →
/// exactly `GET /api/notifications/vapid-key`, `POST /api/notifications/subscriptions`
/// and `DELETE /api/notifications/subscriptions/{id}`. Every valid set also reaches
/// `DELETE /api/auth/current-api-key`, so a scoped key can revoke itself.
///
/// **Fails closed**: a scope string [`ScopeSet::parse`] rejects (blank or unknown entry,
/// two delegated entries) grants nothing, anywhere. Tenant API keys are minted with the
/// full tenant-owner role set regardless of their `scopes` column, so "malformed" must
/// never degrade to "unrestricted".
///
/// `None` means an unscoped credential — unrestricted here, gated by roles/ABAC
/// instead. `validate_api_key` normalises a blank `scopes` column to `None`; a blank
/// string arriving anyway is malformed and grants nothing.
pub fn scope_permits(scope: Option<&str>, method: &Method, path: &str) -> bool {
	let Some(scope) = scope else {
		return true;
	};

	let Some(set) = ScopeSet::parse(scope) else {
		return false;
	};

	set.delegated.as_ref().is_some_and(|ts| delegated_permits(ts, method, path))
		|| (CARDDAV_PREFIXES.iter().any(|p| path_in_family(path, p))
			&& capability_permits(&set, method, Capability::CardDavRead, Capability::CardDavWrite))
		|| (CALDAV_PREFIXES.iter().any(|p| path_in_family(path, p))
			&& capability_permits(&set, method, Capability::CalDavRead, Capability::CalDavWrite))
		|| (set.has(Capability::NotificationsRead)
			&& method == Method::GET
			&& path == "/api/notifications")
		|| (set.has(Capability::NotificationsPush) && push_route(method, path))
		|| (method == Method::DELETE && path == "/api/auth/current-api-key")
}

/// The push-subscription routes `notifications:push` covers.
fn push_route(method: &Method, path: &str) -> bool {
	match *method {
		Method::GET => path == "/api/notifications/vapid-key",
		Method::POST => path == "/api/notifications/subscriptions",
		Method::DELETE => {
			path.strip_prefix("/api/notifications/subscriptions/").is_some_and(one_segment)
		}
		_ => false,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

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
		assert!(scope_permits(s, &Method::POST, "/api/uploads/standard"));
		assert!(scope_permits(s, &Method::GET, "/api/variants/b1~xyz"));
		assert!(scope_permits(s, &Method::GET, "/ws/crdt/f1~abc"));
		assert!(scope_permits(s, &Method::GET, "/ws/file-changes"));
		// Prefixes, not path stems: the bare collections are not on the file surface.
		assert!(!scope_permits(s, &Method::POST, "/api/uploads"));
		assert!(!scope_permits(s, &Method::GET, "/api/variants"));
		// Must stay reachable for `?via=`; rejecting the bare branch is the handler's job.
		assert!(scope_permits(s, &Method::POST, "/api/auth/access-token"));
		// In-document search: the handler confines results to the scoped tree.
		assert!(scope_permits(s, &Method::GET, "/api/search"));
		// ...but the whitelist is an exact match, so the sibling rebuild route
		// (owner/leader only) is not delegable to a file-scoped token.
		assert!(!scope_permits(s, &Method::POST, "/api/search/reindex"));
		// Changes feed: GET only, exact path.
		assert!(scope_permits(s, &Method::GET, "/api/file-changes"));
		assert!(!scope_permits(s, &Method::POST, "/api/file-changes"));
		assert!(!scope_permits(s, &Method::GET, "/api/file-changes/x"));

		assert!(!scope_permits(s, &Method::POST, "/api/idp/identities"));
		assert!(!scope_permits(s, &Method::PUT, "/api/settings/foo"));
		assert!(!scope_permits(s, &Method::POST, "/api/auth/proxy-token"));
		// Claiming a document type is never delegable to an app's own token.
		assert!(!scope_permits(s, &Method::GET, "/api/doc-formats"));
		assert!(!scope_permits(s, &Method::PUT, "/api/doc-formats/cloudillo%2Fnotillo"));
		// Room discovery is a drive-scope permit only.
		assert!(!scope_permits(s, &Method::GET, "/api/channels"));
	}

	#[test]
	fn drive_scope_is_file_surface_plus_channel_list() {
		for s in ["file:__root__:W", "file:~board:R", "file:*:R,notifications:read"] {
			let s = Some(s);
			for (m, p) in [
				(Method::GET, "/api/files/x"),
				(Method::GET, "/api/files"),
				(Method::POST, "/api/uploads/standard"),
				(Method::GET, "/api/variants/b1~xyz"),
				(Method::GET, "/api/search"),
				(Method::GET, "/api/file-changes"),
				(Method::GET, "/ws/crdt/f1~abc"),
				(Method::GET, "/ws/file-changes"),
				(Method::GET, "/api/channels"),
			] {
				assert!(scope_permits(s, &m, p), "{s:?} on {m} {p}");
			}
			for (m, p) in [
				(Method::POST, "/api/channels"),
				(Method::GET, "/api/channels/board"),
				(Method::POST, "/api/file-changes"),
				(Method::POST, "/api/auth/proxy-token"),
				(Method::POST, "/api/idp/identities"),
				(Method::PUT, "/api/settings/foo"),
				(Method::GET, "/api/doc-formats"),
			] {
				assert!(!scope_permits(s, &m, p), "{s:?} on {m} {p}");
			}
		}
	}

	#[test]
	fn apkg_scope_stays_on_the_publish_surface() {
		let s = Some("apkg:publish");
		assert!(scope_permits(s, &Method::POST, "/api/uploads/apkg"));
		// Exact path: neither a sub-path nor the pre-move upload path.
		assert!(!scope_permits(s, &Method::POST, "/api/uploads/apkg/x"));
		assert!(!scope_permits(s, &Method::POST, "/api/uploads/standard"));
		assert!(!scope_permits(s, &Method::POST, "/api/files/apkg/upload"));
		assert!(scope_permits(s, &Method::POST, "/api/actions"));
		assert!(!scope_permits(s, &Method::GET, "/api/actions"));
		assert!(!scope_permits(s, &Method::GET, "/api/apps/installed"));
		assert!(!scope_permits(s, &Method::POST, "/api/apps/install"));
		assert!(!scope_permits(s, &Method::POST, "/api/idp/identities"));
		assert!(!scope_permits(s, &Method::GET, "/ws/file-changes"));
	}

	#[test]
	fn notifications_push_reaches_only_the_push_routes() {
		let s = Some("notifications:push");
		assert!(scope_permits(s, &Method::GET, "/api/notifications/vapid-key"));
		assert!(scope_permits(s, &Method::POST, "/api/notifications/subscriptions"));
		assert!(scope_permits(s, &Method::DELETE, "/api/notifications/subscriptions/7"));
		// Reading the notification log takes `notifications:read`.
		assert!(!scope_permits(s, &Method::GET, "/api/notifications"));
		assert!(!scope_permits(s, &Method::POST, "/api/notifications"));
		assert!(!scope_permits(s, &Method::GET, "/api/notifications/x"));
		// Exact routes and methods only.
		assert!(!scope_permits(s, &Method::GET, "/api/notifications/subscriptions"));
		assert!(!scope_permits(s, &Method::DELETE, "/api/notifications/subscriptions"));
		assert!(!scope_permits(s, &Method::DELETE, "/api/notifications/subscriptions/"));
		assert!(!scope_permits(s, &Method::DELETE, "/api/notifications/subscriptions/7/x"));
		assert!(!scope_permits(s, &Method::POST, "/api/notifications/vapid-key"));
		assert!(!scope_permits(s, &Method::PUT, "/api/notifications/subscriptions"));
		// A capability never grants file access.
		assert!(!scope_permits(s, &Method::GET, "/api/files"));
		assert!(!scope_permits(s, &Method::POST, "/api/uploads/standard"));
	}

	#[test]
	fn device_key_is_a_file_scope_with_notification_caps() {
		let s = Some("file:f1~abc:W,notifications:read,notifications:push");
		assert!(scope_permits(s, &Method::POST, "/api/uploads/standard"));
		assert!(scope_permits(s, &Method::POST, "/api/files"));
		assert!(scope_permits(s, &Method::POST, "/api/files/f1/blob-check"));
		assert!(scope_permits(s, &Method::GET, "/api/files"));
		assert!(scope_permits(s, &Method::GET, "/api/files/f2~x"));
		assert!(scope_permits(s, &Method::GET, "/api/notifications"));
		assert!(scope_permits(s, &Method::GET, "/api/notifications/vapid-key"));
		assert!(scope_permits(s, &Method::POST, "/api/notifications/subscriptions"));
		assert!(scope_permits(s, &Method::DELETE, "/api/notifications/subscriptions/7"));

		// Nothing beyond the File surface and the two capabilities.
		for (m, p) in [
			(Method::GET, "/api/auth/api-keys"),
			(Method::POST, "/api/auth/proxy-token"),
			(Method::POST, "/api/actions"),
			(Method::POST, "/api/trash/empty"),
			(Method::POST, "/api/idp/identities"),
			(Method::PUT, "/api/settings/foo"),
			(Method::GET, "/api/contacts"),
			(Method::POST, "/api/notifications"),
		] {
			assert!(!scope_permits(s, &m, p), "{m} {p}");
		}
	}

	#[test]
	fn every_valid_scope_reaches_only_self_revoke() {
		for s in [
			"file:f1~x:R",
			"file:*:W,notifications:read,notifications:push",
			"rfile:bob.example:__root__:W",
			"carddav:read",
			"notifications:read",
		] {
			let s = Some(s);
			assert!(scope_permits(s, &Method::DELETE, "/api/auth/current-api-key"), "{s:?}");
			for (m, p) in [
				(Method::GET, "/api/auth/current-api-key"),
				(Method::DELETE, "/api/auth/api-keys/1"),
				(Method::DELETE, "/api/auth/current-api-key/x"),
				(Method::DELETE, "/api/auth/api-keys/self"),
				(Method::GET, "/api/auth/api-keys"),
			] {
				assert!(!scope_permits(s, &m, p), "{s:?} on {m} {p}");
			}
		}
		// Malformed stays fail-closed
		for s in ["", "bogus", "file:a:R,file:b:R"] {
			assert!(!scope_permits(Some(s), &Method::DELETE, "/api/auth/current-api-key"), "{s}");
		}
	}

	#[test]
	fn remote_file_scope_reaches_only_proxy_token() {
		for s in ["rfile:bob.example:f1~x:W", "rfile:bob.example:f1~x:R,notifications:read"] {
			let s = Some(s);
			assert!(scope_permits(s, &Method::POST, "/api/auth/proxy-token"));
			for (m, p) in [
				(Method::GET, "/api/auth/proxy-token"),
				(Method::POST, "/api/auth/access-token"),
				(Method::GET, "/api/files"),
				(Method::GET, "/api/files/f1~x"),
				(Method::POST, "/api/files"),
				(Method::POST, "/api/uploads/standard"),
				(Method::GET, "/api/search"),
				(Method::GET, "/ws/crdt/f1~x"),
				(Method::GET, "/api/notifications/vapid-key"),
				(Method::POST, "/api/notifications/subscriptions"),
			] {
				assert!(!scope_permits(s, &m, p), "{s:?} on {m} {p}");
			}
		}
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
	fn mixed_list_ors_its_entries() {
		let s = Some("file:f1~abc:W,notifications:read");
		assert!(scope_permits(s, &Method::GET, "/api/notifications"));
		assert!(scope_permits(s, &Method::POST, "/api/uploads/standard"));
		assert!(!scope_permits(s, &Method::POST, "/api/notifications"));
		assert!(!scope_permits(s, &Method::GET, "/api/notifications/x"));
		assert!(!scope_permits(s, &Method::GET, "/api/notifications/vapid-key"));
		assert!(!scope_permits(s, &Method::GET, "/api/contacts"));
		assert!(!scope_permits(s, &Method::GET, "/api/auth/api-keys"));

		let s = Some("file:f1~abc:W, carddav:read");
		assert!(scope_permits(s, &Method::GET, "/api/contacts"));
		assert!(scope_permits(s, &Method::GET, "/api/files"));
		assert!(!scope_permits(s, &Method::POST, "/api/contacts"));
		assert!(!scope_permits(s, &Method::GET, "/api/notifications"));
	}

	#[test]
	fn notifications_read_reaches_only_the_log() {
		let s = Some("notifications:read");
		assert!(scope_permits(s, &Method::GET, "/api/notifications"));
		assert!(!scope_permits(s, &Method::POST, "/api/notifications"));
		assert!(!scope_permits(s, &Method::GET, "/api/notifications/vapid-key"));
		assert!(!scope_permits(s, &Method::POST, "/api/notifications/subscriptions"));
		assert!(!scope_permits(s, &Method::GET, "/api/files"));
		assert!(!scope_permits(s, &Method::GET, "/api/contacts"));
	}

	#[test]
	fn malformed_list_grants_nothing() {
		// Blank entry, unknown entry, two delegated entries: each poisons the whole list,
		// including the entries that would be valid on their own.
		for s in [
			"file:f1~abc:W,",
			",notifications:read",
			"file:f1~abc:W,bogus",
			"carddav:read,carddav:reader",
			"file:f1~abc:W,file:f1~abc:R",
			"rfile:bob.example:f1~x:W,file:f1~abc:R",
			"device:f1~abc,notifications:read",
			"notifications:read,notifications:write",
		] {
			for (m, p) in [
				(Method::GET, "/api/notifications"),
				(Method::GET, "/api/contacts"),
				(Method::GET, "/api/files"),
				(Method::POST, "/api/uploads/standard"),
				(Method::GET, "/api/files/f2~x"),
				(Method::GET, "/api/anything"),
			] {
				assert!(!scope_permits(Some(s), &m, p), "{s} on {m} {p}");
			}
		}
	}

	#[test]
	fn unrecognised_scope_grants_nothing() {
		// `device:` is no longer a scope kind: every form is unknown, as are malformed
		// `rfile:` entries.
		for s in [
			"admin",
			"nonsense",
			"carddav",
			"read",
			"device",
			"device:",
			"device:a:b",
			"Device:a",
			"device:f1~abc",
			"rfile:bob.example:f1~x",
			"rfile:Bob:f1~x:W",
			"file:~Bad:W",
			"file:~x:C",
			"file:__root__:W:ref",
			"file:~:W",
		] {
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
