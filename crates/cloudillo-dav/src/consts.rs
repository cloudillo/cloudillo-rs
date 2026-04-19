// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! XML namespace URIs used by WebDAV, CardDAV, and common extensions.

/// Core WebDAV namespace (RFC 4918).
pub const NS_DAV: &str = "DAV:";

/// CardDAV namespace (RFC 6352).
pub const NS_CARDDAV: &str = "urn:ietf:params:xml:ns:carddav";

/// CalDAV namespace (RFC 4791) — reserved for future use.
pub const NS_CALDAV: &str = "urn:ietf:params:xml:ns:caldav";

/// Apple Calendar Server namespace — source of the widely-used `getctag` property.
pub const NS_CALSERVER: &str = "http://calendarserver.org/ns/";

// vim: ts=4
