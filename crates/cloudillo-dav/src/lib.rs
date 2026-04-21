// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Shared WebDAV protocol layer used by CardDAV today and CalDAV later.
//!
//! Scope (deliberately narrow): just the plumbing that's reused across feature crates.
//! Everything CardDAV-specific — principal URL, addressbook-home-set, collection listing —
//! lives in `cloudillo-contact::carddav`.

pub mod auth;
pub mod consts;
pub mod http;
pub mod multistatus;
pub mod propfind;
mod propfind_util;
pub mod report;

pub use auth::{dav_basic_auth, has_scope};
pub use consts::{NS_CALDAV, NS_CALSERVER, NS_CARDDAV, NS_DAV};
pub use http::{etag_header, plain_error, unquote_etag, urldecode_path, urlencode_path};
pub use multistatus::{
	MultiResponse, PropStat, escape as escape_xml, render as render_multistatus,
};
pub use propfind::{PropName, Propfind};
pub use report::{CalendarQueryReport, MultigetReport, Report, SyncCollectionReport};

// vim: ts=4
