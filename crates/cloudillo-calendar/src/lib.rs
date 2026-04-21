// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Calendar management: JSON REST API + CalDAV sync.
//!
//! The REST API is the first-class representation: server owns iCalendar generation and
//! field extraction; web clients never see or produce iCalendar text. CalDAV clients get
//! the stored VCALENDAR blob verbatim, preserving any custom properties (VALARM, VTIMEZONE,
//! custom X-* fields) across sync.

pub mod caldav;
pub mod handler;
pub mod ical;
pub mod types;

// vim: ts=4
