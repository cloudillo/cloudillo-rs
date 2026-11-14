// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Compatibility suite: frozen per-release corpora that every later release must still honour.
//!
//! - `tokens`: the golden action-token corpus (`corpus/<version>/tokens/`).
//! - `snapshots`: response snapshots of remote-facing endpoints (`corpus/<version>/snapshots/`).
//! - `static_checks`: source scans, e.g. no `deny_unknown_fields` outside an allowlist.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod server;
mod snapshots;
mod static_checks;
mod tokens;
