// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! `/api/actions/**`, `/api/inbox*`, `/api/outbox`, `/api/read-marker`.
//!
//! ## Method matrix
//!
//! | Path | GET | POST | PUT | PATCH | DELETE |
//! |---|---|---|---|---|---|
//! | `/api/actions`                        | `list_public()` ᴳ | `create()` ᶜ | | | |
//! | `/api/actions/{action_id}`            | `read()` ᴬ | | | `write()` ᶜ | `write()` ᶜ |
//! | `/api/actions/{action_id}/publish`    | | `write()` ᶜ | | | |
//! | `/api/actions/{action_id}/cancel`     | | `write()` ᶜ | | | |
//! | `/api/actions/{action_id}/accept`     | | `write()` ᶜ | | | |
//! | `/api/actions/{action_id}/reject`     | | `write()` ᶜ | | | |
//! | `/api/actions/{action_id}/dismiss`    | | `write()` ᶜ | | | |
//! | `/api/actions/{action_id}/subscribe`  | | | `reader_state()` ᴱ | | |
//! | `/api/read-marker`                    | | | `reader_state()` ᴱ | | |
//! | `/api/outbox`                         | `reader_state()` ᴱ | | | | |
//! | `/api/inbox`                          | | `inbox()` ᶠ | | | |
//! | `/api/inbox/sync`                     | | `inbox()` ᶠ | | | |
//!
//! ᴬ public surface (`optional_auth`) but ABAC-guarded, ᴳ public + rate-limited
//! only, ᶠ public under the `"federation"` bucket + a raised body limit,
//! ᶜ auth + ABAC, ᴱ auth only — handler self-enforces. The guard on each fn is
//! in `routes/protected.rs` / `routes/public.rs`.
//!
//! `/api/actions/{action_id}` spans two guards: `GET` is a public ABAC read,
//! `PATCH`/`DELETE` are protected ABAC writes. They cannot be chained.

use axum::{
	Router,
	routing::{delete, get, post, put},
};

use crate::prelude::*;
use cloudillo_action::handler;

/// Action creation, gated by `check_perm_create("action", "create")` for
/// quota/tier checking. Collection-level — `check_perm_create` takes no `Path`.
pub(crate) fn create() -> Router<App> {
	Router::new().route("/api/actions", post(handler::post_action))
}

/// Action mutation and moderation, gated by `check_perm_action("write")`.
///
/// Every route here **must** capture the action id as `{action_id}` — the guard
/// reads it by name. Other captures are ignored.
pub(crate) fn write() -> Router<App> {
	Router::new()
		.route(
			"/api/actions/{action_id}",
			delete(handler::delete_action).patch(handler::patch_action),
		)
		.route("/api/actions/{action_id}/publish", post(handler::publish_draft))
		.route("/api/actions/{action_id}/cancel", post(handler::cancel_scheduled))
		.route("/api/actions/{action_id}/accept", post(handler::post_action_accept))
		.route("/api/actions/{action_id}/reject", post(handler::post_action_reject))
		.route("/api/actions/{action_id}/dismiss", post(handler::post_action_dismiss))
}

/// The reader's own state — authentication only, no ABAC guard.
///
/// - read markers: the reader's own node, forward-only;
/// - thread subscription level: the reader's own cached row;
/// - `/api/outbox`: federation history sync (peer-initiated pull). Auth is
///   enforced by the `Auth` extractor; non-related peers are rejected with an
///   empty list inside the handler before any action query runs.
pub(crate) fn reader_state() -> Router<App> {
	Router::new()
		.route("/api/read-marker", put(handler::put_read_marker))
		.route("/api/actions/{action_id}/subscribe", put(handler::put_action_subscribe))
		.route("/api/outbox", get(handler::get_outbox))
}

/// Action reads, gated by `check_perm_action("read")` with a guest
/// (OptionalAuth) context. Every route here must capture the action id as
/// `{action_id}`.
pub(crate) fn read() -> Router<App> {
	Router::new().route("/api/actions/{action_id}", get(handler::get_action_by_id))
}

/// Federation inbox — unauthenticated peers POST signed action tokens.
///
/// Attack surface: spam, malicious payloads, resource exhaustion. Mounted under
/// `upload_body_limit()` then the `"federation"` bucket: payloads carry signed
/// action tokens plus their related tokens, and a thread backfill can exceed the
/// 1 MiB global cap.
pub(crate) fn inbox() -> Router<App> {
	Router::new()
		.route("/api/inbox", post(handler::post_inbox))
		.route("/api/inbox/sync", post(handler::post_inbox_sync))
}

/// Unauthenticated action listing; visibility is checked inside the handler.
/// Mounted under the `"general"` rate-limit bucket.
pub(crate) fn list_public() -> Router<App> {
	Router::new().route("/api/actions", get(handler::list_actions))
}

// vim: ts=4
