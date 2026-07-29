// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! `/ws/**` — the WebSocket upgrade endpoints.
//!
//! **API domain only.** Mounted at exactly one place — `routes/public.rs`,
//! under `RateLimitLayer(bucket "websocket")` — so connection-exhaustion
//! protection cannot be bypassed by picking another hostname.
//!
//! Clients must therefore always target the instance API domain,
//! `wss://cl-o.{idTag}`, never their own origin. Sandboxed apps run in iframes
//! served from the *app* domain, so a same-origin fallback would land on a
//! hostname that no longer serves `/ws/*`. The frontend helper `getDocWsUrl`
//! (`libs/core/src/urls.ts` in the `cloudillo` repo) encodes this: a document
//! with no owner tag is owned by the viewer, so it resolves to the viewer's own
//! instance rather than to `window.location.host`.
//!
//! No method matrix: every route is `any(..)` (a WebSocket upgrade is a `GET`
//! with headers, and the handlers do their own protocol negotiation) under one
//! guard at one mount.

use axum::{Router, routing::any};

use crate::prelude::*;
use crate::websocket::{get_ws_bus, get_ws_crdt, get_ws_rtdb};

/// The three WebSocket upgrade endpoints, mounted only on the API domain under
/// the `"websocket"` rate-limit bucket (`routes/public.rs`).
pub(crate) fn all() -> Router<App> {
	Router::new()
		.route("/ws/bus", any(get_ws_bus))
		.route("/ws/rtdb/{file_id}", any(get_ws_rtdb))
		.route("/ws/crdt/{doc_id}", any(get_ws_crdt))
}

// vim: ts=4
