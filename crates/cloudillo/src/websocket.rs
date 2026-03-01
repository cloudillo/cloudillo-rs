//! WebSocket upgrade handlers
//!
//! Routes WebSocket connections to appropriate protocol handlers:
//! - `/ws/bus` - Notification bus (presence, typing, actions, events)
//! - `/ws/rtdb/:file_id` - Real-time database changes for a file
//! - `/ws/crdt/:doc_id` - Collaborative document editing

use axum::{
	extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
	extract::{Path, Query, State},
	response::Response,
};
use futures::SinkExt;
use serde::Deserialize;

use crate::crdt;
use crate::rtdb;
use cloudillo_core::extract::IdTag;
use cloudillo_core::file_access::{self, FileAccessError};
use cloudillo_core::ws_bus;
use cloudillo_core::OptionalAuth;

/// Query parameters for WebSocket file access endpoints
#[derive(Debug, Deserialize, Default)]
pub struct AccessQuery {
	/// Requested access level: "read" or "write"
	/// - "read": Force read-only mode (even if user has write permission)
	/// - "write": Require write permission (reject if user only has read)
	/// - None: Use computed access level based on permissions
	pub access: Option<String>,
}

/// Helper to close WebSocket with error code
async fn close_with_error(mut socket: WebSocket, code: u16, reason: &'static str) {
	let _ = socket
		.send(Message::Close(Some(CloseFrame { code, reason: reason.into() })))
		.await;
	let _ = socket.close().await;
}

/// Create WebSocket close response for file access errors
fn ws_close_for_error(ws: WebSocketUpgrade, error: &FileAccessError) -> Response {
	match error {
		FileAccessError::NotFound => {
			ws.on_upgrade(|socket| close_with_error(socket, 4404, "File not found"))
		}
		FileAccessError::AccessDenied => {
			ws.on_upgrade(|socket| close_with_error(socket, 4403, "Access denied"))
		}
		FileAccessError::InternalError(_) => {
			ws.on_upgrade(|socket| close_with_error(socket, 4500, "Internal error"))
		}
	}
}

/// Create WebSocket close response for unauthenticated requests
fn ws_close_unauthenticated(ws: WebSocketUpgrade) -> Response {
	ws.on_upgrade(|socket| close_with_error(socket, 4401, "Unauthorized - authentication required"))
}

/// Create WebSocket close response for insufficient write permission
fn ws_close_write_denied(ws: WebSocketUpgrade) -> Response {
	ws.on_upgrade(|socket| close_with_error(socket, 4403, "Write access denied"))
}

/// Determine final read_only flag based on query parameter and computed access
///
/// Returns `Ok(read_only)` or `Err(())` if write access was requested but not available
fn resolve_access(query: &AccessQuery, computed_read_only: bool) -> Result<bool, ()> {
	match query.access.as_deref() {
		Some("read") => Ok(true), // Force read-only
		Some("write") => {
			if computed_read_only {
				Err(()) // Write requested but user only has read
			} else {
				Ok(false)
			}
		}
		_ => Ok(computed_read_only), // Use computed access
	}
}

/// WebSocket upgrade handler for the notification bus
///
/// Requires authentication. Routes to ws_bus handler.
pub async fn get_ws_bus(
	ws: WebSocketUpgrade,
	State(app): State<crate::app::App>,
	OptionalAuth(auth): OptionalAuth,
) -> Response {
	use tracing::{debug, warn};

	debug!("WebSocket bus request");

	let Some(auth_ctx) = auth else {
		warn!("Bus WebSocket rejected - no authentication");
		return ws_close_unauthenticated(ws);
	};

	let user_id = auth_ctx.id_tag.to_string();
	let tn_id = auth_ctx.tn_id;
	debug!("Bus WebSocket authenticated: user_id={}, tn_id={}", user_id, tn_id.0);
	ws.on_upgrade(move |socket| ws_bus::handle_bus_connection(socket, user_id, tn_id, app))
}

/// WebSocket upgrade handler for RTDB subscriptions
///
/// Route: `/ws/rtdb/:file_id`
/// Query params: `?access=read` or `?access=write`
/// Requires authentication.
/// Connects to real-time database changes for a specific file.
/// Checks file access level and passes read_only flag to connection handler.
pub async fn get_ws_rtdb(
	ws: WebSocketUpgrade,
	Path(file_id): Path<String>,
	Query(query): Query<AccessQuery>,
	State(app): State<crate::app::App>,
	crate::types::TnId(tn_id): crate::types::TnId,
	IdTag(tenant_id_tag): IdTag,
	OptionalAuth(auth): OptionalAuth,
) -> Response {
	use tracing::{info, warn};

	info!("WebSocket RTDB request for file_id: {}, access={:?}", file_id, query.access);

	let Some(auth_ctx) = auth else {
		warn!("RTDB WebSocket rejected - no authentication");
		return ws_close_unauthenticated(ws);
	};

	let user_id = auth_ctx.id_tag.to_string();
	let user_tn_id = auth_ctx.tn_id;
	let user_roles = auth_ctx.roles.clone();
	let scope = auth_ctx.scope.as_deref();

	// Check file access (with scope for share links)
	let ctx = file_access::FileAccessCtx {
		user_id_tag: &user_id,
		tenant_id_tag: &tenant_id_tag,
		user_roles: &user_roles,
	};
	let access_result = file_access::check_file_access_with_scope(
		&app,
		crate::types::TnId(tn_id),
		&file_id,
		&ctx,
		scope,
	)
	.await;

	match access_result {
		Ok(result) => {
			// Resolve final read_only based on query parameter
			let Ok(read_only) = resolve_access(&query, result.read_only) else {
				warn!("RTDB WebSocket rejected - write access requested but not available: user={}, file={}", user_id, file_id);
				return ws_close_write_denied(ws);
			};
			info!(
				"RTDB WebSocket ({}): user={}, file={}",
				if read_only { "read-only" } else { "read-write" },
				user_id,
				file_id
			);
			ws.on_upgrade(move |socket| {
				rtdb::handle_rtdb_connection(socket, user_id, file_id, app, user_tn_id, read_only)
			})
		}
		Err(e) => {
			warn!("RTDB WebSocket rejected: user={}, file={}", user_id, file_id);
			ws_close_for_error(ws, &e)
		}
	}
}

/// WebSocket upgrade handler for CRDT documents
///
/// Route: `/ws/crdt/:doc_id`
/// Query params: `?access=read` or `?access=write`
/// Requires authentication.
/// Checks file access level and passes read_only flag to connection handler.
pub async fn get_ws_crdt(
	ws: WebSocketUpgrade,
	Path(doc_id): Path<String>,
	Query(query): Query<AccessQuery>,
	State(app): State<crate::app::App>,
	crate::types::TnId(tn_id): crate::types::TnId,
	IdTag(tenant_id_tag): IdTag,
	OptionalAuth(auth): OptionalAuth,
) -> Response {
	use tracing::{info, warn};

	info!("WebSocket CRDT request for doc_id: {}, access={:?}", doc_id, query.access);

	let Some(auth_ctx) = auth else {
		warn!("CRDT WebSocket rejected - no authentication");
		return ws_close_unauthenticated(ws);
	};

	let user_id = auth_ctx.id_tag.to_string();
	let user_tn_id = auth_ctx.tn_id;
	let user_roles = auth_ctx.roles.clone();
	let scope = auth_ctx.scope.as_deref();

	// Check file access (with scope for share links)
	let ctx = file_access::FileAccessCtx {
		user_id_tag: &user_id,
		tenant_id_tag: &tenant_id_tag,
		user_roles: &user_roles,
	};
	let access_result = file_access::check_file_access_with_scope(
		&app,
		crate::types::TnId(tn_id),
		&doc_id,
		&ctx,
		scope,
	)
	.await;

	match access_result {
		Ok(result) => {
			// Resolve final read_only based on query parameter
			let Ok(read_only) = resolve_access(&query, result.read_only) else {
				warn!("CRDT WebSocket rejected - write access requested but not available: user={}, doc={}", user_id, doc_id);
				return ws_close_write_denied(ws);
			};
			info!(
				"CRDT WebSocket ({}): user={}, doc={}",
				if read_only { "read-only" } else { "read-write" },
				user_id,
				doc_id
			);
			ws.on_upgrade(move |socket| {
				crdt::handle_crdt_connection(socket, user_id, doc_id, app, user_tn_id, read_only)
			})
		}
		Err(e) => {
			warn!("CRDT WebSocket rejected: user={}, doc={}", user_id, doc_id);
			ws_close_for_error(ws, &e)
		}
	}
}

// vim: ts=4
