//! WebSocket upgrade handlers
//!
//! Routes WebSocket connections to appropriate protocol handlers:
//! - `/ws/bus` - Notification bus (presence, typing, actions, events)
//! - `/ws/rtdb/:file_id` - Real-time database changes for a file
//! - `/ws/crdt/:doc_id` - Collaborative document editing

use crate::core::extract::OptionalAuth;
use crate::core::ws_bus;
use crate::crdt;
use crate::rtdb;
use axum::{
	extract::{Path, State},
	response::{Response, IntoResponse},
	extract::ws::WebSocketUpgrade,
	http::StatusCode,
};

/// WebSocket upgrade handler for the notification bus
///
/// Requires authentication. Routes to ws_bus handler.
pub async fn get_ws_bus(
	ws: WebSocketUpgrade,
	State(app): State<crate::core::app::App>,
	OptionalAuth(auth): OptionalAuth,
) -> Response {
	use tracing::{info, warn};

	info!("WebSocket bus request");

	match auth {
		Some(auth_ctx) => {
			let user_id = auth_ctx.id_tag.to_string();
			info!("Bus WebSocket authenticated: user_id={}", user_id);
			ws.on_upgrade(move |socket| {
				ws_bus::handle_bus_connection(socket, user_id, app)
			})
		}
		None => {
			warn!("Bus WebSocket rejected - no authentication");
			// Return 401 Unauthorized for WebSocket
			StatusCode::UNAUTHORIZED.into_response()
		}
	}
}

/// WebSocket upgrade handler for RTDB subscriptions
///
/// Route: `/ws/rtdb/:file_id`
/// Requires authentication.
/// Connects to real-time database changes for a specific file.
pub async fn get_ws_rtdb(
	ws: WebSocketUpgrade,
	Path(file_id): Path<String>,
	State(app): State<crate::core::app::App>,
	OptionalAuth(auth): OptionalAuth,
) -> Response {
	use tracing::{info, warn};

	info!("WebSocket RTDB request for file_id: {}", file_id);

	match auth {
		Some(auth_ctx) => {
			let user_id = auth_ctx.id_tag.to_string();
			let tn_id = auth_ctx.tn_id;
			info!("RTDB WebSocket authenticated: user_id={}, tn_id={}", user_id, tn_id.0);
			ws.on_upgrade(move |socket| {
				rtdb::handle_rtdb_connection(socket, user_id, file_id, app, tn_id)
			})
		}
		None => {
			warn!("RTDB WebSocket rejected - no authentication");
			StatusCode::UNAUTHORIZED.into_response()
		}
	}
}

/// WebSocket upgrade handler for CRDT documents
///
/// Route: `/ws/crdt/:doc_id`
/// Requires authentication.
pub async fn get_ws_crdt(
	ws: WebSocketUpgrade,
	Path(doc_id): Path<String>,
	State(app): State<crate::core::app::App>,
	OptionalAuth(auth): OptionalAuth,
) -> Response {
	match auth {
		Some(auth_ctx) => {
			let user_id = auth_ctx.id_tag.to_string();
			let tn_id = auth_ctx.tn_id;
			ws.on_upgrade(move |socket| {
				crdt::handle_crdt_connection(socket, user_id, doc_id, app, tn_id)
			})
		}
		None => StatusCode::UNAUTHORIZED.into_response(),
	}
}

// vim: ts=4
