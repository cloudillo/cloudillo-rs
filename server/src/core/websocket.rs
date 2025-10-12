//! Websocket bus implementations

use crate::prelude::*;
use axum::{
	extract::{
		Path,
		State,
		ws::{Message as WsMessage, WebSocketUpgrade, WebSocket},
	},
	response::Response,
};

//pub async fn get_ws_bus(ws: WebSocketUpgrade, State(app): State<App>) -> Response {
pub async fn get_ws_bus(ws: WebSocketUpgrade) -> Response {
	info!("GET ws bus");
	ws.on_upgrade(move |ws| handle_ws_bus(ws))
}

async fn handle_ws_bus(mut ws: WebSocket) {
	info!("Websocket upgraded");
	while let Some(msg) = ws.recv().await {
		let msg = if let Ok(msg) = msg {
			msg
		} else {
			info!("Websocket error 1");
			return;
		};

		if ws.send(msg).await.is_err() {
			info!("Websocket error 2");
			return;
		}
	}
}

/*
async fn handle_ws_bus(mut ws: WebSocket, app: App) {
	info!("Websocket upgraded");
	while let Some(msg) = ws.recv().await {
		let msg = if let Ok(msg) = msg {
			msg
		} else {
			info!("Websocket error 1");
			return;
		};

		if ws.send(msg).await.is_err() {
			info!("Websocket error 2");
			return;
		}
	}
}
*/

pub async fn get_ws_doc(ws: WebSocketUpgrade, Path(doc_id): Path<String>, State(state): State<App>) -> ClResult<()> {
	ws.on_upgrade(async move |socket| {
		info!("Websocket upgrade");
	});

	Ok(())
}

// vim: ts=4
