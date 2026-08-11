// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! WebSocket CRDT Handler - Collaborative Document Editing
//!
//! The CRDT protocol (`/ws/crdt/:doc_id`) provides real-time collaborative editing
//! using Yjs conflict-free replicated data types.
//!
//! Message Format (Binary):
//! Messages use the Yjs sync protocol format directly (lib0 encoding):
//! - MSG_SYNC (0): Sync protocol messages (SyncStep1, SyncStep2, Update)
//! - MSG_AWARENESS (1): User presence/cursor updates
//!
//! All messages are encoded/decoded using yrs::sync::Message.

use crate::prelude::*;
use axum::extract::ws::{Message, WebSocket};
use futures::sink::SinkExt;
use futures::stream::SplitSink;
use futures::stream::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::sync::Mutex;
use yrs::block::ClientID;
use yrs::sync::awareness::AwarenessUpdateEntry;
use yrs::sync::{AwarenessUpdate, Message as YMessage, SyncMessage};
use yrs::updates::decoder::Decode;
use yrs::updates::encoder::Encode;
use yrs::{Doc, Map, ReadTxn, StateVector, Transact, Update};

/// Throttle interval for access/modification tracking (60 seconds)
const TRACKING_THROTTLE_SECS: u64 = 60;

/// Convert `usize` to `f64`, accepting minor precision loss for values above 2^53.
///
/// Used for byte-size percentages where exact precision is not critical.
#[allow(clippy::cast_precision_loss)]
fn usize_to_f64(v: usize) -> f64 {
	v as f64
}

/// CRDT connection tracking
struct CrdtConnection {
	conn_id: String, // Unique connection ID (to distinguish multiple tabs from same user)
	/// Who this connection is authenticated as. `None` for an anonymous share-link
	/// visitor — there is no identity to assert on their behalf, which is what
	/// [`stamp_awareness_identity`] keys off.
	id_tag: Option<String>,
	doc_id: String,
	tn_id: TnId,
	// Broadcast channel for awareness updates (conn_id, raw_awareness_data)
	awareness_tx: Arc<tokio::sync::broadcast::Sender<(String, Vec<u8>)>>,
	// Broadcast channel for sync updates (conn_id, raw_sync_data)
	sync_tx: Arc<tokio::sync::broadcast::Sender<(String, Vec<u8>)>>,
	// Live Y.Doc kept in memory for instant state vector / diff computation
	doc: Arc<Mutex<Doc>>,
	/// Shared with every other connection on this document — see [`DocState`].
	awareness_owners: SharedAwarenessOwners,
	// User activity tracking state (throttled)
	last_access_update: Mutex<Option<Instant>>,
	last_modify_update: Mutex<Option<Instant>>,
	has_modified: AtomicBool,
}

impl CrdtConnection {
	/// The identity to log and to record file activity under. Empty for a guest.
	fn user_id(&self) -> &str {
		self.id_tag.as_deref().unwrap_or_default()
	}
}

/// Which connection owns a Yjs clientId on a document, and the highest clock seen
/// for it.
struct AwarenessOwner {
	conn_id: Box<str>,
	clock: u32,
}

/// Largest number of Yjs clientIds one connection may own on a document.
///
/// A browser tab publishes one, and a reconnecting tab briefly needs a second while the
/// old connection's [`drain_awareness_removal`] has not run yet. Anything beyond a
/// handful is a client bug or an attempt to grow this map without bound — awareness is
/// ungated by `read_only`, so a read-only share-link visitor reaches this path too.
const MAX_AWARENESS_CLIENT_IDS_PER_CONN: usize = 8;

/// Per-document map of Yjs clientId -> owning connection, plus the per-connection
/// counts that bound it.
///
/// A Yjs clientId is allocated client-side with no server-verifiable provenance, so
/// ownership is established by first publish — the protocol offers no alternative. It
/// is what lets the server tell a connection's own awareness apart from the peer states
/// it legitimately relays (see [`stamp_awareness_identity`]), and what lets the server
/// emit an awareness removal on disconnect.
///
/// Both halves are always mutated under the same lock: `claimed[c]` is the number of
/// `owners` entries whose `conn_id` is `c`, and [`drain_awareness_removal`] clears both.
///
/// Inherits the CRDT registry's bare-`doc_id` key, so two tenants sharing a file id
/// share this map along with the document — a known pre-existing flaw of the registry
/// (`cloudillo_rtdb::presence::PresenceKey` documents it from the other side).
#[derive(Default)]
struct AwarenessOwners {
	owners: HashMap<ClientID, AwarenessOwner>,
	claimed: HashMap<Box<str>, usize>,
}

type SharedAwarenessOwners = Arc<Mutex<AwarenessOwners>>;

/// Per-document state: broadcast channels + live Y.Doc
#[derive(Clone)]
struct DocState {
	awareness_tx: Arc<tokio::sync::broadcast::Sender<(String, Vec<u8>)>>,
	sync_tx: Arc<tokio::sync::broadcast::Sender<(String, Vec<u8>)>>,
	doc: Arc<Mutex<Doc>>,
	awareness_owners: SharedAwarenessOwners,
}

/// Type alias for the CRDT document registry
type CrdtDocRegistry = tokio::sync::RwLock<HashMap<String, DocState>>;

// Global registry of CRDT documents and their connections
static CRDT_DOCS: std::sync::LazyLock<CrdtDocRegistry> =
	std::sync::LazyLock::new(|| tokio::sync::RwLock::new(HashMap::new()));

/// Handle a CRDT connection
///
/// The `read_only` parameter controls whether this connection can send updates.
/// Read-only connections can receive sync messages and awareness updates,
/// but their Update messages will be rejected.
///
/// `id_tag` is `Some` only for an authenticated connection; an anonymous share-link
/// visitor connects as `None`. That is a different question from `read_only` (a
/// signed-in reader is read-only but not anonymous), and it is what decides whose
/// identity gets stamped onto relayed awareness — see [`stamp_awareness_identity`].
///
/// SECURITY TODO: Access level is checked once at connection time but not re-validated.
/// If a user's access is revoked (e.g., FSHR action deleted), they keep their original
/// access level until reconnection. Consider adding periodic re-validation (every 30s
/// or 100 messages) to enforce access revocation mid-session.
pub async fn handle_crdt_connection(
	ws: WebSocket,
	id_tag: Option<String>,
	doc_id: String,
	app: App,
	tn_id: TnId,
	read_only: bool,
) {
	let user_id = id_tag.as_deref().unwrap_or_default().to_owned();
	// Generate unique connection ID
	let conn_id =
		cloudillo_types::utils::random_id().unwrap_or_else(|_| format!("conn-{}", now_timestamp()));
	info!("CRDT connection: {} / {} (tn_id={}, conn_id={})", user_id, doc_id, tn_id.0, conn_id);

	// Get or create per-document state (broadcast channels + live Y.Doc).
	// We check with a read lock first (fast path for existing docs), then
	// acquire a write lock to insert if missing. The write lock is held
	// across load_or_init_doc so that only one connection ever initializes
	// a given document (avoids duplicate initial updates for new docs).
	let doc_state = {
		let docs = CRDT_DOCS.read().await;
		docs.get(&doc_id).cloned()
	};
	let doc_state = if let Some(state) = doc_state {
		state
	} else {
		let mut docs = CRDT_DOCS.write().await;
		// Re-check: another connection may have inserted while we waited
		if let Some(state) = docs.get(&doc_id) {
			state.clone()
		} else {
			let live_doc = match load_or_init_doc(&app, tn_id, &doc_id).await {
				Ok(doc) => doc,
				Err(e) => {
					warn!("Failed to load doc {}, closing connection: {}", doc_id, e);
					return;
				}
			};
			let (awareness_tx, _) = tokio::sync::broadcast::channel(256);
			let (sync_tx, _) = tokio::sync::broadcast::channel(256);
			let state = DocState {
				awareness_tx: Arc::new(awareness_tx),
				sync_tx: Arc::new(sync_tx),
				doc: Arc::new(Mutex::new(live_doc)),
				awareness_owners: Arc::new(Mutex::default()),
			};
			docs.insert(doc_id.clone(), state.clone());
			state
		}
	};

	let conn = Arc::new(CrdtConnection {
		conn_id: conn_id.clone(),
		id_tag,
		doc_id: doc_id.clone(),
		tn_id,
		awareness_tx: doc_state.awareness_tx,
		sync_tx: doc_state.sync_tx,
		doc: doc_state.doc,
		awareness_owners: doc_state.awareness_owners,
		last_access_update: Mutex::new(None),
		last_modify_update: Mutex::new(None),
		has_modified: AtomicBool::new(false),
	});

	// Record initial file access (throttled)
	record_file_access_throttled(&app, &conn).await;

	// Split WebSocket for concurrent operations
	let (ws_tx, ws_rx) = ws.split();
	let ws_tx: Arc<tokio::sync::Mutex<_>> = Arc::new(tokio::sync::Mutex::new(ws_tx));

	// Send server's SyncStep1 (state vector from live doc — instant, no DB read)
	{
		let doc_guard = conn.doc.lock().await;
		let sv = doc_guard.transact().state_vector();
		drop(doc_guard);
		let y_msg = YMessage::Sync(SyncMessage::SyncStep1(sv));
		let encoded = y_msg.encode_v1();
		info!("Sent SyncStep1 to {} for doc {} ({} bytes)", conn.user_id(), doc_id, encoded.len());
		let mut tx = ws_tx.lock().await;
		if let Err(e) = tx.send(Message::Binary(encoded.into())).await {
			warn!("Failed to send SyncStep1 to {}: {}", conn.user_id(), e);
		}
	}

	// Heartbeat task - sends ping frames to keep connection alive
	let heartbeat_task = spawn_heartbeat_task(user_id, ws_tx.clone());

	// WebSocket receive task - handles incoming messages
	let ws_recv_task =
		spawn_receive_task(conn.clone(), ws_tx.clone(), ws_rx, app.clone(), tn_id, read_only);

	// Sync broadcast task - forwards CRDT updates to other clients
	let sync_task =
		spawn_broadcast_task(conn.clone(), ws_tx.clone(), conn.sync_tx.subscribe(), "SYNC");

	// Awareness broadcast task - forwards awareness updates to other clients
	let awareness_task = spawn_broadcast_task(
		conn.clone(),
		ws_tx.clone(),
		conn.awareness_tx.subscribe(),
		"AWARENESS",
	);

	// Wait for WebSocket receive task to complete (client disconnected)
	// We don't need to select on all tasks - the ws_recv_task is the one that matters
	let _ = ws_recv_task.await;
	debug!("WebSocket receive task ended");

	// Record final file activity before closing
	record_final_activity(&app, &conn).await;

	// Abort all other tasks to ensure cleanup
	info!("CRDT connection closing for {}, aborting tasks...", conn.user_id());
	heartbeat_task.abort();
	sync_task.abort();
	awareness_task.abort();

	// Wait for aborted tasks to fully clean up (drop their receivers)
	// We can ignore the JoinError since we just aborted them
	let _ = tokio::join!(heartbeat_task, sync_task, awareness_task);
	info!("CRDT connection closed: {} (all tasks cleaned up)", conn.user_id());

	broadcast_awareness_removal(&conn).await;

	// Always log document statistics on close
	log_doc_statistics(&app, tn_id, &conn.doc_id).await;

	// Check if this was the last connection (read-only check).
	// We do NOT remove from the registry yet — a reconnecting client during the
	// grace period must find the existing DocState (with the live Doc), not create
	// a fresh one.
	if is_last_connection(&conn.doc_id).await {
		info!("Last connection closed for doc {}, waiting before optimization...", conn.doc_id);

		// Wait a grace period to ensure:
		// 1. No new connections are in the process of being established
		// 2. All concurrent disconnections have completed
		// 3. No pending updates are still being processed
		tokio::time::sleep(std::time::Duration::from_secs(2)).await;

		// Acquire write lock, re-check, and only then remove + extract DocState.
		// This avoids TOCTOU: if a new connection joined during the grace period
		// it will have receivers on the existing DocState, so we skip removal.
		let removed = {
			let mut docs = CRDT_DOCS.write().await;
			if let Some(state) = docs.get(&conn.doc_id) {
				if state.awareness_tx.receiver_count() == 0 && state.sync_tx.receiver_count() == 0 {
					docs.remove(&conn.doc_id)
				} else {
					None
				}
			} else {
				None
			}
		};

		if let Some(doc_state) = removed {
			info!(
				"Confirmed no active connections for doc {}, proceeding with optimization",
				conn.doc_id
			);
			optimize_document(&app, tn_id, &conn.doc_id, &doc_state.doc).await;
		} else {
			info!(
				"New connection established for doc {} during grace period, skipping optimization",
				conn.doc_id
			);
		}
	}
}

/// Load a Y.Doc from stored updates, or initialize a new one if the document is empty.
///
/// Called once per document when the first connection opens. The returned Doc is kept
/// in-memory in the `CRDT_DOCS` registry for the lifetime of the document's connections.
async fn load_or_init_doc(app: &App, tn_id: TnId, doc_id: &str) -> ClResult<Doc> {
	let updates = app.crdt_adapter.get_updates(tn_id, doc_id).await?;

	if updates.is_empty() {
		info!("Document {} not initialized, creating initial structure", doc_id);
		let doc = Doc::new();
		let meta = doc.get_or_insert_map("meta");
		{
			let mut txn = doc.transact_mut();
			meta.insert(&mut txn, "i", true);
		}

		// Persist the initial update
		let initial_data = doc.transact().encode_state_as_update_v1(&StateVector::default());
		if !initial_data.is_empty() {
			let update = cloudillo_types::crdt_adapter::CrdtUpdate::with_client(
				initial_data,
				"system".to_string(),
			);
			if let Err(e) = app.crdt_adapter.store_update(tn_id, doc_id, update).await {
				warn!("Failed to store initial CRDT update for doc {}: {}", doc_id, e);
			} else {
				info!("Document {} initialized", doc_id);
			}
		}
		Ok(doc)
	} else {
		let total_bytes: usize = updates.iter().map(|u| u.data.len()).sum();
		info!("Loading {} CRDT updates for doc {} ({} bytes)", updates.len(), doc_id, total_bytes);
		let updates_data: Vec<Vec<u8>> = updates.iter().map(|u| u.data.clone()).collect();
		let doc_id_owned = doc_id.to_string();
		match app
			.worker
			.run_immed(move || {
				let doc = Doc::new();
				{
					let mut txn = doc.transact_mut();
					for (idx, data) in updates_data.iter().enumerate() {
						match Update::decode_v1(data) {
							Ok(update) => {
								if let Err(e) = txn.apply_update(update) {
									warn!(
										"Update #{} for doc {} failed to apply: {}",
										idx, doc_id_owned, e
									);
								}
							}
							Err(e) => {
								warn!(
									"Update #{} for doc {} failed to decode: {}",
									idx, doc_id_owned, e
								);
							}
						}
					}
				}
				doc
			})
			.await
		{
			Ok(doc) => Ok(doc),
			Err(e) => {
				warn!("Worker pool failed loading doc {}: {}", doc_id, e);
				Err(Error::Internal(format!("Worker pool failed loading doc {}", doc_id)))
			}
		}
	}
}

/// Spawn heartbeat task that sends ping frames periodically
fn spawn_heartbeat_task(
	user_id: String,
	ws_tx: Arc<tokio::sync::Mutex<SplitSink<WebSocket, Message>>>,
) -> tokio::task::JoinHandle<()> {
	tokio::spawn(async move {
		let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
		loop {
			interval.tick().await;
			debug!("CRDT heartbeat: {}", user_id);

			let mut tx = ws_tx.lock().await;
			if tx.send(Message::Ping(vec![].into())).await.is_err() {
				debug!("Client disconnected during heartbeat");
				return;
			}
		}
	})
}

/// Spawn WebSocket receive task that handles incoming messages
fn spawn_receive_task(
	conn: Arc<CrdtConnection>,
	ws_tx: Arc<tokio::sync::Mutex<SplitSink<WebSocket, Message>>>,
	ws_rx: futures::stream::SplitStream<WebSocket>,
	app: App,
	tn_id: TnId,
	read_only: bool,
) -> tokio::task::JoinHandle<()> {
	tokio::spawn(async move {
		let mut ws_rx = ws_rx;
		while let Some(msg) = ws_rx.next().await {
			match msg {
				Ok(Message::Binary(data)) => {
					// yrs messages are sent directly without our wrapper
					handle_yrs_message(&conn, &data, &ws_tx, &app, tn_id, read_only).await;
				}
				Ok(Message::Close(_) | Message::Ping(_) | Message::Pong(_)) => {
					// Ignore control frames
				}
				Ok(_) => {
					warn!("Received non-binary WebSocket message");
				}
				Err(e) => {
					warn!("CRDT connection error: {}", e);
					break;
				}
			}
		}
	})
}

/// Spawn a generic broadcast task that forwards updates to other clients
/// This handles both SYNC and AWARENESS broadcasts with the same logic
fn spawn_broadcast_task(
	conn: Arc<CrdtConnection>,
	ws_tx: Arc<tokio::sync::Mutex<SplitSink<WebSocket, Message>>>,
	mut rx: tokio::sync::broadcast::Receiver<(String, Vec<u8>)>,
	label: &'static str,
) -> tokio::task::JoinHandle<()> {
	tokio::spawn(async move {
		debug!(
			"Connection {} (user {}) subscribed to {} broadcasts for doc {}",
			conn.conn_id,
			conn.user_id(),
			label,
			conn.doc_id
		);

		loop {
			match rx.recv().await {
				Ok((sender_conn_id, data)) => {
					debug!(
						"{} broadcast received by conn {}: from conn {} for doc {} ({} bytes)",
						label,
						conn.conn_id,
						sender_conn_id,
						conn.doc_id,
						data.len()
					);

					// Skip if this is from the current connection (already echoed)
					if sender_conn_id == conn.conn_id {
						debug!("Skipping {} echo to self for conn {}", label, conn.conn_id);
						continue;
					}

					// Forward update to this client (data is already yrs-encoded, send directly)
					let ws_msg = Message::Binary(data.into());

					debug!(
						"Forwarding {} update from conn {} to conn {} (user {}) for doc {}",
						label,
						sender_conn_id,
						conn.conn_id,
						conn.user_id(),
						conn.doc_id
					);

					let mut tx = ws_tx.lock().await;
					if tx.send(ws_msg).await.is_err() {
						debug!("Client disconnected while forwarding {} update", label);
						return;
					}
					debug!("{} update successfully forwarded to conn {}", label, conn.conn_id);
				}
				Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
					if label == "SYNC" {
						warn!(
							"Client {} lagged behind on {} updates for doc {}",
							conn.user_id(),
							label,
							conn.doc_id
						);
					} else {
						debug!("Connection {} lagged on {} updates", conn.conn_id, label);
					}
				}
				Err(tokio::sync::broadcast::error::RecvError::Closed) => {
					debug!("{} broadcast channel closed", label);
					return;
				}
			}
		}
	})
}

/// Broadcast a message and log the result
fn broadcast_message(
	tx: &Arc<tokio::sync::broadcast::Sender<(String, Vec<u8>)>>,
	conn_id: &str,
	user_id: &str,
	doc_id: &str,
	payload: Vec<u8>,
	label: &str,
) {
	match tx.send((conn_id.to_string(), payload)) {
		Ok(receiver_count) => {
			if label != "AWARENESS" {
				info!(
					"CRDT {} broadcast from conn {} (user {}) for doc {}: {} receivers",
					label, conn_id, user_id, doc_id, receiver_count
				);
			}
		}
		Err(_) => {
			debug!("CRDT {} broadcast failed - no receivers for doc {}", label, doc_id);
		}
	}
}

/// Send raw echo response back to the client (yrs-encoded data)
async fn send_echo_raw(
	ws_tx: &Arc<tokio::sync::Mutex<SplitSink<WebSocket, Message>>>,
	conn_id: &str,
	user_id: &str,
	doc_id: &str,
	payload: &[u8],
	label: &str,
) {
	let ws_msg = Message::Binary(payload.to_vec().into());
	let mut tx = ws_tx.lock().await;

	match tx.send(ws_msg).await {
		Ok(()) => {
			debug!(
				"CRDT {} echo sent back to conn {} (user {}) for doc {} ({} bytes)",
				label,
				conn_id,
				user_id,
				doc_id,
				payload.len()
			);
		}
		Err(e) => {
			warn!("Failed to send CRDT {} echo to conn {}: {}", label, conn_id, e);
		}
	}
}

/// Handle a yrs-encoded message
///
/// Decode, apply to the live Doc, and persist an update from a client.
///
/// Returns `true` if the update was successfully stored (caller should broadcast),
/// or `false` if it was rejected/skipped/failed (caller should return early).
async fn apply_and_store(
	app: &App,
	tn_id: TnId,
	conn: &Arc<CrdtConnection>,
	update_data: &[u8],
	read_only: bool,
	msg_type: &str,
) -> bool {
	if read_only {
		debug!(
			"Ignoring {} from read-only conn {} for doc {}",
			msg_type, conn.conn_id, conn.doc_id
		);
		return false;
	}
	if update_data.is_empty() {
		debug!("Received empty {} from conn {}", msg_type, conn.conn_id);
		return false;
	}

	// Apply to the live doc first to detect no-ops (e.g., SyncStep2 with only
	// redundant delete-set metadata). yrs::Update is !Send so we must decode
	// inside the lock scope.
	let is_noop = {
		let doc_guard = conn.doc.lock().await;
		let snapshot_before = doc_guard.transact().snapshot();
		match Update::decode_v1(update_data) {
			Ok(decoded) => {
				if let Err(e) = doc_guard.transact_mut().apply_update(decoded) {
					warn!("Failed to apply {} to live doc {}: {}", msg_type, conn.doc_id, e);
					return false;
				}
			}
			Err(e) => {
				warn!(
					"Rejecting malformed {} from conn {} - decode failed: {}",
					msg_type, conn.conn_id, e
				);
				return false;
			}
		}
		let snapshot_after = doc_guard.transact().snapshot();
		snapshot_before == snapshot_after
	};

	if is_noop {
		debug!(
			"{} is a no-op for doc {} ({} bytes) - skipping persist",
			msg_type,
			conn.doc_id,
			update_data.len()
		);
		return false;
	}

	// Persist to DB — the live doc is already updated. On persist failure the
	// live doc is ahead of DB, but this self-corrects: compaction on close
	// will persist the full merged state.
	let update = cloudillo_types::crdt_adapter::CrdtUpdate::with_client(
		update_data.to_vec(),
		conn.user_id().to_owned(),
	);
	if let Err(e) = app.crdt_adapter.store_update(tn_id, &conn.doc_id, update).await {
		warn!(
			"{} FAILED to store for doc {}: {} - live doc is ahead of DB",
			msg_type, conn.doc_id, e
		);
		return false;
	}

	info!(
		"{} stored for doc {} from user {} ({} bytes)",
		msg_type,
		conn.doc_id,
		conn.user_id(),
		update_data.len()
	);
	record_file_modification_throttled(app, conn).await;
	// The hook only enqueues a debounced task, so an editing burst collapses into one
	// run well after the document goes quiet. Same seam `cloudillo-rtdb` uses after a
	// committed transaction.
	if let Ok(index) = app.ext::<cloudillo_core::SearchIndexFn>() {
		index(app, conn.tn_id, &conn.doc_id);
	}
	true
}

/// The `read_only` parameter controls whether Update messages are accepted.
/// Read-only connections can still receive SyncStep1/2 for initial sync,
/// but their Update messages (actual edits) will be rejected.
async fn handle_yrs_message(
	conn: &Arc<CrdtConnection>,
	data: &[u8],
	ws_tx: &Arc<tokio::sync::Mutex<SplitSink<WebSocket, Message>>>,
	app: &App,
	tn_id: TnId,
	read_only: bool,
) {
	if data.is_empty() {
		warn!("Empty message from conn {}", conn.conn_id);
		return;
	}

	// Decode using yrs
	match YMessage::decode_v1(data) {
		Ok(YMessage::Sync(sync_msg)) => {
			debug!(
				"CRDT SYNC message from conn {} (user {}) for doc {}: {:?}",
				conn.conn_id,
				conn.user_id(),
				conn.doc_id,
				match &sync_msg {
					SyncMessage::SyncStep1(_) => "SyncStep1",
					SyncMessage::SyncStep2(_) => "SyncStep2",
					SyncMessage::Update(_) => "Update",
				}
			);

			// Handle each sync message type according to the y-sync protocol.
			// Only SyncStep2 and Update messages that are successfully stored
			// should be broadcast+echoed. SyncStep1, read-only rejections, empty
			// messages, and store failures must return early to avoid broadcast.
			match &sync_msg {
				SyncMessage::SyncStep1(client_sv) => {
					// Client sent its state vector — respond with SyncStep2 (updates the
					// client is missing). Computed instantly from the live in-memory Doc.
					info!(
						"Received SyncStep1 from conn {} (user {}) for doc {} ({} bytes)",
						conn.conn_id,
						conn.user_id(),
						conn.doc_id,
						data.len()
					);
					let doc_guard = conn.doc.lock().await;
					let server_sv = doc_guard.transact().state_vector();
					debug!(
						"SV comparison for doc {}: server={} clients, client={} clients",
						conn.doc_id,
						server_sv.len(),
						client_sv.len()
					);
					let diff = doc_guard.transact().encode_state_as_update_v1(client_sv);
					drop(doc_guard);

					let mut tx = ws_tx.lock().await;
					let msg = YMessage::Sync(SyncMessage::SyncStep2(diff.clone()));
					match tx.send(Message::Binary(msg.encode_v1().into())).await {
						Err(e) => {
							warn!("Failed to send SyncStep2 to {}: {}", conn.user_id(), e);
						}
						Ok(()) => {
							info!(
								"Sent SyncStep2 to conn {} for doc {} ({} bytes)",
								conn.conn_id,
								conn.doc_id,
								diff.len()
							);
						}
					}
					return;
				}
				SyncMessage::SyncStep2(update_data) => {
					// SyncStep2 from client may contain redundant data (the
					// client's full state diff). We persist it like a normal
					// update — yrs handles duplicates idempotently, and
					// compaction merges everything on close.
					info!(
						"Received SyncStep2 from conn {} (user {}) for doc {} ({} bytes)",
						conn.conn_id,
						conn.user_id(),
						conn.doc_id,
						update_data.len()
					);
					if !apply_and_store(app, tn_id, conn, update_data, read_only, "SyncStep2").await
					{
						return;
					}
				}
				SyncMessage::Update(update_data) => {
					if !apply_and_store(app, tn_id, conn, update_data, read_only, "Update").await {
						return;
					}
				}
			}

			// Broadcast successfully stored updates to other clients.
			// SyncStep2 data must be re-encoded as Update for protocol conformance:
			// SyncStep2 is a handshake response, not a live update message.
			let broadcast_data = match &sync_msg {
				SyncMessage::SyncStep2(update_data) => {
					let msg = YMessage::Sync(SyncMessage::Update(update_data.clone()));
					msg.encode_v1()
				}
				_ => data.to_vec(),
			};

			broadcast_message(
				&conn.sync_tx,
				&conn.conn_id,
				conn.user_id(),
				&conn.doc_id,
				broadcast_data.clone(),
				"SYNC",
			);

			// Echo back to sender as keepalive (y-websocket disconnects after 30s
			// without data messages; PING frames don't count as they bypass onmessage).
			// The echoed data is harmless: the client already has it and processes as no-op.
			send_echo_raw(
				ws_tx,
				&conn.conn_id,
				conn.user_id(),
				&conn.doc_id,
				&broadcast_data,
				"SYNC",
			)
			.await;
		}
		Ok(YMessage::Awareness(awareness_update)) => {
			debug!(
				"CRDT AWARENESS from conn {} (user {}) for doc {} ({} bytes)",
				conn.conn_id,
				conn.user_id(),
				conn.doc_id,
				data.len()
			);

			// Never relay what the client sent. The echo gets the stamped bytes too —
			// an app whose local state disagreed with what its peers see would be a
			// second bug. `Unchanged` relays the received bytes verbatim, skipping a
			// re-serialise on the highest-frequency message this socket carries.
			//
			// The owners lock is held only for the stamp: the map is per-document and
			// awareness fires on every cursor move.
			let stamped_data = {
				let mut owners = conn.awareness_owners.lock().await;
				match stamp_awareness_identity(
					&awareness_update,
					conn.id_tag.as_deref(),
					&conn.conn_id,
					&mut owners,
				) {
					Stamped::Unchanged => data.to_vec(),
					Stamped::Rewritten(update) => YMessage::Awareness(update).encode_v1(),
					Stamped::Empty => {
						debug!(
							"Awareness from conn {} (user {}) for doc {} carried only relayed peer states",
							conn.conn_id,
							conn.user_id(),
							conn.doc_id
						);
						return;
					}
					Stamped::Undecodable => {
						warn!(
							"Dropping undecodable awareness state from conn {} (user {}) for doc {}",
							conn.conn_id,
							conn.user_id(),
							conn.doc_id
						);
						return;
					}
				}
			};

			// Broadcast to other clients
			broadcast_message(
				&conn.awareness_tx,
				&conn.conn_id,
				conn.user_id(),
				&conn.doc_id,
				stamped_data.clone(),
				"AWARENESS",
			);

			// Echo back to sender
			send_echo_raw(
				ws_tx,
				&conn.conn_id,
				conn.user_id(),
				&conn.doc_id,
				&stamped_data,
				"AWARENESS",
			)
			.await;
		}
		Ok(other) => {
			debug!("Received non-sync/awareness message: {:?}", other);
		}
		Err(e) => {
			warn!("Failed to decode yrs message from conn {}: {}", conn.conn_id, e);
		}
	}
}

/// Assert this connection's identity over an awareness update: drop entries belonging
/// to other connections, and rewrite `user.idTag` in this connection's own.
///
/// Awareness is relayed verbatim by design and the Yjs clientId is allocated
/// client-side, so nothing in the protocol binds a broadcast identity to the connection
/// it arrived on. Clients derive a collaborator's colour and fetch their profile picture
/// FROM the idTag (`libs/crdt/src/presence.ts`), so an unchecked `idTag` lets anyone
/// appear in everyone's roster wearing a victim's real name and avatar.
///
/// **Ownership comes first, because a client legitimately relays other peers'
/// awareness.** `y-websocket`'s `_awarenessUpdateHandler` ignores its origin argument,
/// so every state a client applies is re-broadcast over that client's own socket — a
/// second tab does exactly that for the whole roster. Stamping those with the sender's
/// tag would relabel every peer, worse than the impersonation it was meant to close. So
/// an entry whose clientId is owned by a *different* connection is dropped from the
/// relay (the owner's own updates are authoritative); only that entry, never the
/// message.
///
/// For an entry this connection owns (or has just claimed):
///
/// - `Some(tag)` (authenticated) -> `idTag` is overwritten with `tag`;
/// - `None` (anonymous share-link visitor) -> `idTag` is REMOVED. There is no identity
///   to assert on their behalf, and the shell hands such a visitor the OWNER's tag
///   client-side, so a stamp here would *be* the impersonation. `name` is left alone,
///   so a guest still shows a display name.
///
/// Overwriting rather than rejecting keeps clients that legitimately send no `idTag`
/// valid and makes the invariant total: every `idTag` on this wire was put there by us.
/// Every other field (`name`, `cursor`, `editing`, …) is app-specific and untouched.
///
/// Returns [`Stamped::Undecodable`] if any client state is unparseable or carries a
/// non-object `user` — a payload we cannot rewrite is exactly the one that must not slip
/// through unrewritten, so the caller drops the whole message.
///
/// **Decide, then commit.** The first pass only reads `owners`, buffering claims and
/// clock bumps; an `Undecodable` message reaches no peer and so must leave no ownership
/// behind either, or a client could squat clientIds with messages nobody sees and the
/// legitimate owner would go silently invisible in every roster.
///
/// Past [`MAX_AWARENESS_CLIENT_IDS_PER_CONN`], further unclaimed ids are dropped like a
/// peer-owned entry, so the connection keeps working with its legitimate clientIds.
fn stamp_awareness_identity(
	update: &AwarenessUpdate,
	id_tag: Option<&str>,
	conn_id: &str,
	owners: &mut AwarenessOwners,
) -> Stamped {
	let mut retained: Vec<(ClientID, AwarenessUpdateEntry)> = Vec::new();
	// Buffered decisions — applied only once the whole message has been accepted.
	let mut claims: Vec<(ClientID, u32)> = Vec::new();
	let mut bumps: Vec<(ClientID, u32)> = Vec::new();
	let mut dropped = false;
	let mut rewritten = false;
	let mut capped = false;
	let mut budget = MAX_AWARENESS_CLIENT_IDS_PER_CONN
		.saturating_sub(owners.claimed.get(conn_id).copied().unwrap_or(0));

	for (&client_id, entry) in &update.clients {
		match owners.owners.get(&client_id) {
			// A peer's state, relayed back to us by a client that received it.
			Some(owner) if *owner.conn_id != *conn_id => {
				dropped = true;
				continue;
			}
			// Ours already: keep the highest clock, which is what the disconnect
			// removal below has to beat for peers to accept it.
			Some(_) => bumps.push((client_id, entry.clock)),
			// Unclaimed: first publish wins, which is the only ownership signal the
			// protocol offers — up to this connection's budget.
			None => {
				if budget == 0 {
					dropped = true;
					capped = true;
					continue;
				}
				budget -= 1;
				claims.push((client_id, entry.clock));
			}
		}

		let Some(stamped) = stamp_state_json(&entry.json, id_tag) else {
			// Nothing has been committed yet, so the dropped message claims nothing.
			return Stamped::Undecodable;
		};
		match stamped {
			Some(json) => {
				rewritten = true;
				retained.push((client_id, AwarenessUpdateEntry { clock: entry.clock, json }));
			}
			None => retained.push((client_id, entry.clone())),
		}
	}

	if capped {
		warn!(
			"Conn {} already owns {} clientIds on this document; dropping further ones",
			conn_id, MAX_AWARENESS_CLIENT_IDS_PER_CONN
		);
	}

	// Commit: reached only when every entry was decodable.
	for (client_id, clock) in claims {
		owners
			.owners
			.insert(client_id, AwarenessOwner { conn_id: conn_id.into(), clock });
		*owners.claimed.entry(conn_id.into()).or_default() += 1;
	}
	for (client_id, clock) in bumps {
		if let Some(owner) = owners.owners.get_mut(&client_id) {
			owner.clock = owner.clock.max(clock);
		}
	}

	if dropped && retained.is_empty() {
		Stamped::Empty
	} else if dropped || rewritten {
		Stamped::Rewritten(AwarenessUpdate { clients: retained.into_iter().collect() })
	} else {
		Stamped::Unchanged
	}
}

/// Outcome of asserting this connection's identity over an awareness update.
enum Stamped {
	/// Nothing was dropped and nothing was rewritten: every entry is this
	/// connection's own and already carried the correct identity. Relay the bytes as
	/// received, skipping the re-serialise and re-encode.
	Unchanged,
	/// At least one state was rewritten or dropped; relay these bytes instead.
	Rewritten(AwarenessUpdate),
	/// Every entry belonged to another connection. Relay nothing — there is no
	/// message left, and the owning connections publish their own states anyway.
	Empty,
	/// A client state could not be parsed, or its `user` was not an object. Relay
	/// nothing: a payload we cannot rewrite is precisely the one that must not
	/// slip through unrewritten.
	Undecodable,
}

/// Tell the remaining peers that every clientId this connection owned is gone.
///
/// Exactly the wire form y-protocols' `removeAwarenessStates` produces — the clientId's
/// clock bumped by one, carrying a `null` state — so peers drop the departing
/// collaborator immediately instead of waiting out the client-side ~30 s awareness
/// timeout.
///
/// The entries are drained, so the clientIds are free for a reconnecting tab to claim
/// again — a browser tab keeps its `doc.clientID` across a reconnect. The `claimed`
/// count goes with them, or a tab that reconnected often enough would exhaust
/// [`MAX_AWARENESS_CLIENT_IDS_PER_CONN`] while owning nothing.
fn drain_awareness_removal(owners: &mut AwarenessOwners, conn_id: &str) -> AwarenessUpdate {
	let mut clients: HashMap<ClientID, AwarenessUpdateEntry> = HashMap::new();
	owners.owners.retain(|&client_id, owner| {
		if *owner.conn_id == *conn_id {
			// One past the highest clock we relayed, so peers accept it as newer
			// than every state they already hold for this clientId.
			clients.insert(
				client_id,
				AwarenessUpdateEntry {
					clock: owner.clock.saturating_add(1),
					json: Arc::from("null"),
				},
			);
			false
		} else {
			true
		}
	});
	owners.claimed.remove(conn_id);
	AwarenessUpdate { clients }
}

/// See [`drain_awareness_removal`] — this is the connection-facing half, splitting
/// the lock and the broadcast off the pure part so the shape of the update is
/// testable.
async fn broadcast_awareness_removal(conn: &CrdtConnection) {
	let update = {
		let mut owners = conn.awareness_owners.lock().await;
		drain_awareness_removal(&mut owners, &conn.conn_id)
	};

	if update.clients.is_empty() {
		return;
	}
	debug!(
		"CRDT awareness removal for conn {} on doc {}: {} client(s)",
		conn.conn_id,
		conn.doc_id,
		update.clients.len()
	);
	let bytes = YMessage::Awareness(update).encode_v1();
	broadcast_message(
		&conn.awareness_tx,
		&conn.conn_id,
		conn.user_id(),
		&conn.doc_id,
		bytes,
		"AWARENESS",
	);
}

/// One client state's JSON payload, with `user.idTag` asserted.
///
/// Three-valued, to let the caller skip the rewrite entirely: `None` is
/// undecodable, `Some(None)` is "already correct, reuse the input", and
/// `Some(Some(json))` is the rewritten payload.
#[allow(clippy::option_option)]
fn stamp_state_json(json: &Arc<str>, id_tag: Option<&str>) -> Option<Option<Arc<str>>> {
	let mut state: serde_json::Value = serde_json::from_str(json).ok()?;
	// A disconnecting client sends `null`, and an app with no presence payload sends a
	// state without `user` — neither carries an identity to assert. (`get_mut` on a
	// `Value::Null` yields `None`, so both land here.) Adding a `user` object would
	// conjure a nameless phantom into every roster.
	let Some(user) = state.get_mut("user") else { return Some(None) };
	// Present but not an object (`{"user":"alice"}`): no identity can be asserted into
	// it, so it must not be relayed — passing it through unrewritten is the evasion the
	// rewrite exists to prevent. `?` is the undecodable outcome.
	let user = user.as_object_mut()?;
	// Nothing to do when the client already sent what we would have written — the
	// overwhelmingly common case, since awareness fires on every cursor move.
	if let Some(tag) = id_tag {
		if user.get("idTag").and_then(serde_json::Value::as_str) == Some(tag) {
			return Some(None);
		}
		user.insert("idTag".to_owned(), serde_json::Value::String(tag.to_owned()));
	} else if user.contains_key("idTag") {
		user.remove("idTag");
	} else {
		return Some(None);
	}
	Some(Some(Arc::from(serde_json::to_string(&state).ok()?)))
}

/// Log document statistics (update count and total size)
async fn log_doc_statistics(app: &App, tn_id: TnId, doc_id: &str) {
	match app.crdt_adapter.get_updates(tn_id, doc_id).await {
		Ok(updates) => {
			let update_count = updates.len();
			let total_size: usize = updates.iter().map(|u| u.data.len()).sum();

			// Calculate average update size
			let avg_size = total_size.checked_div(update_count).unwrap_or(0);

			info!(
				"CRDT doc stats [{}]: {} updates, {} bytes total, {} bytes avg",
				doc_id, update_count, total_size, avg_size
			);
		}
		Err(e) => {
			warn!("Failed to get statistics for doc {}: {}", doc_id, e);
		}
	}
}

/// Optimize document by encoding the live Doc state as a single compacted update.
///
/// Uses the in-memory Doc (already has all updates applied) to produce the merged
/// state — no DB reads or doc reconstruction needed. The replacement is atomic
/// (single database transaction) — no data loss on crash.
async fn optimize_document(app: &App, tn_id: TnId, doc_id: &str, doc: &Arc<Mutex<Doc>>) {
	// Get all existing updates (with seq numbers) for size comparison and seq tracking
	let updates = match app.crdt_adapter.get_updates(tn_id, doc_id).await {
		Ok(u) => u,
		Err(e) => {
			warn!("Failed to get updates for optimization of doc {}: {}", doc_id, e);
			return;
		}
	};

	// Skip optimization if there's only 0 or 1 update
	if updates.len() <= 1 {
		debug!("Skipping optimization for doc {} (only {} updates)", doc_id, updates.len());
		return;
	}

	let updates_before = updates.len();

	// Collect seqs of all updates (we'll replace them all with the merged state)
	let all_seqs: Vec<u64> = updates.iter().filter_map(|u| u.seq).collect();
	if all_seqs.len() != updates.len() {
		warn!(
			"Doc {} has {} updates but only {} have valid seq numbers (possible key corruption)",
			doc_id,
			updates.len(),
			all_seqs.len()
		);
	}
	let size_before: usize = updates.iter().map(|u| u.data.len()).sum();

	if all_seqs.len() <= 1 {
		debug!(
			"Skipping optimization for doc {} (only {} updates with seq)",
			doc_id,
			all_seqs.len()
		);
		return;
	}

	// Encode merged state from the live Doc (instant — no reconstruction)
	let doc_guard = doc.lock().await;
	let merged_update = doc_guard.transact().encode_state_as_update_v1(&StateVector::default());
	drop(doc_guard);

	if merged_update.is_empty() {
		warn!("Merged update for doc {} is empty! Aborting optimization.", doc_id);
		return;
	}

	let size_after = merged_update.len();

	// Only proceed if optimization actually reduces size
	if size_after >= size_before {
		info!(
			"Skipping optimization for doc {} (no size reduction: {} -> {})",
			doc_id, size_before, size_after
		);
		return;
	}

	// Atomically replace all updates with the compacted result
	let merged_crdt_update =
		cloudillo_types::crdt_adapter::CrdtUpdate::with_client(merged_update, "system".to_string());

	if let Err(e) = app
		.crdt_adapter
		.compact_updates(tn_id, doc_id, &all_seqs, merged_crdt_update)
		.await
	{
		warn!("Failed to compact updates for doc {}: {}", doc_id, e);
		return;
	}

	let size_reduction = size_before - size_after;
	let reduction_percent = (usize_to_f64(size_reduction) / usize_to_f64(size_before)) * 100.0;

	info!(
		"CRDT doc optimized [{}]: {} -> 1 updates, {} -> {} bytes ({:.1}% reduction)",
		doc_id, updates_before, size_before, size_after, reduction_percent
	);
}

/// Check if a document has no remaining active connections (read-only).
///
/// Returns `true` if the doc is in the registry with zero receivers on both
/// channels, meaning optimization should be attempted after a grace period.
/// Does **not** remove the entry — that happens later under a write lock to
/// avoid TOCTOU races with reconnecting clients.
async fn is_last_connection(doc_id: &str) -> bool {
	let docs = CRDT_DOCS.read().await;
	if let Some(state) = docs.get(doc_id) {
		let awareness_count = state.awareness_tx.receiver_count();
		let sync_count = state.sync_tx.receiver_count();

		info!(
			"Checking CRDT registry for doc {}: {} awareness receivers, {} sync receivers",
			doc_id, awareness_count, sync_count
		);

		awareness_count == 0 && sync_count == 0
	} else {
		info!("Doc {} not found in registry during cleanup check", doc_id);
		false
	}
}

/// Get current timestamp
fn now_timestamp() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs()
}

/// Record file access with throttling (max once per TRACKING_THROTTLE_SECS)
async fn record_file_access_throttled(app: &App, conn: &CrdtConnection) {
	let should_update = {
		let mut last_update = conn.last_access_update.lock().await;
		let now = Instant::now();
		let should = match *last_update {
			Some(last) => now.duration_since(last).as_secs() >= TRACKING_THROTTLE_SECS,
			None => true,
		};
		if should {
			*last_update = Some(now);
		}
		should
	};

	if should_update
		&& let Err(e) = app
			.meta_adapter
			.record_file_access(conn.tn_id, conn.user_id(), &conn.doc_id)
			.await
	{
		debug!("Failed to record file access for doc {}: {}", conn.doc_id, e);
	}
}

/// Record file modification with throttling (max once per TRACKING_THROTTLE_SECS)
async fn record_file_modification_throttled(app: &App, conn: &CrdtConnection) {
	// Mark that this session has modifications
	conn.has_modified.store(true, Ordering::Relaxed);

	let should_update = {
		let mut last_update = conn.last_modify_update.lock().await;
		let now = Instant::now();
		let should = match *last_update {
			Some(last) => now.duration_since(last).as_secs() >= TRACKING_THROTTLE_SECS,
			None => true,
		};
		if should {
			*last_update = Some(now);
		}
		should
	};

	if should_update
		&& let Err(e) = app
			.meta_adapter
			.record_file_modification(conn.tn_id, conn.user_id(), &conn.doc_id)
			.await
	{
		debug!("Failed to record file modification for doc {}: {}", conn.doc_id, e);
	}
}

/// Record final access and modification on connection close
async fn record_final_activity(app: &App, conn: &CrdtConnection) {
	// Always record final access time
	if let Err(e) = app
		.meta_adapter
		.record_file_access(conn.tn_id, conn.user_id(), &conn.doc_id)
		.await
	{
		debug!("Failed to record final file access for doc {}: {}", conn.doc_id, e);
	}

	// Record final modification if any changes were made
	if conn.has_modified.load(Ordering::Relaxed)
		&& let Err(e) = app
			.meta_adapter
			.record_file_modification(conn.tn_id, conn.user_id(), &conn.doc_id)
			.await
	{
		debug!("Failed to record final file modification for doc {}: {}", conn.doc_id, e);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A fresh, empty ownership registry. Every helper below drives the real one.
	fn owners() -> AwarenessOwners {
		AwarenessOwners::default()
	}

	fn entry(clock: u32, json: &str) -> AwarenessUpdateEntry {
		AwarenessUpdateEntry { clock, json: Arc::from(json) }
	}

	fn update_of(entries: &[(u64, u32, &str)]) -> AwarenessUpdate {
		let mut clients = HashMap::new();
		for &(client_id, clock, json) in entries {
			clients.insert(ClientID::new(client_id), entry(clock, json));
		}
		AwarenessUpdate { clients }
	}

	fn update_with(json: &str) -> AwarenessUpdate {
		update_of(&[(42, 7, json)])
	}

	/// The single entry of a stamped update, as parsed JSON, for a clientId this
	/// connection is publishing for the first time. `Unchanged` maps back to the input,
	/// which is what the caller relays in that case.
	fn stamped(json: &str, id_tag: Option<&str>) -> Option<serde_json::Value> {
		let mut owners = owners();
		match stamp_awareness_identity(&update_with(json), id_tag, "conn-a", &mut owners) {
			Stamped::Unchanged => serde_json::from_str(json).ok(),
			Stamped::Rewritten(out) => {
				let entry = out.clients.get(&ClientID::new(42))?;
				serde_json::from_str(&entry.json).ok()
			}
			Stamped::Empty | Stamped::Undecodable => None,
		}
	}

	fn is_unchanged(json: &str, id_tag: Option<&str>) -> bool {
		let mut owners = owners();
		matches!(
			stamp_awareness_identity(&update_with(json), id_tag, "conn-a", &mut owners),
			Stamped::Unchanged
		)
	}

	// Identity stamping //
	//*******************//

	#[test]
	fn a_rewrite_preserves_the_clock() {
		// The clock is how peers order awareness states; a rewrite that reset it
		// would make every stamped state look stale or brand new.
		let mut owners = owners();
		let Stamped::Rewritten(out) = stamp_awareness_identity(
			&update_with(r#"{"user":{"name":"Alice"}}"#),
			Some("@alice.example.com"),
			"conn-a",
			&mut owners,
		) else {
			panic!("expected a rewrite");
		};
		assert_eq!(out.clients.get(&ClientID::new(42)).expect("the entry").clock, 7);
	}

	#[test]
	fn overwrites_a_forged_id_tag() {
		let state = stamped(
			r#"{"user":{"name":"Mallory","idTag":"@victim.example.com"}}"#,
			Some("@mallory.example.com"),
		);
		assert_eq!(
			state,
			Some(serde_json::json!({
				"user": { "name": "Mallory", "idTag": "@mallory.example.com" }
			}))
		);
	}

	#[test]
	fn stamps_a_state_that_sent_no_id_tag() {
		let state = stamped(r#"{"user":{"name":"Alice"}}"#, Some("@alice.example.com"));
		assert_eq!(
			state,
			Some(serde_json::json!({
				"user": { "name": "Alice", "idTag": "@alice.example.com" }
			}))
		);
	}

	#[test]
	fn strips_the_id_tag_of_a_guest_and_keeps_the_name() {
		// The tag a share-link visitor sends is the OWNER's — that is what the shell
		// hands an unauthenticated app — so relaying it would hand them the owner's
		// name and face in everyone else's roster.
		let state = stamped(r#"{"user":{"name":"Guest","idTag":"@owner.example.com"}}"#, None);
		assert_eq!(state, Some(serde_json::json!({ "user": { "name": "Guest" } })));
	}

	#[test]
	fn leaves_app_specific_fields_alone() {
		let state = stamped(
			r#"{"user":{"name":"Alice"},"cursor":{"x":1,"y":2},"presenting":true}"#,
			Some("@alice.example.com"),
		);
		assert_eq!(
			state,
			Some(serde_json::json!({
				"user": { "name": "Alice", "idTag": "@alice.example.com" },
				"cursor": { "x": 1, "y": 2 },
				"presenting": true
			}))
		);
	}

	#[test]
	fn passes_through_a_state_with_no_user_object() {
		// A disconnect (`null`) and a payload-free app state both have nothing to
		// stamp; inventing a `user` would put a nameless phantom in every roster.
		assert_eq!(stamped("null", Some("@alice.example.com")), Some(serde_json::Value::Null));
		assert_eq!(
			stamped(r#"{"cursor":{"x":1}}"#, Some("@alice.example.com")),
			Some(serde_json::json!({ "cursor": { "x": 1 } }))
		);
	}

	#[test]
	fn carries_an_already_correct_entry_through_a_later_rewrite() {
		// Client 1 already carries the right tag and client 2 forges one; both are
		// this connection's own, so both must come through the rewrite.
		let update = update_of(&[
			(1, 3, r#"{"user":{"idTag":"@alice.example.com"}}"#),
			(2, 4, r#"{"user":{"idTag":"@victim.example.com"}}"#),
		]);
		let mut owners = owners();
		let Stamped::Rewritten(out) =
			stamp_awareness_identity(&update, Some("@alice.example.com"), "conn-a", &mut owners)
		else {
			panic!("expected a rewrite");
		};
		assert_eq!(out.clients.len(), 2);
		let first = out.clients.get(&ClientID::new(1)).expect("first entry carried over");
		assert_eq!(first.clock, 3);
		assert_eq!(&*first.json, r#"{"user":{"idTag":"@alice.example.com"}}"#);
		let second = out.clients.get(&ClientID::new(2)).expect("second entry rewritten");
		assert_eq!(second.clock, 4);
		let parsed: serde_json::Value =
			serde_json::from_str(&second.json).expect("rewritten entry is JSON");
		assert_eq!(parsed, serde_json::json!({ "user": { "idTag": "@alice.example.com" } }));
	}

	#[test]
	fn drops_an_undecodable_state() {
		// The caller relays nothing: a payload we cannot rewrite is precisely the one
		// that must not slip through unrewritten.
		let mut owners = owners();
		assert!(matches!(
			stamp_awareness_identity(
				&update_with("not json"),
				Some("@alice.example.com"),
				"conn-a",
				&mut owners
			),
			Stamped::Undecodable
		));
	}

	#[test]
	fn rejects_a_non_object_user_value() {
		// A `user` that is present but not an object cannot have an identity asserted
		// into it, so relaying it would be a hole straight through the rewrite.
		for json in [r#"{"user":"alice"}"#, r#"{"user":["a"]}"#] {
			let mut owners = owners();
			assert!(matches!(
				stamp_awareness_identity(
					&update_with(json),
					Some("@alice.example.com"),
					"conn-a",
					&mut owners
				),
				Stamped::Undecodable
			));
		}
	}

	#[test]
	fn relays_the_original_bytes_when_the_id_tag_already_matches() {
		// The common case on every cursor move: no re-serialise, no re-encode.
		assert!(is_unchanged(
			r#"{"user":{"name":"Alice","idTag":"@alice.example.com"}}"#,
			Some("@alice.example.com")
		));
	}

	#[test]
	fn a_guest_state_with_no_id_tag_is_unchanged() {
		assert!(is_unchanged(r#"{"user":{"name":"Guest"}}"#, None));
		assert!(is_unchanged("null", None));
		assert!(is_unchanged(r#"{"cursor":{"x":1}}"#, None));
	}

	// clientId ownership //
	//********************//

	#[test]
	fn claims_a_new_client_id_for_the_publishing_connection() {
		let mut owners = owners();
		let update = update_of(&[(1, 3, r#"{"user":{"name":"Alice"}}"#)]);
		let Stamped::Rewritten(out) =
			stamp_awareness_identity(&update, Some("@alice.example.com"), "conn-a", &mut owners)
		else {
			panic!("expected a rewrite");
		};
		let entry = out.clients.get(&ClientID::new(1)).expect("stamped");
		let parsed: serde_json::Value = serde_json::from_str(&entry.json).expect("JSON");
		assert_eq!(
			parsed,
			serde_json::json!({ "user": { "name": "Alice", "idTag": "@alice.example.com" } })
		);

		let owner = owners.owners.get(&ClientID::new(1)).expect("claimed");
		assert_eq!(&*owner.conn_id, "conn-a");
		assert_eq!(owner.clock, 3);
	}

	#[test]
	fn drops_a_peers_client_id_relayed_by_another_connection() {
		// The two-tab case: y-websocket re-broadcasts every awareness state a client
		// applies, so B's socket carries A's clientId. Stamping it with B's tag would
		// relabel A for everyone; the entry is dropped instead, and B's own entry in
		// the very same update still goes out stamped.
		let mut owners = owners();
		let a = update_of(&[(1, 3, r#"{"user":{"idTag":"@alice.example.com"}}"#)]);
		assert!(matches!(
			stamp_awareness_identity(&a, Some("@alice.example.com"), "conn-a", &mut owners),
			Stamped::Unchanged
		));

		let b = update_of(&[
			(1, 4, r#"{"user":{"idTag":"@alice.example.com"}}"#),
			(2, 1, r#"{"user":{"name":"Bob"}}"#),
		]);
		let Stamped::Rewritten(out) =
			stamp_awareness_identity(&b, Some("@bob.example.com"), "conn-b", &mut owners)
		else {
			panic!("expected a rewrite");
		};
		assert_eq!(out.clients.len(), 1, "A's clientId is not relayed by B");
		let entry = out.clients.get(&ClientID::new(2)).expect("B's own entry survives");
		let parsed: serde_json::Value = serde_json::from_str(&entry.json).expect("JSON");
		assert_eq!(
			parsed,
			serde_json::json!({ "user": { "name": "Bob", "idTag": "@bob.example.com" } })
		);

		// A's ownership and clock are untouched by B's relay.
		let owner = owners.owners.get(&ClientID::new(1)).expect("still A's");
		assert_eq!(&*owner.conn_id, "conn-a");
		assert_eq!(owner.clock, 3);
	}

	#[test]
	fn relays_nothing_when_every_entry_belongs_to_someone_else() {
		// The queryAwareness reply: a second tab answers with the whole roster and
		// none of it is its own.
		let mut owners = owners();
		let a = update_of(&[
			(1, 3, r#"{"user":{"idTag":"@alice.example.com"}}"#),
			(2, 3, r#"{"user":{"idTag":"@alice.example.com"}}"#),
		]);
		let _ = stamp_awareness_identity(&a, Some("@alice.example.com"), "conn-a", &mut owners);

		let b = update_of(&[
			(1, 4, r#"{"user":{"idTag":"@alice.example.com"}}"#),
			(2, 4, r#"{"user":{"idTag":"@alice.example.com"}}"#),
		]);
		assert!(matches!(
			stamp_awareness_identity(&b, Some("@alice.example.com"), "conn-b", &mut owners),
			Stamped::Empty
		));
	}

	#[test]
	fn keeps_the_highest_clock_for_an_owned_client_id() {
		// The disconnect removal has to out-clock everything peers have seen, so the
		// recorded clock must be the maximum rather than the latest.
		let mut owners = owners();
		for clock in [3, 9, 5] {
			let update = update_of(&[(1, clock, r#"{"user":{"idTag":"@alice.example.com"}}"#)]);
			let _ =
				stamp_awareness_identity(&update, Some("@alice.example.com"), "c1", &mut owners);
		}
		assert_eq!(owners.owners.get(&ClientID::new(1)).expect("owned").clock, 9);
	}

	#[test]
	fn caps_the_client_ids_one_connection_can_own() {
		// Awareness is ungated by `read_only`, so without a cap a single read-only
		// share-link visitor grows this per-document map without bound.
		let mut owners = owners();
		for i in 0..MAX_AWARENESS_CLIENT_IDS_PER_CONN as u64 {
			let update = update_of(&[(i + 1, 1, r#"{"user":{"idTag":"@alice.example.com"}}"#)]);
			let _ = stamp_awareness_identity(
				&update,
				Some("@alice.example.com"),
				"conn-a",
				&mut owners,
			);
		}
		assert_eq!(owners.owners.len(), MAX_AWARENESS_CLIENT_IDS_PER_CONN);

		// One past the cap: the entry is dropped from the relay and never recorded.
		let over = update_of(&[(9999, 1, r#"{"user":{"idTag":"@alice.example.com"}}"#)]);
		assert!(matches!(
			stamp_awareness_identity(&over, Some("@alice.example.com"), "conn-a", &mut owners),
			Stamped::Empty
		));
		assert_eq!(owners.owners.len(), MAX_AWARENESS_CLIENT_IDS_PER_CONN);
		assert!(!owners.owners.contains_key(&ClientID::new(9999)));
	}

	#[test]
	fn a_different_connection_gets_its_own_budget() {
		let mut owners = owners();
		for i in 0..MAX_AWARENESS_CLIENT_IDS_PER_CONN as u64 {
			let update = update_of(&[(i + 1, 1, r#"{"user":{"name":"Alice"}}"#)]);
			let _ = stamp_awareness_identity(
				&update,
				Some("@alice.example.com"),
				"conn-a",
				&mut owners,
			);
		}
		let b = update_of(&[(500, 1, r#"{"user":{"name":"Bob"}}"#)]);
		let _ = stamp_awareness_identity(&b, Some("@bob.example.com"), "conn-b", &mut owners);
		assert_eq!(&*owners.owners.get(&ClientID::new(500)).expect("claimed").conn_id, "conn-b");
	}

	#[test]
	fn disconnecting_returns_the_whole_budget() {
		// Without clearing `claimed`, a reconnecting tab would exhaust its budget after
		// enough reconnects even though it owns nothing.
		let mut owners = owners();
		let update = update_of(&[(1, 3, r#"{"user":{"name":"Alice"}}"#)]);
		let _ =
			stamp_awareness_identity(&update, Some("@alice.example.com"), "conn-a", &mut owners);
		let _ = drain_awareness_removal(&mut owners, "conn-a");
		assert_eq!(owners.claimed.get("conn-a").copied().unwrap_or(0), 0);
	}

	#[test]
	fn an_undecodable_entry_commits_no_ownership() {
		// The message is relayed to nobody, so it must not be able to squat a clientId
		// that a legitimate peer would then be unable to publish under.
		let mut owners = owners();
		let update = update_of(&[(1, 1, r#"{"user":{"name":"Alice"}}"#), (2, 1, "not json")]);
		assert!(matches!(
			stamp_awareness_identity(&update, Some("@alice.example.com"), "conn-a", &mut owners),
			Stamped::Undecodable
		));
		assert!(owners.owners.is_empty(), "a dropped message claims nothing");

		// …and the clientId is still free for its real owner.
		let legit = update_of(&[(1, 1, r#"{"user":{"name":"Bob"}}"#)]);
		let _ = stamp_awareness_identity(&legit, Some("@bob.example.com"), "conn-b", &mut owners);
		assert_eq!(&*owners.owners.get(&ClientID::new(1)).expect("claimed").conn_id, "conn-b");
	}

	// Disconnect removal //
	//********************//

	#[test]
	fn removal_carries_a_null_state_at_the_next_clock() {
		let mut owners = owners();
		let a = update_of(&[
			(1, 3, r#"{"user":{"idTag":"@alice.example.com"}}"#),
			(2, 8, r#"{"user":{"idTag":"@alice.example.com"}}"#),
		]);
		let _ = stamp_awareness_identity(&a, Some("@alice.example.com"), "conn-a", &mut owners);
		let b = update_of(&[(3, 1, r#"{"user":{"idTag":"@bob.example.com"}}"#)]);
		let _ = stamp_awareness_identity(&b, Some("@bob.example.com"), "conn-b", &mut owners);

		let removal = drain_awareness_removal(&mut owners, "conn-a");
		assert_eq!(removal.clients.len(), 2);
		for (client_id, expected_clock) in [(1, 4), (2, 9)] {
			let entry = removal.clients.get(&ClientID::new(client_id)).expect("removed");
			assert_eq!(entry.clock, expected_clock, "clock must beat what peers have seen");
			assert_eq!(&*entry.json, "null");
		}

		// Only this connection's clientIds are drained; Bob's stays owned.
		assert_eq!(owners.owners.len(), 1);
		assert_eq!(&*owners.owners.get(&ClientID::new(3)).expect("Bob's").conn_id, "conn-b");
	}

	#[test]
	fn a_reconnecting_tab_can_reclaim_its_client_id() {
		// Draining on disconnect is what lets the same clientId be claimed again —
		// a browser tab keeps its `doc.clientID` across a reconnect.
		let mut owners = owners();
		let update = update_of(&[(1, 3, r#"{"user":{"idTag":"@alice.example.com"}}"#)]);
		let _ =
			stamp_awareness_identity(&update, Some("@alice.example.com"), "conn-a", &mut owners);
		let _ = drain_awareness_removal(&mut owners, "conn-a");

		let again = update_of(&[(1, 4, r#"{"user":{"idTag":"@alice.example.com"}}"#)]);
		assert!(matches!(
			stamp_awareness_identity(&again, Some("@alice.example.com"), "conn-a2", &mut owners),
			Stamped::Unchanged
		));
		assert_eq!(&*owners.owners.get(&ClientID::new(1)).expect("reclaimed").conn_id, "conn-a2");
	}
}

// vim: ts=4
