// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! WebSocket upgrade handlers
//!
//! Routes WebSocket connections to appropriate protocol handlers:
//! - `/ws/bus` - Notification bus (presence, typing, actions, events)
//! - `/ws/file-changes` - `filesChanged` hints for a scoped device API key
//! - `/ws/rtdb/:file_id` - Real-time database changes for a file
//! - `/ws/crdt/:doc_id` - Collaborative document editing

use axum::{
	extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
	extract::{ConnectInfo, Path, RawQuery, State},
	http::HeaderMap,
	response::Response,
};
use cloudillo_types::extract::Query;
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use std::net::SocketAddr;
use tokio::sync::broadcast::error::RecvError;

use crate::crdt;
use crate::rtdb;
use cloudillo_core::OptionalAuth;
use cloudillo_core::audit;
use cloudillo_core::extract::IdTag;
use cloudillo_core::file_access::{self, FileAccessError};
use cloudillo_core::ws_bus::{self, BusMessage};
use cloudillo_types::auth_adapter::{AuditCategory, AuditEvent, AuthCtx};
use cloudillo_types::meta_adapter::{CreateFile, FileStatus};
use cloudillo_types::types::{AccessLevel, ScopeSet, TokenScope};
use cloudillo_types::utils::{normalize_id_tag, random_id};

/// Record `access.doc.open` once per accepted connection (gated by the `access` category).
/// `actor` is the asserted identity: `None` for a guest or an anonymous share-link token.
async fn audit_doc_open(
	app: &crate::app::App,
	tn_id: u32,
	actor: Option<&str>,
	addr: &SocketAddr,
	details: serde_json::Value,
) {
	let ev = AuditEvent {
		tn_id: Some(crate::types::TnId(tn_id)),
		details: Some(details),
		..AuditEvent::new(AuditCategory::Access, "access.doc.open", "success")
	};
	audit::record_by(app, ev, actor, addr).await;
}

/// Maximum size of a single inbound WebSocket frame.
///
/// axum/tungstenite default to 16 MiB frames and 64 MiB messages, which is far
/// more than any legitimate CRDT update / RTDB transaction / bus event and lets
/// a single connection pin large buffers. These caps bound per-connection
/// memory while staying generous enough for large collaborative documents.
const WS_MAX_FRAME_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

/// Maximum size of a reassembled inbound WebSocket message.
const WS_MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024; // 16 MiB

/// Apply the conservative frame/message size caps to a WebSocket upgrade.
/// Oversized frames/messages cause tungstenite to close the socket.
fn limit_ws(ws: WebSocketUpgrade) -> WebSocketUpgrade {
	ws.max_frame_size(WS_MAX_FRAME_SIZE).max_message_size(WS_MAX_MESSAGE_SIZE)
}

/// Query parameters for WebSocket file access endpoints
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AccessQuery {
	/// Requested access mode: "read", "comment" or "write"
	/// - "read": Force read-only mode (even if user has write permission)
	/// - "comment": Require comment permission
	/// - "write": Require write permission (reject if user only has read)
	/// - None: Use computed access level based on permissions
	///
	/// Read through [`AccessQuery::mode`], which falls back to `access`.
	pub mode: Option<String>,
	/// Pre-rename name of `mode`, still sent by stale cached bundles (and alongside `mode` by
	/// current clients, for older servers). Not a serde alias: an alias rejects a query that
	/// carries both. Without it a stale bundle's forced read-only would be silently dropped.
	// Drop once no client sends access= any more
	pub access: Option<String>,
	/// Container file_id when opening an embedded file (caps access by share entry)
	pub via: Option<String>,
	/// Opt in to the RTDB presence channel: `presence=true`.
	///
	/// Presence is connection-level, never a subscription — the flag is fixed for the
	/// socket's lifetime, which is what makes reconnect correct by construction: the
	/// URL carries it, so a reconnect re-enables presence and gets a fresh roster.
	/// `get_ws_crdt` shares this struct and ignores the field; CRDT awareness is
	/// always on there.
	#[serde(default, deserialize_with = "de_flag")]
	pub presence: bool,
}

impl AccessQuery {
	/// Requested access mode: `mode=`, else the legacy `access=`.
	pub fn mode(&self) -> Option<&str> {
		self.mode.as_deref().or(self.access.as_deref())
	}
}

/// Query-string bool that also takes the legacy `1` (stale bundles send `presence=1`);
/// anything else is false rather than a 400 for the whole query.
fn de_flag<'de, D: serde::Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
	Ok(matches!(String::deserialize(d)?.as_str(), "1" | "true"))
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

/// Determine final access level based on query parameter and computed access
///
/// Returns `Ok(AccessLevel)` or `Err(())` if write access was requested but not available
fn resolve_access(query: &AccessQuery, computed: AccessLevel) -> Result<AccessLevel, ()> {
	match query.mode() {
		Some("read") => Ok(AccessLevel::Read), // Force read-only
		Some("comment") => {
			// Comment requested: allow if computed is Comment or higher
			if computed.can_comment() { Ok(AccessLevel::Comment) } else { Err(()) }
		}
		Some("write") => {
			// Write requested: only if computed is Write or better
			if computed.can_write() { Ok(AccessLevel::Write) } else { Err(()) }
		}
		_ => Ok(computed), // Use computed access
	}
}

/// Validate a store file_id (`s~{app_id}` format)
///
/// Returns:
/// - `Ok(Some(app_id))` — valid store ID
/// - `Ok(None)` — not a store ID (no `s~` prefix)
/// - `Err(())` — has `s~` prefix but invalid app_id
fn validate_store_id(file_id: &str) -> Result<Option<&str>, ()> {
	let Some(app_id) = file_id.strip_prefix("s~") else {
		return Ok(None);
	};

	if app_id.is_empty() || app_id.len() > 64 {
		return Err(());
	}

	// External app format: name@domain
	if app_id.contains('@') {
		let parts: Vec<&str> = app_id.splitn(2, '@').collect();
		if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
			return Err(());
		}
		// Name part: alphanumeric + hyphens/underscores, starts with letter
		let name = parts[0];
		let first = name.as_bytes()[0];
		if !first.is_ascii_lowercase() {
			return Err(());
		}
		if !name
			.bytes()
			.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
		{
			return Err(());
		}
		// Domain part: basic check for valid hostname chars
		if !parts[1]
			.bytes()
			.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
		{
			return Err(());
		}
		return Ok(Some(app_id));
	}

	// Internal app format: alphanumeric + hyphens/underscores, starts with letter or `_`
	let first = app_id.as_bytes()[0];
	if !first.is_ascii_lowercase() && first != b'_' {
		return Err(());
	}
	if !app_id
		.bytes()
		.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
	{
		return Err(());
	}

	Ok(Some(app_id))
}

/// Auto-create a store file record if it does not already exist
///
/// Store files (`s~{app_id}`) are lazily created on first WebSocket connection.
/// The `file_tp` is set based on the endpoint ("RTDB" or "CRDT").
/// Creation is idempotent — concurrent calls for the same file_id are safe.
async fn ensure_store_file(
	app: &crate::app::App,
	tn_id: crate::types::TnId,
	store_file_id: &str,
	file_tp: &str,
	app_id: &str,
) -> Result<(), FileAccessError> {
	// Check if file already exists
	match app.meta_adapter.read_file(tn_id, store_file_id).await {
		Ok(Some(_)) => return Ok(()),
		Ok(None) => {} // Proceed to create
		Err(e) => return Err(FileAccessError::InternalError(e.to_string())),
	}

	// Create store file — idempotent (create_file with explicit file_id)
	let create_opts = CreateFile {
		file_id: Some(store_file_id.into()),
		file_tp: Some(file_tp.into()),
		content_type: "application/json".into(),
		file_name: app_id.into(),
		status: Some(FileStatus::Active),
		..Default::default()
	};

	match app.meta_adapter.create_file(tn_id, create_opts).await {
		Ok(_) => {
			cloudillo_core::search_index_file(app, tn_id, store_file_id);
			Ok(())
		}
		Err(_) => {
			// Race condition: another connection may have created it concurrently
			match app.meta_adapter.read_file(tn_id, store_file_id).await {
				Ok(Some(_)) => Ok(()),
				_ => Err(FileAccessError::InternalError("Failed to create store file".into())),
			}
		}
	}
}

/// Validate a meta database file_id (`{parent_file_id}~meta` format)
///
/// Returns:
/// - `Some(parent_file_id)` — valid meta ID, returns the parent file_id
/// - `None` — not a meta ID (no `~meta` suffix)
fn validate_meta_id(file_id: &str) -> Option<&str> {
	file_id.strip_suffix("~meta").filter(|parent| !parent.is_empty())
}

/// Auto-create a meta database file record if it does not already exist
///
/// Meta databases (`{file_id}~meta`) store comments and other metadata
/// separate from the document content. They are lazily created on first
/// WebSocket connection. Access is inherited from the parent file.
/// Creation is idempotent — concurrent calls for the same file_id are safe.
pub async fn ensure_meta_file(
	app: &crate::app::App,
	tn_id: crate::types::TnId,
	meta_file_id: &str,
	parent_file_id: &str,
) -> Result<(), FileAccessError> {
	// Check if meta file already exists
	match app.meta_adapter.read_file(tn_id, meta_file_id).await {
		Ok(Some(_)) => return Ok(()),
		Ok(None) => {} // Proceed to create
		Err(e) => return Err(FileAccessError::InternalError(e.to_string())),
	}

	// A part joins its root's drive: the tree's channel filters must see it with the root.
	let channel = match app.meta_adapter.read_file(tn_id, parent_file_id).await {
		Ok(root) => root.and_then(|r| r.channel),
		Err(e) => return Err(FileAccessError::InternalError(e.to_string())),
	};

	// Create meta file — idempotent (create_file with explicit file_id)
	let create_opts = CreateFile {
		file_id: Some(meta_file_id.into()),
		file_tp: Some("RTDB".into()),
		content_type: "application/json".into(),
		file_name: meta_file_id.into(),
		status: Some(FileStatus::Active),
		root_id: Some(parent_file_id.into()),
		channel,
		..Default::default()
	};

	match app.meta_adapter.create_file(tn_id, create_opts).await {
		Ok(_) => {
			cloudillo_core::search_index_file(app, tn_id, meta_file_id);
			Ok(())
		}
		Err(_) => {
			// Race condition: another connection may have created it concurrently
			match app.meta_adapter.read_file(tn_id, meta_file_id).await {
				Ok(Some(_)) => Ok(()),
				_ => Err(FileAccessError::InternalError("Failed to create meta file".into())),
			}
		}
	}
}

/// Create WebSocket close response for invalid store ID
fn ws_close_invalid_store(ws: WebSocketUpgrade) -> Response {
	ws.on_upgrade(|socket| close_with_error(socket, 4400, "Invalid store ID"))
}

/// Create WebSocket close response for store type mismatch
fn ws_close_type_mismatch(ws: WebSocketUpgrade) -> Response {
	ws.on_upgrade(|socket| close_with_error(socket, 4409, "Store type mismatch"))
}

/// Which file WebSocket endpoint is asking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsKind {
	Crdt,
	Rtdb,
}

/// Why `ws_file_access` refused a connection
pub enum WsDeny {
	/// The file access check failed (not found / denied / internal)
	Access(FileAccessError),
	/// `?mode=` asked for more than the subject has
	WriteDenied,
	/// An `s~` store file exists with the other endpoint's type
	TypeMismatch,
	/// An `s~` id with an invalid app id
	InvalidStore,
}

impl std::fmt::Display for WsDeny {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(match self {
			WsDeny::Access(FileAccessError::NotFound) => "not_found",
			WsDeny::Access(FileAccessError::AccessDenied) => "access_denied",
			WsDeny::Access(FileAccessError::InternalError(_)) => "internal_error",
			WsDeny::WriteDenied => "write_denied",
			WsDeny::TypeMismatch => "type_mismatch",
			WsDeny::InvalidStore => "invalid_store",
		})
	}
}

fn ws_close_for_deny(ws: WebSocketUpgrade, deny: &WsDeny) -> Response {
	match deny {
		WsDeny::Access(e) => ws_close_for_error(ws, e),
		WsDeny::WriteDenied => ws_close_write_denied(ws),
		WsDeny::TypeMismatch => ws_close_type_mismatch(ws),
		WsDeny::InvalidStore => ws_close_invalid_store(ws),
	}
}

/// Lazily creates an `s~` store row ahead of [`ws_file_access`], but only for a caller who may
/// create content (unscoped, contributor or above, as `check_perm_create`); for anyone
/// else the missing row is refused there. Anything but a store id is left alone.
pub async fn ws_prepare_store(
	app: &crate::app::App,
	tn_id: crate::types::TnId,
	auth: Option<&cloudillo_types::auth_adapter::AuthCtx>,
	file_id: &str,
	kind: WsKind,
) -> Result<(), WsDeny> {
	let app_id = match validate_store_id(file_id) {
		Ok(Some(app_id)) => app_id,
		Ok(None) => return Ok(()),
		Err(()) => return Err(WsDeny::InvalidStore),
	};
	let creator =
		auth.is_some_and(|a| a.scope.is_none() && cloudillo_core::roles::is_contributor(&a.roles));
	if !creator {
		return Ok(());
	}
	let file_tp = match kind {
		WsKind::Crdt => "CRDT",
		WsKind::Rtdb => "RTDB",
	};
	ensure_store_file(app, tn_id, file_id, file_tp, app_id)
		.await
		.map_err(WsDeny::Access)
}

/// The pre-upgrade access decision for `/ws/rtdb/{id}` and `/ws/crdt/{id}`.
///
/// Pure with respect to the connection: no store/meta auto-creation (the handlers do
/// that first). A `{parent}~meta` RTDB file is checked against its parent. Guests
/// (`auth: None`) get Read; RTDB downgrades Comment to Read outside meta databases.
///
/// Returns the level and the resolved content id (`{content}~meta` for a meta id): an entry id
/// in the path must open the content's document, not a new one named after the entry.
pub async fn ws_file_access(
	app: &crate::app::App,
	tn_id: crate::types::TnId,
	tenant_id_tag: &str,
	auth: Option<&cloudillo_types::auth_adapter::AuthCtx>,
	file_id: &str,
	query: &AccessQuery,
	kind: WsKind,
) -> Result<(AccessLevel, String), WsDeny> {
	let (store_tp, meta_parent) = match kind {
		WsKind::Crdt => ("CRDT", None),
		WsKind::Rtdb => ("RTDB", validate_meta_id(file_id)),
	};

	// Check file access (with scope for share links)
	let ctx = file_access::FileAccessCtx::from_auth(auth, tenant_id_tag);
	let result = file_access::check_file_access(
		app,
		tn_id,
		meta_parent.unwrap_or(file_id),
		&ctx,
		query.via.as_deref(),
	)
	.await
	.map_err(WsDeny::Access)?;
	// A reference (Pin / Place / FSHR) holds no content here: its document lives upstream.
	if result.file_view.upstream_tag.is_some() {
		return Err(WsDeny::Access(FileAccessError::NotFound));
	}

	// Verify store type matches endpoint
	if file_id.starts_with("s~") && result.file_view.file_tp.as_deref() != Some(store_tp) {
		return Err(WsDeny::TypeMismatch);
	}

	// A folder has no content to open.
	let Some(file_id) = result.file_view.file_id.as_deref() else {
		return Err(WsDeny::Access(FileAccessError::NotFound));
	};
	let content_id = match meta_parent {
		Some(_) => format!("{file_id}~meta"),
		None => file_id.to_string(),
	};
	// Guests are always read-only
	if auth.is_none() {
		return Ok((AccessLevel::Read, content_id));
	}
	let al = resolve_access(query, result.access_level).map_err(|()| WsDeny::WriteDenied)?;
	// For non-meta RTDB, downgrade Comment to Read (comment users can only write to
	// meta databases, not the main document RTDB)
	if kind == WsKind::Rtdb && meta_parent.is_none() && al == AccessLevel::Comment {
		return Ok((AccessLevel::Read, content_id));
	}
	Ok((al, content_id))
}

/// Who may open the tenant bus: the tenant account's own session, nobody else. The bus carries
/// the tenant's traffic (inbound actions, file and maintenance events), and the shell only ever
/// connects to its own tenant's bus. A member, a visitor, a scoped token or an API key (`cl_`,
/// `idp_`; no `exp`) is refused.
pub fn ws_bus_admission(a: &cloudillo_types::auth_adapter::AuthCtx, tenant_id_tag: &str) -> bool {
	a.exp.is_some() && cloudillo_core::abac::is_tenant_account(a, tenant_id_tag)
}

/// WebSocket upgrade handler for the notification bus; admission is [`ws_bus_admission`].
pub async fn get_ws_bus(
	ws: WebSocketUpgrade,
	State(app): State<crate::app::App>,
	IdTag(tenant_id_tag): IdTag,
	OptionalAuth(auth): OptionalAuth,
) -> Response {
	use tracing::{debug, warn};

	debug!("WebSocket bus request");

	let ws = limit_ws(ws);
	let Some(auth_ctx) = auth else {
		warn!("Bus WebSocket rejected - no authentication");
		return ws_close_unauthenticated(ws);
	};
	if !ws_bus_admission(&auth_ctx, &tenant_id_tag) {
		warn!(subject = %auth_ctx.id_tag, "Bus WebSocket rejected - not the tenant account");
		return ws_close_for_error(ws, &FileAccessError::AccessDenied);
	}

	let user_id = auth_ctx.id_tag.to_string();
	let tn_id = auth_ctx.tn_id;
	debug!("Bus WebSocket authenticated: user_id={}, tn_id={}", user_id, tn_id.0);
	ws.on_upgrade(move |socket| ws_bus::handle_bus_connection(socket, user_id, tn_id, app))
}

/// Who may open `/ws/file-changes`: an API key (no `exp`) of the host tenant whose scope has a
/// file or drive entry. Sessions and share links (`exp`), unscoped, `idp_`, DAV, notification,
/// `apkg:` and `rfile:` keys are refused. The tenant test compares id_tags directly:
/// `abac::is_tenant_account` requires an unscoped credential, so it rejects every scoped key.
/// Hints are confined to the key's scope ([`hint_in_scope`]).
pub fn ws_file_changes_admission(a: &AuthCtx, tenant_id_tag: &str) -> bool {
	a.exp.is_none()
		&& &*a.id_tag == tenant_id_tag
		&& a.scope.as_deref().and_then(ScopeSet::parse).is_some_and(|s| {
			matches!(s.delegated, Some(TokenScope::File { .. } | TokenScope::Drive { .. }))
		})
}

/// WebSocket upgrade handler for `filesChanged` hints; admission is
/// [`ws_file_changes_admission`]. The client refetches `GET /api/file-changes` on each hint.
pub async fn get_ws_file_changes(
	ws: WebSocketUpgrade,
	State(app): State<crate::app::App>,
	IdTag(tenant_id_tag): IdTag,
	OptionalAuth(auth): OptionalAuth,
	headers: HeaderMap,
	RawQuery(query): RawQuery,
) -> Response {
	use tracing::warn;

	let ws = limit_ws(ws);
	let Some(auth_ctx) = auth else {
		warn!("File-changes WebSocket rejected - no authentication");
		return ws_close_unauthenticated(ws);
	};
	if !ws_file_changes_admission(&auth_ctx, &tenant_id_tag) {
		warn!(subject = %auth_ctx.id_tag, "File-changes WebSocket rejected - not a scoped tenant key");
		return ws_close_for_error(ws, &FileAccessError::AccessDenied);
	}

	// The raw key, the same way `authenticate` reads it, for the periodic revocation recheck.
	let token = match headers.get("Authorization").and_then(|h| h.to_str().ok()) {
		Some(h) => h.strip_prefix("Bearer ").map(|t| t.trim().to_string()),
		None => {
			cloudillo_core::middleware::extract_token_from_query(query.as_deref().unwrap_or(""))
		}
	};
	let Some(token) = token else {
		return ws_close_unauthenticated(ws);
	};

	ws.on_upgrade(move |socket| {
		handle_file_changes_connection(socket, auth_ctx, tenant_id_tag, token, app)
	})
}

/// How often an open `/ws/file-changes` socket rechecks that its key still exists unchanged.
const KEY_RECHECK: std::time::Duration = std::time::Duration::from_mins(5);

/// Whether a `filesChanged` broadcast (`data.entries`) concerns a key scoped by `auth.scope`:
/// some entry lies in a `file:` scope's live folder, or is readable under a drive scope.
/// No entries means "location unknown": true. Errors and NotFound fail closed.
async fn hint_in_scope(
	app: &crate::app::App,
	auth: &AuthCtx,
	tenant_id_tag: &str,
	data: &serde_json::Value,
) -> bool {
	let entries: Vec<&str> = data["entries"]
		.as_array()
		.map(|a| a.iter().filter_map(serde_json::Value::as_str).collect())
		.unwrap_or_default();
	if entries.is_empty() {
		return true;
	}
	let Some(scope) = auth.scope.as_deref() else { return false };
	// one ancestry walk per hint per socket (DirCache memoized); batch if
	// file-change sockets get numerous.
	if file_access::drive_scope(Some(scope)).is_some() {
		let ctx = file_access::FileAccessCtx::from_auth(Some(auth), tenant_id_tag);
		for id in entries {
			if let Ok(r) = file_access::check_file_access(app, auth.tn_id, id, &ctx, None).await
				&& r.access_level.can_read()
			{
				return true;
			}
		}
		return false;
	}
	for id in entries {
		if matches!(file_access::within_scope_folder(app, auth.tn_id, scope, id).await, Ok(true)) {
			return true;
		}
	}
	false
}

/// Forward the tenant's `filesChanged` broadcasts that concern the key's scope
/// ([`hint_in_scope`]), nothing else; inbound frames are dropped. Closes once the key is
/// revoked or its scope changed, checked every [`KEY_RECHECK`].
async fn handle_file_changes_connection(
	socket: WebSocket,
	auth_ctx: AuthCtx,
	tenant_id_tag: Box<str>,
	token: String,
	app: crate::app::App,
) {
	use cloudillo_core::ws_broadcast::FILE_CHANGES_SLOT;
	let tn_id = auth_ctx.tn_id;
	let mut last_checked = std::time::Instant::now();
	let conn_id = random_id().unwrap_or_default();
	let mut rx = app.broadcast.register_user(tn_id, FILE_CHANGES_SLOT, &conn_id).await;
	let (mut tx, mut inbound) = socket.split();
	let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(30));
	// Always an empty hint, whatever the broadcast carried: the key's view of the change is
	// the feed it refetches, which `get_file_changes` confines to its scope.
	let hint = || BusMessage::new("filesChanged", serde_json::json!({})).to_ws_message().ok();

	loop {
		let frame = tokio::select! {
			msg = rx.recv() => match msg {
				Ok(m) if m.cmd == "filesChanged" => {
					if !hint_in_scope(&app, &auth_ctx, &tenant_id_tag, &m.data).await {
						continue;
					}
					hint()
				}
				Ok(_) => continue,
				// A skipped message may have been a hint; the client refetches regardless.
				Err(RecvError::Lagged(_)) => hint(),
				Err(RecvError::Closed) => break,
			},
			msg = inbound.next() => match msg {
				Some(Ok(Message::Close(_)) | Err(_)) | None => break,
				Some(Ok(_)) => continue,
			},
			_ = heartbeat.tick() => {
				if last_checked.elapsed() >= KEY_RECHECK {
					// the key check is a hash verify on the worker pool, so it runs at
					// most every 5 minutes, and a revoked key keeps its socket up to that long.
					let live = app.auth_adapter.validate_api_key(&token).await.is_ok_and(|v| {
						v.tn_id == tn_id && v.scopes == auth_ctx.scope
					});
					if !live {
						break;
					}
					last_checked = std::time::Instant::now();
				}
				Some(Message::Ping(vec![].into()))
			}
		};
		let Some(frame) = frame else { continue };
		if tx.send(frame).await.is_err() {
			break;
		}
	}

	app.broadcast.unregister_user(tn_id, FILE_CHANGES_SLOT, &conn_id).await;
}

/// WebSocket upgrade handler for RTDB subscriptions
///
/// Route: `/ws/rtdb/:file_id`
/// Query params: `?mode=read` or `?mode=write`, `?presence=true` to opt in to the
/// presence channel.
/// Requires authentication.
/// Connects to real-time database changes for a specific file.
/// Checks file access level and passes read_only flag to connection handler.
#[expect(clippy::too_many_arguments, reason = "axum extractors")]
pub async fn get_ws_rtdb(
	ws: WebSocketUpgrade,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Path(file_id): Path<String>,
	Query(query): Query<AccessQuery>,
	State(app): State<crate::app::App>,
	crate::types::TnId(tn_id): crate::types::TnId,
	IdTag(tenant_id_tag): IdTag,
	OptionalAuth(auth): OptionalAuth,
) -> Response {
	use tracing::{info, warn};

	info!("WebSocket RTDB request for file_id: {}, mode={:?}", file_id, query.mode());

	let ws = limit_ws(ws);
	let is_guest = auth.is_none();
	let presence_enabled = query.presence;

	// Asserted identity: only a credential that names a person may be asserted as a lock
	// holder or as the author of per-user file activity. A share-link token has no `sub`,
	// so `AuthCtx::id_tag` fell back to `iss` — the tenant OWNER — and passing that down
	// would let an untrusted visitor take, hold and break hard locks as the owner. A
	// `file:`-scoped token minted for a signed-in user (cloudillo-auth `?via=`) is NOT
	// anonymous and keeps its real identity.
	//
	// Canonicalised here rather than downstream: this is the RTDB lock owner and is
	// matched byte-exact, while `record_file_access` normalises internally — the two must
	// not disagree.
	let identity_id_tag = auth
		.as_ref()
		.filter(|ctx| !ctx.anonymous)
		.map(|ctx| normalize_id_tag(&ctx.id_tag).into_owned());

	let user_id = auth.as_ref().map(|a| a.id_tag.to_string()).unwrap_or_default();
	let user_tn_id = auth.as_ref().map_or(crate::types::TnId(tn_id), |a| a.tn_id);

	let kind = WsKind::Rtdb;
	if let Err(deny) =
		ws_prepare_store(&app, crate::types::TnId(tn_id), auth.as_ref(), &file_id, kind).await
	{
		warn!("RTDB WebSocket rejected ({}): user={}, file={}", deny, user_id, file_id);
		return ws_close_for_deny(ws, &deny);
	}

	let (access_level, content_id) = match ws_file_access(
		&app,
		crate::types::TnId(tn_id),
		&tenant_id_tag,
		auth.as_ref(),
		&file_id,
		&query,
		kind,
	)
	.await
	{
		Ok(res) => res,
		Err(deny) => {
			warn!("RTDB WebSocket rejected ({}): user={}, file={}", deny, user_id, file_id);
			return ws_close_for_deny(ws, &deny);
		}
	};

	// Auto-create meta database for authenticated users, once access is granted.
	// Meta DBs ({parent_content_id}~meta) store comments and metadata
	if !is_guest
		&& let Some(parent_id) = validate_meta_id(&content_id)
		&& let Err(e) =
			ensure_meta_file(&app, crate::types::TnId(tn_id), &content_id, parent_id).await
	{
		return ws_close_for_error(ws, &e);
	}
	info!(
		"RTDB WebSocket ({}): user={}, file={}",
		access_level.as_str(),
		if is_guest { "*guest" } else { &user_id },
		file_id
	);
	audit_doc_open(
		&app,
		tn_id,
		identity_id_tag.as_deref(),
		&addr,
		serde_json::json!({
			"fileId": file_id,
			"contentId": content_id,
			"access": access_level.as_str(),
			"kind": "rtdb",
		}),
	)
	.await;
	ws.on_upgrade(move |socket| {
		// `identity_id_tag`, deliberately *not* `is_guest` — that only governs meta-file
		// auto-creation above, and a `file:{id}:W` share-link visitor keeps write access while
		// losing only the asserted identity.
		rtdb::handle_rtdb_connection(
			socket,
			identity_id_tag,
			content_id,
			app,
			user_tn_id,
			access_level,
			presence_enabled,
		)
	})
}

/// WebSocket upgrade handler for CRDT documents
///
/// Route: `/ws/crdt/:doc_id`
/// Query params: `?mode=read` or `?mode=write`
/// Supports authenticated and guest (unauthenticated) access.
/// Guest access is read-only and only allowed for public files.
/// Checks file access level and passes read_only flag to connection handler.
#[expect(clippy::too_many_arguments, reason = "axum extractors")]
pub async fn get_ws_crdt(
	ws: WebSocketUpgrade,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Path(doc_id): Path<String>,
	Query(query): Query<AccessQuery>,
	State(app): State<crate::app::App>,
	crate::types::TnId(tn_id): crate::types::TnId,
	IdTag(tenant_id_tag): IdTag,
	OptionalAuth(auth): OptionalAuth,
) -> Response {
	use tracing::{info, warn};

	info!("WebSocket CRDT request for doc_id: {}, mode={:?}", doc_id, query.mode());

	let ws = limit_ws(ws);
	let is_guest = auth.is_none();

	// Awareness identity: only a credential that names a person may be asserted on the
	// wire. A share-link token has no `sub`, so `AuthCtx::id_tag` fell back to `iss` —
	// the tenant OWNER — and stamping that would make an untrusted visitor appear as the
	// document owner in everyone's roster. A `file:`-scoped token minted for a signed-in
	// user (cloudillo-auth `?via=`) is NOT anonymous and keeps its real identity.
	//
	// Canonicalised here rather than downstream: this is the identity peers see and is
	// matched byte-exact against what `record_file_access` normalises internally — the
	// two must not disagree.
	let awareness_id_tag = auth
		.as_ref()
		.filter(|ctx| !ctx.anonymous)
		.map(|ctx| normalize_id_tag(&ctx.id_tag).into_owned());

	let user_id = auth.as_ref().map(|a| a.id_tag.to_string()).unwrap_or_default();
	let user_tn_id = auth.as_ref().map_or(crate::types::TnId(tn_id), |a| a.tn_id);

	let kind = WsKind::Crdt;
	if let Err(deny) =
		ws_prepare_store(&app, crate::types::TnId(tn_id), auth.as_ref(), &doc_id, kind).await
	{
		warn!("CRDT WebSocket rejected ({}): user={}, file={}", deny, user_id, doc_id);
		return ws_close_for_deny(ws, &deny);
	}

	let (access_level, content_id) = match ws_file_access(
		&app,
		crate::types::TnId(tn_id),
		&tenant_id_tag,
		auth.as_ref(),
		&doc_id,
		&query,
		kind,
	)
	.await
	{
		Ok(res) => res,
		Err(deny) => {
			warn!("CRDT WebSocket rejected ({}): user={}, doc={}", deny, user_id, doc_id);
			return ws_close_for_deny(ws, &deny);
		}
	};
	// CRDT: only Write-or-better can edit; Comment (and a guest's Read) is read-only
	let read_only = !access_level.can_write();
	info!(
		"CRDT WebSocket ({}): user={}, doc={}",
		if read_only { "read-only" } else { "read-write" },
		if is_guest { "*guest" } else { &user_id },
		doc_id
	);
	audit_doc_open(
		&app,
		tn_id,
		awareness_id_tag.as_deref(),
		&addr,
		serde_json::json!({
			"fileId": doc_id,
			"contentId": content_id,
			"access": access_level.as_str(),
			"readOnly": read_only,
			"kind": "crdt",
		}),
	)
	.await;
	ws.on_upgrade(move |socket| {
		// `awareness_id_tag`, deliberately *not* `is_guest`: a `file:{id}:W` share-link
		// visitor keeps write access while losing only the asserted identity.
		crdt::handle_crdt_connection(
			socket,
			awareness_id_tag,
			content_id,
			app,
			user_tn_id,
			read_only,
		)
	})
}

#[cfg(test)]
mod tests {
	use super::{AccessQuery, ws_bus_admission, ws_file_changes_admission};
	use cloudillo_types::auth_adapter::AuthCtx;
	use cloudillo_types::types::{Timestamp, TnId};

	fn ctx(scope: Option<&str>, exp: Option<Timestamp>, roles: &[&str]) -> AuthCtx {
		AuthCtx {
			tn_id: TnId(1),
			id_tag: "alice.idp.test".into(),
			roles: roles.iter().map(|r| Box::from(*r)).collect(),
			scope: scope.map(Box::from),
			anonymous: false,
			hat: None,
			exp,
			auth_time: None,
		}
	}

	#[test]
	fn bus_admits_only_the_tenant_account() {
		let exp = Some(Timestamp::from_now(60));
		let host = "alice.idp.test";
		// The account's own session.
		assert!(ws_bus_admission(&ctx(None, exp, &["leader"]), host));
		// An `idp_` key on its own IdP host (no scope, no expiry, no roles); a key or an
		// API key of the account (no expiry); a scoped token.
		assert!(!ws_bus_admission(&ctx(None, None, &[]), host));
		assert!(!ws_bus_admission(&ctx(None, None, &["leader"]), host));
		assert!(!ws_bus_admission(&ctx(Some("file:f1~x:R"), exp, &["leader"]), host));
		// Another tenant's session, a leader or moderator there included.
		assert!(!ws_bus_admission(&ctx(None, exp, &["leader"]), "club.test"));
		assert!(!ws_bus_admission(&ctx(None, exp, &["moderator"]), "club.test"));
	}

	#[test]
	fn file_changes_admits_only_scoped_tenant_keys() {
		let exp = Some(Timestamp::from_now(60));
		let host = "alice.idp.test";
		// File- and drive-scoped API keys of the tenant (no expiry).
		for s in ["file:f1~x:R", "file:*:R", "file:__root__:W", "file:*:R,notifications:read"] {
			assert!(ws_file_changes_admission(&ctx(Some(s), None, &["leader"]), host), "{s}");
		}
		// A share link and a session carry `exp`.
		assert!(!ws_file_changes_admission(&ctx(Some("file:f1~x:R"), exp, &[]), host));
		assert!(!ws_file_changes_admission(&ctx(None, exp, &["leader"]), host));
		// An unscoped tenant key; an `idp_` key (no scope, no expiry, no roles).
		assert!(!ws_file_changes_admission(&ctx(None, None, &["leader"]), host));
		assert!(!ws_file_changes_admission(&ctx(None, None, &[]), host));
		// Keys without a file or drive entry, and a malformed scope.
		for s in [
			"carddav:read",
			"notifications:read",
			"apkg:publish",
			"rfile:bob.example:f1~x:R",
			"bogus",
			"",
		] {
			assert!(!ws_file_changes_admission(&ctx(Some(s), None, &["leader"]), host), "{s}");
		}
		// Another tenant's key.
		assert!(!ws_file_changes_admission(&ctx(Some("file:*:R"), None, &["leader"]), "club.test"));
	}

	fn query(q: &str) -> AccessQuery {
		let uri: axum::http::Uri = format!("/ws?{q}").parse().unwrap();
		axum::extract::Query::<AccessQuery>::try_from_uri(&uri).unwrap().0
	}

	#[test]
	fn access_query_accepts_legacy_and_new_forms() {
		let q = query("access=read&presence=1");
		assert_eq!(q.mode(), Some("read"));
		assert!(q.presence);
		let q = query("mode=write&presence=true");
		assert_eq!(q.mode(), Some("write"));
		assert!(q.presence);
		let q = query("mode=read&access=read");
		assert_eq!(q.mode(), Some("read"));
		let q = query("token=x");
		assert_eq!(q.mode(), None);
		assert!(!q.presence);
	}
}

// vim: ts=4
