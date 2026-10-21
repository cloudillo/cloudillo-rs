// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! `GET/POST /api/admin/backup` — backup status and a manual run.
//!
//! The work is [`cloudillo_core::backup`]; the daily run is scheduled from `backup.time`.
//! Gated by `admin::perm::require_admin` through the router it is mounted on.

use std::net::SocketAddr;

use axum::{
	Json,
	extract::{ConnectInfo, State},
	http::StatusCode,
};
use serde::Serialize;

use cloudillo_core::audit::ip_of;
use cloudillo_core::backup::{self, BackupState, LastRun, SnapshotInfo};
use cloudillo_core::extract::Auth;
use cloudillo_types::types::ApiResponse;

use crate::prelude::*;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupStatus {
	pub running: bool,
	/// Last run since the server started; `null` before the first one.
	pub last: Option<LastRun>,
	/// Completed snapshots, newest first.
	pub snapshots: Vec<SnapshotInfo>,
}

/// GET /api/admin/backup — running flag, last outcome, snapshots on disk.
#[axum::debug_handler]
pub async fn get_backup(State(app): State<App>) -> ClResult<Json<ApiResponse<BackupStatus>>> {
	let state = app.ext::<BackupState>()?;
	let status = BackupStatus {
		running: state.is_running(),
		last: state.last(),
		snapshots: backup::list_snapshots(&app).await?,
	};
	Ok(Json(ApiResponse::new(status)))
}

/// POST /api/admin/backup — start a run in the background. 202, or 409 if one is running.
/// The outcome shows up in `GET /api/admin/backup` and as an `admin.backup` audit event.
#[axum::debug_handler]
pub async fn post_backup(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Auth(auth_ctx): Auth,
) -> ClResult<StatusCode> {
	backup::start_backup(&app, &auth_ctx.id_tag, &ip_of(&addr))?;
	info!(actor = %auth_ctx.id_tag, "Backup requested");
	Ok(StatusCode::ACCEPTED)
}

// vim: ts=4
