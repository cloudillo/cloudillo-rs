// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Admin audit trail: `admin.*` event helper, `GET /api/admin/audit` and its CSV export.

use axum::{
	Json,
	extract::{Query, State},
	http::{StatusCode, header},
	response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use cloudillo_core::audit;
use cloudillo_types::auth_adapter::{AuditCategory, AuditEventRow, AuditQuery};
use cloudillo_types::types::ApiResponse;

use crate::prelude::*;

/// Hard cap on CSV export rows.
const CSV_MAX_ROWS: usize = 100_000;
const CSV_COLUMNS: [&str; 9] =
	["id", "ts", "tnId", "actor", "event", "category", "ip", "outcome", "details"];

/// Record one `admin.*` event (always on; never fails the caller). `outcome` is `"success"`
/// or `"fail"`.
pub(crate) async fn record_admin(
	app: &App,
	event: &str,
	outcome: &str,
	tn_id: Option<TnId>,
	actor: &str,
	addr: &SocketAddr,
	details: serde_json::Value,
) {
	let (cat, details) = (AuditCategory::Admin, Some(details));
	audit::record_event(app, cat, event, outcome, tn_id, Some(actor), addr, details).await;
}

/// Query of `GET /api/admin/audit[.csv]`. `from`/`to` are unix seconds (inclusive), `event` is
/// a prefix. `tnId` or `idTag` narrows to one tenant; without either, every row (incl.
/// server-wide ones) is returned.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminAuditQuery {
	pub tn_id: Option<u32>,
	pub id_tag: Option<String>,
	pub from: Option<i64>,
	pub to: Option<i64>,
	pub category: Option<String>,
	pub event: Option<String>,
	pub actor: Option<String>,
	pub outcome: Option<String>,
	pub limit: Option<u32>,
	pub cursor: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminAuditRes {
	pub events: Vec<AuditEventRow>,
	pub next_cursor: Option<i64>,
}

async fn to_query(app: &App, q: AdminAuditQuery) -> ClResult<AuditQuery> {
	let tn_id = match (q.tn_id, q.id_tag.as_deref()) {
		(Some(t), _) => Some(TnId(t)),
		(None, Some(id_tag)) => Some(app.auth_adapter.read_tn_id(id_tag).await?),
		(None, None) => None,
	};
	Ok(AuditQuery {
		tn_id,
		from: q.from.map(Timestamp),
		to: q.to.map(Timestamp),
		category: audit::parse_category(q.category.as_deref())?,
		event_prefix: q.event.map(Into::into),
		actor: q.actor.map(Into::into),
		outcome: q.outcome.map(Into::into),
		limit: Some(audit::page_limit(q.limit)),
		cursor: q.cursor,
	})
}

/// GET /api/admin/audit - All audit rows, filtered and paged (newest first).
pub async fn list_audit(
	State(app): State<App>,
	Query(q): Query<AdminAuditQuery>,
) -> ClResult<(StatusCode, Json<ApiResponse<AdminAuditRes>>)> {
	let (events, next_cursor) = audit::list_page(&app, to_query(&app, q).await?).await?;
	Ok((StatusCode::OK, Json(ApiResponse::new(AdminAuditRes { events, next_cursor }))))
}

/// GET /api/admin/audit.csv - Same filters as the list, every page up to `CSV_MAX_ROWS` rows.
/// `limit` is the page size used internally; `cursor` is the starting point.
pub async fn export_audit_csv(
	State(app): State<App>,
	Query(q): Query<AdminAuditQuery>,
) -> ClResult<impl IntoResponse> {
	let mut query = to_query(&app, q).await?;
	query.limit = Some(audit::MAX_LIMIT);

	let mut out = CSV_COLUMNS.join(",");
	out.push_str("\r\n");
	let mut rows = 0;
	while rows < CSV_MAX_ROWS {
		let (page, next) = audit::list_page(&app, query.clone()).await?;
		for row in page.iter().take(CSV_MAX_ROWS - rows) {
			push_csv_row(&mut out, row)?;
		}
		rows += page.len();
		match next {
			Some(cursor) => query.cursor = Some(cursor),
			None => break,
		}
	}

	Ok((
		[
			(header::CONTENT_TYPE, "text/csv; charset=utf-8"),
			(header::CONTENT_DISPOSITION, "attachment; filename=\"audit.csv\""),
		],
		out,
	))
}

/// Append one CSV line. Cells come from the row's JSON form, so `ts` matches the list API.
fn push_csv_row(out: &mut String, row: &AuditEventRow) -> ClResult<()> {
	let v = serde_json::to_value(row)?;
	for (i, col) in CSV_COLUMNS.iter().enumerate() {
		if i > 0 {
			out.push(',');
		}
		let cell = match v.get(*col) {
			None | Some(serde_json::Value::Null) => String::new(),
			Some(serde_json::Value::String(s)) => s.clone(),
			Some(other) => other.to_string(),
		};
		out.push_str(&csv_cell(&cell));
	}
	out.push_str("\r\n");
	Ok(())
}

/// RFC 4180 quoting, plus a leading `'` on cells a spreadsheet would run as a formula.
fn csv_cell(s: &str) -> String {
	let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
		format!("'{s}")
	} else {
		s.to_string()
	};
	if s.contains([',', '"', '\n', '\r']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s }
}

#[cfg(test)]
mod tests {
	use super::csv_cell;

	#[test]
	fn csv_cell_quotes_and_defuses_formulas() {
		assert_eq!(csv_cell("plain"), "plain");
		assert_eq!(csv_cell("a,b"), "\"a,b\"");
		assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
		assert_eq!(csv_cell("=1+1"), "'=1+1");
		assert_eq!(csv_cell("-x,y"), "\"'-x,y\"");
	}
}

// vim: ts=4
