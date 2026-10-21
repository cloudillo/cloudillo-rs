// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Audit trail store (append, list, purge). No update or delete-by-id path exists.

use sqlx::{Row, SqlitePool};

use crate::utils::Db;
use cloudillo_types::{
	auth_adapter::{AuditCategory, AuditEvent, AuditEventRow, AuditQuery},
	prelude::*,
};

pub(crate) async fn append_audit_event(db: &SqlitePool, ev: &AuditEvent) -> ClResult<()> {
	sqlx::query(
		"INSERT INTO audit_event (ts, tn_id, actor, event, category, ip, outcome, details)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
	)
	.bind(ev.ts.0)
	.bind(ev.tn_id.map(|t| t.0))
	.bind(ev.actor.as_deref())
	.bind(&*ev.event)
	.bind(ev.category.as_str())
	.bind(ev.ip.as_deref())
	.bind(&*ev.outcome)
	.bind(ev.details.as_ref().map(serde_json::Value::to_string))
	.execute(db)
	.await
	.db()?;
	Ok(())
}

pub(crate) async fn list_audit_events(
	db: &SqlitePool,
	q: &AuditQuery,
) -> ClResult<Vec<AuditEventRow>> {
	let mut query = sqlx::QueryBuilder::new(
		"SELECT id, ts, tn_id, actor, event, category, ip, outcome, details \
		FROM audit_event WHERE 1=1",
	);
	if let Some(tn_id) = q.tn_id {
		query.push(" AND tn_id = ").push_bind(tn_id.0);
	}
	if let Some(from) = q.from {
		query.push(" AND ts >= ").push_bind(from.0);
	}
	if let Some(to) = q.to {
		query.push(" AND ts <= ").push_bind(to.0);
	}
	if let Some(category) = q.category {
		query.push(" AND category = ").push_bind(category.as_str());
	}
	if let Some(prefix) = q.event_prefix.as_deref() {
		// Plain prefix compare: no LIKE, so `_` and `%` in event names need no escaping
		let len = i64::try_from(prefix.chars().count()).unwrap_or(i64::MAX);
		query
			.push(" AND substr(event, 1, ")
			.push_bind(len)
			.push(") = ")
			.push_bind(prefix.to_owned());
	}
	if let Some(actor) = q.actor.as_deref() {
		query.push(" AND actor = ").push_bind(actor.to_owned());
	}
	if let Some(outcome) = q.outcome.as_deref() {
		query.push(" AND outcome = ").push_bind(outcome.to_owned());
	}
	if let Some(cursor) = q.cursor {
		query.push(" AND id < ").push_bind(cursor);
	}
	query.push(" ORDER BY id DESC");
	if let Some(limit) = q.limit {
		query.push(" LIMIT ").push_bind(limit);
	}

	let rows = query.build().fetch_all(db).await.db()?;
	rows.iter()
		.map(|row| -> Result<AuditEventRow, sqlx::Error> {
			let category: String = row.try_get("category")?;
			let details: Option<String> = row.try_get("details")?;
			Ok(AuditEventRow {
				id: row.try_get("id")?,
				event: AuditEvent {
					ts: Timestamp(row.try_get("ts")?),
					tn_id: row.try_get::<Option<u32>, _>("tn_id")?.map(TnId),
					actor: row.try_get::<Option<String>, _>("actor")?.map(Into::into),
					event: row.try_get::<String, _>("event")?.into(),
					// Only `record` writes this column, always from the enum
					category: AuditCategory::parse(&category).unwrap_or(AuditCategory::Admin),
					ip: row.try_get::<Option<String>, _>("ip")?.map(Into::into),
					outcome: row.try_get::<String, _>("outcome")?.into(),
					details: details.and_then(|d| serde_json::from_str(&d).ok()),
				},
			})
		})
		.collect::<Result<Vec<_>, _>>()
		.db()
}

pub(crate) async fn purge_audit_events(db: &SqlitePool, before: Timestamp) -> ClResult<u64> {
	let res = sqlx::query("DELETE FROM audit_event WHERE ts < ?")
		.bind(before.0)
		.execute(db)
		.await
		.db()?;
	Ok(res.rows_affected())
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use cloudillo_types::{auth_adapter::AuthAdapter, worker::WorkerPool};

	use super::*;
	use crate::AuthAdapterSqlite;

	#[tokio::test]
	async fn append_list_purge() {
		let tmp = tempfile::TempDir::new().unwrap();
		let adapter = AuthAdapterSqlite::new(Arc::new(WorkerPool::new(1, 1, 1)), tmp.path())
			.await
			.unwrap();

		let old = AuditEvent {
			ts: Timestamp(1000),
			tn_id: Some(TnId(1)),
			actor: Some("alice.test".into()),
			details: Some(serde_json::json!({ "method": "password" })),
			..AuditEvent::new(AuditCategory::Auth, "auth.login", "fail")
		};
		let new = AuditEvent {
			ts: Timestamp(2000),
			tn_id: Some(TnId(1)),
			ip: Some("127.0.0.1".into()),
			..AuditEvent::new(AuditCategory::Sharing, "sharing.share.create", "success")
		};
		let global = AuditEvent {
			ts: Timestamp(3000),
			..AuditEvent::new(AuditCategory::Admin, "admin.settings.change", "success")
		};
		for ev in [&old, &new, &global] {
			adapter.append_audit_event(ev).await.unwrap();
		}

		// All rows, newest first
		let all = adapter.list_audit_events(&AuditQuery::default()).await.unwrap();
		assert_eq!(all.len(), 3);
		assert_eq!(&*all[0].event.event, "admin.settings.change");
		assert!(all[0].event.tn_id.is_none());

		// Tenant filter excludes the server-wide row; round-trip of every field
		let own = adapter
			.list_audit_events(&AuditQuery { tn_id: Some(TnId(1)), ..Default::default() })
			.await
			.unwrap();
		assert_eq!(own.len(), 2);
		let login = &own[1].event;
		assert_eq!(login.ts.0, 1000);
		assert_eq!(login.actor.as_deref(), Some("alice.test"));
		assert_eq!(login.category, AuditCategory::Auth);
		assert_eq!(&*login.outcome, "fail");
		assert_eq!(login.details, Some(serde_json::json!({ "method": "password" })));
		assert_eq!(own[0].event.ip.as_deref(), Some("127.0.0.1"));

		// Prefix, category, range, cursor + limit
		let q = AuditQuery { event_prefix: Some("auth.".into()), ..Default::default() };
		assert_eq!(adapter.list_audit_events(&q).await.unwrap().len(), 1);
		let q = AuditQuery { category: Some(AuditCategory::Sharing), ..Default::default() };
		assert_eq!(adapter.list_audit_events(&q).await.unwrap().len(), 1);
		let q = AuditQuery {
			from: Some(Timestamp(2000)),
			to: Some(Timestamp(3000)),
			..Default::default()
		};
		assert_eq!(adapter.list_audit_events(&q).await.unwrap().len(), 2);
		let q = AuditQuery { cursor: Some(all[0].id), limit: Some(1), ..Default::default() };
		let page = adapter.list_audit_events(&q).await.unwrap();
		assert_eq!(page.len(), 1);
		assert_eq!(page[0].id, all[1].id);

		// Purge strictly before the cutoff
		assert_eq!(adapter.purge_audit_events(Timestamp(2000)).await.unwrap(), 1);
		assert_eq!(adapter.list_audit_events(&AuditQuery::default()).await.unwrap().len(), 2);
	}
}

// vim: ts=4
