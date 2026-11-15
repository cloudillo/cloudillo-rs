// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Push subscription database operations

use crate::utils::Db;
use cloudillo_types::{
	meta_adapter::{NotificationLogEntry, PushSubscription, PushSubscriptionData},
	prelude::*,
	types::ApiTime,
};
use sqlx::{Row, SqlitePool};

/// List all push subscriptions for a tenant
pub async fn list(db: &SqlitePool, tn_id: TnId) -> ClResult<Vec<PushSubscription>> {
	let rows = sqlx::query(
		"SELECT subs_id, subscription, created_at
		 FROM subscriptions
		 WHERE tn_id = ?",
	)
	.bind(tn_id.0)
	.fetch_all(db)
	.await
	.db()?;

	let mut subscriptions = Vec::with_capacity(rows.len());
	for row in rows {
		let subscription_json: String = row.get("subscription");
		let subscription_data: PushSubscriptionData = serde_json::from_str(&subscription_json)
			.map_err(|e| Error::Internal(format!("Invalid subscription JSON: {}", e)))?;

		subscriptions.push(PushSubscription {
			id: u64::try_from(row.get::<i64, _>("subs_id")).unwrap_or_default(),
			subscription: subscription_data,
			created_at: ApiTime(row.get::<i64, _>("created_at")),
		});
	}

	Ok(subscriptions)
}

/// Create a new push subscription
pub async fn create(
	db: &SqlitePool,
	tn_id: TnId,
	subscription: &PushSubscriptionData,
) -> ClResult<u64> {
	let subscription_json = serde_json::to_string(subscription)
		.map_err(|e| Error::Internal(format!("Failed to serialize subscription: {}", e)))?;

	let result = sqlx::query(
		"INSERT INTO subscriptions (tn_id, subscription)
		 VALUES (?, ?)",
	)
	.bind(tn_id.0)
	.bind(&subscription_json)
	.execute(db)
	.await
	.db()?;

	Ok(u64::try_from(result.last_insert_rowid()).unwrap_or_default())
}

/// Delete a push subscription by ID
pub async fn delete(db: &SqlitePool, tn_id: TnId, subscription_id: u64) -> ClResult<()> {
	sqlx::query("DELETE FROM subscriptions WHERE tn_id = ? AND subs_id = ?")
		.bind(tn_id.0)
		.bind(subscription_id.cast_signed())
		.execute(db)
		.await
		.db()?;

	Ok(())
}

/// Append to the tenant's notification log; `seq` = tenant max + 1 (the single INSERT is atomic)
pub async fn append_notification(db: &SqlitePool, tn_id: TnId, payload: &str) -> ClResult<u64> {
	let seq: i64 = sqlx::query_scalar(
		"INSERT INTO notifications (tn_id, seq, payload)
		 VALUES (?1, (SELECT COALESCE(MAX(seq), 0) + 1 FROM notifications WHERE tn_id = ?1), ?2)
		 RETURNING seq",
	)
	.bind(tn_id.0)
	.bind(payload)
	.fetch_one(db)
	.await
	.db()?;

	Ok(seq.cast_unsigned())
}

/// Log entries after `since`, ascending
pub async fn list_notifications_since(
	db: &SqlitePool,
	tn_id: TnId,
	since: u64,
	limit: u32,
) -> ClResult<Vec<NotificationLogEntry>> {
	let rows = sqlx::query(
		"SELECT seq, payload, created_at FROM notifications
		 WHERE tn_id = ? AND seq > ? ORDER BY seq LIMIT ?",
	)
	.bind(tn_id.0)
	.bind(i64::try_from(since).unwrap_or(i64::MAX))
	.bind(limit)
	.fetch_all(db)
	.await
	.db()?;

	Ok(rows
		.into_iter()
		.map(|row| NotificationLogEntry {
			seq: row.get::<i64, _>("seq").cast_unsigned(),
			payload: row.get::<String, _>("payload").into(),
			created_at: ApiTime(row.get::<i64, _>("created_at")),
		})
		.collect())
}

/// Prune old log entries across all tenants, keeping each tenant's newest row so a quiet
/// tenant's next `seq` does not restart below what its devices have already seen
pub async fn prune_notifications(db: &SqlitePool, older_than: Timestamp) -> ClResult<u64> {
	let res = sqlx::query(
		"DELETE FROM notifications WHERE created_at < ?
		 AND seq < (SELECT MAX(n.seq) FROM notifications n WHERE n.tn_id = notifications.tn_id)",
	)
	.bind(older_than.0)
	.execute(db)
	.await
	.db()?;

	Ok(res.rows_affected())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
	use super::*;
	use sqlx::sqlite;

	async fn test_pool(dir: &std::path::Path) -> SqlitePool {
		let opts = sqlite::SqliteConnectOptions::new()
			.filename(dir.join("meta.db"))
			.create_if_missing(true)
			.journal_mode(sqlite::SqliteJournalMode::Wal);
		let db = sqlite::SqlitePoolOptions::new()
			.max_connections(1)
			.connect_with(opts)
			.await
			.expect("connect test pool");
		crate::schema::init_db(&db).await.expect("init schema");
		db
	}

	fn seqs(entries: &[NotificationLogEntry]) -> Vec<u64> {
		entries.iter().map(|e| e.seq).collect()
	}

	#[tokio::test]
	async fn notification_log_seq_since_limit_and_prune() {
		let dir = tempfile::TempDir::new().unwrap();
		let db = test_pool(dir.path()).await;
		let (t1, t2) = (TnId(1), TnId(2));

		// seq starts at 1 and increments per tenant, independently
		for i in 1..=4 {
			assert_eq!(append_notification(&db, t1, &format!("{{\"n\":{i}}}")).await.unwrap(), i);
		}
		assert_eq!(append_notification(&db, t2, "{}").await.unwrap(), 1);
		assert_eq!(append_notification(&db, t2, "{}").await.unwrap(), 2);

		// since + limit, ascending
		assert_eq!(seqs(&list_notifications_since(&db, t1, 0, 100).await.unwrap()), [1, 2, 3, 4]);
		assert_eq!(seqs(&list_notifications_since(&db, t1, 1, 2).await.unwrap()), [2, 3]);
		assert_eq!(seqs(&list_notifications_since(&db, t2, 0, 100).await.unwrap()), [1, 2]);
		// a `since` beyond i64 must not wrap negative and return everything
		assert!(list_notifications_since(&db, t1, u64::MAX, 100).await.unwrap().is_empty());

		// prune keeps each tenant's newest row; the next append continues at max + 1
		let pruned = prune_notifications(&db, Timestamp(i64::MAX)).await.unwrap();
		assert_eq!(pruned, 4);
		assert_eq!(seqs(&list_notifications_since(&db, t1, 0, 100).await.unwrap()), [4]);
		assert_eq!(seqs(&list_notifications_since(&db, t2, 0, 100).await.unwrap()), [2]);
		assert_eq!(append_notification(&db, t1, "{}").await.unwrap(), 5);
	}

	#[tokio::test]
	async fn prune_keeps_rows_newer_than_the_cutoff() {
		let dir = tempfile::TempDir::new().unwrap();
		let db = test_pool(dir.path()).await;
		let t1 = TnId(1);
		for _ in 0..4 {
			append_notification(&db, t1, "{}").await.unwrap();
		}
		// seq 1-2 are old, 3-4 recent
		sqlx::query("UPDATE notifications SET created_at = 1000 WHERE seq <= 2")
			.execute(&db)
			.await
			.unwrap();

		assert_eq!(prune_notifications(&db, Timestamp(2000)).await.unwrap(), 2);
		assert_eq!(seqs(&list_notifications_since(&db, t1, 0, 100).await.unwrap()), [3, 4]);
	}
}

// vim: ts=4
