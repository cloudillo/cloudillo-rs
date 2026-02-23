//! Push subscription database operations

use cloudillo_types::{
	meta_adapter::{PushSubscription, PushSubscriptionData},
	prelude::*,
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
	.or(Err(Error::DbError))?;

	let mut subscriptions = Vec::with_capacity(rows.len());
	for row in rows {
		let subscription_json: String = row.get("subscription");
		let subscription_data: PushSubscriptionData = serde_json::from_str(&subscription_json)
			.map_err(|e| Error::Internal(format!("Invalid subscription JSON: {}", e)))?;

		subscriptions.push(PushSubscription {
			id: row.get::<i64, _>("subs_id") as u64,
			subscription: subscription_data,
			created_at: Timestamp(row.get::<i64, _>("created_at")),
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
	.or(Err(Error::DbError))?;

	Ok(result.last_insert_rowid() as u64)
}

/// Delete a push subscription by ID
pub async fn delete(db: &SqlitePool, tn_id: TnId, subscription_id: u64) -> ClResult<()> {
	sqlx::query("DELETE FROM subscriptions WHERE tn_id = ? AND subs_id = ?")
		.bind(tn_id.0)
		.bind(subscription_id as i64)
		.execute(db)
		.await
		.or(Err(Error::DbError))?;

	Ok(())
}

// vim: ts=4
