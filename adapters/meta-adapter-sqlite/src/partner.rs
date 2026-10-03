// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Partner edges: each membership community's connected community peers, as synced from
//! its `GET /api/partners` and from received PTNR actions.

use cloudillo_types::{meta_adapter::PartnerEdge, prelude::*};
use sqlx::{Row, SqlitePool};

use crate::utils::Db;

const INSERT_EDGE: &str = "INSERT INTO partner_edge (tn_id, community, partner) VALUES (?, ?, ?) \
	ON CONFLICT(tn_id, community, partner) DO NOTHING";

pub async fn replace_partner_edges(
	db: &SqlitePool,
	tn_id: TnId,
	community: &str,
	partners: &[Box<str>],
) -> ClResult<()> {
	let mut tx = db.begin().await.db()?;
	sqlx::query("DELETE FROM partner_edge WHERE tn_id = ? AND community = ?")
		.bind(tn_id.0)
		.bind(community)
		.execute(&mut *tx)
		.await
		.db()?;
	for partner in partners {
		sqlx::query(INSERT_EDGE)
			.bind(tn_id.0)
			.bind(community)
			.bind(partner.as_ref())
			.execute(&mut *tx)
			.await
			.db()?;
	}
	tx.commit().await.db()?;
	Ok(())
}

pub async fn upsert_partner_edge(
	db: &SqlitePool,
	tn_id: TnId,
	community: &str,
	partner: &str,
) -> ClResult<()> {
	sqlx::query(INSERT_EDGE)
		.bind(tn_id.0)
		.bind(community)
		.bind(partner)
		.execute(db)
		.await
		.db()?;
	Ok(())
}

pub async fn delete_partner_edge(
	db: &SqlitePool,
	tn_id: TnId,
	community: &str,
	partner: &str,
) -> ClResult<()> {
	sqlx::query("DELETE FROM partner_edge WHERE tn_id = ? AND community = ? AND partner = ?")
		.bind(tn_id.0)
		.bind(community)
		.bind(partner)
		.execute(db)
		.await
		.db()?;
	Ok(())
}

pub async fn delete_partner_edges_of(
	db: &SqlitePool,
	tn_id: TnId,
	community: &str,
) -> ClResult<()> {
	sqlx::query("DELETE FROM partner_edge WHERE tn_id = ? AND community = ?")
		.bind(tn_id.0)
		.bind(community)
		.execute(db)
		.await
		.db()?;
	Ok(())
}

/// An empty `communities` deletes every edge of the tenant.
pub async fn delete_partner_edges_except(
	db: &SqlitePool,
	tn_id: TnId,
	communities: &[Box<str>],
) -> ClResult<()> {
	let mut query = sqlx::QueryBuilder::new("DELETE FROM partner_edge WHERE tn_id = ");
	query.push_bind(tn_id.0);
	if !communities.is_empty() {
		query.push(" AND community NOT IN (");
		let mut sep = query.separated(", ");
		for community in communities {
			sep.push_bind(community.as_ref());
		}
		query.push(")");
	}
	query.build().execute(db).await.db()?;
	Ok(())
}

pub async fn list_partner_edges(db: &SqlitePool, tn_id: TnId) -> ClResult<Vec<PartnerEdge>> {
	let rows = sqlx::query(
		"SELECT community, partner FROM partner_edge WHERE tn_id = ? \
		 ORDER BY community, partner",
	)
	.bind(tn_id.0)
	.fetch_all(db)
	.await
	.db()?;
	Ok(rows
		.iter()
		.map(|row| PartnerEdge {
			community: row.get::<String, _>("community").into(),
			partner: row.get::<String, _>("partner").into(),
		})
		.collect())
}

// vim: ts=4
