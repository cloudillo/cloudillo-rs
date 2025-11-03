//! Action management and federation

use sqlx::{Row, SqlitePool};

use crate::utils::*;
use cloudillo::meta_adapter::*;
use cloudillo::prelude::*;

/// List actions with filtering options
pub(crate) async fn list(
	db: &SqlitePool,
	tn_id: TnId,
	opts: &ListActionOptions,
) -> ClResult<Vec<ActionView>> {
	let mut query = sqlx::QueryBuilder::new(
		"SELECT a.type, a.sub_type, a.action_id, a.parent_id, a.root_id, a.issuer_tag,
		pi.name as issuer_name, pi.profile_pic as issuer_profile_pic,
		a.audience, pa.name as audience_name, pa.profile_pic as audience_profile_pic,
		a.subject, a.content, a.created_at, a.expires_at,
		own.content as own_reaction,
		a.attachments, a.status, a.reactions, a.comments, a.comments_read
		FROM actions a
		LEFT JOIN profiles pi ON pi.tn_id=a.tn_id AND pi.id_tag=a.issuer_tag
		LEFT JOIN profiles pa ON pa.tn_id=a.tn_id AND pa.id_tag=a.audience
		LEFT JOIN actions own ON own.tn_id=a.tn_id AND own.parent_id=a.action_id AND own.issuer_tag=",
	);
	query
		.push_bind("")
		.push("AND own.type='REACT' AND coalesce(own.status, 'A') NOT IN ('D') WHERE a.tn_id=")
		.push_bind(tn_id.0);

	if let Some(status) = &opts.status {
		query.push(" AND coalesce(a.status, 'A') IN ");
		query = push_in(query, status);
	} else {
		query.push(" AND coalesce(a.status, 'A') NOT IN ('D')");
	}
	if let Some(typ) = &opts.typ {
		query.push(" AND a.type IN ");
		query = push_in(query, typ.as_slice());
	}
	if let Some(issuer) = &opts.issuer {
		query.push(" AND a.issuer_tag=").push_bind(issuer);
	}
	if let Some(audience) = &opts.audience {
		query.push(" AND a.audience=").push_bind(audience);
	}
	if let Some(involved) = &opts.involved {
		query.push(" AND a.audience=").push_bind(involved);
	}
	if let Some(parent_id) = &opts.parent_id {
		query.push(" AND a.parent_id=").push_bind(parent_id);
	}
	if let Some(root_id) = &opts.root_id {
		query.push(" AND a.root_id=").push_bind(root_id);
	}
	if let Some(subject) = &opts.subject {
		query.push(" AND a.subject=").push_bind(subject);
	}
	if let Some(created_after) = &opts.created_after {
		query.push(" AND a.created_at>").push_bind(created_after.0);
	}
	query.push(" ORDER BY a.created_at DESC LIMIT 100");
	info!("SQL: {}", query.sql());

	let res = query
		.build()
		.fetch_all(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	let mut actions = Vec::new();
	for row in res {
		let action_id = row.try_get::<Box<str>, _>("action_id").map_err(|_| Error::DbError)?;
		info!("row: {:?}", action_id);

		let issuer_tag = row.try_get::<Box<str>, _>("issuer_tag").map_err(|_| Error::DbError)?;
		let audience_tag =
			row.try_get::<Option<Box<str>>, _>("audience").map_err(|_| Error::DbError)?;

		// collect attachments
		let attachments = row
			.try_get::<Option<Box<str>>, _>("attachments")
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;
		let attachments = if let Some(attachments) = &attachments {
			info!("attachments: {:?}", attachments);
			let mut attachments = parse_str_list(attachments)
				.iter()
				.map(|a| AttachmentView { file_id: a.clone(), dim: None })
				.collect::<Vec<_>>();
			info!("attachments: {:?}", attachments);
			for a in attachments.iter_mut() {
				if let Ok(file_res) =
					sqlx::query("SELECT x->>'dim' as dim FROM files WHERE tn_id=? AND file_id=?")
						.bind(tn_id.0)
						.bind(&a.file_id)
						.fetch_one(db)
						.await
						.inspect_err(inspect)
				{
					a.dim = serde_json::from_str(
						file_res.try_get("dim").inspect_err(inspect).map_err(|_| Error::DbError)?,
					)?;
				}
				info!("attachment: {:?}", a);
			}
			Some(attachments)
		} else {
			None
		};

		// stat - build from reactions and comments counts
		let reactions_count: i64 = row.try_get("reactions").unwrap_or(0);
		let comments_count: i64 = row.try_get("comments").unwrap_or(0);
		let stat = Some(serde_json::json!({
			"comments": comments_count,
			"reactions": reactions_count
		}));
		actions.push(ActionView {
			action_id: row.try_get::<Box<str>, _>("action_id").map_err(|_| Error::DbError)?,
			typ: row.try_get::<Box<str>, _>("type").map_err(|_| Error::DbError)?,
			sub_typ: row.try_get::<Option<Box<str>>, _>("sub_type").map_err(|_| Error::DbError)?,
			parent_id: row
				.try_get::<Option<Box<str>>, _>("parent_id")
				.map_err(|_| Error::DbError)?,
			root_id: row.try_get::<Option<Box<str>>, _>("root_id").map_err(|_| Error::DbError)?,
			issuer: ProfileInfo {
				id_tag: issuer_tag,
				name: row.try_get::<Box<str>, _>("issuer_name").map_err(|_| Error::DbError)?,
				typ: match row.try_get::<Option<&str>, _>("type").map_err(|_| Error::DbError)? {
					Some("C") => ProfileType::Community,
					_ => ProfileType::Person,
				},
				profile_pic: row
					.try_get::<Option<Box<str>>, _>("issuer_profile_pic")
					.map_err(|_| Error::DbError)?,
			},
			audience: if let Some(audience_tag) = audience_tag {
				Some(ProfileInfo {
					id_tag: audience_tag,
					name: row
						.try_get::<Box<str>, _>("audience_name")
						.map_err(|_| Error::DbError)?,
					typ: match row.try_get::<Option<&str>, _>("type").map_err(|_| Error::DbError)? {
						Some("C") => ProfileType::Community,
						_ => ProfileType::Person,
					},
					profile_pic: row
						.try_get::<Option<Box<str>>, _>("audience_profile_pic")
						.map_err(|_| Error::DbError)?,
				})
			} else {
				None
			},
			subject: row.try_get("subject").map_err(|_| Error::DbError)?,
			content: row.try_get("content").map_err(|_| Error::DbError)?,
			attachments,
			created_at: row.try_get("created_at").map(Timestamp).map_err(|_| Error::DbError)?,
			expires_at: row
				.try_get("expires_at")
				.map(|ts: Option<i64>| ts.map(Timestamp))
				.map_err(|_| Error::DbError)?,
			status: row.try_get("status").map_err(|_| Error::DbError)?,
			stat,
		})
	}

	Ok(actions)
}

/// List action tokens
pub(crate) async fn list_tokens(
	db: &SqlitePool,
	tn_id: TnId,
	opts: &ListActionOptions,
) -> ClResult<Box<[Box<str>]>> {
	let mut query = sqlx::QueryBuilder::new(
		"SELECT at.token FROM action_tokens at
		 JOIN actions a ON a.tn_id=at.tn_id AND a.action_id=at.action_id
		 WHERE at.tn_id=",
	);
	query.push_bind(tn_id.0);

	if let Some(status) = &opts.status {
		query.push(" AND coalesce(a.status, 'A') IN ");
		query = push_in(query, status);
	} else {
		query.push(" AND coalesce(a.status, 'A') NOT IN ('D')");
	}

	if let Some(typ) = &opts.typ {
		query.push(" AND a.type IN ");
		query = push_in(query, typ.as_slice());
	}

	if let Some(action_id) = &opts.action_id {
		query.push(" AND a.action_id=").push_bind(action_id.as_str());
	}

	query.push(" ORDER BY a.created_at DESC LIMIT 100");

	let res = query
		.build()
		.fetch_all(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	let tokens = collect_res(res.iter().map(|row| row.try_get("token")))?;

	Ok(tokens.into_boxed_slice())
}

/// Create a new action
pub(crate) async fn create(
	db: &SqlitePool,
	tn_id: TnId,
	action: &Action<&str>,
	key: Option<&str>,
) -> ClResult<()> {
	let mut tx = db.begin().await.map_err(|_| Error::DbError)?;
	sqlx::QueryBuilder::new(
		"INSERT OR IGNORE INTO actions (tn_id, action_id, key, type, sub_type, parent_id, root_id, issuer_tag, audience, subject, content, created_at, expires_at, attachments) VALUES(")
		.push_bind(tn_id.0).push(", ")
		.push_bind(action.action_id).push(", ")
		.push_bind(key).push(", ")
		.push_bind(action.typ).push(", ")
		.push_bind(action.sub_typ).push(", ")
		.push_bind(action.parent_id).push(", ")
		.push_bind(action.root_id).push(", ")
		.push_bind(action.issuer_tag).push(", ")
		.push_bind(action.audience_tag).push(", ")
		.push_bind(action.subject).push(", ")
		.push_bind(action.content).push(", ")
		.push_bind(action.created_at.0).push(", ")
		.push_bind(action.expires_at.map(|t| t.0)).push(", ")
		.push_bind(action.attachments.as_ref().map(|s| s.join(",")))
		.push(")")
		.build().execute(&mut *tx).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

	let mut add_reactions = if action.content.is_none() { 0 } else { 1 };
	if let Some(key) = &key {
		info!("update with key: {}", key);
		let res = sqlx::query("UPDATE actions SET status='D' WHERE tn_id=? AND key=? AND action_id!=? AND coalesce(status, '')!='D' RETURNING content")
			.bind(tn_id.0).bind(key).bind(action.action_id)
			.fetch_all(&mut *tx).await.inspect_err(inspect).map_err(|_| Error::DbError)?;
		if !res.is_empty()
			&& (res[0].try_get::<Option<&str>, _>("content").map_err(|_| Error::DbError)?).is_some()
		{
			add_reactions -= 1;
		}
	}
	if action.typ == "REACT" && action.content.is_some() {
		info!("update with reaction: {}", action.content.unwrap());
		sqlx::query("UPDATE actions SET reactions=coalesce(reactions, 0)+? WHERE tn_id=? AND action_id IN (?, ?)")
			.bind(add_reactions).bind(tn_id.0).bind(action.parent_id).bind(action.root_id)
			.execute(&mut *tx).await.inspect_err(inspect).map_err(|_| Error::DbError)?;
	}
	tx.commit().await.inspect_err(inspect).map_err(|_| Error::DbError)?;
	Ok(())
}

/// Create an inbound action
pub(crate) async fn create_inbound(
	db: &SqlitePool,
	tn_id: TnId,
	action_id: &str,
	token: &str,
	ack_token: Option<&str>,
) -> ClResult<()> {
	sqlx::query(
		"INSERT OR IGNORE INTO action_tokens (tn_id, action_id, token, status, ack)
		VALUES (?, ?, ?, ?, ?)",
	)
	.bind(tn_id.0)
	.bind(action_id)
	.bind(token)
	.bind("P")
	.bind(ack_token)
	.execute(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;
	Ok(())
}

/// Get action root ID
pub(crate) async fn get_root_id(
	db: &SqlitePool,
	tn_id: TnId,
	action_id: &str,
) -> ClResult<Box<str>> {
	let res = sqlx::query("SELECT root_id FROM actions WHERE tn_id=? AND action_id=?")
		.bind(tn_id.0)
		.bind(action_id)
		.fetch_one(db)
		.await;

	map_res(res, |row| row.try_get("root_id"))
}

/// Get action data
pub(crate) async fn get_data(
	db: &SqlitePool,
	tn_id: TnId,
	action_id: &str,
) -> ClResult<Option<ActionData>> {
	let res = sqlx::query(
		"SELECT subject, reactions, comments FROM actions WHERE tn_id=? AND action_id=?",
	)
	.bind(tn_id.0)
	.bind(action_id)
	.fetch_optional(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

	match res {
		Some(row) => Ok(Some(ActionData {
			subject: row.try_get("subject").ok(),
			reactions: row.try_get("reactions").ok(),
			comments: row.try_get("comments").ok(),
		})),
		None => Ok(None),
	}
}

/// Get action by key
pub(crate) async fn get_by_key(
	db: &SqlitePool,
	tn_id: TnId,
	action_key: &str,
) -> ClResult<Option<Action<Box<str>>>> {
	let res = sqlx::query("SELECT action_id, type, sub_type, issuer_tag, parent_id, root_id, audience, content, attachments, subject, created_at, expires_at
		FROM actions WHERE tn_id=? AND key=?")
		.bind(tn_id.0)
		.bind(action_key)
		.fetch_optional(db).await;

	match res {
		Ok(Some(row)) => {
			let attachments_str: Option<Box<str>> = row.try_get("attachments").ok();
			let attachments = attachments_str.map(|s| parse_str_list(&s).to_vec());

			Ok(Some(Action {
				action_id: row.try_get("action_id").map_err(|_| Error::DbError)?,
				typ: row.try_get("type").map_err(|_| Error::DbError)?,
				sub_typ: row.try_get("sub_type").ok(),
				issuer_tag: row.try_get("issuer_tag").map_err(|_| Error::DbError)?,
				parent_id: row.try_get("parent_id").ok(),
				root_id: row.try_get("root_id").ok(),
				audience_tag: row.try_get("audience").ok(),
				content: row.try_get("content").ok(),
				attachments,
				subject: row.try_get("subject").ok(),
				created_at: row.try_get("created_at").map(Timestamp).map_err(|_| Error::DbError)?,
				expires_at: row
					.try_get("expires_at")
					.ok()
					.and_then(|v: Option<i64>| v.map(Timestamp)),
			}))
		}
		Ok(None) => Ok(None),
		Err(_) => Err(Error::DbError),
	}
}

/// Store action token
pub(crate) async fn store_token(
	db: &SqlitePool,
	tn_id: TnId,
	action_id: &str,
	token: &str,
) -> ClResult<()> {
	sqlx::query(
		"INSERT OR REPLACE INTO action_tokens (tn_id, action_id, token, status)
		VALUES (?, ?, ?, 'L')",
	)
	.bind(tn_id.0)
	.bind(action_id)
	.bind(token)
	.execute(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

	Ok(())
}

/// Get action token
pub(crate) async fn get_token(
	db: &SqlitePool,
	tn_id: TnId,
	action_id: &str,
) -> ClResult<Option<Box<str>>> {
	let res = sqlx::query("SELECT token FROM action_tokens WHERE tn_id=? AND action_id=?")
		.bind(tn_id.0)
		.bind(action_id)
		.fetch_optional(db)
		.await;

	match res {
		Ok(Some(row)) => Ok(Some(row.try_get("token").map_err(|_| Error::DbError)?)),
		Ok(None) => Ok(None),
		Err(_) => Err(Error::DbError),
	}
}

/// Update action data
pub(crate) async fn update_data(
	db: &SqlitePool,
	tn_id: TnId,
	action_id: &str,
	opts: &UpdateActionDataOptions,
) -> ClResult<()> {
	let mut query = sqlx::QueryBuilder::new("UPDATE actions SET ");
	let mut has_updates = false;

	if let Some(subject) = &opts.subject {
		if has_updates {
			query.push(", ");
		}
		query.push("subject=").push_bind(subject.as_str());
		has_updates = true;
	}

	if let Some(reactions) = opts.reactions {
		if has_updates {
			query.push(", ");
		}
		query.push("reactions=").push_bind(reactions);
		has_updates = true;
	}

	if let Some(comments) = opts.comments {
		if has_updates {
			query.push(", ");
		}
		query.push("comments=").push_bind(comments);
		has_updates = true;
	}

	if let Some(status) = &opts.status {
		if has_updates {
			query.push(", ");
		}
		query.push("status=").push_bind(status.as_str());
		has_updates = true;
	}

	if !has_updates {
		return Ok(());
	}

	query
		.push(" WHERE tn_id=")
		.push_bind(tn_id.0)
		.push(" AND action_id=")
		.push_bind(action_id);

	let res = query
		.build()
		.execute(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	if res.rows_affected() == 0 {
		return Err(Error::NotFound);
	}

	Ok(())
}

/// Update inbound action status
pub(crate) async fn update_inbound(
	db: &SqlitePool,
	tn_id: TnId,
	action_id: &str,
	status: Option<char>,
) -> ClResult<()> {
	let status_str = status.map(|c| c.to_string());
	let res = sqlx::query("UPDATE action_tokens SET status=? WHERE tn_id=? AND action_id=?")
		.bind(status_str.as_deref())
		.bind(tn_id.0)
		.bind(action_id)
		.execute(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	if res.rows_affected() == 0 {
		return Err(Error::NotFound);
	}

	Ok(())
}

/// Create outbound action
pub(crate) async fn create_outbound(
	db: &SqlitePool,
	tn_id: TnId,
	action_id: &str,
	token: &str,
	opts: &CreateOutboundActionOptions,
) -> ClResult<()> {
	sqlx::query("INSERT INTO action_outbox_queue (tn_id, action_id, type, token, recipient_tag, status, created_at)
		VALUES (?, ?, ?, ?, ?, 'P', unixepoch())")
		.bind(tn_id.0)
		.bind(action_id)
		.bind(opts.typ.as_str())
		.bind(token)
		.bind(opts.recipient_tag.as_str())
		.execute(db).await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	Ok(())
}

/// Get action (placeholder)
pub(crate) async fn get(
	_db: &SqlitePool,
	_tn_id: TnId,
	_action_id: &str,
) -> ClResult<Option<ActionView>> {
	// TODO: Implement full action view retrieval with issuer and audience profiles
	Ok(None)
}

/// Update action (placeholder)
pub(crate) async fn update(
	_db: &SqlitePool,
	_tn_id: TnId,
	_action_id: &str,
	_content: Option<&str>,
	_attachments: Option<&[&str]>,
) -> ClResult<()> {
	// TODO: Implement action update before federation
	Ok(())
}

/// Delete action (soft delete)
pub(crate) async fn delete(db: &SqlitePool, tn_id: TnId, action_id: &str) -> ClResult<()> {
	// Soft delete action by marking status as 'D'
	sqlx::query("UPDATE actions SET status = 'D' WHERE tn_id = ? AND action_id = ?")
		.bind(tn_id.0)
		.bind(action_id)
		.execute(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	Ok(())
}

/// Set action federation status
pub(crate) async fn set_federation_status(
	db: &SqlitePool,
	tn_id: TnId,
	action_id: &str,
	status: &str,
) -> ClResult<()> {
	sqlx::query("UPDATE actions SET federation_status = ? WHERE tn_id = ? AND action_id = ?")
		.bind(status)
		.bind(tn_id.0)
		.bind(action_id)
		.execute(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	Ok(())
}

/// Add reaction (placeholder)
pub(crate) async fn add_reaction(
	_db: &SqlitePool,
	_tn_id: TnId,
	_action_id: &str,
	_reactor_id_tag: &str,
	_reaction_type: &str,
	_content: Option<&str>,
) -> ClResult<()> {
	// TODO: Implement reaction storage (probably in JSON column)
	Ok(())
}

/// List reactions (placeholder)
pub(crate) async fn list_reactions(
	_db: &SqlitePool,
	_tn_id: TnId,
	_action_id: &str,
) -> ClResult<Vec<ReactionData>> {
	// TODO: Implement reaction retrieval from JSON column
	Ok(Vec::new())
}
