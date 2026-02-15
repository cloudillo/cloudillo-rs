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
		"SELECT DISTINCT a.a_id, a.type, a.sub_type, a.action_id, a.parent_id, a.root_id, a.issuer_tag,
		pi.name as issuer_name, pi.profile_pic as issuer_profile_pic,
		a.audience, pa.name as audience_name, pa.profile_pic as audience_profile_pic,
		a.subject, a.content, a.created_at, a.expires_at,
		own.content as own_reaction,
		a.attachments, a.status, a.reactions, a.comments, a.comments_read, a.visibility, a.flags, a.x
		FROM actions a
		LEFT JOIN profiles pi ON pi.tn_id=a.tn_id AND pi.id_tag=a.issuer_tag
		LEFT JOIN profiles pa ON pa.tn_id=a.tn_id AND pa.id_tag=a.audience
		LEFT JOIN tenants t ON t.tn_id=a.tn_id
		LEFT JOIN actions own ON own.tn_id=a.tn_id AND own.parent_id=a.action_id AND own.issuer_tag=t.id_tag
			AND own.type='REACT' AND coalesce(own.status, 'A') NOT IN ('D')
		WHERE a.tn_id=",
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
	if let Some(issuer) = &opts.issuer {
		query.push(" AND a.issuer_tag=").push_bind(issuer);
	}
	if let Some(audience) = &opts.audience {
		query.push(" AND a.audience=").push_bind(audience);
	}
	if let Some(involved) = &opts.involved {
		if let Some(viewer) = &opts.viewer_id_tag {
			if viewer == involved {
				// Self-messages: both issuer and audience must be the user
				query
					.push(" AND a.issuer_tag=")
					.push_bind(involved)
					.push(" AND a.audience=")
					.push_bind(involved);
			} else {
				// Conversation between viewer and involved person
				query
					.push(" AND ((a.issuer_tag=")
					.push_bind(viewer)
					.push(" AND a.audience=")
					.push_bind(involved)
					.push(") OR (a.issuer_tag=")
					.push_bind(involved)
					.push(" AND a.audience=")
					.push_bind(viewer)
					.push("))");
			}
		} else {
			// No viewer (unauthenticated): fall back to simple OR
			query
				.push(" AND (a.audience=")
				.push_bind(involved)
				.push(" OR a.issuer_tag=")
				.push_bind(involved)
				.push(")");
		}
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
	if let Some(action_id) = &opts.action_id {
		// Handle both @{a_id} placeholders and real action_ids
		if let Some(a_id_str) = action_id.strip_prefix('@') {
			// Query by a_id
			if let Ok(a_id) = a_id_str.parse::<i64>() {
				query.push(" AND a.a_id=").push_bind(a_id);
			} else {
				// Invalid a_id format - no results
				query.push(" AND 1=0");
			}
		} else {
			// Query by action_id
			query.push(" AND a.action_id=").push_bind(action_id);
		}
	}

	// Determine sort order (currently only created_at is supported)
	let _sort_field = opts.sort.as_deref().unwrap_or("created");
	let sort_dir = match opts.sort_dir.as_deref() {
		Some("asc") => "ASC",
		Some("desc") => "DESC",
		_ => "DESC", // Default DESC for actions
	};
	let is_desc = sort_dir == "DESC";

	// Parse cursor for keyset pagination
	if let Some(cursor_str) = &opts.cursor {
		if let Some(cursor) = cloudillo::types::CursorData::decode(cursor_str) {
			// Look up internal a_id from cursor's external action_id
			let cursor_a_id: Option<i64> =
				match sqlx::query_scalar("SELECT a_id FROM actions WHERE tn_id=? AND action_id=?")
					.bind(tn_id.0)
					.bind(&cursor.id)
					.fetch_optional(db)
					.await
				{
					Ok(v) => v,
					Err(e) => {
						warn!("cursor a_id lookup failed: {}", e);
						None
					}
				};

			if let Some(cursor_a_id) = cursor_a_id {
				// Keyset pagination: (created_at, a_id) < (cursor_ts, cursor_a_id) for DESC
				// Note: push_bind() adds bind placeholders, don't use ? in push() strings
				let comparison = if is_desc { "<" } else { ">" };
				if let Some(ts) = cursor.timestamp() {
					query.push(format!(" AND (a.created_at, a.a_id) {} (", comparison));
					query.push_bind(ts);
					query.push(", ");
					query.push_bind(cursor_a_id);
					query.push(")");
				}
			}
		}
	}

	query.push(format!(" ORDER BY a.created_at {}, a.a_id {}", sort_dir, sort_dir));

	// Fetch limit+1 to determine hasMore
	// Note: SQLite doesn't allow bound parameters in LIMIT clause, so we use format!
	let limit = opts.limit.unwrap_or(20) as i64;
	query.push(format!(" LIMIT {}", limit + 1));

	debug!("SQL: {}", query.sql());

	let res = query
		.build()
		.fetch_all(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	let mut actions = Vec::new();
	for row in res {
		// action_id might be NULL for pending actions - use @{a_id} placeholder
		let action_id: Box<str> = row
			.try_get::<Option<String>, _>("action_id")
			.map_err(|_| Error::DbError)?
			.map(|s| s.into_boxed_str())
			.unwrap_or_else(|| {
				// NULL action_id - construct @{a_id} placeholder
				let a_id: i64 = row.try_get("a_id").unwrap_or(0);
				format!("@{}", a_id).into_boxed_str()
			});

		let issuer_tag = row.try_get::<Box<str>, _>("issuer_tag").map_err(|_| Error::DbError)?;
		let audience_tag =
			row.try_get::<Option<Box<str>>, _>("audience").map_err(|_| Error::DbError)?;

		// collect attachments
		let attachments = row
			.try_get::<Option<Box<str>>, _>("attachments")
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;
		let attachments = if let Some(attachments) = &attachments {
			let mut attachments = parse_str_list(attachments)
				.iter()
				.map(|a| AttachmentView { file_id: a.clone(), dim: None, local_variants: None })
				.collect::<Vec<_>>();
			for a in attachments.iter_mut() {
				// Handle both @{f_id} placeholders and real file_ids
				let query_result = if let Some(f_id_str) = a.file_id.strip_prefix('@') {
					// Query by f_id
					if let Ok(f_id) = f_id_str.parse::<i64>() {
						sqlx::query("SELECT x->>'dim' as dim FROM files WHERE tn_id=? AND f_id=?")
							.bind(tn_id.0)
							.bind(f_id)
							.fetch_one(db)
							.await
					} else {
						Err(sqlx::Error::RowNotFound)
					}
				} else {
					// Query by file_id
					sqlx::query("SELECT x->>'dim' as dim FROM files WHERE tn_id=? AND file_id=?")
						.bind(tn_id.0)
						.bind(&a.file_id)
						.fetch_one(db)
						.await
				};

				if let Ok(file_res) = query_result.inspect_err(inspect) {
					if let Ok(Some(dim_str)) = file_res.try_get::<Option<&str>, _>("dim") {
						if !dim_str.is_empty() {
							a.dim = serde_json::from_str(dim_str)?;
						}
					}
				}

				// Query local variants
				let variants = if let Some(f_id_str) = a.file_id.strip_prefix('@') {
					// Query by f_id for placeholder IDs
					if let Ok(f_id) = f_id_str.parse::<i64>() {
						crate::file::list_available_variants_by_fid(db, tn_id, f_id).await.ok()
					} else {
						None
					}
				} else {
					// Query by file_id for real IDs
					crate::file::list_available_variants(db, tn_id, &a.file_id).await.ok()
				};
				if let Some(variants) = variants {
					if !variants.is_empty() {
						a.local_variants = Some(variants);
					}
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
		let comments_read: i64 = row.try_get("comments_read").unwrap_or(0);
		let own_reaction: Option<String> = row.try_get("own_reaction").ok().flatten();
		let own_reaction_json: Option<serde_json::Value> =
			own_reaction.as_ref().and_then(|s| serde_json::from_str(s).ok());
		let mut stat_obj = serde_json::json!({
			"comments": comments_count,
			"commentsRead": comments_read,
			"reactions": reactions_count
		});
		if let Some(own_reaction) = own_reaction_json {
			stat_obj["ownReaction"] = own_reaction;
		}
		let stat = Some(stat_obj);
		let visibility: Option<String> = row.try_get("visibility").ok();
		let visibility = visibility.and_then(|s| s.chars().next());
		actions.push(ActionView {
			action_id,
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
			content: row
				.try_get::<Option<String>, _>("content")
				.map_err(|_| Error::DbError)?
				.and_then(|s| serde_json::from_str(&s).ok()),
			attachments,
			created_at: row.try_get("created_at").map(Timestamp).map_err(|_| Error::DbError)?,
			expires_at: row
				.try_get("expires_at")
				.map(|ts: Option<i64>| ts.map(Timestamp))
				.map_err(|_| Error::DbError)?,
			status: row.try_get("status").map_err(|_| Error::DbError)?,
			stat,
			visibility,
			flags: row.try_get("flags").map_err(|_| Error::DbError)?,
			x: row
				.try_get::<Option<String>, _>("x")
				.map_err(|_| Error::DbError)?
				.and_then(|s| serde_json::from_str(&s).ok()),
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

/// Create a new action (creates pending action with a_id, no action_id yet)
pub(crate) async fn create(
	db: &SqlitePool,
	tn_id: TnId,
	action: &Action<&str>,
	key: Option<&str>,
) -> ClResult<ActionId<Box<str>>> {
	// If action already has action_id (inbound federation), check if it exists
	if !action.action_id.is_empty() {
		let action_id_exists = sqlx::query(
			"SELECT action_id FROM actions WHERE tn_id=? AND action_id=? AND status!='D'",
		)
		.bind(tn_id.0)
		.bind(action.action_id)
		.fetch_optional(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?
		.and_then(|row| row.get(0));

		if let Some(action_id) = action_id_exists {
			return Ok(ActionId::ActionId(action_id));
		}
	}

	// For inbound actions with a key, delete old actions with the same key first
	// This handles key-based deduplication for inbound actions (outbound actions
	// handle this in finalize())
	if !action.action_id.is_empty() {
		if let Some(key) = key {
			info!("Inbound action with key: {}, deleting old entries", key);
			sqlx::query(
				"UPDATE actions SET status='D' WHERE tn_id=? AND key=? AND coalesce(status, 'A')!='D'",
			)
			.bind(tn_id.0)
			.bind(key)
			.execute(db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;
		}
	}

	let status = "P";
	let visibility = action.visibility.map(|c| c.to_string());
	let x_json = action.x.as_ref().and_then(|v| serde_json::to_string(v).ok());
	let res = sqlx::query(
		"INSERT INTO actions (tn_id, action_id, key, type, sub_type, parent_id, root_id, issuer_tag, audience, subject, content, created_at, expires_at, attachments, status, visibility, flags, x)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING a_id"
	)
		.bind(tn_id.0)
		.bind(if action.action_id.is_empty() { None } else { Some(action.action_id) })
		.bind(key)
		.bind(action.typ)
		.bind(action.sub_typ)
		.bind(action.parent_id)
		.bind(action.root_id)
		.bind(action.issuer_tag)
		.bind(action.audience_tag)
		.bind(action.subject)
		.bind(action.content)
		.bind(action.created_at.0)
		.bind(action.expires_at.map(|t| t.0))
		.bind(action.attachments.as_ref().map(|s| s.join(",")))
		.bind(status)
		.bind(visibility)
		.bind(action.flags)
		.bind(x_json)
		.fetch_one(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	Ok(ActionId::AId(res.get(0)))
}

/// Finalize action - atomically set action_id, update attachments/subject/audience/key, and transition from 'P' to 'A' status
pub(crate) async fn finalize(
	db: &SqlitePool,
	tn_id: TnId,
	a_id: u64,
	action_id: &str,
	options: FinalizeActionOptions<'_>,
) -> ClResult<()> {
	// First check if action exists and what its current action_id is
	let existing = sqlx::query("SELECT action_id, status FROM actions WHERE tn_id=? AND a_id=?")
		.bind(tn_id.0)
		.bind(a_id as i64)
		.fetch_optional(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	match existing {
		None => {
			// Action doesn't exist at all
			return Err(Error::NotFound);
		}
		Some(row) => {
			let existing_action_id: Option<String> = row.try_get("action_id").ok().flatten();
			let status: Option<String> = row.try_get("status").ok().flatten();

			if let Some(existing_id) = existing_action_id {
				// Already has an action_id - check if it matches
				if existing_id == action_id {
					// Idempotent success - already set to the correct value
					return Ok(());
				} else {
					// Different action_id - this is a conflict
					let msg = format!(
						"Attempted to finalize a_id={} to action_id={} but already set to {}",
						a_id, action_id, existing_id
					);
					error!("{}", msg);
					return Err(Error::Conflict(msg));
				}
			}

			// action_id is NULL - verify status is 'P'
			if status.as_deref() != Some("P") {
				let msg = format!(
					"Attempted to finalize a_id={} but status is {:?}, expected 'P'",
					a_id, status
				);
				error!("{}", msg);
				return Err(Error::Conflict(msg));
			}
		}
	}

	// Update NULL action_id to new value, update attachments/subject/audience/key, and transition status from 'P' to 'A'
	let mut tx = db.begin().await.map_err(|_| Error::DbError)?;

	let attachments_str = options.attachments.map(|a| a.join(","));
	let res = sqlx::query(
		"UPDATE actions SET action_id=?, attachments=?, subject=COALESCE(?, subject), audience=COALESCE(?, audience), key=COALESCE(?, key), status='A' WHERE tn_id=? AND a_id=? AND action_id IS NULL AND status='P'"
	)
		.bind(action_id)
		.bind(attachments_str)
		.bind(options.subject)
		.bind(options.audience_tag)
		.bind(options.key)
		.bind(tn_id.0)
		.bind(a_id as i64)
		.execute(&mut *tx)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	if res.rows_affected() == 0 {
		// Race condition - someone else just set it between our check and update.
		// Re-check what value was set (idempotent verification)
		let current = sqlx::query("SELECT action_id FROM actions WHERE tn_id=? AND a_id=?")
			.bind(tn_id.0)
			.bind(a_id as i64)
			.fetch_optional(&mut *tx)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

		tx.rollback().await.map_err(|_| Error::DbError)?;

		if let Some(row) = current {
			if let Some(existing_id) = row.try_get::<Option<String>, _>("action_id").ok().flatten()
			{
				if existing_id == action_id {
					// Idempotent success - another task set it to the same value
					return Ok(());
				} else {
					// Conflict - set to different value
					let msg = format!(
						"Race condition: a_id={} was set to {} instead of {}",
						a_id, existing_id, action_id
					);
					error!("{}", msg);
					return Err(Error::Conflict(msg));
				}
			}
		}

		return Err(Error::Internal("Failed to finalize action".into()));
	}

	// Handle key-based deduplication for finalized actions
	let action = sqlx::query("SELECT key FROM actions WHERE tn_id=? AND a_id=?")
		.bind(tn_id.0)
		.bind(a_id as i64)
		.fetch_one(&mut *tx)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;

	let key: Option<String> = action.try_get("key").ok().flatten();

	if let Some(key) = &key {
		info!("Finalizing with key: {}", key);
		// Delete old entries with the same key (key-based deduplication)
		sqlx::query(
			"UPDATE actions SET status='D' WHERE tn_id=? AND key=? AND a_id!=? AND coalesce(status, 'A')!='D'",
		)
		.bind(tn_id.0)
		.bind(key)
		.bind(a_id as i64)
		.execute(&mut *tx)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;
	}

	tx.commit().await.inspect_err(inspect).map_err(|_| Error::DbError)?;
	Ok(())
}

/// Get action_id from a_id
pub(crate) async fn get_id(db: &SqlitePool, tn_id: TnId, a_id: u64) -> ClResult<Box<str>> {
	let res = sqlx::query("SELECT action_id FROM actions WHERE tn_id=? AND a_id=?")
		.bind(tn_id.0)
		.bind(a_id as i64)
		.fetch_one(db)
		.await
		.inspect_err(inspect)
		.map_err(|_| Error::NotFound)?;

	let action_id: String = res.try_get("action_id").map_err(|_| Error::NotFound)?;
	Ok(action_id.into_boxed_str())
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

/// Get related action tokens by APRV action_id
/// Returns (action_id, token) pairs for actions that have ack = aprv_action_id
pub(crate) async fn get_related_tokens(
	db: &SqlitePool,
	tn_id: TnId,
	aprv_action_id: &str,
) -> ClResult<Vec<(Box<str>, Box<str>)>> {
	let rows =
		sqlx::query("SELECT action_id, token FROM action_tokens WHERE tn_id = ? AND ack = ?")
			.bind(tn_id.0)
			.bind(aprv_action_id)
			.fetch_all(db)
			.await
			.inspect_err(inspect)
			.map_err(|_| Error::DbError)?;

	let mut result = Vec::with_capacity(rows.len());
	for row in rows {
		let action_id: String = row.try_get("action_id").map_err(|_| Error::DbError)?;
		let token: String = row.try_get("token").map_err(|_| Error::DbError)?;
		result.push((action_id.into_boxed_str(), token.into_boxed_str()));
	}

	Ok(result)
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
	let res = sqlx::query("SELECT action_id, type, sub_type, issuer_tag, parent_id, root_id, audience, content, attachments, subject, created_at, expires_at, visibility, flags, x
		FROM actions WHERE tn_id=? AND key=?")
		.bind(tn_id.0)
		.bind(action_key)
		.fetch_optional(db).await;

	match res {
		Ok(Some(row)) => {
			let attachments_str: Option<Box<str>> = row.try_get("attachments").ok();
			let attachments = attachments_str.map(|s| parse_str_list(&s).to_vec());
			let visibility: Option<String> = row.try_get("visibility").ok();
			let visibility = visibility.and_then(|s| s.chars().next());

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
				visibility,
				flags: row.try_get("flags").ok(),
				x: row
					.try_get::<Option<String>, _>("x")
					.ok()
					.flatten()
					.and_then(|s| serde_json::from_str(&s).ok()),
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
	use cloudillo::types::Patch;

	// Build dynamic UPDATE query based on which fields are set
	let mut set_clauses = Vec::new();

	if !opts.subject.is_undefined() {
		set_clauses.push("subject = ?");
	}
	if !opts.reactions.is_undefined() {
		set_clauses.push("reactions = ?");
	}
	if !opts.comments.is_undefined() {
		set_clauses.push("comments = ?");
	}
	if !opts.comments_read.is_undefined() {
		set_clauses.push("comments_read = ?");
	}
	if !opts.status.is_undefined() {
		set_clauses.push("status = ?");
	}
	if !opts.visibility.is_undefined() {
		set_clauses.push("visibility = ?");
	}
	if !opts.x.is_undefined() {
		set_clauses.push("x = ?");
	}

	if set_clauses.is_empty() {
		return Ok(()); // Nothing to update
	}

	let sql =
		format!("UPDATE actions SET {} WHERE tn_id = ? AND action_id = ?", set_clauses.join(", "));

	let mut query = sqlx::query(&sql);

	// Bind values in the same order as set_clauses
	if !opts.subject.is_undefined() {
		let val: Option<&str> = match &opts.subject {
			Patch::Null => None,
			Patch::Value(v) => Some(v.as_str()),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}
	if !opts.reactions.is_undefined() {
		let val: Option<u32> = match &opts.reactions {
			Patch::Null => None,
			Patch::Value(v) => Some(*v),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}
	if !opts.comments.is_undefined() {
		let val: Option<u32> = match &opts.comments {
			Patch::Null => None,
			Patch::Value(v) => Some(*v),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}
	if !opts.comments_read.is_undefined() {
		let val: Option<u32> = match &opts.comments_read {
			Patch::Null => None,
			Patch::Value(v) => Some(*v),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}
	if !opts.status.is_undefined() {
		let val: Option<String> = match &opts.status {
			Patch::Null => None,
			Patch::Value(c) => Some(c.to_string()),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}
	if !opts.visibility.is_undefined() {
		let val: Option<String> = match &opts.visibility {
			Patch::Null => None,
			Patch::Value(c) => Some(c.to_string()),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}
	if !opts.x.is_undefined() {
		let val: Option<String> = match &opts.x {
			Patch::Null => None,
			Patch::Value(v) => serde_json::to_string(v).ok(),
			Patch::Undefined => unreachable!(),
		};
		query = query.bind(val);
	}

	// Bind WHERE clause params
	query = query.bind(tn_id.0).bind(action_id);

	let res = query.execute(db).await.inspect_err(inspect).map_err(|_| Error::DbError)?;

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

/// Get a single action by action_id with issuer and audience profiles
pub(crate) async fn get(
	db: &SqlitePool,
	tn_id: TnId,
	action_id: &str,
) -> ClResult<Option<ActionView>> {
	let row = sqlx::query(
		"SELECT a.a_id, a.type, a.sub_type, a.action_id, a.parent_id, a.root_id, a.issuer_tag,
		pi.name as issuer_name, pi.profile_pic as issuer_profile_pic,
		a.audience, pa.name as audience_name, pa.profile_pic as audience_profile_pic,
		a.subject, a.content, a.created_at, a.expires_at,
		a.attachments, a.status, a.reactions, a.comments, a.comments_read, a.visibility, a.flags, a.x
		FROM actions a
		LEFT JOIN profiles pi ON pi.tn_id=a.tn_id AND pi.id_tag=a.issuer_tag
		LEFT JOIN profiles pa ON pa.tn_id=a.tn_id AND pa.id_tag=a.audience
		WHERE a.tn_id=? AND a.action_id=? AND coalesce(a.status, 'A') NOT IN ('D')",
	)
	.bind(tn_id.0)
	.bind(action_id)
	.fetch_optional(db)
	.await
	.inspect_err(inspect)
	.map_err(|_| Error::DbError)?;

	let Some(row) = row else {
		return Ok(None);
	};

	let issuer_tag = row.try_get::<Box<str>, _>("issuer_tag").map_err(|_| Error::DbError)?;
	let audience_tag =
		row.try_get::<Option<Box<str>>, _>("audience").map_err(|_| Error::DbError)?;

	// Parse attachments
	let attachments = row
		.try_get::<Option<Box<str>>, _>("attachments")
		.inspect_err(inspect)
		.map_err(|_| Error::DbError)?;
	let attachments = if let Some(attachments) = &attachments {
		let mut attachments = parse_str_list(attachments)
			.iter()
			.map(|a| AttachmentView { file_id: a.clone(), dim: None, local_variants: None })
			.collect::<Vec<_>>();
		for a in attachments.iter_mut() {
			// Query file dimensions
			let query_result = if let Some(f_id_str) = a.file_id.strip_prefix('@') {
				if let Ok(f_id) = f_id_str.parse::<i64>() {
					sqlx::query("SELECT x->>'dim' as dim FROM files WHERE tn_id=? AND f_id=?")
						.bind(tn_id.0)
						.bind(f_id)
						.fetch_one(db)
						.await
				} else {
					Err(sqlx::Error::RowNotFound)
				}
			} else {
				sqlx::query("SELECT x->>'dim' as dim FROM files WHERE tn_id=? AND file_id=?")
					.bind(tn_id.0)
					.bind(&a.file_id)
					.fetch_one(db)
					.await
			};

			if let Ok(file_res) = query_result.inspect_err(inspect) {
				if let Ok(Some(dim_str)) = file_res.try_get::<Option<&str>, _>("dim") {
					if !dim_str.is_empty() {
						a.dim = serde_json::from_str(dim_str)?;
					}
				}
			}

			// Query local variants
			let variants = if let Some(f_id_str) = a.file_id.strip_prefix('@') {
				// Query by f_id for placeholder IDs
				if let Ok(f_id) = f_id_str.parse::<i64>() {
					crate::file::list_available_variants_by_fid(db, tn_id, f_id).await.ok()
				} else {
					None
				}
			} else {
				// Query by file_id for real IDs
				crate::file::list_available_variants(db, tn_id, &a.file_id).await.ok()
			};
			if let Some(variants) = variants {
				if !variants.is_empty() {
					a.local_variants = Some(variants);
				}
			}
		}
		Some(attachments)
	} else {
		None
	};

	// Build stat from reactions and comments counts
	let reactions_count: i64 = row.try_get("reactions").unwrap_or(0);
	let comments_count: i64 = row.try_get("comments").unwrap_or(0);
	let comments_read: i64 = row.try_get("comments_read").unwrap_or(0);
	let stat = Some(serde_json::json!({
		"comments": comments_count,
		"commentsRead": comments_read,
		"reactions": reactions_count
	}));

	let visibility: Option<String> = row.try_get("visibility").ok();
	let visibility = visibility.and_then(|s| s.chars().next());

	Ok(Some(ActionView {
		action_id: row.try_get::<Box<str>, _>("action_id").map_err(|_| Error::DbError)?,
		typ: row.try_get::<Box<str>, _>("type").map_err(|_| Error::DbError)?,
		sub_typ: row.try_get::<Option<Box<str>>, _>("sub_type").map_err(|_| Error::DbError)?,
		parent_id: row.try_get::<Option<Box<str>>, _>("parent_id").map_err(|_| Error::DbError)?,
		root_id: row.try_get::<Option<Box<str>>, _>("root_id").map_err(|_| Error::DbError)?,
		issuer: ProfileInfo {
			id_tag: issuer_tag,
			name: row
				.try_get::<Option<Box<str>>, _>("issuer_name")
				.map_err(|_| Error::DbError)?
				.unwrap_or_else(|| "Unknown".into()),
			typ: ProfileType::Person,
			profile_pic: row
				.try_get::<Option<Box<str>>, _>("issuer_profile_pic")
				.map_err(|_| Error::DbError)?,
		},
		audience: if let Some(audience_tag) = audience_tag {
			Some(ProfileInfo {
				id_tag: audience_tag,
				name: row
					.try_get::<Option<Box<str>>, _>("audience_name")
					.map_err(|_| Error::DbError)?
					.unwrap_or_else(|| "Unknown".into()),
				typ: ProfileType::Person,
				profile_pic: row
					.try_get::<Option<Box<str>>, _>("audience_profile_pic")
					.map_err(|_| Error::DbError)?,
			})
		} else {
			None
		},
		subject: row.try_get("subject").map_err(|_| Error::DbError)?,
		content: row
			.try_get::<Option<String>, _>("content")
			.map_err(|_| Error::DbError)?
			.and_then(|s| serde_json::from_str(&s).ok()),
		attachments,
		created_at: row.try_get("created_at").map(Timestamp).map_err(|_| Error::DbError)?,
		expires_at: row
			.try_get("expires_at")
			.map(|ts: Option<i64>| ts.map(Timestamp))
			.map_err(|_| Error::DbError)?,
		status: row.try_get("status").map_err(|_| Error::DbError)?,
		stat,
		visibility,
		flags: row.try_get("flags").map_err(|_| Error::DbError)?,
		x: row
			.try_get::<Option<String>, _>("x")
			.map_err(|_| Error::DbError)?
			.and_then(|s| serde_json::from_str(&s).ok()),
	}))
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
