// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! `GET /api/files/{file_id}/access` — the **effective** access of an entry: its audience, the user
//! grants on it and on every ancestor folder, and its share links, shaped by the caller's standing.
//!
//! Behind `check_perm_file("read")`, so anyone who can read the entry may call it; the shaping is
//! what keeps the response within what that caller may see:
//!
//! - a link guest (anonymous, `file:` scope minted from a ref) gets the owner and `shared` only;
//! - a reader/commenter gets the owner, audience and `callerLevel` only: grantees and links are the
//!   share set, which only writers may list (`share_access::is_share_reader`);
//! - a writer or share manager additionally gets the grantees with `permission`/`expiresAt` and the
//!   links. Only a manager gets a usable `refId`, and only for links on the entry itself — everyone
//!   else gets the same surrogate `GET /api/refs` hands a share *reader* (`redacted: true`);
//! - any other scoped token is held to the reader shape, as `share_access` refuses it the share
//!   set.
//!
//! Ancestor grants are listed up to the first ancestor whose share set the caller may read.
//!
//! Share links are `share.file` refs only (`refs.resource_id` = the entry id). `share_entries` rows
//! with `subject_type = 'L'` grant nothing on any access path, so they are not links here.

use std::collections::HashSet;

use axum::{Extension, Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Serialize;

use crate::handler::build_path;
use crate::perm::{ResolvedEntry, ResolvedLevel};
use crate::prelude::*;
use cloudillo_core::abac::VisibilityLevel;
use cloudillo_core::channels::reader_enterable_channels;
use cloudillo_core::dir_cache::DirCache;
use cloudillo_core::extract::{IdTag, OptionalAuth, OptionalRequestId};
use cloudillo_core::share_access::{ShareStanding, share_standing};
use cloudillo_types::auth_adapter::AuthCtx;
use cloudillo_types::hasher;
use cloudillo_types::meta_adapter::{self, ListRefsOptions, SHARE_FILE_REF_TYPE, ShareEntry};
use cloudillo_types::types::{AccessLevel, ApiResponse, TokenScope, serialize_timestamp_iso_opt};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FileAccess {
	owner: AccessOwner,
	audience: AccessAudience,
	people: Vec<AccessPerson>,
	/// Writers and share managers only.
	#[serde(skip_serializing_if = "Option::is_none")]
	links: Option<AccessLinks>,
	caller_level: AccessLevel,
	can_manage: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessOwner {
	id_tag: Box<str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessAudience {
	/// `owner` | `members` | `room` | `shared` | `public` | `verified` | `secondDegree` |
	/// `followers` | `connections` | `subscribers`
	kind: &'static str,
	#[serde(skip_serializing_if = "Option::is_none")]
	channel: Option<AccessChannel>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessChannel {
	/// Bare room name (no `@tenant~`).
	name: Box<str>,
	#[serde(skip_serializing_if = "Option::is_none")]
	title: Option<Box<str>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	min_role: Option<Box<str>>,
	closed: bool,
	/// Closed rooms only, as `PorchMember`.
	#[serde(skip_serializing_if = "Option::is_none")]
	member_count: Option<usize>,
}

/// Where an inherited grant or link comes from.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessSource {
	entry_id: Box<str>,
	file_name: Box<str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessPerson {
	id_tag: Box<str>,
	/// Share permission char `R|C|W|A`.
	permission: char,
	#[serde(
		skip_serializing_if = "Option::is_none",
		serialize_with = "serialize_timestamp_iso_opt"
	)]
	expires_at: Option<Timestamp>,
	inherited: bool,
	/// Absent = direct.
	#[serde(skip_serializing_if = "Option::is_none")]
	inherited_from: Option<AccessSource>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessLinks {
	count: usize,
	items: Vec<AccessLink>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessLink {
	ref_id: Box<str>,
	/// `true` when `ref_id` is the opaque surrogate, not the bearer credential.
	#[serde(skip_serializing_if = "std::ops::Not::not")]
	redacted: bool,
	/// `read` | `comment` | `write` (a link never carries admin).
	access_level: &'static str,
	#[serde(
		skip_serializing_if = "Option::is_none",
		serialize_with = "serialize_timestamp_iso_opt"
	)]
	expires_at: Option<Timestamp>,
	/// Absent = direct.
	#[serde(skip_serializing_if = "Option::is_none")]
	inherited_from: Option<AccessSource>,
}

/// An anonymous token minted from a share-link ref.
fn is_link_guest(auth: &AuthCtx) -> bool {
	auth.anonymous
		&& matches!(
			auth.scope.as_deref().and_then(TokenScope::parse),
			Some(TokenScope::File { ref_id: Some(_), .. })
		)
}

/// The room row behind an absolute `@tenant~name` channel; `None` if not this tenant's or gone.
async fn read_room(
	app: &App,
	tn_id: TnId,
	tenant_id_tag: &str,
	channel: &str,
) -> ClResult<Option<AccessChannel>> {
	let Some(name) = channel
		.strip_prefix('@')
		.and_then(|c| c.strip_prefix(tenant_id_tag))
		.and_then(|c| c.strip_prefix('~'))
	else {
		return Ok(None);
	};
	let room = match app.meta_adapter.read_channel(tn_id, name).await {
		Ok(room) => room,
		Err(Error::NotFound) => return Ok(None),
		Err(e) => return Err(e),
	};
	let member_count = if room.closed {
		Some(app.meta_adapter.list_channel_members(tn_id, &room.name).await?.len())
	} else {
		None
	};
	Ok(Some(AccessChannel {
		name: room.name,
		title: room.title,
		min_role: room.min_role,
		closed: room.closed,
		member_count,
	}))
}

/// One user grant found on the walk; `source` is `None` for a grant on the entry itself.
struct Grant {
	entry: ShareEntry,
	depth: usize,
	source: Option<AccessSource>,
}

/// GET /api/files/{file_id}/access — effective access of the resolved entry
pub async fn get_file_access(
	State(app): State<App>,
	IdTag(tenant_id_tag): IdTag,
	tn_id: TnId,
	OptionalAuth(maybe_auth): OptionalAuth,
	Extension(ResolvedEntry(file)): Extension<ResolvedEntry>,
	Extension(ResolvedLevel(level)): Extension<ResolvedLevel>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<impl IntoResponse> {
	let owner_tag: Box<str> = file
		.owner
		.as_ref()
		.map(|p| p.id_tag.clone())
		.filter(|t| !t.is_empty())
		.unwrap_or_else(|| tenant_id_tag.clone());
	let owner = AccessOwner { id_tag: owner_tag };
	let access = if maybe_auth.as_ref().is_some_and(is_link_guest) {
		FileAccess {
			owner,
			audience: AccessAudience { kind: "shared", channel: None },
			people: Vec::new(),
			links: None,
			caller_level: level,
			can_manage: false,
		}
	} else {
		access_for_caller(&app, tn_id, &tenant_id_tag, maybe_auth.as_ref(), &file, owner, level)
			.await?
	};
	let response = ApiResponse::new(access).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

/// The access of `file` for any caller but a link guest.
async fn access_for_caller(
	app: &App,
	tn_id: TnId,
	tenant_id_tag: &str,
	maybe_auth: Option<&AuthCtx>,
	file: &meta_adapter::FileView,
	owner: AccessOwner,
	level: AccessLevel,
) -> ClResult<FileAccess> {
	// Same rule as `require_share_manager`; `share_standing` refuses scoped tokens, so only an
	// unscoped authenticated caller is asked.
	let unscoped = maybe_auth.filter(|a| a.scope.is_none());
	let can_manage = match unscoped {
		Some(auth) => match share_standing(app, tn_id, &file.entry_id, auth, tenant_id_tag).await {
			Ok(authority) => authority.standing == ShareStanding::Manager,
			Err(Error::PermissionDenied | Error::NotFound) => false,
			Err(e) => return Err(e),
		},
		None => false,
	};
	let detailed = unscoped.is_some() && (can_manage || level.can_write());

	let audience = if let Some(channel) = file.channel.as_deref() {
		// Room details only to a caller who may enter it.
		let (subject, roles) =
			maybe_auth.map_or(("", &[][..]), |a| (a.id_tag.as_ref(), &a.roles[..]));
		let enterable =
			reader_enterable_channels(app, tn_id, tenant_id_tag, maybe_auth, subject, roles)
				.await?
				.is_none_or(|list| list.iter().any(|c| c.as_ref() == channel));
		let channel =
			if enterable { read_room(app, tn_id, tenant_id_tag, channel).await? } else { None };
		AccessAudience { kind: "room", channel }
	} else {
		// Mirrored by `push_access_filter` (meta-adapter-sqlite); the access matrix
		// `access_filter_agrees_with_access_endpoint` scenario checks the two agree.
		let kind = match VisibilityLevel::from_char(file.visibility) {
			VisibilityLevel::Public => "public",
			VisibilityLevel::Verified => "verified",
			VisibilityLevel::SecondDegree => "secondDegree",
			VisibilityLevel::Follower => "followers",
			VisibilityLevel::Connected => "connections",
			VisibilityLevel::Subscribed => "subscribers",
			// NULL / 'D': owner plus members (role holders), see `push_entry_gate`.
			VisibilityLevel::Direct => {
				let tenant = app.meta_adapter.read_tenant(tn_id).await?;
				if matches!(tenant.typ, meta_adapter::ProfileType::Community) {
					"members"
				} else {
					"owner"
				}
			}
		};
		AccessAudience { kind, channel: None }
	};

	if !detailed {
		return Ok(FileAccess {
			owner,
			audience,
			people: Vec::new(),
			links: None,
			caller_level: level,
			can_manage,
		});
	}

	// Level 0 is the entry itself; every later level is an ancestor folder, closest first.
	let cache = app.ext::<DirCache>()?;
	let mut path = build_path(app, cache, tn_id, file.parent_id.as_deref(), None).await;
	path.reverse();
	let levels = std::iter::once((file.entry_id.clone(), None))
		.chain(path.into_iter().map(|seg| (seg.id, Some(seg.name))));

	let now = Timestamp::now().0;
	let mut grants = Vec::new();
	let mut links = Vec::new();
	for (depth, (entry_id, name)) in levels.enumerate() {
		// An ancestor's grants and links are its share set, which needs share-reader standing on
		// that ancestor (as `GET /api/shares`); stop at the first one the caller may not read.
		if name.is_some() {
			let Some(auth) = unscoped else { break };
			match share_standing(app, tn_id, &entry_id, auth, tenant_id_tag).await {
				Ok(a) if a.standing >= ShareStanding::Reader => {}
				Ok(_) | Err(Error::PermissionDenied | Error::NotFound) => break,
				Err(e) => return Err(e),
			}
		}
		// two queries per ancestor level; one recursive CTE if deep trees get slow.
		let shares = app.meta_adapter.list_share_entries(tn_id, 'F', &entry_id).await?;
		let refs = app
			.meta_adapter
			.list_refs(
				tn_id,
				&ListRefsOptions {
					typ: Some(SHARE_FILE_REF_TYPE.into()),
					filter: Some("active".into()),
					resource_id: Some(entry_id.to_string()),
				},
			)
			.await?;
		let shares: Vec<ShareEntry> = shares
			.into_iter()
			.filter(|s| {
				s.subject_type == 'U'
					&& *s.subject_id != *owner.id_tag
					&& s.expires_at.is_none_or(|t| t.0 > now)
			})
			.collect();
		if shares.is_empty() && refs.is_empty() {
			continue;
		}
		let source = name.map(|file_name| AccessSource { entry_id: entry_id.clone(), file_name });
		grants.extend(shares.into_iter().map(|entry| Grant {
			entry,
			depth,
			source: source.clone(),
		}));
		links.extend(refs.into_iter().map(|r| (r, source.clone())));
	}

	// Per idTag the grant at the smallest depth wins (direct first); within one depth the newest
	// (`created_at`, then `id`, descending).
	grants.sort_by(|a, b| {
		a.depth
			.cmp(&b.depth)
			.then(b.entry.created_at.0.cmp(&a.entry.created_at.0))
			.then(b.entry.id.cmp(&a.entry.id))
	});
	let mut seen = HashSet::new();
	grants.retain(|g| seen.insert(g.entry.subject_id.clone()));
	// Display order only.
	let rank = |g: &Grant| AccessLevel::from_perm_char(g.entry.permission);
	grants.sort_by(|a, b| {
		rank(b)
			.cmp(&rank(a))
			.then(b.entry.created_at.0.cmp(&a.entry.created_at.0))
			.then(b.entry.id.cmp(&a.entry.id))
	});

	let people = grants
		.into_iter()
		.map(|g| AccessPerson {
			id_tag: g.entry.subject_id,
			permission: g.entry.permission,
			expires_at: g.entry.expires_at,
			inherited: g.source.is_some(),
			inherited_from: g.source,
		})
		.collect();

	let count = links.len();
	let items = links
		.into_iter()
		.map(|(r, source)| {
			// The real credential only to a manager, and only for a link on this entry: an
			// ancestor's link re-shares the whole ancestor, which this standing does not cover.
			let real = can_manage && source.is_none();
			AccessLink {
				ref_id: if real { r.ref_id } else { hasher::ref_surrogate(&r.ref_id) },
				redacted: !real,
				access_level: AccessLevel::from_link_char(r.access_level.unwrap_or('R')).as_str(),
				expires_at: r.expires_at,
				inherited_from: source,
			}
		})
		.collect();

	Ok(FileAccess {
		owner,
		audience,
		people,
		links: Some(AccessLinks { count, items }),
		caller_level: level,
		can_manage,
	})
}

// vim: ts=4
