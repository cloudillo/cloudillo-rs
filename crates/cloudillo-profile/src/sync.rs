// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Profile synchronization from remote instances

use crate::prelude::*;
use crate::settings::MAX_SHOWN_BADGES;
use cloudillo_core::request::ConditionalResult;
use cloudillo_core::scheduler::{RetryPolicy, Task, TaskId};
use cloudillo_types::auth_adapter::{ActionToken, AuditCategory, AuditEvent};
use cloudillo_types::badges::{BADGE_EXP_SLACK_SECS, badge_claims, read_badge_issuer};
use cloudillo_types::meta_adapter::{
	Profile, ProfileBadgeRow, ProfileStatus, ProfileType, UpsertProfileFields, UpsertResult,
	VerifiedBadge,
};
use cloudillo_types::types::{ApiResponse, PROTOCOL_VERSION, ProfileBase};
use cloudillo_types::utils::{decode_jwt_no_verify, normalize_id_tag};
use cloudillo_types::validation::validate_id_tag;

use async_trait::async_trait;
use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Stale profile threshold in seconds (24 hours)
const STALE_PROFILE_THRESHOLD_SECS: i64 = 86400;
/// Maximum profiles to process per batch
const BATCH_SIZE: u32 = 100;
/// Days of continuous sync failure before flipping a profile to Suspended.
const DEACTIVATE_AFTER_DAYS: i64 = 1;
/// Days of continuous sync failure before the refresh batch stops attempting.
const DISABLE_REFRESH_AFTER_DAYS: i64 = 7;
const SECS_PER_DAY: i64 = 86400;
/// The single profile-picture variant we mirror locally (public, hashed thumbnail).
const PROFILE_PIC_VARIANT: &str = "vis.pf";

/// Cap of [`PROTOCOL_MISMATCH_SEEN`]
const MAX_PROTOCOL_MISMATCH_SEEN: usize = 1024;

/// Peers already reported with a different `protocolVersion`, once per process lifetime.
static PROTOCOL_MISMATCH_SEEN: std::sync::LazyLock<
	parking_lot::Mutex<std::collections::HashSet<Box<str>>>,
> = std::sync::LazyLock::new(Default::default);

/// Log and audit a peer whose advertised protocol version differs from ours, once per peer.
/// A missing version (a node predating it) is not a mismatch. Nothing is dropped.
async fn check_protocol_version(app: &App, id_tag: &str, remote: &ProfileBase) {
	let Some(version) = remote.protocol_version.filter(|v| *v != PROTOCOL_VERSION) else {
		return;
	};
	let first = {
		let mut seen = PROTOCOL_MISMATCH_SEEN.lock();
		// Clear-on-full, a peer may be re-reported after 1024 distinct mismatches
		if seen.len() >= MAX_PROTOCOL_MISMATCH_SEEN {
			seen.clear();
		}
		seen.insert(id_tag.into())
	};
	if !first {
		return;
	}
	warn!(peer = %id_tag, remote = version, local = PROTOCOL_VERSION,
		"federation protocol version mismatch");
	let ev = AuditEvent {
		details: Some(serde_json::json!({
			"peer": id_tag,
			"remoteVersion": version,
			"localVersion": PROTOCOL_VERSION,
		})),
		..AuditEvent::new(AuditCategory::Admin, "federation.protocol_mismatch", "fail")
	};
	cloudillo_core::audit::record(app, ev).await;
}

/// Returns true if the local `vis.pf` variant of a remote profile picture is
/// already cached in `file_variants`. Used to retry the picture-only sync
/// when the profile row has the right `file_id` but the variant blob never
/// landed (e.g. transient network failure during initial sync).
async fn local_profile_pic_present(app: &App, tn_id: TnId, file_id: &str) -> bool {
	// "Present" means we read the variant successfully. Any error (NotFound,
	// DB error, lock error) is treated as "not confirmed present" so the
	// best-effort retry path is still taken — that's the safe direction.
	let variant_id = format!("{}:{}", file_id, PROFILE_PIC_VARIANT);
	app.meta_adapter.read_file_variant(tn_id, &variant_id).await.is_ok()
}

/// Ensure a profile exists locally by fetching from remote if needed.
///
/// This function:
/// 1. Checks if the profile already exists locally
/// 2. If not, fetches the profile from the remote instance
/// 3. Creates the profile locally with the fetched data
///
/// Returns Ok(true) if the profile was synced (created), Ok(false) if it already existed.
pub async fn ensure_profile(app: &App, tn_id: TnId, id_tag: &str) -> ClResult<bool> {
	// Check if profile already exists
	if app.meta_adapter.read_profile(tn_id, id_tag).await.is_ok() {
		tracing::debug!("Profile {} already exists locally", id_tag);
		return Ok(false);
	}

	// Fetch profile from remote instance
	tracing::info!("Syncing profile {} from remote instance", id_tag);

	// Use the conditional request (auth-less, like the old `get_noauth`) so we
	// capture the *real* etag from the response instead of a synthetic value.
	// No stored etag yet → `None` → a normal 200 with the peer's etag.
	let result: ClResult<ConditionalResult<ApiResponse<ProfileBase>>> =
		app.request.get_conditional(id_tag, "/me", None).await;

	match result {
		Ok(ConditionalResult::Modified { data: api_response, etag: new_etag }) => {
			let remote = api_response.data;
			check_protocol_version(app, id_tag, &remote).await;

			// Determine profile type
			let typ = match remote.r#type.as_str() {
				"community" => ProfileType::Community,
				_ => ProfileType::Person,
			};
			let badges = person_badges(app, tn_id, id_tag, typ, &remote).await;

			// Create the row WITHOUT profile_pic; the picture is fetched by a
			// retryable background task (uniform with `refresh_profile`). Store
			// the real etag if the peer provided one, otherwise leave it empty
			// (`Patch::Null`) — never a synthetic `sync-<ts>` placeholder. A badge
			// that failed to verify transiently also leaves it empty (see `badge_rows`).
			let fields = UpsertProfileFields {
				name: Patch::Value(remote.name.clone().into()),
				typ: Patch::Value(typ),
				synced: Patch::Value(true),
				following: Patch::Undefined,
				connected: Patch::Undefined,
				etag: badge_etag(badges.as_ref(), new_etag.as_deref()).unwrap_or(Patch::Null),
				..Default::default()
			};

			// Badges before the etag: a failed upsert stores no etag, so the next refresh retries.
			if let Some(b) = &badges {
				app.meta_adapter.replace_profile_badges(tn_id, id_tag, &b.rows).await?;
			}
			let upsert_result = app.meta_adapter.upsert_profile(tn_id, id_tag, &fields).await?;
			if fields.affects_search_index() {
				cloudillo_core::search_index_profile(app, tn_id, id_tag);
			}
			let created = matches!(upsert_result, UpsertResult::Created);
			if created {
				tracing::info!("Successfully synced profile {} from remote", id_tag);
			} else {
				tracing::debug!(
					"Profile {} already existed; merged sync result via upsert",
					id_tag
				);
			}

			// Fetch the picture inline first; on success advance `profile_pic`.
			// Transient failures fall back to the retryable background task.
			if let Some(ref file_id) = remote.profile_pic
				&& sync_or_enqueue_profile_pic(app, tn_id, id_tag, file_id).await?
			{
				let pic_fields = UpsertProfileFields {
					profile_pic: Patch::Value(Some(file_id.clone().into())),
					..Default::default()
				};
				app.meta_adapter.upsert_profile(tn_id, id_tag, &pic_fields).await?;
			}
			Ok(created)
		}
		Ok(ConditionalResult::NotModified) => {
			// We sent no `If-None-Match`, so a 304 is unexpected; treat as
			// "not created" and let the next scheduled refresh try again.
			tracing::warn!("Unexpected 304 on first sync of profile {}", id_tag);
			Ok(false)
		}
		Err(e) => {
			tracing::warn!("Failed to fetch profile {} from remote: {}", id_tag, e);
			Err(e)
		}
	}
}

/// Refresh one profile, and whether it was modified: a person tenant's membership (see
/// [`via_me_full`]) goes through [`crate::partners::sync_membership`] (profile + partner edges
/// from `/me/full`, no outbound fetch budget), so its stored etag is always a `/me/full` one;
/// anything else (incl. a community tenant's partners) through [`refresh_me`].
pub async fn refresh_profile(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	etag: Option<&str>,
) -> ClResult<bool> {
	let tenant_typ = app.meta_adapter.read_tenant(tn_id).await?.typ;
	let membership = app
		.meta_adapter
		.read_profile(tn_id, id_tag)
		.await
		.is_ok_and(|(_, p)| via_me_full(tenant_typ, &p));
	if !membership {
		return refresh_me(app, tn_id, id_tag, etag).await;
	}
	let own_id_tag = app.auth_adapter.read_id_tag(tn_id).await?;
	let old = app
		.meta_adapter
		.list_partner_edges(tn_id)
		.await?
		.into_iter()
		.filter(|e| e.community.as_ref() == id_tag)
		.map(|e| (e.community, e.partner))
		.collect();
	// Unattended paths fetch nothing: unknown partners resolve on the next map-open sync,
	// which an unresolved one brings forward.
	let mut fetches = crate::partners::Fetches::exhausted();
	let (modified, resolved) =
		crate::partners::sync_membership(app, tn_id, &own_id_tag, id_tag, etag, &old, &mut fetches)
			.await?;
	if !resolved {
		crate::partners::mark_partners_partial(app, tn_id).await?;
	}
	Ok(modified)
}

/// Whether a tenant of `tenant_typ` refreshes `p` via `/me/full`: a person tenant's membership.
fn via_me_full<S: AsRef<str>>(tenant_typ: ProfileType, p: &Profile<S>) -> bool {
	tenant_typ != ProfileType::Community && crate::partners::is_connected_community(p)
}

/// Refresh an existing profile with a conditional `GET /me` (`If-None-Match: etag`), stored by
/// [`apply_refresh`]: a 304 bumps `synced_at`, a 200 updates name, type, status, etag and the
/// picture. Returns whether the profile was modified. A failed fetch is `Ok(false)` (it counts
/// toward suspension); store errors propagate.
pub(crate) async fn refresh_me(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	etag: Option<&str>,
) -> ClResult<bool> {
	tracing::debug!("Refreshing profile {} (etag: {:?})", id_tag, etag);
	let result: ClResult<ConditionalResult<ApiResponse<ProfileBase>>> =
		app.request.get_conditional(id_tag, "/me", etag).await;
	apply_refresh(app, tn_id, id_tag, result.map(|r| r.map(|d| d.data))).await
}

/// Test seam for the access-matrix suite (`badge_sync`).
#[cfg(feature = "test-util")]
pub async fn apply_refresh_for_test(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	result: ClResult<ConditionalResult<ProfileBase>>,
) -> ClResult<bool> {
	apply_refresh(app, tn_id, id_tag, result).await
}

/// Store a fetched remote profile (see [`refresh_me`]). Only the base fields are
/// written; `Err` is a failed fetch (counts toward suspension, never bumps `synced_at`).
pub(crate) async fn apply_refresh(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	result: ClResult<ConditionalResult<ProfileBase>>,
) -> ClResult<bool> {
	// Snapshot prior status so both success branches can recover S → A.
	let prev_status = app
		.meta_adapter
		.read_profile(tn_id, id_tag)
		.await
		.ok()
		.and_then(|(_, p)| p.status);
	let reactivate = matches!(prev_status, Some(ProfileStatus::Suspended));
	let reactivate_status =
		if reactivate { Patch::Value(ProfileStatus::Active) } else { Patch::Undefined };

	match result {
		Ok(ConditionalResult::NotModified) => {
			// Profile hasn't changed, just update synced_at (and recover from S if applicable)
			tracing::debug!("Profile {} not modified (304), updating synced_at", id_tag);

			let fields = UpsertProfileFields {
				synced: Patch::Value(true),
				status: reactivate_status,
				..Default::default()
			};

			app.meta_adapter.upsert_profile(tn_id, id_tag, &fields).await?;
			if reactivate {
				// The status gates whether `/me` serves this issuer's badges.
				app.profile_me.invalidate(tn_id);
			}
			if fields.affects_search_index() {
				cloudillo_core::search_index_profile(app, tn_id, id_tag);
			}

			// Preserve "broken picture" recovery: an unchanged profile returns
			// 304, so the picture won't be re-examined here. If we hold a stored
			// picture ref but its local `vis.pf` variant never landed, heal it.
			// The stored `file_id` is unchanged, so only the variant blob needs
			// healing — no `profile_pic` write; we ignore the returned bool.
			if let Ok((_, p)) = app.meta_adapter.read_profile(tn_id, id_tag).await
				&& let Some(file_id) = p.profile_pic.as_deref()
				&& !local_profile_pic_present(app, tn_id, file_id).await
			{
				sync_or_enqueue_profile_pic(app, tn_id, id_tag, file_id).await?;
			}
			Ok(false)
		}
		Ok(ConditionalResult::Modified { data: remote, etag: new_etag }) => {
			check_protocol_version(app, id_tag, &remote).await;
			tracing::info!(
				"Profile {} modified, updating (name={}, profile_pic={:?}, etag={:?})",
				id_tag,
				remote.name,
				remote.profile_pic,
				new_etag
			);

			// Read current stored picture ref to detect a *changed* file_id.
			let current_profile_pic = app
				.meta_adapter
				.read_profile(tn_id, id_tag)
				.await
				.ok()
				.and_then(|(_, p)| p.profile_pic);

			// Determine remote profile type
			let typ = match remote.r#type.as_str() {
				"community" => ProfileType::Community,
				_ => ProfileType::Person,
			};

			// Metadata always advances — this bumps `synced_at`, keeping a
			// reachable `/api/me` permanently out of the abandonment window.
			// The etag is stored whenever the remote provided one, unconditional
			// of picture sync (which is now a separate background job).
			// Badges of a person only — `partners::sync_membership` refreshes communities
			// through here too. A transient verify failure clears the etag so the next
			// refresh refetches the body instead of a 304 hiding the badge.
			let badges = person_badges(app, tn_id, id_tag, typ, &remote).await;
			let mut fields = UpsertProfileFields {
				name: Patch::Value(remote.name.clone().into()),
				typ: Patch::Value(typ),
				synced: Patch::Value(true),
				status: reactivate_status,
				etag: badge_etag(badges.as_ref(), new_etag.as_deref()).unwrap_or_default(),
				..Default::default()
			};

			// Picture removed upstream → clear immediately (no blob needed).
			// Otherwise leave `profile_pic` untouched (`Patch::Undefined`) so the
			// previously rendered picture stays live until the task fetches the
			// new one and writes the ref on success.
			if remote.profile_pic.is_none() {
				fields.profile_pic = Patch::Null;
			}

			// Badges before the etag (see ensure_profile).
			if let Some(b) = &badges {
				app.meta_adapter.replace_profile_badges(tn_id, id_tag, &b.rows).await?;
			}
			app.meta_adapter.upsert_profile(tn_id, id_tag, &fields).await?;
			if reactivate {
				app.profile_me.invalidate(tn_id);
			}
			if fields.affects_search_index() {
				cloudillo_core::search_index_profile(app, tn_id, id_tag);
			}

			// Fetch the picture inline when the remote still has one and either
			// the file_id changed or the local `vis.pf` variant is missing; on
			// success advance `profile_pic`. Transient failures fall back to the
			// retryable background task.
			if let Some(ref file_id) = remote.profile_pic {
				let changed = current_profile_pic.as_deref() != Some(file_id.as_str());
				if (changed || !local_profile_pic_present(app, tn_id, file_id).await)
					&& sync_or_enqueue_profile_pic(app, tn_id, id_tag, file_id).await?
				{
					let pic_fields = UpsertProfileFields {
						profile_pic: Patch::Value(Some(file_id.clone().into())),
						..Default::default()
					};
					app.meta_adapter.upsert_profile(tn_id, id_tag, &pic_fields).await?;
				}
			}

			Ok(true)
		}
		Err(e) => {
			tracing::warn!("Failed to refresh profile {}: {}", id_tag, e);
			// CRITICAL: do NOT bump synced_at here. Once `synced_at` only
			// advances on success, every higher-level question — "is it
			// failing?", "for how long?", "should we stop trying?" — is
			// answered by `now - synced_at` against a single column.
			let now = Timestamp::now().0;
			let (last_success, current_status) = app
				.meta_adapter
				.read_profile(tn_id, id_tag)
				.await
				.map_or((None, None), |(_, p)| (p.synced_at.map(|t| t.0), p.status));

			let should_suspend = last_success.is_some_and(|s| {
				now.saturating_sub(s).max(0) >= DEACTIVATE_AFTER_DAYS * SECS_PER_DAY
			}) && matches!(current_status, None | Some(ProfileStatus::Active));

			if should_suspend {
				let fields = UpsertProfileFields {
					status: Patch::Value(ProfileStatus::Suspended),
					..Default::default()
				};
				match app.meta_adapter.upsert_profile(tn_id, id_tag, &fields).await {
					Ok(_) => app.profile_me.invalidate(tn_id),
					Err(e) => {
						warn!(id_tag = %id_tag, error = %e, "failed to mark profile Suspended");
					}
				}
			}
			Ok(false)
		}
	}
}

/// Result of [`badge_rows`].
struct BadgeSync {
	rows: Vec<ProfileBadgeRow>,
	/// A verification failed transiently: store no etag, so the next refresh refetches.
	transient: bool,
}

/// The etag to store after a sync that fetched `etag`: `Null` after a transient badge
/// failure, `None` (caller's default) when the peer sent none.
fn badge_etag(badges: Option<&BadgeSync>, etag: Option<&str>) -> Option<Patch<Box<str>>> {
	if badges.is_some_and(|b| b.transient) {
		return Some(Patch::Null);
	}
	etag.map(|e| Patch::Value(e.into()))
}

/// [`badge_rows`] of `remote` when it is a person (communities never hold badges), else `None`.
async fn person_badges(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	typ: ProfileType,
	remote: &ProfileBase,
) -> Option<BadgeSync> {
	if typ != ProfileType::Person {
		return None;
	}
	Some(badge_rows(app, tn_id, id_tag, remote.badges.as_deref().unwrap_or_default()).await)
}

/// The `profile_badges` rows for `id_tag`'s `/me` badge `tokens`, and whether a verification
/// failed transiently. Issuers are compared normalized.
///
/// The body is untrusted: at most [`MAX_SHOWN_BADGES`] tokens are read, and only the first
/// row per `(community, slot)` is kept. Each token is first only decoded, to read `iss`.
/// Only when `iss` is a community this tenant follows or is connected to is it verified
/// through [`cloudillo_core::ActionVerifyFn`] (which may fetch the issuer's key), then stored
/// with its fields or silently dropped. Any other issuer costs no fetch and leaves an
/// unverified index row (`verified: None`), if the decoded claims are a well-formed badge
/// ([`verified_badge_row`]). A failed issuer read, or a verify error other than
/// [`Error::is_invalid_token`] (e.g. the issuer's key could not be fetched), drops the token
/// and sets `transient`.
async fn badge_rows(app: &App, tn_id: TnId, id_tag: &str, tokens: &[String]) -> BadgeSync {
	let mut rows: Vec<ProfileBadgeRow> = Vec::new();
	let mut transient = false;
	for token in tokens.iter().take(MAX_SHOWN_BADGES) {
		let Ok(claims) = decode_jwt_no_verify::<ActionToken>(token) else {
			continue;
		};
		let iss = normalize_id_tag(&claims.iss);
		if !validate_id_tag(&iss) {
			continue;
		}
		let known = match read_badge_issuer(app.meta_adapter.as_ref(), tn_id, &iss).await {
			Ok(p) => p.is_some(),
			Err(e) => {
				tracing::debug!(%id_tag, issuer = %iss, "badge issuer read failed: {}", e);
				transient = true;
				continue;
			}
		};
		let row = if known {
			let verified = match app.ext::<cloudillo_core::ActionVerifyFn>() {
				Ok(verify) => verify(app, tn_id, token.as_str(), None).await,
				Err(e) => Err(e),
			};
			match verified {
				Ok(t) => match verified_badge_row(&t, id_tag) {
					Some(row) => row,
					None => continue,
				},
				Err(e) if e.is_invalid_token() => continue,
				Err(e) => {
					tracing::debug!(%id_tag, issuer = %claims.iss, "badge verify failed: {}", e);
					transient = true;
					continue;
				}
			}
		} else {
			// unverified, so a holder can still name any community; bounded by
			// MAX_SHOWN_BADGES refetches per holder per follow. Upgrade: verify the issuer key
			// before keeping an index row.
			if verified_badge_row(&claims, id_tag).is_none() {
				continue;
			}
			ProfileBadgeRow { community: iss.into(), verified: None }
		};
		let slot = row.verified.as_ref().map(|v| &v.slot);
		if !rows
			.iter()
			.any(|r| r.community == row.community && r.verified.as_ref().map(|v| &v.slot) == slot)
		{
			rows.push(row);
		}
	}
	BadgeSync { rows, transient }
}

/// The row a *verified* badge token yields: `None` unless [`badge_claims`] accepts it for
/// `id_tag` (`exp` is required there: `ActionVerifyFn` rejects an expired token but accepts
/// one without `exp`).
///
/// No downgrade check: see the module doc of cloudillo_action's native_hooks::bdg.
fn verified_badge_row(t: &ActionToken, id_tag: &str) -> Option<ProfileBadgeRow> {
	let (slot, level, exp) = badge_claims(t, &normalize_id_tag(id_tag), BADGE_EXP_SLACK_SECS)?;
	Some(ProfileBadgeRow {
		community: normalize_id_tag(&t.iss).into(),
		verified: Some(VerifiedBadge { slot: slot.into(), level: level.into(), exp }),
	})
}

/// Sync the 'pf' (profile) variant of a profile picture from a remote instance.
///
/// Uses the unified file sync helper to fetch the file descriptor,
/// verify hashes, and sync only the 'pf' variant.
///
/// Returns Ok(()) if vis.pf was successfully synced or already exists locally.
/// Returns Err if vis.pf variant doesn't exist in the remote descriptor or sync failed.
async fn sync_profile_pic_variant(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	file_id: &str,
) -> ClResult<()> {
	use cloudillo_file::sync::sync_file_variants;

	tracing::debug!(
		"Syncing profile picture variant '{}' for {} (file_id: {})",
		PROFILE_PIC_VARIANT,
		id_tag,
		file_id
	);

	// Sync only the profile-picture variant (public, no auth needed).
	// Profile pictures are inherently Public so the shared blob cache applies.
	let result = sync_file_variants(
		app,
		tn_id,
		id_tag,
		file_id,
		None,
		Some(&[PROFILE_PIC_VARIANT]),
		false,
		Some('P'),
		None,
		false,
		// The picture may land over content another peer's action brought in.
		true,
	)
	.await?;

	// Check if it was specifically synced or skipped (already exists).
	// Failure cases short-circuit via `?` above (sync_file_variants is atomic).
	let vis_pf_synced = result.synced_variants.iter().any(|v| v == PROFILE_PIC_VARIANT);
	let vis_pf_skipped = result.skipped_variants.iter().any(|v| v == PROFILE_PIC_VARIANT);

	// Never rewrite visibility on an already-existing row: `file_id` comes from the
	// peer's own profile document (`remote.profile_pic`), so loosening whatever local
	// row matches it would let a remote make a local file Public. New rows get 'P' from
	// `sync_file_variants` above; pre-existing restrictive rows are repaired only by
	// meta-adapter migration 37.

	if vis_pf_synced {
		tracing::info!(
			"Synced profile picture variant '{}' for {} (file_id: {})",
			PROFILE_PIC_VARIANT,
			id_tag,
			file_id
		);
		// sync_file_variants already created the row with
		// parent_id = MANAGED_PARENT_ID, making it eligible for the file GC
		// once a refresh swaps `profiles.profile_pic` to a different file_id.
		Ok(())
	} else if vis_pf_skipped {
		tracing::debug!(
			"Profile picture variant '{}' already exists for {} (file_id: {})",
			PROFILE_PIC_VARIANT,
			id_tag,
			file_id
		);
		Ok(())
	} else {
		// Wasn't in synced, skipped, or failed → not present in the descriptor.
		tracing::warn!(
			"No '{}' variant found in descriptor for profile picture {} (file_id: {})",
			PROFILE_PIC_VARIANT,
			id_tag,
			file_id
		);
		Err(Error::NotFound)
	}
}

/// Enqueue a retryable background sync of a profile's picture variant.
///
/// Deduped on `(tn_id, id_tag, file_id)` so repeated refreshes for the same
/// profile's picture collapse to a single task, while two distinct profiles that
/// happen to share a content-addressed `file_id` get separate tasks rather than
/// one clobbering the other's params; a refresh that observes a *new* file_id schedules
/// a distinct task that overwrites `profile_pic` on success. Bounded backoff
/// (30s → 30m, 6 attempts) handles transient failures without hammering a
/// remote, and `NotFound` stops immediately (see `ProfilePicSyncTask::run`).
async fn enqueue_profile_pic_sync(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	file_id: &str,
) -> ClResult<()> {
	let task = ProfilePicSyncTask::new(tn_id, id_tag.into(), file_id.into());
	app.scheduler
		.task(task)
		.key(format!("profile.pic_sync:{},{},{}", tn_id.0, id_tag, file_id))
		.with_retry(RetryPolicy::new((30, 1800), 6))
		.schedule()
		.await?;
	Ok(())
}

/// Sync a profile picture variant inline; on a transient failure, fall back to the
/// retryable `ProfilePicSyncTask`. Returns `true` when `vis.pf` is present locally
/// afterward (so the caller may advance `profile_pic`).
async fn sync_or_enqueue_profile_pic(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	file_id: &str,
) -> ClResult<bool> {
	match sync_profile_pic_variant(app, tn_id, id_tag, file_id).await {
		Ok(()) => Ok(true),
		Err(Error::NotFound) => {
			// Variant genuinely absent in the remote descriptor — permanent; don't retry.
			info!("Profile picture {} for {} not found; keeping previous picture", file_id, id_tag);
			Ok(false)
		}
		Err(e) => {
			// Transient (network/timeout/etc.) → hand off to the retryable task.
			debug!("Inline profile-pic sync for {} failed ({}); enqueuing retry task", id_tag, e);
			enqueue_profile_pic_sync(app, tn_id, id_tag, file_id).await?;
			Ok(false)
		}
	}
}

/// Background task that fetches a profile's `vis.pf` picture variant and, on
/// success, writes `profile_pic` to the freshly-synced `file_id`.
///
/// This is the retry fallback for transient inline-sync failures: callers try
/// `sync_or_enqueue_profile_pic` (which syncs inline first) and this task only
/// runs when the inline fetch fails transiently. Decoupled from metadata sync so
/// a picture-fetch hiccup never blocks profile freshness or keeps the row
/// eligible for abandonment. The previously rendered picture stays live until
/// this task succeeds — `profile_pic` is only ever advanced to a reference we
/// can actually render.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProfilePicSyncTask {
	tn_id: TnId,
	id_tag: Box<str>,
	file_id: Box<str>,
}

impl ProfilePicSyncTask {
	pub fn new(tn_id: TnId, id_tag: Box<str>, file_id: Box<str>) -> Arc<Self> {
		Arc::new(Self { tn_id, id_tag, file_id })
	}
}

#[async_trait]
impl Task<App> for ProfilePicSyncTask {
	fn kind() -> &'static str {
		"profile.pic_sync"
	}
	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		let task: ProfilePicSyncTask = serde_json::from_str(ctx)?;
		Ok(Arc::new(task))
	}

	fn serialize(&self) -> String {
		serde_json::to_string(self).unwrap_or_else(|e| {
			error!("Failed to serialize ProfilePicSyncTask: {}", e);
			"{}".to_string()
		})
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		match sync_profile_pic_variant(app, self.tn_id, &self.id_tag, &self.file_id).await {
			Ok(()) => {
				// Advance profile_pic only if the row still exists, so a future
				// profile-delete path can't be resurrected as a nameless stub by a
				// late-running task (upsert_profile is INSERT-on-conflict).
				if app.meta_adapter.read_profile(self.tn_id, &self.id_tag).await.is_ok() {
					let fields = UpsertProfileFields {
						profile_pic: Patch::Value(Some(self.file_id.clone())),
						..Default::default()
					};
					app.meta_adapter.upsert_profile(self.tn_id, &self.id_tag, &fields).await?;
					debug!(
						"Profile picture synced for {} (file_id: {})",
						self.id_tag, self.file_id
					);
				} else {
					debug!(
						"Profile {} gone; skipping profile_pic write for {}",
						self.id_tag, self.file_id
					);
				}
				Ok(())
			}
			Err(Error::NotFound) => {
				// Permanent: the descriptor/variant is genuinely absent or the
				// file 404s. Keep the previous picture and stop retrying — the
				// scheduler retries on any `Err`, so returning `Ok` abandons it.
				info!(
					"Profile picture {} for {} not found; keeping previous picture (no retry)",
					self.file_id, self.id_tag
				);
				Ok(())
			}
			Err(e) => {
				// Transient (network/timeout/etc.) → reschedule with backoff.
				Err(e)
			}
		}
	}

	async fn on_failed(&self, _app: &App, attempts: u16, last_error: &str) {
		// Bounded transient retries exhausted. Leave `profile_pic` untouched so
		// the previously rendered picture stays live.
		warn!(
			"Profile picture sync for {} (file_id: {}) abandoned after {} transient attempts: {}",
			self.id_tag, self.file_id, attempts, last_error
		);
	}
}

/// Batch task for refreshing stale profiles
///
/// This task queries profiles that haven't been synced in 24 hours
/// and refreshes them from their remote instances.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileRefreshBatchTask;

#[async_trait]
impl Task<App> for ProfileRefreshBatchTask {
	fn kind() -> &'static str {
		"profile.refresh_batch"
	}

	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: u64, _context: &str) -> ClResult<Arc<dyn Task<App>>> {
		Ok(Arc::new(ProfileRefreshBatchTask))
	}

	fn serialize(&self) -> String {
		"{}".to_string()
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		info!("Starting profile refresh batch task");

		// Query stale profiles
		let stale_profiles = app
			.meta_adapter
			.list_stale_profiles(
				STALE_PROFILE_THRESHOLD_SECS,
				DISABLE_REFRESH_AFTER_DAYS * SECS_PER_DAY,
				BATCH_SIZE,
			)
			.await?;

		let total = stale_profiles.len();
		if total == 0 {
			info!("No stale profiles to refresh");
			return Ok(());
		}

		info!("Found {} stale profiles to refresh", total);

		// Process profiles concurrently (up to 10 at a time)
		let results: Vec<_> = stream::iter(stale_profiles)
			.map(|(tn_id, id_tag, etag)| {
				let app = app.clone();
				async move {
					let result = refresh_profile(&app, tn_id, &id_tag, etag.as_deref()).await;
					(id_tag, result)
				}
			})
			.buffer_unordered(10)
			.collect()
			.await;

		// Count results
		let mut refreshed = 0;
		let mut not_modified = 0;
		let mut errors = 0;

		for (id_tag, result) in results {
			match result {
				Ok(true) => refreshed += 1,
				Ok(false) => not_modified += 1,
				Err(e) => {
					warn!("Error refreshing profile {}: {}", id_tag, e);
					errors += 1;
				}
			}
		}

		info!(
			"Profile refresh batch complete: {} refreshed, {} not modified, {} errors",
			refreshed, not_modified, errors
		);

		Ok(())
	}
}

/// Most holders one [`BadgeResyncTask`] run refetches.
const MAX_BADGE_RESYNC_HOLDERS: usize = 200;

/// Refetches (no `If-None-Match`) every profile holding a `profile_badges` row from
/// `community`, which this tenant just connected to or followed: until now its badges from
/// there were stored as unverified index rows only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BadgeResyncTask {
	pub tn_id: TnId,
	pub community: Box<str>,
}

/// Schedule a [`BadgeResyncTask`]; a no-op unless this tenant is a person. Whether
/// `community` is one is left to the task, which can sync a row the hook saw unsynced.
/// Fire-and-forget: logs on enqueue failure. The action hooks reach it through
/// `cloudillo_core::BadgeResyncFn`.
pub async fn schedule_badge_resync(app: &App, tn_id: TnId, community: &str) {
	let person = app
		.meta_adapter
		.read_tenant(tn_id)
		.await
		.is_ok_and(|t| t.typ == ProfileType::Person);
	if !person {
		return;
	}
	// No dedup key: a keyed duplicate would be dropped while one is pending, losing a re-trigger.
	// Refreshes are idempotent, so a duplicate run is harmless.
	let task = Arc::new(BadgeResyncTask { tn_id, community: community.into() });
	if let Err(e) = app.scheduler.task(task).now().await {
		warn!("Failed to enqueue badge resync of {} for tenant {}: {}", community, tn_id, e);
	}
}

#[async_trait]
impl Task<App> for BadgeResyncTask {
	fn kind() -> &'static str {
		"profile.badge_resync"
	}

	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		let task: BadgeResyncTask = serde_json::from_str(ctx)?;
		Ok(Arc::new(task))
	}

	fn serialize(&self) -> String {
		serde_json::to_string(self).unwrap_or_else(|e| {
			tracing::error!("Failed to serialize BadgeResyncTask: {}", e);
			"{}".to_string()
		})
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		async fn is_community(app: &App, tn_id: TnId, id_tag: &str) -> bool {
			app.meta_adapter
				.read_profile(tn_id, id_tag)
				.await
				.is_ok_and(|(_, p)| p.typ == ProfileType::Community)
		}
		// `ensure_profile` skips an existing row, so an unsynced one is refreshed instead.
		if !is_community(app, self.tn_id, &self.community).await {
			if let Err(e) = refresh_profile(app, self.tn_id, &self.community, None).await {
				warn!("Badge resync: sync of {} failed: {}", self.community, e);
			}
			if !is_community(app, self.tn_id, &self.community).await {
				return Ok(());
			}
		}
		let holders =
			app.meta_adapter.list_profile_badge_holders(self.tn_id, &self.community).await?;
		// holders past the cap keep unverified rows until their `/me` changes;
		// paginate across task runs if communities outgrow it.
		stream::iter(holders.into_iter().take(MAX_BADGE_RESYNC_HOLDERS))
			.for_each_concurrent(10, |id_tag| async move {
				if let Err(e) = refresh_profile(app, self.tn_id, &id_tag, None).await {
					warn!("Badge resync of {} for tenant {} failed: {}", id_tag, self.tn_id, e);
				}
			})
			.await;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use cloudillo_types::meta_adapter::ProfileConnectionStatus;

	#[test]
	fn verified_badge_row_requires_exp_aud_and_catalog() {
		let tok = |t: &str, b: &str, aud: Option<&str>, exp: Option<i64>| ActionToken {
			iss: "club.test".into(),
			t: t.into(),
			c: Some(serde_json::json!({ "b": b })),
			aud: aud.map(Into::into),
			exp: exp.map(Timestamp),
			..Default::default()
		};
		let ok = |t: &ActionToken| verified_badge_row(t, "bob.test");
		let row = ok(&tok("BDG:PAT", "gold", Some("bob.test"), Some(9))).expect("valid badge");
		let v = row.verified.expect("verified");
		assert_eq!(
			(&*row.community, &*v.slot, &*v.level, v.exp.0),
			("club.test", "PAT", "gold", 9)
		);
		assert!(ok(&tok("BDG:STD", "verified", Some("bob.test"), Some(9))).is_some());
		assert!(ok(&tok("BDG:PAT", "gold", Some("bob.test"), None)).is_none(), "no exp");
		assert!(ok(&tok("BDG:PAT", "gold", Some("eve.test"), Some(9))).is_none(), "foreign aud");
		assert!(ok(&tok("BDG:PAT", "gold", None, Some(9))).is_none(), "no aud");
		let holder_mixed = tok("BDG:STD", "verified", Some("bob.test"), Some(9));
		assert!(verified_badge_row(&holder_mixed, "Bob.Test").is_some(), "normalized aud");
		assert!(ok(&tok("BDG:STD", "gold", Some("bob.test"), Some(9))).is_none(), "wrong slot");
		assert!(ok(&tok("BDG:DEL", "gold", Some("bob.test"), Some(9))).is_none(), "bad subtype");
		assert!(ok(&tok("POST", "gold", Some("bob.test"), Some(9))).is_none(), "not a badge");
		let far = Some(i64::MAX / 2);
		assert!(ok(&tok("BDG:PAT", "gold", Some("bob.test"), far)).is_none(), "exp too far");
		let mixed = ActionToken {
			iss: "Club.Test".into(),
			..tok("BDG:STD", "verified", Some("bob.test"), Some(9))
		};
		assert_eq!(&*ok(&mixed).expect("valid badge").community, "club.test", "normalized iss");
	}

	#[test]
	fn badge_etag_clears_on_transient() {
		let sync = |transient| BadgeSync { rows: Vec::new(), transient };
		assert!(matches!(badge_etag(None, Some("e")), Some(Patch::Value(e)) if &*e == "e"));
		assert!(matches!(badge_etag(Some(&sync(false)), Some("e")), Some(Patch::Value(_))));
		assert!(matches!(badge_etag(Some(&sync(true)), Some("e")), Some(Patch::Null)));
		assert!(badge_etag(Some(&sync(false)), None).is_none());
	}

	#[test]
	fn via_me_full_only_for_memberships() {
		let comm = |status| Profile::<&str> {
			id_tag: "club.test",
			name: "Club",
			typ: ProfileType::Community,
			profile_pic: None,
			status,
			synced_at: None,
			following: true,
			follower: true,
			connected: ProfileConnectionStatus::Connected,
			roles: None,
			trust: None,
			feed_read_at: None,
			msg_read_at: None,
			hidden_in_home: None,
			hat_roles: None,
			peer_hat_roles: None,
			hats: None,
		};
		assert!(via_me_full(ProfileType::Person, &comm(None)));
		// A community tenant's connected communities are its partners.
		assert!(!via_me_full(ProfileType::Community, &comm(None)));
		let person = Profile { typ: ProfileType::Person, ..comm(None) };
		assert!(!via_me_full(ProfileType::Person, &person));
		assert!(!via_me_full(ProfileType::Person, &comm(Some(ProfileStatus::Suspended))));
	}
}

// vim: ts=4
