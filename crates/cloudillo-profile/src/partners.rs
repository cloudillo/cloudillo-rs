// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Partner communities: the tenant's connected community peers, and the connection map
//! the home node assembles from its memberships' partner lists.

use async_trait::async_trait;
use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

use crate::list::PublicProfile;
use crate::prelude::*;
use cloudillo_core::abac;
use cloudillo_core::extract::{Auth, IdTag, OptionalAuth, OptionalRequestId};
use cloudillo_core::profile_visibility::RequesterTier;
use cloudillo_core::scheduler::{Task, TaskId};
use cloudillo_core::settings::SettingValue;
use cloudillo_types::meta_adapter::{
	ListProfileOptions, PartnerEdge, Profile, ProfileConnectionStatus, ProfileStatus, ProfileType,
	RemotePartner, RemotePartners,
};
use cloudillo_types::types::ApiResponse;
use cloudillo_types::validation::validate_id_tag;

/// A map older than this is re-synced when opened.
const STALE_SECS: i64 = 24 * 3600;

/// A partial sync is retried this long after it ran, instead of after [`STALE_SECS`].
const PARTIAL_RETRY_SECS: i64 = 3600;

/// Max partner entries taken from one remote list.
const MAX_REMOTE_PARTNERS: usize = 1000;

/// Max unknown partner profiles fetched per sync, across all memberships.
const MAX_PROFILE_FETCHES: usize = 100;

/// A manual sync request this soon after the last sync is not scheduled.
const SYNC_COOLDOWN_SECS: i64 = 300;

/// Connected community profiles of this tenant (Active/Muted only).
///
/// On a community tenant these are its partners; on a person tenant its memberships.
async fn connected_communities(app: &App, tn_id: TnId) -> ClResult<Vec<Profile<Box<str>>>> {
	let opts = ListProfileOptions {
		typ: Some(ProfileType::Community),
		connected: Some(ProfileConnectionStatus::Connected),
		status: Some(Box::from([ProfileStatus::Active, ProfileStatus::Muted])),
		// Single page (adapter max), add paging if a tenant ever has >1000 of these
		limit: Some(1000),
		..Default::default()
	};
	app.meta_adapter.list_profiles(tn_id, &opts).await
}

/// GET /api/partners — connected community profiles of this tenant.
///
/// These are the tenant's community connections, so `profile.connection_visibility.community`
/// (else the base key, default `connected`) decides who sees them. An anonymous refusal is an
/// empty list (200); an authenticated one is 403, so a syncing home node keeps its old edges
/// instead of reading the refusal as "no partners".
pub async fn list_partners(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	OptionalAuth(maybe_auth): OptionalAuth,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<PublicProfile>>>)> {
	let tier = RequesterTier::from_auth(&app, tn_id, &tenant_id_tag, maybe_auth.as_ref()).await?;
	let visible = tier.sees_connections(&app, tn_id, ProfileType::Community).await?;
	if !visible && tier.is_authenticated {
		return Err(Error::PermissionDenied);
	}

	let partners = if visible {
		connected_communities(&app, tn_id)
			.await?
			.into_iter()
			.map(PublicProfile::from)
			.collect()
	} else {
		Vec::new()
	};

	let response = ApiResponse::new(partners).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

// Sync task
//***********

/// A remote partner list reduced to valid, distinct id_tags other than `own` and
/// `community`, capped at [`MAX_REMOTE_PARTNERS`].
fn sanitize_remote_partners(data: Vec<RemotePartner>, own: &str, community: &str) -> Vec<Box<str>> {
	let mut seen = HashSet::new();
	data.into_iter()
		.map(|p| p.id_tag)
		.filter(|p| validate_id_tag(p) && p.as_ref() != own && p.as_ref() != community)
		.filter(|p| seen.insert(p.clone()))
		.take(MAX_REMOTE_PARTNERS)
		.collect()
}

/// The `partners` of `community` that are community profiles here, and whether every one was
/// resolved. An unknown one is fetched first while `fetches` stays under
/// [`MAX_PROFILE_FETCHES`]. One that stays unresolved (budget spent or fetch failed) sets the
/// flag `false`, so a later sync retries it; it is kept if `old` already has its edge (it was
/// a verified community then), else dropped.
async fn community_partners(
	app: &App,
	tn_id: TnId,
	community: &str,
	partners: Vec<Box<str>>,
	old: &HashSet<(Box<str>, Box<str>)>,
	fetches: &mut usize,
) -> (Vec<Box<str>>, bool) {
	let mut resolved = true;
	let mut out = Vec::new();
	for partner in partners {
		let mut known = app.meta_adapter.read_profile(tn_id, &partner).await;
		if matches!(known, Err(Error::NotFound)) && *fetches < MAX_PROFILE_FETCHES {
			*fetches += 1;
			known = cloudillo_core::fetch_profile(app, tn_id, &partner).await;
		}
		let keep = if let Ok((_, p)) = known {
			p.typ == ProfileType::Community
		} else {
			resolved = false;
			old.contains(&(community.into(), partner.clone()))
		};
		if keep {
			out.push(partner);
		}
	}
	(out, resolved)
}

/// Pulls every membership's partner list into `partner_edge`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartnerSyncTask {
	pub tn_id: TnId,
}

/// Schedule a partner sync for a tenant. Fire-and-forget: logs on enqueue failure.
pub async fn schedule_partner_sync(app: &App, tn_id: TnId) {
	let key = format!("partners-sync:{}", tn_id.0);
	let task = Arc::new(PartnerSyncTask { tn_id });
	if let Err(e) = app.scheduler.task(task).key(key).now().await {
		warn!("Failed to enqueue partner sync for tenant {}: {}", tn_id, e);
	}
}

#[async_trait]
impl Task<App> for PartnerSyncTask {
	fn kind() -> &'static str {
		"profile.partner_sync"
	}

	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		let task: PartnerSyncTask = serde_json::from_str(ctx)?;
		Ok(Arc::new(task))
	}

	fn serialize(&self) -> String {
		// `TnId(i64)` cannot fail to serialize; the fallback only satisfies the signature.
		serde_json::to_string(self).unwrap_or_else(|e| {
			error!("Failed to serialize PartnerSyncTask: {}", e);
			"{}".to_string()
		})
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		let tn_id = self.tn_id;
		debug!("→ PARTNER_SYNC: tenant={}", tn_id);
		let own_id_tag = app.auth_adapter.read_id_tag(tn_id).await?;
		let memberships: Vec<Box<str>> =
			connected_communities(app, tn_id).await?.into_iter().map(|p| p.id_tag).collect();
		let old: HashSet<(Box<str>, Box<str>)> = app
			.meta_adapter
			.list_partner_edges(tn_id)
			.await?
			.into_iter()
			.map(|e| (e.community, e.partner))
			.collect();

		// A partial sync backdates `synced_at`, so a map open retries after PARTIAL_RETRY_SECS.
		let mut complete = true;
		let mut fetches = 0;
		for community in &memberships {
			// A failed fetch keeps the community's previous edges.
			let response: RemotePartners =
				match app.request.get(tn_id, community, "/partners").await {
					Ok(r) => r,
					Err(e) => {
						warn!(%community, "partner sync: fetch failed, keeping old edges: {}", e);
						complete = false;
						continue;
					}
				};
			let partners = sanitize_remote_partners(response.data, &own_id_tag, community);
			let (partners, resolved) =
				community_partners(app, tn_id, community, partners, &old, &mut fetches).await;
			complete &= resolved;
			app.meta_adapter.replace_partner_edges(tn_id, community, &partners).await?;
		}

		app.meta_adapter.delete_partner_edges_except(tn_id, &memberships).await?;
		let now = Timestamp::now().0;
		let at = if complete { now } else { now - STALE_SECS + PARTIAL_RETRY_SECS };
		app.settings
			.set_system(tn_id, "partners.synced_at", SettingValue::Int(at))
			.await?;
		Ok(())
	}
}

// Home-node endpoints
//*********************

#[derive(Debug, Serialize)]
pub struct SyncScheduled {
	pub scheduled: bool,
}

/// POST /api/partners/sync — schedule a partner sync now.
pub async fn sync_partners(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<SyncScheduled>>)> {
	abac::require_tenant_self(&auth, &tenant_id_tag, "partners")?;
	// A partial sync backdates synced_at, so it bypasses the cooldown; the per-sync
	// fetch budget still bounds each run.
	let synced_at = app.settings.get_int(tn_id, "partners.synced_at").await?;
	let scheduled = Timestamp::now().0 - synced_at >= SYNC_COOLDOWN_SECS;
	if scheduled {
		schedule_partner_sync(&app, tn_id).await;
	}
	let response =
		ApiResponse::new(SyncScheduled { scheduled }).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::ACCEPTED, Json(response)))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PartnerMap {
	/// Ring 1: the owner's memberships.
	pub communities: Vec<PublicProfile>,
	/// Ring 2: partners of memberships that are not memberships themselves.
	pub partners: Vec<PublicProfile>,
	/// Every edge whose ends are both on the map (incl. membership↔membership chords).
	pub edges: Vec<PartnerEdge>,
	/// Last sync (unix seconds; a partial one is backdated to retry sooner), `None` if never.
	pub synced_at: Option<i64>,
	/// A sync was scheduled by this request because the map was stale.
	pub syncing: bool,
}

/// Ring 2 (`ring2` minus memberships) and every edge from a membership to a profile on the
/// map.
fn assemble_map(
	communities: &[PublicProfile],
	edges: Vec<PartnerEdge>,
	ring2: Vec<PublicProfile>,
) -> (Vec<PublicProfile>, Vec<PartnerEdge>) {
	let members: HashSet<&str> = communities.iter().map(|c| c.id_tag.as_str()).collect();
	let partners: Vec<PublicProfile> =
		ring2.into_iter().filter(|p| !members.contains(p.id_tag.as_str())).collect();
	let on_map: HashSet<&str> = members
		.iter()
		.copied()
		.chain(partners.iter().map(|p| p.id_tag.as_str()))
		.collect();
	let edges = edges
		.into_iter()
		.filter(|e| members.contains(e.community.as_ref()) && on_map.contains(e.partner.as_ref()))
		.collect();
	(partners, edges)
}

/// GET /api/partners/map — the owner's connection map, re-synced when stale.
pub async fn get_partner_map(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<PartnerMap>>)> {
	abac::require_tenant_self(&auth, &tenant_id_tag, "partners")?;

	let synced_at = app.settings.get_int(tn_id, "partners.synced_at").await?;
	let syncing = synced_at == 0 || Timestamp::now().0 - synced_at > STALE_SECS;
	if syncing {
		schedule_partner_sync(&app, tn_id).await;
	}

	let communities: Vec<PublicProfile> = connected_communities(&app, tn_id)
		.await?
		.into_iter()
		.map(PublicProfile::from)
		.collect();
	let member_tags: HashSet<&str> = communities.iter().map(|c| c.id_tag.as_str()).collect();
	let edges = app.meta_adapter.list_partner_edges(tn_id).await?;

	// Only edges of current memberships: the ones `assemble_map` keeps.
	let ring2_tags: Vec<&str> = edges
		.iter()
		.filter(|e| member_tags.contains(e.community.as_ref()))
		.map(|e| e.partner.as_ref())
		.filter(|p| !member_tags.contains(p))
		.collect::<HashSet<_>>()
		.into_iter()
		.collect();
	let hidden: HashSet<Box<str>> = if ring2_tags.is_empty() {
		HashSet::new()
	} else {
		// `read_profiles` carries no status, so Blocked/Banned come from their own listing.
		let opts = ListProfileOptions {
			typ: Some(ProfileType::Community),
			status: Some(Box::from([ProfileStatus::Blocked, ProfileStatus::Banned])),
			// Single page (adapter max), page it if >1000 blocked/banned communities
			limit: Some(1000),
			..Default::default()
		};
		app.meta_adapter
			.list_profiles(tn_id, &opts)
			.await?
			.into_iter()
			.map(|p| p.id_tag)
			.collect()
	};
	let ring2: Vec<PublicProfile> = app
		.meta_adapter
		.read_profiles(tn_id, &ring2_tags)
		.await?
		.into_iter()
		// The type check covers edges recorded before PTNR checked the partner's type.
		.filter(|p| p.typ == ProfileType::Community && !hidden.contains(&p.id_tag))
		.map(PublicProfile::from)
		.collect();
	let (partners, edges) = assemble_map(&communities, edges, ring2);

	let map = PartnerMap {
		communities,
		partners,
		edges,
		synced_at: (synced_at > 0).then_some(synced_at),
		syncing,
	};
	let response = ApiResponse::new(map).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn prof(id_tag: &str) -> PublicProfile {
		PublicProfile {
			id_tag: id_tag.into(),
			name: id_tag.into(),
			r#type: "community".into(),
			profile_pic: None,
		}
	}

	fn edge(community: &str, partner: &str) -> PartnerEdge {
		PartnerEdge { community: community.into(), partner: partner.into() }
	}

	fn tags(p: &[PublicProfile]) -> Vec<&str> {
		p.iter().map(|p| p.id_tag.as_str()).collect()
	}

	#[test]
	fn assemble_map_filters_and_prunes() {
		let communities = [prof("a.test"), prof("b.test")];
		let edges = vec![
			edge("a.test", "b.test"),
			edge("a.test", "x.test"),
			edge("b.test", "blocked.test"),
			edge("b.test", "unknown.test"),
		];
		// `blocked.test` was filtered out before assembly.
		let ring2 = vec![prof("x.test"), prof("a.test")];

		let (partners, edges) = assemble_map(&communities, edges, ring2);
		// Members never land in ring 2.
		assert_eq!(tags(&partners), ["x.test"]);
		let edges: Vec<_> =
			edges.iter().map(|e| (e.community.as_ref(), e.partner.as_ref())).collect();
		// The member chord stays; edges to dropped or unread nodes are pruned.
		assert_eq!(edges, [("a.test", "b.test"), ("a.test", "x.test")]);
	}

	#[test]
	fn sanitize_remote_partners_filters() {
		let remote = |t: &str| RemotePartner { id_tag: t.into() };
		let data = vec![
			remote("x.test"),
			remote("Bad_Tag"),
			remote("own.test"),
			remote("club.test"),
			remote("x.test"),
			remote("y.test"),
		];
		let got = sanitize_remote_partners(data, "own.test", "club.test");
		assert_eq!(got, [Box::from("x.test"), Box::from("y.test")]);

		let many = (0..MAX_REMOTE_PARTNERS + 5).map(|i| remote(&format!("p{i}.test"))).collect();
		assert_eq!(
			sanitize_remote_partners(many, "own.test", "club.test").len(),
			MAX_REMOTE_PARTNERS
		);
	}
}

// vim: ts=4
