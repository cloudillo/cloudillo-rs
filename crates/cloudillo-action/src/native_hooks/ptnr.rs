// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! PTNR (Partnership) action native hooks
//!
//! - `announce_partnership`: called by the CONN hooks when a community↔community connection
//!   becomes Connected; schedules [`PtnrAnnounceTask`], which broadcasts `PTNR` with
//!   `subject = @peer` to our followers once the peer's public partner list shows us.
//! - `connection_ended`: called by the CONN:DEL hooks; a community emits `PTNR:DEL`
//!   (superseding the announcement under the same key), a person drops the ex-membership's
//!   partner edges.
//! - on_receive: a PTNR from one of our memberships naming a known community records the edge
//!   in `partner_edge`; a `PTNR:DEL` from one drops it.
//!
//! A later `profile.connection_visibility.community` change away from public does not
//! retract announced partnerships; the settings system has no on-change hook. Add it when one
//! exists.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::hooks::{HookContext, HookResult};
use crate::prelude::*;
use crate::subject_ref::{SubjectRef, parse_subject_ref};
use crate::task::{CreateAction, create_action};
use cloudillo_core::profile_visibility::{
	SectionVisibility, connection_visibility, public_partner_list,
};
use cloudillo_core::scheduler::{RetryPolicy, Task, TaskId};
use cloudillo_types::meta_adapter::ProfileType;
use cloudillo_types::validation::validate_id_tag;

/// Whether `peer`'s anonymous `GET /api/partners` lists `us`; any failure reads as no.
async fn peer_lists_us(app: &App, peer: &str, us: &str) -> bool {
	public_partner_list(app, peer)
		.await
		.is_some_and(|l| l.iter().any(|p| p.as_ref() == us))
}

/// Announce that we (`context.tenant_tag`) are now partners with `context.issuer`.
///
/// Only when both sides are communities and our community connections are public
/// (`profile.connection_visibility.community`, else the base key). The rest waits in
/// [`PtnrAnnounceTask`]: community peers do not follow each other, so neither side sees the
/// other's PTNR, and the accepting side runs before the requester has recorded CONN:ACC.
pub async fn announce_partnership(app: &App, context: &HookContext) {
	if context.tenant_type != "community" {
		return;
	}
	let tn_id = context.tn_id;
	let peer = &context.issuer;
	if !may_announce(app, tn_id, peer, false).await {
		return;
	}
	let task = Arc::new(PtnrAnnounceTask { tn_id, peer: peer.as_str().into() });
	if let Err(e) = app
		.scheduler
		.task(task)
		.key(announce_task_key(tn_id, peer))
		.with_retry(RetryPolicy::new((60, 3600), 5))
		.after(30)
		.await
	{
		warn!(peer = %peer, "PTNR: failed to schedule partnership announcement: {e}");
	}
}

/// Whether a partnership with `peer` may be announced: it is a community (and, with
/// `connected`, still a connection) and our community connections are public.
async fn may_announce(app: &App, tn_id: TnId, peer: &str, connected: bool) -> bool {
	// The peer's `typ` comes from its own signed `/me`; the real gate is the
	// `connected` status we negotiated. Verify the type in the CONN token, or fetch `/me`
	// once on connect, if a self-declared community type ever matters.
	let peer_ok = app.meta_adapter.read_profile(tn_id, peer).await.is_ok_and(|(_, p)| {
		p.typ == ProfileType::Community && (!connected || p.connected.is_connected())
	});
	peer_ok
		&& matches!(
			connection_visibility(app, tn_id, ProfileType::Community).await,
			Ok(Some(SectionVisibility::Public))
		)
}

/// The live (not retracted) `PTNR:{us}:@{peer}` row, pending ones included: the key is
/// stored at creation and `get_action_by_key` skips only deleted rows.
async fn live_announcement(app: &App, tn_id: TnId, key: &str) -> ClResult<bool> {
	Ok(app
		.meta_adapter
		.get_action_by_key(tn_id, key)
		.await?
		.is_some_and(|a| a.sub_typ.as_deref() != Some("DEL")))
}

/// A connection with `peer` ended (CONN:DEL either way). A community retracts its partnership;
/// a person drops the partner edges of what was its membership.
pub async fn connection_ended(app: &App, tn_id: TnId, tenant_type: &str, peer: &str) {
	if tenant_type == "community" {
		retract_partnership(app, tn_id, peer).await;
	} else if let Err(e) = app.meta_adapter.delete_partner_edges_of(tn_id, peer).await {
		warn!(%peer, "PTNR: failed to drop ex-membership partner edges: {e}");
	}
}

/// Emits `PTNR:DEL`, superseding our announcement of `peer`, if one is live. Errors are
/// logged, never returned.
async fn retract_partnership(app: &App, tn_id: TnId, peer: &str) {
	let res: ClResult<()> = async {
		let us = app.auth_adapter.read_id_tag(tn_id).await?;
		if !live_announcement(app, tn_id, &format!("PTNR:{us}:@{peer}")).await? {
			return Ok(());
		}
		let del = CreateAction {
			typ: "PTNR".into(),
			sub_typ: Some("DEL".into()),
			subject: Some(format!("@{peer}").into()),
			..Default::default()
		};
		create_action(app, tn_id, &us, del).await?;
		Ok(())
	}
	.await;
	if let Err(e) = res {
		warn!(%peer, "PTNR: failed to retract partnership: {e}");
	}
}

/// Scheduler key of the pending announcement of `peer` on `tn_id`.
pub fn announce_task_key(tn_id: TnId, peer: &str) -> String {
	format!("ptnr-announce:{}:{peer}", tn_id.0)
}

/// Emits `PTNR:{us}:@{peer}` once the peer's public partner list shows us (it has not opted
/// out); fails, and so retries, until it does. Emitted at most once per pair: a live row
/// suppresses it (a retracted or deleted one does not, so a reconnect re-announces). Ends
/// quietly if the peer disconnected or our visibility changed meanwhile. The scheduler key
/// keeps one task per pair.
#[derive(Debug, Serialize, Deserialize)]
pub struct PtnrAnnounceTask {
	tn_id: TnId,
	peer: Box<str>,
}

#[async_trait]
impl Task<App> for PtnrAnnounceTask {
	fn kind() -> &'static str {
		"action.ptnr_announce"
	}

	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		let task: PtnrAnnounceTask = serde_json::from_str(ctx)?;
		Ok(Arc::new(task))
	}

	fn serialize(&self) -> String {
		serde_json::to_string(self).unwrap_or_else(|e| {
			error!("Failed to serialize PtnrAnnounceTask: {}", e);
			"{}".to_string()
		})
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		let (tn_id, peer) = (self.tn_id, self.peer.as_ref());
		let us = app.auth_adapter.read_id_tag(tn_id).await?;
		let key = format!("PTNR:{us}:@{peer}");
		if !may_announce(app, tn_id, peer, true).await
			|| live_announcement(app, tn_id, &key).await?
		{
			return Ok(());
		}
		if !peer_lists_us(app, peer, &us).await {
			return Err(Error::ServiceUnavailable(format!("{peer} does not list us yet")));
		}
		let ptnr = CreateAction {
			typ: "PTNR".into(),
			subject: Some(format!("@{peer}").into()),
			..Default::default()
		};
		create_action(app, tn_id, &us, ptnr).await?;
		// CONN:DEL clears `connected` before `connection_ended`, so a disconnect that ran between
		// the gate and the emit saw no live row to retract; it shows here.
		if !may_announce(app, tn_id, peer, true).await {
			retract_partnership(app, tn_id, peer).await;
		}
		Ok(())
	}
}

/// PTNR on_receive, on a person tenant: if the issuer is one of our memberships and the partner
/// is a community, record the edge. A `PTNR:DEL` from a membership drops it. A community tenant
/// ignores PTNR: partner edges only feed a person's partner map.
///
/// The issuer is a connected membership, so its signed PTNR is trusted as is: neither this nor
/// the partner sync checks reciprocity. The announcing side already waits for the peer to list
/// it ([`PtnrAnnounceTask`]).
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	if context.tenant_type == "community" {
		return Ok(HookResult::default());
	}
	let tn_id = context.tn_id;
	let Some(SubjectRef::Identity(partner)) =
		context.subject.as_deref().and_then(parse_subject_ref)
	else {
		return Ok(HookResult::default());
	};
	if partner == context.issuer || partner == context.tenant_tag || !validate_id_tag(partner) {
		return Ok(HookResult::default());
	}
	let is_membership = app
		.meta_adapter
		.read_profile(tn_id, &context.issuer)
		.await
		.is_ok_and(|(_, p)| p.typ == ProfileType::Community && p.connected.is_connected());
	if !is_membership {
		return Ok(HookResult::default());
	}
	if context.subtype.as_deref() == Some("DEL") {
		if let Err(e) = app.meta_adapter.delete_partner_edge(tn_id, &context.issuer, partner).await
		{
			warn!(issuer = %context.issuer, "PTNR: failed to drop partner edge: {e}");
		}
		return Ok(HookResult::default());
	}
	let mut known = app.meta_adapter.read_profile(tn_id, partner).await;
	if matches!(known, Err(Error::NotFound)) {
		known = cloudillo_core::fetch_profile(&app, tn_id, partner).await;
	}
	let partner_is_community = known.is_ok_and(|(_, p)| p.typ == ProfileType::Community);
	if !partner_is_community {
		debug!(issuer = %context.issuer, %partner, "PTNR: partner is not a known community");
		return Ok(HookResult::default());
	}
	if let Err(e) = app.meta_adapter.upsert_partner_edge(tn_id, &context.issuer, partner).await {
		warn!(issuer = %context.issuer, "PTNR: failed to record partner edge: {e}");
	}
	Ok(HookResult::default())
}
