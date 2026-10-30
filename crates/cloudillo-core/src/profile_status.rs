// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Lifting the automatic `Suspended` profile status on verified contact.

use cloudillo_types::meta_adapter::{ProfileStatus, UpsertProfileFields};

use crate::prelude::*;

/// Only an inbound action whose `iat` is this recent counts as proof of life.
pub const FRESH_CONTACT_SECS: i64 = 3600;

/// The single S → A rule: `Suspended` lifts to `Active`, every other status is left alone.
pub fn lifted(status: Option<ProfileStatus>) -> Patch<ProfileStatus> {
	if status == Some(ProfileStatus::Suspended) {
		Patch::Value(ProfileStatus::Active)
	} else {
		Patch::Undefined
	}
}

/// Lift `Suspended → Active` for `id_tag`; a failure is logged, never returned.
///
/// Suspended is the automatic "unreachable" state set by `cloudillo_profile::sync::apply_refresh`;
/// the PATCH endpoints refuse `S`, so only sync sets it. A verified action or token exchange
/// shows the peer is back. `synced` bumps `synced_at` so the refresh batch doesn't re-suspend it
/// at once. `apply_refresh` applies [`lifted`] inside its own synced/etag upsert.
pub async fn reactivate_suspended(app: &App, tn_id: TnId, id_tag: &str) {
	if let Err(e) = reactivate(app, tn_id, id_tag).await {
		warn!(id_tag = %id_tag, error = %e, "failed to reactivate suspended profile");
	}
}

async fn reactivate(app: &App, tn_id: TnId, id_tag: &str) -> ClResult<()> {
	// Read-then-upsert isn't atomic: a concurrent refresh-failure suspend can win; the next
	// verified contact lifts it again.
	let p = match app.meta_adapter.read_profile(tn_id, id_tag).await {
		Ok((_, p)) => p,
		Err(Error::NotFound) => return Ok(()),
		Err(e) => return Err(e),
	};
	let status = lifted(p.status);
	if status.is_undefined() {
		return Ok(());
	}
	let fields = UpsertProfileFields { status, synced: Patch::Value(true), ..Default::default() };
	app.meta_adapter.upsert_profile(tn_id, id_tag, &fields).await?;
	// The status gates whether `/me` serves this peer's badges.
	app.profile_me.invalidate(tn_id);
	info!(id_tag = %id_tag, "Suspended profile reactivated");
	Ok(())
}
