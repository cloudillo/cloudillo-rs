// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! BDG (community badge) action: pre-store checks and native hooks.
//!
//! A community issues `BDG:STD` / `BDG:PAT` to a person who follows or is connected to it.
//! No revocation and no acceptance: a badge only expires (mandatory, at most
//! `BADGE_MAX_TTL_SECS` ahead). Both checks run pre-store because a hook runs after the row is
//! stored — and its key has already retired the older badge — so it cannot reject one.
//! - [`check_issue`]: `handler::post_action` on the issuing community
//! - [`check_inbound`]: `process.rs` step 5c on the receiving person
//! - on_receive: rests at 'N' (notification); `process.rs` drops the cached `/me` once that
//!   status is written
//!
//! No downgrade. A viewer accepts any validly signed badge until its `exp` (at most
//! `BADGE_MAX_TTL_SECS`); a newer tier replaces the old one only on the community's and the
//! holder's nodes, so a demoted holder can keep serving the old token until it expires.
//! Upgrade path: a community-published revocation / latest-tier check during viewer sync, or
//! shorter TTLs.

use cloudillo_types::action_types::CreateAction;
use cloudillo_types::auth_adapter::ActionToken;
use cloudillo_types::badges::{
	BADGE_EXP_SLACK_SECS, badge_claims, badge_exp_within_max, badge_levels, read_badge_issuer,
};
use cloudillo_types::meta_adapter::{ProfileStatus, ProfileType};

use crate::hooks::{HookContext, HookResult};
use crate::prelude::*;

/// Connected ('C', the BDG default) only: a wider one lists hidden badges to followers.
/// `None` is refused: inbound, the receiver would store its own default visibility instead.
fn check_visibility(v: Option<char>) -> ClResult<()> {
	match v {
		Some('C') => Ok(()),
		_ => Err(Error::ValidationError("badge visibility must be connected".into())),
	}
}

/// `exp` is mandatory, in the future and at most `BADGE_MAX_TTL_SECS` (+ `slack`) ahead.
fn check_expiry(exp: Option<Timestamp>, slack: i64) -> ClResult<()> {
	let now = Timestamp::now();
	match exp {
		Some(exp) if exp > now && badge_exp_within_max(exp, slack) => Ok(()),
		_ => Err(Error::ValidationError("badge expiry missing or out of range".into())),
	}
}

/// Outbound: the community tenant issues a badge to a person who follows or is connected to it.
/// The DSL schema enforces the level; the role gate (moderator) is `post_action`'s.
pub(crate) async fn check_issue(app: &App, tn_id: TnId, action: &CreateAction) -> ClResult<()> {
	if app.meta_adapter.read_tenant(tn_id).await?.typ != ProfileType::Community {
		return Err(Error::PermissionDenied);
	}
	if action.sub_typ.as_deref().and_then(badge_levels).is_none() {
		return Err(Error::ValidationError("unknown badge slot".into()));
	}
	let Some(audience) = action.audience_tag.as_deref() else {
		return Err(Error::ValidationError("badge needs an audience".into()));
	};
	let member = match app.meta_adapter.read_profile(tn_id, audience).await {
		Ok((_, p)) => p,
		Err(Error::NotFound) => return Err(Error::PermissionDenied),
		Err(e) => return Err(e),
	};
	// On the community node the member-follows-community flag is `follower`. No badge for a
	// blocked/banned/suspended member.
	if member.typ != ProfileType::Person
		|| !(member.follower || member.connected.is_connected())
		|| !ProfileStatus::in_good_standing(member.status)
	{
		return Err(Error::PermissionDenied);
	}
	// The DSL default ('C') fills in a missing visibility on issue.
	check_visibility(action.visibility.or(Some('C')))?;
	check_expiry(action.expires_at, 0)
}

/// Inbound, pre-store: a badge lands only on a person, addressed to it, from a community it
/// follows or is connected to. `allow_unknown` lets any issuer past `check_inbound_permissions`,
/// so this is the only issuer gate.
pub(crate) async fn check_inbound(app: &App, tn_id: TnId, action: &ActionToken) -> ClResult<()> {
	let tenant = app.meta_adapter.read_tenant(tn_id).await?;
	if tenant.typ == ProfileType::Community {
		warn!("BDG from {} refused: receiver {} is a community", action.iss, tenant.id_tag);
		return Err(Error::PermissionDenied);
	}
	let Some((_, _, exp)) = badge_claims(action, &tenant.id_tag, BADGE_EXP_SLACK_SECS) else {
		return Err(Error::ValidationError("badge slot, level, audience or expiry invalid".into()));
	};
	if exp <= Timestamp::now() {
		return Err(Error::ValidationError("badge expired".into()));
	}
	check_visibility(action.v)?;
	if read_badge_issuer(app.meta_adapter.as_ref(), tn_id, &action.iss)
		.await?
		.is_none()
	{
		warn!("BDG from {} refused: not a community {} follows", action.iss, tenant.id_tag);
		return Err(Error::PermissionDenied);
	}
	Ok(())
}

/// BDG on_receive: rest at 'N' so it shows as a notification (dismiss moves it to 'A').
/// The cached `/me` is dropped by `process.rs` after this status is written, not here: an
/// invalidation before the write would let a `/me` rebuild miss the new badge.
pub async fn on_receive(_app: App, _context: HookContext) -> ClResult<HookResult> {
	Ok(HookResult { status: Some('N'), ..Default::default() })
}

#[cfg(test)]
mod tests {
	use super::*;
	use cloudillo_types::badges::BADGE_MAX_TTL_SECS;

	#[test]
	fn check_expiry_bounds() {
		let now = Timestamp::now();
		assert!(check_expiry(None, 0).is_err(), "missing");
		assert!(check_expiry(Some(now.add_seconds(-10)), 0).is_err(), "past");
		assert!(check_expiry(Some(now.add_seconds(3600)), 0).is_ok(), "within");
		let beyond = now.add_seconds(BADGE_MAX_TTL_SECS + 3600);
		assert!(check_expiry(Some(beyond), 0).is_err(), "beyond max");
		assert!(check_expiry(Some(beyond), BADGE_EXP_SLACK_SECS).is_ok(), "within slack");
		let past_slack = now.add_seconds(BADGE_MAX_TTL_SECS + BADGE_EXP_SLACK_SECS + 3600);
		assert!(check_expiry(Some(past_slack), BADGE_EXP_SLACK_SECS).is_err(), "beyond slack");
	}

	#[test]
	fn check_visibility_connected_only() {
		assert!(check_visibility(Some('C')).is_ok());
		assert!(check_visibility(None).is_err(), "must be explicit; bdg_issue covers the default");
		assert!(check_visibility(Some('P')).is_err());
	}
}

// vim: ts=4
