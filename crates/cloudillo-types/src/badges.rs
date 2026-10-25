// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Community badge catalog (`BDG:STD` / `BDG:PAT` actions).
//!
//! A community issues at most one badge per slot to a person; the slot is the action subtype and
//! the level rides in the content as `{ "b": "<level>" }`. The single source of the level lists:
//! the DSL schema enums, the inbound checks and profile sync all read them from here.

use crate::auth_adapter::ActionToken;
use crate::meta_adapter::{MetaAdapter, Profile, ProfileStatus, ProfileType};
use crate::prelude::*;

/// Standing slot (`BDG:STD`) levels, lowest first.
pub const BADGE_STD_LEVELS: &[&str] = &["verified", "trusted"];

/// Patron slot (`BDG:PAT`) levels, lowest first.
pub const BADGE_PAT_LEVELS: &[&str] = &["bronze", "silver", "gold", "diamond"];

/// Longest accepted badge lifetime: expiry is mandatory and at most this far ahead.
pub const BADGE_MAX_TTL_SECS: i64 = 366 * 24 * 3600;

/// Tolerance on the `exp` upper bound of a badge received from elsewhere, for clock skew
/// between issuer and receiver.
pub const BADGE_EXP_SLACK_SECS: i64 = 86_400;

/// The level list for a slot (`"STD"` / `"PAT"`), `None` for any other subtype.
pub fn badge_levels(slot: &str) -> Option<&'static [&'static str]> {
	match slot {
		"STD" => Some(BADGE_STD_LEVELS),
		"PAT" => Some(BADGE_PAT_LEVELS),
		_ => None,
	}
}

/// Whether `exp` is no further ahead than an issuer may set, plus `slack`.
pub fn badge_exp_within_max(exp: Timestamp, slack: i64) -> bool {
	exp <= Timestamp::now().add_seconds(BADGE_MAX_TTL_SECS + slack)
}

/// `(slot, level, exp)` of a badge token addressed to `aud`: `BDG:STD`/`BDG:PAT`, `c.b` in the
/// slot's catalog, `exp` present and within [`badge_exp_within_max`]. Does not check `exp > now`.
pub fn badge_claims<'a>(
	t: &'a ActionToken,
	aud: &str,
	slack: i64,
) -> Option<(&'a str, &'a str, Timestamp)> {
	let exp = t.exp.filter(|&e| badge_exp_within_max(e, slack))?;
	if t.aud.as_deref() != Some(aud) {
		return None;
	}
	let slot = t.t.strip_prefix("BDG:")?;
	let level = t.c.as_ref()?.get("b")?.as_str()?;
	badge_levels(slot)?.contains(&level).then_some((slot, level, exp))
}

/// Whether `p` (a local profile row) is a community trusted to issue badges here: followed or
/// connected, and not blocked/banned/suspended. The single issuer predicate of inbound BDG
/// actions and profile badge sync; the `list_badges_for` SQL mirrors it.
pub fn is_badge_issuer<S: AsRef<str>>(p: &Profile<S>) -> bool {
	p.typ == ProfileType::Community
		&& (p.following || p.connected.is_connected())
		&& ProfileStatus::in_good_standing(p.status)
}

/// `issuer`'s local profile iff it is a badge issuer here ([`is_badge_issuer`]); unknown is `None`.
pub async fn read_badge_issuer(
	meta: &dyn MetaAdapter,
	tn_id: TnId,
	issuer: &str,
) -> ClResult<Option<Profile<Box<str>>>> {
	match meta.read_profile(tn_id, issuer).await {
		Ok((_, p)) if is_badge_issuer(&p) => Ok(Some(p)),
		Ok(_) | Err(Error::NotFound) => Ok(None),
		Err(e) => Err(e),
	}
}

/// Whether an action type (`"BDG"`, `"BDG:STD"`, …) is a badge.
pub fn is_badge_type(typ: &str) -> bool {
	typ.split(':').next() == Some("BDG")
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn badge_claims_table() {
		fn ok(t: &ActionToken) -> Option<(&str, &str)> {
			badge_claims(t, "p.test", 0).map(|(s, l, _)| (s, l))
		}
		let tok = |t: &str, aud: Option<&str>, b: &str, exp: Option<i64>| ActionToken {
			t: t.into(),
			c: Some(serde_json::json!({ "b": b })),
			aud: aud.map(Into::into),
			exp: exp.map(|s| Timestamp::now().add_seconds(s)),
			..Default::default()
		};
		assert_eq!(
			ok(&tok("BDG:STD", Some("p.test"), "trusted", Some(60))),
			Some(("STD", "trusted"))
		);
		assert_eq!(ok(&tok("BDG:PAT", Some("p.test"), "gold", Some(60))), Some(("PAT", "gold")));
		assert_eq!(ok(&tok("BDG:PAT", Some("p.test"), "trusted", Some(60))), None, "level");
		assert_eq!(ok(&tok("BDG:XYZ", Some("p.test"), "gold", Some(60))), None, "slot");
		assert_eq!(ok(&tok("BDGX:STD", Some("p.test"), "trusted", Some(60))), None, "type");
		assert_eq!(ok(&tok("BDG:STD", Some("x.test"), "trusted", Some(60))), None, "aud");
		assert_eq!(ok(&tok("BDG:STD", None, "trusted", Some(60))), None, "no aud");
		assert_eq!(ok(&tok("BDG:STD", Some("p.test"), "trusted", None)), None, "no exp");
		let far = Some(BADGE_MAX_TTL_SECS + 3600);
		assert_eq!(ok(&tok("BDG:STD", Some("p.test"), "trusted", far)), None, "exp too far");
		assert!(
			badge_claims(&tok("BDG:STD", Some("p.test"), "trusted", far), "p.test", 86_400)
				.is_some()
		);
		assert!(!is_badge_type("BDGX"));
		assert!(is_badge_type("BDG:STD"));
		assert_eq!(badge_levels("XYZ"), None);
	}
}

// vim: ts=4
