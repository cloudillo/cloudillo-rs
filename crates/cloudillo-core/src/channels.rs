// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Channel enterability — the per-request predicate every channel-aware read, write and
//! fanout path consumes.

use crate::prelude::*;
use crate::roles::{highest_role_level, role_level};
use cloudillo_types::meta_adapter::Channel;

/// Whether a reader may enter a channel.
///
/// The floor is `min_role` (`None` = `public`); an unparsable stored floor fails closed.
/// A closed room also needs a roster row, and a hatted reader never counts as rostered:
/// the hat replaces the reader's standing, it never adds to it.
pub fn can_enter(
	min_role: Option<&str>,
	closed: bool,
	reader_roles: &[Box<str>],
	rostered: bool,
	hatted: bool,
) -> bool {
	let Some(floor) = role_level(min_role.unwrap_or("public")) else {
		return false;
	};
	highest_role_level(reader_roles) >= floor && (!closed || (rostered && !hatted))
}

/// Absolute channel form `@<tenant>~<name>`, as stored on entity `channel` columns.
pub fn absolute_channel(tenant_id_tag: &str, name: &str) -> Box<str> {
	format!("@{tenant_id_tag}~{name}").into()
}

/// Bare names of the closed rooms `reader` is rostered in; empty when no room is closed or
/// the reader is hatted (a hat never counts as rostered).
pub async fn reader_roster(
	app: &App,
	tn_id: TnId,
	reader: &str,
	channels: &[Channel],
	hatted: bool,
) -> ClResult<Vec<Box<str>>> {
	if !hatted && channels.iter().any(|c| c.closed) {
		app.meta_adapter.list_member_channels(tn_id, reader).await
	} else {
		Ok(Vec::new())
	}
}

/// Absolute forms of the tenant's channels the reader may enter, or `None` for no filter
/// at all (the reader is the tenant itself).
// ponytail: IN-list per request, uncached; cache per (tn_id, reader, roles-hash) if it shows in a profile.
pub async fn enterable_channels(
	app: &App,
	tn_id: TnId,
	tenant_id_tag: &str,
	reader: &str,
	reader_roles: &[Box<str>],
	hatted: bool,
) -> ClResult<Option<Vec<Box<str>>>> {
	if reader == tenant_id_tag {
		return Ok(None);
	}
	let channels = app.meta_adapter.list_channels(tn_id).await?;
	let roster = reader_roster(app, tn_id, reader, &channels, hatted).await?;
	Ok(Some(
		channels
			.iter()
			.filter(|c| {
				let rostered = roster.contains(&c.name);
				can_enter(c.min_role.as_deref(), c.closed, reader_roles, rostered, hatted)
			})
			.map(|c| absolute_channel(tenant_id_tag, &c.name))
			.collect(),
	))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn roles(r: &[&str]) -> Vec<Box<str>> {
		r.iter().map(|&s| s.into()).collect()
	}

	#[test]
	fn floor_admits_below_denies_above() {
		let contrib = roles(&["contributor"]);
		assert!(can_enter(Some("supporter"), false, &contrib, false, false));
		assert!(can_enter(None, false, &[], false, false));
		assert!(!can_enter(Some("moderator"), false, &contrib, false, false));
	}

	#[test]
	fn closed_room_needs_roster() {
		let contrib = roles(&["contributor"]);
		assert!(can_enter(Some("follower"), true, &contrib, true, false));
		assert!(!can_enter(Some("follower"), true, &contrib, false, false));
	}

	#[test]
	fn closed_room_rostered_but_hatted_denies() {
		let contrib = roles(&["contributor"]);
		assert!(!can_enter(Some("follower"), true, &contrib, true, true));
	}

	#[test]
	fn roster_below_floor_denies() {
		let follower = roles(&["follower"]);
		assert!(!can_enter(Some("contributor"), true, &follower, true, false));
	}

	#[test]
	fn unknown_min_role_denies() {
		let leader = roles(&["leader"]);
		assert!(!can_enter(Some("overlord"), false, &leader, false, false));
	}

	#[test]
	fn absolute_form() {
		assert_eq!(&*absolute_channel("team.example", "club"), "@team.example~club");
	}
}
