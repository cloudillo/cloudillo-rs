// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

use std::collections::{HashMap, HashSet};

use axum::{Json, extract::State, http::StatusCode};

use crate::prelude::*;
use cloudillo_core::IdTag;
use cloudillo_core::extract::{OptionalAuth, OptionalRequestId};
use cloudillo_core::profile_visibility::{CommunityRole, RequesterTier, SectionVisibility};
use cloudillo_types::types::{ApiResponse, Profile};

/// Suffix appended to a section field name to mark its required visibility.
const VIS_SUFFIX: &str = ".vis";

/// Filter the tenant `x` map according to the caller's tier.
///
/// Sections are gated by `<field>.vis` markers. Sections without a marker are
/// treated as public (matches today's behaviour). Unknown marker values
/// (`SectionVisibility::parse` returns `None`) are treated as hidden — fail
/// closed.
///
/// When a section is hidden we strip:
/// - the `<field>` entry itself (if present),
/// - the `<field>.vis` marker (so anonymous callers see no hint),
/// - the `<field>` entry from the comma-separated `sections` list (dropped
///   entirely if the list becomes empty).
fn filter_sections(x: HashMap<Box<str>, Box<str>>, tier: RequesterTier) -> HashMap<String, String> {
	let mut hidden: HashSet<String> = HashSet::new();
	for (k, v) in &x {
		let Some(field) = k.strip_suffix(VIS_SUFFIX) else {
			continue;
		};
		// `RequesterTier::can_view` is the single source of truth for owner
		// short-circuits and tier comparisons; don't duplicate the logic here.
		let visible = match SectionVisibility::parse(v) {
			Some(req) => tier.can_view(req),
			None => tier.is_owner,
		};
		if !visible {
			hidden.insert(field.to_string());
		}
	}

	let mut out: HashMap<String, String> = HashMap::with_capacity(x.len());
	for (k, v) in x {
		let key = k.to_string();
		// Filter the comma-separated `sections` list before the hidden-key
		// check, so that even if a meta-marker accidentally inserted the
		// literal "sections" into `hidden`, we still produce a correctly
		// filtered list rather than dropping the entry entirely.
		if key == "sections" {
			let kept: Vec<&str> = v
				.split(',')
				.map(str::trim)
				.filter(|s| !s.is_empty() && !hidden.contains(*s))
				.collect();
			if kept.is_empty() {
				continue;
			}
			out.insert(key, kept.join(","));
			continue;
		}
		if hidden.contains(&key) {
			continue;
		}
		if let Some(field) = key.strip_suffix(VIS_SUFFIX)
			&& hidden.contains(field)
		{
			continue;
		}
		out.insert(key, v.to_string());
	}
	out
}

pub async fn get_tenant_profile(
	State(app): State<App>,
	IdTag(id_tag): IdTag,
	OptionalAuth(auth): OptionalAuth,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Profile>>)> {
	let auth_profile = app.auth_adapter.read_tenant(&id_tag).await?;
	let tn_id = app.auth_adapter.read_tn_id(&id_tag).await?;
	let tenant_meta = app.meta_adapter.read_tenant(tn_id).await?;

	let typ = match tenant_meta.typ {
		cloudillo_types::meta_adapter::ProfileType::Person => "person",
		cloudillo_types::meta_adapter::ProfileType::Community => "community",
	};

	let is_owner = auth.as_ref().is_some_and(|a| a.id_tag.as_ref() == &*id_tag);
	let is_authenticated = auth.is_some();
	let max_role = auth
		.as_ref()
		.and_then(|a| a.roles.iter().filter_map(|r| CommunityRole::parse(r)).max());

	let (follows_tenant, connected_to_tenant) = if is_owner || !is_authenticated {
		(false, false)
	} else if let Some(a) = auth.as_ref() {
		let caller = a.id_tag.as_ref();
		let map = app.meta_adapter.get_relationships(tn_id, &[caller]).await?;
		let (f, c) = map.get(caller).copied().unwrap_or((false, false));
		(f, c)
	} else {
		(false, false)
	};

	let tier =
		RequesterTier { is_owner, is_authenticated, follows_tenant, connected_to_tenant, max_role };

	let x_map = filter_sections(tenant_meta.x, tier);

	let profile = Profile {
		id_tag: auth_profile.id_tag.to_string(),
		name: tenant_meta.name.to_string(),
		r#type: typ.to_string(),
		profile_pic: tenant_meta.profile_pic.map(|s| s.to_string()),
		cover_pic: tenant_meta.cover_pic.map(|s| s.to_string()),
		keys: auth_profile.keys,
		x: if x_map.is_empty() { None } else { Some(x_map) },
	};

	let mut response = ApiResponse::new(profile);
	if let Some(id) = req_id {
		response = response.with_req_id(id);
	}

	Ok((StatusCode::OK, Json(response)))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn input() -> HashMap<Box<str>, Box<str>> {
		let mut x: HashMap<Box<str>, Box<str>> = HashMap::new();
		x.insert("links.vis".into(), "contributor".into());
		x.insert("sections".into(), "about,links".into());
		x.insert("links".into(), "{\"github\":\"x\"}".into());
		x.insert("about".into(), "hi".into());
		x
	}

	fn anon() -> RequesterTier {
		RequesterTier::anonymous()
	}

	fn auth_no_role() -> RequesterTier {
		RequesterTier { is_authenticated: true, ..RequesterTier::anonymous() }
	}

	fn auth_role(r: CommunityRole) -> RequesterTier {
		RequesterTier { is_authenticated: true, max_role: Some(r), ..RequesterTier::anonymous() }
	}

	fn owner() -> RequesterTier {
		RequesterTier { is_owner: true, ..RequesterTier::anonymous() }
	}

	#[test]
	fn anonymous_loses_gated_section_and_hint() {
		let out = filter_sections(input(), anon());
		assert_eq!(out.get("about").map(String::as_str), Some("hi"));
		assert_eq!(out.get("sections").map(String::as_str), Some("about"));
		assert!(!out.contains_key("links"));
		assert!(!out.contains_key("links.vis"));
	}

	#[test]
	fn authenticated_no_role_blocked() {
		let out = filter_sections(input(), auth_no_role());
		assert!(!out.contains_key("links"));
		assert!(!out.contains_key("links.vis"));
		assert_eq!(out.get("sections").map(String::as_str), Some("about"));
	}

	#[test]
	fn contributor_sees_all_entries_unchanged() {
		let out = filter_sections(input(), auth_role(CommunityRole::Contributor));
		assert!(out.contains_key("links"));
		assert_eq!(out.get("links.vis").map(String::as_str), Some("contributor"));
		assert!(out.contains_key("about"));
		let sections = out.get("sections").map_or("", String::as_str);
		let mut parts: Vec<&str> = sections.split(',').collect();
		parts.sort_unstable();
		assert_eq!(parts, vec!["about", "links"]);
	}

	#[test]
	fn supporter_below_contributor_is_blocked() {
		let out = filter_sections(input(), auth_role(CommunityRole::Supporter));
		assert!(!out.contains_key("links"));
		assert!(!out.contains_key("links.vis"));
		assert_eq!(out.get("sections").map(String::as_str), Some("about"));
	}

	#[test]
	fn owner_sees_everything() {
		let out = filter_sections(input(), owner());
		assert!(out.contains_key("links"));
		assert!(out.contains_key("links.vis"));
		assert!(out.contains_key("about"));
	}

	#[test]
	fn unknown_vis_label_hides_for_non_owner() {
		let mut x: HashMap<Box<str>, Box<str>> = HashMap::new();
		x.insert("secrets.vis".into(), "banana".into());
		x.insert("secrets".into(), "shh".into());
		x.insert("about".into(), "hi".into());

		let out = filter_sections(x.clone(), auth_role(CommunityRole::Leader));
		assert!(!out.contains_key("secrets"));
		assert!(!out.contains_key("secrets.vis"));
		assert!(out.contains_key("about"));

		let out_owner = filter_sections(x, owner());
		assert!(out_owner.contains_key("secrets"));
		assert!(out_owner.contains_key("secrets.vis"));
	}

	#[test]
	fn vis_marker_without_section_data_is_still_stripped() {
		let mut x: HashMap<Box<str>, Box<str>> = HashMap::new();
		x.insert("links.vis".into(), "contributor".into());
		x.insert("about".into(), "hi".into());

		let out = filter_sections(x, anon());
		assert!(!out.contains_key("links.vis"));
		assert!(out.contains_key("about"));
	}

	#[test]
	fn sections_dropped_entirely_when_all_hidden() {
		let mut x: HashMap<Box<str>, Box<str>> = HashMap::new();
		x.insert("links.vis".into(), "contributor".into());
		x.insert("sections".into(), "links".into());
		x.insert("links".into(), "{}".into());

		let out = filter_sections(x, anon());
		assert!(!out.contains_key("sections"));
		assert!(!out.contains_key("links"));
		assert!(!out.contains_key("links.vis"));
	}

	#[test]
	fn sections_with_whitespace_is_trimmed() {
		let mut x: HashMap<Box<str>, Box<str>> = HashMap::new();
		x.insert("links.vis".into(), "contributor".into());
		x.insert("sections".into(), " about , links , bio ".into());
		x.insert("links".into(), "{}".into());
		x.insert("about".into(), "a".into());
		x.insert("bio".into(), "b".into());

		let out = filter_sections(x, anon());
		let sections = out.get("sections").map_or("", String::as_str);
		let parts: Vec<&str> = sections.split(',').collect();
		assert!(parts.contains(&"about"));
		assert!(parts.contains(&"bio"));
		assert!(!parts.contains(&"links"));
	}
}

// vim: ts=4
