// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Profile listing and retrieval handlers

use axum::{
	Json,
	extract::{Path, Query, State},
	http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::prelude::*;
use cloudillo_core::extract::OptionalRequestId;
use cloudillo_types::meta_adapter::{
	ListProfileOptions, ProfileConnectionStatus, ProfileStatus, ProfileTrust,
};
use cloudillo_types::types::{ApiResponse, ProfileInfo};

/// Profile with relationship status (for GET /api/profiles/:idTag)
#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileWithStatus {
	pub id_tag: String,
	pub name: String,
	#[serde(rename = "type")]
	pub r#type: Option<String>,
	pub profile_pic: Option<String>,
	pub status: Option<ProfileStatus>,
	pub connected: Option<bool>,
	pub following: Option<bool>,
	pub follower: Option<bool>,
	pub trust: Option<ProfileTrust>,
	/// Reader's feed read-watermark for this context (seeds `useReadMarker`).
	/// ISO 8601 string (round-trips with `PUT /api/read-marker`'s `position`).
	#[serde(
		serialize_with = "cloudillo_types::types::serialize_timestamp_iso_opt",
		skip_serializing_if = "Option::is_none"
	)]
	pub feed_read_at: Option<Timestamp>,
	/// Reader's DM read-watermark for this peer (seeds `useReadMarker`).
	/// ISO 8601 string (round-trips with `PUT /api/read-marker`'s `position`).
	#[serde(
		serialize_with = "cloudillo_types::types::serialize_timestamp_iso_opt",
		skip_serializing_if = "Option::is_none"
	)]
	pub msg_read_at: Option<Timestamp>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListProfilesQuery {
	#[serde(alias = "q")]
	search: Option<String>,
	#[serde(rename = "type")]
	typ: Option<cloudillo_types::meta_adapter::ProfileType>,
	/// `trustSet=true` returns only profiles with a non-null trust preference;
	/// `trustSet=false` returns only profiles with no trust preference set.
	/// Used by the shell's trusted-profiles settings page.
	trust_set: Option<bool>,
	/// Filter by id_tag (exact match, used for the personal-profile lookup path).
	id_tag: Option<String>,
	/// Filter by `following` flag.
	following: Option<bool>,
	/// Filter by `follower` flag (profiles that follow this tenant).
	follower: Option<bool>,
	/// Filter by connection status. Wire values: `"true"` / `"false"` for the
	/// boolean cases plus `"R"` for `RequestPending` — mirrors the frontend
	/// `ProfileConnectionStatus = boolean | 'R'` shape.
	connected: Option<String>,
	/// Comma-separated list of `ProfileStatus` codes (e.g. `status=A,T`).
	/// Frontend `qs()` encodes arrays as comma-joined strings.
	status: Option<String>,
}

/// Parse the `connected=` query value.
///
/// Unknown values yield `None` (no filter applied) — silent drop matches the
/// rest of this module's query parsing. A 400 would be stricter, but the
/// frontend uses `qs()` which is the only client; bad values here would be a
/// frontend bug, not user input.
fn parse_connected(value: &str) -> Option<ProfileConnectionStatus> {
	match value {
		"true" => Some(ProfileConnectionStatus::Connected),
		"false" => Some(ProfileConnectionStatus::Disconnected),
		"R" => Some(ProfileConnectionStatus::RequestPending),
		_ => None,
	}
}

/// Parse a comma-separated `status=` list into a `Box<[ProfileStatus]>`.
///
/// - `Ok(None)`: input was empty/whitespace-only/just commas → no filter.
/// - `Ok(Some(codes))`: at least one recognized code; unknown codes alongside
///   recognized ones are silently dropped (matches `parse_connected`).
/// - `Err(ValidationError)`: caller provided a non-empty value but every
///   token is unrecognized — surfacing this as 400 prevents a frontend bug
///   producing `?status=foo` from returning the entire profile catalogue.
fn parse_status_list(value: &str) -> ClResult<Option<Box<[ProfileStatus]>>> {
	let mut had_token = false;
	let parsed: Box<[ProfileStatus]> = value
		.split(',')
		.filter_map(|s| {
			let t = s.trim();
			if t.is_empty() {
				return None;
			}
			had_token = true;
			match t {
				"A" => Some(ProfileStatus::Active),
				"B" => Some(ProfileStatus::Blocked),
				"M" => Some(ProfileStatus::Muted),
				"S" => Some(ProfileStatus::Suspended),
				"X" => Some(ProfileStatus::Banned),
				_ => None,
			}
		})
		.collect();
	if parsed.is_empty() {
		if had_token {
			return Err(Error::ValidationError("unknown status codes".into()));
		}
		Ok(None)
	} else {
		Ok(Some(parsed))
	}
}

/// GET /profile - List all profiles or search profiles
/// Query parameters:
///   type: Optional filter by profile type ("person" or "community")
///   search: Optional search term to filter profiles by id_tag or name
///   limit: Results per page (default 20, max 100)
///   offset: Pagination offset (default 0)
///
/// Status default policy: when `status` is omitted, the handler defaults to
/// the visible set `[Active, Muted]` — Active is the default state, Muted is
/// a soft moderation state still visible to callers. The adapter treats
/// `status IS NULL` rows as Active, so legacy rows surface under this default
/// and under any explicit filter that includes Active. Suspended, Blocked,
/// and Banned are only returned when explicitly requested via `?status=...`.
pub async fn list_profiles(
	State(app): State<App>,
	tn_id: TnId,
	OptionalRequestId(req_id): OptionalRequestId,
	Query(params): Query<ListProfilesQuery>,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<ProfileInfo>>>)> {
	// Build options for list_profiles
	let status = match params.status.as_deref() {
		Some(s) => parse_status_list(s)?,
		None => Some(Box::from([ProfileStatus::Active, ProfileStatus::Muted])),
	};
	let opts = ListProfileOptions {
		typ: params.typ,
		status,
		connected: params.connected.as_deref().and_then(parse_connected),
		following: params.following,
		follower: params.follower,
		q: params.search.as_ref().map(|s| s.to_lowercase()),
		id_tag: params.id_tag,
		trust_set: params.trust_set,
		hidden_in_home: None,
	};

	// Fetch profiles with optional search
	let profiles_list = app.meta_adapter.list_profiles(tn_id, &opts).await?;

	// Convert Profile to ProfileInfo
	let profiles: Vec<ProfileInfo> = profiles_list
		.into_iter()
		.map(|p| ProfileInfo {
			id_tag: p.id_tag.to_string(),
			name: p.name.to_string(),
			r#type: Some(
				match p.typ {
					cloudillo_types::meta_adapter::ProfileType::Person => "person",
					cloudillo_types::meta_adapter::ProfileType::Community => "community",
				}
				.to_string(),
			),
			profile_pic: p.profile_pic.map(|s| s.to_string()),
			status: p.status,
			connected: Some(p.connected.is_connected()),
			following: Some(p.following),
			follower: Some(p.follower),
			trust: p.trust,
			roles: p.roles.map(|r| r.iter().map(ToString::to_string).collect()),
			created_at: None, // Not available in Profile type
			feed_read_at: p.feed_read_at,
			msg_read_at: p.msg_read_at,
			// NULL/0 in the column both mean "shown" → only surface a positive flag.
			hidden_in_home: p.hidden_in_home.filter(|&h| h),
			x: None,
		})
		.collect();

	let response = ApiResponse::new(profiles).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// GET /profile/:idTag - Get specific profile's local relationship state
/// Returns the locally cached relationship data (connected, following, status)
/// Returns empty/null if the profile is not known locally
pub async fn get_profile_by_id_tag(
	State(app): State<App>,
	tn_id: TnId,
	OptionalRequestId(req_id): OptionalRequestId,
	Path(id_tag): Path<String>,
) -> ClResult<(StatusCode, Json<ApiResponse<Option<ProfileWithStatus>>>)> {
	// Lookup profile in local profiles table (relationship data)
	let profile = match app.meta_adapter.read_profile(tn_id, &id_tag).await {
		Ok((_etag, p)) => {
			let typ = match p.typ {
				cloudillo_types::meta_adapter::ProfileType::Person => None,
				cloudillo_types::meta_adapter::ProfileType::Community => {
					Some("community".to_string())
				}
			};
			Some(ProfileWithStatus {
				id_tag: p.id_tag.to_string(),
				name: p.name.to_string(),
				r#type: typ,
				profile_pic: p.profile_pic.map(|s| s.to_string()),
				status: p.status,
				connected: Some(p.connected.is_connected()),
				following: Some(p.following),
				follower: Some(p.follower),
				trust: p.trust,
				feed_read_at: p.feed_read_at,
				msg_read_at: p.msg_read_at,
			})
		}
		Err(Error::NotFound) => None, // Return empty when not found locally
		Err(e) => return Err(e),
	};

	let response = ApiResponse::new(profile).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parse_connected_known_values() {
		assert_eq!(parse_connected("true"), Some(ProfileConnectionStatus::Connected));
		assert_eq!(parse_connected("false"), Some(ProfileConnectionStatus::Disconnected));
		assert_eq!(parse_connected("R"), Some(ProfileConnectionStatus::RequestPending));
	}

	#[test]
	fn parse_connected_unknown_drops_to_none() {
		assert_eq!(parse_connected(""), None);
		assert_eq!(parse_connected("foo"), None);
		assert_eq!(parse_connected("TRUE"), None);
		assert_eq!(parse_connected("1"), None);
	}

	fn ok_some(value: &str) -> Box<[ProfileStatus]> {
		parse_status_list(value)
			.expect("should not error")
			.expect("should produce a filter")
	}

	#[test]
	fn parse_status_list_single_code() {
		assert_eq!(&*ok_some("A"), &[ProfileStatus::Active]);
	}

	#[test]
	fn parse_status_list_multiple_codes() {
		assert_eq!(
			&*ok_some("A,M,B"),
			&[ProfileStatus::Active, ProfileStatus::Muted, ProfileStatus::Blocked]
		);
	}

	#[test]
	fn parse_status_list_all_five_codes() {
		assert_eq!(
			&*ok_some("A,B,M,S,X"),
			&[
				ProfileStatus::Active,
				ProfileStatus::Blocked,
				ProfileStatus::Muted,
				ProfileStatus::Suspended,
				ProfileStatus::Banned,
			]
		);
	}

	#[test]
	fn parse_status_list_trims_whitespace() {
		assert_eq!(&*ok_some(" A , M "), &[ProfileStatus::Active, ProfileStatus::Muted]);
	}

	#[test]
	fn parse_status_list_drops_unknown_codes() {
		assert_eq!(&*ok_some("A,Q,T,Z"), &[ProfileStatus::Active]);
	}

	#[test]
	fn parse_status_list_empty_string_yields_none() {
		assert!(matches!(parse_status_list(""), Ok(None)));
	}

	#[test]
	fn parse_status_list_only_commas_yields_none() {
		assert!(matches!(parse_status_list(",,,"), Ok(None)));
	}

	#[test]
	fn parse_status_list_leading_trailing_commas() {
		assert_eq!(&*ok_some(",A,"), &[ProfileStatus::Active]);
	}

	#[test]
	fn parse_status_list_all_unknown_errors() {
		assert!(matches!(parse_status_list("Q,Z,foo"), Err(Error::ValidationError(_))));
	}
}

// vim: ts=4
