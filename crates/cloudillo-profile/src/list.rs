// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Profile listing and retrieval handlers

use std::collections::HashSet;

use axum::{
	Json,
	extract::{Path, Query, State},
	http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::prelude::*;
use cloudillo_core::abac;
use cloudillo_core::extract::{Auth, IdTag, OptionalRequestId};
use cloudillo_core::profile_visibility::RequesterTier;
use cloudillo_types::meta_adapter::{
	ListProfileOptions, Profile, ProfileConnectionStatus, ProfileStatus, ProfileTrust, ProfileType,
	PublicProfileRow,
};
use cloudillo_types::types::{ApiResponse, ProfileInfo};
use cloudillo_types::utils::normalize_id_tag;

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
	/// Our hat role map for this peer community (leaders only)
	pub hat_roles: Option<String>,
	/// The peer community's hat map for our members, mirrored and advisory (leaders only)
	pub peer_hat_roles: Option<String>,
	/// Identities the tenant owner has used at this peer (`""` = as themselves; owner only)
	pub hats: Option<Vec<String>>,
}

/// Reduced, deliberately public projection returned by `GET /api/profiles/batch`.
///
/// **Every field here is already obtainable without authentication** at that profile's
/// own node, from `GET /api/me` (`routes/public.rs` → `handler::get_tenant_profile_base`)
/// — this is exactly that response minus `keys`. That equivalence is what admits the
/// route to the scope-agnostic tier whose rule is on
/// `cloudillo_core::middleware::require_auth_public_data`.
///
/// It is **not** [`ProfileWithStatus`], which leaks the reading tenant's private
/// relationship state (`status` including Blocked/Muted/Banned, `connected`,
/// `following`, `follower`, `trust`, and the `feedReadAt`/`msgReadAt` DM read
/// watermarks), and **not** `ProfileBase`, which carries `keys`.
#[skip_serializing_none]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicProfile {
	pub id_tag: String,
	pub name: String,
	#[serde(rename = "type")]
	pub r#type: String,
	pub profile_pic: Option<String>,
}

impl From<Profile<Box<str>>> for PublicProfile {
	fn from(p: Profile<Box<str>>) -> Self {
		PublicProfileRow { id_tag: p.id_tag, name: p.name, typ: p.typ, profile_pic: p.profile_pic }
			.into()
	}
}

impl From<PublicProfileRow> for PublicProfile {
	fn from(p: PublicProfileRow) -> Self {
		Self {
			id_tag: p.id_tag.to_string(),
			name: p.name.to_string(),
			r#type: p.typ.as_str().to_string(),
			profile_pic: p.profile_pic.map(|s| s.to_string()),
		}
	}
}

/// Hard server-side cap on `?idTags=` entries. Matches the shell's existing
/// client-side cap.
///
/// It bounds the size of one request's `IN (…)` lookup; requests *per second* are
/// bounded separately by the `"general"` `RateLimitLayer` the route carries in
/// `routes/protected.rs`.
pub const PROFILE_BATCH_MAX: usize = 64;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchProfilesQuery {
	/// Comma-separated id_tags. Absent or empty yields an empty result set.
	id_tags: Option<String>,
}

/// Normalise a raw `?idTags=` value into the lookup set: canonicalise each entry with
/// [`cloudillo_types::utils::normalize_id_tag`] (the same helper the meta adapter applies
/// to every stored id_tag), drop empties, de-duplicate preserving first-seen order, and
/// enforce [`PROFILE_BATCH_MAX`]. Not redundant with the adapter's normalisation: the
/// de-duplication and the cap are both case-insensitive accounting the handler has to do
/// for itself.
///
/// The cap is checked against the raw split count **first**, so an oversized query string
/// is rejected without work proportional to its length. Empty and whitespace-only entries
/// therefore count toward that early check. It is applied again after normalisation, so
/// the error stays correct for a value that is only oversized once trimmed.
fn normalise_batch_tags(raw: &str) -> ClResult<Vec<String>> {
	fn too_many() -> Error {
		Error::ValidationError(format!("idTags: at most {PROFILE_BATCH_MAX} entries per request"))
	}

	if raw.split(',').count() > PROFILE_BATCH_MAX {
		return Err(too_many());
	}

	let mut seen: HashSet<String> = HashSet::new();
	let mut out: Vec<String> = Vec::new();
	for tag in raw.split(',') {
		let tag = normalize_id_tag(tag).into_owned();
		if tag.is_empty() {
			continue;
		}
		if seen.insert(tag.clone()) {
			out.push(tag);
		}
	}

	if out.len() > PROFILE_BATCH_MAX {
		return Err(too_many());
	}

	Ok(out)
}

/// `GET /api/profiles/batch?idTags=a,b,c` — reduced public projection for a set
/// of locally mirrored profiles.
///
/// Exists so that collaborators on a **foreign-hosted** document resolve to a name and
/// picture for viewers whose own node has never synced them. A document app holds a
/// `file:{file_id}:{R|C|W}`-scoped token for the *document's* node, so it asks that node
/// — the one guaranteed to know every collaborator. `GET /api/profiles/{id_tag}` cannot
/// serve this: it is scope-denied to a file-scoped token, and it returns the reading
/// tenant's private relationship state.
///
/// The tier's admission rule — and why any valid token, whatever its scope, reaches this
/// handler — is on `cloudillo_core::middleware::require_auth_public_data`.
///
/// ## What this deliberately exposes
///
/// A document token becomes a lookup capability against this node's mirrored profiles,
/// accepted knowingly. Every *field* returned is already public at that profile's own
/// node (see [`PublicProfile`]), so the sole incremental disclosure is **which** profiles
/// this node has mirrored. Mitigated by the reduced projection, [`PROFILE_BATCH_MAX`],
/// and the `"general"` rate-limit bucket.
///
/// ## Behaviour
///
/// - Absent or empty `idTags` → `200` with an empty array.
/// - Over [`PROFILE_BATCH_MAX`] entries → `400` (see [`normalise_batch_tags`] for what is
///   counted). Rejected, not truncated: a silent truncation would show our own clients a
///   *partial* roster with no signal that it was cut.
/// - Unknown or not-locally-mirrored id_tags are **omitted**, not reported — so the
///   caller cannot distinguish "no such profile" from "this node has not mirrored it",
///   and one bad entry does not fail the batch.
/// - The response may therefore be shorter than the request, is *not* positionally
///   aligned with it, and its order is unspecified. Callers key by `idTag`.
pub async fn get_profiles_batch(
	State(app): State<App>,
	tn_id: TnId,
	OptionalRequestId(req_id): OptionalRequestId,
	Query(params): Query<BatchProfilesQuery>,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<PublicProfile>>>)> {
	let raw = params.id_tags.unwrap_or_default();
	let id_tags = normalise_batch_tags(&raw)?;
	let tag_refs: Vec<&str> = id_tags.iter().map(String::as_str).collect();

	let profiles: Vec<PublicProfile> = app
		.meta_adapter
		.read_profiles(tn_id, &tag_refs)
		.await?
		.into_iter()
		.map(PublicProfile::from)
		.collect();

	let response = ApiResponse::new(profiles).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
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
///
/// Per-caller projection ([`RequesterTier::from_auth`]): only the owner tier gets the above.
/// For everyone else `status` is forced to `[Active, Muted]` and the `trustSet`,
/// `following` and `follower` filters are ignored; each row drops `status`, `following`,
/// `follower`, `trust`, `feedReadAt`, `msgReadAt`, `hiddenInHome`, `hatRoles` and
/// `peerHatRoles`, and non-members also drop `roles`. `hats` is the tenant account's alone.
/// Connections follow the tenant's `profile.connection_visibility` per connected profile type:
/// a non-owner lists only the types it may see (none → empty list, a forbidden `type=` → empty
/// list), and only ever the Connected rows: `connected` is forced to Connected, and
/// `connected=R` / `connected=false` give an empty list (followed, follower and disconnected
/// contacts are not connections).
pub async fn list_profiles(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Query(params): Query<ListProfilesQuery>,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<ProfileInfo>>>)> {
	let is_self = abac::is_tenant_self(&auth, &tenant_id_tag);
	let tier = RequesterTier::from_auth(&app, tn_id, &tenant_id_tag, Some(&auth)).await?;
	let full = tier.is_owner;
	let member = tier.max_role.is_some();
	let sees = ConnectionSight::new(&app, tn_id, tier).await?;

	let empty = |req_id: Option<String>| {
		let response = ApiResponse::new(Vec::new()).with_req_id(req_id.unwrap_or_default());
		Ok((StatusCode::OK, Json(response)))
	};
	let parsed = params.connected.as_deref().and_then(parse_connected);
	// Non-owners list only the profile types whose connections they may see: every row is
	// one of the tenant's contacts, so the list itself reveals the relationship.
	let typ = if full {
		params.typ
	} else {
		// Pending requests are the tenant's inbox; non-connections are not shown at all.
		if parsed.is_some_and(|c| !c.is_connected()) {
			return empty(req_id);
		}
		match params.typ {
			Some(t) if !sees.of(t) => return empty(req_id),
			Some(t) => Some(t),
			None => match (sees.person, sees.community) {
				(true, true) => None,
				(true, false) => Some(ProfileType::Person),
				(false, true) => Some(ProfileType::Community),
				(false, false) => return empty(req_id),
			},
		}
	};

	let connected = if full { parsed } else { Some(ProfileConnectionStatus::Connected) };

	// Build options for list_profiles
	let status = match params.status.as_deref() {
		Some(s) if full => parse_status_list(s)?,
		_ => Some(Box::from([ProfileStatus::Active, ProfileStatus::Muted])),
	};
	let opts = ListProfileOptions {
		typ,
		status,
		connected,
		following: params.following.filter(|_| full),
		follower: params.follower.filter(|_| full),
		q: params.search.as_ref().map(|s| s.to_lowercase()),
		id_tag: params.id_tag,
		trust_set: params.trust_set.filter(|_| full),
		hidden_in_home: None,
		// Unset: this endpoint keeps the name-ordered top-100 listing.
		limit: None,
		after_id_tag: None,
	};

	// Fetch profiles with optional search
	let profiles_list = app.meta_adapter.list_profiles(tn_id, &opts).await?;

	// Convert Profile to ProfileInfo
	let profiles: Vec<ProfileInfo> = profiles_list
		.into_iter()
		.map(|p| ProfileInfo {
			id_tag: p.id_tag.to_string(),
			name: p.name.to_string(),
			r#type: Some(p.typ.as_str().to_string()),
			profile_pic: p.profile_pic.map(|s| s.to_string()),
			status: p.status.filter(|_| full),
			connected: Some(p.connected.is_connected()),
			following: Some(p.following).filter(|_| full),
			follower: Some(p.follower).filter(|_| full),
			trust: p.trust.filter(|_| full),
			roles: p
				.roles
				.filter(|_| full || member)
				.map(|r| r.iter().map(ToString::to_string).collect()),
			created_at: None, // Not available in Profile type
			feed_read_at: p.feed_read_at.filter(|_| full),
			msg_read_at: p.msg_read_at.filter(|_| full),
			// NULL/0 in the column both mean "shown" → only surface a positive flag.
			hidden_in_home: p.hidden_in_home.filter(|&h| h && full),
			hat_roles: p.hat_roles.filter(|_| full).map(Into::into),
			peer_hat_roles: p.peer_hat_roles.filter(|_| full).map(Into::into),
			// `is_self` implies the owner tier.
			hats: tenant_hats(p.hats, is_self),
			x: None,
		})
		.collect();

	let response = ApiResponse::new(profiles).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// The profile's hats, shown only to the tenant account itself.
fn tenant_hats(hats: Option<Box<[Box<str>]>>, is_self: bool) -> Option<Vec<String>> {
	hats.filter(|_| is_self).map(|h| h.iter().map(ToString::to_string).collect())
}

/// Which of the tenant's connections a caller may see, per connected profile type.
struct ConnectionSight {
	person: bool,
	community: bool,
}

impl ConnectionSight {
	async fn new(app: &App, tn_id: TnId, tier: RequesterTier) -> ClResult<Self> {
		Ok(Self {
			person: tier.sees_connections(app, tn_id, ProfileType::Person).await?,
			community: tier.sees_connections(app, tn_id, ProfileType::Community).await?,
		})
	}

	fn of(&self, typ: ProfileType) -> bool {
		match typ {
			ProfileType::Person => self.person,
			ProfileType::Community => self.community,
		}
	}
}

/// GET /profile/:idTag - Get specific profile's local relationship state
/// Returns the locally cached relationship data (connected, following, status)
/// Returns empty/null if the profile is not known locally
///
/// Same projection as [`list_profiles`]: the relationship fields are the owner tier's,
/// `connected` follows `profile.connection_visibility` for the profile's type, `hats` is the
/// tenant account's alone.
pub async fn get_profile_by_id_tag(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Path(id_tag): Path<String>,
) -> ClResult<(StatusCode, Json<ApiResponse<Option<ProfileWithStatus>>>)> {
	let is_self = abac::is_tenant_self(&auth, &tenant_id_tag);
	let tier = RequesterTier::from_auth(&app, tn_id, &tenant_id_tag, Some(&auth)).await?;
	let full = tier.is_owner;
	// Lookup profile in local profiles table (relationship data)
	let profile = match app.meta_adapter.read_profile(tn_id, &id_tag).await {
		Ok((_etag, p)) => {
			let (hat_roles, peer_hat_roles) = if p.typ == ProfileType::Community && full {
				(p.hat_roles.map(Into::into), p.peer_hat_roles.map(Into::into))
			} else {
				(None, None)
			};
			let typ = match p.typ {
				ProfileType::Person => None,
				ProfileType::Community => Some("community".to_string()),
			};
			let sees = tier.sees_connections(&app, tn_id, p.typ).await?;
			Some(ProfileWithStatus {
				id_tag: p.id_tag.to_string(),
				name: p.name.to_string(),
				r#type: typ,
				profile_pic: p.profile_pic.map(|s| s.to_string()),
				status: p.status.filter(|_| full),
				connected: Some(p.connected.is_connected()).filter(|_| sees),
				following: Some(p.following).filter(|_| full),
				follower: Some(p.follower).filter(|_| full),
				trust: p.trust.filter(|_| full),
				feed_read_at: p.feed_read_at.filter(|_| full),
				msg_read_at: p.msg_read_at.filter(|_| full),
				hat_roles,
				peer_hat_roles,
				hats: tenant_hats(p.hats, is_self),
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

	fn normalised(raw: &str) -> Vec<String> {
		normalise_batch_tags(raw).expect("within the cap")
	}

	/// `n` distinct tags, comma-joined with **no** trailing comma — a trailing one would
	/// add an empty entry to the raw split count, which `normalise_batch_tags` counts.
	fn tags(n: usize) -> String {
		(0..n).map(|i| format!("u{i}.example.com")).collect::<Vec<_>>().join(",")
	}

	#[test]
	fn normalise_batch_tags_trims_and_drops_empties() {
		assert_eq!(
			normalised(" a.example.com , b.example.com "),
			["a.example.com", "b.example.com"]
		);
		assert_eq!(normalised(",a.example.com,,"), ["a.example.com"]);
		assert!(normalised("").is_empty());
		assert!(normalised(",,, ").is_empty());
	}

	#[test]
	fn normalise_batch_tags_dedupes_preserving_first_seen_order() {
		// De-dup runs *after* the raw-count cap check, so duplicates still consume budget
		// against `PROFILE_BATCH_MAX`.
		assert_eq!(
			normalised("b.example.com,a.example.com,b.example.com"),
			["b.example.com", "a.example.com"]
		);
	}

	/// id_tags are DNS names and the write paths store them lowercased, so the
	/// lookup set is lowercased too — otherwise `Alice.example.com` burns a slot
	/// and then silently misses on SQLite's case-sensitive `id_tag=?`.
	#[test]
	fn normalise_batch_tags_lowercases_and_dedupes_case_insensitively() {
		assert_eq!(normalised("Alice.Example.COM"), ["alice.example.com"]);
		assert_eq!(
			normalised("Alice.Example.COM,alice.example.com,BOB.example.com"),
			["alice.example.com", "bob.example.com"]
		);
	}

	#[test]
	fn normalise_batch_tags_accepts_the_cap_exactly() {
		let out = normalised(&tags(PROFILE_BATCH_MAX));
		assert_eq!(out.len(), PROFILE_BATCH_MAX);
	}

	/// The cap is the endpoint's fan-out control; one entry over it is a 400.
	#[test]
	fn normalise_batch_tags_rejects_one_over_the_cap() {
		assert!(matches!(
			normalise_batch_tags(&tags(PROFILE_BATCH_MAX + 1)),
			Err(Error::ValidationError(_))
		));
	}

	/// Duplicates do not push a caller over the cap as long as the raw entry
	/// count stays within it.
	#[test]
	fn normalise_batch_tags_duplicates_do_not_consume_the_cap_twice() {
		let mut raw = tags(PROFILE_BATCH_MAX - 2);
		raw.push_str(",u0.example.com,u1.example.com");
		let out = normalised(&raw);
		assert_eq!(out.len(), PROFILE_BATCH_MAX - 2);
	}

	/// The cap is checked against the **raw** entry count before de-duplication,
	/// so the quadratic-ish normalisation work can never run on an unbounded
	/// query string. Rejecting a value whose *distinct* count would have fit is
	/// the deliberate trade — do not "fix" this by moving the check after de-dup.
	#[test]
	fn normalise_batch_tags_rejects_oversized_raw_input_even_when_duplicated() {
		let dupes = vec!["u.example.com"; PROFILE_BATCH_MAX + 10].join(",");
		assert!(matches!(normalise_batch_tags(&dupes), Err(Error::ValidationError(_))));
	}

	/// The projection is the whole justification for mounting this route on the
	/// scope-agnostic tier, so pin the wire shape exactly: the four public fields and
	/// nothing else — in particular none of the reading tenant's private relationship
	/// state (`status`, `connected`, `following`, `follower`, `trust`, `feedReadAt`,
	/// `msgReadAt`) and none of `keys` / `roles`.
	#[test]
	fn public_profile_serialises_only_the_four_public_fields() {
		let cases = [
			(Some("f1~abc"), vec!["idTag", "name", "profilePic", "type"]),
			// An absent picture is omitted, not serialised as null.
			(None, vec!["idTag", "name", "type"]),
		];

		for (profile_pic, expected) in cases {
			let json = serde_json::to_value(PublicProfile {
				id_tag: "alice.example.com".into(),
				name: "Alice".into(),
				r#type: "person".into(),
				profile_pic: profile_pic.map(Into::into),
			})
			.expect("serialises");

			let obj = json.as_object().expect("object");
			let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
			keys.sort_unstable();
			assert_eq!(keys, expected);
		}
	}
}

// vim: ts=4
