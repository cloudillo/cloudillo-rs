// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Profile listing and retrieval handlers

use std::collections::HashSet;

use axum::{
	Json,
	extract::{Path, State},
	http::StatusCode,
};
use cloudillo_types::extract::Query;
use serde::Deserialize;

use crate::prelude::*;
use cloudillo_core::abac;
use cloudillo_core::extract::{Auth, IdTag, OptionalAuth};
use cloudillo_core::profile_visibility::RequesterTier;
use cloudillo_types::auth_adapter::AuthCtx;
use cloudillo_types::meta_adapter::{
	ListProfileOptions, ProfileConnectionStatus, ProfileStatus, ProfileType,
};
use cloudillo_types::types::{ApiResponse, CursorData, ProfileView};
use cloudillo_types::utils::normalize_id_tag;

/// Public profile projection; defined in `cloudillo-types` so `/api/me/full` can carry it.
pub use cloudillo_types::types::PublicProfile;

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
	#[serde(default, deserialize_with = "cloudillo_types::meta_adapter::deserialize_split")]
	id_tags: Option<Vec<String>>,
}

/// Normalise a split `?idTags=` list into the lookup set: canonicalise each entry with
/// [`cloudillo_types::utils::normalize_id_tag`] (the same helper the meta adapter applies
/// to every stored id_tag), drop empties, de-duplicate preserving first-seen order, and
/// enforce [`PROFILE_BATCH_MAX`]. Not redundant with the adapter's normalisation: the
/// de-duplication and the cap are both case-insensitive accounting the handler has to do
/// for itself.
///
/// The cap is checked against the split entry count **first**, so an oversized list is
/// rejected before any normalisation or de-duplication work. It is applied again after
/// normalisation, so the error stays correct for a value that is only oversized once trimmed.
fn normalise_batch_tags(raw: &[String]) -> ClResult<Vec<String>> {
	fn too_many() -> Error {
		Error::ValidationError(format!("idTags: at most {PROFILE_BATCH_MAX} entries per request"))
	}

	if raw.len() > PROFILE_BATCH_MAX {
		return Err(too_many());
	}

	let mut seen: HashSet<String> = HashSet::new();
	let mut out: Vec<String> = Vec::new();
	for tag in raw {
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

/// `GET /api/profile-lookups?idTags=a,b,c` — reduced public projection for a set
/// of locally mirrored profiles.
///
/// Exists so that collaborators on a **foreign-hosted** document resolve to a name and
/// picture for viewers whose own node has never synced them. A document app holds a
/// `file:{file_id}:{R|C|W}`-scoped token for the *document's* node, so it asks that node
/// — the one guaranteed to know every collaborator. `GET /api/profiles/{idTag}` cannot
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
/// **Exception, owner-only: `badges`.** Which badges this node verified and displays
/// reveals the tenant's own community memberships (only badges from communities it is
/// connected to or follows are shown), so `badges` is filled only for the tenant account
/// itself ([`abac::is_tenant_account`] — not SADM, not a share-link or other scoped token,
/// which a bare `id_tag` comparison would admit). Every other caller gets it omitted.
/// The tenant's own entry carries its shown badges too, read from its `BDG` actions, and is
/// added from the tenant row when the tenant is not in its own `profiles` table.
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
	IdTag(tenant_id_tag): IdTag,
	OptionalAuth(auth): OptionalAuth,
	Query(params): Query<BatchProfilesQuery>,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<PublicProfile>>>)> {
	let id_tags = normalise_batch_tags(params.id_tags.as_deref().unwrap_or_default())?;
	let tag_refs: Vec<&str> = id_tags.iter().map(String::as_str).collect();

	let mut profiles: Vec<PublicProfile> = app
		.meta_adapter
		.read_profiles(tn_id, &tag_refs)
		.await?
		.into_iter()
		.map(PublicProfile::from)
		.collect();

	// Owner-only (see the doc above).
	if auth.as_ref().is_some_and(|a| abac::is_tenant_account(a, &tenant_id_tag)) {
		crate::handler::attach_owner_badges(&app, tn_id, &tenant_id_tag, &tag_refs, &mut profiles)
			.await?;
	}

	let response = ApiResponse::new(profiles);

	Ok((StatusCode::OK, Json(response)))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListProfilesQuery {
	/// Free-text filter.
	q: Option<String>,
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
	/// Filter by connection status: `connection=connected|pending|none`.
	connection: Option<ConnectionFilter>,
	/// Comma-separated list of `ProfileStatus` words (e.g. `status=active,muted`).
	#[serde(default, deserialize_with = "cloudillo_types::meta_adapter::deserialize_split")]
	status: Option<Vec<String>>,
	/// Opaque cursor from a previous page's `next`.
	cursor: Option<String>,
	/// Page size (default 50, max 100).
	limit: Option<u32>,
}

/// `connection=` query value (tri-state enum word). An unknown word is a 400 — an
/// ignored filter would return the whole contact list instead.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
enum ConnectionFilter {
	Connected,
	Pending,
	None,
}

impl From<ConnectionFilter> for ProfileConnectionStatus {
	fn from(c: ConnectionFilter) -> Self {
		match c {
			ConnectionFilter::Connected => ProfileConnectionStatus::Connected,
			ConnectionFilter::Pending => ProfileConnectionStatus::RequestPending,
			ConnectionFilter::None => ProfileConnectionStatus::Disconnected,
		}
	}
}

/// Parse a split `status=` list into a `Box<[ProfileStatus]>`.
///
/// - `Ok(None)`: empty list → no filter.
/// - `Ok(Some(codes))`: every word recognized.
/// - `Err(ValidationError)`: any unknown word — a typo must not silently widen or narrow
///   the filter.
fn parse_status_list(value: &[String]) -> ClResult<Option<Box<[ProfileStatus]>>> {
	if value.is_empty() {
		return Ok(None);
	}
	let parsed = value
		.iter()
		.map(|t| {
			ProfileStatus::from_word(t)
				.ok_or_else(|| Error::ValidationError(format!("unknown status `{t}`")))
		})
		.collect::<ClResult<Box<[_]>>>()?;
	Ok(Some(parsed))
}

/// GET /profile - List all profiles or search profiles
/// Query parameters:
///   type: Optional filter by profile type ("person" or "community")
///   q: Optional search term to filter profiles by id_tag or name
///   limit: Results per page (default 50, max 100)
///   cursor: Opaque cursor from the previous page's `next`
///
/// Ordered by `id_tag` (the adapter's keyset); `next` is set when another page exists.
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
/// `follower`, `trust`, `msgState`, `feedState`, `hiddenInHome`, `hatRoles` and
/// `peerHatRoles`, and non-members also drop `roles`. `hats` is the tenant account's alone.
/// Connections follow the tenant's `profile.connection_visibility` per connected profile type:
/// a non-owner lists only the types it may see (none → empty list, a forbidden `type=` → empty
/// list), and only ever the Connected rows: `connected` is forced to Connected, and
/// `connected=R` / `connected=false` give an empty list (followed, follower and disconnected
/// contacts are not connections).
///
/// The tenant's own row is never listed (it is not a contact), so `?idTag=<own>` is empty;
/// read it with `GET /api/profiles/{idTag}`.
pub async fn list_profiles(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	Auth(auth): Auth,
	Query(params): Query<ListProfilesQuery>,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<ProfileView>>>)> {
	let is_self = abac::is_tenant_self(&auth, &tenant_id_tag);
	let tier = RequesterTier::from_auth(&app, tn_id, &tenant_id_tag, Some(&auth)).await?;
	let full = tier.is_owner;
	let member = tier.max_role.is_some();
	let sees = ConnectionSight::new(&app, tn_id, tier).await?;
	let limit = params.limit.unwrap_or(50).clamp(1, 100);
	let after_id_tag = match params.cursor.as_deref() {
		None => None,
		Some(c) => Some(
			CursorData::decode(c)
				.filter(|c| c.s == "profile")
				.ok_or_else(|| Error::ValidationError("invalid cursor".into()))?
				.id,
		),
	};

	let empty = || {
		let response = ApiResponse::new(Vec::new());
		Ok((StatusCode::OK, Json(response)))
	};
	let parsed = params.connection.map(ProfileConnectionStatus::from);
	// Non-owners list only the profile types whose connections they may see: every row is
	// one of the tenant's contacts, so the list itself reveals the relationship.
	let typ = if full {
		params.typ
	} else {
		// Pending requests are the tenant's inbox; non-connections are not shown at all.
		if parsed.is_some_and(|c| !c.is_connected()) {
			return empty();
		}
		match params.typ {
			Some(t) if !sees.of(t) => return empty(),
			Some(t) => Some(t),
			None => match (sees.person, sees.community) {
				(true, true) => None,
				(true, false) => Some(ProfileType::Person),
				(false, true) => Some(ProfileType::Community),
				(false, false) => return empty(),
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
		q: params.q.as_ref().map(|s| s.to_lowercase()),
		id_tag: params.id_tag,
		exclude_id_tag: Some(tenant_id_tag.to_string()),
		trust_set: params.trust_set.filter(|_| full),
		hidden_in_home: None,
		// `id_tag`-ordered keyset page; one extra row tells whether another page exists
		limit: Some(limit + 1),
		after_id_tag,
	};

	// Fetch profiles with optional search
	let mut profiles_list = app.meta_adapter.list_profiles(tn_id, &opts).await?;
	let next = if profiles_list.len() > limit as usize {
		profiles_list.truncate(limit as usize);
		profiles_list
			.last()
			.map(|p| CursorData::new("profile", serde_json::Value::Null, &p.id_tag).encode())
	} else {
		None
	};

	let profiles: Vec<ProfileView> = profiles_list
		.into_iter()
		.map(|p| ProfileView {
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
			msg_state: p.msg_state.filter(|_| full),
			feed_state: p.feed_state.filter(|_| full),
			// NULL/0 in the column both mean "shown" → only surface a positive flag.
			hidden_in_home: p.hidden_in_home.filter(|&h| h && full),
			hat_roles: p.hat_roles.filter(|_| full).map(Into::into),
			peer_hat_roles: p.peer_hat_roles.filter(|_| full).map(Into::into),
			// `is_self` implies the owner tier.
			hats: tenant_hats(p.hats, is_self),
			x: None,
		})
		.collect();

	let response = ApiResponse::with_next(profiles, next);

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
/// 404 if the profile is not known locally
///
/// Same projection as [`list_profiles`]: the relationship fields are the owner tier's,
/// `connected` follows `profile.connection_visibility` for the profile's type, `hats` is the
/// tenant account's alone.
pub async fn get_profile_by_id_tag(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(tenant_id_tag): IdTag,
	Auth(auth): Auth,
	Path(id_tag): Path<String>,
) -> ClResult<(StatusCode, Json<ApiResponse<ProfileView>>)> {
	let profile = profile_with_status(&app, tn_id, &tenant_id_tag, &auth, &id_tag).await?;
	Ok((StatusCode::OK, Json(ApiResponse::new(profile))))
}

/// The requester's view of one locally known profile, filtered by their tier; `NotFound`
/// when no local row exists.
pub(crate) async fn profile_with_status(
	app: &App,
	tn_id: TnId,
	tenant_id_tag: &str,
	auth: &AuthCtx,
	id_tag: &str,
) -> ClResult<ProfileView> {
	let is_self = abac::is_tenant_self(auth, tenant_id_tag);
	let tier = RequesterTier::from_auth(app, tn_id, tenant_id_tag, Some(auth)).await?;
	let full = tier.is_owner;
	// Lookup profile in local profiles table (relationship data)
	let (_etag, p) = app.meta_adapter.read_profile(tn_id, id_tag).await?;
	let (hat_roles, peer_hat_roles) = if p.typ == ProfileType::Community && full {
		(p.hat_roles.map(Into::into), p.peer_hat_roles.map(Into::into))
	} else {
		(None, None)
	};
	let sees = tier.sees_connections(app, tn_id, p.typ).await?;
	Ok(ProfileView {
		id_tag: p.id_tag.to_string(),
		name: p.name.to_string(),
		r#type: Some(p.typ.as_str().to_string()),
		profile_pic: p.profile_pic.map(|s| s.to_string()),
		status: p.status.filter(|_| full),
		connected: Some(p.connected.is_connected()).filter(|_| sees),
		following: Some(p.following).filter(|_| full),
		follower: Some(p.follower).filter(|_| full),
		trust: p.trust.filter(|_| full),
		msg_state: p.msg_state.filter(|_| full),
		feed_state: p.feed_state.filter(|_| full),
		hat_roles,
		peer_hat_roles,
		hats: tenant_hats(p.hats, is_self),
		..ProfileView::default()
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	/// What `deserialize_split` hands the handler for a raw `a,b` value.
	fn split(raw: &str) -> Vec<String> {
		raw.split(',').map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).collect()
	}

	#[test]
	fn connection_words_map_to_status() {
		let parse = |w: &str| {
			serde_json::from_value::<ConnectionFilter>(serde_json::json!(w))
				.map(ProfileConnectionStatus::from)
				.ok()
		};
		assert_eq!(parse("connected"), Some(ProfileConnectionStatus::Connected));
		assert_eq!(parse("pending"), Some(ProfileConnectionStatus::RequestPending));
		assert_eq!(parse("none"), Some(ProfileConnectionStatus::Disconnected));
		assert_eq!(parse("true"), None);
		assert_eq!(parse("R"), None);
	}

	fn ok_some(value: &str) -> Box<[ProfileStatus]> {
		parse_status_list(&split(value))
			.expect("should not error")
			.expect("should produce a filter")
	}

	#[test]
	fn parse_status_list_single_code() {
		assert_eq!(&*ok_some("active"), &[ProfileStatus::Active]);
	}

	#[test]
	fn parse_status_list_multiple_codes() {
		assert_eq!(
			&*ok_some("active,muted,blocked"),
			&[ProfileStatus::Active, ProfileStatus::Muted, ProfileStatus::Blocked]
		);
	}

	#[test]
	fn parse_status_list_all_five_codes() {
		assert_eq!(
			&*ok_some("active,blocked,muted,suspended,banned"),
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
		assert_eq!(&*ok_some(" active , muted "), &[ProfileStatus::Active, ProfileStatus::Muted]);
	}

	#[test]
	fn parse_status_list_refuses_any_unknown_code() {
		assert!(matches!(
			parse_status_list(&split("active,bogus")),
			Err(Error::ValidationError(_))
		));
	}

	#[test]
	fn parse_status_list_empty_string_yields_none() {
		assert!(matches!(parse_status_list(&split("")), Ok(None)));
	}

	#[test]
	fn parse_status_list_only_commas_yields_none() {
		assert!(matches!(parse_status_list(&split(",,,")), Ok(None)));
	}

	#[test]
	fn parse_status_list_leading_trailing_commas() {
		assert_eq!(&*ok_some(",active,"), &[ProfileStatus::Active]);
	}

	#[test]
	fn parse_status_list_all_unknown_errors() {
		assert!(matches!(parse_status_list(&split("Q,Z,foo")), Err(Error::ValidationError(_))));
		// The old letter codes are no longer words.
		assert!(matches!(parse_status_list(&split("A,B")), Err(Error::ValidationError(_))));
	}

	fn normalised(raw: &str) -> Vec<String> {
		normalise_batch_tags(&split(raw)).expect("within the cap")
	}

	/// `n` distinct tags, comma-joined.
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
			normalise_batch_tags(&split(&tags(PROFILE_BATCH_MAX + 1))),
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
		assert!(matches!(normalise_batch_tags(&split(&dupes)), Err(Error::ValidationError(_))));
	}

	/// The projection is the whole justification for mounting this route on the
	/// scope-agnostic tier, so pin the wire shape exactly: the four public fields and
	/// nothing else — in particular none of the reading tenant's private relationship
	/// state (`status`, `connected`, `following`, `follower`, `trust`, `msgState`,
	/// `feedState`) and none of `keys` / `roles`.
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
				badges: None,
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
