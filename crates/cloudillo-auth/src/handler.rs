// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

use axum::{
	Json,
	extract::{ConnectInfo, Query, State},
	http::{HeaderMap, StatusCode},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::skip_serializing_none;
use std::net::SocketAddr;

use cloudillo_core::{
	ActionVerifyFn, Auth,
	extract::{IdTag, OptionalAuth, OptionalRequestId},
	rate_limit::{PenaltyReason, RateLimitApi},
	roles::{active_member_role, expand_roles, expand_roles_preserving_extras},
	settings::SettingValue,
};
use cloudillo_email::{EmailModule, EmailTaskParams, get_tenant_lang};
use cloudillo_ref::service::{CreateRefInternalParams, create_ref_internal};
use cloudillo_types::{
	action_types::{ACCESS_TOKEN_EXPIRY, CreateAction},
	auth_adapter::{self, ActionToken, ListTenantsOptions},
	meta_adapter::{
		ListRefsOptions, PASSWORD_REF_TYPE, ProfileStatus, ProfileType, SHARE_FILE_REF_TYPE,
		WELCOME_REF_TYPE,
	},
	roles::{check_hat_aprv, hat_peer, map_hat_role, parse_hat_roles},
	types::{AccessLevel, ApiResponse},
	utils::decode_jwt_no_verify,
	validation::validate_id_tag,
};

use crate::prelude::*;

/// Longest `exp` a PROXY token may carry to be traded for a session.
///
/// `cloudillo_core::request::create_proxy_token` mints them with 60s; the slack covers
/// clock skew between federated servers. See the `t == "PROXY"` gate in
/// [`get_access_token`].
const PROXY_TOKEN_MAX_LIFETIME: i64 = 300;

/// # Login
#[skip_serializing_none]
#[derive(Clone, Serialize)]
pub struct Login {
	// auth data
	#[serde(rename = "tnId")]
	tn_id: TnId,
	#[serde(rename = "idTag")]
	id_tag: String,
	roles: Option<Vec<String>>,
	token: String,
	// profile data
	name: String,
	#[serde(rename = "profilePic")]
	profile_pic: String,
	settings: Vec<(String, String)>,
}

#[derive(Serialize)]
pub struct IdTagRes {
	#[serde(rename = "idTag")]
	id_tag: String,
}

pub async fn get_id_tag(
	State(app): State<App>,
	OptionalRequestId(_req_id): OptionalRequestId,
	req: axum::http::Request<axum::body::Body>,
) -> ClResult<(StatusCode, Json<IdTagRes>)> {
	let host = req
		.uri()
		.host()
		.or_else(|| req.headers().get(axum::http::header::HOST).and_then(|h| h.to_str().ok()))
		.unwrap_or_default();
	let cert_data = app.auth_adapter.read_cert_by_domain(host).await?;

	Ok((StatusCode::OK, Json(IdTagRes { id_tag: cert_data.id_tag.to_string() })))
}

pub async fn return_login(
	app: &App,
	auth: auth_adapter::AuthLogin,
) -> ClResult<(StatusCode, Json<Login>)> {
	// Fetch tenant data for name and profile_pic
	// Use read_tenant since the user is logging into their own tenant
	let tenant = app.meta_adapter.read_tenant(auth.tn_id).await.ok();

	let (name, profile_pic) = match tenant {
		Some(t) => (t.name.to_string(), t.profile_pic.map(|p| p.to_string())),
		None => (auth.id_tag.to_string(), None),
	};

	let login = Login {
		tn_id: auth.tn_id,
		id_tag: auth.id_tag.to_string(),
		roles: auth.roles.map(|roles| roles.iter().map(ToString::to_string).collect()),
		token: auth.token.to_string(),
		name,
		profile_pic: profile_pic.unwrap_or_default(),
		settings: vec![],
	};

	Ok((StatusCode::OK, Json(login)))
}

/// # POST /api/auth/login
#[derive(Deserialize)]
pub struct LoginReq {
	#[serde(rename = "idTag")]
	id_tag: String,
	password: String,
}

pub async fn post_login(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(login): Json<LoginReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<Login>>)> {
	let auth = app.auth_adapter.check_tenant_password(&login.id_tag, &login.password).await;

	if let Ok(auth) = auth {
		let (_status, Json(login_data)) = return_login(&app, auth).await?;
		let response = ApiResponse::new(login_data).with_req_id(req_id.unwrap_or_default());
		Ok((StatusCode::OK, Json(response)))
	} else {
		// Penalize rate limit for failed login attempt
		if let Err(e) = app.rate_limiter.penalize(&addr.ip(), PenaltyReason::AuthFailure, 1) {
			warn!("Failed to record auth penalty for {}: {}", addr.ip(), e);
		}
		tokio::time::sleep(std::time::Duration::from_secs(1)).await;
		Err(Error::PermissionDenied)
	}
}

/// # GET /api/auth/login-token
pub async fn get_login_token(
	State(app): State<App>,
	IdTag(id_tag): IdTag,
	OptionalAuth(auth): OptionalAuth,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Option<Login>>>)> {
	if let Some(auth) = auth {
		// A delegated credential is never the account. A share-link token's `id_tag` *is*
		// the tenant (it is minted `sub: None`), so it would satisfy the host binding in
		// `create_tenant_login` and trade a read-only file scope for an owner session.
		if auth.scope.is_some() {
			warn!(subject = %auth.id_tag, "login-token denied - delegated token");
			return Err(Error::PermissionDenied);
		}
		info!("login-token for {}", &auth.id_tag);
		// A session whose `id_tag` is not this host's tenant fails the adapter's host binding.
		// Tokens here are bearer-only and stored per origin, so an ordinary same-origin session
		// cannot produce that mismatch — it means a credential minted elsewhere is being
		// presented. Denied outright, with the delay kept as an anti-enumeration measure for
		// the adapter's other failure modes (absent or disabled tenant).
		match app.auth_adapter.create_tenant_login(&auth.id_tag, &id_tag).await {
			Ok(auth_login) => {
				let (_status, Json(login_data)) = return_login(&app, auth_login).await?;
				let response =
					ApiResponse::new(Some(login_data)).with_req_id(req_id.unwrap_or_default());
				Ok((StatusCode::OK, Json(response)))
			}
			Err(e) => {
				warn!(subject = %auth.id_tag, host = %id_tag, error = %e, "login-token denied");
				tokio::time::sleep(std::time::Duration::from_secs(1)).await;
				Err(Error::PermissionDenied)
			}
		}
	} else {
		// No authentication - return empty result
		info!("login-token called without authentication");
		let response = ApiResponse::new(None).with_req_id(req_id.unwrap_or_default());
		Ok((StatusCode::OK, Json(response)))
	}
}

/// Request body for logout endpoint
#[derive(Deserialize, Default)]
pub struct LogoutReq {
	/// Optional API key to delete on logout (for "stay logged in" cleanup)
	#[serde(rename = "apiKey")]
	api_key: Option<String>,
}

/// POST /auth/logout - Invalidate current access token
pub async fn post_logout(
	State(app): State<App>,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<LogoutReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	// Note: Token invalidation could be implemented with a token blacklist table
	// For now, tokens remain valid until expiration (short-lived access tokens)

	// If API key provided, validate it belongs to this user and delete it
	if let Some(ref api_key) = req.api_key {
		match app.auth_adapter.validate_api_key(api_key).await {
			Ok(validation) if validation.tn_id == auth.tn_id => {
				if let Err(e) = app.auth_adapter.delete_api_key(auth.tn_id, validation.key_id).await
				{
					warn!("Failed to delete API key {} on logout: {:?}", validation.key_id, e);
				} else {
					info!(
						"Deleted API key {} for user {} on logout",
						validation.key_id, auth.id_tag
					);
				}
			}
			Ok(_) => {
				warn!("API key provided at logout does not belong to user {}", auth.id_tag);
			}
			Err(e) => {
				// Invalid/expired key, ignore silently (might already be deleted)
				debug!("API key validation failed on logout: {:?}", e);
			}
		}
	}

	info!("User {} logged out", auth.id_tag);

	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// # POST /api/auth/password
#[derive(Deserialize)]
pub struct PasswordReq {
	#[serde(rename = "currentPassword")]
	current_password: String,
	#[serde(rename = "newPassword")]
	new_password: String,
}

pub async fn post_password(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<PasswordReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	// Validate new password strength
	if req.new_password.trim().is_empty() {
		return Err(Error::ValidationError("Password cannot be empty or only whitespace".into()));
	}

	if req.new_password.len() < 8 {
		return Err(Error::ValidationError("Password must be at least 8 characters".into()));
	}

	if req.new_password == req.current_password {
		return Err(Error::ValidationError(
			"New password must be different from current password".into(),
		));
	}

	// Verify current password using authenticated user's id_tag
	let verification = app
		.auth_adapter
		.check_tenant_password(&auth.id_tag, &req.current_password)
		.await;

	if verification.is_err() {
		// Penalize rate limit for failed password verification
		if let Err(e) = app.rate_limiter.penalize(&addr.ip(), PenaltyReason::AuthFailure, 1) {
			warn!("Failed to record auth penalty for {}: {}", addr.ip(), e);
		}
		// Delay to prevent timing attacks
		tokio::time::sleep(std::time::Duration::from_secs(1)).await;
		warn!("Failed password verification for user {}", auth.id_tag);
		return Err(Error::PermissionDenied);
	}

	// Update to new password
	app.auth_adapter.update_tenant_password(&auth.id_tag, &req.new_password).await?;

	info!("User {} successfully changed their password", auth.id_tag);

	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// # GET /api/auth/access-token
/// Gets an access token for a subject.
/// Can be called with either:
/// 1. A token query parameter (action token to exchange)
/// 2. A refId query parameter (share link to exchange for scoped token)
/// 3. An apiKey query parameter (API key to exchange for access token)
/// 4. A via parameter (cross-document link: get token for target file via source file)
/// 5. Just subject parameter (uses authenticated session)
#[derive(Deserialize)]
pub struct GetAccessTokenQuery {
	#[serde(default)]
	token: Option<String>,
	scope: Option<String>,
	/// Share link ref_id to exchange for a scoped access token
	#[serde(rename = "refId")]
	ref_id: Option<String>,
	/// API key to exchange for an access token
	#[serde(rename = "apiKey")]
	api_key: Option<String>,
	/// If true with refId, use validate_ref instead of use_ref (for token refresh)
	#[serde(default)]
	refresh: Option<bool>,
	/// Source file_id for cross-document link access (requires scope param with target file)
	via: Option<String>,
	/// Hat endorsement (an `APRV` from the hat community, see [`get_hat_endorse`]). Only
	/// with `token`; the session then carries the mapped role and `h`.
	hat: Option<String>,
}

/// `hat=` rides only on a bare PROXY exchange: combined with any other mode it would mean a
/// hatted session that is also scoped, share-linked or API-keyed, which nothing defines.
fn hat_params_valid(query: &GetAccessTokenQuery) -> bool {
	query.hat.is_none()
		|| (query.token.is_some()
			&& query.scope.is_none()
			&& query.ref_id.is_none()
			&& query.api_key.is_none()
			&& query.via.is_none())
}

/// B-side check of a session hat endorsement, returning the local role it maps to.
///
/// `proxy` is the caller's verified PROXY (already `aud`/expiry-checked), `endorsement` the
/// verified `APRV` from the hat community, `peer` that community's local profile row as
/// [`hat_peer`] gives it. The shared part is [`check_hat_aprv`]. Signature
/// verification does not require `exp`, so the endorsement's expiry is checked here.
fn check_session_hat(
	proxy: &ActionToken,
	endorsement: &ActionToken,
	us: &str,
	now: i64,
	peer: Option<(ProfileType, bool, Option<&str>)>,
) -> ClResult<Box<str>> {
	let deny = |why: &str| {
		warn!(member = %proxy.iss, hat = %endorsement.iss, "Hat session denied - {why}");
		Err(Error::PermissionDenied)
	};
	let local = match check_hat_aprv(endorsement, us, peer) {
		Ok(local) => local,
		Err(why) => return deny(why),
	};
	if endorsement.iss.as_ref() == us || endorsement.iss == proxy.iss {
		return deny("self-endorsement");
	}
	if endorsement.sub.as_deref().and_then(|s| s.strip_prefix('@')) != Some(&*proxy.iss) {
		return deny("endorsement names another member");
	}
	match endorsement.exp.map(|e| e.0) {
		Some(exp) if exp > now && exp <= now + PROXY_TOKEN_MAX_LIFETIME => Ok(local),
		_ => deny("endorsement expiry missing, past or too distant"),
	}
}

/// The `sub` a *derived* token (`?via=` cross-document link) should carry.
///
/// A derived token inherits the caller's identity, because the caller is the person who
/// will be editing the embedded document. It carries none only when the caller has none
/// to pass on — an anonymous share-link visitor, whose `AuthCtx::id_tag` is the tenant
/// owner by `iss` fallback and must never be asserted as a person.
///
/// Keyed on [`auth_adapter::AuthCtx::anonymous`], NOT on `scope`: a `file:`-scoped token
/// minted for a signed-in user names a real person, and chaining a second `?via=` hop
/// must not silently demote them to a guest. The token's *authority* is unaffected
/// either way — it comes from the freshly computed `file:` scope, and `r` is `None`.
fn derived_sub(auth: &auth_adapter::AuthCtx) -> Option<&str> {
	(!auth.anonymous).then_some(&*auth.id_tag)
}

/// Whether an inbound action token may be traded for a session.
///
/// **PROXY only.** PROXY is minted for exactly this exchange
/// (`cloudillo_core::request::create_proxy_token`, 60s `exp`); every *other* action type is
/// handed to third parties by design — `/api/actions?includeTokens=true` is unauthenticated,
/// `/api/outbox` reaches any follower, CONV fan-out and roster backfill reach every member —
/// so without this any signed action token naming this tenant in `aud` is a bearer credential
/// minting a full-role session as its issuer.
///
/// **And it must expire soon.** `verify_jwt_signature` in cloudillo-action cannot require `exp`
/// globally (ordinary federated posts legitimately carry none), so the requirement lives here,
/// on the one path where a missing or distant expiry turns a captured token into a standing
/// credential. `max_exp` is `now + PROXY_TOKEN_MAX_LIFETIME`; the slack over PROXY's own 60s
/// covers clock skew between federated servers.
fn proxy_exchange_allowed(typ: &str, exp: Option<i64>, max_exp: i64) -> bool {
	typ == "PROXY" && exp.is_some_and(|e| e <= max_exp)
}

/// The role set a re-minted session token should carry, re-read from storage rather than
/// copied from the presented `r` claim — these tokens are renewable indefinitely, so carrying
/// `r` forward would let an out-of-band revocation never take effect.
///
/// The tenant account itself gets the base `leader` hierarchy plus the extras in
/// `tenants.roles` (`SADM`), mirroring auth-adapter-sqlite's `build_tenant_owner_roles`; a
/// failed `read_tenant` still leaves the base hierarchy. For everyone else the outcomes are
/// kept apart: a revocation returns `Ok(None)` (row present, no roles) or `Err(NotFound)`
/// (profile deleted), and both narrow. Only a genuinely transient `Err` falls back to the
/// presented claim rather than presenting as a downgrade.
/// `None` means "no roles" (an empty set never becomes `Some("")`).
///
/// The "is this the tenant account" comparison stays a plain `==`; both sides are canonical by
/// construction — see [`cloudillo_types::utils::normalize_id_tag`] for why that rule holds.
async fn reread_roles(
	app: &App,
	tn_id: TnId,
	tenant_id_tag: &str,
	auth: &auth_adapter::AuthCtx,
) -> ClResult<Option<String>> {
	// The revocation choke point for the tenant's `status`, for every caller and not just the
	// account: a soft-deleted tenant (`"X"`, what `assert_tenant_active` rejects at login)
	// must not keep minting refreshes for a community member either — they take the
	// `read_profile_roles` branch below. A *failed* read is not a denial; it only narrows.
	//
	// ponytail: a community member pays two reads per refresh here, and they cannot be merged —
	// `read_tenant` is on the **auth** adapter, `read_profile_roles` on the **meta** adapter,
	// different databases. Revisit only with a measurement, and then by moving the status into
	// the roles' adapter rather than caching a revocation gate.
	let tenant = app.auth_adapter.read_tenant(tenant_id_tag).await.ok();
	if tenant.as_ref().is_some_and(|t| t.status.as_deref() == Some("X")) {
		warn!(subject = %auth.id_tag, tenant = %tenant_id_tag, "Role re-read denied - tenant deleted");
		return Err(Error::PermissionDenied);
	}

	let expanded = if auth.id_tag.as_ref() == tenant_id_tag {
		let mut roles: Vec<Box<str>> = vec!["leader".into()];
		// A failed read keeps the plain `leader` hierarchy.
		if let Some(extra) = tenant.and_then(|t| t.roles) {
			roles.extend(extra.iter().cloned());
		}
		Some(expand_roles_preserving_extras(&roles))
	} else {
		match app.meta_adapter.read_profile_roles(tn_id, &auth.id_tag).await {
			Ok(Some(roles)) => Some(expand_roles(&roles)),
			// A deleted profile surfaces as `Err(NotFound)`, not `Ok(None)` — that is a
			// revocation, not a transient fault, so it narrows just like a NULL `roles`.
			Ok(None) | Err(Error::NotFound) => None,
			Err(e) => {
				warn!(
					"Failed to re-read roles for {} in tn_id {:?}, keeping presented set: {}",
					auth.id_tag, tn_id, e
				);
				Some(auth.roles.iter().map(AsRef::as_ref).collect::<Vec<&str>>().join(","))
			}
		}
	};
	Ok(narrow_to_presented(expanded, &auth.roles).filter(|s| !s.is_empty()))
}

/// Intersect a re-read role set with the presented one: a re-read may only *narrow*.
///
/// Several credential families authenticate *as* the tenant while deliberately carrying no
/// roles — `cloudillo_core::middleware` builds an `idp_` API key's `AuthCtx` with
/// `roles: Box::new([])` — so an unintersected re-read turns one into a full owner session.
/// A JWT session's presented set was minted by the same expansion, so this never costs it a
/// role it legitimately holds; an out-of-band *promotion* simply waits for the next login.
fn narrow_to_presented(expanded: Option<String>, presented: &[Box<str>]) -> Option<String> {
	let presented: std::collections::HashSet<&str> = presented.iter().map(AsRef::as_ref).collect();
	expanded
		.map(|s| s.split(',').filter(|r| presented.contains(r)).collect::<Vec<&str>>().join(","))
}

/// The four DAV capability scopes, comma-separated, normalised — or `None` if `requested`
/// contains anything else. Whitespace around entries is trimmed, mirroring
/// `cloudillo_core::scope::has_scope`'s tolerance for `", "` separators.
fn normalized_dav_scope(requested: &str) -> Option<String> {
	const DAV_SCOPES: &[&str] = &["carddav:read", "carddav:write", "caldav:read", "caldav:write"];

	// `split` always yields at least one entry, so an empty string fails the membership test.
	let entries: Vec<&str> = requested.split(',').map(str::trim).collect();
	entries.iter().all(|e| DAV_SCOPES.contains(e)).then(|| entries.join(","))
}

/// Validate a client-requested `?scope=` against what the caller can actually reach, returning the
/// scope string to stamp into the minted token.
///
/// Without this, `?scope=file:{id}:W` was a self-service capability mint: `file_access`'s scope
/// short-circuit treats a matching file scope as *the* grant, on the assumption that only a server
/// that checked the access ever minted one. Same `min()` cap as the `?via=` branch.
///
/// Every call site rejects a *scoped* caller before reaching here (the `auth.scope.is_some()` guard
/// in the session branch, hatted or not; the federated branch authenticates with an action token,
/// which carries no scope), so `apkg:publish` only needs the role test.
///
/// Its `App`-dependent half — the `check_file_access` call — is covered indirectly by
/// `cloudillo_core::tests::file_access_scope::scope_mint_denies_strangers_and_caps_at_real_access`,
/// which pins the ladder and the `scope_char_within` cap this composes. There is no `App` test
/// harness in the tree to pin the composition itself.
async fn validated_scope(
	app: &App,
	tn_id: TnId,
	tenant_id_tag: &str,
	caller_id_tag: &str,
	caller_roles: &[Box<str>],
	caller_hatted: bool,
	requested: Option<&str>,
) -> ClResult<Option<String>> {
	use cloudillo_core::file_access::{self, FileAccessCtx};
	use cloudillo_types::types::TokenScope;
	use tracing::warn;

	let Some(requested) = requested else { return Ok(None) };

	// Fail closed on an unrecognised scope: `scope::scope_permits` grants a non-`TokenScope`
	// string nothing outside the DAV families, so minting one would produce a token that is
	// useless at best and, on any looser consumer, unrestricted.
	let Some(token_scope) = TokenScope::parse(requested) else {
		// The DAV capability families are the one legitimate non-`TokenScope` value here.
		// They only ever narrow a session (`scope::scope_permits` allowlists them for the
		// DAV surface and denies everything else), so no authorisation test is needed.
		return normalized_dav_scope(requested)
			.map(Some)
			.ok_or_else(|| Error::ValidationError("Invalid scope format".into()));
	};

	match token_scope {
		TokenScope::File { file_id, access } => {
			let ctx = FileAccessCtx {
				user_id_tag: caller_id_tag,
				tenant_id_tag,
				user_roles: caller_roles,
				hatted: caller_hatted,
				scope: None,
				names_holder: true,
			};
			let denied = || {
				warn!("Scope denied: {} has no access to file {}", caller_id_tag, file_id);
				Error::PermissionDenied
			};
			// A write scope is a placement: by content id it resolves to the one entry the
			// caller is admitted to (409 when several), then caps as any scope. A read scope
			// takes the read union.
			let result = if access > AccessLevel::Read {
				let floor = AccessLevel::Read;
				match file_access::resolve_placement(app, tn_id, &file_id, &ctx, floor).await {
					Ok(r) => r,
					Err(e @ Error::Conflict(_)) => return Err(e),
					Err(_) => return Err(denied()),
				}
			} else {
				file_access::check_file_access(app, tn_id, &file_id, &ctx, None)
					.await
					.map_err(|_| denied())?
			};

			// `to_scope_char` caps admin at 'W' — a scope never carries share-management
			// authority. `None` only for `AccessLevel::None`, which `check_file_access`
			// already turned into `Err`.
			// A BLOB content id is granted through one of its entries: bind the scope to that
			// entry, so it never reaches a private sibling of the same content.
			let fv = &result.file_view;
			let scope_id = if fv.file_tp.as_deref() == Some("BLOB") && *fv.entry_id != *file_id {
				&*fv.entry_id
			} else {
				&*file_id
			};
			let scope_char = file_access::scope_char_within(access, result.access_level)
				.ok_or(Error::PermissionDenied)?;
			Ok(Some(format!("file:{}:{}", scope_id, scope_char)))
		}
		// Grants no file access, but `scope::scope_permits` allowlists it for app publishing,
		// so it must not be self-mintable either. Mirrors `require_leader`.
		TokenScope::ApkgPublish => {
			if !cloudillo_core::roles::is_leader(caller_roles) {
				warn!("apkg:publish scope denied for non-leader {}", caller_id_tag);
				return Err(Error::PermissionDenied);
			}
			Ok(Some(requested.to_string()))
		}
	}
}

/// Expiry for a hatted session's child token, which may only be a `file:` scope and never
/// outlives its parent. Anything else is 401: the param-less refresh would re-read roles and drop
/// the mapped one, and other scopes would widen the hat's reach. No parent `exp` fails closed.
fn hatted_scope_exp(
	parent_exp: Option<Timestamp>,
	requested: Option<&str>,
	now: Timestamp,
) -> ClResult<Timestamp> {
	use cloudillo_types::types::TokenScope;

	if !matches!(requested.and_then(TokenScope::parse), Some(TokenScope::File { .. })) {
		return Err(Error::Unauthorized);
	}
	let parent = parent_exp.ok_or(Error::Unauthorized)?;
	Ok(Timestamp((now.0 + ACCESS_TOKEN_EXPIRY).min(parent.0)))
}

/// A presented token that cannot be verified is a 401. A bad signature against a cached key
/// surfaces as the failed key refetch (`NetworkError` / blocked `ServiceUnavailable`), so
/// those count too; local faults (DB, I/O, internal) stay 5xx.
fn verify_failure_is_401(e: Error) -> Error {
	match e {
		Error::Parse
		| Error::NotFound
		| Error::PermissionDenied
		| Error::ValidationError(_)
		| Error::NetworkError(_)
		| Error::Timeout
		| Error::ServiceUnavailable(_) => {
			warn!("Presented token failed verification: {:?}", e);
			Error::Unauthorized
		}
		e => e,
	}
}

pub async fn get_access_token(
	State(app): State<App>,
	tn_id: TnId,
	id_tag: IdTag,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	OptionalAuth(maybe_auth): OptionalAuth,
	Query(query): Query<GetAccessTokenQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<serde_json::Value>>)> {
	use tracing::warn;

	debug!("Got access token request for id_tag={} with scope={:?}", id_tag.0, query.scope);

	if !hat_params_valid(&query) {
		return Err(Error::ValidationError("hat requires token and excludes other modes".into()));
	}

	// Cross-document link: get scoped token for target file via source file
	if let Some(ref via_file_id) = query.via {
		use cloudillo_types::types::TokenScope;

		// Requires scope param: "file:{target_file_id}:{R|W}"
		let scope_str = query
			.scope
			.as_deref()
			.ok_or_else(|| Error::ValidationError("scope parameter required with via".into()))?;

		let token_scope = TokenScope::parse(scope_str)
			.ok_or_else(|| Error::ValidationError("Invalid scope format".into()))?;

		let TokenScope::File { file_id: ref target_file_id, access: requested_access } =
			token_scope
		else {
			return Err(Error::ValidationError("scope must be a file scope".into()));
		};

		debug!(
			"Via token request: via={}, target={}, access={:?}",
			via_file_id, target_file_id, requested_access
		);

		// Caller must be authenticated (either session or scoped token)
		let auth = maybe_auth.as_ref().ok_or(Error::Unauthorized)?;

		// Parse via reference: could be "id_tag:file_id" or just "file_id"
		let via_bare_file_id =
			via_file_id.split_once(':').map_or(via_file_id.as_str(), |(_, fid)| fid);

		// Share entries and scopes name entries; resolve both ids like `read_file` does. A
		// missing or ambiguous id grants nothing.
		let via_entry_id = app
			.meta_adapter
			.read_file(tn_id, via_bare_file_id)
			.await
			.ok()
			.flatten()
			.ok_or(Error::PermissionDenied)?
			.entry_id;
		// The scope is minted on the linked entry, never a content id (which binds no entry).
		let target_entry_id = app
			.meta_adapter
			.read_file(tn_id, target_file_id)
			.await
			.ok()
			.flatten()
			.ok_or(Error::PermissionDenied)?
			.entry_id;

		// Check caller has access to the via (source) file, and remember the ceiling that
		// access imposes. A scoped caller must never hand out more than it holds: a
		// `file:X:R` guest re-scoping through an embed link stored at `'W'` would
		// otherwise walk the whole embed graph with write access.
		let mut caller_cap: Option<AccessLevel> = None;
		let caller_has_via_access = if let Some(ref caller_scope) = auth.scope {
			// Must be scoped to the via file (bare id), and the level it carries caps
			// whatever is minted below.
			if let Some(TokenScope::File { file_id: ref scope_fid, access }) =
				TokenScope::parse(caller_scope)
			{
				caller_cap = Some(access);
				// The same resolution file access applies: a content-id scope binds no entry.
				match cloudillo_core::file_access::resolve_scope_entry(
					&app.meta_adapter,
					tn_id,
					scope_fid,
				)
				.await
				{
					Some(v) => v.entry_id == via_entry_id,
					None => false,
				}
			} else {
				false
			}
		} else {
			// Session-authenticated user: verify actual file access using bare file_id
			use cloudillo_core::file_access::{self, FileAccessCtx};
			// Unscoped branch: `from_auth` carries `scope: None`.
			let ctx = FileAccessCtx::from_auth(Some(auth), &id_tag.0);
			match file_access::check_file_access(&app, tn_id, via_bare_file_id, &ctx, None).await {
				Ok(result) => {
					// The level the caller actually holds on the via file caps the
					// mint, exactly as the scoped arm's `access` does. `is_ok()`
					// alone succeeds at `Read`, so discarding this let a read-only
					// caller mint `:W` off a `'W'` embed link.
					caller_cap = Some(result.access_level);
					true
				}
				Err(_) => false,
			}
		};

		if !caller_has_via_access {
			warn!("Via token denied: caller has no access to source file {}", via_file_id);
			return Err(Error::PermissionDenied);
		}

		// Look up share entry: resource=target/embedded, subject=via/container
		let link_perm = app
			.meta_adapter
			.check_share_access(tn_id, 'F', &target_entry_id, 'F', &via_entry_id)
			.await?
			.ok_or_else(|| {
				warn!(
					"Via token denied: no file link from {} to {}",
					via_bare_file_id, target_file_id
				);
				Error::PermissionDenied
			})?;

		// Determine effective access: min(requested, link_permission, caller's own level).
		// Both arms above set `caller_cap` whenever `caller_has_via_access` holds, and the
		// handler has already returned when it does not — so the `None` default is
		// unreachable and fails closed if a future arm forgets to set it.
		//
		// `scope_char_within` caps admin at 'W' — a scope never carries share-management
		// authority. Its `None` arm is unreachable here: the link permission came from a
		// stored share entry.
		let asked = requested_access.min(AccessLevel::from_perm_char(link_perm));
		let caller_ceiling = caller_cap.unwrap_or(AccessLevel::None);
		let scope_char = cloudillo_core::file_access::scope_char_within(asked, caller_ceiling)
			.ok_or(Error::PermissionDenied)?;
		let target_scope = format!("file:{}:{}", target_entry_id, scope_char);

		let token_result = app
			.auth_adapter
			.create_access_token(
				tn_id,
				&auth_adapter::AccessToken {
					iss: &id_tag.0,
					sub: derived_sub(auth),
					r: None,
					scope: Some(&target_scope),
					exp: Timestamp::from_now(ACCESS_TOKEN_EXPIRY),
					h: None,
				},
			)
			.await?;

		info!(
			"Issued access token: id_tag={} sub={} scope={} via=cross_doc_link",
			id_tag.0,
			derived_sub(auth).unwrap_or("anonymous"),
			target_scope
		);
		debug!("Created via token for {} with scope {}", target_file_id, target_scope);
		let response = ApiResponse::new(json!({
			"token": token_result,
			"scope": target_scope,
			"resourceId": target_file_id,
			// Derived from the minted char, not recomputed: `scope_char_within` is the one
			// place the cap lives, and `to_scope_char` already caps Admin at 'W'.
			"accessLevel": AccessLevel::from_perm_char(scope_char).as_str(),
		}))
		.with_req_id(req_id.unwrap_or_default());
		return Ok((StatusCode::OK, Json(response)));
	}

	// If token is provided in query, verify it; otherwise use authenticated session
	if let Some(token_param) = query.token {
		debug!("Verifying action token from query parameter");
		let verify_fn = app.ext::<ActionVerifyFn>()?;
		let auth_action = verify_fn(&app, tn_id, &token_param, Some(&addr.ip()))
			.await
			.map_err(verify_failure_is_401)?;
		if *auth_action.aud.as_ref().ok_or(Error::PermissionDenied)?.as_ref() != *id_tag.0 {
			warn!("Auth action issuer {} doesn't match id_tag {}", auth_action.iss, id_tag.0);
			return Err(Error::PermissionDenied);
		}

		// See [`proxy_exchange_allowed`] for why PROXY, and only a short-lived one, is the
		// single action type tradeable for a session.
		let max_exp = Timestamp::from_now(PROXY_TOKEN_MAX_LIFETIME).0;
		if !proxy_exchange_allowed(&auth_action.t, auth_action.exp.map(|e| e.0), max_exp) {
			if auth_action.t.as_ref() == "PROXY" {
				warn!(
					issuer = %auth_action.iss,
					exp = ?auth_action.exp,
					"Access-token exchange denied - PROXY expiry missing or too distant"
				);
			} else {
				warn!(
					issuer = %auth_action.iss,
					action_type = %auth_action.t,
					"Access-token exchange denied - not a PROXY token"
				);
			}
			return Err(Error::PermissionDenied);
		}
		debug!(
			"Got auth action: iss={} sub={:?} exp={:?}",
			auth_action.iss, auth_action.sub, auth_action.exp
		);

		// Hatted session: `(hat community, local role)`. The mapped role *replaces* whatever
		// the member holds here directly, and is never persisted — it lives in the token only.
		let hat = match query.hat.as_deref() {
			Some(hat_token) => {
				let endorsement = verify_fn(&app, tn_id, hat_token, Some(&addr.ip()))
					.await
					.map_err(verify_failure_is_401)?;
				let peer = match app.meta_adapter.read_profile(tn_id, &endorsement.iss).await {
					Ok((_, p)) => Some(p),
					Err(Error::NotFound) => None,
					Err(e) => return Err(e),
				};
				let local = check_session_hat(
					&auth_action,
					&endorsement,
					&id_tag.0,
					Timestamp::now().0,
					peer.as_ref().map(hat_peer),
				)?;
				Some((endorsement.iss, local))
			}
			None => None,
		};

		debug!(
			"Creating access token with t={}, u={}, scope={:?}",
			id_tag.0,
			auth_action.iss,
			query.scope.as_deref()
		);

		// Fetch profile roles from meta adapter and expand them
		// Hat replaces, never adds: a hatted session does not consult the direct roles at all.
		let read = match &hat {
			Some((_, local)) => {
				// The hat never lifts a restriction we placed on the member directly.
				match app.meta_adapter.read_profile(tn_id, &auth_action.iss).await {
					Ok((_, p)) if p.status.is_some_and(ProfileStatus::restricts_access) => {
						warn!(member = %auth_action.iss, "Hat session denied - member restricted");
						return Err(Error::PermissionDenied);
					}
					Ok(_) | Err(Error::NotFound) => {}
					Err(e) => return Err(e),
				}
				Ok(Some(vec![local.clone()].into()))
			}
			None => app.meta_adapter.read_profile_roles(tn_id, &auth_action.iss).await,
		};
		let profile_roles = match read {
			Ok(roles) => {
				debug!(
					"Found profile roles for {} in tn_id {:?}: {:?}",
					auth_action.iss, tn_id, roles
				);
				roles
			}
			Err(Error::NotFound) => {
				// Stranger requesting a federated access token — no local
				// profile, so no roles. Expected case in cross-instance flows.
				debug!(
					"No profile yet for {} in tn_id {:?}, issuing token without roles",
					auth_action.iss, tn_id
				);
				None
			}
			Err(e) => {
				warn!(
					"Failed to read profile roles for {} in tn_id {:?}: {}",
					auth_action.iss, tn_id, e
				);
				None
			}
		};

		let expanded_roles = profile_roles
			.as_ref()
			.map(|roles| expand_roles(roles))
			.filter(|s| !s.is_empty());

		debug!("Expanded roles for access token: {:?}", expanded_roles);

		// The caller may only be handed a scope for a file they can already reach.
		let caller_roles = expanded_roles
			.as_deref()
			.map(cloudillo_core::roles::parse_roles)
			.unwrap_or_default();
		let scope = validated_scope(
			&app,
			tn_id,
			&id_tag.0,
			&auth_action.iss,
			&caller_roles,
			hat.is_some(),
			query.scope.as_deref(),
		)
		.await?;

		let token_result = app
			.auth_adapter
			.create_access_token(
				tn_id,
				&auth_adapter::AccessToken {
					iss: &id_tag.0,
					sub: Some(&auth_action.iss),
					r: expanded_roles.as_deref(),
					scope: scope.as_deref(),
					exp: Timestamp::from_now(ACCESS_TOKEN_EXPIRY),
					h: hat.as_ref().map(|(h, _)| &**h),
				},
			)
			.await?;
		info!(
			"Issued access token: id_tag={} sub={} scope={:?} hat={:?} via=action_token",
			id_tag.0, auth_action.iss, scope, hat
		);
		let mut body = json!({ "token": token_result });
		if let Some((hat_tag, role)) = &hat {
			body["hat"] = json!(hat_tag);
			body["role"] = json!(role);
		}
		let response = ApiResponse::new(body).with_req_id(req_id.unwrap_or_default());
		Ok((StatusCode::OK, Json(response)))
	} else if let Some(ref_id) = query.ref_id {
		// Exchange share link ref for scoped access token (no auth required)
		let is_refresh = query.refresh.unwrap_or(false);
		debug!("Exchanging ref_id {} for scoped access token (refresh={})", ref_id, is_refresh);

		// For refresh: validate without decrementing counter
		// For initial access: validate and decrement counter
		let (ref_tn_id, _ref_id_tag, ref_data) = if is_refresh {
			app.meta_adapter.validate_ref(&ref_id, &[SHARE_FILE_REF_TYPE]).await
		} else {
			app.meta_adapter.use_ref(&ref_id, &[SHARE_FILE_REF_TYPE]).await
		}
		.map_err(|e| {
			warn!(
				"Failed to {} ref {}: {}",
				if is_refresh { "validate" } else { "use" },
				ref_id,
				e
			);
			match e {
				Error::NotFound => Error::ValidationError("Invalid or expired share link".into()),
				Error::ValidationError(_) => e,
				_ => Error::ValidationError("Invalid share link".into()),
			}
		})?;

		// Validate ref belongs to this tenant
		if ref_tn_id != tn_id {
			warn!(
				"Ref tenant mismatch: ref belongs to {:?} but request is for {:?}",
				ref_tn_id, tn_id
			);
			return Err(Error::PermissionDenied);
		}

		// Extract resource_id (file_id) and access_level
		let file_id = ref_data
			.resource_id
			.ok_or_else(|| Error::ValidationError("Share link missing resource_id".into()))?;
		// `to_scope_char` caps admin at 'W', so a ref that somehow carried 'A' cannot emit
		// `file:{id}:A` — which `TokenScope::parse` rejects outright, silently denying the link.
		let access_level = AccessLevel::from_perm_char(ref_data.access_level.unwrap_or('R'));

		// Scope format: "file:{file_id}:{R|C|W}". `from_perm_char` never returns `None`, so
		// `to_scope_char`'s `None` arm is unreachable; deny rather than mint an unsupported scope.
		let scope_char = access_level.to_scope_char().ok_or(Error::PermissionDenied)?;
		let scope = format!("file:{}:{}", file_id, scope_char);
		debug!("Creating scoped access token with scope={}", scope);

		let token_result = app
			.auth_adapter
			.create_access_token(
				tn_id,
				&auth_adapter::AccessToken {
					iss: &id_tag.0,
					sub: None, // Anonymous/guest access
					r: None,   // No roles for share link access
					scope: Some(&scope),
					exp: Timestamp::from_now(ACCESS_TOKEN_EXPIRY),
					h: None,
				},
			)
			.await?;

		info!("Issued access token: id_tag={} sub=anonymous scope={} via=ref_id", id_tag.0, scope);
		debug!("Got scoped access token for share link");
		let mut result = json!({
			"token": token_result,
			"scope": scope,
			"resourceId": file_id.to_string(),
			// Same cap as the scope: a share link never reports admin.
			"accessLevel": access_level.min(AccessLevel::Write).as_str(),
		});
		if let Some(ref params) = ref_data.params {
			result["params"] = json!(params);
		}
		let response = ApiResponse::new(result).with_req_id(req_id.unwrap_or_default());
		Ok((StatusCode::OK, Json(response)))
	} else if let Some(api_key) = query.api_key {
		// Exchange API key for access token (no auth required)
		debug!("Exchanging API key for access token");

		// Validate the API key
		let validation = app.auth_adapter.validate_api_key(&api_key).await.map_err(|e| {
			warn!("API key validation failed: {:?}", e);
			Error::PermissionDenied
		})?;

		// Verify API key belongs to this tenant
		if validation.tn_id != tn_id {
			warn!(
				"API key tenant mismatch: key belongs to {:?} but request is for {:?}",
				validation.tn_id, tn_id
			);
			return Err(Error::PermissionDenied);
		}

		// A capability key (DAV scope) reaches its PIM routes directly; it is never exchanged.
		if validation
			.scopes
			.as_deref()
			.is_some_and(|s| s.split(',').any(|e| normalized_dav_scope(e).is_some()))
		{
			warn!("API key exchange refused: capability (DAV) key");
			return Err(Error::PermissionDenied);
		}

		debug!(
			"Creating access token from API key for id_tag={}, scopes={:?}",
			validation.id_tag, validation.scopes
		);

		// Create access token with API key's scopes
		let token_result = app
			.auth_adapter
			.create_access_token(
				tn_id,
				&auth_adapter::AccessToken {
					iss: &id_tag.0,
					sub: Some(&validation.id_tag),
					r: validation.roles.as_deref(),
					scope: validation.scopes.as_deref(),
					exp: Timestamp::from_now(ACCESS_TOKEN_EXPIRY),
					h: None,
				},
			)
			.await?;

		info!(
			"Issued access token: id_tag={} sub={} scope={:?} via=api_key",
			id_tag.0, validation.id_tag, validation.scopes
		);

		let response = ApiResponse::new(json!({ "token": token_result }))
			.with_req_id(req_id.unwrap_or_default());
		Ok((StatusCode::OK, Json(response)))
	} else {
		// Use authenticated session token - requires auth
		let auth = maybe_auth.ok_or(Error::Unauthorized)?;

		// A scoped token (e.g. a share link) must never mint a broader session token.
		// Only this bare, param-less branch is closed: `?via=` (cross-document
		// re-scoping) accepts a scoped bearer and `?refId=` needs no auth at all —
		// which is why `cloudillo_core::scope` still allowlists this path for `file:*`.
		if auth.scope.is_some() {
			warn!("Scoped token attempted to mint an unscoped session token");
			return Err(Error::PermissionDenied);
		}
		// A hatted session is refreshed by re-running the handshake, never by a role re-read:
		// the mapped roles are not stored here, so a re-read would mint a role-less session.
		// Its one mint is a `file:` scope for iframe apps, keeping the presented `r` and `h`.
		if let Some(hat) = auth.hat.as_deref() {
			let exp = hatted_scope_exp(auth.exp, query.scope.as_deref(), Timestamp::now())?;
			let scope = validated_scope(
				&app,
				tn_id,
				&id_tag.0,
				&auth.id_tag,
				&auth.roles,
				true,
				query.scope.as_deref(),
			)
			.await?;
			let roles = auth.roles.join(",");
			let token_result = app
				.auth_adapter
				.create_access_token(
					tn_id,
					&auth_adapter::AccessToken {
						iss: &id_tag.0,
						sub: Some(&auth.id_tag),
						r: Some(roles.as_str()).filter(|r| !r.is_empty()),
						scope: scope.as_deref(),
						exp,
						h: Some(hat),
					},
				)
				.await?;
			info!(
				"Issued access token: id_tag={} sub={} scope={:?} hat={} via=hatted_session",
				id_tag.0, auth.id_tag, scope, hat
			);
			let response = ApiResponse::new(json!({ "token": token_result }))
				.with_req_id(req_id.unwrap_or_default());
			return Ok((StatusCode::OK, Json(response)));
		}

		debug!(
			"Using authenticated session for id_tag={}, scope={:?}",
			auth.id_tag,
			query.scope.as_deref()
		);

		// Re-read rather than copy the presented `r` claim forward; see `reread_roles`.
		let expanded_roles = reread_roles(&app, tn_id, &id_tag.0, &auth).await?;

		// The caller may only be handed a scope for a file they can already reach.
		// Scored on the *re-read* set above, not the presented token's `r` claim — that claim
		// is what the re-read exists to distrust, and it decides both `ApkgPublish` and the
		// role rung of `file_access`.
		let caller_roles = expanded_roles
			.as_deref()
			.map(cloudillo_core::roles::parse_roles)
			.unwrap_or_default();
		let scope = validated_scope(
			&app,
			tn_id,
			&id_tag.0,
			&auth.id_tag,
			&caller_roles,
			auth.hat.is_some(),
			query.scope.as_deref(),
		)
		.await?;

		let token_result = app
			.auth_adapter
			.create_access_token(
				tn_id,
				&auth_adapter::AccessToken {
					iss: &id_tag.0,
					sub: Some(&auth.id_tag),
					r: expanded_roles.as_deref(),
					scope: scope.as_deref(),
					exp: Timestamp::from_now(ACCESS_TOKEN_EXPIRY),
					h: None,
				},
			)
			.await?;
		info!(
			"Issued access token: id_tag={} sub={} scope={:?} via=session",
			id_tag.0, auth.id_tag, scope
		);
		let response = ApiResponse::new(json!({ "token": token_result }))
			.with_req_id(req_id.unwrap_or_default());
		Ok((StatusCode::OK, Json(response)))
	}
}

/// # GET /api/auth/hat-endorse
/// Runs at the hat community: vouches, to `peer`, for the PROXY issuer's role here. The
/// endorsement is a plain 60s `APRV` minted straight through the auth adapter and never
/// stored — a credential for one `access-token?hat=` exchange, not an action.
#[derive(Deserialize)]
pub struct HatEndorseQuery {
	peer: String,
	token: String,
}

pub async fn get_hat_endorse(
	State(app): State<App>,
	tn_id: TnId,
	id_tag: IdTag,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Query(query): Query<HatEndorseQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<serde_json::Value>>)> {
	let verify_fn = app.ext::<ActionVerifyFn>()?;
	let proxy = verify_fn(&app, tn_id, &query.token, Some(&addr.ip())).await?;
	let max_exp = Timestamp::from_now(PROXY_TOKEN_MAX_LIFETIME).0;
	if proxy.aud.as_deref() != Some(&*id_tag.0)
		|| !proxy_exchange_allowed(&proxy.t, proxy.exp.map(|e| e.0), max_exp)
	{
		warn!(issuer = %proxy.iss, "Hat endorsement denied - not a short-lived PROXY to us");
		return Err(Error::PermissionDenied);
	}
	if !validate_id_tag(&query.peer) || query.peer == *id_tag.0 || query.peer == *proxy.iss {
		return Err(Error::ValidationError("invalid peer".into()));
	}

	// No active role here, no hat.
	let role = active_member_role(&app, tn_id, &proxy.iss).await?.ok_or(Error::NotFound)?;

	let peer = match app.meta_adapter.read_profile(tn_id, &query.peer).await {
		Ok((_, p)) => Some(p),
		Err(Error::NotFound) => None,
		Err(e) => return Err(e),
	};
	let peer = peer.as_ref().map(|p| {
		let (typ, usable, _) = hat_peer(p);
		(typ, usable, p.peer_hat_roles.as_deref())
	});
	check_endorse_peer(peer, &role).inspect_err(|e| {
		if matches!(e, Error::PermissionDenied) {
			warn!(peer = %query.peer, "Hat endorsement denied - not a usable connected community");
		}
	})?;

	let token = app
		.auth_adapter
		.create_action_token(
			tn_id,
			CreateAction {
				typ: "APRV".into(),
				audience_tag: Some(query.peer.as_str().into()),
				subject: Some(format!("@{}", proxy.iss).into()),
				content: Some(json!({ "r": role })),
				expires_at: Some(Timestamp::from_now(60)),
				..Default::default()
			},
		)
		.await?;
	info!(
		"Issued hat endorsement: hat={} member={} peer={} role={}",
		id_tag.0, proxy.iss, query.peer, role
	);
	let response =
		ApiResponse::new(json!({ "token": token })).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

/// May we endorse `role` to `peer`, given as `(type, usable, peer_hat_roles)`? Only to a
/// connected, unrestricted community (`PermissionDenied`). Advisory skip (`NotFound`): the
/// peer's published map already refuses this role. An absent or unparsable map endorses
/// anyway — the peer decides.
fn check_endorse_peer(peer: Option<(ProfileType, bool, Option<&str>)>, role: &str) -> ClResult<()> {
	let Some((ProfileType::Community, true, map)) = peer else {
		return Err(Error::PermissionDenied);
	};
	if let Some(map) = map.and_then(parse_hat_roles)
		&& map_hat_role(&map, role).is_none()
	{
		return Err(Error::NotFound);
	}
	Ok(())
}

/// # GET /api/auth/proxy-token
/// Generate a proxy token for federation (allows this user to authenticate on behalf of the server)
/// If `idTag` query parameter is provided and different from the current server, this will
/// perform a federated token exchange with the target server.
#[skip_serializing_none]
#[derive(Serialize)]
pub struct ProxyTokenRes {
	token: String,
	/// User's roles in this context (extracted from JWT for federated tokens)
	roles: Option<Vec<String>>,
	/// Hat community the session was entered with (`?hat=` only)
	hat: Option<String>,
	/// Local role the target mapped the hat to (`?hat=` only)
	role: Option<String>,
}

#[derive(Deserialize)]
pub struct ProxyTokenQuery {
	#[serde(rename = "idTag")]
	id_tag: Option<String>,
	/// Enter `idTag` wearing this community's hat (requires a federated `idTag`)
	hat: Option<String>,
}

/// `data` of the `ApiResponse` envelope around a federated token exchange.
#[derive(Deserialize)]
struct TokenEnvelope {
	data: TokenData,
}

#[derive(Deserialize)]
struct TokenData {
	token: String,
	role: Option<String>,
}

/// Hat session handshake from the member's own node: a PROXY to the hat community buys a
/// short-lived endorsement, which a second PROXY presents at the target. Returns the target's
/// access token and the local role it mapped the hat to.
///
/// Errors keep the remote's status class (`request::get_bin`): 404 → `NotFound` (no
/// role at the hat, or the hat's published map for the target skips it), 401/403 →
/// `PermissionDenied`, anything else → `NetworkError`.
async fn hat_session(
	app: &App,
	tn_id: TnId,
	target: &str,
	hat: &str,
) -> ClResult<(String, Option<String>)> {
	let mint_proxy = |aud: &str| {
		app.auth_adapter.create_action_token(
			tn_id,
			CreateAction {
				typ: "PROXY".into(),
				audience_tag: Some(aud.into()),
				expires_at: Some(Timestamp::from_now(60)),
				..Default::default()
			},
		)
	};
	let proxy = mint_proxy(hat).await?;
	let endorsement: TokenEnvelope = app
		.request
		.get_noauth(tn_id, hat, &format!("/auth/hat-endorse?peer={target}&token={proxy}"))
		.await?;
	let hat_token = endorsement.data.token;
	// Goes into the target's query string verbatim: only a JWT's base64url segments pass.
	if !hat_token
		.bytes()
		.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
	{
		warn!(hat = %hat, "Hat endorsement is not a JWT");
		return Err(Error::PermissionDenied);
	}
	let proxy = mint_proxy(target).await?;
	let session: TokenEnvelope = app
		.request
		.get_noauth(tn_id, target, &format!("/auth/access-token?token={proxy}&hat={hat_token}"))
		.await?;
	Ok((session.data.token, session.data.role))
}

pub async fn get_proxy_token(
	State(app): State<App>,
	IdTag(own_id_tag): IdTag,
	Auth(auth): Auth,
	Query(query): Query<ProxyTokenQuery>,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<ProxyTokenRes>>)> {
	// `scope::scope_permits` already keeps every delegated token off this route. Fail closed
	// here as well, for both branches: a share-link token must never be able to renew itself
	// past its link's revocation, and re-deriving roles below would hand it the tenant's own
	// (its `id_tag` *is* the tenant, since it is minted `sub: None`).
	if auth.scope.is_some() {
		warn!(subject = %auth.id_tag, scope = ?auth.scope, "Proxy token denied - delegated token");
		return Err(Error::PermissionDenied);
	}
	// Before `reread_roles`, which falls back to the presented `r` on a transient error: a
	// hatted session re-enters through the handshake, in either branch.
	if auth.hat.is_some() {
		return Err(Error::Unauthorized);
	}
	if let Some(hat) = query.hat.as_deref() {
		// Both go into a remote's query string, so they must be canonical id_tags.
		let bad_target = |t: &str| !validate_id_tag(t) || t == hat || t == own_id_tag.as_ref();
		if !validate_id_tag(hat)
			|| hat == own_id_tag.as_ref()
			|| query.id_tag.as_deref().is_none_or(bad_target)
		{
			return Err(Error::ValidationError("hat needs a distinct federated idTag".into()));
		}
	}

	// Re-read rather than copy the presented `r` claim forward; see `reread_roles`.
	let expanded_roles = reread_roles(&app, auth.tn_id, &own_id_tag, &auth).await?;

	// If target idTag is specified and different from own server, use federation
	if let Some(ref target_id_tag) = query.id_tag
		&& target_id_tag != own_id_tag.as_ref()
	{
		#[derive(Deserialize)]
		struct AccessTokenClaims {
			r: Option<String>,
		}

		// Federated exchange mints a token in which the *tenant* vouches for the caller
		// toward a remote server, so it stays owner/leader-only — and that standing is
		// re-read from storage above, not taken from the presented `r` claim, which a
		// since-revoked leader would otherwise keep presenting until their token expired.
		// The local branch below is an ordinary self-scoped session token and needs only auth.
		let reread = cloudillo_core::roles::parse_roles(expanded_roles.as_deref().unwrap_or(""));
		if !cloudillo_core::roles::is_leader(&reread) {
			warn!(
				subject = %auth.id_tag,
				target = %target_id_tag,
				"Federated proxy token denied - owner/leader required"
			);
			return Err(Error::PermissionDenied);
		}

		debug!("Getting federated proxy token for {} -> {}", &auth.id_tag, target_id_tag);

		// Mint fresh on each call: clients want full TTL, cache is for server-to-server only.
		let (token, role) = match query.hat.as_deref() {
			Some(hat) => hat_session(&app, auth.tn_id, target_id_tag, hat).await?,
			None => (
				app.request.create_proxy_token(auth.tn_id, target_id_tag, None).await?.into(),
				None,
			),
		};

		let roles: Option<Vec<String>> = match decode_jwt_no_verify::<AccessTokenClaims>(&token) {
			Ok(claims) => {
				debug!("Decoded federated token, roles claim: {:?}", claims.r);
				claims.r.map(|r| r.split(',').map(String::from).collect())
			}
			Err(e) => {
				warn!("Failed to decode federated token for roles: {:?}", e);
				None
			}
		};

		info!(
			"Issued proxy token: id_tag={} sub={} target={} hat={:?} via=federation",
			own_id_tag, auth.id_tag, target_id_tag, query.hat
		);
		let response =
			ApiResponse::new(ProxyTokenRes { token, roles, hat: query.hat.clone(), role })
				.with_req_id(req_id.unwrap_or_default());
		return Ok((StatusCode::OK, Json(response)));
	}

	// Default: create local access token (valid on own server)
	debug!("Generating local access token for {}", &auth.id_tag);

	let roles_str = expanded_roles.unwrap_or_default();
	let token = app
		.auth_adapter
		.create_access_token(
			auth.tn_id,
			&auth_adapter::AccessToken {
				iss: &own_id_tag,
				sub: Some(&auth.id_tag),
				r: if roles_str.is_empty() { None } else { Some(&roles_str) },
				scope: None,
				exp: Timestamp::from_now(ACCESS_TOKEN_EXPIRY),
				h: None,
			},
		)
		.await?;

	info!("Issued proxy token: id_tag={} sub={} via=local", own_id_tag, auth.id_tag);
	// Return roles alongside token for local context
	let roles: Vec<String> = roles_str
		.split(',')
		.filter(|s| !s.is_empty())
		.map(ToString::to_string)
		.collect();
	let response = ApiResponse::new(ProxyTokenRes {
		token: token.to_string(),
		roles: Some(roles),
		hat: None,
		role: None,
	})
	.with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// # POST /auth/set-password
/// Set password using a reference (welcome or password reset)
/// This endpoint is used during registration (welcome ref) and password reset flows
#[derive(Deserialize)]
pub struct SetPasswordReq {
	#[serde(rename = "refId")]
	ref_id: String,
	#[serde(rename = "newPassword")]
	new_password: String,
}

pub async fn post_set_password(
	State(app): State<App>,
	IdTag(host_id_tag): IdTag,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<SetPasswordReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<Login>>)> {
	// Validate new password strength
	if req.new_password.trim().is_empty() {
		return Err(Error::ValidationError("Password cannot be empty or only whitespace".into()));
	}

	if req.new_password.len() < 8 {
		return Err(Error::ValidationError("Password must be at least 8 characters".into()));
	}

	// Validate the ref non-destructively first so we can refuse to consume
	// the counter when the IDP-activation gate is still engaged. The user
	// will retry from the same welcome link after activating their identity.
	let (tn_id, id_tag, ref_data) = app
		.meta_adapter
		.validate_ref(&req.ref_id, &[WELCOME_REF_TYPE, PASSWORD_REF_TYPE])
		.await
		.map_err(|e| {
			warn!("Failed to validate ref {}: {}", req.ref_id, e);
			match e {
				Error::NotFound => Error::ValidationError("Invalid or expired reference".into()),
				Error::ValidationError(_) => e,
				_ => Error::ValidationError("Invalid reference".into()),
			}
		})?;

	// Bind the ref to the host tenant before any mutation. `validate_ref` is
	// tenant-agnostic, so without this a ref belonging to tenant A could be
	// posted to tenant B's host and A's password would be changed (a
	// cross-tenant write) before `create_tenant_login` below refused the
	// session. Same check as the `?refId=` branch in `get_access_token`.
	if id_tag.as_ref() != host_id_tag.as_ref() {
		warn!(
			ref_owner = %id_tag,
			host = %host_id_tag,
			"set-password ref does not belong to the host tenant"
		);
		return Err(Error::PermissionDenied);
	}

	// Defence-in-depth: the frontend gates the password form on
	// /api/refs/{refId}/idp-status, but a curl client could otherwise post
	// straight here with an active welcome ref. Reject while the gate is
	// engaged; the counter is preserved (validate_ref doesn't decrement) so
	// the user can retry after activating.
	//
	// Fail closed on transient settings-adapter errors — if we cannot tell
	// whether the gate is engaged we must not silently allow the password set.
	match app.settings.get(tn_id, "ui.onboarding").await {
		Ok(Some(SettingValue::String(ref s))) if s == "verify-idp" => {
			return Err(Error::ValidationError(
				"Identity is not yet activated. Please click the activation link \
				 in your identity-provider email first."
					.into(),
			));
		}
		Ok(Some(_) | None) => {}
		Err(e) => {
			warn!(error = %e, ?tn_id, "Failed to read ui.onboarding gate; rejecting set-password");
			return Err(Error::ValidationError(
				"Unable to verify identity activation status, please try again".into(),
			));
		}
	}

	info!(
		tn_id = ?tn_id,
		id_tag = %id_tag,
		ref_id = %req.ref_id,
		"Setting password via reference"
	);

	// Consume the ref now that we're committed to the success path — but ONLY
	// for `password` (reset) refs, which must stay strictly single-use. A
	// `welcome` ref is deliberately left intact here so the reversible
	// onboarding wizard can re-enter the flow from the same link (resume on
	// reopen) and commit only at the end. The welcome ref is consumed later by
	// the authenticated POST /api/onboarding/complete endpoint. Re-posting here
	// with a still-valid welcome ref simply re-sets the password (idempotent).
	if &*ref_data.r#type == PASSWORD_REF_TYPE {
		app.meta_adapter.use_ref(&req.ref_id, &[PASSWORD_REF_TYPE]).await.map_err(|e| {
			warn!("Failed to use ref {}: {}", req.ref_id, e);
			match e {
				Error::NotFound => Error::ValidationError("Invalid or expired reference".into()),
				Error::ValidationError(_) => e,
				_ => Error::ValidationError("Invalid reference".into()),
			}
		})?;
	}

	// Update the password
	app.auth_adapter.update_tenant_password(&id_tag, &req.new_password).await?;

	info!(
		tn_id = ?tn_id,
		id_tag = %id_tag,
		"Password set successfully, generating login token"
	);

	// Create a login token for the user. `id_tag == host_id_tag` is enforced by
	// the guard above, so the auth adapter's host binding cannot fail here.
	let auth = app.auth_adapter.create_tenant_login(&id_tag, &host_id_tag).await?;

	// Return login info using the existing return_login helper
	let (_status, Json(login_data)) = return_login(&app, auth).await?;
	let response = ApiResponse::new(login_data).with_req_id(req_id.unwrap_or_default());

	Ok((StatusCode::OK, Json(response)))
}

/// # POST /api/onboarding/complete
/// Finish the reversible onboarding wizard.
///
/// `post_set_password` deliberately leaves the `welcome` ref intact so the user
/// can re-enter the flow from the welcome link (resume on reopen) until they
/// commit. This authenticated endpoint is the single commit point: it validates
/// that `refId` is a `welcome` ref belonging to the caller's own tenant and then
/// consumes it, retiring the link. Clearing the `ui.onboarding` gate is done by
/// the frontend via `settings.update` to avoid a double-clear race.
///
/// Idempotent for the client: if the ref is already consumed (e.g. a retried
/// Finish) the lookup fails and we return success rather than an error, since
/// "already complete" is the desired end state.
#[derive(Deserialize)]
pub struct CompleteOnboardingReq {
	#[serde(rename = "refId")]
	ref_id: String,
}

pub async fn post_complete_onboarding(
	State(app): State<App>,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<CompleteOnboardingReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	// Validate the ref is a welcome ref and belongs to the caller. We validate
	// first (non-destructive) so an unrelated/already-consumed ref can't be
	// used to tamper, and so we can treat "already gone" as success below.
	match app.meta_adapter.validate_ref(&req.ref_id, &[WELCOME_REF_TYPE]).await {
		Ok((tn_id, _id_tag, _ref_data)) => {
			if tn_id != auth.tn_id {
				warn!(
					caller = %auth.id_tag,
					ref_id = %req.ref_id,
					"complete-onboarding: welcome ref belongs to a different tenant"
				);
				return Err(Error::PermissionDenied);
			}
			// Consume the welcome ref, retiring the onboarding link.
			if let Err(e) = app.meta_adapter.use_ref(&req.ref_id, &[WELCOME_REF_TYPE]).await {
				warn!("complete-onboarding: failed to consume welcome ref {}: {}", req.ref_id, e);
			} else {
				info!(id_tag = %auth.id_tag, ref_id = %req.ref_id, "Onboarding completed");
			}
		}
		Err(Error::NotFound | Error::ValidationError(_)) => {
			// Ref already consumed/expired — onboarding is effectively complete.
			info!(
				id_tag = %auth.id_tag,
				ref_id = %req.ref_id,
				"complete-onboarding: welcome ref already retired; treating as complete"
			);
		}
		Err(e) => return Err(e),
	}

	let response = ApiResponse::new(()).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

/// # POST /api/auth/forgot-password
/// Request a password reset email (user-initiated)
/// Always returns success to prevent email enumeration
#[derive(Deserialize)]
pub struct ForgotPasswordReq {
	email: String,
}

#[derive(Serialize)]
pub struct ForgotPasswordRes {
	message: String,
}

pub async fn post_forgot_password(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	OptionalRequestId(req_id): OptionalRequestId,
	id_tag_ext: Option<IdTag>,
	Json(req): Json<ForgotPasswordReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<ForgotPasswordRes>>)> {
	let email = req.email.trim().to_lowercase();

	info!(email = %email, ip = %addr.ip(), "Password reset requested");

	// Success response (always returned for security)
	let success_response = || {
		ApiResponse::new(ForgotPasswordRes {
			message: "If an account with this email exists, a password reset link has been sent."
				.to_string(),
		})
		.with_req_id(req_id.clone().unwrap_or_default())
	};

	// Basic email validation
	if !email.contains('@') || email.len() < 5 {
		return Ok((StatusCode::OK, Json(success_response())));
	}

	// Scope lookup to the current Host's tenant so that when the same email is
	// registered against multiple tenants we only match the one the user is on.
	let Some(IdTag(host_id_tag)) = id_tag_ext else {
		info!(email = %email, "No Host/IdTag on request; returning silent success");
		return Ok((StatusCode::OK, Json(success_response())));
	};

	let auth_opts =
		ListTenantsOptions { status: None, q: Some(&host_id_tag), limit: Some(10), offset: None };
	let tenants = match app.auth_adapter.list_tenants(&auth_opts).await {
		Ok(t) => t,
		Err(e) => {
			warn!(id_tag = %host_id_tag, error = ?e, "Failed to look up tenant by id_tag");
			return Ok((StatusCode::OK, Json(success_response())));
		}
	};

	// Pick exact id_tag match, then verify email matches the submitted email.
	let tenant = tenants.into_iter().find(|t| {
		t.id_tag.as_ref() == host_id_tag.as_ref() && t.email.as_deref() == Some(email.as_str())
	});

	let Some(tenant) = tenant else {
		info!(id_tag = %host_id_tag, "Host tenant has no matching email (not revealing)");
		return Ok((StatusCode::OK, Json(success_response())));
	};

	let tn_id = tenant.tn_id;
	let id_tag = tenant.id_tag.to_string();

	// Rate limiting: check recent password reset refs for this tenant
	// Allow max 3 per hour, 5 per day
	let opts = ListRefsOptions {
		typ: Some(PASSWORD_REF_TYPE.to_string()),
		filter: Some("all".to_string()),
		resource_id: None,
	};
	let recent_refs = app.meta_adapter.list_refs(tn_id, &opts).await.unwrap_or_default();

	let now = Timestamp::now().0;
	let one_hour_ago = now - 3600;
	let one_day_ago = now - 86400;

	let hourly_count = recent_refs.iter().filter(|r| r.created_at.0 > one_hour_ago).count();
	let daily_count = recent_refs.iter().filter(|r| r.created_at.0 > one_day_ago).count();

	if hourly_count >= 3 {
		info!(tn_id = ?tn_id, id_tag = %id_tag, "Password reset rate limited (hourly)");
		return Ok((StatusCode::OK, Json(success_response())));
	}

	if daily_count >= 5 {
		info!(tn_id = ?tn_id, id_tag = %id_tag, "Password reset rate limited (daily)");
		return Ok((StatusCode::OK, Json(success_response())));
	}

	// Get tenant meta data for the name
	let user_name = app
		.meta_adapter
		.read_tenant(tn_id)
		.await
		.map_or_else(|_| id_tag.clone(), |t| t.name.to_string());

	// Create password reset ref
	let expires_at = Some(Timestamp(now + 86400)); // 24 hours
	let (ref_id, reset_url) = match create_ref_internal(
		&app,
		tn_id,
		CreateRefInternalParams {
			id_tag: &id_tag,
			typ: PASSWORD_REF_TYPE,
			description: Some("User-initiated password reset"),
			expires_at,
			path_prefix: "/reset-password",
			..Default::default()
		},
	)
	.await
	{
		Ok(result) => result,
		Err(e) => {
			warn!(tn_id = ?tn_id, id_tag = %id_tag, error = ?e, "Failed to create password reset ref");
			return Ok((StatusCode::OK, Json(success_response())));
		}
	};

	// Get tenant's preferred language
	let lang = get_tenant_lang(&app.settings, tn_id).await;

	// A password reset is for the user's own account, so the email is branded with
	// the user's id_tag (subject prefix + sender name), not the node's base tenant.
	let email_params = EmailTaskParams {
		to: email.clone(),
		subject: None,
		template_name: "password_reset".to_string(),
		template_vars: serde_json::json!({
			"identity_tag": user_name,
			"idTag": id_tag,
			"instance_name": "Cloudillo",
			"reset_link": reset_url,
			"expire_hours": 24,
		}),
		lang,
		custom_key: Some(format!("pw-reset:{}:{}", tn_id.0, now)),
		from_name_override: Some(format!("Cloudillo | {}", id_tag.to_uppercase())),
		delay_seconds: None,
		notify_guard: None,
	};

	if let Err(e) =
		EmailModule::schedule_email_task(&app.scheduler, &app.settings, tn_id, email_params).await
	{
		warn!(tn_id = ?tn_id, id_tag = %id_tag, error = ?e, "Failed to schedule password reset email");
		// Still return success to not reveal anything
	} else {
		info!(
			tn_id = ?tn_id,
			id_tag = %id_tag,
			ref_id = %ref_id,
			"Password reset email scheduled"
		);
	}

	Ok((StatusCode::OK, Json(success_response())))
}

// ============================================================================
// POST /api/auth/login-init — Combined login initialization endpoint
// ============================================================================

#[derive(Serialize)]
#[serde(tag = "status")]
pub enum LoginInitResponse {
	#[serde(rename = "authenticated")]
	Authenticated { login: Login },
	#[serde(rename = "unauthenticated")]
	Unauthenticated {
		#[serde(rename = "qrLogin")]
		qr_login: crate::qr_login::InitResponse,
		#[serde(rename = "webAuthn")]
		web_authn: bool,
		#[serde(rename = "maskedEmail", skip_serializing_if = "Option::is_none")]
		masked_email: Option<String>,
	},
}

pub async fn post_login_init(
	State(app): State<App>,
	OptionalAuth(auth): OptionalAuth,
	tn_id: TnId,
	id_tag: IdTag,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	OptionalRequestId(req_id): OptionalRequestId,
	headers: HeaderMap,
) -> ClResult<(StatusCode, Json<ApiResponse<LoginInitResponse>>)> {
	if let Some(auth) = auth {
		// Same delegated-credential rejection as `get_login_token`.
		if auth.scope.is_some() {
			warn!(subject = %auth.id_tag, "login-init denied - delegated token");
			return Err(Error::PermissionDenied);
		}
		// Authenticated path: create fresh login token (replaces login-token)
		info!("login-init for authenticated user {}", &auth.id_tag);
		// A host-binding miss is not a routine "no account here" — see `get_login_token`.
		// This route sits in `recovery()`, where the IP ban is deliberately skipped, so it
		// must not be the softer sibling: deny, and pay the same delay.
		match app.auth_adapter.create_tenant_login(&auth.id_tag, &id_tag.0).await {
			Ok(auth_login) => {
				let (_status, Json(login_data)) = return_login(&app, auth_login).await?;
				let response =
					ApiResponse::new(LoginInitResponse::Authenticated { login: login_data })
						.with_req_id(req_id.unwrap_or_default());
				Ok((StatusCode::OK, Json(response)))
			}
			Err(e) => {
				warn!(subject = %auth.id_tag, host = %id_tag.0, error = %e, "login-init denied");
				tokio::time::sleep(std::time::Duration::from_secs(1)).await;
				Err(Error::PermissionDenied)
			}
		}
	} else {
		// Unauthenticated path: QR init data + a "passkeys exist" flag (the challenge
		// itself is minted at prompt time) + masked email for forgot-password
		debug!("login-init for unauthenticated user");
		let qr_result = crate::qr_login::create_session(&app, tn_id, &addr, &headers)?;
		let wa_result = crate::webauthn::has_passkeys(&app, tn_id).await;

		let masked_email = match app.auth_adapter.read_tenant(&id_tag.0).await {
			Ok(profile) => profile.email.as_deref().and_then(cloudillo_types::utils::mask_email),
			Err(_) => None,
		};

		let response = ApiResponse::new(LoginInitResponse::Unauthenticated {
			qr_login: qr_result,
			web_authn: wa_result,
			masked_email,
		})
		.with_req_id(req_id.unwrap_or_default());
		Ok((StatusCode::OK, Json(response)))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn auth_ctx(anonymous: bool, scope: Option<&str>) -> auth_adapter::AuthCtx {
		auth_adapter::AuthCtx {
			tn_id: TnId(1),
			id_tag: "alice.example.com".into(),
			roles: Box::default(),
			scope: scope.map(Box::from),
			anonymous,
			hat: None,
			exp: None,
		}
	}

	#[test]
	fn a_re_read_never_upgrades_a_credential_that_carries_no_roles() {
		// `middleware.rs` builds an `idp_` API key's `AuthCtx` with an empty role set on
		// purpose; without the intersection the tenant branch would mint it a full owner.
		assert_eq!(narrow_to_presented(Some("leader,moderator".into()), &[]), Some(String::new()));
	}

	#[test]
	fn a_re_read_keeps_the_roles_a_session_legitimately_holds() {
		let presented: Vec<Box<str>> = vec!["leader".into(), "moderator".into()];
		assert_eq!(
			narrow_to_presented(Some("leader,moderator".into()), &presented),
			Some("leader,moderator".into())
		);
	}

	#[test]
	fn a_re_read_drops_roles_the_presented_set_never_had() {
		let presented: Vec<Box<str>> = vec!["moderator".into()];
		assert_eq!(
			narrow_to_presented(Some("leader,moderator".into()), &presented),
			Some("moderator".into())
		);
	}

	#[test]
	fn derived_sub_keeps_a_session_callers_identity() {
		assert_eq!(derived_sub(&auth_ctx(false, None)), Some("alice.example.com"));
	}

	#[test]
	fn derived_sub_keeps_a_scoped_signed_in_callers_identity() {
		// Keying on `scope` instead would demote a signed-in user following a second
		// `?via=` hop to a nameless guest — no awareness idTag, an `anon:` RTDB lock
		// owner, no `file_user_data` row.
		assert_eq!(derived_sub(&auth_ctx(false, Some("file:f1~abc:W"))), Some("alice.example.com"));
	}

	#[test]
	fn derived_sub_asserts_nothing_for_an_anonymous_caller() {
		// A share-link visitor's `id_tag` is the tenant owner by `iss` fallback —
		// there is no person to name.
		assert_eq!(derived_sub(&auth_ctx(true, Some("file:f1~abc:R"))), None);
	}

	/// Only PROXY, and only with a near expiry. Every other action type is handed to third
	/// parties by design, so accepting one here makes it a bearer credential.
	#[test]
	fn only_a_short_lived_proxy_token_is_exchangeable() {
		let max = 1_000;
		assert!(proxy_exchange_allowed("PROXY", Some(940), max));
		assert!(proxy_exchange_allowed("PROXY", Some(max), max), "the boundary is inclusive");

		assert!(!proxy_exchange_allowed("PROXY", None, max), "a missing exp never expires");
		assert!(!proxy_exchange_allowed("PROXY", Some(max + 1), max), "too distant");
		// The types a third party can legitimately hold.
		for typ in ["POST", "APRV", "CONN", "STAT", ""] {
			assert!(!proxy_exchange_allowed(typ, Some(940), max), "{typ} must not be exchangeable");
		}
	}

	const NOW: i64 = 1_000;

	fn proxy() -> ActionToken {
		ActionToken { iss: "alice.example".into(), t: "PROXY".into(), ..Default::default() }
	}

	fn endorsement() -> ActionToken {
		ActionToken {
			iss: "a.example".into(),
			t: "APRV".into(),
			aud: Some("b.example".into()),
			sub: Some("@alice.example".into()),
			c: Some(json!({ "r": "contributor" })),
			exp: Some(Timestamp(NOW + 60)),
			..Default::default()
		}
	}

	const PEER: Option<(ProfileType, bool, Option<&str>)> =
		Some((ProfileType::Community, true, Some("contributor:supporter")));

	fn check(
		e: &ActionToken,
		peer: Option<(ProfileType, bool, Option<&str>)>,
	) -> ClResult<Box<str>> {
		check_session_hat(&proxy(), e, "b.example", NOW, peer)
	}

	#[test]
	fn a_valid_hat_endorsement_maps_the_role() {
		assert_eq!(check(&endorsement(), PEER).ok().as_deref(), Some("supporter"));
	}

	/// Session-plane rejections, each on its own.
	#[test]
	fn session_hat_rejections() {
		let denied = |e: ActionToken, peer| matches!(check(&e, peer), Err(Error::PermissionDenied));
		let e = endorsement;

		assert!(
			denied(ActionToken { sub: Some("@mallory.example".into()), ..e() }, PEER),
			"wrong member"
		);
		assert!(denied(ActionToken { aud: Some("c.example".into()), ..e() }, PEER), "wrong aud");
		assert!(denied(ActionToken { t: "POST".into(), ..e() }, PEER), "not an APRV");
		assert!(denied(ActionToken { exp: Some(Timestamp(NOW - 1)), ..e() }, PEER), "expired");
		assert!(denied(ActionToken { exp: None, ..e() }, PEER), "missing exp");
		let far = Some(Timestamp(NOW + PROXY_TOKEN_MAX_LIFETIME + 1));
		assert!(denied(ActionToken { exp: far, ..e() }, PEER), "exp too distant");
		assert!(
			denied(ActionToken { c: Some(json!({ "r": "king" })), ..e() }, PEER),
			"unknown role"
		);
		assert!(denied(ActionToken { c: Some(json!("contributor")), ..e() }, PEER), "no c.r");

		assert!(denied(e(), None), "no peer profile");
		assert!(denied(e(), Some((ProfileType::Community, true, None))), "NULL map");
		assert!(
			denied(e(), Some((ProfileType::Community, false, Some("contributor:supporter")))),
			"not connected"
		);
		assert!(
			denied(e(), Some((ProfileType::Person, true, Some("contributor:supporter")))),
			"not a community"
		);
		assert!(
			denied(e(), Some((ProfileType::Community, true, Some("moderator:supporter")))),
			"unmapped"
		);
		assert!(
			denied(e(), Some((ProfileType::Community, true, Some("contributor:leader")))),
			"a hand-edited leader target is refused on read"
		);
	}

	/// A hatted session mints a `file:` scope only, capped at the parent token's expiry.
	#[test]
	fn hatted_scope_mint_is_file_only_and_capped() {
		let now = Timestamp(NOW);
		let file = Some("file:f1~abc:R");
		let parent = |d| Some(Timestamp(NOW + d));

		let exp = |p, s| hatted_scope_exp(p, s, now).map(|t| t.0);
		assert_eq!(exp(parent(10), file).ok(), Some(NOW + 10), "capped at parent exp");
		assert_eq!(
			exp(parent(ACCESS_TOKEN_EXPIRY * 2), file).ok(),
			Some(NOW + ACCESS_TOKEN_EXPIRY),
			"capped at the access-token TTL"
		);

		let unauthorized = |p, s| matches!(exp(p, s), Err(Error::Unauthorized));
		assert!(unauthorized(parent(10), None), "param-less refresh");
		assert!(unauthorized(parent(10), Some("apkg:publish")), "non-file scope");
		assert!(unauthorized(parent(10), Some("dav:rw")), "DAV scope");
		assert!(unauthorized(None, file), "no parent exp fails closed");
	}

	#[test]
	fn endorse_peer_checks() {
		const C: ProfileType = ProfileType::Community;
		let denied = |r: ClResult<()>| matches!(r, Err(Error::PermissionDenied));
		assert!(denied(check_endorse_peer(None, "contributor")), "no profile");
		let person = Some((ProfileType::Person, true, None));
		assert!(denied(check_endorse_peer(person, "contributor")), "a person");
		assert!(denied(check_endorse_peer(Some((C, false, None)), "contributor")), "unusable");
		let skips = Some((C, true, Some("moderator:contributor")));
		assert!(matches!(check_endorse_peer(skips, "contributor"), Err(Error::NotFound)));
		let maps = Some((C, true, Some("contributor:supporter")));
		assert!(check_endorse_peer(maps, "contributor").is_ok());
		assert!(check_endorse_peer(maps, "leader").is_ok(), "falls back to a lower mapped role");
		assert!(check_endorse_peer(Some((C, true, None)), "contributor").is_ok(), "no map");
		let invalid = Some((C, true, Some("contributor:leader")));
		assert!(check_endorse_peer(invalid, "moderator").is_ok(), "invalid map: the peer decides");
	}

	#[test]
	fn hat_rides_only_on_a_bare_proxy_exchange() {
		let q = |token: bool, scope: bool| GetAccessTokenQuery {
			token: token.then(|| "t".into()),
			scope: scope.then(|| "file:f1~x:R".into()),
			ref_id: None,
			api_key: None,
			refresh: None,
			via: None,
			hat: Some("h".into()),
		};
		assert!(hat_params_valid(&q(true, false)));
		assert!(!hat_params_valid(&q(true, true)), "hat with scope");
		assert!(!hat_params_valid(&q(false, false)), "hat without token");
	}

	/// The DAV capability families are not `TokenScope` values, so `validated_scope` would
	/// otherwise 400 them. They only ever narrow a session, so they pass through — but
	/// nothing else does, or the fail-closed mint is back to stamping arbitrary strings.
	#[test]
	fn only_known_dav_capability_scopes_pass_through() {
		assert_eq!(normalized_dav_scope("carddav:read").as_deref(), Some("carddav:read"));
		assert_eq!(
			normalized_dav_scope("carddav:read,caldav:write").as_deref(),
			Some("carddav:read,caldav:write")
		);
		assert_eq!(
			normalized_dav_scope("carddav:read, caldav:write").as_deref(),
			Some("carddav:read,caldav:write"),
			"`, ` separators are tolerated like scope::has_scope does"
		);

		assert_eq!(normalized_dav_scope("carddav:reader"), None);
		assert_eq!(normalized_dav_scope("carddav"), None);
		assert_eq!(normalized_dav_scope(""), None);
		assert_eq!(normalized_dav_scope("carddav:read,bogus"), None, "one bad entry sinks it");
	}
}

// vim: ts=4
