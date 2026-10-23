// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Adapter that manages and stores authentication, authorization and other sensitive data.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::fmt::Debug;

use std::collections::HashMap;

use crate::{
	action_types,
	prelude::*,
	types::{serialize_timestamp_iso, serialize_timestamp_iso_opt},
};

pub const ACCESS_TOKEN_EXPIRY: i64 = 3600;

/// Action tokens represent federated user actions as signed JWTs (ES384/P-384).
///
/// Actions are content-addressed: `action_id = "a1~" + SHA256(token)`.
/// Field names are short (JWT claims) to minimize token size.
#[skip_serializing_none]
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ActionToken {
	/// Issuer - id_tag of the action creator (e.g., "alice.example.com")
	pub iss: Box<str>,

	/// Key ID - identifier of the signing key used (for key rotation support)
	pub k: Box<str>,

	/// Type - action type with optional subtype (e.g., "POST", "REACT:LIKE", "CONN:DEL")
	pub t: Box<str>,

	/// Content - action-specific payload as JSON.
	pub c: Option<serde_json::Value>,

	/// Parent - action_id of parent action for TRUE HIERARCHY (threading).
	pub p: Option<Box<str>>,

	/// Attachments - array of file IDs (content-addressed, e.g., "f1~abc123...")
	pub a: Option<Vec<Box<str>>>,

	/// Audience - id_tag of the target recipient.
	pub aud: Option<Box<str>>,

	/// Subject - action_id or resource_id being referenced WITHOUT creating hierarchy.
	pub sub: Option<Box<str>>,

	/// Issued At - Unix timestamp of action creation
	pub iat: Timestamp,

	/// Expires At - optional Unix timestamp for action expiration
	pub exp: Option<Timestamp>,

	/// Flags - capability flags for this action
	pub f: Option<Box<str>>,

	/// Visibility - P=Public, V=Verified, 2=2ndDegree, F=Follower, C=Connected, None=Direct
	pub v: Option<char>,

	/// Hat - id_tag of the community whose role the issuer acts in (relayed and endorsed by it).
	pub h: Option<Box<str>>,

	/// Channel - absolute `@tenant~name` of the room the action belongs to.
	pub ch: Option<Box<str>>,

	/// Nonce - Proof-of-work nonce for rate limiting (CONN actions only).
	#[serde(rename = "_", default, skip_serializing_if = "Option::is_none")]
	pub nonce: Option<Box<str>>,
}

/// Access tokens are used to authenticate users
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccessToken<S> {
	pub iss: S,
	pub sub: Option<S>,
	pub scope: Option<S>,
	pub r: Option<S>,
	/// Hat - id_tag of the peer community whose mapped role `r` holds (hatted session).
	pub h: Option<S>,
	pub exp: Timestamp,
	/// Time of the interactive login this session descends from (unix seconds). Renewals
	/// copy it unchanged, so `auth.session_timeout` bounds the session's absolute lifetime.
	/// Tokens issued before this claim existed lack it; read them as
	/// `exp - ACCESS_TOKEN_EXPIRY` (see `AccessToken::auth_time_or_fallback`).
	pub auth_time: Option<Timestamp>,
}

impl<S> AccessToken<S> {
	/// `auth_time`, or `exp - ACCESS_TOKEN_EXPIRY` for a token minted before the claim existed.
	pub fn auth_time_or_fallback(&self) -> Timestamp {
		self.auth_time.unwrap_or(self.exp.add_seconds(-ACCESS_TOKEN_EXPIRY))
	}
}

/// Represents a profile key
#[skip_serializing_none]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthKey {
	#[serde(rename = "keyId")]
	pub key_id: Box<str>,
	#[serde(rename = "publicKey")]
	pub public_key: Box<str>,
	#[serde(rename = "expiresAt", serialize_with = "serialize_timestamp_iso_opt")]
	pub expires_at: Option<Timestamp>,
}

/// A profile signing key as the owner sees it (`GET /api/auth/keys`); never public.
///
/// `status`: `'A'` active (signs; legacy NULL rows read as `'A'`), `'V'` verify-only
/// (published, no longer signs), `'R'` revoked (not published).
#[skip_serializing_none]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyInfo {
	pub key_id: Box<str>,
	pub status: char,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
	#[serde(serialize_with = "serialize_timestamp_iso_opt")]
	pub expires_at: Option<Timestamp>,
}

/// Represents an auth profile.
///
/// Adapter-internal: not serialized to clients (handlers project this into
/// separate wire types). The `Serialize`/`Deserialize` derives are kept for
/// adapter ergonomics only, so adding `tn_id` does not change any wire shape.
#[skip_serializing_none]
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthProfile {
	pub tn_id: TnId,
	pub id_tag: Box<str>,
	pub email: Option<Box<str>>,
	pub roles: Option<Box<[Box<str>]>>,
	/// Tenant status — typically `'A'` (Active) or `'S'` (Suspended).
	pub status: Option<Box<str>>,
	#[serde(skip)]
	pub suspended_at: Option<Timestamp>,
	#[serde(skip)]
	pub expires_at: Option<Timestamp>,
	pub keys: Vec<AuthKey>,
}

/// False for tenants that may not authenticate: soft-deleted (status='X' = purging in progress),
/// suspended by an admin (`suspended_at` set) or past their `expires_at`.
pub fn tenant_active(
	status: Option<&str>,
	suspended_at: Option<i64>,
	expires_at: Option<i64>,
) -> bool {
	!(status == Some("X")
		|| suspended_at.is_some()
		|| expires_at.is_some_and(|exp| exp <= Timestamp::now().0))
}

/// Context struct for an authenticated user
#[derive(Clone, Debug)]
pub struct AuthCtx {
	pub tn_id: TnId,
	pub id_tag: Box<str>,
	pub roles: Box<[Box<str>]>,
	pub scope: Option<Box<str>>,
	/// True when the credential carries no `sub` claim, so `id_tag` came from
	/// `iss` and names the *tenant*, not a person — an anonymous share-link
	/// token. Anything that asserts an identity on the holder's behalf (CRDT
	/// awareness stamping, activity attribution) must treat this as "no
	/// identity to assert". Scope checks must NOT read this: a share link's
	/// authority comes from `scope`, and that is unchanged. An owner session is
	/// sub-less too, so owner-only rungs use [`AuthCtx::names_holder`], not this.
	pub anonymous: bool,
	/// Peer community this session wears as a hat (token claim `h`). Attribution and refresh
	/// gating only: `roles` already holds the mapped roles. Not a delegated credential, so it
	/// is never treated like `scope`.
	pub hat: Option<Box<str>>,
	/// Expiry of the presented access token; `None` for credentials that are not one (API keys,
	/// DAV passwords, synthetic contexts). Caps the hatted `file:` scope mint.
	pub exp: Option<Timestamp>,
	/// When the session behind the credential began (access token `auth_time`, or a `cl_`
	/// key's original login). `None` for synthetic contexts; session-age checks treat that
	/// as epoch, i.e. stale.
	pub auth_time: Option<Timestamp>,
}

impl AuthCtx {
	/// Whether `id_tag` names the credential's holder, for owner-only rungs that match it
	/// (pending uploads). False only for a sub-less *scoped* token (share link, via-embed),
	/// whose `id_tag` is the tenant's. An owner session is sub-less but unscoped: the tenant
	/// is its holder.
	pub fn names_holder(&self) -> bool {
		!(self.anonymous && self.scope.is_some())
	}
}

#[derive(Debug)]
pub struct AuthLogin {
	pub tn_id: TnId,
	pub id_tag: Box<str>,
	pub roles: Option<Box<[Box<str>]>>,
	pub token: Box<str>,
}

/// A private/public key pair
#[derive(Debug)]
pub struct KeyPair {
	pub private_key: Box<str>,
	pub public_key: Box<str>,
}

#[derive(Debug)]
pub struct Webauthn {
	pub credential_id: Box<str>,
	pub counter: u32,
	pub public_key: Box<str>,
	pub description: Option<Box<str>>,
}

/// Data needed to create a new tenant
#[derive(Debug)]
pub struct CreateTenantData<'a> {
	pub vfy_code: Option<&'a str>,
	pub email: Option<&'a str>,
	pub password: Option<&'a str>,
	pub roles: Option<&'a [&'a str]>,
}

/// Tenant list item from auth adapter
#[skip_serializing_none]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantListItem {
	pub tn_id: TnId,
	pub id_tag: Box<str>,
	pub email: Option<Box<str>>,
	pub roles: Option<Box<[Box<str>]>>,
	pub status: Option<Box<str>>,
	/// Set while an admin has suspended the tenant (login refused)
	#[serde(serialize_with = "serialize_timestamp_iso_opt")]
	pub suspended_at: Option<Timestamp>,
	/// Account expiry; login refused once reached
	#[serde(serialize_with = "serialize_timestamp_iso_opt")]
	pub expires_at: Option<Timestamp>,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
}

/// Options for listing tenants
#[derive(Debug, Default)]
pub struct ListTenantsOptions<'a> {
	pub status: Option<&'a str>,
	pub q: Option<&'a str>,
	pub limit: Option<u32>,
	pub offset: Option<u32>,
}

/// Audit trail category. `Auth` and `Admin` are always recorded; `Sharing` and `Access`
/// only when enabled in `audit.categories` ∪ `audit.tenant_categories`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditCategory {
	Auth,
	Admin,
	Sharing,
	Access,
}

impl AuditCategory {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Auth => "auth",
			Self::Admin => "admin",
			Self::Sharing => "sharing",
			Self::Access => "access",
		}
	}

	pub fn parse(s: &str) -> Option<Self> {
		match s {
			"auth" => Some(Self::Auth),
			"admin" => Some(Self::Admin),
			"sharing" => Some(Self::Sharing),
			"access" => Some(Self::Access),
			_ => None,
		}
	}
}

/// One audit trail entry. `tn_id = None` is a server-wide event (SADM-only).
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub ts: Timestamp,
	pub tn_id: Option<TnId>,
	pub actor: Option<Box<str>>,
	pub event: Box<str>,
	pub category: AuditCategory,
	pub ip: Option<Box<str>>,
	/// `"success"` or `"fail"`.
	pub outcome: Box<str>,
	pub details: Option<serde_json::Value>,
}

impl AuditEvent {
	/// Event stamped now, with every optional field empty. Fill the rest with struct update
	/// syntax: `AuditEvent { tn_id: Some(tn_id), ..AuditEvent::new(cat, "x.y", "success") }`.
	/// `outcome` is `"success"` or `"fail"`.
	pub fn new(category: AuditCategory, event: &str, outcome: &str) -> Self {
		Self {
			ts: Timestamp::now(),
			tn_id: None,
			actor: None,
			event: event.into(),
			category,
			ip: None,
			outcome: outcome.into(),
			details: None,
		}
	}
}

/// Stored audit entry: the event plus its row id (the paging cursor).
#[derive(Debug, Clone, Serialize)]
pub struct AuditEventRow {
	pub id: i64,
	#[serde(flatten)]
	pub event: AuditEvent,
}

/// Filters for listing audit events. Every `None` is "no filter"; `tn_id: None` includes
/// server-wide rows. Results are newest first; `cursor` returns rows with `id < cursor`.
/// `from`/`to` are inclusive. `event_prefix` matches by plain string prefix.
#[derive(Debug, Default, Clone)]
pub struct AuditQuery {
	pub tn_id: Option<TnId>,
	pub from: Option<Timestamp>,
	pub to: Option<Timestamp>,
	pub category: Option<AuditCategory>,
	pub event_prefix: Option<Box<str>>,
	pub actor: Option<Box<str>>,
	pub outcome: Option<Box<str>>,
	pub limit: Option<u32>,
	pub cursor: Option<i64>,
}

/// Certificate associated with a tenant
#[derive(Debug)]
pub struct CertData {
	pub tn_id: TnId,
	pub id_tag: Box<str>,
	pub domain: Box<str>,
	pub cert: Box<str>,
	pub key: Box<str>,
	pub expires_at: Timestamp,
	pub last_renewal_attempt_at: Option<Timestamp>,
	pub last_renewal_error: Option<Box<str>>,
	pub failure_count: u32,
	pub notified_at: Option<Timestamp>,
}

/// Row returned by `list_tenants_needing_cert_renewal`. Includes failure-tracking
/// state so the renewal task can decide on notifications and tenant suspension
/// without an extra read per tenant.
#[derive(Debug)]
pub struct TenantCertRenewalRow {
	pub tn_id: TnId,
	pub id_tag: Box<str>,
	/// `None` ⇒ tenant has no cert yet (initial bootstrap)
	pub expires_at: Option<Timestamp>,
	pub failure_count: u32,
	pub last_renewal_error: Option<Box<str>>,
	pub notified_at: Option<Timestamp>,
}

/// API key information (without the secret key)
#[skip_serializing_none]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyInfo {
	pub key_id: i64,
	pub key_prefix: Box<str>,
	pub name: Option<Box<str>>,
	pub scopes: Option<Box<str>>,
	#[serde(serialize_with = "serialize_timestamp_iso_opt")]
	pub expires_at: Option<Timestamp>,
	#[serde(serialize_with = "serialize_timestamp_iso_opt")]
	pub last_used_at: Option<Timestamp>,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
}

/// Options for creating an API key
#[derive(Debug)]
pub struct CreateApiKeyOptions<'a> {
	pub name: Option<&'a str>,
	pub scopes: Option<&'a str>,
	pub expires_at: Option<Timestamp>,
	/// Login time of the session that created the key, carried into sessions it mints
	pub auth_time: Option<Timestamp>,
}

/// Result of creating an API key (includes plaintext key shown only once)
#[derive(Debug)]
pub struct CreatedApiKey {
	pub info: ApiKeyInfo,
	pub plaintext_key: Box<str>,
}

/// Result of validating an API key
#[derive(Debug)]
pub struct ApiKeyValidation {
	pub tn_id: TnId,
	pub id_tag: Box<str>,
	pub key_id: i64,
	pub scopes: Option<Box<str>>,
	pub roles: Option<Box<str>>,
	/// Scoped key: original login time behind it (`created_at` for keys without one).
	/// Unscoped key: now — each use counts as a fresh login, bounded by `auth.remember_days`.
	pub auth_time: Option<Timestamp>,
}

// Proxy site types
// =================

/// Configuration for a proxy site (stored as JSON in the config column)
#[skip_serializing_none]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxySiteConfig {
	pub connect_timeout_secs: Option<u32>,
	pub read_timeout_secs: Option<u32>,
	pub preserve_host: Option<bool>,
	pub proxy_protocol: Option<bool>,
	pub custom_headers: Option<HashMap<String, String>>,
	pub forward_headers: Option<bool>,
	pub websocket: Option<bool>,
}

/// Proxy site data from the database
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxySiteData {
	pub site_id: i64,
	pub domain: Box<str>,
	pub backend_url: Box<str>,
	pub status: Box<str>,
	#[serde(rename = "type")]
	pub proxy_type: Box<str>,
	#[serde(skip_serializing)]
	pub cert: Option<Box<str>>,
	#[serde(skip_serializing)]
	pub cert_key: Option<Box<str>>,
	#[serde(serialize_with = "serialize_timestamp_iso_opt")]
	pub cert_expires_at: Option<Timestamp>,
	pub config: ProxySiteConfig,
	pub created_by: Option<i64>,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub created_at: Timestamp,
	#[serde(serialize_with = "serialize_timestamp_iso")]
	pub updated_at: Timestamp,
}

/// Data needed to create a new proxy site
#[derive(Debug)]
pub struct CreateProxySiteData<'a> {
	pub domain: &'a str,
	pub backend_url: &'a str,
	pub proxy_type: &'a str,
	pub config: &'a ProxySiteConfig,
	pub created_by: Option<i64>,
}

/// Data to update an existing proxy site
#[derive(Debug)]
pub struct UpdateProxySiteData<'a> {
	pub backend_url: Option<&'a str>,
	pub status: Option<&'a str>,
	pub proxy_type: Option<&'a str>,
	pub config: Option<&'a ProxySiteConfig>,
}

/// A `Cloudillo` auth adapter
///
/// Every `AuthAdapter` implementation is required to implement this trait.
/// An `AuthAdapter` is responsible for storing and managing all sensitive data used for
/// authentication and authorization.
#[async_trait]
pub trait AuthAdapter: Debug + Send + Sync {
	/// Validates an access token and returns the user context
	async fn validate_access_token(
		&self,
		tn_id: TnId,
		id_tag: &str,
		token: &str,
	) -> ClResult<AuthCtx>;

	/// # Profiles
	/// Reads the ID tag of the given tenant, referenced by its ID
	async fn read_id_tag(&self, tn_id: TnId) -> ClResult<Box<str>>;

	/// Reads the ID  the given tenant, referenced by its ID tag
	async fn read_tn_id(&self, id_tag: &str) -> ClResult<TnId>;

	/// Reads a tenant profile
	async fn read_tenant(&self, id_tag: &str) -> ClResult<AuthProfile>;

	/// Creates a tenant registration
	async fn create_tenant_registration(&self, email: &str) -> ClResult<()>;

	/// Creates a new tenant
	async fn create_tenant(&self, id_tag: &str, data: CreateTenantData<'_>) -> ClResult<TnId>;

	/// Deletes a tenant
	async fn delete_tenant(&self, id_tag: &str) -> ClResult<()>;

	/// Lists all tenants (for admin use)
	async fn list_tenants(&self, opts: &ListTenantsOptions<'_>) -> ClResult<Vec<TenantListItem>>;

	/// Returns the total number of tenants matching the filter (ignoring limit/offset)
	async fn count_tenants(&self, opts: &ListTenantsOptions<'_>) -> ClResult<usize>;

	// Password management
	/// Mint an owner login for `id_tag`.
	///
	/// `host_id_tag` is the tenant the request arrived at (the `IdTag` extractor's
	/// value). The returned token carries the full owner role hierarchy, so `id_tag`
	/// — which reaches callers from a token's `sub`, a ref, or a WebAuthn challenge,
	/// all of which can name a *foreign* tenant — must be that same tenant.
	/// Implementations reject a mismatch.
	///
	/// `auth_time` becomes the token's `auth_time` claim: `Timestamp::now()` at an interactive
	/// login, the presenting token's value on a renewal.
	async fn create_tenant_login(
		&self,
		id_tag: &str,
		host_id_tag: &str,
		auth_time: Timestamp,
	) -> ClResult<AuthLogin>;
	async fn check_tenant_password(&self, id_tag: &str, password: &str) -> ClResult<AuthLogin>;
	async fn update_tenant_password(&self, id_tag: &str, password: &str) -> ClResult<()>;

	// IDP API key management
	async fn update_idp_api_key(&self, id_tag: &str, api_key: &str) -> ClResult<()>;

	// Certificate management
	async fn create_cert(&self, cert_data: &CertData) -> ClResult<()>;
	async fn read_cert_by_tn_id(&self, tn_id: TnId) -> ClResult<CertData>;
	async fn read_cert_by_id_tag(&self, id_tag: &str) -> ClResult<CertData>;
	async fn read_cert_by_domain(&self, domain: &str) -> ClResult<CertData>;
	/// Tenant id_tag a host names (`<id_tag>`, `cl-o.<id_tag>` or a custom app domain),
	/// without requiring a certificate. `NotFound` when no tenant matches.
	async fn read_id_tag_by_domain(&self, domain: &str) -> ClResult<Box<str>>;
	async fn list_all_certs(&self) -> ClResult<Vec<CertData>>;
	async fn list_tenants_needing_cert_renewal(
		&self,
		renewal_days: u32,
	) -> ClResult<Vec<TenantCertRenewalRow>>;

	/// Record an ACME renewal failure for the given tenant: increments
	/// `failure_count`, sets `last_renewal_error`, and stamps
	/// `last_renewal_attempt_at`. No-op if no cert row exists for the tenant.
	async fn record_cert_renewal_failure(&self, tn_id: TnId, error: &str) -> ClResult<()>;

	/// Record a successful ACME renewal: clears `last_renewal_error`,
	/// resets `failure_count` to 0, clears `notified_at`.
	async fn record_cert_renewal_success(&self, tn_id: TnId) -> ClResult<()>;

	/// Stamp `notified_at` after sending a renewal-failure notification email.
	async fn record_cert_renewal_notification(&self, tn_id: TnId) -> ClResult<()>;

	/// Update tenant status. Known statuses:
	/// `'A'` = Active, `'S'` = Suspended (cert-related, set/cleared automatically
	/// by the ACME renewal task when an expired cert keeps failing renewal),
	/// `'X'` = Purging (soft-deleted; admin force-purge has begun. Auth is
	/// blocked and a retry of the purge endpoint resumes destructive cleanup).
	async fn update_tenant_status(&self, tn_id: TnId, status: char) -> ClResult<()>;

	/// Admin suspension, independent of `status`. `true` stamps `suspended_at`; `false`
	/// (resume) clears both `suspended_at` and `expires_at`. Login, login-token refresh and
	/// API-key exchange are refused while suspended; issued access tokens run out (<= 1 h).
	async fn set_tenant_suspended(&self, tn_id: TnId, suspended: bool) -> ClResult<()>;

	/// Set (`Some`) or clear (`None`) the account expiry; login is refused once it is reached.
	async fn set_tenant_expiry(&self, tn_id: TnId, expires_at: Option<Timestamp>) -> ClResult<()>;

	// Key management
	async fn list_profile_keys(&self, tn_id: TnId) -> ClResult<Vec<AuthKey>>;
	async fn create_profile_key(
		&self,
		tn_id: TnId,
		expires_at: Option<Timestamp>,
	) -> ClResult<AuthKey>;
	/// Create a new active signing key and demote every active key to verify-only.
	async fn rotate_profile_key(&self, tn_id: TnId) -> ClResult<AuthKey>;
	/// Mark a key revoked. Refused (`Conflict`) if it is the only active key.
	async fn revoke_profile_key(&self, tn_id: TnId, key_id: &str) -> ClResult<()>;
	/// Every key of the tenant, revoked ones included, with status (owner listing).
	async fn list_profile_keys_admin(&self, tn_id: TnId) -> ClResult<Vec<KeyInfo>>;
	async fn create_access_token(
		&self,
		tn_id: TnId,
		data: &AccessToken<&str>,
	) -> ClResult<Box<str>>;
	async fn create_action_token(
		&self,
		tn_id: TnId,
		data: action_types::CreateAction,
	) -> ClResult<Box<str>>;

	// Vapid keys
	async fn read_vapid_key(&self, tn_id: TnId) -> ClResult<KeyPair>;
	async fn read_vapid_public_key(&self, tn_id: TnId) -> ClResult<Box<str>>;
	async fn create_vapid_key(&self, tn_id: TnId) -> ClResult<KeyPair>;
	async fn update_vapid_key(&self, tn_id: TnId, key: &KeyPair) -> ClResult<()>;

	// Variables
	async fn read_var(&self, tn_id: TnId, var: &str) -> ClResult<Box<str>>;
	async fn update_var(&self, tn_id: TnId, var: &str, value: &str) -> ClResult<()>;

	// Webauthn
	async fn list_webauthn_credentials(&self, tn_id: TnId) -> ClResult<Box<[Webauthn]>>;
	async fn create_webauthn_credential(&self, tn_id: TnId, data: &Webauthn) -> ClResult<()>;
	async fn update_webauthn_credential_counter(
		&self,
		tn_id: TnId,
		credential_id: &str,
		counter: u32,
	) -> ClResult<()>;
	async fn delete_webauthn_credential(&self, tn_id: TnId, credential_id: &str) -> ClResult<()>;

	// API Key management
	async fn create_api_key(
		&self,
		tn_id: TnId,
		opts: CreateApiKeyOptions<'_>,
	) -> ClResult<CreatedApiKey>;
	async fn validate_api_key(&self, key: &str) -> ClResult<ApiKeyValidation>;
	async fn list_api_keys(&self, tn_id: TnId) -> ClResult<Vec<ApiKeyInfo>>;
	async fn read_api_key(&self, tn_id: TnId, key_id: i64) -> ClResult<ApiKeyInfo>;
	async fn update_api_key(
		&self,
		tn_id: TnId,
		key_id: i64,
		name: Option<&str>,
		scopes: Option<&str>,
		expires_at: Option<Timestamp>,
	) -> ClResult<ApiKeyInfo>;
	async fn delete_api_key(&self, tn_id: TnId, key_id: i64) -> ClResult<()>;
	async fn cleanup_expired_api_keys(&self) -> ClResult<u32>;
	async fn cleanup_expired_verification_codes(&self) -> ClResult<u32>;

	// Proxy site management
	async fn create_proxy_site(&self, data: &CreateProxySiteData<'_>) -> ClResult<ProxySiteData>;
	async fn read_proxy_site(&self, site_id: i64) -> ClResult<ProxySiteData>;
	async fn update_proxy_site(
		&self,
		site_id: i64,
		data: &UpdateProxySiteData<'_>,
	) -> ClResult<ProxySiteData>;
	async fn delete_proxy_site(&self, site_id: i64) -> ClResult<()>;
	async fn list_proxy_sites(&self) -> ClResult<Vec<ProxySiteData>>;
	async fn update_proxy_site_cert(
		&self,
		site_id: i64,
		cert: &str,
		key: &str,
		expires_at: Timestamp,
	) -> ClResult<()>;
	async fn list_proxy_sites_needing_cert_renewal(
		&self,
		renewal_days: u32,
	) -> ClResult<Vec<ProxySiteData>>;

	// TOTP MFA (`tenants.totp_secret` base32, `tenants.totp_last_step` RFC 6238 counter)
	/// `None` = not enrolled; `Some((secret, last_accepted_step))`. `NotFound` for no tenant.
	async fn get_totp(&self, tn_id: TnId) -> ClResult<Option<(Box<str>, Option<i64>)>>;
	/// Store the secret and its first accepted step only if the account is not enrolled;
	/// `false` = already enrolled.
	async fn enroll_totp(&self, tn_id: TnId, secret: &str, step: i64) -> ClResult<bool>;
	/// Remove the secret and the last accepted step. `NotFound` for no tenant.
	async fn clear_totp(&self, tn_id: TnId) -> ClResult<()>;
	/// Store `step` only if newer than the stored one; `false` = replayed/stale step.
	async fn set_totp_last_step(&self, tn_id: TnId, step: i64) -> ClResult<bool>;

	// Audit trail (append-only; write through `cloudillo_core::audit::record`)
	async fn append_audit_event(&self, ev: &AuditEvent) -> ClResult<()>;
	async fn list_audit_events(&self, q: &AuditQuery) -> ClResult<Vec<AuditEventRow>>;
	/// Delete events with `ts < before`; returns the number of rows deleted.
	async fn purge_audit_events(&self, before: Timestamp) -> ClResult<u64>;

	/// Write a consistent online copy of this store into the existing directory `dest`.
	/// Writes `auth.db` (SQLite `VACUUM INTO`).
	async fn snapshot(&self, dest: &std::path::Path) -> ClResult<crate::snapshot::SnapshotPart>;
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	pub fn test_access_token() {
		let token: AccessToken<String> = AccessToken {
			iss: "a@a".into(),
			sub: Some("b@b".into()),
			scope: None,
			r: None,
			h: None,
			exp: Timestamp::now(),
			auth_time: None,
		};

		assert_eq!(token.iss, "a@a");
		assert_eq!(token.sub.as_ref().unwrap(), "b@b");
	}
}

// vim: ts=4
