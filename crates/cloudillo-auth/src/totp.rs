// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! TOTP MFA (RFC 6238: SHA-1, 6 digits, 30 s step, ±1 step, no reuse of the last step).
//!
//! Holds the code check, the pending-login store behind `POST /api/auth/login/mfa`, and the
//! owner's enrollment routes under `/api/auth/totp`. An enrolled account always needs the code,
//! whatever `auth.mfa` says; the setting only governs offering (`optional`) and forcing
//! (`required`) enrollment for accounts that are not enrolled.

use axum::{
	Json,
	extract::{ConnectInfo, State},
	http::StatusCode,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL};
use dashmap::DashMap;
use data_encoding::BASE32_NOPAD;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use rand::RngExt;
use ring::hmac;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use cloudillo_core::{
	Auth,
	extract::{IdTag, OptionalRequestId},
};
use cloudillo_email::{EmailModule, EmailTaskParams, get_tenant_lang};
use cloudillo_types::types::{ApiResponse, SHARED_TN};

use crate::audit::{penalize, record_auth, record_auth_fail};
use crate::prelude::*;

const STEP_SECS: i64 = 30;
/// Pending login / enrollment lifetime: 5 minutes
const PENDING_EXPIRY: Duration = Duration::from_mins(5);
/// Maximum number of pending logins + enrollments held in memory
const MAX_PENDING: usize = 10_000;
/// Wrong codes after which a pending login token is dropped
const MAX_ATTEMPTS: u8 = 5;
/// Pending logins per account; the oldest is dropped beyond this
const MAX_PENDING_PER_TENANT: usize = 5;

// ============================================================================
// RFC 6238
// ============================================================================

/// A new shared secret: 20 random bytes, base32 without padding.
pub fn generate_secret() -> String {
	let bytes: [u8; 20] = rand::rng().random();
	BASE32_NOPAD.encode(&bytes)
}

/// RFC 3986 unreserved characters pass; everything else is percent-encoded.
const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

/// Provisioning URI for authenticator apps (QR code content). The secret is base32 and the
/// issuer a constant, so only the id_tag needs encoding.
pub fn otpauth_uri(id_tag: &str, secret: &str) -> String {
	let id_tag = utf8_percent_encode(id_tag, UNRESERVED);
	format!("otpauth://totp/Cloudillo:{id_tag}?secret={secret}&issuer=Cloudillo")
}

fn hmac_key(secret: &str) -> Option<hmac::Key> {
	let key_bytes = BASE32_NOPAD.decode(secret.as_bytes()).ok()?;
	Some(hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &key_bytes))
}

fn code_at(key: &hmac::Key, step: i64) -> Option<u32> {
	let counter = u64::try_from(step).ok()?;
	let tag = hmac::sign(key, &counter.to_be_bytes());
	let h = tag.as_ref();
	let off = usize::from(h.last()? & 0x0f);
	let word: [u8; 4] = h.get(off..off + 4)?.try_into().ok()?;
	Some((u32::from_be_bytes(word) & 0x7fff_ffff) % 1_000_000)
}

/// The 6-digit code of `secret` at unix time `now` (what an authenticator app shows).
pub fn code_at_time(secret: &str, now: i64) -> Option<String> {
	code_at(&hmac_key(secret)?, now.div_euclid(STEP_SECS)).map(|c| format!("{c:06}"))
}

/// Check a 6-digit `code` against `secret` at unix time `now`, accepting the current step
/// and one on either side. Steps not newer than `last_step` are refused (no reuse).
/// Returns the matched step, to be stored as the new `last_step`.
pub fn verify(secret: &str, code: &str, now: i64, last_step: Option<i64>) -> Option<i64> {
	if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
		return None;
	}
	let code: u32 = code.parse().ok()?;
	let key = hmac_key(secret)?;
	let cur = now.div_euclid(STEP_SECS);
	[cur, cur - 1, cur + 1]
		.into_iter()
		.filter(|step| last_step.is_none_or(|last| *step > last))
		.find(|step| code_at(&key, *step) == Some(code))
}

// ============================================================================
// Pending logins and enrollments
// ============================================================================

/// A password login waiting for its TOTP code.
pub(crate) struct PendingLogin {
	pub tn_id: TnId,
	pub id_tag: Box<str>,
	/// Forced enrollment: the secret shown at login, stored once a code for it checks out.
	pub enroll_secret: Option<Box<str>>,
	attempts: u8,
	expires_at: Instant,
}

struct PendingEnroll {
	secret: Box<str>,
	expires_at: Instant,
}

/// In-memory store of pending MFA logins (keyed by the opaque `mfaToken`), pending
/// owner enrollments (keyed by tn_id). App extension.
/// Pruned when full; expired entries are never served.
#[derive(Default)]
pub struct MfaStore {
	logins: DashMap<String, PendingLogin>,
	enrolls: DashMap<TnId, PendingEnroll>,
}

impl MfaStore {
	/// Remove expired entries.
	pub fn cleanup_expired(&self) -> usize {
		let now = Instant::now();
		let before = self.logins.len() + self.enrolls.len();
		self.logins.retain(|_, p| now < p.expires_at);
		self.enrolls.retain(|_, p| now < p.expires_at);
		before - (self.logins.len() + self.enrolls.len())
	}

	fn ensure_room(&self) -> ClResult<()> {
		if self.logins.len() + self.enrolls.len() >= MAX_PENDING {
			self.cleanup_expired();
			if self.logins.len() + self.enrolls.len() >= MAX_PENDING {
				return Err(Error::ServiceUnavailable("too many pending MFA logins".into()));
			}
		}
		Ok(())
	}

	/// Park a password-verified login; returns the `mfaToken` (32 random bytes, base64url).
	pub(crate) fn start_login(
		&self,
		tn_id: TnId,
		id_tag: &str,
		enroll_secret: Option<Box<str>>,
	) -> ClResult<String> {
		self.ensure_room()?;
		// O(n) scan of pending logins (≤ MAX_PENDING); index by tn_id if it shows up
		let mine: Vec<(String, Instant)> = self
			.logins
			.iter()
			.filter(|p| p.tn_id == tn_id)
			.map(|p| (p.key().clone(), p.expires_at))
			.collect();
		if mine.len() >= MAX_PENDING_PER_TENANT
			&& let Some((oldest, _)) = mine.iter().min_by_key(|(_, exp)| *exp)
		{
			self.logins.remove(oldest);
		}
		let token = BASE64_URL.encode(rand::rng().random::<[u8; 32]>());
		self.logins.insert(
			token.clone(),
			PendingLogin {
				tn_id,
				id_tag: id_tag.into(),
				enroll_secret,
				attempts: 0,
				expires_at: Instant::now() + PENDING_EXPIRY,
			},
		);
		Ok(token)
	}

	/// Single use: removes the entry. [`Self::retry_login`] puts it back after a wrong code.
	pub(crate) fn take_login(&self, token: &str) -> Option<PendingLogin> {
		self.logins
			.remove(token)
			.map(|(_, p)| p)
			.filter(|p| Instant::now() < p.expires_at)
	}

	/// Re-park a login after a wrong code, unless it has used up its attempts.
	/// Returns whether the token is still live.
	pub(crate) fn retry_login(&self, token: String, mut pending: PendingLogin) -> bool {
		pending.attempts = pending.attempts.saturating_add(1);
		let live = pending.attempts < MAX_ATTEMPTS;
		if live {
			self.logins.insert(token, pending);
		}
		live
	}

	fn start_enroll(&self, tn_id: TnId, secret: &str) -> ClResult<()> {
		self.ensure_room()?;
		self.enrolls.insert(
			tn_id,
			PendingEnroll { secret: secret.into(), expires_at: Instant::now() + PENDING_EXPIRY },
		);
		Ok(())
	}

	fn enroll_secret(&self, tn_id: TnId) -> Option<Box<str>> {
		self.enrolls
			.get(&tn_id)
			.filter(|p| Instant::now() < p.expires_at)
			.map(|p| p.secret.clone())
	}
}

// ============================================================================
// Login integration (used by `handler::post_login` / `post_login_mfa`)
// ============================================================================

/// The MFA step a password login returns instead of a session.
/// `{mfaRequired: true, mfaToken}` or `{mfaEnroll: true, mfaToken, secret, otpauthUri}`.
#[skip_serializing_none]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MfaChallenge {
	pub mfa_required: Option<bool>,
	pub mfa_enroll: Option<bool>,
	pub mfa_token: String,
	pub secret: Option<String>,
	pub otpauth_uri: Option<String>,
}

/// Server-wide `auth.mfa` mode: `off`, `optional` or `required`.
pub(crate) async fn mfa_mode(app: &App) -> ClResult<String> {
	app.settings.get_string(SHARED_TN, "auth.mfa").await
}

pub(crate) enum CodeCheck {
	Ok,
	Wrong,
}

/// Spend `code` for an enrolled account. Refusals are penalized (the per-IP ban caps
/// guessing); the caller audits.
pub(crate) async fn spend_code(
	app: &App,
	addr: &SocketAddr,
	tn_id: TnId,
	secret: &str,
	last_step: Option<i64>,
	code: &str,
) -> ClResult<CodeCheck> {
	// Spend the step (compare-and-set) so a code seen once cannot be used twice
	let spent = match verify(secret, code, Timestamp::now().0, last_step) {
		Some(step) => app.auth_adapter.set_totp_last_step(tn_id, step).await?,
		None => false,
	};
	if !spent {
		penalize(app, addr);
		return Ok(CodeCheck::Wrong);
	}
	Ok(CodeCheck::Ok)
}

/// After a correct password: `None` = no MFA applies, log in now; `Some` = the MFA step.
pub(crate) async fn login_challenge(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
) -> ClResult<Option<MfaChallenge>> {
	let store = app.ext::<MfaStore>()?;
	if app.auth_adapter.get_totp(tn_id).await?.is_some() {
		let mfa_token = store.start_login(tn_id, id_tag, None)?;
		return Ok(Some(MfaChallenge {
			mfa_required: Some(true),
			mfa_enroll: None,
			mfa_token,
			secret: None,
			otpauth_uri: None,
		}));
	}
	if mfa_mode(app).await? != "required" {
		return Ok(None);
	}
	let secret = generate_secret();
	let mfa_token = store.start_login(tn_id, id_tag, Some(secret.as_str().into()))?;
	Ok(Some(MfaChallenge {
		mfa_required: None,
		mfa_enroll: Some(true),
		mfa_token,
		otpauth_uri: Some(otpauth_uri(id_tag, &secret)),
		secret: Some(secret),
	}))
}

/// Check the code of a pending login; on success stores the step (and, for a forced
/// enrollment, the secret). `false` = wrong, replayed, or no longer applicable code.
pub(crate) async fn check_login_code(
	app: &App,
	pending: &PendingLogin,
	code: &str,
) -> ClResult<bool> {
	let now = Timestamp::now().0;
	let current = app.auth_adapter.get_totp(pending.tn_id).await?;
	match (&pending.enroll_secret, current) {
		(Some(secret), None) => {
			let Some(step) = verify(secret, code, now, None) else { return Ok(false) };
			app.auth_adapter.enroll_totp(pending.tn_id, secret, step).await
		}
		(None, Some((secret, last_step))) => match verify(&secret, code, now, last_step) {
			Some(step) => app.auth_adapter.set_totp_last_step(pending.tn_id, step).await,
			None => Ok(false),
		},
		// Enrollment changed since the password step (enrolled elsewhere, or reset)
		_ => Ok(false),
	}
}

/// Tell the owner that an authenticator was linked, by a forced enrollment at login or by
/// `/api/auth/totp/confirm`. Never fails the caller: errors are logged.
pub(crate) async fn notify_mfa_enrolled(app: &App, tn_id: TnId, id_tag: &str, addr: &SocketAddr) {
	let email = match app.auth_adapter.read_tenant(id_tag).await {
		Ok(t) => t.email,
		Err(e) => {
			warn!(?tn_id, error = %e, "Failed to read tenant for MFA enrollment email");
			return;
		}
	};
	let Some(email) = email else { return };
	let user_name = app
		.meta_adapter
		.read_tenant(tn_id)
		.await
		.map_or_else(|_| id_tag.to_string(), |t| t.name.to_string());
	let lang = get_tenant_lang(&app.settings, tn_id).await;
	let params = EmailTaskParams {
		to: email.to_string(),
		subject: None,
		template_name: "mfa_enrolled".to_string(),
		template_vars: serde_json::json!({
			"identity_tag": user_name,
			"idTag": id_tag,
			"instance_name": "Cloudillo",
			"ip": addr.ip().to_string(),
		}),
		lang,
		custom_key: Some(format!("mfa-enrolled:{}:{}", tn_id.0, Timestamp::now().0)),
		from_name_override: Some(format!("Cloudillo | {}", id_tag.to_uppercase())),
		delay_seconds: None,
		notify_guard: None,
	};
	if let Err(e) =
		EmailModule::schedule_email_task(&app.scheduler, &app.settings, tn_id, params).await
	{
		warn!(?tn_id, error = %e, "Failed to schedule MFA enrollment email");
	}
}

// ============================================================================
// Owner routes: /api/auth/totp
// ============================================================================

fn require_account(auth: &cloudillo_types::auth_adapter::AuthCtx, id_tag: &str) -> ClResult<()> {
	// SADM visiting passes `require_tenant_self` but must not enroll or drop a second factor
	// on someone else's account.
	if cloudillo_core::abac::is_tenant_account(auth, id_tag) {
		Ok(())
	} else {
		Err(Error::PermissionDenied)
	}
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpStatus {
	mode: String,
	enrolled: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpEnrollRes {
	secret: String,
	otpauth_uri: String,
}

#[derive(Deserialize)]
pub struct TotpEnrollReq {
	password: String,
}

#[derive(Deserialize)]
pub struct TotpCodeReq {
	code: String,
}

/// GET /api/auth/totp - `{mode, enrolled}`
pub async fn get_totp(
	State(app): State<App>,
	IdTag(id_tag): IdTag,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<TotpStatus>>)> {
	require_account(&auth, &id_tag)?;
	let mode = mfa_mode(&app).await?;
	let enrolled = app.auth_adapter.get_totp(auth.tn_id).await?.is_some();
	let response =
		ApiResponse::new(TotpStatus { mode, enrolled }).with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

/// POST /api/auth/totp/enroll `{password}` - new pending secret `{secret, otpauthUri}`;
/// refused when `auth.mfa = off` or the password is wrong (403), or already enrolled (409).
pub async fn post_enroll(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	IdTag(id_tag): IdTag,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<TotpEnrollReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<TotpEnrollRes>>)> {
	require_account(&auth, &id_tag)?;
	if mfa_mode(&app).await? == "off" {
		return Err(Error::PermissionDenied);
	}
	// A stolen session alone must not link the thief's authenticator
	if app
		.auth_adapter
		.check_tenant_password(&auth.id_tag, &req.password)
		.await
		.is_err()
	{
		penalize(&app, &addr);
		tokio::time::sleep(std::time::Duration::from_secs(1)).await;
		let (tn_id, actor) = (Some(auth.tn_id), &auth.id_tag);
		record_auth_fail(&app, "auth.mfa.enroll", tn_id, actor, &addr, serde_json::Value::Null)
			.await;
		return Err(Error::PermissionDenied);
	}
	if app.auth_adapter.get_totp(auth.tn_id).await?.is_some() {
		return Err(Error::Conflict("TOTP already enrolled".into()));
	}
	let secret = generate_secret();
	app.ext::<MfaStore>()?.start_enroll(auth.tn_id, &secret)?;
	let res = TotpEnrollRes { otpauth_uri: otpauth_uri(&auth.id_tag, &secret), secret };
	Ok((StatusCode::OK, Json(ApiResponse::new(res).with_req_id(req_id.unwrap_or_default()))))
}

/// POST /api/auth/totp/confirm `{code}` - store the pending secret once a code checks out.
pub async fn post_confirm(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	IdTag(id_tag): IdTag,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<TotpCodeReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<TotpStatus>>)> {
	require_account(&auth, &id_tag)?;
	let mode = mfa_mode(&app).await?;
	if mode == "off" {
		return Err(Error::PermissionDenied);
	}
	let store = app.ext::<MfaStore>()?;
	let secret = store.enroll_secret(auth.tn_id).ok_or(Error::NotFound)?;
	let Some(step) = verify(&secret, &req.code, Timestamp::now().0, None) else {
		penalize(&app, &addr);
		let (tn_id, actor) = (Some(auth.tn_id), &auth.id_tag);
		record_auth_fail(&app, "auth.mfa.enroll", tn_id, actor, &addr, serde_json::Value::Null)
			.await;
		return Err(Error::PermissionDenied);
	};
	if !app.auth_adapter.enroll_totp(auth.tn_id, &secret, step).await? {
		store.enrolls.remove(&auth.tn_id);
		return Err(Error::Conflict("TOTP already enrolled".into()));
	}
	store.enrolls.remove(&auth.tn_id);
	record_auth(&app, "auth.mfa.enroll", "success", Some(auth.tn_id), &auth.id_tag, &addr, None)
		.await;
	notify_mfa_enrolled(&app, auth.tn_id, &auth.id_tag, &addr).await;
	let response = ApiResponse::new(TotpStatus { mode, enrolled: true })
		.with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

/// DELETE /api/auth/totp `{code}` - remove the second factor; refused when
/// `auth.mfa = required` (403).
pub async fn delete_totp(
	State(app): State<App>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	IdTag(id_tag): IdTag,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(req): Json<TotpCodeReq>,
) -> ClResult<(StatusCode, Json<ApiResponse<TotpStatus>>)> {
	require_account(&auth, &id_tag)?;
	let mode = mfa_mode(&app).await?;
	if mode == "required" {
		return Err(Error::PermissionDenied);
	}
	let (secret, last_step) =
		app.auth_adapter.get_totp(auth.tn_id).await?.ok_or(Error::NotFound)?;
	// Wrong codes are penalized, so the per-IP ban stops a stolen session brute-forcing it
	if let CodeCheck::Wrong =
		spend_code(&app, &addr, auth.tn_id, &secret, last_step, &req.code).await?
	{
		let (tn_id, actor) = (Some(auth.tn_id), &auth.id_tag);
		record_auth_fail(&app, "auth.mfa.disable", tn_id, actor, &addr, serde_json::Value::Null)
			.await;
		return Err(Error::PermissionDenied);
	}
	app.auth_adapter.clear_totp(auth.tn_id).await?;
	record_auth(&app, "auth.mfa.disable", "success", Some(auth.tn_id), &auth.id_tag, &addr, None)
		.await;
	let response = ApiResponse::new(TotpStatus { mode, enrolled: false })
		.with_req_id(req_id.unwrap_or_default());
	Ok((StatusCode::OK, Json(response)))
}

#[cfg(test)]
mod tests {
	use super::*;

	/// RFC 6238 Appendix B SHA-1 vectors (seed "12345678901234567890"), last 6 digits.
	#[test]
	fn rfc6238_vectors_and_reuse() {
		let secret = BASE32_NOPAD.encode(b"12345678901234567890");
		for (t, code) in [
			(59, "287082"),
			(1_111_111_109, "081804"),
			(1_111_111_111, "050471"),
			(1_234_567_890, "005924"),
			(2_000_000_000, "279037"),
			(20_000_000_000, "353130"),
		] {
			assert_eq!(verify(&secret, code, t, None), Some(t / STEP_SECS), "t={t}");
			// One step of clock skew either way is accepted
			assert_eq!(verify(&secret, code, t + STEP_SECS, None), Some(t / STEP_SECS));
			assert_eq!(verify(&secret, code, t - STEP_SECS, None), Some(t / STEP_SECS));
			// Reuse of the last accepted step is refused
			assert_eq!(verify(&secret, code, t, Some(t / STEP_SECS)), None);
		}
		assert_eq!(verify(&secret, "287082", 59 + 3 * STEP_SECS, None), None);
		assert_eq!(verify(&secret, "28708", 59, None), None);
		assert_eq!(verify(&secret, "28708a", 59, None), None);
		assert_eq!(verify(&secret, "2870820", 59, None), None);
		// Two steps of skew is too many, either way.
		let t = 1_111_111_109;
		assert_eq!(verify(&secret, "081804", t + 2 * STEP_SECS, None), None);
		assert_eq!(verify(&secret, "081804", t - 2 * STEP_SECS, None), None);
		// Not base32: refused, no panic.
		assert_eq!(verify("not-base32!", "081804", t, None), None);
		assert_eq!(code_at_time("not-base32!", t), None);
		assert_eq!(verify(&secret, "000000", 59, None), None);
		assert_eq!(generate_secret().len(), 32);
	}

	#[test]
	fn otpauth_uri_encodes_id_tag() {
		assert_eq!(
			otpauth_uri("a b:c@d.test", "ABC"),
			"otpauth://totp/Cloudillo:a%20b%3Ac%40d.test?secret=ABC&issuer=Cloudillo"
		);
		assert_eq!(
			otpauth_uri("alice-1_x~.test", "ABC"),
			"otpauth://totp/Cloudillo:alice-1_x~.test?secret=ABC&issuer=Cloudillo"
		);
	}

	#[test]
	fn code_at_time_round_trips() {
		let secret = generate_secret();
		let code = code_at_time(&secret, 1_000_000).unwrap();
		assert_eq!(code.len(), 6);
		assert_eq!(verify(&secret, &code, 1_000_000, None), Some(1_000_000 / STEP_SECS));
	}

	#[test]
	fn pending_login_single_use_and_expiry() {
		let store = MfaStore::default();
		let token = store.start_login(TnId(1), "alice", None).unwrap();
		assert!(store.take_login(&token).is_some());
		assert!(store.take_login(&token).is_none());
		assert!(store.take_login("unknown").is_none());

		let pending = PendingLogin {
			tn_id: TnId(1),
			id_tag: "alice".into(),
			enroll_secret: None,
			attempts: 0,
			expires_at: Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
		};
		store.logins.insert("old".into(), pending);
		assert!(store.take_login("old").is_none());
	}

	#[test]
	fn retry_login_drops_after_max_attempts() {
		let store = MfaStore::default();
		let token = store.start_login(TnId(1), "alice", None).unwrap();
		for i in 1..=MAX_ATTEMPTS {
			let pending = store.take_login(&token).unwrap();
			assert_eq!(store.retry_login(token.clone(), pending), i < MAX_ATTEMPTS);
		}
		assert!(store.take_login(&token).is_none());
	}

	#[test]
	fn pending_logins_capped_per_tenant() {
		let store = MfaStore::default();
		let first = store.start_login(TnId(1), "alice", None).unwrap();
		let other = store.start_login(TnId(2), "bob", None).unwrap();
		for _ in 0..MAX_PENDING_PER_TENANT {
			store.start_login(TnId(1), "alice", None).unwrap();
		}
		assert_eq!(store.logins.iter().filter(|p| p.tn_id == TnId(1)).count(), 5);
		assert!(!store.logins.contains_key(&first));
		assert!(store.logins.contains_key(&other));
	}
}

// vim: ts=4
