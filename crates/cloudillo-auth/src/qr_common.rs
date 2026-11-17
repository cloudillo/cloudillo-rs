// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! The in-memory session store shared by QR login ([`crate::qr_login`]) and QR device pairing
//! ([`crate::qr_pair`]): a client creates a session and long-polls it with its secret; the
//! tenant account approves or denies it from another device; the result stays re-readable by
//! the secret holder for a short grace period after delivery, so a lost response is not fatal.

use axum::http::{HeaderMap, header};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL};
use dashmap::DashMap;
use rand::RngExt;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

use cloudillo_core::rate_limit::AddressKey;
use cloudillo_types::auth_adapter::AuthCtx;

use crate::prelude::*;

/// Session expiry: 5 minutes
const SESSION_EXPIRY_SECS: u64 = 300;

/// How long a delivered result stays re-readable (a lost poll response retries within it)
const DELIVERED_GRACE_SECS: u64 = 60;

/// Maximum number of concurrent sessions, all tenants
const MAX_SESSIONS: usize = 10_000;

/// Maximum number of concurrent sessions from one source (IPv4 /32, IPv6 /64), all tenants:
/// session creation is unauthenticated, so a per-tenant cap would let anyone lock a tenant out.
/// Over the cap the source's oldest pending session is evicted, so a source only churns its own
/// sessions; a client behind a shared NAT may lose a pending QR to a newer one (accepted).
/// Answered sessions are never evicted (an approval is not lost before it is collected).
const MAX_SESSIONS_PER_SOURCE: usize = 32;

/// Maximum long-poll timeout in seconds
const MAX_POLL_TIMEOUT_SECS: u64 = 30;

/// Default long-poll timeout in seconds
const DEFAULT_POLL_TIMEOUT_SECS: u64 = 15;

/// Failed approvals (bad verification code) before a session is removed
const MAX_FAILURES: u8 = 5;

pub(crate) enum QrState<R> {
	Pending,
	Approved(R),
	Denied,
}

pub(crate) struct QrSession<M, R> {
	tn_id: TnId,
	source: AddressKey,
	secret_hash: String,
	state: QrState<R>,
	meta: M,
	expires_at: Instant,
	notify: Arc<Notify>,
	failures: u8,
}

/// Sessions keyed by their public id, registered as an extension on App (one per flow).
pub struct QrStore<M, R> {
	sessions: DashMap<String, QrSession<M, R>>,
}

/// What a poll sees.
pub(crate) enum Polled<R> {
	Pending,
	Approved(R),
	Denied,
	Expired,
}

impl<R> Polled<R> {
	/// `(status, result)` for a status response.
	pub(crate) fn into_parts(self) -> (&'static str, Option<R>) {
		match self {
			Self::Pending => ("pending", None),
			Self::Approved(r) => ("approved", Some(r)),
			Self::Denied => ("denied", None),
			Self::Expired => ("expired", None),
		}
	}
}

/// The session secret from header `name`; `Unauthorized` when missing or not ASCII.
pub(crate) fn secret_from<'a>(headers: &'a HeaderMap, name: &str) -> ClResult<&'a str> {
	headers.get(name).and_then(|v| v.to_str().ok()).ok_or(Error::Unauthorized)
}

/// The error for an approve/deny on a session that already left `Pending`.
pub(crate) fn already_responded() -> Error {
	Error::ValidationError("Session already responded".into())
}

/// `(user_agent, ip_address)` of the requesting client.
pub(crate) fn client_info(
	addr: &SocketAddr,
	headers: &HeaderMap,
) -> (Option<String>, Option<String>) {
	let user_agent =
		headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).map(String::from);
	(user_agent, Some(addr.ip().to_string()))
}

impl<M, R> Default for QrStore<M, R> {
	fn default() -> Self {
		Self { sessions: DashMap::new() }
	}
}

/// Constant-time byte compare (the length is not hidden).
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
	a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Hash a secret string with SHA-256 and return the hex digest.
fn hash_secret(secret: &str) -> String {
	let hash = Sha256::digest(secret.as_bytes());
	hash.iter().fold(String::with_capacity(64), |mut s, b| {
		use std::fmt::Write;
		let _ = write!(s, "{b:02x}");
		s
	})
}

impl<M, R> QrStore<M, R> {
	pub fn new() -> Self {
		Self::default()
	}

	/// Remove expired sessions.
	pub fn cleanup_expired(&self) -> usize {
		let now = Instant::now();
		let before = self.sessions.len();
		self.sessions.retain(|_, session| now < session.expires_at);
		before - self.sessions.len()
	}

	fn source_count(&self, source: &AddressKey) -> usize {
		// O(n) scan on insert bounded by MAX_SESSIONS; per-source counter map if hot
		self.sessions.iter().filter(|s| s.source == *source).count()
	}

	/// Start a pending session: `(session_id, secret)`. The id (16 bytes) is public and goes
	/// into the QR; the secret (32 bytes) stays with the polling client. Over the per-source
	/// cap the source's oldest pending session is evicted; `ServiceUnavailable` when the store
	/// is full or the source has no pending session to evict.
	pub(crate) fn create(&self, tn_id: TnId, ip: IpAddr, meta: M) -> ClResult<(String, String)> {
		let source = AddressKey::from_ip_individual(&ip);
		if self.sessions.len() >= MAX_SESSIONS
			|| self.source_count(&source) >= MAX_SESSIONS_PER_SOURCE
		{
			self.cleanup_expired();
			if self.source_count(&source) >= MAX_SESSIONS_PER_SOURCE {
				let oldest = self
					.sessions
					.iter()
					.filter(|s| s.source == source && matches!(s.state, QrState::Pending))
					.min_by_key(|s| s.expires_at)
					.map(|s| s.key().clone());
				match oldest {
					Some(key) => {
						self.sessions.remove(&key);
					}
					None => return Err(Error::ServiceUnavailable("too many QR sessions".into())),
				}
			}
			if self.sessions.len() >= MAX_SESSIONS {
				return Err(Error::ServiceUnavailable("too many QR sessions".into()));
			}
		}
		let session_id = BASE64_URL.encode(rand::rng().random::<[u8; 16]>());
		let secret = BASE64_URL.encode(rand::rng().random::<[u8; 32]>());
		self.sessions.insert(
			session_id.clone(),
			QrSession {
				tn_id,
				source,
				secret_hash: hash_secret(&secret),
				state: QrState::Pending,
				meta,
				expires_at: Instant::now() + Duration::from_secs(SESSION_EXPIRY_SECS),
				notify: Arc::new(Notify::new()),
				failures: 0,
			},
		);
		Ok((session_id, secret))
	}

	/// The session's state, `None` while pending. A terminal state stays in place (a clone goes
	/// out) and the session's expiry shrinks to [`DELIVERED_GRACE_SECS`] from now (`finish`
	/// guaranteed at least that much), so a retry after a lost response gets the same result.
	fn resolve(&self, id: &str) -> Option<Polled<R>>
	where
		R: Clone,
	{
		let Some(mut session) = self.sessions.get_mut(id) else { return Some(Polled::Expired) };
		let now = Instant::now();
		if now >= session.expires_at {
			drop(session);
			// remove_if: a concurrent approve may land between drop and remove
			self.sessions.remove_if(id, |_, s| Instant::now() >= s.expires_at);
			return Some(Polled::Expired);
		}
		let polled = match &session.state {
			QrState::Pending => return None,
			QrState::Approved(r) => Polled::Approved(r.clone()),
			QrState::Denied => Polled::Denied,
		};
		session.expires_at =
			session.expires_at.min(now + Duration::from_secs(DELIVERED_GRACE_SECS));
		Some(polled)
	}

	/// Check `secret` (`NotFound` on mismatch or unknown id, revealing nothing), then long-poll
	/// up to `timeout` seconds (default 15, max 30) for the session to leave `Pending`.
	pub(crate) async fn poll(
		&self,
		id: &str,
		secret: &str,
		timeout: Option<u64>,
	) -> ClResult<Polled<R>>
	where
		R: Clone,
	{
		let (notify, expires_at) = {
			let session = self.sessions.get(id).ok_or(Error::NotFound)?;
			// Constant-time compare; both are 64-char hex digests, so the length leaks nothing.
			if !ct_eq(session.secret_hash.as_bytes(), hash_secret(secret).as_bytes()) {
				return Err(Error::NotFound);
			}
			(session.notify.clone(), session.expires_at)
		};
		// Registered for `notify_waiters` on creation, before the state check: an approval
		// between the check and the wait still wakes it.
		let notified = std::pin::pin!(notify.notified());
		if let Some(polled) = self.resolve(id) {
			return Ok(polled);
		}
		let secs = timeout.unwrap_or(DEFAULT_POLL_TIMEOUT_SECS).min(MAX_POLL_TIMEOUT_SECS);
		let wait =
			Duration::from_secs(secs).min(expires_at.saturating_duration_since(Instant::now()));
		let _ = tokio::time::timeout(wait, notified).await;
		Ok(self.resolve(id).unwrap_or(Polled::Pending))
	}

	/// Pending session `id`, checked for the approver: unexpired, same tenant, and the tenant
	/// account itself (`is_tenant_account` — SADM and community leaders excluded: a login or
	/// key authenticates as the tenant). Runs `f` on its meta under the short map guard.
	pub(crate) fn with_pending<T>(
		&self,
		id: &str,
		auth: &AuthCtx,
		id_tag: &str,
		f: impl FnOnce(&M) -> ClResult<T>,
	) -> ClResult<T> {
		let session = self.sessions.get(id).ok_or(Error::NotFound)?;
		if Instant::now() >= session.expires_at {
			return Err(Error::NotFound);
		}
		if auth.tn_id != session.tn_id {
			return Err(Error::PermissionDenied);
		}
		// `auth.tn_id` is always the host tenant, so the check above admits any visitor
		// holding a session here (login CSRF, reading the client's IP and User-Agent).
		if !cloudillo_core::abac::is_tenant_account(auth, id_tag) {
			warn!(subject = %auth.id_tag, host = %id_tag, "QR approval denied - not the account");
			return Err(Error::PermissionDenied);
		}
		if !matches!(session.state, QrState::Pending) {
			return Err(already_responded());
		}
		f(&session.meta)
	}

	/// Approve (`Some`) or deny (`None`) session `id` if it is still pending and unexpired, and
	/// wake its pollers. The expiry grows to at least [`DELIVERED_GRACE_SECS`] from now, so an
	/// approval near the session limit still leaves the full window to collect it.
	/// `Err` hands the result back when the session is gone or answered.
	pub(crate) fn finish(&self, id: &str, result: Option<R>) -> Result<(), Option<R>> {
		let notify = match self.sessions.get_mut(id) {
			Some(mut s) if matches!(s.state, QrState::Pending) && Instant::now() < s.expires_at => {
				s.state = match result {
					Some(r) => QrState::Approved(r),
					None => QrState::Denied,
				};
				s.expires_at =
					s.expires_at.max(Instant::now() + Duration::from_secs(DELIVERED_GRACE_SECS));
				s.notify.clone()
			}
			_ => return Err(result),
		};
		notify.notify_waiters();
		Ok(())
	}

	/// A bad verification code counts against session `id`; [`MAX_FAILURES`] strikes remove
	/// it, so the 10^6 code space can't be brute-forced.
	pub(crate) fn record_failure(&self, id: &str) {
		let Some(mut session) = self.sessions.get_mut(id) else { return };
		session.failures += 1;
		if session.failures >= MAX_FAILURES {
			drop(session);
			self.sessions.remove(id);
		}
	}

	/// [`Self::finish`], answering the respond call's status (`"approved"` / `"denied"`);
	/// `Err` hands back an unclaimed approval when the session is gone or already answered.
	pub(crate) fn respond(&self, id: &str, result: Option<R>) -> Result<&'static str, Option<R>> {
		let status = if result.is_some() { "approved" } else { "denied" };
		self.finish(id, result).map(|()| status)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	type Store = QrStore<(), u32>;

	const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));

	#[test]
	fn per_source_cap() -> ClResult<()> {
		let store = Store::new();
		let (first, _) = store.create(TnId(1), IP, ())?;
		for _ in 1..MAX_SESSIONS_PER_SOURCE {
			store.create(TnId(1), IP, ())?;
		}
		// Over the cap (per source, whatever the tenant) the source's oldest session goes.
		store.create(TnId(2), IP, ())?;
		assert!(!store.sessions.contains_key(&first));
		let source = AddressKey::from_ip_individual(&IP);
		assert_eq!(store.source_count(&source), MAX_SESSIONS_PER_SOURCE);
		let other = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2));
		store.create(TnId(1), other, ())?;
		assert_eq!(store.source_count(&source), MAX_SESSIONS_PER_SOURCE);
		Ok(())
	}

	#[tokio::test]
	async fn per_source_cap_keeps_approved() -> ClResult<()> {
		let store = Store::new();
		let (first, secret) = store.create(TnId(1), IP, ())?;
		for _ in 1..MAX_SESSIONS_PER_SOURCE {
			store.create(TnId(1), IP, ())?;
		}
		assert!(store.finish(&first, Some(1)).is_ok());
		store.create(TnId(1), IP, ())?;
		assert!(matches!(store.poll(&first, &secret, Some(0)).await?, Polled::Approved(1)));
		Ok(())
	}

	#[test]
	fn answered_session_has_no_details() -> ClResult<()> {
		let store = Store::new();
		let (id, _) = store.create(TnId(1), IP, ())?;
		assert!(store.finish(&id, Some(7)).is_ok());
		let tenant_auth = AuthCtx {
			tn_id: TnId(1),
			id_tag: "alice.test".into(),
			roles: Box::new(["leader".into()]),
			scope: None,
			anonymous: false,
			hat: None,
			exp: None,
			auth_time: None,
		};
		let res = store.with_pending(&id, &tenant_auth, "alice.test", |()| Ok(()));
		assert!(matches!(res, Err(Error::ValidationError(_))));
		Ok(())
	}

	#[test]
	fn finish_extends_expiry_to_grace() -> ClResult<()> {
		let store = Store::new();
		let (id, _) = store.create(TnId(1), IP, ())?;
		if let Some(mut s) = store.sessions.get_mut(&id) {
			s.expires_at = Instant::now() + Duration::from_secs(1);
		}
		assert!(store.finish(&id, Some(7)).is_ok());
		let expires_at = store.sessions.get(&id).map(|s| s.expires_at);
		assert!(expires_at >= Some(Instant::now() + Duration::from_secs(59)));
		Ok(())
	}

	#[tokio::test]
	async fn approved_result_is_re_readable() -> ClResult<()> {
		let store = Store::new();
		let (id, secret) = store.create(TnId(1), IP, ())?;
		assert!(matches!(store.poll(&id, "wrong", Some(0)).await, Err(Error::NotFound)));
		assert!(store.finish(&id, Some(7)).is_ok());
		assert_eq!(store.finish(&id, Some(8)), Err(Some(8)));
		// A lost response is retried: the secret holder reads the same result again.
		assert!(matches!(store.poll(&id, &secret, Some(0)).await?, Polled::Approved(7)));
		assert!(matches!(store.poll(&id, &secret, Some(0)).await?, Polled::Approved(7)));
		assert!(matches!(store.poll(&id, "wrong", Some(0)).await, Err(Error::NotFound)));
		Ok(())
	}

	#[tokio::test]
	async fn denied_session_polls_denied() -> ClResult<()> {
		let store = Store::new();
		let (id, secret) = store.create(TnId(1), IP, ())?;
		assert!(store.finish(&id, None).is_ok());
		assert!(matches!(store.poll(&id, &secret, Some(0)).await?, Polled::Denied));
		Ok(())
	}

	#[test]
	fn failures_remove_session() -> ClResult<()> {
		let store = Store::new();
		let (id, _) = store.create(TnId(1), IP, ())?;
		for _ in 1..MAX_FAILURES {
			store.record_failure(&id);
		}
		assert!(store.sessions.contains_key(&id));
		store.record_failure(&id);
		assert!(!store.sessions.contains_key(&id));
		Ok(())
	}

	#[tokio::test]
	async fn unknown_id_is_not_found() {
		let store = Store::new();
		assert!(matches!(store.poll("nope", "secret", Some(0)).await, Err(Error::NotFound)));
	}

	#[tokio::test]
	async fn approve_wakes_a_waiting_poll() -> ClResult<()> {
		let store = Arc::new(Store::new());
		let (id, secret) = store.create(TnId(1), IP, ())?;
		let started = Instant::now();
		let poller = {
			let (store, id) = (store.clone(), id.clone());
			tokio::spawn(async move { store.poll(&id, &secret, Some(5)).await })
		};
		tokio::time::sleep(Duration::from_millis(50)).await;
		assert!(store.finish(&id, Some(1)).is_ok());
		let polled = poller.await.map_err(|_| Error::Internal("join".into()))?;
		assert!(matches!(polled?, Polled::Approved(1)));
		assert!(started.elapsed() < Duration::from_secs(5));
		Ok(())
	}
}

// vim: ts=4
