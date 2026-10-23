// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! E-mail security alerts. [`crate::audit::record`] hands every stored event to [`notify`];
//! the alerted ones are mailed to `audit.alert_email` (Global, empty = off) through
//! [`crate::ScheduleEmailFn`] with the `security_alert` template.
//!
//! Alerted: `security.ban`; `auth.login` failures once one actor reaches
//! [`LOGIN_FAIL_THRESHOLD`] within [`WINDOW`] (fed by [`login_failed`] for every failure, not
//! from the gated audit rows); `admin.tenant.mfa_reset`, `admin.tenant.suspend`,
//! `admin.tenant.purge`; `admin.settings.change` of a global setting (`tn_id` None);
//! `admin.backup` `fail`. At most one mail per (event, tenant, setting key or actor) per
//! [`WINDOW`]; failed logins throttle per tenant, whichever actor tripped them. A change of
//! `audit.alert_email` is mailed to the previous address too, and is never throttled.

use std::collections::{HashMap, VecDeque};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::prelude::*;
use crate::{ScheduleEmailFn, ScheduleEmailParams};
use cloudillo_types::auth_adapter::{AuditCategory, AuditEvent};
use cloudillo_types::types::SHARED_TN;

/// Failed-login counting window and per-key mail throttle.
const WINDOW: Duration = Duration::from_mins(15);
const LOGIN_FAIL_THRESHOLD: u64 = 5;
/// Cap on (tenant, actor) failure windows held at once.
const MAX_TRACKED_ACTORS: usize = 10_000;
pub const ALERT_EMAIL_SETTING: &str = "audit.alert_email";

fn alerted(ev: &AuditEvent) -> bool {
	match &*ev.event {
		"security.ban"
		| "admin.tenant.mfa_reset"
		| "admin.tenant.suspend"
		| "admin.tenant.purge" => true,
		"admin.settings.change" => ev.tn_id.is_none(),
		"admin.backup" => &*ev.outcome == "fail",
		_ => false,
	}
}

/// (tenant, actor) a failed-login window is kept for.
type FailKey = (Option<u32>, Box<str>);

// In-process counters, reset on restart and not shared across nodes; persist them
// in the auth db if alerts must survive restarts.
#[derive(Default)]
struct AlertState {
	/// Per (tenant, actor): failures in the window.
	fails: HashMap<FailKey, VecDeque<Instant>>,
	/// Per throttle key (see [`throttle_key`]): when the last mail was queued.
	last_sent: HashMap<String, Instant>,
}

/// Event, tenant and the settings key (or else the actor), so distinct settings each alert.
/// Failed logins: tenant only, so a spray over many usernames mails once. `None` (a change
/// of the alert address, carrying `prevAlertEmail`) is never throttled.
fn throttle_key(ev: &AuditEvent) -> Option<String> {
	let detail = |k| ev.details.as_ref().and_then(|d| d.get(k)).and_then(serde_json::Value::as_str);
	if detail("prevAlertEmail").is_some() {
		return None;
	}
	let tn = ev.tn_id.map(|t| t.0);
	if &*ev.event == "auth.login" {
		return Some(format!("auth.login.fail:{tn:?}"));
	}
	let subject = detail("key").or(ev.actor.as_deref()).unwrap_or_default();
	Some(format!("{}:{tn:?}:{subject}", ev.event))
}

impl AlertState {
	/// Whether `ev` should be mailed now (alerted, and its throttle key not sent recently).
	fn decide(&mut self, ev: &AuditEvent, now: Instant) -> bool {
		alerted(ev) && self.unthrottled(ev, now)
	}

	/// Count one failed login; `Some(failures)` once the actor reaches the threshold and the
	/// alert is not throttled.
	fn login_failed(&mut self, ev: &AuditEvent, now: Instant) -> Option<u64> {
		self.fails.retain(|_, q| {
			while q.front().is_some_and(|t| now.duration_since(*t) >= WINDOW) {
				q.pop_front();
			}
			!q.is_empty()
		});
		let key = (ev.tn_id.map(|t| t.0), ev.actor.clone().unwrap_or_default());
		// Hard cap on tracked actors, sprays beyond it go uncounted; per-tenant
		// counter if that matters
		if self.fails.len() >= MAX_TRACKED_ACTORS && !self.fails.contains_key(&key) {
			return None;
		}
		let q = self.fails.entry(key.clone()).or_default();
		q.push_back(now);
		let count = q.len() as u64;
		if count < LOGIN_FAIL_THRESHOLD {
			return None;
		}
		self.fails.remove(&key);
		self.unthrottled(ev, now).then_some(count)
	}

	/// Undo the throttle mark of `ev` after its mail failed to queue, so the next one sends.
	fn release(&mut self, ev: &AuditEvent) {
		if let Some(key) = throttle_key(ev) {
			self.last_sent.remove(&key);
		}
	}

	fn unthrottled(&mut self, ev: &AuditEvent, now: Instant) -> bool {
		self.last_sent.retain(|_, t| now.duration_since(*t) < WINDOW);
		let Some(key) = throttle_key(ev) else {
			return true;
		};
		if self.last_sent.contains_key(&key) {
			return false;
		}
		self.last_sent.insert(key, now);
		true
	}
}

static STATE: LazyLock<Mutex<AlertState>> = LazyLock::new(Mutex::default);

/// Queue a security alert for `ev` if it is one. Runs in a spawned task; never fails the caller.
pub(crate) fn notify(app: &App, ev: &AuditEvent) {
	if !alerted(ev) {
		return;
	}
	spawn_send(app, ev.clone(), false);
}

/// Count a failed login for `actor`, whether or not its audit row was written (the auth layer
/// collapses failure rows per minute). Alerts once the actor reaches the threshold.
pub fn login_failed(app: &App, tn_id: Option<TnId>, actor: &str, ip: &str) {
	let ev = AuditEvent {
		tn_id,
		actor: Some(actor.into()),
		ip: Some(ip.into()),
		..AuditEvent::new(AuditCategory::Auth, "auth.login", "fail")
	};
	spawn_send(app, ev, true);
}

/// `login` routes `ev` through the failed-login counter instead of [`AlertState::decide`].
fn spawn_send(app: &App, ev: AuditEvent, login: bool) {
	let app = app.clone();
	tokio::spawn(async move {
		if let Err(e) = send(&app, &ev, login).await {
			warn!(error = %e, event = &*ev.event, "security alert: failed to queue e-mail");
		}
	});
}

/// The configured address plus, for a change of the address itself, the previous one
/// (`details.prevAlertEmail`). Trimmed, empty dropped, deduplicated.
fn recipients(current: &str, ev: &AuditEvent) -> Vec<String> {
	let prev = ev
		.details
		.as_ref()
		.and_then(|d| d.get("prevAlertEmail"))
		.and_then(serde_json::Value::as_str);
	let mut out: Vec<String> = Vec::new();
	for to in std::iter::once(current).chain(prev).map(str::trim) {
		if !to.is_empty() && !out.iter().any(|o| o == to) {
			out.push(to.to_string());
		}
	}
	out
}

async fn send(app: &App, ev: &AuditEvent, login: bool) -> ClResult<()> {
	let current = app
		.settings
		.get_string_opt(SHARED_TN, ALERT_EMAIL_SETTING)
		.await?
		.unwrap_or_default();
	let to = recipients(&current, ev);
	if to.is_empty() {
		return Ok(());
	}
	let schedule_email = app.ext::<ScheduleEmailFn>()?;
	let failures = {
		let mut state = STATE.lock();
		if login {
			let Some(n) = state.login_failed(ev, Instant::now()) else {
				return Ok(());
			};
			n
		} else {
			if !state.decide(ev, Instant::now()) {
				return Ok(());
			}
			0
		}
	};
	let base_id_tag = app.opts.base_id_tag.as_ref().map_or("cloudillo", AsRef::as_ref);
	let template_vars = serde_json::json!({
		"event": &*ev.event,
		"outcome": &*ev.outcome,
		"category": ev.category.as_str(),
		"tnId": ev.tn_id.map(|t| t.0),
		"actor": ev.actor.as_deref(),
		"ip": ev.ip.as_deref(),
		"time": ev.ts.to_iso_string(),
		"failures": (failures > 0).then_some(failures),
		"details": ev.details.as_ref().map(serde_json::Value::to_string),
		"base_id_tag": base_id_tag,
		"instance_name": "Cloudillo",
	});
	for (i, to) in to.into_iter().enumerate() {
		let params = ScheduleEmailParams {
			custom_key: Some(format!("security-alert:{}:{}:{}", ev.event, ev.ts.0, to)),
			to,
			template_name: "security_alert".to_string(),
			template_vars: template_vars.clone(),
			lang: None,
			from_name_override: Some(format!("Cloudillo | {}", base_id_tag.to_uppercase())),
		};
		if let Err(e) = schedule_email(app, SHARED_TN, params).await {
			// Release the throttle only if nothing was queued: a retry after a partial send
			// would mail the earlier recipients again.
			if i == 0 {
				STATE.lock().release(ev);
			}
			return Err(e);
		}
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	fn fail(actor: &str) -> AuditEvent {
		AuditEvent {
			tn_id: Some(TnId(1)),
			actor: Some(actor.into()),
			..AuditEvent::new(AuditCategory::Auth, "auth.login", "fail")
		}
	}

	fn setting(key: &str, prev: Option<&str>) -> AuditEvent {
		AuditEvent {
			details: Some(serde_json::json!({ "key": key, "prevAlertEmail": prev })),
			..AuditEvent::new(AuditCategory::Admin, "admin.settings.change", "success")
		}
	}

	#[test]
	fn alert_rules() {
		let mut s = AlertState::default();
		let t0 = Instant::now();
		// Four failures stay quiet; the fifth alerts with the count.
		for _ in 0..4 {
			assert_eq!(s.login_failed(&fail("bob"), t0), None);
		}
		assert_eq!(s.login_failed(&fail("bob"), t0), Some(5));
		// The next five are throttled; after the window they alert again.
		for _ in 0..5 {
			assert_eq!(s.login_failed(&fail("bob"), t0), None);
		}
		for _ in 0..4 {
			assert_eq!(s.login_failed(&fail("bob"), t0 + WINDOW), None);
		}
		assert_eq!(s.login_failed(&fail("bob"), t0 + WINDOW), Some(5));

		// Failures older than the window drop out; other actors count separately.
		let mut s = AlertState::default();
		for _ in 0..3 {
			assert_eq!(s.login_failed(&fail("a"), t0), None);
		}
		assert_eq!(s.login_failed(&fail("b"), t0 + WINDOW), None);
		assert_eq!(s.login_failed(&fail("a"), t0 + WINDOW), None);

		// Event set.
		let ev = |event: &str, outcome: &str, tn: Option<TnId>| AuditEvent {
			tn_id: tn,
			..AuditEvent::new(AuditCategory::Admin, event, outcome)
		};
		let mut s = AlertState::default();
		assert!(!s.decide(&ev("admin.settings.change", "success", Some(TnId(1))), t0));
		assert!(s.decide(&ev("admin.settings.change", "success", None), t0));
		assert!(!s.decide(&ev("admin.settings.change", "success", None), t0));
		assert!(!s.decide(&ev("admin.backup", "success", None), t0));
		assert!(s.decide(&ev("admin.backup", "fail", None), t0));
		assert!(!s.decide(&ev("admin.tenant.resume", "success", None), t0));
		for e in [
			"security.ban",
			"admin.tenant.mfa_reset",
			"admin.tenant.suspend",
			"admin.tenant.purge",
		] {
			assert!(s.decide(&ev(e, "success", None), t0), "{e}");
		}
		// Login failures alert only through the counter.
		assert!(!s.decide(&fail("bob"), t0));

		// Settings changes throttle per key.
		let mut s = AlertState::default();
		assert!(s.decide(&setting("a.x", None), t0));
		assert!(s.decide(&setting("a.y", None), t0));
		assert!(!s.decide(&setting("a.x", None), t0));
		// Throttle entries expire with the window.
		assert_eq!(s.last_sent.len(), 2);
		assert!(s.decide(&setting("a.z", None), t0 + WINDOW));
		assert_eq!(s.last_sent.len(), 1);

		// Alert-address changes always send, even back to back.
		let mut s = AlertState::default();
		assert!(s.decide(&setting(ALERT_EMAIL_SETTING, Some("old@x")), t0));
		assert!(s.decide(&setting(ALERT_EMAIL_SETTING, Some("older@x")), t0));

		// A spray over many usernames mails once per tenant.
		let mut s = AlertState::default();
		let mut sent = 0;
		for i in 0..20 {
			for _ in 0..5 {
				sent += usize::from(s.login_failed(&fail(&format!("u{i}")), t0).is_some());
			}
		}
		assert_eq!(sent, 1);
		let other = AuditEvent { tn_id: Some(TnId(2)), ..fail("u0") };
		for _ in 0..4 {
			assert_eq!(s.login_failed(&other, t0), None);
		}
		assert_eq!(s.login_failed(&other, t0), Some(5));

		// Tracked actors are capped: a new actor past the cap is not counted.
		let mut s = AlertState::default();
		for i in 0..MAX_TRACKED_ACTORS {
			assert_eq!(s.login_failed(&fail(&format!("u{i}")), t0), None);
		}
		for _ in 0..5 {
			assert_eq!(s.login_failed(&fail("late"), t0), None);
		}
		assert_eq!(s.fails.len(), MAX_TRACKED_ACTORS);
	}

	#[test]
	fn release_reopens_the_throttle() {
		let mut s = AlertState::default();
		let t0 = Instant::now();
		let ev = setting("a.x", None);
		assert!(s.decide(&ev, t0));
		s.release(&ev);
		assert!(s.decide(&ev, t0), "a failed send must not suppress the next alert");
	}

	#[test]
	fn alert_recipients() {
		let ev = setting(ALERT_EMAIL_SETTING, Some("old@x"));
		assert_eq!(recipients("new@x", &ev), ["new@x", "old@x"]);
		assert_eq!(recipients("", &ev), ["old@x"]);
		assert_eq!(recipients(" old@x ", &ev), ["old@x"]);
		assert!(recipients("", &setting("a.x", None)).is_empty());
	}
}

// vim: ts=4
