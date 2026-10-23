// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Audit trail: the single write path (`record`), its settings, and the retention purge.
//!
//! Every event goes to the `audit` tracing target (for SIEM/journald shipping) and to the
//! `audit_event` table of the auth adapter. `auth` and `admin` events are always recorded;
//! `sharing` and `access` only when enabled in `audit.categories` (server-wide) or
//! `audit.tenant_categories` (the event's tenant). A failed write is logged, never returned.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::prelude::*;
use crate::scheduler::{Task, TaskId};
use crate::settings::{
	PermissionLevel, SettingDefinition, SettingScope, SettingValue, SettingsRegistry,
};
use cloudillo_types::auth_adapter::{AuditCategory, AuditEvent, AuditEventRow, AuditQuery};
use cloudillo_types::types::SHARED_TN;

const DEFAULT_RETENTION_DAYS: i64 = 365;
const PURGE_CRON: &str = "40 4 * * *";
/// `actor` and `details` can come from the request (e.g. a login id_tag): keep rows bounded.
const MAX_ACTOR_CHARS: usize = 128;
const MAX_DETAILS_BYTES: usize = 4096;
/// Page size of the audit list APIs
pub const DEFAULT_LIMIT: u32 = 100;
pub const MAX_LIMIT: u32 = 1000;

/// Clamp `actor` and drop oversized `details`; returns the serialized `details`.
fn bound(ev: &mut AuditEvent) -> Option<String> {
	if ev.actor.as_deref().is_some_and(|a| a.chars().nth(MAX_ACTOR_CHARS).is_some()) {
		ev.actor = ev
			.actor
			.as_deref()
			.map(|a| a.chars().take(MAX_ACTOR_CHARS).collect::<String>().into());
	}
	let details = ev.details.as_ref().map(serde_json::Value::to_string);
	if details.as_ref().is_some_and(|d| d.len() > MAX_DETAILS_BYTES) {
		let truncated = serde_json::json!({ "truncated": true });
		let s = truncated.to_string();
		ev.details = Some(truncated);
		return Some(s);
	}
	details
}

/// Record `ev` as done by `actor` (`None` = anonymous) from `addr`.
pub async fn record_by(app: &App, mut ev: AuditEvent, actor: Option<&str>, addr: &SocketAddr) {
	ev.actor = actor.map(Into::into);
	ev.ip = Some(ip_of(addr));
	record(app, ev).await;
}

/// Record one event of `category` as done by `actor` (`None` = anonymous) from `addr`.
#[expect(clippy::too_many_arguments, reason = "every field of the audit row")]
pub async fn record_event(
	app: &App,
	category: AuditCategory,
	event: &str,
	outcome: &str,
	tn_id: Option<TnId>,
	actor: Option<&str>,
	addr: &SocketAddr,
	details: Option<serde_json::Value>,
) {
	let ev = AuditEvent { tn_id, details, ..AuditEvent::new(category, event, outcome) };
	record_by(app, ev, actor, addr).await;
}

/// Record one audit event. Never fails the caller: errors are logged with `warn!`.
pub async fn record(app: &App, ev: AuditEvent) {
	if matches!(ev.category, AuditCategory::Sharing | AuditCategory::Access)
		&& !category_enabled(app, ev.category, ev.tn_id).await
	{
		return;
	}

	let mut ev = ev;
	let details = bound(&mut ev);
	info!(
		target: "audit",
		tn_id = ev.tn_id.map(|t| t.0),
		actor = ev.actor.as_deref(),
		event = &*ev.event,
		category = ev.category.as_str(),
		ip = ev.ip.as_deref(),
		outcome = &*ev.outcome,
		details = details.as_deref(),
		"audit event"
	);

	if let Err(e) = app.auth_adapter.append_audit_event(&ev).await {
		warn!(error = %e, event = &*ev.event, "audit: failed to store event");
	}
	crate::alert::notify(app, &ev);
}

/// The `category` query parameter of the audit list APIs.
pub fn parse_category(c: Option<&str>) -> ClResult<Option<AuditCategory>> {
	c.map(|c| {
		AuditCategory::parse(c)
			.ok_or_else(|| Error::ValidationError("unknown audit category".into()))
	})
	.transpose()
}

/// The `limit` query parameter of the audit list APIs.
pub fn page_limit(l: Option<u32>) -> u32 {
	l.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
}

/// One page of `q`, plus the cursor of the next page (`None` = this was the last one).
pub async fn list_page(
	app: &App,
	mut q: AuditQuery,
) -> ClResult<(Vec<AuditEventRow>, Option<i64>)> {
	let limit = q.limit.unwrap_or(DEFAULT_LIMIT);
	// One extra row tells whether another page exists, so no cursor leads to an empty page
	q.limit = Some(limit.saturating_add(1));
	let mut rows = app.auth_adapter.list_audit_events(&q).await?;
	if rows.len() > limit as usize {
		rows.truncate(limit as usize);
		let next = rows.last().map(|r| r.id);
		return Ok((rows, next));
	}
	Ok((rows, None))
}

/// Client IP as stored in `AuditEvent::ip`.
pub fn ip_of(addr: &SocketAddr) -> Box<str> {
	addr.ip().to_string().into()
}

/// Effective set = `audit.categories` (global) ∪ `audit.tenant_categories` (event tenant).
/// Both reads hit the settings cache, so a disabled category costs no DB read.
async fn category_enabled(app: &App, cat: AuditCategory, tn_id: Option<TnId>) -> bool {
	let name = cat.as_str();
	let contains = |v: ClResult<serde_json::Value>| {
		v.ok()
			.and_then(|v| v.as_array().map(|a| a.iter().any(|c| c.as_str() == Some(name))))
			.unwrap_or(false)
	};
	if contains(app.settings.get_json(SHARED_TN, "audit.categories").await) {
		return true;
	}
	match tn_id {
		Some(tn_id) => contains(app.settings.get_json(tn_id, "audit.tenant_categories").await),
		None => false,
	}
}

/// A JSON array whose elements are each `"sharing"` or `"access"`.
fn categories_validator(v: &SettingValue) -> ClResult<()> {
	let ok = match v {
		SettingValue::Json(serde_json::Value::Array(a)) => {
			a.iter().all(|c| matches!(c.as_str(), Some("sharing" | "access")))
		}
		_ => false,
	};
	if ok {
		Ok(())
	} else {
		Err(Error::ValidationError(
			"Audit categories must be a JSON array of \"sharing\" and/or \"access\"".into(),
		))
	}
}

pub fn register_settings(registry: &mut SettingsRegistry) -> ClResult<()> {
	registry.register(
		SettingDefinition::builder("audit.categories")
			.description(
				"Optional audit categories recorded for every tenant (auth and admin are \
				 always recorded): JSON array of \"sharing\" and/or \"access\"",
			)
			.default(SettingValue::Json(serde_json::json!(["sharing"])))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.validator(categories_validator)
			.build()?,
	)?;
	registry.register(
		SettingDefinition::builder("audit.tenant_categories")
			.description(
				"Additional audit categories recorded for this tenant, on top of the \
				 server-wide ones: JSON array of \"sharing\" and/or \"access\"",
			)
			.default(SettingValue::Json(serde_json::json!([])))
			.scope(SettingScope::Tenant)
			// Admin: `access` adds an awaited insert into the shared auth.db to every file
			// and doc open, a cost one tenant must not impose on the whole node
			.permission(PermissionLevel::Admin)
			.validator(categories_validator)
			.build()?,
	)?;
	registry.register(
		SettingDefinition::builder("audit.retention_days")
			.description("Days to keep audit events before the nightly purge deletes them")
			.default(SettingValue::Int(DEFAULT_RETENTION_DAYS))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.validator(|v| match v {
				SettingValue::Int(n) if *n >= 1 => Ok(()),
				_ => Err(Error::ValidationError(
					"Audit retention must be a positive number of days".into(),
				)),
			})
			.build()?,
	)?;
	registry.register(
		SettingDefinition::builder(crate::alert::ALERT_EMAIL_SETTING)
			.description("E-mail address for security alerts (empty = off)")
			.default(SettingValue::String(String::new()))
			.scope(SettingScope::Global)
			.permission(PermissionLevel::Admin)
			.build()?,
	)?;
	Ok(())
}

/// Nightly purge of audit events older than `audit.retention_days`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AuditPurgeTask;

#[async_trait]
impl Task<App> for AuditPurgeTask {
	fn kind() -> &'static str {
		"core.audit_purge"
	}
	fn kind_of(&self) -> &'static str {
		Self::kind()
	}

	fn build(_id: TaskId, _ctx: &str) -> ClResult<Arc<dyn Task<App>>> {
		Ok(Arc::new(AuditPurgeTask))
	}

	fn serialize(&self) -> String {
		String::new()
	}

	async fn run(&self, app: &App) -> ClResult<()> {
		let days = app
			.settings
			.get_int_opt(SHARED_TN, "audit.retention_days")
			.await
			.ok()
			.flatten()
			.unwrap_or(DEFAULT_RETENTION_DAYS)
			.max(1);
		let before = Timestamp::now().add_seconds(-days.saturating_mul(86_400));
		match app.auth_adapter.purge_audit_events(before).await {
			Ok(n) => info!(deleted = n, retention_days = days, "audit: purge complete"),
			Err(e) => warn!(error = %e, "audit: purge failed"),
		}
		Ok(())
	}
}

/// Register the purge task kind. Must run before the scheduler loads persisted tasks.
pub fn init(app: &App) -> ClResult<()> {
	app.scheduler.register::<AuditPurgeTask>()?;
	Ok(())
}

/// Schedule the nightly purge (04:40, after file GC and DB maintenance).
pub async fn schedule(app: &App) -> ClResult<()> {
	let task: Arc<dyn Task<App>> = Arc::new(AuditPurgeTask);
	app.scheduler
		.task(task)
		.key("core.audit_purge")
		.cron(PURGE_CRON)
		.run_on_startup()
		.schedule()
		.await?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn categories_validator_accepts_only_optional_categories() {
		let j = SettingValue::Json;
		assert!(categories_validator(&j(serde_json::json!([]))).is_ok());
		assert!(categories_validator(&j(serde_json::json!(["sharing", "access"]))).is_ok());
		assert!(categories_validator(&j(serde_json::json!(["auth"]))).is_err());
		assert!(categories_validator(&j(serde_json::json!("sharing"))).is_err());
		assert!(categories_validator(&SettingValue::String("sharing".into())).is_err());
	}

	#[test]
	fn bound_clamps_actor_and_details() {
		let mut ev = AuditEvent::new(AuditCategory::Auth, "auth.login", "fail");
		ev.actor = Some("é".repeat(1000).into());
		ev.details = Some(serde_json::json!({ "x": "a".repeat(5000) }));
		let details = bound(&mut ev);
		assert_eq!(ev.actor.as_deref().map(|a| a.chars().count()), Some(MAX_ACTOR_CHARS));
		assert_eq!(ev.details, Some(serde_json::json!({ "truncated": true })));
		assert_eq!(details.as_deref(), Some(r#"{"truncated":true}"#));

		let mut ev = AuditEvent::new(AuditCategory::Auth, "auth.login", "fail");
		ev.actor = Some("alice".into());
		ev.details = Some(serde_json::json!({ "method": "mfa" }));
		bound(&mut ev);
		assert_eq!(ev.actor.as_deref(), Some("alice"));
		assert_eq!(ev.details, Some(serde_json::json!({ "method": "mfa" })));
	}

	#[test]
	fn query_params() {
		assert_eq!(page_limit(None), DEFAULT_LIMIT);
		assert_eq!(page_limit(Some(0)), 1);
		assert_eq!(page_limit(Some(u32::MAX)), MAX_LIMIT);
		assert_eq!(parse_category(None).ok(), Some(None));
		assert_eq!(parse_category(Some("auth")).ok(), Some(Some(AuditCategory::Auth)));
		assert!(parse_category(Some("bogus")).is_err());
	}
}

// vim: ts=4
