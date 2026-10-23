// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Federation peer policy (`federation.peers`): which remote identities this instance
//! exchanges federation traffic with, in both directions.
//!
//! Outbound, every [`crate::request::Request`] call checks the target before it builds the
//! URL. Inbound, `cloudillo_action::process::verify_action_token` checks the issuer before
//! the key fetch. ACME and DNS lookups are not federation and are not covered.

use serde::Deserialize;

use crate::prelude::*;
use crate::settings::SettingValue;
use crate::settings::service::SettingsService;
use cloudillo_types::auth_adapter::AuthAdapter;
use cloudillo_types::types::SHARED_TN;
use cloudillo_types::validation::canonicalize_dns_host;

/// Global/Admin setting key holding the [`PeerPolicy`] JSON.
pub const PEERS_SETTING: &str = "federation.peers";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerMode {
	Open,
	Allowlist,
	Off,
}

/// `{"mode": "open"|"allowlist"|"off", "allow": ["id.tag", "*.domain"]}`
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerPolicy {
	pub mode: PeerMode,
	#[serde(default)]
	pub allow: Vec<String>,
}

/// Whether `policy` admits the peer `id_tag`. `off` is `allowlist` with an empty list.
/// `*.example.hu` matches any id_tag ending in `.example.hu`, not the apex `example.hu`.
pub fn peer_allowed(policy: &PeerPolicy, id_tag: &str) -> bool {
	match policy.mode {
		PeerMode::Open => true,
		PeerMode::Off => false,
		PeerMode::Allowlist => policy.allow.iter().any(|entry| match entry.strip_prefix('*') {
			Some(suffix) => id_tag.ends_with(suffix),
			None => entry == id_tag,
		}),
	}
}

/// Setting validator for `federation.peers`: known mode, every entry a canonical id_tag or
/// `*.` followed by one.
pub fn peers_validator(v: &SettingValue) -> ClResult<()> {
	let SettingValue::Json(json) = v else {
		return Err(Error::ValidationError("federation.peers must be a JSON object".into()));
	};
	let policy: PeerPolicy = serde_json::from_value(json.clone())
		.map_err(|e| Error::ValidationError(format!("invalid federation.peers: {e}")))?;
	// A DNS host, not an id_tag: a suffix such as `*.hu` is below the id_tag length policy.
	for entry in &policy.allow {
		let host = entry.strip_prefix("*.").unwrap_or(entry);
		if !canonicalize_dns_host(host).is_ok_and(|c| c == host) {
			return Err(Error::ValidationError(format!("invalid federation.peers entry: {entry}")));
		}
	}
	Ok(())
}

/// Refuse a federation peer the instance policy does not admit (`PermissionDenied`).
///
/// Tenants hosted on this instance are not federation peers: their traffic still goes over
/// HTTPS and through `verify_action_token`, so they always pass, whatever the mode.
pub async fn check_peer(
	settings: &SettingsService,
	auth_adapter: &dyn AuthAdapter,
	id_tag: &str,
) -> ClResult<()> {
	let json = settings.get_json(SHARED_TN, PEERS_SETTING).await?;
	let policy: PeerPolicy = serde_json::from_value(json)
		.map_err(|e| Error::ConfigError(format!("invalid federation.peers: {e}")))?;
	if peer_allowed(&policy, id_tag) || auth_adapter.read_tn_id(id_tag).await.is_ok() {
		return Ok(());
	}
	warn!(peer = %id_tag, "federation peer refused by federation.peers policy");
	Err(Error::PermissionDenied)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn policy(v: serde_json::Value) -> PeerPolicy {
		serde_json::from_value(v).unwrap()
	}

	#[test]
	fn open_admits_everyone() {
		let p = policy(serde_json::json!({"mode": "open"}));
		assert!(peer_allowed(&p, "anyone.example.com"));
	}

	#[test]
	fn off_admits_nobody_even_if_listed() {
		let p = policy(serde_json::json!({"mode": "off", "allow": ["a.example.hu"]}));
		assert!(!peer_allowed(&p, "a.example.hu"));
	}

	#[test]
	fn allowlist_exact_and_wildcard() {
		let p = policy(
			serde_json::json!({"mode": "allowlist", "allow": ["exact.org", "*.example.hu"]}),
		);
		assert!(peer_allowed(&p, "exact.org"));
		assert!(!peer_allowed(&p, "sub.exact.org"));
		assert!(peer_allowed(&p, "alice.example.hu"));
		assert!(peer_allowed(&p, "a.b.example.hu"));
		assert!(!peer_allowed(&p, "example.hu"));
		assert!(!peer_allowed(&p, "evilexample.hu"));
		assert!(!peer_allowed(&p, "other.org"));
	}

	#[test]
	fn validator_rejects_bad_values() {
		let ok = |v| peers_validator(&SettingValue::Json(v)).is_ok();
		assert!(ok(serde_json::json!({"mode": "open", "allow": []})));
		assert!(ok(serde_json::json!({"mode": "allowlist", "allow": ["a.hu", "*.example.hu"]})));
		assert!(!ok(serde_json::json!({"mode": "closed"})));
		assert!(!ok(serde_json::json!({"allow": []})));
		assert!(!ok(serde_json::json!({"mode": "open", "extra": 1})));
		assert!(!ok(serde_json::json!({"mode": "allowlist", "allow": ["*example.hu"]})));
		assert!(!ok(serde_json::json!({"mode": "allowlist", "allow": ["a/b"]})));
		assert!(!ok(serde_json::json!({"mode": "allowlist", "allow": ["Upper.hu"]})));
		assert!(peers_validator(&SettingValue::String("open".into())).is_err());
	}
}

// vim: ts=4
