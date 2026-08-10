// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Core infrastructure for the Cloudillo platform.
//!
//! This crate contains shared infrastructure modules that are used by the server
//! crate and potentially by future feature crates. Extracting these into a separate
//! crate enables better build parallelism and clearer module boundaries.

pub mod abac;
pub mod acme;
pub mod app;
pub mod bootstrap_types;
pub mod bundled_apps;
pub mod core_settings;
pub mod create_perm;
pub mod dir_cache;
pub mod dns;
pub mod doc_format;
pub mod extensions;
pub mod extract;
pub mod file_access;
pub mod log;
pub mod maintenance;
pub mod middleware;
pub mod prelude;
pub mod profile_me_cache;
pub mod profile_visibility;
pub mod proxy_token_cache;
pub mod rate_limit;
pub mod request;
pub mod roles;
pub mod scheduler;
pub mod scope;
pub mod settings;
pub mod share_access;
pub mod ws_broadcast;
pub mod ws_bus;

use std::net::IpAddr;
use std::pin::Pin;

// Re-export commonly used types
pub use app::{App, AppBuilderOpts, AppState, ServerMode};
pub use dir_cache::{DirCache, DirEntry};
pub use extract::{Auth, IdTag, OptionalAuth};
pub use middleware::{PermissionCheckFactory, PermissionCheckInput, PermissionCheckOutput};
pub use profile_me_cache::ProfileMeCache;
pub use profile_visibility::{CommunityRole, RequesterTier, SectionVisibility};
pub use proxy_token_cache::ProxyTokenCache;
pub use ws_broadcast::BroadcastManager;

/// Type-erased function for verifying action tokens.
/// Registered as an extension by the server's action module.
/// Used by auth module for the token exchange flow.
pub type ActionVerifyFn = Box<
	dyn for<'a> Fn(
			&'a app::App,
			cloudillo_types::types::TnId,
			&'a str,
			Option<&'a IpAddr>,
		) -> Pin<
			Box<
				dyn Future<
						Output = cloudillo_types::error::ClResult<
							cloudillo_types::auth_adapter::ActionToken,
						>,
					> + Send
					+ 'a,
			>,
		> + Send
		+ Sync,
>;

/// Type-erased function for creating a complete tenant (bootstrap).
/// Registered as an extension by the server's bootstrap module.
/// Used by profile crate for registration and community creation.
pub type CreateCompleteTenantFn = Box<
	dyn for<'a> Fn(
			&'a app::App,
			bootstrap_types::CreateCompleteTenantOptions<'a>,
		) -> Pin<
			Box<
				dyn Future<Output = cloudillo_types::error::ClResult<cloudillo_types::types::TnId>>
					+ Send
					+ 'a,
			>,
		> + Send
		+ Sync,
>;

/// Type-erased function for creating an action.
/// Registered as an extension by the server's action module.
/// Used by profile crate for community CONN creation.
pub type CreateActionFn = Box<
	dyn for<'a> Fn(
			&'a app::App,
			cloudillo_types::types::TnId,
			&'a str,
			cloudillo_types::action_types::CreateAction,
		) -> Pin<
			Box<dyn Future<Output = cloudillo_types::error::ClResult<Box<str>>> + Send + 'a>,
		> + Send
		+ Sync,
>;

/// Type-erased hook asking for a document to be (re)indexed for full-text search.
/// Registered as an extension by the server's app module (delegates to
/// `cloudillo_search::indexer::schedule`).
///
/// Exists so storage crates can notify the search subsystem without depending on it:
/// `cloudillo-rtdb` calling `cloudillo-search` directly would be a dependency cycle,
/// since search reads documents back through the adapters.
///
/// Synchronous and infallible on purpose — the hook only enqueues a debounced task,
/// so a write path must never await or fail on it.
pub type SearchIndexFn = Box<dyn Fn(&app::App, cloudillo_types::types::TnId, &str) + Send + Sync>;

/// Type-erased hook asking for one **whole object** — a file, a profile, an action —
/// to be re-indexed. The counterpart of [`SearchIndexFn`], which covers the deep parts
/// of a document.
///
/// `obj_tp` is the `search_docs` object type: `'F'`, `'P'` or `'A'`. Same contract as
/// [`SearchIndexFn`]. Call it through [`search_index_object`] rather than looking the
/// extension up by hand.
pub type SearchObjectFn =
	Box<dyn Fn(&app::App, cloudillo_types::types::TnId, char, &str) + Send + Sync>;

/// Ask for one object's whole-object index row to be rebuilt. Prefer the three typed
/// wrappers below.
///
/// Call this right after a write that changes a column the index reads — a file's
/// `file_name`, `tags`, `status`, `visibility`, `owner_tag`, `root_id` or
/// `content_type`; a profile's `name` or `id_tag`; an action's `content`, `type`,
/// `sub_type`, `status`, `visibility` or `root_id`. Writes that only bump timestamps
/// or counters need nothing.
///
/// A no-op when the search subsystem is not wired in, so a feature crate can call it
/// unconditionally.
pub fn search_index_object(
	app: &app::App,
	tn_id: cloudillo_types::types::TnId,
	obj_tp: char,
	obj_id: &str,
) {
	if let Ok(f) = app.ext::<SearchObjectFn>() {
		f(app, tn_id, obj_tp, obj_id);
	}
}

/// [`search_index_object`] for a file.
pub fn search_index_file(app: &app::App, tn_id: cloudillo_types::types::TnId, file_id: &str) {
	search_index_object(app, tn_id, 'F', file_id);
}

/// Ask for one document's deep `'D'` index rows to be rebuilt; a no-op when the search
/// subsystem is not wired in. The counterpart of [`search_index_file`], which covers
/// the file's own row.
pub fn search_index_document(app: &app::App, tn_id: cloudillo_types::types::TnId, file_id: &str) {
	if let Ok(f) = app.ext::<SearchIndexFn>() {
		f(app, tn_id, file_id);
	}
}

/// [`search_index_object`] for a profile.
pub fn search_index_profile(app: &app::App, tn_id: cloudillo_types::types::TnId, id_tag: &str) {
	search_index_object(app, tn_id, 'P', id_tag);
}

/// [`search_index_object`] for an action.
pub fn search_index_action(app: &app::App, tn_id: cloudillo_types::types::TnId, action_id: &str) {
	search_index_object(app, tn_id, 'A', action_id);
}

/// Type-erased lookup of an action type's search manifest, resolved through the DSL
/// engine (`TYPE:SUB` first, then `TYPE`). Registered by the server's app module.
///
/// Exists for the same reason as [`SearchIndexFn`]: `cloudillo-search` must not depend
/// on `cloudillo-action`. The manifest crosses as opaque JSON, so only
/// `cloudillo-search` ever parses it.
///
/// Returns `None` when the type has no definition at all; otherwise the **resolved**
/// definition key and that definition's manifest, itself `None` for a type that is not
/// indexed. The key comes back separately so the caller can cache parsed rules under
/// it — a resolved key is one of the process's fixed definition names, whereas the
/// `(type, subType)` pair a federated action carries is not bounded by anything.
pub type ActionSearchRulesFn =
	Box<dyn Fn(&str, Option<&str>) -> Option<(Box<str>, Option<serde_json::Value>)> + Send + Sync>;

/// Parameters passed to a `ScheduleEmailFn` invocation. Mirrors
/// `cloudillo_email::EmailTaskParams` but lives in core so the ACME renewal
/// task (and other core-side tasks) can schedule emails without a cyclic
/// dependency on the email crate.
pub struct ScheduleEmailParams {
	pub to: String,
	pub template_name: String,
	pub template_vars: serde_json::Value,
	pub lang: Option<String>,
	pub custom_key: Option<String>,
	pub from_name_override: Option<String>,
}

/// Type-erased function for scheduling a templated email via the scheduler.
/// Registered as an extension by the server's app module (delegates to
/// `cloudillo_email::EmailModule::schedule_email_task`).
pub type ScheduleEmailFn = Box<
	dyn for<'a> Fn(
			&'a app::App,
			cloudillo_types::types::TnId,
			ScheduleEmailParams,
		) -> Pin<
			Box<dyn Future<Output = cloudillo_types::error::ClResult<()>> + Send + 'a>,
		> + Send
		+ Sync,
>;

/// Type-erased function invoked once the very first ACME certificate for a
/// tenant has been successfully issued. Registered by the profile crate so
/// it can flush deferred work (e.g. queueing a welcome email that requires
/// HTTPS to be usable). Called from `acme::handle_renewal_success` only when
/// the renewal row's pre-renewal `expires_at` was `None`.
///
/// **Implementations MUST be idempotent.** The hook may fire multiple times
/// for the same `tn_id`: the bootstrap path (`bootstrap.rs`) and the
/// early-retry task (`acme.rs::AcmeEarlyRetryTask`) can both observe the
/// first successful issuance after a process restart, both with
/// `is_first_issuance: true`. Implementations must dedupe — e.g. by using a
/// scheduler dedup key or a marker setting cleared after first run.
pub type OnFirstCertIssuedFn = Box<
	dyn for<'a> Fn(
			&'a app::App,
			cloudillo_types::types::TnId,
			&'a str,
		) -> Pin<
			Box<dyn Future<Output = cloudillo_types::error::ClResult<()>> + Send + 'a>,
		> + Send
		+ Sync,
>;

/// Type-erased function for ensuring a remote profile exists locally.
/// Registered as an extension by the server's app module.
/// Used by action hooks for profile sync.
pub type EnsureProfileFn = Box<
	dyn for<'a> Fn(
			&'a app::App,
			cloudillo_types::types::TnId,
			&'a str,
		) -> Pin<
			Box<dyn Future<Output = cloudillo_types::error::ClResult<bool>> + Send + 'a>,
		> + Send
		+ Sync,
>;

pub fn register_settings(
	registry: &mut settings::SettingsRegistry,
) -> cloudillo_types::error::ClResult<()> {
	core_settings::register_settings(registry)
}

// vim: ts=4
