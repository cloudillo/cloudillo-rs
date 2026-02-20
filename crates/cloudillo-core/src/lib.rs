//! Core infrastructure for the Cloudillo platform.
//!
//! This crate contains shared infrastructure modules that are used by the server
//! crate and potentially by future feature crates. Extracting these into a separate
//! crate enables better build parallelism and clearer module boundaries.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

pub mod abac;
pub mod acme;
pub mod app;
pub mod bootstrap_types;
pub mod core_settings;
pub mod create_perm;
pub mod dns;
pub mod extensions;
pub mod extract;
pub mod file_access;
pub mod middleware;
pub mod prelude;
pub mod rate_limit;
pub mod request;
pub mod roles;
pub mod scheduler;
pub mod settings;
pub mod ws_broadcast;
pub mod ws_bus;

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

// Re-export commonly used types
pub use app::{App, AppBuilderOpts, AppState, ServerMode};
pub use extract::{Auth, IdTag, OptionalAuth};
pub use middleware::{PermissionCheckFactory, PermissionCheckInput, PermissionCheckOutput};
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
