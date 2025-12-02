//! Core subsystem. This handles the core infrascructure of Cloudillo.

pub mod abac;
pub mod acme;
pub mod address;
pub mod app;
pub mod create_perm;
pub mod dns;
pub mod extract;
pub mod file_access;
pub mod hasher;
pub mod middleware;
pub mod rate_limit;
pub mod request;
pub mod roles;
pub mod scheduler;
pub mod settings;
pub mod utils;
pub mod webserver;
pub mod websocket;
pub mod worker;
pub mod ws_broadcast;
pub mod ws_bus;

pub use crate::core::extract::{Auth, IdTag, OptionalAuth};
pub use crate::core::middleware::{
	PermissionCheckFactory, PermissionCheckInput, PermissionCheckOutput,
};
pub use crate::core::ws_broadcast::BroadcastManager;
