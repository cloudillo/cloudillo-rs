//! Cloudillo is open-source, self-hosted collaboration application platform.
//!
//! # Features
//!
//! - Self-contained
//!     - one binary, no dependencies
//!     - everything integrated (HTTPS, ACME, databases, etc.)
//! - Multi-tenant (users can be invited to the instance)
//! - File storage
//! - Documents with collaborative editing
//!     - real-time collaboration
//!     - generic CRDT API
//!     - word processor, spreadsheet, whiteboard app included
//! - Social/community features
//!     - profiles
//!     - posts, comments, reactions, etc.
//! - Messaging
//! - Application platform
//!     - Third party apps can be implemented

// Re-export shared types and adapter traits from cloudillo-types
pub use cloudillo_types::auth_adapter;
pub use cloudillo_types::blob_adapter;
pub use cloudillo_types::crdt_adapter;
pub use cloudillo_types::error;
pub use cloudillo_types::identity_provider_adapter;
pub use cloudillo_types::meta_adapter;
pub use cloudillo_types::rtdb_adapter;
pub use cloudillo_types::types;
pub use cloudillo_types::utils;

// Re-export the lock! macro so `$crate::error::Error` resolves correctly
// for code in this crate that uses `lock!` via cloudillo_types
pub use cloudillo_types::lock;

// Re-export additional cloudillo-types modules used by adapters
pub use cloudillo_types::action_types;
pub use cloudillo_types::hasher;
pub use cloudillo_types::worker;

// Feature crate re-exports
pub use cloudillo_action as action;
pub use cloudillo_admin as admin;
pub use cloudillo_auth as auth;
pub use cloudillo_core::scheduler;
pub use cloudillo_core::settings;
pub use cloudillo_crdt as crdt;
pub use cloudillo_email as email;
pub use cloudillo_file as file;
pub use cloudillo_idp as idp;
pub use cloudillo_profile as profile;
pub use cloudillo_proxy as proxy;
pub use cloudillo_push as push;
pub use cloudillo_ref as r#ref;
pub use cloudillo_rtdb as rtdb;

// Local modules
pub mod app;
pub mod bootstrap;
pub mod prelude;
pub mod routes;
pub mod webserver;
pub mod websocket;

pub use crate::app::{App, AppBuilder, ServerMode};

// vim: ts=4
