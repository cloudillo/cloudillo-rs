//! Cloudillo is open-source, self-hosted collaboration application platform.
//!
//! # Features
//!
//! - Self-contained
//!		- one binary, no dependencies
//!		- everything integrated (HTTPS, ACME, databases, etc.)
//!	- Multi-tenant (users can be invited to the instance)
//!	- File storage
//!	- Documents with collaborative editing
//!		- real-time collaboration
//!		- generic CRDT API
//!		- word processor, spreadsheet, whiteboard app included
//!	- Social/community features
//!		- profiles
//!		- posts, comments, reactions, etc.
//!	- Messaging
//!	- Application platform
//!		- Third party apps can be implemented

#![allow(unused_attributes, dead_code)]
#![forbid(unsafe_code)]
#[allow(clippy::all)]

pub mod action;
pub mod auth;
pub mod auth_adapter;
pub mod blob_adapter;
pub mod core;
pub mod crdt;
pub mod crdt_adapter;
pub mod error;
pub mod file;
pub mod meta_adapter;
pub mod prelude;
pub mod profile;
pub mod r#ref;
pub mod routes;
pub mod rtdb;
pub mod rtdb_adapter;
pub mod settings;
pub mod types;

pub use crate::core::app::{App, AppBuilder, ServerMode};

// vim: ts=4
