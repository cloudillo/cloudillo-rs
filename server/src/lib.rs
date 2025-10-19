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

pub mod error;
pub mod core;
pub mod action;
pub mod auth;
pub mod file;
pub mod profile;
pub mod auth_adapter;
pub mod blob_adapter;
pub mod meta_adapter;
pub mod prelude;
pub mod types;
pub mod routes;

pub use crate::core::app::{App, AppBuilder, ServerMode};

// vim: ts=4
