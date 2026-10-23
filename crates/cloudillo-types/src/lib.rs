// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Shared types, adapter traits, and core utilities for the Cloudillo platform.
//!
//! This crate contains the foundational types that are shared between the
//! server crate and all adapter implementations. Extracting these into a
//! separate crate allows adapter crates to compile in parallel with the
//! server's feature modules.

pub mod abac;
pub mod action_types;
pub mod address;
pub mod auth_adapter;
pub mod blob_adapter;
pub mod crdt_adapter;
pub mod error;
pub mod extract;
pub mod hasher;
pub mod identity_provider_adapter;
pub mod meta_adapter;
pub mod prelude;
pub mod reactions;
pub mod roles;
pub mod rtdb_adapter;
pub mod secret_box;
pub mod site;
pub mod snapshot;
pub mod types;
pub mod utils;
pub mod validation;
pub mod worker;

// vim: ts=4
