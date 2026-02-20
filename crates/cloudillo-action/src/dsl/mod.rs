//! Action DSL (Domain-Specific Language) for declarative action type definitions
//!
//! This module provides a JSON-based DSL for defining federated social action types
//! without writing Rust code. It replaces hardcoded action type implementations with
//! a runtime-configurable, declarative system.

pub mod definitions;
pub mod engine;
pub mod expression;
pub mod operations;
pub mod types;
pub mod validator;

pub use crate::hooks::HookType;
pub use engine::DslEngine;
pub use types::*;

// vim: ts=4
