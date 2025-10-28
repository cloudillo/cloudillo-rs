//! Common test utilities and helpers
//!
//! This module contains shared testing infrastructure used across all integration tests.
//! It includes adapter builders, fixtures, and common test setup patterns.

pub mod adapters;
pub mod fixtures;

pub use adapters::*;
pub use fixtures::*;
