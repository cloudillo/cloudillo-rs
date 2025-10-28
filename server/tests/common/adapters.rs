//! Test adapter builders and helpers
//!
//! This module provides utilities for creating test instances of adapters
//! with proper temporary storage isolation.
//!
//! Each adapter has its own builder function following the pattern:
//! ```text
//! async fn create_test_<adapter_name>() -> (<Adapter>, TempDir)
//! ```
//!
//! The TempDir is returned alongside the adapter to ensure cleanup happens
//! when the TempDir is dropped at the end of the test.

// Note: Actual adapter builders are defined in their respective crates:
// - AuthAdapterSqlite: adapters/auth-adapter-sqlite/tests/phase*.rs
// - RtdbAdapterRedb: adapters/rtdb-adapter-redb/tests/integration_tests.rs
// - BlobAdapterFs: adapters/blob-adapter-fs/tests/filesystem_tests.rs
//
// This module serves as documentation for test patterns and can be extended
// with shared setup utilities if needed.

/// Common test setup helper
pub fn setup_test_logging() {
	// Optional: Initialize tracing subscriber for test debugging
	// This can be called at the start of tests that need logging output
	let _ = tracing_subscriber::fmt()
		.with_test_writer()
		.with_max_level(tracing::Level::DEBUG)
		.try_init();
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_logging_setup() {
		// Verify logging setup doesn't panic
		setup_test_logging();
	}
}
