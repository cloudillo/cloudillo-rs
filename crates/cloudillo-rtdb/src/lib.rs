#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

pub(crate) mod aggregate;
pub(crate) mod computed;
pub(crate) mod merge;
pub mod websocket;

mod prelude;

pub use websocket::handle_rtdb_connection;

// vim: ts=4
