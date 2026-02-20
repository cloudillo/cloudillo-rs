#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod prelude;
pub mod websocket;

pub use websocket::handle_crdt_connection;

// vim: ts=4
