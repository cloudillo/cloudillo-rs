//! CRDT (Conflict-free Replicated Data Type) subsystem.
//!
//! This module handles CRDT synchronization via WebSocket connections.

pub mod websocket;

pub use websocket::handle_crdt_connection;
