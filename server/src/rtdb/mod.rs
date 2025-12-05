//! RTDB (Real-Time Database) subsystem.
//!
//! This module handles the real-time database functionality including
//! WebSocket connections, computed values, and database operations.

pub mod computed;
pub mod merge;
pub mod websocket;

pub use websocket::handle_rtdb_connection;
