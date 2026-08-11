// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

pub(crate) mod aggregate;
pub(crate) mod computed;
pub(crate) mod merge;
pub(crate) mod presence;
pub mod websocket;

mod prelude;

pub use websocket::handle_rtdb_connection;

// vim: ts=4
