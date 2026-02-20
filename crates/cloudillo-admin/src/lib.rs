//! Admin API handlers for system administration

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

pub mod email;
pub mod invite;
pub mod perm;
pub mod tenant;

mod prelude;

// vim: ts=4
