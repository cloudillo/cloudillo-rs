//! Core subsystem. This handles the core infrascructure of Cloudillo.

pub mod acme;
pub mod app;
pub mod extract;
pub mod hasher;
pub mod request;
pub mod middleware;
pub mod scheduler;
pub mod utils;
pub mod webserver;
pub mod websocket;
pub mod worker;

pub use crate::core::extract::{IdTag, Auth};
