//! Common types used throughout the Cloudillo platform.

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

use crate::prelude::*;

// TnId //
//******//
//pub type TnId = u32;
#[derive(Clone, Copy, Debug)]
pub struct TnId(pub u32);

impl std::fmt::Display for TnId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl std::cmp::PartialEq for TnId {
	fn eq(&self, other: &Self) -> bool {
		self.0 == other.0
	}
}

impl Serialize for TnId {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		serializer.serialize_u32(self.0)
	}
}

impl<'de> Deserialize<'de> for TnId {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		Ok(TnId(u32::deserialize(deserializer)?))
	}
}

// Timestamp //
//***********//
//pub type Timestamp = u32;
#[derive(Clone, Copy, Debug, Default)]
pub struct Timestamp(pub i64);

impl std::fmt::Display for Timestamp {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl std::cmp::PartialEq for Timestamp {
	fn eq(&self, other: &Self) -> bool {
		self.0 == other.0
	}
}

impl std::cmp::PartialOrd for Timestamp {
	fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
		self.0.partial_cmp(&other.0)
	}
}

impl std::cmp::Eq for Timestamp {}

impl std::cmp::Ord for Timestamp {
	fn cmp(&self, other: &Self) -> std::cmp::Ordering {
		self.0.cmp(&other.0)
	}
}

impl Serialize for Timestamp {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		serializer.serialize_i64(self.0)
	}
}

impl<'de> Deserialize<'de> for Timestamp {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		Ok(Timestamp(i64::deserialize(deserializer)?))
	}
}

pub fn now() -> Timestamp {
	let res = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
	Timestamp(res.as_secs() as i64)
}

// vim: ts=4
