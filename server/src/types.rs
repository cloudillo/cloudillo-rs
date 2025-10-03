use serde::Serialize;
use std::time::SystemTime;

use crate::prelude::*;

pub type TnId = u32;
pub type Timestamp = u32;

pub fn now() -> ClResult<Timestamp> {
	Ok(SystemTime::now()
		.duration_since(SystemTime::UNIX_EPOCH)?
		.as_secs() as Timestamp)
}


pub trait TimestampExt {
	fn now() -> Timestamp;
}

impl TimestampExt for Timestamp {
	fn now() -> Timestamp {
		SystemTime::now()
			.duration_since(SystemTime::UNIX_EPOCH)
			.unwrap()
			.as_secs() as Timestamp
	}
}

// vim: ts=4
