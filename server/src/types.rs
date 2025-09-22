use serde::Serialize;

pub type TnId = u32;
pub type Timestamp = u32;

pub trait TimestampExt {
	fn now() -> Timestamp;
}

impl TimestampExt for Timestamp {
	fn now() -> Timestamp {
		use std::time::SystemTime;
		SystemTime::now()
			.duration_since(SystemTime::UNIX_EPOCH)
			.unwrap()
			.as_secs() as Timestamp
	}
}

// vim: ts=4
