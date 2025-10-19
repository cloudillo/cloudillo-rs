use crate::prelude::*;
use rand::Rng;

pub const ID_LENGTH: usize = 24;
pub const SAFE: [char; 62] = [
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
];

pub fn random_id() -> ClResult<String> {
	let mut rng = rand::rng();
	let mut result = String::with_capacity(ID_LENGTH);

	for _ in 0..ID_LENGTH {
		result.push(SAFE[rng.random_range(0..SAFE.len())]);
	}
	Ok(result)
}

// vim: ts=4
