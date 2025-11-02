//! Action type configuration for federated delivery

use lazy_static::lazy_static;
use std::collections::HashMap;

/// Configuration for each action type
#[derive(Debug, Clone)]
pub struct ActionTypeConfig {
	/// Should this action be broadcast to all followers?
	pub broadcast: bool,
	/// Allow from unknown/unfollowed profiles?
	pub allow_unknown: bool,
}

lazy_static! {
	/// Action type configurations (from TypeScript implementation)
	pub static ref ACTION_TYPES: HashMap<&'static str, ActionTypeConfig> = {
		let mut m = HashMap::new();

		// Broadcast types - sent to all followers
		m.insert("POST", ActionTypeConfig {
			broadcast: true,
			allow_unknown: false,
		});
		m.insert("REPOST", ActionTypeConfig {
			broadcast: true,
			allow_unknown: false,
		});
		m.insert("STAT", ActionTypeConfig {
			broadcast: true,
			allow_unknown: false,
		});
		m.insert("ACK", ActionTypeConfig {
			broadcast: true,
			allow_unknown: false,
		});
		m.insert("ENDR", ActionTypeConfig {
			broadcast: true,
			allow_unknown: false,
		});

		// Direct types - sent to specific audience only
		m.insert("MSG", ActionTypeConfig {
			broadcast: false,
			allow_unknown: false,
		});

		// Reaction types - allow from unknown (parent action determines permission)
		m.insert("REACT", ActionTypeConfig {
			broadcast: false,
			allow_unknown: true,
		});
		m.insert("CMNT", ActionTypeConfig {
			broadcast: false,
			allow_unknown: true,
		});

		// Connection types - allow from unknown (connection requests)
		m.insert("FLLW", ActionTypeConfig {
			broadcast: false,
			allow_unknown: true,
		});
		m.insert("CONN", ActionTypeConfig {
			broadcast: false,
			allow_unknown: true,
		});

		m
	};
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_broadcast_action_types() {
		// These should be broadcast to all followers
		let broadcast_types = vec!["POST", "REPOST", "STAT", "ACK"];
		for typ in broadcast_types {
			let config = ACTION_TYPES.get(typ);
			assert!(config.is_some(), "{} should have config", typ);
			let config = config.unwrap();
			assert!(config.broadcast, "{} should have broadcast=true", typ);
			assert!(!config.allow_unknown, "{} should have allow_unknown=false", typ);
		}
	}

	#[test]
	fn test_direct_action_types() {
		// These should NOT broadcast
		let direct_types = vec!["MSG"];
		for typ in direct_types {
			let config = ACTION_TYPES.get(typ);
			assert!(config.is_some(), "{} should have config", typ);
			let config = config.unwrap();
			assert!(!config.broadcast, "{} should have broadcast=false", typ);
			assert!(!config.allow_unknown, "{} should have allow_unknown=false", typ);
		}
	}

	#[test]
	fn test_reaction_action_types() {
		// These allow from unknown (permission checked via parent action)
		let reaction_types = vec!["REACT", "CMNT"];
		for typ in reaction_types {
			let config = ACTION_TYPES.get(typ);
			assert!(config.is_some(), "{} should have config", typ);
			let config = config.unwrap();
			assert!(!config.broadcast, "{} should have broadcast=false", typ);
			assert!(config.allow_unknown, "{} should have allow_unknown=true", typ);
		}
	}

	#[test]
	fn test_connection_action_types() {
		// These allow from unknown (connection requests)
		let connection_types = vec!["FLLW", "CONN"];
		for typ in connection_types {
			let config = ACTION_TYPES.get(typ);
			assert!(config.is_some(), "{} should have config", typ);
			let config = config.unwrap();
			assert!(!config.broadcast, "{} should have broadcast=false", typ);
			assert!(config.allow_unknown, "{} should have allow_unknown=true", typ);
		}
	}
}

// vim: ts=4
