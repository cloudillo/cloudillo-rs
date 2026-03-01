//! Attribute-based access control trait.

/// Attribute set trait - all objects implement this
pub trait AttrSet: Send + Sync {
	/// Get a single string attribute
	fn get(&self, key: &str) -> Option<&str>;

	/// Get a list attribute
	fn get_list(&self, key: &str) -> Option<Vec<&str>>;

	/// Check if attribute equals value
	fn has(&self, key: &str, value: &str) -> bool {
		self.get(key) == Some(value)
	}

	/// Check if list attribute contains value
	fn contains(&self, key: &str, value: &str) -> bool {
		self.get_list(key).is_some_and(|list| list.contains(&value))
	}
}

// vim: ts=4
