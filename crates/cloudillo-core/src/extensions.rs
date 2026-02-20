//! Type-erased extension map for AppState
//!
//! Allows feature modules to register their own state without coupling
//! the core AppState struct to feature-specific types.

use std::any::{Any, TypeId};
use std::collections::HashMap;

pub struct Extensions {
	map: HashMap<TypeId, Box<dyn Any + Send + Sync>>,
}

impl Extensions {
	pub fn new() -> Self {
		Self { map: HashMap::new() }
	}

	pub fn insert<T: Send + Sync + 'static>(&mut self, val: T) {
		self.map.insert(TypeId::of::<T>(), Box::new(val));
	}

	pub fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
		self.map.get(&TypeId::of::<T>())?.downcast_ref::<T>()
	}
}

impl Default for Extensions {
	fn default() -> Self {
		Self::new()
	}
}

// vim: ts=4
