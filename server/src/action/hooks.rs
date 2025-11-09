//! Hook implementation types and registry for hybrid DSL + native execution

use crate::core::app::AppState;
use crate::error::ClResult;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use super::dsl::types::Operation;

/// Result type for hook functions
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Native hook function type
/// Takes AppState and HookContext, returns a Future resolving to HookResult
pub type HookFunction = Arc<
	dyn Fn(Arc<AppState>, HookContext) -> BoxFuture<'static, ClResult<HookResult>> + Send + Sync,
>;

/// Represents how a hook is implemented
#[derive(Clone)]
pub enum HookImplementation {
	/// DSL-based hook (declarative JSON operations)
	Dsl(Vec<Operation>),

	/// Native Rust async function implementation
	Native(HookFunction),

	/// Both DSL and native (DSL runs first, then native)
	Hybrid { dsl: Vec<Operation>, native: HookFunction },

	/// No hook defined
	None,
}

// Custom serialization for HookImplementation
// Only serializes DSL operations as Option<Vec<Operation>>, not native functions
impl Serialize for HookImplementation {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		match self {
			HookImplementation::Dsl(ops) => ops.serialize(serializer),
			HookImplementation::None => None::<Vec<Operation>>.serialize(serializer),
			HookImplementation::Native(_) => {
				// Can't serialize native functions, treat as None
				None::<Vec<Operation>>.serialize(serializer)
			}
			HookImplementation::Hybrid { dsl, .. } => {
				// Only serialize DSL portion, drop native
				dsl.serialize(serializer)
			}
		}
	}
}

// Custom deserialization for HookImplementation
impl<'de> Deserialize<'de> for HookImplementation {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let ops: Option<Vec<Operation>> = Option::deserialize(deserializer)?;
		match ops {
			None => Ok(HookImplementation::None),
			Some(ops) => Ok(HookImplementation::Dsl(ops)),
		}
	}
}

impl std::fmt::Debug for HookImplementation {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Dsl(ops) => f.debug_tuple("Dsl").field(ops).finish(),
			Self::Native(_) => f.debug_tuple("Native").field(&"<function>").finish(),
			Self::Hybrid { dsl, .. } => f
				.debug_struct("Hybrid")
				.field("dsl", dsl)
				.field("native", &"<function>")
				.finish(),
			Self::None => write!(f, "None"),
		}
	}
}

impl Default for HookImplementation {
	fn default() -> Self {
		Self::None
	}
}

impl HookImplementation {
	/// Check if this hook is defined (not None)
	pub fn is_some(&self) -> bool {
		!matches!(self, HookImplementation::None)
	}

	/// Check if this hook is undefined
	pub fn is_none(&self) -> bool {
		matches!(self, HookImplementation::None)
	}
}

/// Result returned by hook execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookResult {
	/// Variables to merge back into context
	pub vars: HashMap<String, serde_json::Value>,

	/// Whether to continue processing (false = abort)
	pub continue_processing: bool,

	/// Optional early return value
	pub return_value: Option<serde_json::Value>,
}

impl Default for HookResult {
	fn default() -> Self {
		Self { vars: HashMap::new(), continue_processing: true, return_value: None }
	}
}

/// Hook type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookType {
	OnCreate,
	OnReceive,
	OnAccept,
	OnReject,
}

impl HookType {
	/// Get string representation of hook type
	pub fn as_str(&self) -> &'static str {
		match self {
			HookType::OnCreate => "on_create",
			HookType::OnReceive => "on_receive",
			HookType::OnAccept => "on_accept",
			HookType::OnReject => "on_reject",
		}
	}
}

/// Hook execution context
#[derive(Debug, Clone)]
pub struct HookContext {
	// Action data
	pub action_id: String,
	pub r#type: String,
	pub subtype: Option<String>,
	pub issuer: String,
	pub audience: Option<String>,
	pub parent: Option<String>,
	pub subject: Option<String>,
	pub content: Option<serde_json::Value>,
	pub attachments: Option<Vec<String>>,

	// Timestamps
	pub created_at: String,
	pub expires_at: Option<String>,

	// Context
	pub tenant_id: i64,
	pub tenant_tag: String,
	pub tenant_type: String,

	// Flags
	pub is_inbound: bool,
	pub is_outbound: bool,

	// Variables set by operations
	pub vars: HashMap<String, serde_json::Value>,
}

/// All hooks for a specific action type
pub struct ActionTypeHooks {
	pub on_create: Option<HookFunction>,
	pub on_receive: Option<HookFunction>,
	pub on_accept: Option<HookFunction>,
	pub on_reject: Option<HookFunction>,
}

/// Registry of native hook implementations
pub struct HookRegistry {
	hooks: HashMap<String, ActionTypeHooks>,
}

impl HookRegistry {
	/// Create a new empty hook registry
	pub fn new() -> Self {
		Self { hooks: HashMap::new() }
	}

	/// Register a complete action type with all hooks
	pub fn register_type(&mut self, type_name: &str, hooks: ActionTypeHooks) {
		self.hooks.insert(type_name.to_string(), hooks);
	}

	/// Register a single hook for an action type
	pub fn register_hook(&mut self, type_name: &str, hook_type: HookType, function: HookFunction) {
		let entry = self.hooks.entry(type_name.to_string()).or_insert_with(|| ActionTypeHooks {
			on_create: None,
			on_receive: None,
			on_accept: None,
			on_reject: None,
		});

		match hook_type {
			HookType::OnCreate => entry.on_create = Some(function),
			HookType::OnReceive => entry.on_receive = Some(function),
			HookType::OnAccept => entry.on_accept = Some(function),
			HookType::OnReject => entry.on_reject = Some(function),
		}
	}

	/// Get hook function if registered
	pub fn get_hook(&self, type_name: &str, hook_type: HookType) -> Option<&HookFunction> {
		self.hooks.get(type_name).and_then(|hooks| match hook_type {
			HookType::OnCreate => hooks.on_create.as_ref(),
			HookType::OnReceive => hooks.on_receive.as_ref(),
			HookType::OnAccept => hooks.on_accept.as_ref(),
			HookType::OnReject => hooks.on_reject.as_ref(),
		})
	}

	/// Check if a hook is registered
	pub fn has_hook(&self, type_name: &str, hook_type: HookType) -> bool {
		self.get_hook(type_name, hook_type).is_some()
	}

	/// Get all registered action types
	pub fn registered_types(&self) -> Vec<&str> {
		self.hooks.keys().map(|s| s.as_str()).collect()
	}
}

impl Default for HookRegistry {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_hook_type_str_conversion() {
		assert_eq!(HookType::OnCreate.as_str(), "on_create");
		assert_eq!(HookType::OnReceive.as_str(), "on_receive");
		assert_eq!(HookType::OnAccept.as_str(), "on_accept");
		assert_eq!(HookType::OnReject.as_str(), "on_reject");
	}

	#[test]
	fn test_hook_result_default() {
		let result = HookResult::default();
		assert!(result.vars.is_empty());
		assert!(result.continue_processing);
		assert!(result.return_value.is_none());
	}

	#[test]
	fn test_hook_registry_create() {
		let registry = HookRegistry::new();
		assert!(registry.registered_types().is_empty());
	}

	#[test]
	fn test_hook_registry_register_hook() {
		let mut registry = HookRegistry::new();

		// Create a dummy hook function
		let hook: HookFunction = Arc::new(|_, _| Box::pin(async { Ok(HookResult::default()) }));

		registry.register_hook("TEST", HookType::OnCreate, hook.clone());
		assert!(registry.has_hook("TEST", HookType::OnCreate));
		assert!(!registry.has_hook("TEST", HookType::OnReceive));
	}

	#[test]
	fn test_hook_implementation_default() {
		let impl_hook = HookImplementation::default();
		match impl_hook {
			HookImplementation::None => (),
			_ => panic!("expected None variant"),
		}
	}

	#[test]
	fn test_hook_context_creation() {
		let context = HookContext {
			action_id: "a1~test".to_string(),
			r#type: "POST".to_string(),
			subtype: None,
			issuer: "user1".to_string(),
			audience: None,
			parent: None,
			subject: None,
			content: None,
			attachments: None,
			created_at: "2025-11-09T00:00:00Z".to_string(),
			expires_at: None,
			tenant_id: 1,
			tenant_tag: "dev".to_string(),
			tenant_type: "user".to_string(),
			is_inbound: false,
			is_outbound: true,
			vars: HashMap::new(),
		};

		assert_eq!(context.action_id, "a1~test");
		assert_eq!(context.r#type, "POST");
		assert_eq!(context.issuer, "user1");
	}
}

// vim: ts=4
