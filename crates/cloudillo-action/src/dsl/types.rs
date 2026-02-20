//! Type definitions for the Action DSL

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashMap;

use crate::hooks::HookImplementation;

/// Complete action type definition in DSL format
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionDefinition {
	/// Action type identifier (e.g., "CONN", "POST")
	pub r#type: String,
	/// Semantic version
	pub version: String,
	/// Human-readable description
	pub description: String,

	/// Metadata about the action type
	pub metadata: Option<ActionMetadata>,

	/// Subtype definitions
	pub subtypes: Option<HashMap<String, String>>,

	/// Field constraints (required/optional/forbidden)
	pub fields: FieldConstraints,

	/// Content schema definition (only field with configurable schema)
	pub schema: Option<ContentSchemaWrapper>,

	/// Behavior flags
	pub behavior: BehaviorFlags,

	/// Key pattern for unique action identification
	pub key_pattern: Option<String>,

	/// Lifecycle hooks
	pub hooks: ActionHooks,

	/// Permission rules
	pub permissions: Option<PermissionRules>,
}

/// Metadata about an action type
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionMetadata {
	pub category: Option<String>,
	pub tags: Option<Vec<String>>,
	pub deprecated: Option<bool>,
	pub experimental: Option<bool>,
}

/// Field constraints - only optionality is configurable (types are fixed)
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FieldConstraints {
	/// Content field (type: json)
	pub content: Option<FieldConstraint>,
	/// Audience field (type: idTag)
	pub audience: Option<FieldConstraint>,
	/// Parent field (type: actionId)
	pub parent: Option<FieldConstraint>,
	/// Subject field (type: actionId/string)
	pub subject: Option<FieldConstraint>,
	/// Attachments field (type: fileId[])
	pub attachments: Option<FieldConstraint>,
}

/// Field constraint - controls whether a field is required, forbidden, or optional
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldConstraint {
	/// Field must be present and valid
	Required,
	/// Field must be null/undefined
	Forbidden,
}

/// Wrapper for content schema
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentSchemaWrapper {
	pub content: Option<ContentSchema>,
}

/// Schema definition for the content field
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentSchema {
	/// Content type
	#[serde(rename = "type")]
	pub content_type: ContentType,

	/// String constraints
	pub min_length: Option<usize>,
	pub max_length: Option<usize>,
	pub pattern: Option<String>,

	/// Enum constraint
	pub r#enum: Option<Vec<serde_json::Value>>,

	/// Object properties (for object type)
	pub properties: Option<HashMap<String, SchemaField>>,

	/// Required properties (for object type)
	pub required: Option<Vec<String>>,

	/// Description
	pub description: Option<String>,
}

/// Content type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContentType {
	String,
	Number,
	Boolean,
	Object,
	Json,
}

/// Schema field definition for object properties
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaField {
	#[serde(rename = "type")]
	pub field_type: FieldType,

	pub min_length: Option<usize>,
	pub max_length: Option<usize>,
	pub r#enum: Option<Vec<serde_json::Value>>,
	pub items: Option<Box<SchemaField>>,
}

/// Field type for schema properties
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
	String,
	Number,
	Boolean,
	Array,
	Json,
}

/// Behavior flags controlling action processing
///
/// # Implementation Status
///
/// ## Fully Implemented
/// - `broadcast` - Checked in `schedule_delivery()` for self-posting
/// - `allow_unknown` - Validated on both inbound (permission check) and outbound (create_action)
/// - `ephemeral` - Skips persistence, forwards to WebSocket only
/// - `approvable` - Enables APRV flow, auto-approve for trusted sources
/// - `requires_subscription` - Validated on both inbound and outbound
/// - `deliver_subject` - Delivers subject action along with main action
/// - `subscribable` - Enables SUBS-based permissions and visibility
/// - `deliver_to_subject_owner` - Dual delivery to subject owner
/// - `default_flags` - Applied during action creation
///
/// ## Reserved (Not Implemented)
/// - `requires_acceptance` - RESERVED: Would set initial status to CONFIRMATION
/// - `local_only` - RESERVED: Would skip federation in schedule_delivery
/// - `ttl` - RESERVED: Time-to-live for action expiration
/// - `sync` - RESERVED: Synchronous processing mode
/// - `federated` - RESERVED: Cross-instance federation control
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BehaviorFlags {
	// === Fully Implemented ===
	/// Send to all followers when posting to own wall (no audience).
	/// Checked in `schedule_delivery()` for self-posting.
	pub broadcast: Option<bool>,

	/// Accept actions from non-connected/non-following users.
	/// Validated on both inbound (permission check) and outbound (create_action).
	pub allow_unknown: Option<bool>,

	/// Don't persist to database, only forward to WebSocket.
	/// Used for real-time ephemeral actions like typing indicators.
	pub ephemeral: Option<bool>,

	/// Can this action receive APRV (approval) from audience?
	/// When true, accepting this action will generate an APRV federated signal.
	/// Also enables auto-approve for trusted sources.
	pub approvable: Option<bool>,

	/// Child actions require SUBS (subscription) validation.
	/// Validated on both inbound and outbound flows.
	pub requires_subscription: Option<bool>,

	/// Deliver subject action along with this action to recipients.
	/// Used by APRV to include the approved POST when fanning out.
	pub deliver_subject: Option<bool>,

	/// This action type can have SUBS (subscriptions) pointing to it.
	/// When true, subscribers are included in visibility checks for Direct visibility.
	/// Also enables fan-out to subscribers in parent chain.
	pub subscribable: Option<bool>,

	/// Also deliver to subject's owner (in addition to audience).
	/// Used by INVT to deliver to both invitee and CONV home for validation.
	pub deliver_to_subject_owner: Option<bool>,

	/// Default flags for this action type (R/r=reactions, C/c=comments, O/o=open).
	/// Applied during action creation.
	pub default_flags: Option<String>,

	// === Reserved (Not Implemented) ===
	/// RESERVED: Requires user confirmation before activation.
	/// When implemented, would set initial status to CONFIRMATION.
	pub requires_acceptance: Option<bool>,

	/// RESERVED: Never federate this action type.
	/// When implemented, would skip federation in schedule_delivery.
	pub local_only: Option<bool>,

	/// RESERVED: Time to live in seconds.
	/// When implemented, would enable automatic action expiration.
	pub ttl: Option<u64>,

	/// RESERVED: Process synchronously.
	/// Currently only affects IDP:REG hook execution.
	pub sync: Option<bool>,

	/// RESERVED: Allow cross-instance federation.
	/// Default behavior is to federate; this flag is reserved for future use.
	pub federated: Option<bool>,
}

/// Lifecycle hooks for action processing
#[derive(Debug, Clone, Default)]
pub struct ActionHooks {
	/// Execute when creating an action locally
	pub on_create: HookImplementation,
	/// Execute when receiving an action from remote
	pub on_receive: HookImplementation,
	/// Execute when user accepts a confirmation action
	pub on_accept: HookImplementation,
	/// Execute when user rejects a confirmation action
	pub on_reject: HookImplementation,
}

// Custom serialization for ActionHooks
impl Serialize for ActionHooks {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		use serde::ser::SerializeStruct;
		let mut state = serializer.serialize_struct("ActionHooks", 4)?;
		state.serialize_field("on_create", &self.on_create)?;
		state.serialize_field("on_receive", &self.on_receive)?;
		state.serialize_field("on_accept", &self.on_accept)?;
		state.serialize_field("on_reject", &self.on_reject)?;
		state.end()
	}
}

// Custom deserialization for ActionHooks
impl<'de> Deserialize<'de> for ActionHooks {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		use serde::de::{self, MapAccess, Visitor};
		#[allow(unused_imports)]
		use std::fmt;

		enum Field {
			Create,
			Receive,
			Accept,
			Reject,
		}

		impl<'de> Deserialize<'de> for Field {
			fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
			where
				D: serde::Deserializer<'de>,
			{
				struct FieldVisitor;

				impl<'de> Visitor<'de> for FieldVisitor {
					type Value = Field;

					fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
						formatter
							.write_str("`on_create`, `on_receive`, `on_accept`, or `on_reject`")
					}

					fn visit_str<E>(self, value: &str) -> Result<Field, E>
					where
						E: de::Error,
					{
						match value {
							"on_create" => Ok(Field::Create),
							"on_receive" => Ok(Field::Receive),
							"on_accept" => Ok(Field::Accept),
							"on_reject" => Ok(Field::Reject),
							_ => Err(de::Error::unknown_field(value, FIELDS)),
						}
					}
				}

				deserializer.deserialize_identifier(FieldVisitor)
			}
		}

		struct ActionHooksVisitor;

		impl<'de> Visitor<'de> for ActionHooksVisitor {
			type Value = ActionHooks;

			fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
				formatter.write_str("struct ActionHooks")
			}

			fn visit_map<V>(self, mut map: V) -> Result<ActionHooks, V::Error>
			where
				V: MapAccess<'de>,
			{
				let mut on_create = HookImplementation::None;
				let mut on_receive = HookImplementation::None;
				let mut on_accept = HookImplementation::None;
				let mut on_reject = HookImplementation::None;

				while let Some(key) = map.next_key()? {
					match key {
						Field::Create => {
							if !matches!(on_create, HookImplementation::None) {
								return Err(de::Error::duplicate_field("on_create"));
							}
							on_create = map.next_value()?;
						}
						Field::Receive => {
							if !matches!(on_receive, HookImplementation::None) {
								return Err(de::Error::duplicate_field("on_receive"));
							}
							on_receive = map.next_value()?;
						}
						Field::Accept => {
							if !matches!(on_accept, HookImplementation::None) {
								return Err(de::Error::duplicate_field("on_accept"));
							}
							on_accept = map.next_value()?;
						}
						Field::Reject => {
							if !matches!(on_reject, HookImplementation::None) {
								return Err(de::Error::duplicate_field("on_reject"));
							}
							on_reject = map.next_value()?;
						}
					}
				}

				Ok(ActionHooks { on_create, on_receive, on_accept, on_reject })
			}
		}

		const FIELDS: &[&str] = &["on_create", "on_receive", "on_accept", "on_reject"];
		deserializer.deserialize_struct("ActionHooks", FIELDS, ActionHooksVisitor)
	}
}

/// Permission rules for action types
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRules {
	pub can_create: Option<String>,
	pub can_receive: Option<String>,
	pub requires_following: Option<bool>,
	pub requires_connected: Option<bool>,
}

/// DSL operation - tagged enum for all operation types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Operation {
	// Profile operations
	UpdateProfile {
		target: Expression,
		set: HashMap<String, Expression>,
	},
	GetProfile {
		target: Expression,
		#[serde(skip_serializing_if = "Option::is_none")]
		r#as: Option<String>,
	},

	// Action operations
	CreateAction {
		r#type: String,
		#[serde(skip_serializing_if = "Option::is_none")]
		subtype: Option<Expression>,
		#[serde(skip_serializing_if = "Option::is_none")]
		audience: Option<Expression>,
		#[serde(skip_serializing_if = "Option::is_none")]
		parent: Option<Expression>,
		#[serde(skip_serializing_if = "Option::is_none")]
		subject: Option<Expression>,
		#[serde(skip_serializing_if = "Option::is_none")]
		content: Option<Expression>,
		#[serde(skip_serializing_if = "Option::is_none")]
		attachments: Option<Expression>,
	},
	GetAction {
		#[serde(skip_serializing_if = "Option::is_none")]
		key: Option<Expression>,
		#[serde(skip_serializing_if = "Option::is_none")]
		action_id: Option<Expression>,
		#[serde(skip_serializing_if = "Option::is_none")]
		r#as: Option<String>,
	},
	UpdateAction {
		target: Expression,
		set: HashMap<String, UpdateValue>,
	},
	DeleteAction {
		target: Expression,
	},

	// Control flow operations
	If {
		condition: Expression,
		then: Vec<Operation>,
		#[serde(skip_serializing_if = "Option::is_none")]
		r#else: Option<Vec<Operation>>,
	},
	Switch {
		value: Expression,
		cases: HashMap<String, Vec<Operation>>,
		#[serde(skip_serializing_if = "Option::is_none")]
		default: Option<Vec<Operation>>,
	},
	Foreach {
		array: Expression,
		#[serde(skip_serializing_if = "Option::is_none")]
		r#as: Option<String>,
		r#do: Vec<Operation>,
	},
	Return {
		#[serde(skip_serializing_if = "Option::is_none")]
		value: Option<Expression>,
	},

	// Data operations
	Set {
		var: String,
		value: Expression,
	},
	Get {
		var: String,
		from: Expression,
	},
	Merge {
		objects: Vec<Expression>,
		r#as: String,
	},

	// Federation operations
	BroadcastToFollowers {
		action_id: Expression,
		token: Expression,
	},
	SendToAudience {
		action_id: Expression,
		token: Expression,
		audience: Expression,
	},

	// Notification operations
	CreateNotification {
		user: Expression,
		r#type: Expression,
		action_id: Expression,
		#[serde(skip_serializing_if = "Option::is_none")]
		priority: Option<Expression>,
	},

	// Utility operations
	Log {
		#[serde(skip_serializing_if = "Option::is_none")]
		level: Option<String>,
		message: Expression,
	},
	Abort {
		error: Expression,
		#[serde(skip_serializing_if = "Option::is_none")]
		code: Option<String>,
	},
}

/// Update value for action updates (supports increment/decrement)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UpdateValue {
	Direct(Expression),
	Increment { increment: Expression },
	Decrement { decrement: Expression },
	Set { set: Expression },
}

/// Expression - can be a literal, variable reference, or complex expression
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Expression {
	// Literals
	Null,
	Bool(bool),
	Number(f64),
	String(String),

	// Complex expressions
	Comparison(Box<ComparisonExpr>),
	Logical(Box<LogicalExpr>),
	Arithmetic(Box<ArithmeticExpr>),
	StringOp(Box<StringOpExpr>),
	Ternary(Box<TernaryExpr>),
	Coalesce(Box<CoalesceExpr>),
}

/// Comparison expressions
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComparisonExpr {
	Eq([Expression; 2]),
	Ne([Expression; 2]),
	Gt([Expression; 2]),
	Gte([Expression; 2]),
	Lt([Expression; 2]),
	Lte([Expression; 2]),
}

/// Logical expressions
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogicalExpr {
	And(Vec<Expression>),
	Or(Vec<Expression>),
	Not(Expression),
}

/// Arithmetic expressions
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArithmeticExpr {
	Add(Vec<Expression>),
	Subtract([Expression; 2]),
	Multiply(Vec<Expression>),
	Divide([Expression; 2]),
}

/// String operations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StringOpExpr {
	Concat(Vec<Expression>),
	Contains([Expression; 2]),
	StartsWith([Expression; 2]),
	EndsWith([Expression; 2]),
}

/// Ternary expression (if-then-else)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TernaryExpr {
	pub r#if: Expression,
	pub then: Expression,
	pub r#else: Expression,
}

/// Coalesce expression (return first non-null value)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoalesceExpr {
	pub coalesce: Vec<Expression>,
}

// Note: HookContext is now in crate::hooks and re-exported above
// vim: ts=4
