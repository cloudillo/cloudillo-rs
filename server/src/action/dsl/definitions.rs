//! Built-in action type definitions
//!
//! All action types are defined here as Rust data structures for compile-time validation

use super::types::*;
use crate::action::hooks::HookImplementation;
use std::collections::HashMap;

/// Helper to create default behavior flags
fn default_behavior() -> BehaviorFlags {
	BehaviorFlags {
		broadcast: None,
		allow_unknown: None,
		requires_acceptance: None,
		ttl: None,
		..Default::default()
	}
}

/// Get all built-in action definitions
pub fn get_definitions() -> Vec<ActionDefinition> {
	vec![
		connection_definition(),
		follow_definition(),
		post_definition(),
		react_definition(),
		comment_definition(),
		message_definition(),
		repost_definition(),
		ack_definition(),
		stat_definition(),
	]
}

/// CONN - Bidirectional connection action
fn connection_definition() -> ActionDefinition {
	ActionDefinition {
		r#type: "CONN".to_string(),
		version: "1.0".to_string(),
		description: "Establish bidirectional connection between users".to_string(),
		metadata: Some(ActionMetadata {
			category: Some("social".to_string()),
			tags: Some(vec!["connection".to_string(), "relationship".to_string()]),
			deprecated: None,
			experimental: None,
		}),
		subtypes: Some({
			let mut map = HashMap::new();
			map.insert("DEL".to_string(), "Remove existing connection".to_string());
			map
		}),
		fields: FieldConstraints {
			content: None,
			audience: Some(FieldConstraint::Required),
			parent: Some(FieldConstraint::Forbidden),
			attachments: Some(FieldConstraint::Forbidden),
			subject: Some(FieldConstraint::Forbidden),
		},
		schema: Some(ContentSchemaWrapper {
			content: Some(ContentSchema {
				content_type: ContentType::String,
				min_length: None,
				max_length: Some(500),
				pattern: None,
				r#enum: None,
				properties: None,
				required: None,
				description: Some("Optional connection message".to_string()),
			}),
		}),
		behavior: BehaviorFlags {
			broadcast: Some(false),
			allow_unknown: Some(true),
			requires_acceptance: Some(false),

			..Default::default()
		},
		hooks: ActionHooks {
			on_create: HookImplementation::None, // Native implementation registered via registry
			on_receive: HookImplementation::None, // Native implementation registered via registry
			on_accept: HookImplementation::None, // Native implementation registered via registry
			on_reject: HookImplementation::None, // Native implementation registered via registry
		},
		permissions: Some(PermissionRules {
			can_create: Some("authenticated".to_string()),
			can_receive: Some("any".to_string()),
			requires_following: Some(false),
			requires_connected: Some(false),
		}),
		key_pattern: Some("{type}:{issuer}:{audience}".to_string()),
	}
}

/// FLLW - One-way follow action
fn follow_definition() -> ActionDefinition {
	ActionDefinition {
		r#type: "FLLW".to_string(),
		version: "1.0".to_string(),
		description: "One-way follow relationship".to_string(),
		metadata: Some(ActionMetadata {
			category: Some("social".to_string()),
			tags: Some(vec!["follow".to_string(), "subscription".to_string()]),
			deprecated: None,
			experimental: None,
		}),
		subtypes: Some({
			let mut map = HashMap::new();
			map.insert("DEL".to_string(), "Unfollow".to_string());
			map
		}),
		fields: FieldConstraints {
			content: None,
			audience: Some(FieldConstraint::Required),
			parent: Some(FieldConstraint::Forbidden),
			attachments: Some(FieldConstraint::Forbidden),
			subject: Some(FieldConstraint::Forbidden),
		},
		schema: Some(ContentSchemaWrapper {
			content: Some(ContentSchema {
				content_type: ContentType::String,
				min_length: None,
				max_length: Some(500),
				pattern: None,
				r#enum: None,
				properties: None,
				required: None,
				description: Some("Optional follow message".to_string()),
			}),
		}),
		behavior: BehaviorFlags {
			broadcast: Some(false),
			allow_unknown: Some(true),
			requires_acceptance: Some(false),

			..Default::default()
		},
		hooks: ActionHooks {
			on_create: HookImplementation::None, // Native implementation registered via registry
			on_receive: HookImplementation::None,
			on_accept: HookImplementation::None,
			on_reject: HookImplementation::None,
		},
		permissions: Some(PermissionRules {
			can_create: Some("authenticated".to_string()),
			can_receive: Some("any".to_string()),
			requires_following: Some(false),
			requires_connected: Some(false),
		}),
		key_pattern: Some("{type}:{issuer}:{audience}".to_string()),
	}
}

/// POST - Broadcast post action
fn post_definition() -> ActionDefinition {
	ActionDefinition {
		r#type: "POST".to_string(),
		version: "1.0".to_string(),
		description: "Broadcast post to followers".to_string(),
		metadata: Some(ActionMetadata {
			category: Some("content".to_string()),
			tags: Some(vec!["post".to_string(), "broadcast".to_string(), "content".to_string()]),
			deprecated: None,
			experimental: None,
		}),
		subtypes: Some({
			let mut map = HashMap::new();
			map.insert("TEXT".to_string(), "Text post".to_string());
			map.insert("IMG".to_string(), "Image post".to_string());
			map.insert("VID".to_string(), "Video post".to_string());
			map.insert("DEL".to_string(), "Delete post".to_string());
			map
		}),
		fields: FieldConstraints { content: Some(FieldConstraint::Required), ..Default::default() },
		schema: Some(ContentSchemaWrapper {
			content: Some(ContentSchema {
				content_type: ContentType::String,
				min_length: Some(1),
				max_length: Some(50000),
				pattern: None,
				r#enum: None,
				properties: None,
				required: None,
				description: Some("Post content".to_string()),
			}),
		}),
		behavior: BehaviorFlags {
			broadcast: Some(true),
			allow_unknown: Some(false),
			requires_acceptance: Some(false),

			..Default::default()
		},
		hooks: ActionHooks {
			on_create: HookImplementation::None, // Broadcasting is handled automatically by the system
			on_receive: HookImplementation::None, // TODO: Add profile check and conditional ACK creation from JSON
			on_accept: HookImplementation::None,
			on_reject: HookImplementation::None,
		},
		permissions: Some(PermissionRules {
			can_create: Some("authenticated".to_string()),
			can_receive: Some("followers".to_string()),
			requires_following: Some(false),
			requires_connected: Some(false),
		}),
		key_pattern: None,
	}
}

/// REACT - Reaction to content
fn react_definition() -> ActionDefinition {
	ActionDefinition {
		r#type: "REACT".to_string(),
		version: "1.0".to_string(),
		description: "React to posts and comments".to_string(),
		metadata: Some(ActionMetadata {
			category: Some("interaction".to_string()),
			tags: Some(vec!["reaction".to_string(), "like".to_string()]),
			deprecated: None,
			experimental: None,
		}),
		subtypes: Some({
			let mut map = HashMap::new();
			map.insert("LIKE".to_string(), "Like reaction".to_string());
			map.insert("LOVE".to_string(), "Love reaction".to_string());
			map.insert("LAUGH".to_string(), "Laugh reaction".to_string());
			map.insert("WOW".to_string(), "Wow reaction".to_string());
			map.insert("SAD".to_string(), "Sad reaction".to_string());
			map.insert("ANGRY".to_string(), "Angry reaction".to_string());
			map.insert("DEL".to_string(), "Remove reaction".to_string());
			map
		}),
		fields: FieldConstraints {
			content: Some(FieldConstraint::Forbidden),
			audience: None,
			parent: Some(FieldConstraint::Required),
			attachments: None,
			..Default::default()
		},
		schema: None,
		behavior: BehaviorFlags {
			broadcast: Some(false),
			allow_unknown: Some(true),
			requires_acceptance: Some(false),

			..Default::default()
		},
		hooks: ActionHooks {
			on_create: HookImplementation::None,
			on_receive: HookImplementation::None, // TODO: Get parent, check if owner, update counters, create STAT
			on_accept: HookImplementation::None,
			on_reject: HookImplementation::None,
		},
		permissions: Some(PermissionRules {
			can_create: Some("authenticated".to_string()),
			can_receive: Some("any".to_string()),
			requires_following: Some(false),
			requires_connected: Some(false),
		}),
		key_pattern: Some("{type}:{parent}:{issuer}".to_string()),
	}
}

/// CMNT - Comment on content
fn comment_definition() -> ActionDefinition {
	ActionDefinition {
		r#type: "CMNT".to_string(),
		version: "1.0".to_string(),
		description: "Comment on posts and other comments".to_string(),
		metadata: Some(ActionMetadata {
			category: Some("interaction".to_string()),
			tags: Some(vec!["comment".to_string(), "reply".to_string()]),
			deprecated: None,
			experimental: None,
		}),
		subtypes: Some({
			let mut map = HashMap::new();
			map.insert("DEL".to_string(), "Delete comment".to_string());
			map
		}),
		fields: FieldConstraints {
			content: Some(FieldConstraint::Required),
			audience: None,
			parent: Some(FieldConstraint::Required),
			..Default::default()
		},
		schema: Some(ContentSchemaWrapper {
			content: Some(ContentSchema {
				content_type: ContentType::String,
				min_length: Some(1),
				max_length: Some(10000),
				pattern: None,
				r#enum: None,
				properties: None,
				required: None,
				description: Some("Comment content".to_string()),
			}),
		}),
		behavior: BehaviorFlags {
			broadcast: Some(false),
			allow_unknown: Some(true),
			requires_acceptance: Some(false),

			..Default::default()
		},
		hooks: ActionHooks {
			on_create: HookImplementation::None,
			on_receive: HookImplementation::None, // TODO: Get parent, update comment counter, create STAT, create notification
			on_accept: HookImplementation::None,
			on_reject: HookImplementation::None,
		},
		permissions: Some(PermissionRules {
			can_create: Some("authenticated".to_string()),
			can_receive: Some("any".to_string()),
			requires_following: Some(false),
			requires_connected: Some(false),
		}),
		key_pattern: None,
	}
}

/// MSG - Direct message
fn message_definition() -> ActionDefinition {
	ActionDefinition {
		r#type: "MSG".to_string(),
		version: "1.0".to_string(),
		description: "Direct message to another user".to_string(),
		metadata: Some(ActionMetadata {
			category: Some("communication".to_string()),
			tags: Some(vec!["message".to_string(), "dm".to_string(), "direct".to_string()]),
			deprecated: None,
			experimental: None,
		}),
		subtypes: Some({
			let mut map = HashMap::new();
			map.insert("DEL".to_string(), "Delete message".to_string());
			map
		}),
		fields: FieldConstraints {
			content: Some(FieldConstraint::Required),
			audience: Some(FieldConstraint::Required),
			..Default::default()
		},
		schema: Some(ContentSchemaWrapper {
			content: Some(ContentSchema {
				content_type: ContentType::String,
				min_length: Some(1),
				max_length: Some(50000),
				pattern: None,
				r#enum: None,
				properties: None,
				required: None,
				description: Some("Message content".to_string()),
			}),
		}),
		behavior: BehaviorFlags {
			broadcast: Some(false),
			allow_unknown: Some(false),
			requires_acceptance: Some(false),
			ttl: None,
			..Default::default()
		},
		hooks: ActionHooks {
			on_create: HookImplementation::None,
			on_receive: HookImplementation::None, // TODO: Check subtype != DEL, create notification with type=message, priority=high
			on_accept: HookImplementation::None,
			on_reject: HookImplementation::None,
		},
		permissions: Some(PermissionRules {
			can_create: Some("authenticated".to_string()),
			can_receive: Some("authenticated".to_string()),
			requires_following: Some(false),
			requires_connected: Some(false),
		}),
		key_pattern: None,
	}
}

/// REPOST - Repost/share action
fn repost_definition() -> ActionDefinition {
	ActionDefinition {
		r#type: "REPOST".to_string(),
		version: "1.0".to_string(),
		description: "Repost another action to your followers".to_string(),
		metadata: Some(ActionMetadata {
			category: Some("content".to_string()),
			tags: Some(vec!["repost".to_string(), "share".to_string(), "broadcast".to_string()]),
			deprecated: None,
			experimental: None,
		}),
		subtypes: Some({
			let mut map = HashMap::new();
			map.insert("DEL".to_string(), "Delete repost".to_string());
			map
		}),
		fields: FieldConstraints {
			content: None,
			audience: None,
			parent: Some(FieldConstraint::Required),
			attachments: Some(FieldConstraint::Forbidden),
			subject: Some(FieldConstraint::Forbidden),
		},
		schema: Some(ContentSchemaWrapper {
			content: Some(ContentSchema {
				content_type: ContentType::String,
				min_length: None,
				max_length: Some(1000),
				pattern: None,
				r#enum: None,
				properties: None,
				required: None,
				description: Some("Optional comment on repost".to_string()),
			}),
		}),
		behavior: BehaviorFlags {
			broadcast: Some(true),
			allow_unknown: Some(false),
			requires_acceptance: Some(false),

			..Default::default()
		},
		hooks: ActionHooks {
			on_create: HookImplementation::None, // TODO: Get parent action and log
			on_receive: HookImplementation::None, // TODO: Check subtype != DEL, get parent, create notification if parent issuer is tenant
			on_accept: HookImplementation::None,
			on_reject: HookImplementation::None,
		},
		permissions: Some(PermissionRules {
			can_create: Some("authenticated".to_string()),
			can_receive: Some("followers".to_string()),
			requires_following: Some(false),
			requires_connected: Some(false),
		}),
		key_pattern: None, // No key pattern since subject is forbidden
	}
}

/// ACK - Acknowledgment receipt
fn ack_definition() -> ActionDefinition {
	ActionDefinition {
		r#type: "ACK".to_string(),
		version: "1.0".to_string(),
		description: "Acknowledge receipt of an action".to_string(),
		metadata: Some(ActionMetadata {
			category: Some("system".to_string()),
			tags: Some(vec!["acknowledgment".to_string(), "receipt".to_string()]),
			deprecated: None,
			experimental: None,
		}),
		subtypes: None,
		fields: FieldConstraints {
			content: Some(FieldConstraint::Forbidden),
			audience: Some(FieldConstraint::Required),
			parent: None,
			attachments: Some(FieldConstraint::Forbidden),
			subject: Some(FieldConstraint::Required),
		},
		schema: None,
		behavior: BehaviorFlags {
			broadcast: Some(true),
			allow_unknown: Some(false),
			requires_acceptance: Some(false),
			ttl: None,
			..Default::default()
		},
		hooks: ActionHooks {
			on_create: HookImplementation::None,
			on_receive: HookImplementation::None,
			on_accept: HookImplementation::None,
			on_reject: HookImplementation::None,
		},
		permissions: Some(PermissionRules {
			can_create: Some("authenticated".to_string()),
			can_receive: Some("any".to_string()),
			requires_following: Some(false),
			requires_connected: Some(false),
		}),
		key_pattern: None,
	}
}

/// STAT - Statistics update
fn stat_definition() -> ActionDefinition {
	ActionDefinition {
		r#type: "STAT".to_string(),
		version: "1.0".to_string(),
		description: "Statistics update for an action (reactions, comments)".to_string(),
		metadata: Some(ActionMetadata {
			category: Some("system".to_string()),
			tags: Some(vec!["statistics".to_string(), "counters".to_string()]),
			deprecated: None,
			experimental: None,
		}),
		subtypes: None,
		fields: FieldConstraints {
			content: Some(FieldConstraint::Required),
			audience: None,
			parent: Some(FieldConstraint::Required),
			attachments: Some(FieldConstraint::Forbidden),
			..Default::default()
		},
		schema: Some(ContentSchemaWrapper {
			content: Some(ContentSchema {
				content_type: ContentType::Object,
				min_length: None,
				max_length: None,
				pattern: None,
				r#enum: None,
				properties: None, // TODO: Add properties for reactions, comments, shares
				required: None,
				description: Some("Action statistics".to_string()),
			}),
		}),
		behavior: BehaviorFlags {
			broadcast: Some(true),
			allow_unknown: Some(false),
			requires_acceptance: Some(false),
			ttl: None,
			..Default::default()
		},
		hooks: ActionHooks {
			on_create: HookImplementation::None,
			on_receive: HookImplementation::None,
			on_accept: HookImplementation::None,
			on_reject: HookImplementation::None,
		},
		permissions: Some(PermissionRules {
			can_create: Some("authenticated".to_string()),
			can_receive: Some("any".to_string()),
			requires_following: Some(false),
			requires_connected: Some(false),
		}),
		key_pattern: Some("{type}:{parent}".to_string()),
	}
}

// vim: ts=4
