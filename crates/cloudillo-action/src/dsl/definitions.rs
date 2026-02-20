//! Built-in action type definitions
//!
//! All action types are defined here as Rust data structures for compile-time validation

use super::types::*;
use crate::hooks::HookImplementation;
use std::collections::HashMap;

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
		aprv_definition(),
		stat_definition(),
		idp_reg_definition(),
		fileshare_definition(),
		pres_definition(),
		subs_definition(),
		conv_definition(),
		invt_definition(),
		prinvt_definition(),
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
			approvable: Some(true),
			..Default::default()
		},
		hooks: ActionHooks {
			on_create: HookImplementation::None, // Broadcasting is handled automatically by the system
			on_receive: HookImplementation::None, // Auto-approve handled in process.rs based on approvable flag
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
			parent: Some(FieldConstraint::Forbidden), // Use subject instead for non-hierarchical reference
			attachments: None,
			subject: Some(FieldConstraint::Required), // The action being reacted to
		},
		schema: None,
		behavior: BehaviorFlags {
			broadcast: Some(false),
			allow_unknown: Some(true),
			requires_acceptance: Some(false),

			..Default::default()
		},
		hooks: ActionHooks {
			on_create: HookImplementation::None, // Native hook registered via registry
			on_receive: HookImplementation::None, // Native hook registered via registry
			on_accept: HookImplementation::None,
			on_reject: HookImplementation::None,
		},
		permissions: Some(PermissionRules {
			can_create: Some("authenticated".to_string()),
			can_receive: Some("any".to_string()),
			requires_following: Some(false),
			requires_connected: Some(false),
		}),
		key_pattern: Some("{type}:{subject}:{issuer}".to_string()), // One reaction per user per action
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

/// MSG - Direct message or conversation message
fn message_definition() -> ActionDefinition {
	ActionDefinition {
		r#type: "MSG".to_string(),
		version: "1.0".to_string(),
		description: "Direct message to another user or within a conversation".to_string(),
		metadata: Some(ActionMetadata {
			category: Some("communication".to_string()),
			tags: Some(vec![
				"message".to_string(),
				"dm".to_string(),
				"direct".to_string(),
				"conversation".to_string(),
			]),
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
			audience: None, // Optional: for DMs. For CONV messages, inherits from CONV.
			parent: None,   // Optional: CONV_id for first message, MSG_id for replies
			subject: None,  // Optional: Reserved for future use
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
			approvable: Some(true),
			requires_subscription: Some(true), // When subject is present, requires subscription
			ttl: None,
			..Default::default()
		},
		hooks: ActionHooks {
			on_create: HookImplementation::None,
			on_receive: HookImplementation::None, // Auto-approve handled in process.rs; TODO: notification for new messages
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
			approvable: Some(true),
			..Default::default()
		},
		hooks: ActionHooks {
			on_create: HookImplementation::None, // TODO: Get parent action and log
			on_receive: HookImplementation::None, // Auto-approve handled in process.rs; TODO: notification if parent issuer is tenant
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

/// APRV - Approval action
/// Sent to signal trust and acceptance of an action, allowing further federation
fn aprv_definition() -> ActionDefinition {
	ActionDefinition {
		r#type: "APRV".to_string(),
		version: "1.0".to_string(),
		description: "Approve an action for federation to user's network".to_string(),
		metadata: Some(ActionMetadata {
			category: Some("system".to_string()),
			tags: Some(vec!["approval".to_string(), "trust".to_string(), "federation".to_string()]),
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

/// IDP:REG - Identity Provider Registration
fn idp_reg_definition() -> ActionDefinition {
	ActionDefinition {
		r#type: "IDP:REG".to_string(),
		version: "1.0".to_string(),
		description: "Identity provider registration request - creates a new identity on the receiving IdP instance".to_string(),
		metadata: Some(ActionMetadata {
			category: Some("identity-provider".to_string()),
			tags: Some(vec!["registration".to_string(), "identity".to_string(), "federation".to_string()]),
			deprecated: None,
			experimental: None,
		}),
		subtypes: None,
		fields: FieldConstraints {
			content: Some(FieldConstraint::Required),
			audience: Some(FieldConstraint::Required),
			parent: Some(FieldConstraint::Forbidden),
			attachments: Some(FieldConstraint::Forbidden),
			subject: Some(FieldConstraint::Forbidden),
		},
		schema: Some(ContentSchemaWrapper {
			content: Some(ContentSchema {
				content_type: ContentType::Object,
				min_length: None,
				max_length: None,
				pattern: None,
				r#enum: None,
				properties: Some({
					let mut props = std::collections::HashMap::new();
					props.insert("id_tag".to_string(), SchemaField {
						field_type: FieldType::String,
						min_length: Some(1),
						max_length: Some(255),
						r#enum: None,
						items: None,
					});
					props.insert("email".to_string(), SchemaField {
						field_type: FieldType::String,
						min_length: None,
						max_length: Some(255),
						r#enum: None,
						items: None,
					});
					// Owner id_tag for community ownership
					props.insert("owner_id_tag".to_string(), SchemaField {
						field_type: FieldType::String,
						min_length: None,
						max_length: Some(255),
						r#enum: None,
						items: None,
					});
					// Issuer role: "registrar" (default) or "owner"
					props.insert("issuer".to_string(), SchemaField {
						field_type: FieldType::String,
						min_length: None,
						max_length: Some(20),
						r#enum: Some(vec![
							serde_json::Value::String("registrar".to_string()),
							serde_json::Value::String("owner".to_string()),
						]),
						items: None,
					});
					props.insert("expires_at".to_string(), SchemaField {
						field_type: FieldType::Number,
						min_length: None,
						max_length: None,
						r#enum: None,
						items: None,
					});
					props
				}),
				// Only id_tag is required; email is optional when owner_id_tag is provided
				required: Some(vec!["id_tag".to_string()]),
				description: Some("Identity registration content with id_tag, optional email/owner, and expiration".to_string()),
			}),
		}),
		behavior: BehaviorFlags {
			broadcast: Some(false),
			allow_unknown: Some(true),
			requires_acceptance: Some(false),
			ttl: None,
			..Default::default()
		},
		hooks: ActionHooks {
			on_create: HookImplementation::None,
			on_receive: HookImplementation::None, // Native hook registered via registry
			on_accept: HookImplementation::None,
			on_reject: HookImplementation::None,
		},
		permissions: Some(PermissionRules {
			can_create: Some("authenticated".to_string()),
			can_receive: Some("any".to_string()),
			requires_following: Some(false),
			requires_connected: Some(false),
		}),
		key_pattern: Some("{type}:{issuer}:{audience}:{content.id_tag}".to_string()),
	}
}

/// PRES - Presence indication (ephemeral)
/// Used for typing indicators, online status, etc. - NOT persisted to database
fn pres_definition() -> ActionDefinition {
	ActionDefinition {
		r#type: "PRES".to_string(),
		version: "1.0".to_string(),
		description: "Presence indication - ephemeral, not persisted".to_string(),
		metadata: Some(ActionMetadata {
			category: Some("ephemeral".to_string()),
			tags: Some(vec!["presence".to_string(), "typing".to_string(), "status".to_string()]),
			deprecated: None,
			experimental: None,
		}),
		subtypes: Some({
			let mut map = HashMap::new();
			map.insert("TYPING".to_string(), "User is typing".to_string());
			map.insert("ONLINE".to_string(), "User is online".to_string());
			map.insert("AWAY".to_string(), "User is away".to_string());
			map.insert("OFFLINE".to_string(), "User went offline".to_string());
			map
		}),
		fields: FieldConstraints {
			content: None,  // Optional presence data
			audience: None, // Optional specific target
			parent: None,
			attachments: Some(FieldConstraint::Forbidden),
			subject: Some(FieldConstraint::Required), // What context (conversation, document, etc.)
		},
		schema: Some(ContentSchemaWrapper {
			content: Some(ContentSchema {
				content_type: ContentType::Object,
				min_length: None,
				max_length: None,
				pattern: None,
				r#enum: None,
				properties: None, // Flexible presence data
				required: None,
				description: Some("Optional presence metadata".to_string()),
			}),
		}),
		behavior: BehaviorFlags {
			broadcast: Some(false),
			allow_unknown: Some(true),
			requires_acceptance: Some(false),
			ephemeral: Some(true), // NOT persisted
			ttl: Some(30),         // Short TTL for presence info
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
		key_pattern: None, // Ephemeral actions don't need deduplication keys
	}
}

/// SUBS - Subscribe to an action
/// Universal subscription mechanism for conversations, posts, events, etc.
fn subs_definition() -> ActionDefinition {
	ActionDefinition {
		r#type: "SUBS".to_string(),
		version: "1.0".to_string(),
		description: "Subscribe to an action's updates".to_string(),
		metadata: Some(ActionMetadata {
			category: Some("subscription".to_string()),
			tags: Some(vec![
				"subscribe".to_string(),
				"membership".to_string(),
				"follow".to_string(),
			]),
			deprecated: None,
			experimental: None,
		}),
		subtypes: Some({
			let mut map = HashMap::new();
			map.insert(
				"UPD".to_string(),
				"Update subscription (role change, preferences)".to_string(),
			);
			map.insert("DEL".to_string(), "Unsubscribe / leave".to_string());
			map
		}),
		fields: FieldConstraints {
			content: None,                             // Optional: role info, preferences
			audience: Some(FieldConstraint::Required), // Owner of the target action
			parent: Some(FieldConstraint::Forbidden),
			attachments: Some(FieldConstraint::Forbidden),
			subject: Some(FieldConstraint::Required), // The action being subscribed to
		},
		schema: Some(ContentSchemaWrapper {
			content: Some(ContentSchema {
				content_type: ContentType::Object,
				min_length: None,
				max_length: None,
				pattern: None,
				r#enum: None,
				properties: Some({
					let mut props = HashMap::new();
					// Role in the subscription: observer, member, moderator, admin
					props.insert(
						"role".to_string(),
						SchemaField {
							field_type: FieldType::String,
							min_length: None,
							max_length: Some(20),
							r#enum: Some(vec![
								serde_json::Value::String("observer".to_string()),
								serde_json::Value::String("member".to_string()),
								serde_json::Value::String("moderator".to_string()),
								serde_json::Value::String("admin".to_string()),
							]),
							items: None,
						},
					);
					// Who invited this user (for closed subscriptions)
					props.insert(
						"invitedBy".to_string(),
						SchemaField {
							field_type: FieldType::String,
							min_length: None,
							max_length: Some(255),
							r#enum: None,
							items: None,
						},
					);
					// Optional join/subscription message
					props.insert(
						"message".to_string(),
						SchemaField {
							field_type: FieldType::String,
							min_length: None,
							max_length: Some(500),
							r#enum: None,
							items: None,
						},
					);
					props
				}),
				required: None, // All fields are optional
				description: Some(
					"Subscription content with role, invitedBy, and optional message".to_string(),
				),
			}),
		}),
		behavior: BehaviorFlags {
			broadcast: Some(false),
			allow_unknown: Some(true),          // Anyone can attempt to subscribe
			requires_acceptance: Some(false),   // Auto-accept for open; moderated via hooks
			requires_subscription: Some(false), // SUBS itself doesn't require subscription
			..Default::default()
		},
		hooks: ActionHooks {
			on_create: HookImplementation::None,
			on_receive: HookImplementation::None, // TODO: Native hook for open/closed check, INVT validation
			on_accept: HookImplementation::None,
			on_reject: HookImplementation::None,
		},
		permissions: Some(PermissionRules {
			can_create: Some("authenticated".to_string()),
			can_receive: Some("any".to_string()),
			requires_following: Some(false),
			requires_connected: Some(false),
		}),
		key_pattern: Some("{type}:{subject}:{issuer}".to_string()), // One subscription per user per action
	}
}

/// FSHR - File share action
fn fileshare_definition() -> ActionDefinition {
	ActionDefinition {
		r#type: "FSHR".to_string(),
		version: "1.0".to_string(),
		description: "Share a file with another user".to_string(),
		metadata: Some(ActionMetadata {
			category: Some("file".to_string()),
			tags: Some(vec!["file".to_string(), "share".to_string()]),
			deprecated: None,
			experimental: None,
		}),
		subtypes: Some({
			let mut map = HashMap::new();
			map.insert("DEL".to_string(), "Revoke file share".to_string());
			map.insert("WRITE".to_string(), "Grant write permission".to_string());
			map
		}),
		fields: FieldConstraints {
			content: Some(FieldConstraint::Required),
			audience: Some(FieldConstraint::Required),
			parent: Some(FieldConstraint::Forbidden),
			attachments: Some(FieldConstraint::Forbidden),
			subject: Some(FieldConstraint::Required), // file_id
		},
		schema: Some(ContentSchemaWrapper {
			content: Some(ContentSchema {
				content_type: ContentType::Object,
				min_length: None,
				max_length: None,
				pattern: None,
				r#enum: None,
				properties: Some({
					let mut props = HashMap::new();
					props.insert(
						"contentType".to_string(),
						SchemaField {
							field_type: FieldType::String,
							min_length: Some(1),
							max_length: Some(255),
							r#enum: None,
							items: None,
						},
					);
					props.insert(
						"fileName".to_string(),
						SchemaField {
							field_type: FieldType::String,
							min_length: Some(1),
							max_length: Some(255),
							r#enum: None,
							items: None,
						},
					);
					props.insert(
						"fileTp".to_string(),
						SchemaField {
							field_type: FieldType::String,
							min_length: Some(1),
							max_length: Some(10),
							r#enum: Some(vec![
								serde_json::Value::String("BLOB".to_string()),
								serde_json::Value::String("CRDT".to_string()),
								serde_json::Value::String("RTDB".to_string()),
							]),
							items: None,
						},
					);
					props
				}),
				required: Some(vec![
					"contentType".to_string(),
					"fileName".to_string(),
					"fileTp".to_string(),
				]),
				description: Some(
					"File share content with contentType, fileName, and fileTp".to_string(),
				),
			}),
		}),
		behavior: BehaviorFlags {
			broadcast: Some(false),
			allow_unknown: Some(false),
			requires_acceptance: Some(true),
			..Default::default()
		},
		hooks: ActionHooks {
			on_create: HookImplementation::None,
			on_receive: HookImplementation::None, // Native hook registered via registry
			on_accept: HookImplementation::None,  // Native hook registered via registry
			on_reject: HookImplementation::None,
		},
		permissions: Some(PermissionRules {
			can_create: Some("authenticated".to_string()),
			can_receive: Some("any".to_string()),
			requires_following: Some(false),
			requires_connected: Some(false),
		}),
		key_pattern: Some("{type}:{subject}:{audience}".to_string()),
	}
}

/// CONV - Conversation container action
/// Groups messages and enables subscription-based access control
fn conv_definition() -> ActionDefinition {
	ActionDefinition {
		r#type: "CONV".to_string(),
		version: "1.0".to_string(),
		description: "Create a conversation for group messaging".to_string(),
		metadata: Some(ActionMetadata {
			category: Some("communication".to_string()),
			tags: Some(vec![
				"conversation".to_string(),
				"group".to_string(),
				"messaging".to_string(),
			]),
			deprecated: None,
			experimental: None,
		}),
		subtypes: Some({
			let mut map = HashMap::new();
			map.insert("UPD".to_string(), "Update conversation settings".to_string());
			map.insert("DEL".to_string(), "Archive/delete conversation".to_string());
			map
		}),
		fields: FieldConstraints {
			content: Some(FieldConstraint::Required), // name, description
			audience: None, // Optional: community conversations have community as audience
			parent: Some(FieldConstraint::Forbidden),
			attachments: None,                         // Optional cover image
			subject: Some(FieldConstraint::Forbidden), // CONV is the root
		},
		schema: Some(ContentSchemaWrapper {
			content: Some(ContentSchema {
				content_type: ContentType::Object,
				min_length: None,
				max_length: None,
				pattern: None,
				r#enum: None,
				properties: Some({
					let mut props = HashMap::new();
					// Conversation name (required)
					props.insert(
						"name".to_string(),
						SchemaField {
							field_type: FieldType::String,
							min_length: Some(1),
							max_length: Some(100),
							r#enum: None,
							items: None,
						},
					);
					// Optional description
					props.insert(
						"description".to_string(),
						SchemaField {
							field_type: FieldType::String,
							min_length: None,
							max_length: Some(500),
							r#enum: None,
							items: None,
						},
					);
					props
				}),
				required: Some(vec!["name".to_string()]),
				description: Some(
					"Conversation settings with name and optional description".to_string(),
				),
			}),
		}),
		behavior: BehaviorFlags {
			broadcast: Some(false),
			allow_unknown: Some(false),
			requires_acceptance: Some(false),
			requires_subscription: Some(false), // Creating CONV doesn't require subscription
			default_flags: Some("rco".to_string()), // Default: closed, no reactions/comments on CONV itself
			subscribable: Some(true),           // CONV can have SUBS pointing to it
			..Default::default()
		},
		hooks: ActionHooks {
			on_create: HookImplementation::None, // Native hook creates admin SUBS
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
		key_pattern: None, // Each conversation is unique
	}
}

/// INVT - Invitation to subscribe to an action
/// Used to invite users to conversations, channels, or other subscribable content
fn invt_definition() -> ActionDefinition {
	ActionDefinition {
		r#type: "INVT".to_string(),
		version: "1.0".to_string(),
		description: "Invite a user to subscribe to an action".to_string(),
		metadata: Some(ActionMetadata {
			category: Some("invitation".to_string()),
			tags: Some(vec![
				"invite".to_string(),
				"subscription".to_string(),
				"conversation".to_string(),
			]),
			deprecated: None,
			experimental: None,
		}),
		subtypes: Some({
			let mut map = HashMap::new();
			map.insert("DEL".to_string(), "Revoke invitation".to_string());
			map
		}),
		fields: FieldConstraints {
			content: None,                             // Optional invitation message, role
			audience: Some(FieldConstraint::Required), // Who is being invited
			parent: Some(FieldConstraint::Forbidden),
			attachments: Some(FieldConstraint::Forbidden),
			subject: Some(FieldConstraint::Required), // The action being invited to (e.g., CONV action_id)
		},
		schema: Some(ContentSchemaWrapper {
			content: Some(ContentSchema {
				content_type: ContentType::Object,
				min_length: None,
				max_length: None,
				pattern: None,
				r#enum: None,
				properties: Some({
					let mut props = HashMap::new();
					// Assigned role for the invitee
					props.insert(
						"role".to_string(),
						SchemaField {
							field_type: FieldType::String,
							min_length: None,
							max_length: Some(20),
							r#enum: Some(vec![
								serde_json::Value::String("observer".to_string()),
								serde_json::Value::String("member".to_string()),
								serde_json::Value::String("moderator".to_string()),
								serde_json::Value::String("admin".to_string()),
							]),
							items: None,
						},
					);
					// Optional message
					props.insert(
						"message".to_string(),
						SchemaField {
							field_type: FieldType::String,
							min_length: None,
							max_length: Some(500),
							r#enum: None,
							items: None,
						},
					);
					props
				}),
				required: None,
				description: Some("Invitation content with optional role and message".to_string()),
			}),
		}),
		behavior: BehaviorFlags {
			broadcast: Some(false),
			allow_unknown: Some(false),       // Only send to known profiles
			requires_acceptance: Some(false), // Doesn't require user to accept INVT itself
			// Note: Subscription check is done by on_create hook on sender side, not on receiver
			requires_subscription: Some(false),
			deliver_subject: Some(true), // Deliver the target action (CONV) with the invitation
			deliver_to_subject_owner: Some(true), // Also deliver to CONV home for SUBS validation
			..Default::default()
		},
		hooks: ActionHooks {
			on_create: HookImplementation::None, // Native hook validates inviter permission
			on_receive: HookImplementation::None, // Native hook sends notification
			on_accept: HookImplementation::None,
			on_reject: HookImplementation::None,
		},
		permissions: Some(PermissionRules {
			can_create: Some("authenticated".to_string()),
			can_receive: Some("any".to_string()),
			requires_following: Some(false),
			requires_connected: Some(false),
		}),
		key_pattern: Some("{type}:{subject}:{audience}".to_string()), // One invitation per user per action
	}
}

/// PRINVT - Profile Invite notification
/// Delivers invite refs (for community or personal profile creation) to connected users
fn prinvt_definition() -> ActionDefinition {
	ActionDefinition {
		r#type: "PRINVT".to_string(),
		version: "1.0".to_string(),
		description: "Deliver a profile creation invite to a connected user".to_string(),
		metadata: Some(ActionMetadata {
			category: Some("system".to_string()),
			tags: Some(vec!["invite".to_string(), "profile".to_string(), "community".to_string()]),
			deprecated: None,
			experimental: None,
		}),
		subtypes: None,
		fields: FieldConstraints {
			content: Some(FieldConstraint::Required), // Invite details (refId, nodeName, etc.)
			audience: Some(FieldConstraint::Required), // Target user
			parent: Some(FieldConstraint::Forbidden),
			attachments: Some(FieldConstraint::Forbidden),
			subject: Some(FieldConstraint::Forbidden),
		},
		schema: Some(ContentSchemaWrapper {
			content: Some(ContentSchema {
				content_type: ContentType::Object,
				min_length: None,
				max_length: None,
				pattern: None,
				r#enum: None,
				properties: Some({
					let mut props = HashMap::new();
					props.insert(
						"refId".to_string(),
						SchemaField {
							field_type: FieldType::String,
							min_length: Some(1),
							max_length: Some(255),
							r#enum: None,
							items: None,
						},
					);
					props.insert(
						"nodeName".to_string(),
						SchemaField {
							field_type: FieldType::String,
							min_length: None,
							max_length: Some(255),
							r#enum: None,
							items: None,
						},
					);
					props.insert(
						"message".to_string(),
						SchemaField {
							field_type: FieldType::String,
							min_length: None,
							max_length: Some(500),
							r#enum: None,
							items: None,
						},
					);
					props
				}),
				required: Some(vec!["refId".to_string()]),
				description: Some(
					"Profile invite details with ref ID and optional message".to_string(),
				),
			}),
		}),
		behavior: BehaviorFlags {
			broadcast: Some(false),
			allow_unknown: Some(false), // Only send to known connected users
			requires_acceptance: Some(false),
			..Default::default()
		},
		hooks: ActionHooks {
			on_create: HookImplementation::None,
			on_receive: HookImplementation::None, // Native hook registered via registry
			on_accept: HookImplementation::None,
			on_reject: HookImplementation::None,
		},
		permissions: Some(PermissionRules {
			can_create: Some("authenticated".to_string()),
			can_receive: Some("any".to_string()),
			requires_following: Some(false),
			requires_connected: Some(true),
		}),
		key_pattern: Some("{type}:{issuer}:{audience}".to_string()),
	}
}

// vim: ts=4
