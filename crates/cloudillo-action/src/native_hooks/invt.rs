// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! INVT (Invitation) action native hooks
//!
//! Handles invitation lifecycle:
//! - on_create: Validates inviter has moderator+ permission on target
//! - on_receive: Notifies invitee about the invitation (status='C')
//! - on_accept: Creates SUBS action when invitation is accepted
//! - Subtypes:
//!   - DEL: Revoke invitation

use crate::helpers::{self, SubscriptionRole};
use crate::hooks::{HookContext, HookResult};
use crate::prelude::*;
use crate::subject_ref::{SubjectRef, parse_subject_ref};
use crate::task::{CreateAction, create_action};
use cloudillo_types::meta_adapter::{
	ProfileConnectionStatus, UpdateActionDataOptions, UpsertProfileFields,
};

/// Extract the community id_tag from an identity-typed subject string.
///
/// Identity subjects are always `@<id_tag>`; bare-id_tag subjects are not
/// supported. Returns `None` for placeholder/action subjects.
fn community_id_tag_from_subject(subject: &str) -> Option<&str> {
	match parse_subject_ref(subject) {
		Some(SubjectRef::Identity(id_tag)) => Some(id_tag),
		_ => None,
	}
}

/// Resolve a profile id_tag to a local tenant id.
///
/// Returns `Some(tn_id)` when the id_tag matches a tenant hosted on this
/// server, `None` otherwise. Used by the community-membership-invite path
/// to gate authorization on the issuer's role *inside* the community
/// tenant.
async fn lookup_local_tenant(app: &App, id_tag: &str) -> ClResult<Option<TnId>> {
	match app.auth_adapter.read_tn_id(id_tag).await {
		Ok(tn_id) => Ok(Some(tn_id)),
		Err(Error::NotFound) => Ok(None),
		Err(e) => Err(e),
	}
}

/// Did the issuer reach moderator+ role in the given community tenant?
async fn issuer_has_community_authority(
	app: &App,
	community_tn_id: TnId,
	issuer: &str,
) -> ClResult<bool> {
	let roles = app.meta_adapter.read_profile_roles(community_tn_id, issuer).await?;
	let Some(roles) = roles else {
		return Ok(false);
	};
	Ok(roles.iter().any(|r| {
		let r = r.as_ref();
		r == "leader" || r == "moderator"
	}))
}

/// INVT on_create hook - Validate inviter permission
///
/// Logic:
/// - Check inviter has active SUBS on target with moderator+ role
/// - Creator of target action can always invite
pub async fn on_create(app: App, context: HookContext) -> ClResult<HookResult> {
	let tn_id = context.tn_id;

	let Some(subject_id) = context.subject.as_deref() else {
		warn!("INVT on_create: No subject specified");
		return Ok(HookResult { continue_processing: false, ..Default::default() });
	};

	let Some(audience) = context.audience.as_deref() else {
		warn!("INVT on_create: No audience specified");
		return Ok(HookResult { continue_processing: false, ..Default::default() });
	};

	info!("INVT: {} inviting {} to {}", context.issuer, audience, subject_id);

	// Identity subjects (`@<id_tag>`) route to the community-membership
	// branch. Anything else is required to resolve to a known action.
	if matches!(parse_subject_ref(subject_id), Some(SubjectRef::Identity(_))) {
		return on_create_community(app, &context, subject_id).await;
	}

	// Get the target action
	let Some(target_action) = app.meta_adapter.get_action(tn_id, subject_id).await? else {
		warn!("INVT on_create: subject {} does not resolve to a known action", subject_id);
		return Ok(HookResult { continue_processing: false, ..Default::default() });
	};

	// Creator of target can always invite
	if context.issuer == target_action.issuer.id_tag.as_ref() {
		debug!("INVT: Inviter is target creator, permission granted");
		return Ok(HookResult::default());
	}

	// Check inviter's subscription
	let subs_key = format!("SUBS:{}:{}", subject_id, context.issuer);
	let subscription = app.meta_adapter.get_action_by_key(tn_id, &subs_key).await.ok().flatten();

	let Some(subscription) = subscription else {
		warn!("INVT on_create: Inviter {} has no subscription to {}", context.issuer, subject_id);
		return Ok(HookResult { continue_processing: false, ..Default::default() });
	};

	// Parse role and check permission using x.role (with fallback to content.role)
	let content_json = subscription
		.content
		.as_ref()
		.and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok());
	let user_role = helpers::get_subscription_role(subscription.x.as_ref(), content_json.as_ref());
	let required = SubscriptionRole::required_for_action("INVT", None);

	if user_role < required {
		warn!(
			"INVT on_create: Inviter {} has insufficient role ({:?}) for INVT (requires {:?})",
			context.issuer, user_role, required
		);
		return Ok(HookResult { continue_processing: false, ..Default::default() });
	}

	info!("INVT: Permission granted for {} to invite to {}", context.issuer, subject_id);
	Ok(HookResult::default())
}

/// INVT on_create branch — community-membership invitation.
///
/// Triggered when `subject` resolves to a profile id_tag (rather than an
/// action id). The invitation invites `audience` to become a member of the
/// community identified by `subject_id`.
///
/// Authorization: the inviter must hold `moderator` or `leader` in the
/// community tenant. If the community is not hosted locally, the local
/// server cannot verify the role and admits the action — the community
/// home will re-validate on receive.
async fn on_create_community(
	app: App,
	context: &HookContext,
	subject_id: &str,
) -> ClResult<HookResult> {
	let Some(community_id_tag) = community_id_tag_from_subject(subject_id) else {
		warn!("INVT on_create (community): subject {} is not an identity reference", subject_id);
		return Ok(HookResult { continue_processing: false, ..Default::default() });
	};

	let local_community_tn_id = lookup_local_tenant(&app, community_id_tag).await?;
	if let Some(community_tn_id) = local_community_tn_id {
		let authorized =
			issuer_has_community_authority(&app, community_tn_id, &context.issuer).await?;
		if !authorized {
			warn!(
				"INVT on_create (community): Inviter {} lacks moderator+ role in {}",
				context.issuer, community_id_tag
			);
			return Ok(HookResult { continue_processing: false, ..Default::default() });
		}
	} else {
		// Remote community — cannot verify inviter authority; allow to proceed
		// as the remote community will enforce its own authorization on accept.
		warn!(
			"INVT on_create (community): skipping authz for remote community {} (inviter: {})",
			community_id_tag, context.issuer
		);
	}

	info!(
		"INVT on_create (community): {} invites {} to community {}",
		context.issuer,
		context.audience.as_deref().unwrap_or("?"),
		community_id_tag
	);
	Ok(HookResult::default())
}

/// INVT on_receive hook - Handle invitation receipt
///
/// Logic:
/// - Determine if we're the CONV home (subject owner) or the invitee
/// - CONV home: Store for SUBS validation (status stays 'A')
/// - Invitee: Set status to 'C' (confirmation) so user can accept/reject
pub async fn on_receive(app: App, context: HookContext) -> ClResult<HookResult> {
	let tn_id = context.tn_id;

	info!(
		"INVT: Received invitation for {} from {} to action {:?}",
		context.audience.as_deref().unwrap_or("unknown"),
		context.issuer,
		context.subject
	);

	// Determine if we're the subject owner (CONV home / community home) or
	// the invitee. For action subjects, the home is the action's issuer.
	// For identity subjects, the home is the identity itself.
	let is_conv_home = if let Some(ref subject_id) = context.subject {
		let tenant_id_tag = app.meta_adapter.read_tenant(tn_id).await.ok().map(|t| t.id_tag);
		match (parse_subject_ref(subject_id), tenant_id_tag) {
			(Some(SubjectRef::Identity(id_tag)), Some(tenant)) => id_tag == tenant.as_ref(),
			(Some(SubjectRef::Action(_)), Some(tenant)) => app
				.meta_adapter
				.get_action(tn_id, subject_id)
				.await
				.ok()
				.flatten()
				.is_some_and(|sa| sa.issuer.id_tag.as_ref() == tenant.as_ref()),
			_ => false,
		}
	} else {
		false
	};

	match context.subtype.as_deref() {
		None => {
			if is_conv_home {
				// CONV home context - store for SUBS validation, keep default 'A' status
				info!(
					"INVT: Storing invitation at CONV home for SUBS validation (action_id: {})",
					context.action_id
				);
				// Status stays 'A' (default) - invitation is recorded for SUBS validation lookup
			} else {
				// Invitee context - set status to 'C' for confirmation UI
				info!(
					"INVT: Setting invitation to confirmation status for invitee (action_id: {})",
					context.action_id
				);
				let update_opts =
					UpdateActionDataOptions { status: Patch::Value('C'), ..Default::default() };

				if let Err(e) = app
					.meta_adapter
					.update_action_data(tn_id, &context.action_id, &update_opts)
					.await
				{
					warn!("INVT: Failed to update action status to C: {}", e);
				}
			}
		}
		Some("DEL") => {
			// Invitation revoked - handled by normal action processing
			info!("INVT:DEL: Invitation revoked by {}", context.issuer);
		}
		Some(subtype) => {
			warn!("INVT on_receive: Unknown subtype '{}', ignoring", subtype);
		}
	}

	Ok(HookResult::default())
}

/// INVT on_accept hook - Create subscription when invitation accepted
///
/// Logic:
/// - When invitee accepts invitation, create SUBS action for them
/// - SUBS targets the subject (group/action) from the invitation
/// - SUBS will auto-accept because INVT exists (see subs.rs on_receive)
pub async fn on_accept(app: App, context: HookContext) -> ClResult<HookResult> {
	let tn_id = context.tn_id;

	// INVT structure:
	// - issuer = person who invited (Alice)
	// - audience = person being invited (Bob)
	// - subject = group/action being invited to

	let Some(audience) = context.audience.as_deref() else {
		warn!("INVT on_accept: No audience (invitee) specified");
		return Ok(HookResult::default());
	};

	let Some(subject) = context.subject.as_deref() else {
		warn!("INVT on_accept: No subject (target group) specified");
		return Ok(HookResult::default());
	};

	info!("INVT: {} accepted invitation from {} to join {}", audience, context.issuer, subject);

	// Identity subjects route straight to the community-membership branch.
	if matches!(parse_subject_ref(subject), Some(SubjectRef::Identity(_))) {
		return on_accept_community(&app, &context, subject, audience).await;
	}

	// Get the target action to find its owner. If the subject does not
	// resolve to an action, bail — bare-id_tag subjects are not supported.
	let Some(target_action) = app.meta_adapter.get_action(tn_id, subject).await? else {
		warn!("INVT on_accept: subject {} does not resolve to a known action", subject);
		return Ok(HookResult::default());
	};

	// Create SUBS action for the invitee
	// The invitee (audience) becomes the issuer of the SUBS
	// audience_tag = CONV owner so SUBS federates to them
	// Role is stored in x.role (server-side metadata, not in JWT)
	let subs_action = CreateAction {
		typ: "SUBS".into(),
		audience_tag: Some(target_action.issuer.id_tag.clone()),
		subject: Some(subject.to_owned().into()),
		x: Some(serde_json::json!({ "role": "member" })),
		..Default::default()
	};

	// Create the subscription on behalf of the invitee
	match create_action(&app, tn_id, audience, subs_action).await {
		Ok(subs_id) => {
			info!("INVT: Created SUBS {} for {} on {}", subs_id, audience, subject);
		}
		Err(e) => {
			error!("INVT: Failed to create SUBS for {} on {}: {}", audience, subject, e);
			// Don't fail the accept - the invitation is still accepted
		}
	}

	Ok(HookResult::default())
}

/// INVT on_accept branch — community-membership invitation.
///
/// Marks the invitee as a member of the community in the local profile
/// cache, and sends a CONN action to the community so the relationship
/// is recorded on both sides. The CONN bypasses the community's
/// `connection_mode='I'` (Invite only) gate because there is a matching
/// outstanding INVT.
async fn on_accept_community(
	app: &App,
	context: &HookContext,
	subject: &str,
	audience: &str,
) -> ClResult<HookResult> {
	let tn_id = context.tn_id;

	let Some(community_id_tag) = community_id_tag_from_subject(subject) else {
		warn!("INVT on_accept (community): subject {} is not an identity reference", subject);
		return Ok(HookResult::default());
	};

	info!("INVT (community): {} accepts invitation to community {}", audience, community_id_tag);

	// Update invitee-side profile cache for the community.
	let community_upsert = UpsertProfileFields {
		connected: Patch::Value(ProfileConnectionStatus::Connected),
		following: if context.tenant_type == "community" {
			Patch::Undefined
		} else {
			Patch::Value(true)
		},
		..Default::default()
	};
	if let Err(e) = app
		.meta_adapter
		.upsert_profile(tn_id, community_id_tag, &community_upsert)
		.await
	{
		warn!(
			"INVT (community): Failed to update community profile cache for {}: {}",
			community_id_tag, e
		);
	}

	// If the community is hosted locally, also flip the invitee's row in
	// the community tenant to Connected with a baseline `member` role.
	if let Ok(Some(community_tn_id)) = lookup_local_tenant(app, community_id_tag).await {
		let invitee_upsert = UpsertProfileFields {
			connected: Patch::Value(ProfileConnectionStatus::Connected),
			roles: Patch::Value(Some(vec!["member".into()])),
			..Default::default()
		};
		if let Err(e) = app
			.meta_adapter
			.upsert_profile(community_tn_id, audience, &invitee_upsert)
			.await
		{
			warn!(
				"INVT (community): Failed to upsert invitee profile in community tenant {}: {}",
				community_id_tag, e
			);
		}
	}

	// Federate a CONN action to the community so the connection is
	// recorded on the community side as well. The community's CONN
	// on_receive sees the existing INVT and skips the connection_mode
	// 'I' rejection.
	let conn_action = CreateAction {
		typ: "CONN".into(),
		audience_tag: Some(community_id_tag.to_string().into()),
		..Default::default()
	};
	if let Err(e) = create_action(app, tn_id, audience, conn_action).await {
		warn!("INVT (community): Failed to create CONN to community {}: {}", community_id_tag, e);
	}

	Ok(HookResult::default())
}

// vim: ts=4
