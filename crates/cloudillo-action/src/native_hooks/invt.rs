// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! INVT (Invitation) action native hooks
//!
//! Handles invitation lifecycle:
//! - on_create: resolves the invite target; community-membership authorization runs pre-store
//!   on the community's own side (see `check_community_authority`)
//! - on_receive: Notifies invitee about the invitation (status='C')
//! - on_accept: Creates SUBS action when invitation is accepted
//! - Subtypes:
//!   - DEL: Revoke invitation

use crate::helpers::{self, SubscriptionRole};
use crate::hooks::{HookContext, HookResult};
use crate::prelude::*;
use crate::subject_ref::{SubjectRef, parse_subject_ref};
use crate::task::{CreateAction, create_action};
use cloudillo_core::roles::is_moderator;
use cloudillo_types::auth_adapter::ActionToken;
use cloudillo_types::meta_adapter::{ProfileConnectionStatus, UpsertProfileFields};

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

/// Whether `issuer` may invite people into the community `community_tag`.
///
/// The community's own account is exempt — a tenant has no `profiles` row of itself.
/// Everyone else needs moderator+; `None` (no row, or a NULL `roles` column) is a non-member.
fn community_invite_allowed(issuer: &str, community_tag: &str, roles: Option<&[Box<str>]>) -> bool {
	issuer == community_tag || roles.is_some_and(is_moderator)
}

/// [`community_invite_allowed`] against the community's own tenant rows. Fails closed on every
/// read error, including the `Err(NotFound)` a missing profile surfaces as.
async fn issuer_may_invite(app: &App, tn_id: TnId, issuer: &str, community_tag: &str) -> bool {
	let roles = match app.meta_adapter.read_profile_roles(tn_id, issuer).await {
		Ok(roles) => roles,
		Err(Error::NotFound) => None,
		Err(e) => {
			warn!(issuer = %issuer, error = %e, "INVT: role lookup failed, denying invite");
			None
		}
	};
	community_invite_allowed(issuer, community_tag, roles.as_deref())
}

/// Whether `issuer` may revoke the community invitation issued by `original_invt_issuer`.
///
/// A moderator may withdraw anyone's; otherwise only its issuer may, which is what lets a
/// since-demoted inviter take their own invitation back. `None` = nothing on record to revoke.
fn community_revoke_allowed(
	issuer: &str,
	original_invt_issuer: Option<&str>,
	is_moderator: bool,
) -> bool {
	is_moderator || original_invt_issuer == Some(issuer)
}

/// The issuer of the active community invitation on record for `invitee`, if any.
/// `exclude_sub_typ` filters to bare INVTs in SQL, so the `LIMIT` cannot hide the row
/// behind `INVT:DEL`s.
async fn pending_invitation_issuer(
	app: &App,
	tn_id: TnId,
	community_tag: &str,
	invitee: &str,
) -> Option<Box<str>> {
	let opts = cloudillo_types::meta_adapter::ListActionOptions {
		typ: Some(vec!["INVT".to_string()]),
		subject: Some(vec![format!("@{}", community_tag)]),
		audience: Some(invitee.to_string()),
		status: Some(vec!["A".to_string()]),
		exclude_sub_typ: Some(Box::new(["DEL".into()])),
		limit: Some(1),
		..Default::default()
	};
	app.meta_adapter
		.list_actions(tn_id, &opts)
		.await
		.ok()?
		.into_iter()
		.next()
		.map(|a| a.issuer.id_tag)
}

/// The INVT subtypes [`check_community_authority`] knows how to judge: the invite (`None`) and
/// its revocation (`DEL`). An allowlist, not a denylist — `conn::has_pending_invitation`
/// filters bare invites with `exclude_sub_typ: ["DEL"]`, so any unknown subtype that reached
/// storage would read back as a pending invitation and grant the `connection_mode = 'I'` bypass.
///
/// [`check_community_authority`] guards on this before its match, so the allowlist lives in one
/// place and a new subtype landing in `definitions.rs` cannot silently acquire an arm.
fn community_invt_subtype_known(subtype: Option<&str>) -> bool {
	matches!(subtype, None | Some("DEL"))
}

/// Whether an action is a community-membership INVT addressed to *this* tenant — the only case
/// [`check_community_authority`] gates.
///
/// A raw compare, and safe as one: `helpers::check_subject_field` rejects a non-canonical
/// identity subject at both boundaries, so `@Club.Example.COM` never reaches storage.
fn is_community_invt(action_type: &str, subject: Option<&str>, tenant_tag: &str) -> bool {
	let (base_type, _) = helpers::extract_type_and_subtype(action_type);
	base_type == "INVT" && subject.and_then(community_id_tag_from_subject) == Some(tenant_tag)
}

/// Community-membership INVT / INVT:DEL authorization. A no-op for everything but an
/// identity-subject INVT addressed to this very tenant.
///
/// `actor` is who asserts the authority — the token's `iss` inbound, `auth.id_tag` outbound.
/// Deliberately NOT the stored `issuer_tag`: outbound that is the tenant's own id_tag, which
/// satisfies [`community_invite_allowed`]'s "the community itself" disjunct unconditionally.
///
/// `typ` is `(type, separate subtype)` — outbound `("INVT", Some("DEL"))`, inbound
/// `("INVT:DEL", None)`.
///
/// **Must run pre-store on both paths.** Inbound, key-pattern dedup retires the pending INVT
/// the moment an INVT:DEL is stored, so a post-store hook can neither prevent a revocation nor
/// still see the row it must judge. Outbound, `on_create` runs after `finalize_action` set
/// status 'A', and `continue_processing: false` does not roll back.
pub(crate) async fn check_community_authority(
	app: &App,
	tn_id: TnId,
	tenant_tag: &str,
	typ: (&str, Option<&str>),
	subject: Option<&str>,
	audience: Option<&str>,
	actor: &str,
) -> ClResult<()> {
	let (typ, sub_typ) = typ;
	if !is_community_invt(typ, subject, tenant_tag) {
		return Ok(());
	}
	let (_, embedded) = helpers::extract_type_and_subtype(typ);
	let subtype = sub_typ.map(str::to_owned).or(embedded);

	// Unknown subtypes are refused, not exempted: `conn::has_pending_invitation` filters bare
	// invites with `exclude_sub_typ: ["DEL"]`, so anything unrecognised that reached storage
	// would read back as a pending invitation and grant the `connection_mode = 'I'` bypass.
	if !community_invt_subtype_known(subtype.as_deref()) {
		warn!("INVT: unknown subtype {:?} for community {}, rejecting", subtype, tenant_tag);
		return Err(Error::PermissionDenied);
	}

	let allowed = match subtype.as_deref() {
		// The invite itself. Storing it at the community home is what `conn::on_receive`'s
		// `has_pending_invitation` treats as authority to bypass `connection_mode = 'I'`.
		None => issuer_may_invite(app, tn_id, actor, tenant_tag).await,
		// The revocation. `pending_invitation_issuer` runs before the dedup retires the row,
		// so its `status: ['A']` filter still sees the invitation being withdrawn — which is
		// what keeps the since-demoted inviter's own withdrawal working.
		Some("DEL") => {
			let invitee = audience.unwrap_or_default();
			let original = pending_invitation_issuer(app, tn_id, tenant_tag, invitee).await;
			let is_mod = issuer_may_invite(app, tn_id, actor, tenant_tag).await;
			community_revoke_allowed(actor, original.as_deref(), is_mod)
		}
		// Unreachable — the guard above already refused these. Defence in depth.
		_ => false,
	};
	if !allowed {
		warn!(
			"INVT: {} has no authority for {} in community {}, rejecting",
			actor, typ, tenant_tag
		);
		return Err(Error::PermissionDenied);
	}
	Ok(())
}

/// Pre-store authorization for a federated community INVT / INVT:DEL arriving at this tenant.
/// Thin wrapper over [`check_community_authority`]: the token's `iss` is the acting identity.
pub(crate) async fn check_inbound(
	app: &App,
	tn_id: TnId,
	action: &ActionToken,
	tenant_tag: &str,
) -> ClResult<()> {
	check_community_authority(
		app,
		tn_id,
		tenant_tag,
		(&action.t, None),
		action.sub.as_deref(),
		action.aud.as_deref(),
		&action.iss,
	)
	.await
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
		return on_create_community(&context, subject_id).await;
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

	let user_role = helpers::get_subscription_role(subscription.x.as_ref());
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
/// Authorization is **not** the inviter side's to do: reading the issuer's role in the
/// community would mean reading another tenant's rows, which this architecture does not allow,
/// and it only ever worked for communities that happen to be hosted here. It lives on the
/// community's own side, pre-store and never in this hook — [`check_inbound`] for a federated
/// invite, `handler::post_action` for a locally-created one — both via
/// [`check_community_authority`]. See its doc for why a hook cannot stand in.
///
/// So `conn::on_receive`'s `has_pending_invitation` lookup still matches on type / subject /
/// audience / status only, never on the INVT issuer — but the INVT it finds is trustworthy,
/// because it could not have been stored without passing that gate.
async fn on_create_community(context: &HookContext, subject_id: &str) -> ClResult<HookResult> {
	let Some(community_id_tag) = community_id_tag_from_subject(subject_id) else {
		warn!("INVT on_create (community): subject {} is not an identity reference", subject_id);
		return Ok(HookResult { continue_processing: false, ..Default::default() });
	};

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
	let mut is_community_home = false;
	let is_conv_home = if let Some(ref subject_id) = context.subject {
		let tenant_id_tag = app.meta_adapter.read_tenant(tn_id).await.ok().map(|t| t.id_tag);
		match (parse_subject_ref(subject_id), tenant_id_tag) {
			(Some(SubjectRef::Identity(id_tag)), Some(tenant)) => {
				is_community_home = id_tag == tenant.as_ref();
				is_community_home
			}
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

	// Authorization for both the invite and its revocation runs pre-store, in
	// [`check_inbound`] — a post-store hook is too late to stop either. What is left here is
	// the *effect* of an already-authorized revocation.
	//
	// The key-pattern dedup already covers the normal case: `{type}` substitutes the *base*
	// type, so an `INVT:DEL` builds the same `INVT:@community:invitee` key as the invite it
	// withdraws and retires it on store. This sweep is for rows that key differently — ones
	// written before `helpers::check_subject_field` made the `@<id_tag>` subject canonical on
	// write. Idempotent, so the overlap costs nothing.
	if is_community_home && context.subtype.as_deref() == Some("DEL") {
		crate::native_hooks::conn::retire_community_invitations(
			&app,
			tn_id,
			&context.tenant_tag,
			context.audience.as_deref().unwrap_or_default(),
		)
		.await;
	}

	// Resting status is declared here and written once by the post-store
	// pipeline (process.rs). The invitee copy must rest at 'C' so it shows as
	// an actionable, persistent confirmation; the community-home copy stays at
	// 'A' (default) so the `has_pending_invitation` lookup in conn.rs finds it.
	let status: Option<char> = match context.subtype.as_deref() {
		None => {
			if is_conv_home {
				// CONV home context - store for SUBS validation, keep default 'A' status
				info!(
					"INVT: Storing invitation at CONV home for SUBS validation (action_id: {})",
					context.action_id
				);
				None
			} else {
				// Invitee context - set status to 'C' for confirmation UI
				info!(
					"INVT: Setting invitation to confirmation status for invitee (action_id: {})",
					context.action_id
				);
				Some('C')
			}
		}
		Some("DEL") => {
			// Invitation revoked - handled by normal action processing
			info!("INVT:DEL: Invitation revoked by {}", context.issuer);
			None
		}
		Some(subtype) => {
			// A rejection, not "no opinion": `process.rs` writes `status.unwrap_or('A')`,
			// so `None` here would leave an unrecognised INVT resting as an active one.
			warn!("INVT on_receive: Unknown subtype '{}', rejecting", subtype);
			Some('D')
		}
	};

	Ok(HookResult { status, ..Default::default() })
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

	// The community learns of the membership the only way it may: as a federated CONN it
	// processes in its own tenant context. Writing the invitee's row in the community's
	// tenant directly from here — which this used to do for locally-hosted communities —
	// is a cross-tenant write, and it granted `contributor` driven entirely from the
	// invitee's side, with the inviter's authority never established. The community's own
	// CONN `on_receive` sees the existing INVT and skips the connection_mode 'I'
	// rejection, so the shortcut was redundant as well as forbidden.
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

#[cfg(test)]
mod tests {
	use super::*;

	fn roles(list: &[&str]) -> Vec<Box<str>> {
		list.iter().map(|r| Box::from(*r)).collect()
	}

	/// The revocation gate. An ungated `INVT:DEL` was the escalation path: it rests at 'A'
	/// like an invite and `ListActionOptions` has no `sub_typ` filter, so `conn.rs` read it
	/// as a pending invitation and handed its issuer the `connection_mode = 'I'` bypass.
	#[test]
	fn only_a_moderator_or_the_original_inviter_may_revoke() {
		// A moderator may withdraw anyone's, including one with no invitation on record.
		assert!(community_revoke_allowed("mod.example.com", Some("alice.example.com"), true));
		assert!(community_revoke_allowed("mod.example.com", None, true));

		// The original inviter keeps the right even after being demoted.
		assert!(community_revoke_allowed("alice.example.com", Some("alice.example.com"), false));

		// An ordinary member with nothing of their own on record — the bug.
		assert!(!community_revoke_allowed("mallory.example.com", Some("alice.example.com"), false));
		assert!(!community_revoke_allowed("mallory.example.com", None, false));
	}

	/// The subtype allowlist. `exclude_sub_typ: ["DEL"]` in `conn::has_pending_invitation` is a
	/// denylist, so an unknown subtype slipping past this gate reads back as a pending
	/// invitation and hands its issuer the `connection_mode = 'I'` bypass.
	#[test]
	fn only_the_invite_and_its_revocation_are_judgeable_subtypes() {
		assert!(community_invt_subtype_known(None));
		assert!(community_invt_subtype_known(Some("DEL")));

		assert!(!community_invt_subtype_known(Some("XYZ")));
		assert!(!community_invt_subtype_known(Some("del"))); // subtypes are case-sensitive
		assert!(!community_invt_subtype_known(Some("")));
	}

	/// The routing half of the pre-store gate: which inbound actions `check_inbound` judges
	/// at all. The authority half is the two predicates tested above.
	#[test]
	fn only_an_identity_invt_addressed_to_this_tenant_is_gated() {
		// The invite and its revocation, both aimed at the community we are.
		assert!(is_community_invt("INVT", Some("@club.example.com"), "club.example.com"));
		assert!(is_community_invt("INVT:DEL", Some("@club.example.com"), "club.example.com"));
		// A non-canonical spelling cannot get this far: `helpers::check_subject_field` refuses
		// it at both boundaries, so it never reaches storage — and here it simply misses.
		assert!(!is_community_invt("INVT", Some("@Club.Example.COM"), "club.example.com"));

		// Another community's invite merely passing through, an action-subject INVT (the
		// CONV branch, gated by subscription role instead), a subject-less one, and a
		// different action type entirely.
		assert!(!is_community_invt("INVT", Some("@other.example.com"), "club.example.com"));
		assert!(!is_community_invt("INVT", Some("a1~abc"), "club.example.com"));
		assert!(!is_community_invt("INVT", None, "club.example.com"));
		assert!(!is_community_invt("CONN", Some("@club.example.com"), "club.example.com"));
	}

	/// The community-membership gate. Storing an INVT at the community home is what
	/// `conn::on_receive`'s `has_pending_invitation` treats as authorization to bypass
	/// `connection_mode = 'I'`, so anyone below moderator getting one stored is the whole bug.
	#[test]
	fn only_the_community_itself_or_a_moderator_may_invite() {
		// The community's own account — no `profiles` row of itself, so no roles to read.
		assert!(community_invite_allowed("club.example.com", "club.example.com", None));

		assert!(community_invite_allowed(
			"mod.example.com",
			"club.example.com",
			Some(&roles(&["moderator"]))
		));
		assert!(community_invite_allowed(
			"boss.example.com",
			"club.example.com",
			Some(&roles(&["leader"]))
		));

		// An ordinary member — passes INVT's `allow_unknown: false` reachability test, but
		// has no standing to invite.
		assert!(!community_invite_allowed(
			"member.example.com",
			"club.example.com",
			Some(&roles(&["contributor"]))
		));
		// No profile row at all (`read_profile_roles` returns `Err(NotFound)`, mapped to
		// `None`), and a row with a NULL `roles` column — both are non-members.
		assert!(!community_invite_allowed("stranger.example.com", "club.example.com", None));
		assert!(!community_invite_allowed(
			"stranger.example.com",
			"club.example.com",
			Some(&roles(&[]))
		));
	}

	/// Fed the action's stored `issuer_tag` — the *tenant's own* id_tag on the outbound path —
	/// the "community's own account" disjunct passes unconditionally on a locally-hosted
	/// community, and any `contributor` can store an INVT. The authority argument must be the
	/// authenticated caller; `handler::post_action` supplies `auth.id_tag`.
	#[test]
	fn a_plain_member_is_refused_but_the_tenant_tag_as_actor_would_not_be() {
		let member = "member.example.com";
		let community = "club.example.com";
		let member_roles = roles(&["contributor"]);

		assert!(!community_invite_allowed(member, community, Some(&member_roles)));
		// Passing the tenant tag instead of the caller is what made the gate a no-op.
		assert!(community_invite_allowed(community, community, Some(&member_roles)));
	}
}

// vim: ts=4
