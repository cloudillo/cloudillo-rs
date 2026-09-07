// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Who may read and who may change a file's share set.
//!
//! Lives in `cloudillo-core` because it gates two crates: the share-entry endpoints in
//! `cloudillo-file` and the ref (share-link) endpoints in `cloudillo-ref`. A `refId` is a bearer
//! credential, so minting, listing or revoking one is share management and must pass the same gate
//! as `POST /api/files/{id}/shares`.
//!
//! Every `require_*` entry point refuses any scoped token, share-link delegation *or* API-key
//! capability scope alike: a delegated link must never widen or mutate the grant that admitted it
//! (confused-deputy), and share management is never delegable.
//!
//! # Handler ordering convention
//!
//! Every share-entry and ref handler runs its checks in this order, so both crates answer the same
//! request shape the same way:
//!
//! 1. The caller-shape check (`reject_scoped`, or the scope refusal inside
//!    [`require_unscoped_file_access`]) before anything, body validation included: a scoped caller
//!    must not learn even whether their request was well formed.
//! 2. Resource authorization as soon as the resource id is known.
//! 3. Body validation last — except where a gate needs a parsed value, such as
//!    [`ensure_grant_within`] needing the validated permission char.

use crate::prelude::*;
use cloudillo_types::auth_adapter::AuthCtx;
use cloudillo_types::types::AccessLevel;

use crate::file_access::{self, FileAccessCtx, FileAccessResult};

/// Refuse any scoped token, then resolve the caller's unscoped access to `file_id`.
///
/// The weakest of the share gates: it confers no standing, only "this caller can reach the row
/// under their own identity". Use it where [`require_share_reader`]'s Write floor would be too
/// strict; for anything conferring standing use [`share_standing`] or the `require_*` wrappers.
pub async fn require_unscoped_file_access(
	app: &App,
	tn_id: TnId,
	file_id: &str,
	auth: &AuthCtx,
	tenant_id_tag: &str,
) -> ClResult<FileAccessResult> {
	if auth.scope.is_some() {
		warn!("Scoped token attempted to access share entries");
		return Err(Error::PermissionDenied);
	}

	let ctx = FileAccessCtx { user_id_tag: &auth.id_tag, tenant_id_tag, user_roles: &auth.roles };
	// Scope `None` — scoped callers were rejected above.
	match file_access::check_file_access_with_scope(app, tn_id, file_id, &ctx, None, None).await {
		Err(file_access::FileAccessError::NotFound) => Err(Error::NotFound),
		Err(file_access::FileAccessError::AccessDenied) => Err(Error::PermissionDenied),
		Err(file_access::FileAccessError::InternalError(msg)) => Err(Error::Internal(msg)),
		Ok(access) => Ok(access),
	}
}

/// Pure share-management decision.
///
/// Requires access to the file itself, plus standing: an explicit `'A'` share grant, or a community
/// leader over a locally originating row.
///
/// Ownership needs no test of its own here: `file_access::get_access_level` already returns `Admin`
/// to the owner of a locally originating row, so `can_manage_shares()` carries it. On a *mirrored*
/// row share management belongs to the upstream node, and an owner test would reopen exactly what
/// that gate closes.
///
/// `leader_over_local_row` means "holds `leader` **and** the row originates here": leadership is
/// authority over what this node hosts, not over a foreign owner's file that merely happens to be
/// placed here. Same boundary `file_access::get_access_level` draws for roles.
fn is_share_manager(access: AccessLevel, leader_over_local_row: bool) -> bool {
	// Defence in depth: `require_unscoped_file_access` already rejected anyone who cannot reach it.
	if access == AccessLevel::None {
		return false;
	}
	// `can_manage_shares()` covers the `'A'` grant — `from_perm_char` maps it straight to `Admin`,
	// as does ownership of a local row. The explicit leader test is for rows a leader does not
	// otherwise reach at `Admin`.
	leader_over_local_row || access.can_manage_shares()
}

/// Pure share-*listing* decision: any unscoped caller with Write-or-better access may enumerate a
/// file's share entries.
///
/// Not the whole reader test — a manager outranks a reader even at `AccessLevel::Read` (a leader
/// over a local row). [`classify_standing`] composes the two.
fn is_share_reader(access: AccessLevel) -> bool {
	access.can_write()
}

/// A caller's standing over one file's share set. Ordered: `Manager` implies `Reader`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ShareStanding {
	None,
	Reader,
	Manager,
}

/// Pure classifier behind [`share_standing`].
fn classify_standing(access: AccessLevel, leader_over_local_row: bool) -> ShareStanding {
	if is_share_manager(access, leader_over_local_row) {
		ShareStanding::Manager
	} else if is_share_reader(access) {
		ShareStanding::Reader
	} else {
		ShareStanding::None
	}
}

/// Pure grant-ceiling rule behind [`share_standing`].
///
/// Everyone is capped at what they hold — already `Admin` for the owner of a local row or an
/// explicit `'A'` grantee. The cap is what stops a `Read`-level manager from minting a `write`
/// grant and redeeming it.
///
/// `leader_over_local_row` means the same as in [`is_share_manager`], so a leader never gains a
/// ceiling over a mirrored row whose content authority lives on another node.
fn grant_ceiling(access: AccessLevel, leader_over_local_row: bool) -> AccessLevel {
	if leader_over_local_row { AccessLevel::Admin } else { access }
}

/// The conjunction the two rules above take as a parameter: holds `leader` **and** the row
/// originates on this node.
///
/// Leadership is authority over what this node hosts, not over a foreign owner's file that merely
/// happens to be placed here — a mirrored row (Pin/Place copy, FSHR-accepted share) names its
/// source in `upstream`, and minting grants or links on it is that node's call. A member-owned
/// *local* row is reached, which is the point of the ownership model: leadership extends over the
/// tenant's members' own content. Same boundary `file_access::get_access_level` draws for roles.
fn leader_over_local_row(
	roles: &[Box<str>],
	upstream: Option<&cloudillo_types::meta_adapter::ProfileInfo>,
) -> bool {
	crate::roles::is_leader(roles) && upstream.is_none()
}

/// A caller's resolved authority over one file's share set.
pub struct ShareAuthority {
	/// The caller's own access, so callers needing the file view do not re-fetch it.
	pub access: FileAccessResult,
	pub standing: ShareStanding,
	/// The highest level this caller may hand out: their own `access_level`, already `Admin` for
	/// ownership-derived standing.
	pub grant_ceiling: AccessLevel,
}

/// Resolve the caller's standing over `file_id`'s share set in one pass.
///
/// Rejects scoped (share-link) callers, resolves file access, then classifies.
pub async fn share_standing(
	app: &App,
	tn_id: TnId,
	file_id: &str,
	auth: &AuthCtx,
	tenant_id_tag: &str,
) -> ClResult<ShareAuthority> {
	let access = require_unscoped_file_access(app, tn_id, file_id, auth, tenant_id_tag).await?;

	let leader_over_local_row =
		leader_over_local_row(&auth.roles, access.file_view.upstream.as_ref());

	// No extra query needed: an explicit `'A'` entry (direct or folder-inherited) and ownership of a
	// local row both already reached `access_level` as `Admin`.
	let standing = classify_standing(access.access_level, leader_over_local_row);

	let ceiling = grant_ceiling(access.access_level, leader_over_local_row);

	Ok(ShareAuthority { access, standing, grant_ceiling: ceiling })
}

/// Resolve share standing for a server-side actor named only by `id_tag` — no token, hence no
/// [`AuthCtx`] to hand in. Used by the FSHR native hook, where the actor is the action's issuer and
/// the write it guards (`create_share_entry`) is the same one `POST /api/files/{id}/shares` makes.
///
/// Roles are resolved the way `cloudillo-auth`'s access-token path does: the tenant account is
/// implicitly `leader`, everyone else gets their profile row expanded through
/// [`crate::roles::expand_roles_preserving_extras`]. A *missing* profile yields no roles, which only
/// ever denies; an *unreadable* one propagates, so a transient database failure surfaces as an
/// internal error rather than a misleading `PermissionDenied`. `scope` is always `None` — a hook is
/// never a delegated caller.
pub async fn share_standing_for_actor(
	app: &App,
	tn_id: TnId,
	file_id: &str,
	actor_id_tag: &str,
	tenant_id_tag: &str,
) -> ClResult<ShareAuthority> {
	let roles: Box<[Box<str>]> = if actor_id_tag == tenant_id_tag {
		crate::roles::parse_roles(&crate::roles::expand_roles_preserving_extras(&["leader".into()]))
	} else {
		match app.meta_adapter.read_profile_roles(tn_id, actor_id_tag).await? {
			Some(highest) => {
				crate::roles::parse_roles(&crate::roles::expand_roles_preserving_extras(&highest))
			}
			None => Box::new([]),
		}
	};

	let auth = AuthCtx { tn_id, id_tag: actor_id_tag.into(), roles, scope: None, anonymous: false };
	share_standing(app, tn_id, file_id, &auth, tenant_id_tag).await
}

/// A share manager may not hand out more access than [`ShareAuthority::grant_ceiling`] allows.
///
/// Manager standing is not Write-derived (a `Read`-level leader qualifies), and
/// `file_access::get_access_level_with_scope` returns a share-link scope's level uncapped by the
/// holder's own ACL — so without this a `Read` manager could mint a `write` link and redeem it to
/// escalate themselves.
pub fn ensure_grant_within(
	granted: AccessLevel,
	own: AccessLevel,
	subject: &str,
	file_id: &str,
) -> ClResult<()> {
	if granted <= own {
		return Ok(());
	}
	warn!(
		subject = %subject,
		file_id = %file_id,
		granted = %granted.as_str(),
		own = %own.as_str(),
		"Share grant denied - a manager may not hand out more access than they hold"
	);
	Err(Error::PermissionDenied)
}

/// Enforce a minimum standing, with the denial log every call site wants.
///
/// Shared by the `require_*` wrappers and by callers that need the [`ShareStanding`] itself (ref
/// listing uses it to decide redaction), so there is one deny path rather than several.
pub fn ensure_standing(
	standing: ShareStanding,
	min: ShareStanding,
	subject: &str,
	file_id: &str,
) -> ClResult<()> {
	if standing >= min {
		return Ok(());
	}
	let reason = match min {
		ShareStanding::Manager => "Share management denied - owner/leader/admin required",
		ShareStanding::Reader => "Share listing denied - write access or share management required",
		// Unreachable (`standing >= None` always returns above), but given its own arm so a future
		// variant cannot inherit the listing message by accident.
		ShareStanding::None => "Share access denied - no minimum standing was required",
	};
	warn!(subject = %subject, file_id = %file_id, "{}", reason);
	Err(Error::PermissionDenied)
}

/// Authorize share *management* (create/update/delete share entries, mint/revoke share links).
///
/// An ownership/admin operation, strictly stronger than plain Write access — see
/// [`is_share_manager`] for who qualifies. Plain FSHR-`W` grantees and scoped share-link tokens are
/// excluded, or a delegated link or mere write grant could re-share, grant admin, or emit FSHR to
/// arbitrary users. They may only *list* shares, via [`require_share_reader`].
pub async fn require_share_manager(
	app: &App,
	tn_id: TnId,
	file_id: &str,
	auth: &AuthCtx,
	tenant_id_tag: &str,
) -> ClResult<ShareAuthority> {
	let authority = share_standing(app, tn_id, file_id, auth, tenant_id_tag).await?;
	ensure_standing(authority.standing, ShareStanding::Manager, &auth.id_tag, file_id)?;
	Ok(authority)
}

/// Authorize *listing* a file's share entries or share links.
///
/// Weaker than [`require_share_manager`]: any Write-access caller — including a plain FSHR-`W`
/// grantee — may see who the file is shared with, since enumeration is not part of the re-share
/// escalation that gate defends against. Scoped tokens are still rejected. Managers always pass,
/// even at `AccessLevel::Read` — a creator who may mint and revoke links must be able to list them.
pub async fn require_share_reader(
	app: &App,
	tn_id: TnId,
	file_id: &str,
	auth: &AuthCtx,
	tenant_id_tag: &str,
) -> ClResult<ShareAuthority> {
	let authority = share_standing(app, tn_id, file_id, auth, tenant_id_tag).await?;
	ensure_standing(authority.standing, ShareStanding::Reader, &auth.id_tag, file_id)?;
	Ok(authority)
}

#[cfg(test)]
mod tests {
	use super::*;

	const MEMBER: &str = "alice.example.com";

	const R: AccessLevel = AccessLevel::Read;
	const W: AccessLevel = AccessLevel::Write;
	const A: AccessLevel = AccessLevel::Admin;

	#[test]
	fn no_access_denies_before_any_standing_rule() {
		// The `AccessLevel::None` short-circuit runs first, so even leadership over a local row
		// confers nothing on a caller who cannot reach the file at all.
		assert!(!is_share_manager(AccessLevel::None, true));
	}

	#[test]
	fn manager_standing_implies_reader() {
		// Every combination `is_share_manager` accepts must reach at least Reader.
		for (access, leader) in [(A, false), (W, true), (R, true)] {
			assert!(is_share_manager(access, leader));
			let standing = classify_standing(access, leader);
			assert_eq!(standing, ShareStanding::Manager);
			assert!(standing >= ShareStanding::Reader);
		}

		// A plain FSHR-`W` grantee reads the share set but does not manage it.
		assert_eq!(classify_standing(W, false), ShareStanding::Reader);

		// Read access with no standing reaches neither.
		assert_eq!(classify_standing(R, false), ShareStanding::None);
	}

	#[test]
	fn share_reader_needs_write_access() {
		assert!(is_share_reader(AccessLevel::Write));
		assert!(is_share_reader(AccessLevel::Admin));
		// Read access is not enough to enumerate the share set.
		assert!(!is_share_reader(AccessLevel::Read));
		assert!(!is_share_reader(AccessLevel::Comment));
	}

	#[test]
	fn ensure_standing_enforces_the_minimum() {
		let ok = |standing, min| ensure_standing(standing, min, MEMBER, "f1~test").is_ok();

		// Manager outranks Reader, so it satisfies either minimum.
		assert!(ok(ShareStanding::Manager, ShareStanding::Reader));
		assert!(ok(ShareStanding::Manager, ShareStanding::Manager));
		// A plain reader may list but not manage.
		assert!(ok(ShareStanding::Reader, ShareStanding::Reader));
		assert!(!ok(ShareStanding::Reader, ShareStanding::Manager));
		// No standing satisfies nothing.
		assert!(!ok(ShareStanding::None, ShareStanding::Reader));
		assert!(!ok(ShareStanding::None, ShareStanding::Manager));

		assert!(matches!(
			ensure_standing(ShareStanding::None, ShareStanding::Reader, MEMBER, "f1~test"),
			Err(Error::PermissionDenied)
		));
	}

	#[test]
	fn a_manager_cannot_grant_beyond_their_own_access() {
		let ok = |granted, own| ensure_grant_within(granted, own, MEMBER, "f1~test").is_ok();

		// The escalation this closes: a `Read`-level manager (a leader over a local row they hold
		// only read access on) could otherwise mint a `write` link and redeem it themselves.
		assert!(!ok(AccessLevel::Write, AccessLevel::Read));
		assert!(!ok(AccessLevel::Comment, AccessLevel::Read));
		// Handing out what they hold, or less, is fine.
		assert!(ok(AccessLevel::Read, AccessLevel::Read));
		assert!(ok(W, W));
		assert!(ok(AccessLevel::Comment, W));
		assert!(ok(AccessLevel::Read, W));
		// Admin outranks Write, so a Write-ceiling manager may not mint an admin-level grant.
		assert_eq!(AccessLevel::from_perm_char('A'), AccessLevel::Admin);
		assert!(!ok(AccessLevel::from_perm_char('A'), W));
		assert!(ok(AccessLevel::from_perm_char('A'), AccessLevel::Admin));

		assert!(matches!(
			ensure_grant_within(W, AccessLevel::Read, MEMBER, "f1~test"),
			Err(Error::PermissionDenied)
		));
	}

	#[test]
	fn grant_ceiling_is_admin_only_for_leadership_over_a_local_row() {
		// Leadership lifts the ceiling only over a locally originating row; the caller resolves that
		// conjunction (see `leadership_extends_over_local_rows_only`).
		assert_eq!(grant_ceiling(W, true), AccessLevel::Admin);
		// An owner needs no special case: over a local row `file_access` already handed them Admin.
		assert_eq!(grant_ceiling(A, false), AccessLevel::Admin);
		// ...and over a mirrored row they are capped at what they actually hold.
		assert_eq!(grant_ceiling(R, false), AccessLevel::Read);
		assert_eq!(grant_ceiling(W, false), W);

		// End to end: a `Read`-level leader may hand out Read and nothing more once the row is
		// mirrored, but the full Admin ceiling while it is local.
		let mirrored = grant_ceiling(R, false);
		assert!(ensure_grant_within(AccessLevel::Read, mirrored, MEMBER, "f1~test").is_ok());
		assert!(ensure_grant_within(W, mirrored, MEMBER, "f1~test").is_err());
		let local = grant_ceiling(R, true);
		assert!(
			ensure_grant_within(AccessLevel::from_perm_char('A'), local, MEMBER, "f1~test").is_ok()
		);
	}

	/// The conjunction `share_standing` feeds into every rule above. The predicates it
	/// parameterises are near-tautologies on their own — asserting them back is not
	/// coverage — so this is the layer that actually decides whether a leader reaches a
	/// mirrored row, and the only one worth pinning here.
	#[test]
	fn leadership_extends_over_local_rows_only() {
		use cloudillo_types::meta_adapter::{ProfileInfo, ProfileType};

		let upstream = ProfileInfo {
			id_tag: "bob.example.com".into(),
			name: "Bob".into(),
			typ: ProfileType::Person,
			profile_pic: None,
		};
		let leader: Box<[Box<str>]> = Box::new(["leader".into()]);
		let member: Box<[Box<str>]> = Box::new(["contributor".into()]);

		// Leader over a locally originating row: manager standing and a lifted ceiling.
		assert!(leader_over_local_row(&leader, None));
		assert_eq!(
			classify_standing(R, leader_over_local_row(&leader, None)),
			ShareStanding::Manager
		);
		assert_eq!(grant_ceiling(R, leader_over_local_row(&leader, None)), AccessLevel::Admin);

		// The same leader on a mirrored row: judged on their own access alone, no lifted ceiling.
		assert!(!leader_over_local_row(&leader, Some(&upstream)));
		let mirrored = leader_over_local_row(&leader, Some(&upstream));
		assert_eq!(classify_standing(R, mirrored), ShareStanding::None);
		assert_eq!(classify_standing(W, mirrored), ShareStanding::Reader);
		assert_eq!(grant_ceiling(R, mirrored), AccessLevel::Read);

		// A non-leader gets nothing from provenance. A member-owned local row does not make its
		// owner a leader — their Admin comes from `file_access`, not from here.
		assert!(!leader_over_local_row(&member, None));
		assert!(!leader_over_local_row(&[], None));
	}
}

// vim: ts=4
