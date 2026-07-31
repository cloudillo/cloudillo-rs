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
/// Requires access to the file itself, plus standing: a community leader whose tenant owns the row,
/// an explicit `'A'` share grant, the file owner, or — **only for tenant-owned files** — the member
/// who created the row.
///
/// The creator rule exists because a local file leaves `files.owner_tag` NULL and the meta adapter
/// back-fills the *tenant* profile as owner (`build_owner_profile`); without it, on a community
/// tenant even the file's creator fails the owner test and only `leader` could manage shares. The
/// `tenant_owned` guard keeps a locally-placed copy of a foreign file (Pin/Place row, `owner_tag` =
/// foreign owner) out of the placer's reach.
///
/// `leader_over_tenant_row` means "holds `leader` **and** the row is tenant-owned": leadership is
/// authority over the tenant's own content, not over a foreign owner's file that merely happens to
/// be placed here. Same boundary `file_access::role_access_level` draws.
fn is_share_manager(
	access: AccessLevel,
	subject: &str,
	tenant_id_tag: &str,
	owner_id_tag: Option<&str>,
	creator_id_tag: Option<&str>,
	leader_over_tenant_row: bool,
) -> bool {
	// Defence in depth: `require_unscoped_file_access` already rejected anyone who cannot reach it.
	if access == AccessLevel::None {
		return false;
	}
	// `can_manage_shares()` covers the `'A'` grant — `from_perm_char` maps it straight to `Admin`,
	// as does owner/leader over a tenant-owned row. The explicit tests are for foreign-owned rows,
	// where neither fires.
	if leader_over_tenant_row || access.can_manage_shares() || owner_id_tag == Some(subject) {
		return true;
	}
	let tenant_owned = owner_id_tag == Some(tenant_id_tag);
	tenant_owned && creator_id_tag == Some(subject)
}

/// Pure share-*listing* decision: any unscoped caller with Write-or-better access may enumerate a
/// file's share entries.
///
/// Not the whole reader test — a manager outranks a reader even at `AccessLevel::Read` (the
/// creator rule above). [`classify_standing`] composes the two.
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
fn classify_standing(
	access: AccessLevel,
	subject: &str,
	tenant_id_tag: &str,
	owner_id_tag: Option<&str>,
	creator_id_tag: Option<&str>,
	leader_over_tenant_row: bool,
) -> ShareStanding {
	if is_share_manager(
		access,
		subject,
		tenant_id_tag,
		owner_id_tag,
		creator_id_tag,
		leader_over_tenant_row,
	) {
		ShareStanding::Manager
	} else if is_share_reader(access) {
		ShareStanding::Reader
	} else {
		ShareStanding::None
	}
}

/// Pure grant-ceiling rule behind [`share_standing`].
///
/// Everyone is capped at what they hold — already `Admin` for an owner, a leader over a
/// tenant-owned row, or an explicit `'A'` grantee. The cap is what stops the `Read`-level creator
/// of a tenant-owned file (a share manager by the creator rule) from minting a `write` grant and
/// redeeming it.
///
/// `is_owner` still has to be named: `file_access::role_access_level` resolves roles only for
/// tenant-owned files, so over a *foreign-owned* pinned row `access` alone would under-grant the
/// owner. `leader_over_tenant_row` means the same as in [`is_share_manager`], so a leader never
/// gains a ceiling over foreign content.
fn grant_ceiling(access: AccessLevel, is_owner: bool, leader_over_tenant_row: bool) -> AccessLevel {
	if leader_over_tenant_row || is_owner { AccessLevel::Admin } else { access }
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

	let owner_id_tag =
		effective_owner(access.file_view.owner.as_ref().map(|p| p.id_tag.as_ref()), tenant_id_tag);
	let creator_id_tag =
		non_empty_id_tag(access.file_view.creator.as_ref().map(|p| p.id_tag.as_ref()));
	// Leadership is authority over the tenant's own content only: a Pin/Place row carries the
	// foreign owner in `owner_tag`, and minting grants or links on it is the owner's call.
	let leader_over_tenant_row =
		crate::roles::is_leader(&auth.roles) && owner_id_tag == tenant_id_tag;

	// No extra query needed: an explicit `'A'` entry (direct or folder-inherited), ownership, and
	// the leader role on a tenant-owned file all already reached `access_level` as `Admin`.
	let standing = classify_standing(
		access.access_level,
		&auth.id_tag,
		tenant_id_tag,
		Some(owner_id_tag),
		creator_id_tag,
		leader_over_tenant_row,
	);

	let ceiling =
		grant_ceiling(access.access_level, owner_id_tag == &*auth.id_tag, leader_over_tenant_row);

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

	let auth = AuthCtx { tn_id, id_tag: actor_id_tag.into(), roles, scope: None };
	share_standing(app, tn_id, file_id, &auth, tenant_id_tag).await
}

/// A share manager may not hand out more access than [`ShareAuthority::grant_ceiling`] allows.
///
/// Manager standing is ownership-derived, not Write-derived (a `Read`-level creator of a
/// tenant-owned file qualifies), and `file_access::get_access_level_with_scope` returns a
/// share-link scope's level uncapped by the holder's own ACL — so without this a `Read` manager
/// could mint a `write` link and redeem it to escalate themselves.
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
		ShareStanding::Manager => "Share management denied - owner/creator/leader/admin required",
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

/// Normalize a present-but-blank id_tag into `None`.
fn non_empty_id_tag(id_tag: Option<&str>) -> Option<&str> {
	id_tag.filter(|s| !s.is_empty())
}

/// A row's effective owner: mirrors `file_access::check_file_access_with_scope`, where a missing or
/// blank `owner` means the tenant owns it. The two must agree — without the fallback,
/// `tenant_owned` and `leader_over_tenant_row` read false wherever the meta adapter does not
/// back-fill an owner, and the creator rule silently stops applying.
fn effective_owner<'a>(owner: Option<&'a str>, tenant_id_tag: &'a str) -> &'a str {
	non_empty_id_tag(owner).unwrap_or(tenant_id_tag)
}

#[cfg(test)]
mod tests {
	use super::*;

	const TENANT: &str = "community.example.com";
	const MEMBER: &str = "alice.example.com";
	const OTHER: &str = "bob.example.com";

	const W: AccessLevel = AccessLevel::Write;
	const A: AccessLevel = AccessLevel::Admin;

	#[test]
	fn personal_tenant_owner_manages_shares() {
		// Personal tenant: owner back-fills to the tenant profile, which *is* the caller.
		assert!(is_share_manager(W, TENANT, TENANT, Some(TENANT), Some(TENANT), false));
	}

	#[test]
	fn creator_of_tenant_owned_file_manages_shares() {
		// On a community tenant the owner is the tenant, so the member who created the row must
		// pass on the creator rule.
		assert!(is_share_manager(W, MEMBER, TENANT, Some(TENANT), Some(MEMBER), false));
	}

	#[test]
	fn non_creator_member_cannot_manage_shares() {
		assert!(!is_share_manager(W, MEMBER, TENANT, Some(TENANT), Some(OTHER), false));
	}

	#[test]
	fn leader_manages_shares() {
		assert!(is_share_manager(W, MEMBER, TENANT, Some(TENANT), Some(OTHER), true));
	}

	#[test]
	fn leader_does_not_reach_a_foreign_owned_row() {
		// Pin/Place row: `owner_tag` holds the foreign owner, so `share_standing` passes
		// `leader_over_tenant_row = false` and the leader is judged on their own access alone.
		for access in [AccessLevel::Read, W] {
			assert!(!is_share_manager(access, MEMBER, TENANT, Some(OTHER), Some(OTHER), false));
			// ...and no lifted ceiling either: they may hand out at most what they hold.
			assert_eq!(grant_ceiling(access, false, false), access);
		}
		// A leader who nonetheless holds an explicit `'A'` grant on the foreign row still manages
		// it — that authority comes from the owner's own grant, not from leadership.
		assert!(is_share_manager(A, MEMBER, TENANT, Some(OTHER), Some(OTHER), false));
	}

	#[test]
	fn leader_over_a_tenant_owned_row_keeps_manager_standing_and_an_admin_ceiling() {
		// Regression guard for the foreign-owned narrowing above: over the tenant's own content
		// leadership is unchanged.
		assert_eq!(
			classify_standing(AccessLevel::Read, MEMBER, TENANT, Some(TENANT), Some(OTHER), true),
			ShareStanding::Manager
		);
		assert_eq!(grant_ceiling(AccessLevel::Read, false, true), AccessLevel::Admin);
	}

	#[test]
	fn creator_of_placed_foreign_file_cannot_manage_shares() {
		// Pin/Place row: `owner_tag` holds the foreign owner, so the local
		// placer (recorded as creator) must not gain share management.
		assert!(!is_share_manager(W, MEMBER, TENANT, Some(OTHER), Some(MEMBER), false));
	}

	#[test]
	fn explicit_admin_grant_manages_shares() {
		// Same caller, at Write and at Admin: the `'A'` share entry resolves to `Admin` through
		// `AccessLevel::from_perm_char`, so the access level alone carries the grant.
		assert!(!is_share_manager(W, OTHER, TENANT, Some(TENANT), Some(MEMBER), false));
		assert!(is_share_manager(A, OTHER, TENANT, Some(TENANT), Some(MEMBER), false));
	}

	#[test]
	fn plain_write_grantee_cannot_manage_shares() {
		// The FSHR-`W` grantee: no owner/creator/leader/admin standing, so it fails
		// regardless of access level.
		assert!(!is_share_manager(W, OTHER, TENANT, Some(MEMBER), Some(MEMBER), false));
	}

	#[test]
	fn missing_owner_and_creator_deny() {
		assert!(!is_share_manager(W, MEMBER, TENANT, None, None, false));
	}

	#[test]
	fn no_access_denies_before_any_standing_rule() {
		// The `AccessLevel::None` short-circuit runs first, so even leadership over a tenant-owned
		// row confers nothing on a caller who cannot reach the file at all.
		assert!(!is_share_manager(
			AccessLevel::None,
			MEMBER,
			TENANT,
			Some(TENANT),
			Some(MEMBER),
			true
		));
	}

	#[test]
	fn read_access_creator_is_still_a_share_manager() {
		// Manager standing is ownership-derived, not Write-derived: read access is enough once the
		// caller created the tenant-owned file.
		assert!(is_share_manager(
			AccessLevel::Read,
			MEMBER,
			TENANT,
			Some(TENANT),
			Some(MEMBER),
			false
		));
	}

	#[test]
	fn manager_standing_implies_reader() {
		// Every combination `is_share_manager` accepts must reach at least Reader — including the
		// `Read`-level creator, who fails `is_share_reader` and is admitted by the ordering alone.
		for (access, subject, owner, creator, leader) in [
			(W, TENANT, Some(TENANT), Some(TENANT), false),
			(W, MEMBER, Some(TENANT), Some(MEMBER), false),
			(W, MEMBER, Some(TENANT), Some(OTHER), true),
			(A, OTHER, Some(TENANT), Some(MEMBER), false),
			(AccessLevel::Read, MEMBER, Some(TENANT), Some(MEMBER), false),
		] {
			assert!(is_share_manager(access, subject, TENANT, owner, creator, leader));
			let standing = classify_standing(access, subject, TENANT, owner, creator, leader);
			assert_eq!(standing, ShareStanding::Manager);
			assert!(standing >= ShareStanding::Reader);
		}

		// A plain FSHR-`W` grantee reads the share set but does not manage it.
		let grantee = classify_standing(W, OTHER, TENANT, Some(MEMBER), Some(MEMBER), false);
		assert_eq!(grantee, ShareStanding::Reader);

		// Read access with no ownership standing reaches neither.
		let outsider =
			classify_standing(AccessLevel::Read, OTHER, TENANT, Some(MEMBER), Some(MEMBER), false);
		assert_eq!(outsider, ShareStanding::None);
	}

	#[test]
	fn admin_access_alone_confers_manager_standing_and_an_admin_ceiling() {
		// The `'A'` grantee over a *foreign-owned* file: not owner, not creator, not leader, so
		// the resolved access level is the whole story.
		let standing = classify_standing(A, OTHER, TENANT, Some(MEMBER), Some(MEMBER), false);
		assert_eq!(standing, ShareStanding::Manager);
		// ...and they may re-share up to admin, because their own level already is admin.
		assert_eq!(grant_ceiling(A, false, false), AccessLevel::Admin);
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

		// The escalation this closes: the `Read`-level creator of a tenant-owned file is a share
		// manager, so without the cap they could mint a `write` link and redeem it themselves.
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
	fn grant_ceiling_is_admin_only_for_ownership_derived_standing() {
		// Ownership is named explicitly, so an owner reading their own foreign-tenant-hosted row —
		// where `role_access_level` never lifts `access` to Admin — still gets a full ceiling.
		assert_eq!(grant_ceiling(W, true, false), AccessLevel::Admin);
		// Leadership lifts the ceiling only over a tenant-owned row; the caller resolves that
		// conjunction (see `leader_does_not_reach_a_foreign_owned_row`).
		assert_eq!(grant_ceiling(W, false, true), AccessLevel::Admin);
		// An explicit `'A'` grantee needs no special case: their own level already is Admin.
		assert_eq!(grant_ceiling(A, false, false), AccessLevel::Admin);

		// The creator rule confers management but no extra reach: the `Read`-level creator of a
		// tenant-owned file is capped at Read, so they cannot mint the `write` link they would
		// redeem to escalate themselves.
		assert_eq!(grant_ceiling(AccessLevel::Read, false, false), AccessLevel::Read);
		assert_eq!(grant_ceiling(W, false, false), W);

		// End to end: that creator may hand out Read and nothing more.
		let creator = grant_ceiling(AccessLevel::Read, false, false);
		assert!(ensure_grant_within(AccessLevel::Read, creator, MEMBER, "f1~test").is_ok());
		assert!(ensure_grant_within(W, creator, MEMBER, "f1~test").is_err());
		let owner = grant_ceiling(W, true, false);
		assert!(
			ensure_grant_within(AccessLevel::from_perm_char('A'), owner, MEMBER, "f1~test").is_ok()
		);
	}

	#[test]
	fn non_empty_id_tag_normalizes_blank() {
		assert_eq!(non_empty_id_tag(Some("")), None);
		assert_eq!(non_empty_id_tag(Some(MEMBER)), Some(MEMBER));
		assert_eq!(non_empty_id_tag(None), None);
	}

	#[test]
	fn a_row_with_no_explicit_owner_belongs_to_the_tenant() {
		// `file_access::check_file_access_with_scope` resolves a missing owner to the tenant, so
		// this must too — otherwise `tenant_owned` reads false and the creator rule silently stops
		// applying to exactly the rows it exists for.
		assert_eq!(effective_owner(None, TENANT), TENANT);
		assert_eq!(effective_owner(Some(""), TENANT), TENANT);
		assert_eq!(effective_owner(Some(MEMBER), TENANT), MEMBER);

		// End to end over the pure half: the creator of such a row still manages its shares...
		let owner = effective_owner(None, TENANT);
		assert!(is_share_manager(W, MEMBER, TENANT, Some(owner), Some(MEMBER), false));
		// ...and a leader still reaches it (the caller resolves the same conjunction).
		let leader_over_tenant_row = owner == TENANT;
		assert!(is_share_manager(
			AccessLevel::Read,
			OTHER,
			TENANT,
			Some(owner),
			Some(MEMBER),
			leader_over_tenant_row
		));
		// An unresolved owner denies, which is why the fallback has to run before this point.
		assert!(!is_share_manager(W, MEMBER, TENANT, None, Some(MEMBER), false));
	}
}

// vim: ts=4
