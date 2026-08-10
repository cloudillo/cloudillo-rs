// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! `/api/doc-formats` — which app indexes a document type, and how.
//!
//! # The claim rule
//!
//! `(tn_id, content_type)` is a primary key, so exactly one app may *index* a
//! document type per tenant. Other apps may still open documents of that type;
//! this is only about who owns the index rules. An upsert succeeds when there
//! is no active row, when the caller is the same `(publisher_tag, app_name)`
//! that already holds it, or when the caller is site admin. Anything else is a
//! [`Error::PermissionDenied`] naming the incumbent.
//!
//! Reads are gated too, one step looser: the listing is owner / community leader
//! / site admin ([`require_format_reader`]), not any authenticated caller. The
//! full manifest set names every app a tenant runs and everything each of them
//! indexes, which is the same enumeration [`check_claim`] refuses to put in its
//! 403 body.
//!
//! # Two tiers
//!
//! A `doc_formats` row is not the only source. The apps this build bundles ship
//! their manifests inside `dist`, and
//! [`cloudillo_core::bundled_apps::BundledAppRegistry`] loads them once at
//! startup as an in-memory global default — no rows written, nothing duplicated
//! per tenant. `cloudillo_core::doc_format::resolve` is the choke point every
//! reader goes through: **tenant row first, bundled entry as the fallback**.
//!
//! Only the row is a *claim*. [`check_claim`] is deliberately fed the tenant row
//! alone, so a tenant installing a different app for a content type this build
//! bundles is allowed — its row then wins on every read, and `DELETE` reverts to
//! the bundled default. There is no way to turn a bundled format off, only to
//! override it.
//!
//! # Why apps cannot call this directly
//!
//! Apps run in sandboxed iframes with opaque origins and only ever hold
//! *file-scoped* tokens. [`cloudillo_core::scope::scope_permits`] whitelists
//! `/api/search` for `TokenScope::File` and nothing else here, so this route is
//! unreachable with an app's own credential. Registration goes app → shell →
//! backend, and the shell attests the app's identity from its own window
//! tracker rather than from the message body. A rogue app therefore cannot
//! claim a content type it does not own on either side of the boundary.
//!
//! # The version gate
//!
//! `format_version` is a *document format* version, not an app version: it
//! describes the search-index contract an app declares for one content type.
//! `major.minor` is the contract, `patch` the app's counter for compatible
//! tweaks, and the wire carries the integer encoding `MMMmmmppp` — three decimal
//! digits per component, so `2.1` patch `42` is `2_001_042` and one `<`
//! comparison orders two registrations.
//!
//! Ordering exists because a registering client does so from every device its
//! user owns, on every app start. Under last-writer-wins an older build
//! overwrites a newer one, and since a changed `search` payload drops and
//! rebuilds the whole content type's index, two devices on different versions
//! bounce a full tenant reindex between them indefinitely. [`gate`] ignores a
//! registration older than the stored one.
//!
//! Bundled apps do not register at all — their versions are compared inside the
//! bundle, not on the wire — so the gate covers installed (packaged) apps and
//! older shells.
//!
//! An ignored registration answers `200` with the *stored* row, not `409`. The
//! shell memoises a success like any other, so a stale device goes quiet after
//! one call; a `409` would make every tab of that build retry forever.
//!
//! Orthogonal to [`crate::rules::SUPPORTED_VERSION`], which is the
//! platform-owned schema version of the rules DSL itself.

use axum::{
	Json,
	extract::{Path, State},
	http::StatusCode,
};
use cloudillo_core::{
	abac, doc_format,
	extract::{Auth, IdTag, OptionalRequestId},
};
use cloudillo_types::{
	auth_adapter::AuthCtx,
	meta_adapter::{DocFormat, UpsertDocFormat},
	types::ApiResponse,
};
use serde::{Deserialize, Serialize};

use crate::prelude::*;

/// Body of `PUT /api/doc-formats/{content_type}`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PutDocFormat {
	pub publisher_tag: String,
	pub app_name: String,
	/// Encoded document format version, `MMMmmmppp` — three decimal digits for each
	/// of `major.minor.patch`, so `2.1` patch `42` is `2_001_042`. Registrations are
	/// ordered by it; see the module docs.
	pub format_version: Option<i64>,
	/// Legacy app-version string, accepted and ignored.
	///
	/// `deny_unknown_fields` above would turn an older shell's request into a 400 on
	/// every app start. Keeping the field is what lets the backend ship before the
	/// frontend, which is the required deploy order. Remove one release after both
	/// halves have shipped.
	pub version: Option<String>,
	/// `"RTDB"` | `"CRDT"` | `"BLOB"`
	pub store_tp: Option<String>,
	/// Deep-link query param name, e.g. `"nav"`.
	pub nav_param: Option<String>,
	pub search: Option<serde_json::Value>,
	pub x: Option<serde_json::Value>,
}

/// One entry of the listing: a resolved format plus which tier it came from.
///
/// `source` is not a column — [`DocFormat`] is an adapter type describing a
/// `doc_formats` row, and a bundled entry has no row. It is a property of the
/// *resolution*, so it is attached here rather than pushed down into the adapter.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DocFormatEntry {
	#[serde(flatten)]
	format: DocFormat,
	/// `"tenant"` — a row this tenant owns, which an admin may delete to revert.
	/// `"bundled"` — this build's default, with no row behind it.
	source: &'static str,
}

/// `GET /api/doc-formats` — every format in effect for this tenant.
///
/// The tenant's own rows, plus each bundled default no row overrides. A node with
/// an empty `doc_formats` table still lists everything its bundle handles — the
/// normal state, since bundled apps do not register at runtime.
pub async fn list_doc_formats(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	IdTag(tenant_id_tag): IdTag,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<DocFormatEntry>>>)> {
	require_format_reader(&auth, &tenant_id_tag)?;
	let formats = doc_format::resolve_list(&app, tn_id)
		.await?
		.into_iter()
		.map(|(format, source)| DocFormatEntry { format, source: source.as_str() })
		.collect();
	Ok((StatusCode::OK, Json(ApiResponse::new(formats).with_req_id(req_id.unwrap_or_default()))))
}

/// `PUT /api/doc-formats/{content_type}` — register or update a manifest.
pub async fn put_doc_format(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	IdTag(tenant_id_tag): IdTag,
	OptionalRequestId(req_id): OptionalRequestId,
	Path(content_type): Path<String>,
	Json(body): Json<PutDocFormat>,
) -> ClResult<(StatusCode, Json<ApiResponse<Option<DocFormat>>>)> {
	require_tenant_admin(&auth, &tenant_id_tag)?;
	if content_type.is_empty() || content_type.len() > 128 {
		return Err(Error::ValidationError("Invalid content type".into()));
	}
	validate_format_version(body.format_version)?;
	// Reject bad rules at registration rather than discovering them on every
	// index run, when there is no caller left to tell.
	if let Some(search) = &body.search {
		crate::rules::IndexRules::parse(search)?;
	}

	let existing = app.meta_adapter.read_doc_format(tn_id, &content_type).await?;

	// A registration that restates what this build already bundles writes nothing.
	// An older shell still registers bundled apps at runtime; without this, every
	// tenant it touches would get a row duplicating data the process already holds
	// in memory, permanently shadowing the bundled tier.
	if existing.is_none()
		&& let Some(bundled) = app.bundled_apps.get(&content_type)
		&& same_as_bundled(bundled, &body)
	{
		debug!(content_type, "Doc format registration matches the bundled default; ignoring");
		return Ok((
			StatusCode::OK,
			Json(ApiResponse::new(Some(bundled.clone())).with_req_id(req_id.unwrap_or_default())),
		));
	}

	// `existing` is the tenant row alone, deliberately — a bundled entry is *not*
	// passed in. A bundled manifest is a default, not a claim, so a tenant
	// installing a different app for a content type this build happens to bundle
	// must succeed. Resolving the incumbent through `doc_format::resolve` here
	// would look natural and would break exactly that case.
	check_claim(&auth, &content_type, existing.as_ref(), &body)?;

	match gate(existing.as_ref(), &body) {
		GateDecision::Unchanged => {
			return Ok((
				StatusCode::OK,
				Json(ApiResponse::new(existing).with_req_id(req_id.unwrap_or_default())),
			));
		}
		GateDecision::Stale => {
			// 200 with the stored row rather than a 409 — see the module docs.
			warn!(
				content_type,
				stored = ?existing.as_ref().and_then(|e| e.format_version),
				submitted = ?body.format_version,
				app = %format!("{}/{}", body.publisher_tag, body.app_name),
				"Ignored a doc format registration older than the stored one"
			);
			return Ok((
				StatusCode::OK,
				Json(ApiResponse::new(existing).with_req_id(req_id.unwrap_or_default())),
			));
		}
		GateDecision::WriteSameVersion => {
			warn!(
				content_type,
				format_version = ?body.format_version,
				app = %format!("{}/{}", body.publisher_tag, body.app_name),
				"Doc format rules changed without a formatVersion bump — two builds \
				 sharing a version will re-index this content type against each other"
			);
		}
		GateDecision::Write => {}
	}

	// Compared as `Option<&Value>` on both sides: comparing `Option<Option<Value>>`
	// would read a first-ever registration with no `search` as a change and
	// schedule a content-type sweep for a format that indexes nothing.
	let rules_changed = existing.as_ref().and_then(|e| e.search.as_ref()) != body.search.as_ref();

	app.meta_adapter
		.upsert_doc_format(
			tn_id,
			&UpsertDocFormat {
				content_type: &content_type,
				publisher_tag: &body.publisher_tag,
				app_name: &body.app_name,
				format_version: body.format_version,
				store_tp: body.store_tp.as_deref(),
				nav_param: body.nav_param.as_deref(),
				search: body.search.as_ref(),
				x: body.x.as_ref(),
			},
		)
		.await?;

	// Before anything downstream resolves this content type again — the sweep
	// scheduled below indexes through `doc_format::resolve` — or the new rules and
	// nav param would not take effect until restart.
	doc_format::invalidate(&app, tn_id, &content_type);

	// Rules changed ⇒ every already-indexed document of this type is stale, so the
	// rows go and the sweep rebuilds them.
	//
	// The sweep is scheduled *first*, and a scheduling failure aborts with `?`
	// before anything is dropped: a sweep over rows still in place is a no-op
	// rebuild, whereas rows dropped with no sweep persisted stay unfindable until
	// the weekly `All` cron.
	//
	// Only the deep `'D'` rows go, which is all the manifest produced. The files'
	// own `'F'` rows are server-owned and the content-type sweep does not rebuild
	// them.
	if rules_changed {
		crate::reindex::schedule_content_type(&app, tn_id, &content_type).await?;
		app.meta_adapter
			.delete_deep_search_by_content_type(tn_id, &content_type)
			.await?;
	}

	let stored = app.meta_adapter.read_doc_format(tn_id, &content_type).await?;
	Ok((StatusCode::OK, Json(ApiResponse::new(stored).with_req_id(req_id.unwrap_or_default()))))
}

/// `DELETE /api/doc-formats/{content_type}` — drop the tenant's row.
///
/// With a bundled entry behind it this is a *revert*, not a removal: the format
/// resolves back to what the build ships. A content type the bundle also declares
/// therefore cannot be turned off, only overridden — see
/// [`cloudillo_core::bundled_apps`].
pub async fn delete_doc_format(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	IdTag(tenant_id_tag): IdTag,
	OptionalRequestId(req_id): OptionalRequestId,
	Path(content_type): Path<String>,
) -> ClResult<(StatusCode, Json<ApiResponse<()>>)> {
	require_tenant_admin(&auth, &tenant_id_tag)?;
	if app.meta_adapter.read_doc_format(tn_id, &content_type).await?.is_none() {
		// Already at the bundled default: nothing to drop, and nothing wrong
		// either. Only a content type neither tier knows is a 404.
		if app.bundled_apps.get(&content_type).is_some() {
			return Ok((
				StatusCode::OK,
				Json(ApiResponse::new(()).with_req_id(req_id.unwrap_or_default())),
			));
		}
		return Err(Error::NotFound);
	}

	app.meta_adapter.delete_doc_format(tn_id, &content_type).await?;
	// Same as the PUT path: the entry now resolves to the bundled tier (or to
	// nothing), and the sweep below reads through `doc_format::resolve`.
	doc_format::invalidate(&app, tn_id, &content_type);
	// Dropping an override changes the effective rules exactly as a PUT does, so
	// what was indexed is stale. Scheduled before the delete, and propagating on
	// failure, for the reason spelled out in `put_doc_format`.
	crate::reindex::schedule_content_type(&app, tn_id, &content_type).await?;
	// Deep parts only: the rules that built them are gone, but the files
	// themselves are still there and must stay findable by name.
	app.meta_adapter
		.delete_deep_search_by_content_type(tn_id, &content_type)
		.await?;

	Ok((StatusCode::OK, Json(ApiResponse::new(()).with_req_id(req_id.unwrap_or_default()))))
}

/// Registering or dropping a document format is a tenant-administrative act.
///
/// Apps never reach this route at all (`scope_permits` denies it to file
/// scopes), so the caller is always the shell acting with an unscoped session
/// credential. Requiring the tenant owner — or SADM — is what stops a federated
/// visitor, who also reaches this tenant's Host context with a valid token, from
/// claiming or deleting a content type on a node that is not theirs.
///
/// Intended consequence: a user browsing a *remote* node is not that node's
/// tenant owner, so the shell's `format:register.req` proxy gets a 403 there. A
/// document's index lives on its owner's node. The shell memoises the 403 for
/// the session, so the app degrades to file-level hits without retry storms.
fn require_tenant_admin(auth: &AuthCtx, tenant_id_tag: &str) -> ClResult<()> {
	if abac::is_admin(auth) || &*auth.id_tag == tenant_id_tag {
		return Ok(());
	}
	Err(Error::PermissionDenied)
}

/// Owner, community leader, or site admin. Looser than [`require_tenant_admin`] —
/// reading which formats a tenant registered is a leader-level operation, whereas
/// claiming one is the owner's alone — but strictly tighter than "any
/// authenticated caller", which would let a federated visitor enumerate the
/// tenant's apps and their full index manifests: exactly what [`check_claim`]
/// withholds from its bare 403.
///
/// Checked here rather than by moving the route into `protected.rs`'s
/// `require_leader` group: `SADM` is not part of `roles::ROLE_HIERARCHY`, so that
/// group would lock a site admin out of the sibling `PUT`/`DELETE` routes
/// [`require_tenant_admin`] deliberately admits them to.
fn require_format_reader(auth: &AuthCtx, tenant_id_tag: &str) -> ClResult<()> {
	if abac::is_admin(auth)
		|| &*auth.id_tag == tenant_id_tag
		|| cloudillo_core::roles::is_leader(&auth.roles)
	{
		return Ok(());
	}
	Err(Error::PermissionDenied)
}

/// Enforce the claim rule described in the module docs.
///
/// Applied *in addition* to [`require_tenant_admin`] on the upsert path: the
/// tenant owner has the authority to register formats, but not to silently steal
/// a claim another app already holds.
fn check_claim(
	auth: &AuthCtx,
	content_type: &str,
	existing: Option<&DocFormat>,
	body: &PutDocFormat,
) -> ClResult<()> {
	if abac::is_admin(auth) {
		return Ok(());
	}
	let Some(existing) = existing else { return Ok(()) };
	if claimed_by(existing, &body.publisher_tag, &body.app_name) {
		return Ok(());
	}
	// The incumbent's identity is logged rather than returned: the response is a
	// bare 403 so a probing app cannot enumerate which apps a tenant runs.
	warn!(
		content_type,
		claimant = %format!("{}/{}", existing.publisher_tag, existing.app_name),
		challenger = %format!("{}/{}", body.publisher_tag, body.app_name),
		"Rejected doc format claim by a different app"
	);
	Err(Error::PermissionDenied)
}

fn claimed_by(existing: &DocFormat, publisher_tag: &str, app_name: &str) -> bool {
	&*existing.publisher_tag == publisher_tag && &*existing.app_name == app_name
}

/// Whether a registration would write a row saying exactly what the bundle
/// already says.
///
/// Everything a `doc_formats` row carries except `x` — which the bundle has no
/// way to express, so a body naming one is a genuine difference and must write.
/// `updated_at` is not compared: it is when the row (or the manifest file) was
/// last touched, not part of what either declares.
fn same_as_bundled(bundled: &DocFormat, body: &PutDocFormat) -> bool {
	*bundled.publisher_tag == body.publisher_tag
		&& *bundled.app_name == body.app_name
		&& bundled.format_version == body.format_version
		&& bundled.store_tp.as_deref() == body.store_tp.as_deref()
		&& bundled.nav_param.as_deref() == body.nav_param.as_deref()
		&& bundled.search.as_ref() == body.search.as_ref()
		&& body.x.is_none()
}

/// Every field a registration can change, compared. `format_version` is not
/// here — the only caller has already established the two are equal.
///
/// [`gate`] returning [`GateDecision::Unchanged`] means "the stored row already
/// says exactly this", so it has to mean *every* field, not just `search`: an app
/// that edits `nav_param` or `store_tp` without bumping its version would
/// otherwise get a 200 and no write, and every deep link would keep using the
/// stale param.
fn same_content(existing: &DocFormat, body: &PutDocFormat) -> bool {
	*existing.publisher_tag == body.publisher_tag
		&& *existing.app_name == body.app_name
		&& existing.store_tp.as_deref() == body.store_tp.as_deref()
		&& existing.nav_param.as_deref() == body.nav_param.as_deref()
		&& existing.search.as_ref() == body.search.as_ref()
		&& existing.x.as_ref() == body.x.as_ref()
}

/// Largest encodable format version, `999.999.999`.
const FORMAT_VERSION_MAX: i64 = 999_999_999;

/// Reject a version that cannot have come from the documented encoding.
fn validate_format_version(format_version: Option<i64>) -> ClResult<()> {
	match format_version {
		Some(v) if !(0..=FORMAT_VERSION_MAX).contains(&v) => {
			Err(Error::ValidationError("Invalid formatVersion".into()))
		}
		_ => Ok(()),
	}
}

/// What the version gate decided about one registration.
#[derive(Debug, PartialEq, Eq)]
enum GateDecision {
	/// Persist it.
	Write,
	/// Persist it, but the caller reused a version for different rules.
	WriteSameVersion,
	/// The stored row already says exactly this. 200, nothing written.
	Unchanged,
	/// Older than what is stored. 200 with the stored row, nothing written.
	Stale,
}

/// Decide whether a registration should touch the database.
///
/// Pure, so every branch is unit-testable. See the module docs for why
/// registrations have to be ordered at all.
fn gate(existing: Option<&DocFormat>, body: &PutDocFormat) -> GateDecision {
	// Nothing to order against.
	let Some(existing) = existing else { return GateDecision::Write };

	// A NULL stored version predates the integer encoding, or came from a client
	// that had none. It carries no ordering, so it must never block a write —
	// otherwise a migrated row would be frozen forever.
	let Some(stored) = existing.format_version else { return GateDecision::Write };

	// A caller that states no version cannot claim to be newer than one that did.
	// Without this an old client clobbers `format_version` back to NULL on every
	// session, restoring the ping-pong.
	let Some(submitted) = body.format_version else { return GateDecision::Stale };

	if submitted < stored {
		return GateDecision::Stale;
	}
	if submitted > stored {
		return GateDecision::Write;
	}

	// Equal. The common case by far is every open tab of one build re-registering
	// identical rules, which must not write.
	if same_content(existing, body) {
		GateDecision::Unchanged
	} else {
		GateDecision::WriteSameVersion
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn auth(id_tag: &str, roles: &[&str]) -> AuthCtx {
		AuthCtx {
			tn_id: TnId(1),
			id_tag: id_tag.into(),
			roles: roles.iter().map(|r| (*r).into()).collect(),
			scope: None,
		}
	}

	/// The whole read/write matrix for these two routes, in one table.
	///
	/// Both halves matter and neither implies the other: a valid `AuthCtx` is not
	/// enough to *write* — a stranger reaching this tenant's Host context must not
	/// be able to claim or drop a content type — and the listing they would *read*
	/// names every app the tenant runs and everything each of them indexes, which
	/// is exactly the enumeration `check_claim` refuses to put in its 403 body.
	#[test]
	fn reading_formats_is_one_step_looser_than_writing_them() {
		// (who, may read, may write)
		let cases = [
			("the tenant owner", auth("alice.example", &[]), true, true),
			("a site admin", auth("root.example", &["SADM"]), true, true),
			("a community leader", auth("bob.example", &["leader"]), true, false),
			// A member below leader is still a visitor as far as this route goes.
			("a contributor", auth("carol.example", &["contributor"]), false, false),
			("a federated visitor", auth("mallory.example", &[]), false, false),
		];
		for (who, ctx, may_read, may_write) in cases {
			let read = require_format_reader(&ctx, "alice.example");
			let write = require_tenant_admin(&ctx, "alice.example");
			assert_eq!(read.is_ok(), may_read, "{who} read: {read:?}");
			assert_eq!(write.is_ok(), may_write, "{who} write: {write:?}");
			// The denial has to be a 403, not some other error standing in for one.
			if !may_read {
				assert!(matches!(read, Err(Error::PermissionDenied)), "{who}: {read:?}");
			}
			if !may_write {
				assert!(matches!(write, Err(Error::PermissionDenied)), "{who}: {write:?}");
			}
		}
	}

	fn rules(title: &str) -> serde_json::Value {
		serde_json::json!({ "v": 1, "parts": [{ "kind": "p", "title": [title] }] })
	}

	/// A stored row, as `read_doc_format` would return it.
	fn stored(format_version: Option<i64>, search: Option<serde_json::Value>) -> DocFormat {
		DocFormat {
			content_type: "cloudillo/notillo".into(),
			publisher_tag: "cloudillo.org".into(),
			app_name: "notillo".into(),
			format_version,
			store_tp: Some("RTDB".into()),
			nav_param: Some("nav".into()),
			search,
			x: None,
			updated_at: Timestamp(0),
		}
	}

	/// An incoming registration.
	fn put(format_version: Option<i64>, search: Option<serde_json::Value>) -> PutDocFormat {
		PutDocFormat {
			publisher_tag: "cloudillo.org".into(),
			app_name: "notillo".into(),
			format_version,
			version: None,
			store_tp: Some("RTDB".into()),
			nav_param: Some("nav".into()),
			search,
			x: None,
		}
	}

	/// Every ordering branch of [`gate`], as one table: `(why, stored row,
	/// submitted body, decision)`. The `why` is what a failure prints, so a broken
	/// branch still names itself.
	#[test]
	fn the_write_gate_orders_registrations_by_version() {
		use GateDecision::{Stale, Unchanged, Write, WriteSameVersion};

		let (v0, v1) = (Some(1_000_000), Some(1_001_000));
		let ti = || Some(rules("ti"));
		let tj = || Some(rules("tj"));
		let cases: Vec<(&str, Option<DocFormat>, PutDocFormat, GateDecision)> = vec![
			("a first registration has nothing to order against", None, put(v0, ti()), Write),
			// Rows migrated off the old TEXT `version` column land here. Treating
			// NULL as an ordering would freeze them forever.
			(
				"a NULL stored version carries no ordering",
				Some(stored(None, ti())),
				put(v0, ti()),
				Write,
			),
			// An old client would otherwise clobber `format_version` back to NULL on
			// every session, restoring the reindex ping-pong (see `gate`).
			(
				"a caller stating no version cannot outrank one that did",
				Some(stored(v0, ti())),
				put(None, ti()),
				Stale,
			),
			("an older registration is ignored", Some(stored(v1, ti())), put(v0, ti()), Stale),
			("a newer registration writes", Some(stored(v0, ti())), put(v1, tj()), Write),
			// Every open tab of one build takes this path on startup.
			(
				"the same version restating the same rules writes nothing",
				Some(stored(v0, ti())),
				put(v0, ti()),
				Unchanged,
			),
			// A developer editing rules without bumping. It still writes — refusing
			// would break that loop — but it is the one path that can still bounce.
			(
				"the same version with different rules still writes",
				Some(stored(v0, ti())),
				put(v0, tj()),
				WriteSameVersion,
			),
		];
		for (why, existing, body, expected) in cases {
			assert_eq!(gate(existing.as_ref(), &body), expected, "{why}");
		}
	}

	#[test]
	fn the_same_version_with_a_changed_non_rule_field_still_writes() {
		// `Unchanged` claims the stored row already says exactly this, so every
		// field a registration can change has to be compared — not just `search`.
		// An app editing `nav_param` without bumping its version would otherwise
		// leave every deep link built from the stale param.
		let v = Some(1_000_000);
		let existing = stored(v, Some(rules("ti")));

		let nav = PutDocFormat { nav_param: Some("page".into()), ..put(v, Some(rules("ti"))) };
		assert_eq!(gate(Some(&existing), &nav), GateDecision::WriteSameVersion);

		let store = PutDocFormat { store_tp: Some("CRDT".into()), ..put(v, Some(rules("ti"))) };
		assert_eq!(gate(Some(&existing), &store), GateDecision::WriteSameVersion);

		let x = PutDocFormat {
			x: Some(serde_json::json!({ "icon": "note" })),
			..put(v, Some(rules("ti")))
		};
		assert_eq!(gate(Some(&existing), &x), GateDecision::WriteSameVersion);

		let app = PutDocFormat { app_name: "notillo2".into(), ..put(v, Some(rules("ti"))) };
		assert_eq!(gate(Some(&existing), &app), GateDecision::WriteSameVersion);
	}

	#[test]
	fn a_registration_restating_the_bundled_default_writes_nothing() {
		// The path an older shell — or any app that still registers — takes. Without
		// it every tenant such a client touches grows a row duplicating what the
		// process already holds in memory, permanently shadowing the bundled tier.
		let bundled = stored(Some(1_000_000), Some(rules("ti")));
		assert!(same_as_bundled(&bundled, &put(Some(1_000_000), Some(rules("ti")))));
	}

	#[test]
	fn anything_the_bundle_does_not_already_say_still_writes() {
		let bundled = stored(Some(1_000_000), Some(rules("ti")));

		// Different rules, or a different version of them.
		assert!(!same_as_bundled(&bundled, &put(Some(1_000_000), Some(rules("tj")))));
		assert!(!same_as_bundled(&bundled, &put(Some(1_001_000), Some(rules("ti")))));

		// A different app entirely — the override case, which must reach the write.
		let mut other_app = put(Some(1_000_000), Some(rules("ti")));
		other_app.app_name = "otherillo".into();
		assert!(!same_as_bundled(&bundled, &other_app));

		// `x` has no bundled counterpart, so a body carrying one always differs.
		let mut with_x = put(Some(1_000_000), Some(rules("ti")));
		with_x.x = Some(serde_json::json!({ "k": 1 }));
		assert!(!same_as_bundled(&bundled, &with_x));

		// A field the bundle states and the body does not.
		let mut no_nav = put(Some(1_000_000), Some(rules("ti")));
		no_nav.nav_param = None;
		assert!(!same_as_bundled(&bundled, &no_nav));
	}

	#[test]
	fn a_bundled_entry_does_not_block_a_tenants_own_claim() {
		// A bundled manifest is a default, not a claim. `check_claim` is fed the
		// tenant row only (`None` here, since the content type resolves through the
		// bundle), so a tenant installing a different app for a content type this
		// build bundles is allowed — and its row then wins on every read.
		let owner = auth("alice.example", &[]);
		let mut challenger = put(Some(1_000_000), Some(rules("tj")));
		challenger.publisher_tag = "other.example".into();
		challenger.app_name = "otherillo".into();

		assert!(check_claim(&owner, "cloudillo/notillo", None, &challenger).is_ok());
	}

	#[test]
	fn the_encoding_bounds_are_accepted_and_anything_outside_them_is_not() {
		assert!(validate_format_version(None).is_ok());
		assert!(validate_format_version(Some(0)).is_ok());
		assert!(validate_format_version(Some(999_999_999)).is_ok());
		assert!(matches!(validate_format_version(Some(-1)), Err(Error::ValidationError(_))));
		assert!(matches!(
			validate_format_version(Some(1_000_000_000)),
			Err(Error::ValidationError(_))
		));
	}
}

// vim: ts=4
