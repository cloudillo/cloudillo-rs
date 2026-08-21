// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! `/api/sites` — a tenant's site configuration.
//!
//! # Authorization
//!
//! The whole group is mounted behind `require_leader` (`routes/protected.rs`), so a
//! caller is the tenant owner or a community leader and a delegated share-link token
//! is refused outright. There is deliberately no **file-level** check: configuring
//! and publishing a site is one owner/leader decision, so a mount may name any
//! document of the tenant.
//!
//! The guard is not the whole check. Published pages are served under a CSP that
//! must carry `script-src 'unsafe-inline'` (`cache::content_security_policy`), so
//! their markup is held to an element/attribute allowlist by
//! `cloudillo_file::site_html` at **upload** time, long before this route commits
//! them. A leader can publish any *content*; they cannot publish script.
//!
//! # Shape
//!
//! One row per tenant, so the resource has no id and no listing: `GET` and `PATCH`
//! both address `/api/sites` and answer with the same [`SiteConfig`]. `publish` and
//! `rollback` each answer with the one `site_docs` row they wrote.
//! `GET /api/sites/pages` is the odd one out — it opens every mount's container, for
//! the navigation editor's target picker alone.
//!
//! Downloading a generation is not here: a container is an ordinary managed file, so
//! `GET /api/files/{file_id}` already serves it under its own ABAC.

use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};

use crate::cache;
use crate::prelude::*;
use cloudillo_core::extract::{Auth, OptionalRequestId};
use cloudillo_types::meta_adapter::{
	PublishSiteDoc, Site, SiteDoc, SiteNavItem, UpsertSite, UpsertSiteMount,
};
use cloudillo_types::types::ApiResponse;
use cloudillo_types::worker::Priority;

/// A tenant's whole site configuration — the answer of both routes.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteConfig {
	/// `None` until the tenant first writes a site record — distinct from a record
	/// with no document at `/`, which is a site that exists and serves nothing yet.
	pub site: Option<Site>,
	/// Every document mounted into the site, the root included. A row exists from the
	/// moment the owner adds a document, with both generation columns still unset.
	pub docs: Vec<SiteDoc>,
	/// What the navigation would be with no explicit list: the root container's
	/// manifest nav, joined onto `/`. Returned whether or not `sites.nav` is set,
	/// because the editor shows it as "automatic" and seeds a new list from it. Empty
	/// when there is no published root container, or its manifest is unreadable.
	pub derived_nav: Vec<SiteNavItem>,
}

/// Body of `PATCH /api/sites`.
///
/// [`Patch`] gives each field the three PATCH states; the adapter's `UpsertSite` is
/// a full assignment, so this handler reads the record first and fills in the rest.
///
/// `status` is deliberately not writable: it is the serving kill switch and the
/// settings page has no control for it yet. A new record is created `'A'`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct PatchSite {
	/// The owner's explicit main navigation, assigned wholesale. `null` is the
	/// editor's "reset to automatic"; an empty array means the same thing, since empty
	/// *is* the derive state in storage.
	pub nav: Patch<Vec<SiteNavItem>>,
}

/// Longest label and target one entry may carry, in characters.
///
/// Counted in `chars()`, not bytes, so the limit means the same thing for a
/// Hungarian label as for an English one.
const MAX_NAV_LABEL_LEN: usize = 128;
const MAX_NAV_TARGET_LEN: usize = 512;

/// `GET /api/sites` — the tenant's site record and its mounted documents.
pub async fn get_site(
	State(app): State<App>,
	tn_id: TnId,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<SiteConfig>>)> {
	let config = read_config(&app, tn_id).await?;
	Ok((StatusCode::OK, Json(ApiResponse::new(config).with_req_id(req_id.unwrap_or_default()))))
}

/// `PATCH /api/sites` — set or clear the site's explicit main navigation.
///
/// Creates the record if the tenant has none, so the settings page needs no
/// separate "enable site" call.
pub async fn patch_site(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(mut body): Json<PatchSite>,
) -> ClResult<(StatusCode, Json<ApiResponse<SiteConfig>>)> {
	// Trimmed before it is checked: `is_safe_nav_target` judges the *trimmed* string,
	// so canonicalising here keeps the value checked and the value emitted the same
	// one — and makes `aria-current`'s `target == path` work despite a stray blank.
	if let Patch::Value(items) = &mut body.nav {
		normalize_nav(items);
		validate_nav(items)?;
	}

	// Straight through as a patch, with no read first: `nav` is the only column this
	// path writes, so reading `status` back only to write it in again would let two
	// concurrent edits lose one side. A missing record upserts as an active one — `'A'`
	// is the column default, and a site created disabled would be dark with no control
	// to turn it on.
	let nav = match &body.nav {
		Patch::Undefined => Patch::Undefined,
		Patch::Null => Patch::Null,
		Patch::Value(items) => Patch::Value(items.as_slice()),
	};
	app.meta_adapter.upsert_site(tn_id, &UpsertSite { nav }).await?;
	info!("User {} updated the site config", auth.id_tag);

	// The nav a request sees is resolved onto the cache entry, so a nav edit only goes
	// live once the entry carries it. The narrow refresh: a nav edit cannot touch a
	// container, so rebuilding would re-open every mounted one for nothing. Never fatal:
	// the row is committed either way, and the next publish or reload picks it up.
	if let Err(e) = cache::refresh_tenant_nav(&app, tn_id).await {
		warn!(error = %e, "Failed to refresh the site cache after a config change");
	}

	// Re-read rather than echo the request back: `created_at` / `updated_at` are
	// written by the row's triggers, so only the stored row knows them.
	let config = read_config(&app, tn_id).await?;
	Ok((StatusCode::OK, Json(ApiResponse::new(config).with_req_id(req_id.unwrap_or_default()))))
}

/// One published page, as the navigation editor's target picker lists it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SitePage {
	/// The mount the page came from, so the picker can group by document.
	pub mount_path: Box<str>,
	/// **Site-absolute**, joined here and not in the editor: a manifest path is
	/// container-relative and only the server knows which mount served it.
	pub path: String,
	pub title: Box<str>,
	/// `index` pages are the natural nav targets, so the editor surfaces them
	/// first. Absent on a container built before the field existed.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub archetype: Option<Box<str>>,
}

/// The slice of `_site/manifest.json` [`list_site_pages`] reads — a third projection
/// of the same file, alongside [`ContainerManifest`] and `cache::RootManifest`.
#[derive(Debug, Deserialize)]
struct PagesManifest {
	#[serde(default)]
	pages: std::collections::HashMap<String, PagesManifestPage>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PagesManifestPage {
	path: String,
	#[serde(default)]
	title: Box<str>,
	#[serde(default)]
	archetype: Option<Box<str>>,
}

/// `GET /api/sites/pages` — every published page of every mount, for the
/// navigation editor's target picker.
///
/// Read on demand and **never cached**: one blob read per *mount* on a leader-only
/// route a human opens by hand, where [`cache::SiteEntry`] is held in memory for
/// every site on the node and this grows with the page count.
///
/// A mount whose manifest cannot be read contributes nothing rather than failing the
/// request — one broken container must not hide the other documents' pages.
pub async fn list_site_pages(
	State(app): State<App>,
	tn_id: TnId,
	OptionalRequestId(req_id): OptionalRequestId,
) -> ClResult<(StatusCode, Json<ApiResponse<Vec<SitePage>>>)> {
	let docs = app.meta_adapter.list_site_docs(tn_id).await?;
	let mut pages: Vec<SitePage> = Vec::new();

	for doc in &docs {
		// An unpublished row has no container to read, which is the normal state
		// between "add to site" and the first publish. Its mount path still reaches
		// the editor, through `SiteConfig::docs`.
		let (Some(mount_path), Some(file_id)) =
			(doc.published_mount_path.as_deref(), doc.published_file_id.as_deref())
		else {
			continue;
		};
		let manifest: PagesManifest = match read_manifest_as(&app, tn_id, file_id).await {
			Ok(manifest) => manifest,
			Err(e) => {
				warn!(mount = %mount_path, error = %e, "Unreadable container manifest");
				continue;
			}
		};
		for page in manifest.pages.into_values() {
			pages.push(SitePage {
				mount_path: mount_path.into(),
				path: crate::site_path(mount_path, &page.path),
				title: page.title,
				archetype: page.archetype,
			});
		}
	}

	// A manifest's pages are a hash map, so without this the order changes between
	// two identical requests and the picker reshuffles under the cursor.
	pages.sort_by(|a, b| a.mount_path.cmp(&b.mount_path).then_with(|| a.path.cmp(&b.path)));
	Ok((StatusCode::OK, Json(ApiResponse::new(pages).with_req_id(req_id.unwrap_or_default()))))
}

/// Body of `POST /api/sites/publish`.
///
/// Both ids are already the caller's: the browser built the container, the shell
/// uploaded it, and this call is the commit half. Nothing here describes the site —
/// the `site_docs` row says where it mounts and the manifest only has to agree.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishRequest {
	/// The Notillo document the container was serialized from.
	pub doc_file_id: String,
	/// The freshly uploaded container.
	pub container_file_id: String,
}

/// The slice of `_site/manifest.json` this endpoint reads. The full shape is
/// `SiteManifest` in `libs/core/src/site.ts`; the rest — pages, nav, redirects — is
/// the client runtime's and `cloudillo-search`'s business. Unknown fields are ignored
/// so a newer publisher cannot fail against an older server.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContainerManifest {
	version: u32,
	mount_path: String,
}

/// The manifest version this server understands.
const MANIFEST_VERSION: u32 = 1;

/// `POST /api/sites/publish` — commit an uploaded container as a document's live
/// generation.
///
/// Answers with the `site_docs` row after the flip, so `publishedFileId` echoes the
/// container just committed and `previousFileId` names the one it displaced.
///
/// Reserved-path re-validation is left out on purpose: the node's own handlers run
/// *before* the site, so a page claiming a reserved name is unreachable rather than
/// dangerous, and Notillo warns while the author types. A second list here would have
/// to be kept in step with the first across two repositories to prevent nothing.
///
/// The manifest read does not *take* the mount path, it only checks it. The
/// `site_docs` row is written in settings before a document ever publishes, and the
/// publisher reads it back before it builds, so the row is the authority on where a
/// document mounts; the manifest's `mountPath` is a claim about which prefix the
/// container's baked links point at, and a disagreement means a repath mid-publish.
///
/// Neither re-index call writes a search row here: `cloudillo-search` contributes a
/// container's pages only while a `site_docs` row serves it, so re-indexing the new
/// container adds its pages and re-indexing the displaced one drops them, by set
/// replacement. The container's own filename row survives either way.
///
/// The generation stored is the *container's* `file_id`, not the id the request
/// named: `read_file` resolves both that and the pending `@{f_id}` spelling the
/// upload's 201 returns, but `list_referenced_managed_fids` and the indexer's
/// liveness check join on `files.file_id` — hence the finalization check below.
///
/// There is no retention step: the displaced generation is simply unreferenced once
/// `previous_file_id` moves past it, and `GcTask` reaps it.
/// `list_referenced_managed_fids` knows both generations, so reaping cannot take a
/// live container.
///
/// # Authorization
///
/// The `require_leader` group guard is the whole check — publishing is one
/// owner/leader decision over the tenant — so there is deliberately no file-level
/// write check on `docFileId`. What is checked here is that both files exist under
/// this tenant, that the container is a `site` container, and that it is **Public**:
/// a private one would serve 404s to every reader with no owner-visible symptom.
pub async fn publish_site(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(body): Json<PublishRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<SiteDoc>>)> {
	// Publishing into an unconfigured tenant would succeed and serve nothing; into a
	// disabled one it would quietly re-arm the kill switch.
	let site = app
		.meta_adapter
		.read_site(tn_id)
		.await?
		.ok_or_else(|| Error::ValidationError("site is not configured".into()))?;
	if site.status.as_ref() != "A" {
		return Err(Error::ValidationError("site is disabled".into()));
	}

	// `read_file` is tenant-scoped, so a foreign id simply does not resolve.
	app.meta_adapter
		.read_file(tn_id, &body.doc_file_id)
		.await?
		.ok_or_else(|| Error::ValidationError("source document not found".into()))?;
	let container = app
		.meta_adapter
		.read_file(tn_id, &body.container_file_id)
		.await?
		.ok_or_else(|| Error::ValidationError("container not found".into()))?;

	if container.preset.as_deref() != Some("site") {
		return Err(Error::ValidationError("container is not a site container".into()));
	}
	// The upload asks for `?visibility=P`; this is the last place that can catch
	// a container that did not get it.
	if container.visibility != Some('P') {
		return Err(Error::ValidationError("container is not public".into()));
	}
	// A pending container's `file_id` is still the `@{f_id}` placeholder the upload's
	// 201 handed the client, but `list_referenced_managed_fids` and the indexer's
	// liveness check both join on `files.file_id` — a placeholder would make `GcTask`
	// blind to a live container and leave its pages unindexed.
	if container.file_id.starts_with('@') {
		return Err(Error::ValidationError("container is not finalized yet".into()));
	}

	// Read before the row, because an unreadable or wrong-version manifest is a
	// container that must not go live whatever the row says.
	let manifest: ContainerManifest =
		read_manifest_as(&app, tn_id, &body.container_file_id).await?;
	if manifest.version != MANIFEST_VERSION {
		return Err(Error::ValidationError(format!(
			"unsupported container manifest version {}",
			manifest.version
		)));
	}
	// No row means the document was never added to the site. Publishing would have to
	// invent a path — `/` is what a publisher that could not resolve one builds for —
	// and a stray document taking the site root silently is worse than a refusal that
	// names the fix.
	let doc_row =
		app.meta_adapter.read_site_doc(tn_id, &body.doc_file_id).await?.ok_or_else(|| {
			Error::ValidationError(
				"document is not part of this site — add it in site settings first".into(),
			)
		})?;
	let mount_path = normalize_mount_path(&doc_row.mount_path)?;
	let mount_path = mount_path.as_str();

	// A container bakes absolute links against the path it was built for, so going
	// live elsewhere would serve a page whose every link points away. Both paths are
	// named because which one is wrong depends on what the owner meant.
	let declared = normalize_mount_path(&manifest.mount_path)?;
	if declared != mount_path {
		return Err(Error::Conflict(format!(
			"container was built for {declared} but this document is mounted at \
			 {mount_path} — publish again to build for {mount_path}"
		)));
	}

	// The unique index on (tn_id, mount_path) would catch this as a raw constraint
	// violation; naming the document that holds the mount is the handler's job.
	if let Some(existing) = app.meta_adapter.read_site_doc_by_mount(tn_id, mount_path).await?
		&& existing.doc_file_id.as_ref() != body.doc_file_id.as_str()
	{
		return Err(Error::Conflict(format!(
			"mount path {mount_path} is already served by document {}",
			existing.doc_file_id
		)));
	}

	// The check above is backed by `UNIQUE (tn_id, mount_path)`; this one has no index
	// behind it. Serving reads `published_mount_path` (`cache::mounts_from_docs`), and
	// a document repathed away without republishing keeps serving the path it left — so
	// a second document publishing there would leave two live mounts claiming one
	// prefix, with `resolve_mount` picking arbitrarily between them.
	if let Some(serving) =
		app.meta_adapter.read_site_doc_by_published_mount(tn_id, mount_path).await?
		&& serving.doc_file_id.as_ref() != body.doc_file_id.as_str()
	{
		return Err(Error::Conflict(format!(
			"{mount_path} is still served by document {} — publish that document at \
			 its new path, or remove it from the site, before publishing here",
			serving.doc_file_id
		)));
	}

	// The generation swap. Read-demote-write is one upsert inside the adapter, so two
	// concurrent publishes of one document cannot both read the same generation and
	// lose one. Nothing above this line writes, so a failure anywhere leaves an orphan
	// container for `GcTask` and no half-published site.
	//
	// A republish of an unedited document dedups to the same file id, so
	// `published_file_id` can end up equal to what it displaced. Normal, not an error.
	app.meta_adapter
		.publish_site_doc(
			tn_id,
			&PublishSiteDoc {
				doc_file_id: &body.doc_file_id,
				mount_path,
				// The resolved row's id, not the one the request named: only the
				// content id works for what later joins on this column.
				published_file_id: &container.file_id,
			},
		)
		.await?;
	info!(
		"User {} published document {} at {} (container {})",
		auth.id_tag, body.doc_file_id, mount_path, container.file_id
	);

	// The cache is push-triggered, so nothing serves the new generation until this
	// runs. A failure leaves the previous cache in place: stale, not empty.
	if let Err(e) = cache::refresh_tenant(&app, tn_id).await {
		warn!("Site published but the site cache could not be refreshed: {}", e);
	}

	let doc = app
		.meta_adapter
		.read_site_doc(tn_id, &body.doc_file_id)
		.await?
		.ok_or_else(|| Error::Internal("site_docs row vanished after publish".into()))?;

	// `published_file_id` is necessarily set here; the `Option` models the row that
	// has never published, which this path cannot reach.
	reindex_generations(&app, tn_id, &doc);

	Ok((StatusCode::OK, Json(ApiResponse::new(doc).with_req_id(req_id.unwrap_or_default()))))
}

/// Re-index both container generations a document points at.
///
/// Fire-and-forget in every caller: a missed run costs a stale search result, which
/// must not fail an already-committed operation, and the reindex sweep converges
/// either way. No transaction handle crosses the `MetaAdapter` boundary, so a crash
/// between the flip and this leaves a live generation briefly unindexed.
///
/// The displaced generation goes first, so a half-run errs towards missing pages
/// rather than pages served from a container nothing points at. Skipped when the two
/// are equal — identical bytes dedup to one id, and indexing it twice would race the
/// scheduler on one key.
fn reindex_generations(app: &App, tn_id: TnId, doc: &SiteDoc) {
	let published = doc.published_file_id.as_deref();
	if let Some(previous) = doc.previous_file_id.as_deref()
		&& Some(previous) != published
	{
		cloudillo_core::search_index_file(app, tn_id, previous);
	}
	if let Some(published) = published {
		cloudillo_core::search_index_file(app, tn_id, published);
	}
}

/// Body of `POST /api/sites/mounts` — one document, one site path.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MountRequest {
	/// The Notillo document to serve. Must be a file of this tenant — mounts are
	/// same-tenant only.
	pub doc_file_id: String,
	/// Where it is served from — `/` for the root document, `/blog` for a mount.
	pub mount_path: String,
}

/// `POST /api/sites/mounts` — add a document to the site, or move one.
///
/// Writes `mount_path` and nothing else, so it is safe on a published row: the
/// container being served was built for `published_mount_path` and keeps serving from
/// there until that document publishes again. That separation is why repathing cannot
/// break a live site, and why this handler does not refresh the site cache — nothing
/// it writes is cached.
///
/// Same-tenant only: `read_file` is tenant-scoped, so another tenant's document does
/// not resolve, and there is deliberately no `doc_owner_tag` column.
pub async fn mount_site_doc(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(body): Json<MountRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<SiteConfig>>)> {
	if body.doc_file_id.trim().is_empty() {
		return Err(Error::ValidationError("docFileId must not be empty".into()));
	}
	app.meta_adapter
		.read_file(tn_id, &body.doc_file_id)
		.await?
		.ok_or_else(|| Error::ValidationError("document not found".into()))?;

	// One canonical spelling per served path: `/blog` and `/blog/` would both pass the
	// unique index and then fight over the same prefix.
	let mount_path = normalize_mount_path(&body.mount_path)?;

	// The unique index would catch this as a raw constraint violation; naming the
	// document already there is what the settings page can act on.
	if let Some(existing) = app.meta_adapter.read_site_doc_by_mount(tn_id, &mount_path).await?
		&& existing.doc_file_id.as_ref() != body.doc_file_id.as_str()
	{
		return Err(Error::Conflict(format!(
			"mount path {mount_path} is already served by document {}",
			existing.doc_file_id
		)));
	}

	app.meta_adapter
		.upsert_site_mount(
			tn_id,
			&UpsertSiteMount { doc_file_id: &body.doc_file_id, mount_path: &mount_path },
		)
		.await?;
	info!("User {} mounted document {} at {}", auth.id_tag, body.doc_file_id, mount_path);

	let config = read_config(&app, tn_id).await?;
	Ok((StatusCode::OK, Json(ApiResponse::new(config).with_req_id(req_id.unwrap_or_default()))))
}

/// Body of `DELETE /api/sites/mounts`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnmountRequest {
	/// The document to take out of the site.
	pub doc_file_id: String,
}

/// `DELETE /api/sites/mounts` — take a document out of the site.
///
/// Unconditional, including a row that is currently serving: both generations lose
/// their last reference and `GcTask` reaps them, exactly as a displaced generation is
/// reaped on publish. Refusing while a container exists would make a published
/// document permanently unremovable, since nothing in this API unpublishes one.
///
/// A site whose root mount is gone serves nothing at `/` and falls through to the
/// shell, which `build_entry` already handles.
///
/// Both generations are re-indexed *after* the delete: `cloudillo-search` contributes
/// page rows only while a `site_docs` row names the container in `published_file_id`
/// (`objects::is_live_site_container`), so with the row gone both would otherwise keep
/// every page row they had and every hit would 404. Hence the row is read *before* the
/// delete, for the two ids.
pub async fn unmount_site_doc(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(body): Json<UnmountRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<SiteConfig>>)> {
	// Read first: after the delete there is no row left to name the two containers
	// whose page rows have to go.
	let doc = app
		.meta_adapter
		.read_site_doc(tn_id, &body.doc_file_id)
		.await?
		.ok_or_else(|| Error::ValidationError("document is not part of the site".into()))?;

	// Kept for the concurrent-delete case: the read above raced someone else's
	// unmount of the same document.
	if !app.meta_adapter.delete_site_mount(tn_id, &body.doc_file_id).await? {
		return Err(Error::ValidationError("document is not part of the site".into()));
	}
	info!("User {} removed document {} from the site", auth.id_tag, body.doc_file_id);

	// Unlike the mount write above, this one *is* visible to serving: the removed
	// row may have been the mount answering a live prefix.
	if let Err(e) = cache::refresh_tenant(&app, tn_id).await {
		warn!("Site mount removed but the site cache could not be refreshed: {}", e);
	}

	// Both generations, because neither is live now.
	reindex_generations(&app, tn_id, &doc);

	let config = read_config(&app, tn_id).await?;
	Ok((StatusCode::OK, Json(ApiResponse::new(config).with_req_id(req_id.unwrap_or_default()))))
}

/// Body of `POST /api/sites/rollback`.
///
/// Only the document, because a `site_docs` row keeps exactly two generations and
/// the operation is a swap — there is no version to name.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RollbackRequest {
	/// The document whose two generations are exchanged.
	pub doc_file_id: String,
}

/// `POST /api/sites/rollback` — put the previous container back in service.
///
/// Reached for when a publish went wrong, so it depends on nothing but the two ids
/// already in the row: no generator, no container read, no manifest parse, and
/// deliberately **no `sites.status` check** — a site disabled mid-incident must still
/// be repairable, and the kill switch decides whether the result is served, not
/// whether the pointer may be fixed.
///
/// The swap is symmetric, so calling this twice returns the document to where it
/// started. Neither container loses its last reference, so there is no retention step.
///
/// Both generations are re-indexed *after* the write, because the swap moves both
/// columns and `cloudillo-search` contributes page rows only while a `site_docs` row
/// names the container in `published_file_id` (`objects::is_live_site_container`):
/// the liveness check has to see the new state.
pub async fn rollback_site(
	State(app): State<App>,
	tn_id: TnId,
	Auth(auth): Auth,
	OptionalRequestId(req_id): OptionalRequestId,
	Json(body): Json<RollbackRequest>,
) -> ClResult<(StatusCode, Json<ApiResponse<SiteDoc>>)> {
	// The adapter answers `false` for both "no such row" and "published once only".
	// Neither is a server fault and both need the same fix, so they share a message.
	if !app.meta_adapter.rollback_site_doc(tn_id, &body.doc_file_id).await? {
		return Err(Error::ValidationError(
			"document has no previous generation to roll back to".into(),
		));
	}
	info!("User {} rolled back the site document {}", auth.id_tag, body.doc_file_id);

	// Same push-triggered cache as a publish: without this the old generation is
	// committed in the table and the previous one still served.
	if let Err(e) = cache::refresh_tenant(&app, tn_id).await {
		warn!("Site rolled back but the site cache could not be refreshed: {}", e);
	}

	let doc = app
		.meta_adapter
		.read_site_doc(tn_id, &body.doc_file_id)
		.await?
		.ok_or_else(|| Error::Internal("site_docs row vanished after rollback".into()))?;

	reindex_generations(&app, tn_id, &doc);

	Ok((StatusCode::OK, Json(ApiResponse::new(doc).with_req_id(req_id.unwrap_or_default()))))
}

/// The longest mount path a manifest may declare. The manifest is
/// attacker-controlled JSON and this value becomes a database key.
const MAX_MOUNT_PATH_LEN: usize = 512;

/// Canonical form of a container's declared mount path.
///
/// `UNIQUE (tn_id, mount_path)` only prevents byte-equal collisions, but
/// `SiteEntry::resolve_mount` trims trailing slashes — so `/blog` and `/blog/` would
/// pass the index and then fight over the same prefix.
///
/// It also refuses a mount whose first segment is one the node answers before a site
/// ever runs (`cloudillo_types::site::is_reserved_root_segment`): the asset roots
/// `ServeDir` claims and the roots the shell's router claims, which
/// `static_fallback_handler` resolves ahead of the site — a document mounted at
/// `/apps` or `/login` would publish successfully and then be dead with no signal.
/// `publish_site` normalises both the stored `mount_path` and the manifest's declared
/// one, so this covers the settings write, an older row, and the container's claim.
/// The root mount `/` has no segments and is unaffected.
///
/// Stricter than the treatment of a *page* claiming a reserved name, which
/// `publish_site` waives: a page is one URL and Notillo warns while the author types,
/// where a mount is a whole document and nothing warns.
fn normalize_mount_path(raw: &str) -> ClResult<String> {
	let raw = raw.trim();
	// Before the split, not after: normalising only removes characters, so this bounds
	// the result too — and `raw` comes from a manifest bounded only by
	// `container::MAX_ENTRY_BYTES`, so the split and join must not run on it first.
	if raw.len() > MAX_MOUNT_PATH_LEN {
		return Err(Error::ValidationError("container mount path is too long".into()));
	}
	if !raw.starts_with('/') {
		return Err(Error::ValidationError("container mount path must start with '/'".into()));
	}

	// Empty segments collapse `//`; `.` and `..` never reach the mount table, so
	// no stored path can climb out of the prefix it claims.
	let mut segments = Vec::new();
	for segment in raw.split('/') {
		if segment.is_empty() {
			continue;
		}
		if segment == "." || segment == ".." {
			return Err(Error::ValidationError(
				"container mount path must not contain '.' or '..' segments".into(),
			));
		}
		segments.push(segment);
	}

	if let Some(first) = segments.first()
		&& cloudillo_types::site::is_reserved_root_segment(first)
	{
		return Err(Error::ValidationError(format!(
			"/{first} is reserved by the application and cannot serve a site"
		)));
	}

	let path =
		if segments.is_empty() { "/".to_owned() } else { format!("/{}", segments.join("/")) };
	// Whole paths, not root segments, so this is a second check and not part of the
	// one above: `serve_site_path` answers `/robots.txt` and `/sitemap-index.xml`
	// ahead of the mount match, and a document mounted at either would be dark.
	if cloudillo_types::site::is_reserved_mount_path(&path) {
		return Err(Error::ValidationError(format!(
			"{path} is generated by the site itself and cannot serve a document"
		)));
	}
	Ok(path)
}

/// Read and parse `_site/manifest.json` out of a container, into any projection
/// of it — this module models two, and neither is the definition (`SiteManifest`
/// in `libs/core/src/site.ts` is).
async fn read_manifest_as<T: serde::de::DeserializeOwned + Send + 'static>(
	app: &App,
	tn_id: TnId,
	file_id: &str,
) -> ClResult<T> {
	let container = cloudillo_file::open_container(app, tn_id, file_id, Priority::High).await?;
	// The request path — a publish or a settings read, with a person waiting.
	let manifest = container.read_manifest(app, Priority::High).await?;
	manifest.ok_or_else(|| {
		Error::ValidationError(format!("container has no {}", crate::MANIFEST_ENTRY))
	})
}

/// Read the record and its mounted documents. The list is returned even when
/// there is no record — a stale `site_docs` row is worth showing rather than
/// hiding behind a missing singleton.
async fn read_config(app: &App, tn_id: TnId) -> ClResult<SiteConfig> {
	let site = app.meta_adapter.read_site(tn_id).await?;
	let docs = app.meta_adapter.list_site_docs(tn_id).await?;
	// Off the cache entry, which parsed the root manifest when it was built, so this
	// response costs no blob read. The container read is the fallback for a tenant with
	// no entry — disabled ('D'), or no published root.
	let derived_nav = match cache::lookup_by_tenant(app.ext::<cache::SiteCache>()?, tn_id).await {
		Some(entry) => entry.derived_nav.clone(),
		None => match root_container(&docs) {
			Some(file_id) => cache::read_derived_nav_uncached(app, tn_id, file_id).await,
			None => Vec::new(),
		},
	};
	Ok(SiteConfig { site, docs, derived_nav })
}

/// The container currently *served* at `/`, if the tenant has one. Keyed on
/// `published_mount_path` for the same reason the cache is: a row repathed to `/`
/// but not yet republished is still serving from wherever it was built for.
fn root_container(docs: &[SiteDoc]) -> Option<&str> {
	docs.iter()
		.find(|doc| doc.published_mount_path.as_deref() == Some("/"))
		.and_then(|doc| doc.published_file_id.as_deref())
}

/// Trim every label and target, at both levels, so the stored value is the one
/// [`validate_nav_entry`] judged. See [`patch_site`].
fn normalize_nav(items: &mut [SiteNavItem]) {
	fn trim(value: &mut Box<str>) {
		let trimmed = value.trim();
		if trimmed.len() != value.len() {
			*value = trimmed.into();
		}
	}
	for item in items {
		trim(&mut item.label);
		trim(&mut item.target);
		for child in &mut item.children {
			trim(&mut child.label);
			trim(&mut child.target);
		}
	}
}

/// Reject a nav list that cannot render: a blank label is an invisible link, a blank
/// target is a link to nothing.
///
/// Bounded three ways, because the resolved copy lives on the cache entry for the
/// process lifetime and is serialized into both the chrome HTML and the boot seed on
/// every page render: [`cache::MAX_NAV_ITEMS`] per level, [`cache::MAX_NAV_TOTAL`]
/// over the whole tree — the per-level caps alone multiply out to 4096 entries — and
/// [`MAX_NAV_LABEL_LEN`] / [`MAX_NAV_TARGET_LEN`] on each value.
///
/// A target must be site-absolute or an `http(s)` URL
/// ([`cloudillo_types::site::is_safe_nav_target`]): it lands in an `href` and the site
/// CSP does not stop a `javascript:` one. Beyond its scheme it is **not** checked —
/// navigation is not routing, so a target may name a path no document serves.
fn validate_nav(items: &[SiteNavItem]) -> ClResult<()> {
	if items.len() > cache::MAX_NAV_ITEMS {
		return Err(Error::ValidationError(format!(
			"a site navigation may hold at most {} entries",
			cache::MAX_NAV_ITEMS
		)));
	}
	let total = items.len() + items.iter().map(|item| item.children.len()).sum::<usize>();
	if total > cache::MAX_NAV_TOTAL {
		return Err(Error::ValidationError(format!(
			"a site navigation may hold at most {} entries in total",
			cache::MAX_NAV_TOTAL
		)));
	}
	for item in items {
		validate_nav_entry(&item.label, &item.target)?;
		if item.children.len() > cache::MAX_NAV_ITEMS {
			return Err(Error::ValidationError(format!(
				"a navigation entry may hold at most {} sub-entries",
				cache::MAX_NAV_ITEMS
			)));
		}
		for child in &item.children {
			validate_nav_entry(&child.label, &child.target)?;
		}
	}
	Ok(())
}

/// The per-value half of [`validate_nav`], shared by both levels — a child is
/// bounded exactly as its parent is.
fn validate_nav_entry(label: &str, target: &str) -> ClResult<()> {
	if label.trim().is_empty() || target.trim().is_empty() {
		return Err(Error::ValidationError(
			"every navigation entry needs a label and a target".into(),
		));
	}
	if label.chars().count() > MAX_NAV_LABEL_LEN {
		return Err(Error::ValidationError(format!(
			"a navigation label may be at most {MAX_NAV_LABEL_LEN} characters"
		)));
	}
	if target.chars().count() > MAX_NAV_TARGET_LEN {
		return Err(Error::ValidationError(format!(
			"a navigation target may be at most {MAX_NAV_TARGET_LEN} characters"
		)));
	}
	if !cloudillo_types::site::is_safe_nav_target(target) {
		return Err(Error::ValidationError(
			"a navigation target must be a site path or an http(s) URL".into(),
		));
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use cloudillo_types::meta_adapter::SiteNavChild;

	/// Every spelling of the root mount is one stored path, because
	/// `SiteEntry::resolve_mount` cannot tell them apart either.
	#[test]
	fn every_spelling_of_the_root_mount_normalises_to_one() {
		for raw in ["/", "/ ", "//", " // "] {
			assert_eq!(normalize_mount_path(raw).expect("normalised"), "/", "{raw:?}");
		}
	}

	/// The trailing slash is the collision the unique index cannot see: `/blog`
	/// and `/blog/` are two rows claiming one served prefix.
	#[test]
	fn a_trailing_or_doubled_slash_is_not_a_second_mount() {
		for raw in ["/blog", "/blog/", "//blog//", " /blog/ "] {
			assert_eq!(normalize_mount_path(raw).expect("normalised"), "/blog", "{raw:?}");
		}
		assert_eq!(normalize_mount_path("/a/b/").expect("normalised"), "/a/b");
	}

	#[test]
	fn a_relative_or_dotted_mount_path_is_refused() {
		assert!(normalize_mount_path("blog").is_err());
		assert!(normalize_mount_path("/a/../b").is_err());
		assert!(normalize_mount_path("/a/./b").is_err());
		assert!(normalize_mount_path(&format!("/{}", "a".repeat(MAX_MOUNT_PATH_LEN))).is_err());
	}

	/// `static_fallback_handler` answers these before the site ever runs, so a
	/// document mounted under one would publish and then be dead with no signal.
	#[test]
	fn a_mount_under_a_root_the_node_answers_itself_is_refused() {
		for raw in ["/apps", "/login", "/~", "/@x", "/sw.js", "/assets-0.8.18", "/apps/blog"] {
			assert!(normalize_mount_path(raw).is_err(), "{raw}");
		}
	}

	/// `serve_site_path` composes these two ahead of the mount match, so a document
	/// mounted at either would be published and then unreachable.
	#[test]
	fn a_mount_at_a_path_the_site_generates_is_refused() {
		for raw in ["/robots.txt", "/sitemap-index.xml", "/robots.txt/", " /robots.txt "] {
			assert!(normalize_mount_path(raw).is_err(), "{raw}");
		}
		// Only those two exact paths; a name that merely resembles one is free.
		for raw in ["/robots", "/robots.txt.html", "/sitemap.xml", "/blog/robots.txt"] {
			assert!(normalize_mount_path(raw).is_ok(), "{raw}");
		}
	}

	fn nav_item(label: &str, target: &str, children: usize) -> SiteNavItem {
		SiteNavItem {
			label: label.into(),
			target: target.into(),
			children: (0..children)
				.map(|i| SiteNavChild { label: format!("c{i}").into(), target: "/c".into() })
				.collect(),
		}
	}

	/// A blank label is an invisible link and a blank target is a link to nothing,
	/// at either level.
	#[test]
	fn a_blank_label_or_target_is_refused() {
		assert!(validate_nav(&[nav_item("  ", "/blog", 0)]).is_err());
		assert!(validate_nav(&[nav_item("Blog", " ", 0)]).is_err());
		let mut parent = nav_item("Blog", "/blog", 1);
		parent.children[0].label = "".into();
		assert!(validate_nav(&[parent]).is_err());
	}

	/// Both values are otherwise unbounded: every page render serializes them twice, and
	/// the cache entry holds them for the process lifetime.
	#[test]
	fn an_overlong_label_or_target_is_refused() {
		let long_label = "a".repeat(MAX_NAV_LABEL_LEN + 1);
		assert!(validate_nav(&[nav_item(&long_label, "/blog", 0)]).is_err());
		let long_target = format!("/{}", "b".repeat(MAX_NAV_TARGET_LEN));
		assert!(validate_nav(&[nav_item("Blog", &long_target, 0)]).is_err());
		let mut parent = nav_item("Blog", "/blog", 1);
		parent.children[0].label = long_label.into();
		assert!(validate_nav(&[parent]).is_err());
	}

	/// The per-level caps multiply: 64 entries of 64 children each pass both and
	/// still amount to 4096 links. The total is what actually bounds the tree.
	#[test]
	fn a_wide_but_shallow_nav_is_refused_on_the_total() {
		let items: Vec<SiteNavItem> =
			(0..cache::MAX_NAV_ITEMS).map(|i| nav_item(&format!("n{i}"), "/n", 4)).collect();
		assert!(validate_nav(&items).is_err());
	}

	/// The target lands in an `href` and the site CSP carries `script-src
	/// 'unsafe-inline'`, which does not stop a `javascript:` URL — and `require_leader`
	/// makes this reachable on a community tenant by someone who does not own it.
	#[test]
	fn a_nav_target_that_is_not_a_path_or_an_http_url_is_refused() {
		for target in [
			"javascript:alert(1)",
			"JaVaScRiPt:alert(1)",
			"data:text/html,<script>",
			"//evil.example",
			"\tjavascript:x",
			"blog/hello",
		] {
			assert!(validate_nav(&[nav_item("Blog", target, 0)]).is_err(), "{target}");
			let mut parent = nav_item("Blog", "/blog", 1);
			parent.children[0].target = target.into();
			assert!(validate_nav(&[parent]).is_err(), "child {target}");
		}
	}

	/// The stored value has to be the one `is_safe_nav_target` judged: it lands in an
	/// `href` and in the boot seed, and `aria-current` compares it to the request path.
	#[test]
	fn a_nav_entry_is_stored_trimmed() {
		let mut items = vec![nav_item("  Blog  ", "  /blog  ", 1)];
		items[0].children[0].label = "  One  ".into();
		items[0].children[0].target = "  /blog/one  ".into();

		normalize_nav(&mut items);
		validate_nav(&items).expect("trimmed nav");

		assert_eq!(&*items[0].label, "Blog");
		assert_eq!(&*items[0].target, "/blog");
		assert_eq!(&*items[0].children[0].label, "One");
		assert_eq!(&*items[0].children[0].target, "/blog/one");
	}

	#[test]
	fn an_ordinary_two_level_nav_passes() {
		let items = vec![nav_item("Home", "/", 0), nav_item("Blog", "/blog", 3)];
		validate_nav(&items).expect("ordinary nav");
		// An external URL is a perfectly ordinary nav target.
		validate_nav(&[nav_item("Elsewhere", "https://example.com/x", 0)]).expect("external nav");
		validate_nav(&[nav_item("Plain", "http://example.com/x", 0)]).expect("plain http nav");
	}
}

// vim: ts=4
