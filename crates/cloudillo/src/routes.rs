// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! API routes

use axum::{
	Router,
	body::Body,
	extract::{DefaultBodyLimit, State},
	http::{HeaderMap, HeaderValue, Request, StatusCode, header},
	middleware,
	response::{IntoResponse, Response},
	routing::{any, delete, get, patch, post, put},
};
use tower::Service;
use tower_http::{
	compression::{CompressionLayer, CompressionLevel, Predicate, predicate::SizeAbove},
	services::ServeDir,
	set_header::SetResponseHeaderLayer,
};

use crate::admin;
use crate::auth;
use crate::file;
use crate::file::perm::check_perm_file;
use crate::idp;
use crate::prelude::*;
use crate::proxy;
use crate::push;
use crate::r#ref;
use crate::settings;
use crate::websocket;
use cloudillo_action as action;
use cloudillo_action::perm::check_perm_action;
use cloudillo_calendar as calendar;
use cloudillo_contact as contact;
use cloudillo_core::acme;
use cloudillo_core::create_perm::check_perm_create;
use cloudillo_core::middleware::{optional_auth, request_id_middleware, require_auth};
use cloudillo_core::rate_limit::RateLimitLayer;
use cloudillo_profile as profile;
use cloudillo_profile::perm::check_perm_profile;

// ============================================================================
// REQUEST BODY SIZE LIMITS
// ============================================================================

/// Conservative global request-body limit applied to every API route.
///
/// `DefaultBodyLimit` only constrains *buffering* extractors (`Json`, `Bytes`,
/// `String`, `Form`); raw streaming `Body` handlers (file upload, DAV) are
/// unaffected and keep enforcing their own caps. 1 MiB comfortably covers the
/// small JSON payloads that make up the bulk of the API while preventing a
/// single request from buffering unbounded memory.
const GLOBAL_BODY_LIMIT: usize = 1024 * 1024; // 1 MiB

/// Higher body limit for routes that legitimately buffer a whole image, a
/// vCard import or a batch of federated action tokens. Still bounded, just
/// generous enough not to reject real payloads.
const UPLOAD_BODY_LIMIT: usize = 16 * 1024 * 1024; // 16 MiB

/// Per-route override layer raising the body limit to [`UPLOAD_BODY_LIMIT`].
/// A more specific (inner) `DefaultBodyLimit` overrides the global one.
fn upload_body_limit() -> DefaultBodyLimit {
	DefaultBodyLimit::max(UPLOAD_BODY_LIMIT)
}

/// Default-deny allowlist of genuinely-compressible, text-based media types.
/// Used as the extra `compress_when` predicate on the API `CompressionLayer`.
/// Self-contained (no longer ANDed with `DefaultPredicate`): the size floor lives
/// in the layer's `SizeAbove(32)`, while the content-type allowlist, the SSE
/// exclusion and the 206-partial exclusion live here. `image/svg+xml` matches the
/// `+xml` arm and IS compressed (it is text and compresses well).
fn is_compressible_media_type(
	status: axum::http::StatusCode,
	_: axum::http::Version,
	headers: &axum::http::HeaderMap,
	_: &axum::http::Extensions,
) -> bool {
	// Never compress partial responses: tower-http would re-encode the body while
	// leaving Content-Range untouched (it only strips Accept-Ranges/Content-Length),
	// corrupting the 206. Range/seek responses must pass through uncompressed.
	if status == axum::http::StatusCode::PARTIAL_CONTENT {
		return false;
	}
	let essence = headers
		.get(axum::http::header::CONTENT_TYPE)
		.and_then(|v| v.to_str().ok())
		.unwrap_or("")
		.split(';')
		.next()
		.unwrap_or("")
		.trim();
	// SSE must stay unbuffered/uncompressed (matched by the text/ arm below otherwise).
	if essence == "text/event-stream" {
		return false;
	}
	essence.starts_with("text/")
		|| matches!(
			essence,
			"application/json"
				| "application/javascript"
				| "application/xml"
				| "application/xhtml+xml"
				| "application/wasm"
		) || essence.ends_with("+json")
		|| essence.ends_with("+xml") // includes image/svg+xml — intentionally compressed
}

// ============================================================================
// SECURITY HEADERS
// ============================================================================

/// Add transport/sniffing/referrer hardening headers to every response of a
/// router.
///
/// Deliberately scoped to three headers and **no framing policy**: the shell
/// embeds sandboxed apps in iframes (including, in future, apps served from
/// external origins), so we must not add `X-Frame-Options` or a restrictive
/// `frame-ancestors`/`frame-src` CSP that would block that embedding.
///
/// All three use `if_not_present` so handler- or file-specific headers (e.g.
/// the per-SVG `Content-Security-Policy` set when serving uploaded files) are
/// never overwritten.
fn with_security_headers(router: Router) -> Router {
	router
		// HTTPS-only platform: opt browsers into HTTPS for two years.
		.layer(SetResponseHeaderLayer::if_not_present(
			header::STRICT_TRANSPORT_SECURITY,
			HeaderValue::from_static("max-age=63072000; includeSubDomains"),
		))
		// Block MIME sniffing across the whole API/app surface.
		.layer(SetResponseHeaderLayer::if_not_present(
			header::X_CONTENT_TYPE_OPTIONS,
			HeaderValue::from_static("nosniff"),
		))
		// Don't leak full URLs (paths can carry id-tags) to cross-origin targets.
		.layer(SetResponseHeaderLayer::if_not_present(
			header::REFERRER_POLICY,
			HeaderValue::from_static("strict-origin-when-cross-origin"),
		))
}

// ============================================================================
// PROTECTED ROUTES - All routes require valid authentication
// ============================================================================
fn init_protected_routes(app: App) -> Router<App> {
	// --- Permission-Checked Routes (ABAC) ---
	// These routes use attribute-based access control beyond basic auth

	// Action create routes (check_perm_create for quota/tier checking)
	let action_router_create = Router::new()
		.route("/api/actions", post(action::handler::post_action))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_create("action", "create")));

	// Action write routes (check_perm_action("write"))
	let action_router_write = Router::new()
		.route("/api/actions/{action_id}", delete(action::handler::delete_action))
		.route("/api/actions/{action_id}", patch(action::handler::patch_action))
		.route("/api/actions/{action_id}/publish", post(action::handler::publish_draft))
		.route("/api/actions/{action_id}/cancel", post(action::handler::cancel_scheduled))
		.route("/api/actions/{action_id}/accept", post(action::handler::post_action_accept))
		.route("/api/actions/{action_id}/reject", post(action::handler::post_action_reject))
		.route("/api/actions/{action_id}/dismiss", post(action::handler::post_action_dismiss))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_action("write")));

	// Profile read routes (check_perm_profile("read")) - requires auth
	let profile_router_read = Router::new()
		.route("/api/profiles/{id_tag}", get(profile::list::get_profile_by_id_tag))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_profile("read")));

	// Profile write routes (check_perm_profile("write"))
	let profile_router_write = Router::new()
		.route("/api/profiles/{id_tag}", patch(profile::update::patch_profile_relationship))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_profile("write")));

	// Profile admin routes (check_perm_profile("admin"))
	let profile_router_admin = Router::new()
		.route("/api/admin/profiles/{id_tag}", patch(profile::update::patch_profile_admin))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_profile("admin")));

	// Admin tenant routes (require_admin - checks for SADM role)
	let admin_tenant_router = Router::new()
		.route("/api/admin/tenants", get(admin::tenant::list_tenants))
		.route(
			"/api/admin/tenants/{id_tag}/password-reset",
			post(admin::tenant::send_password_reset),
		)
		.route(
			"/api/admin/tenants/{id_tag}/purge",
			post(admin::tenant::purge_tenant_handler),
		)
		.route("/api/admin/email/test", post(admin::email::send_test_email))
		.route("/api/admin/cert-status", get(admin::cert::get_cert_status))
		// Proxy site management
		.route("/api/admin/proxy-sites", get(proxy::admin::list_proxy_sites))
		.route("/api/admin/proxy-sites", post(proxy::admin::create_proxy_site))
		.route("/api/admin/proxy-sites/{site_id}", get(proxy::admin::get_proxy_site))
		.route("/api/admin/proxy-sites/{site_id}", patch(proxy::admin::update_proxy_site))
		.route("/api/admin/proxy-sites/{site_id}", delete(proxy::admin::delete_proxy_site))
		.route("/api/admin/proxy-sites/{site_id}/renew-cert", post(proxy::admin::trigger_cert_renewal))
		// Community invite management
		.route("/api/admin/invite-community", post(admin::invite::post_invite_community))
		.layer(middleware::from_fn_with_state(app.clone(), admin::perm::require_admin));

	// File create routes (check_perm_create for quota/tier checking)
	let file_router_create = Router::new()
		.route("/api/files", post(file::handler::post_file))
		// Streaming upload: reads the raw `Body` and enforces its own
		// per-tenant size cap, so opt out of the global buffering limit.
		.route(
			"/api/files/{preset}/{file_name}",
			post(file::handler::post_file_blob).layer(DefaultBodyLimit::disable()),
		)
		.route("/api/files/{file_id}/duplicate", post(file::management::duplicate_file))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_create("file", "create")));

	// File write routes (check_perm_file("write"))
	let file_router_write = Router::new()
		.route("/api/files/{file_id}", patch(file::management::patch_file))
		.route("/api/files/{file_id}", delete(file::management::delete_file))
		.route("/api/files/{file_id}/restore", post(file::management::restore_file))
		.route("/api/files/{file_id}/tag/{tag}", put(file::tag::put_file_tag))
		.route("/api/files/{file_id}/tag/{tag}", delete(file::tag::delete_file_tag))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_file("write")));

	// File user data routes (authentication only, no file write permission needed)
	// Users can pin/star any file they have read access to. The refresh
	// endpoint also lives here: it checks read-access on the destination row
	// internally rather than going through the file-write ABAC layer.
	let file_user_router = Router::new()
		.route("/api/files/{file_id}/user", patch(file::management::patch_file_user_data))
		.route("/api/files/{file_id}/refresh", post(file::handler::refresh_file));

	// Trash management (collection-level permission - no file_id needed)
	let trash_router = Router::new()
		.route("/api/trash", delete(file::management::empty_trash))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_create("file", "write")));

	// App management routes (check_perm_create for leader-level check)
	let app_management_router = Router::new()
		.route("/api/apps/install", post(file::apkg::install_app))
		.route("/api/apps/installed", get(file::apkg::list_installed_apps))
		.route("/api/apps/@{publisher}/{name}", delete(file::apkg::uninstall_app))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_create("app", "create")));

	// --- Standard Protected Routes ---
	// These routes only require authentication, no additional permission checks

	Router::new()
		// --- Session Management ---
		.route("/api/auth/logout", post(auth::handler::post_logout))
		.route("/api/auth/proxy-token", get(auth::handler::get_proxy_token))
		.route("/api/auth/password", post(auth::handler::post_password))
		.route("/api/auth/vapid", get(push::handler::get_vapid_public_key))

		// --- Onboarding completion (authenticated) ---
		// Single commit point of the reversible onboarding wizard: consumes the
		// welcome ref (left intact by post_set_password) to retire the link.
		.route("/api/onboarding/complete", post(auth::handler::post_complete_onboarding))

		// --- QR Login (Protected) ---
		.route("/api/auth/qr-login/{session_id}/details", get(auth::qr_login::get_details))
		.route("/api/auth/qr-login/{session_id}/respond", post(auth::qr_login::post_respond))

		// --- WebAuthn (Passkey) Management ---
		.route("/api/auth/wa/reg", get(auth::webauthn::list_reg))
		.route("/api/auth/wa/reg/challenge", get(auth::webauthn::get_reg_challenge))
		.route("/api/auth/wa/reg", post(auth::webauthn::post_reg))
		.route("/api/auth/wa/reg/{key_id}", delete(auth::webauthn::delete_reg))

		// --- API Key Management ---
		.route("/api/auth/api-keys", get(auth::api_key::list_api_keys))
		.route("/api/auth/api-keys", post(auth::api_key::create_api_key))
		.route("/api/auth/api-keys/{key_id}", get(auth::api_key::get_api_key))
		.route("/api/auth/api-keys/{key_id}", patch(auth::api_key::update_api_key))
		.route("/api/auth/api-keys/{key_id}", delete(auth::api_key::delete_api_key))

		// --- Settings API ---
		.route("/api/settings", get(settings::handler::list_settings))
		.route("/api/settings/{name}", get(settings::handler::get_setting))
		.route("/api/settings/{name}", put(settings::handler::update_setting))
		.route("/api/settings/{name}", delete(settings::handler::delete_setting))

		// --- Reference API ---
		.route("/api/refs", get(r#ref::handler::list_refs))
		.route("/api/refs", post(r#ref::handler::create_ref))
		.route("/api/refs/{ref_id}", patch(r#ref::handler::update_ref))
		.route("/api/refs/{ref_id}", delete(r#ref::handler::delete_ref))

		// --- Own Profile Management ---
		.route("/api/me", patch(profile::update::patch_own_profile))
		// Profile/cover images are buffered whole into memory (`Bytes`).
		.route(
			"/api/me/image",
			put(profile::media::put_profile_image).layer(upload_body_limit()),
		)
		.route("/api/me/cover", put(profile::media::put_cover_image).layer(upload_body_limit()))
		.route("/api/profiles", get(profile::list::list_profiles))

		// --- IDP Onboarding Gate (verify-idp) ---
		// Pull-on-demand IDP identity status + activation-email resend.
		// Active only during onboarding (ui.onboarding === 'verify-idp');
		// once cleared, no client should be calling these.
		.route(
			"/api/profiles/me/idp-status",
			get(profile::idp_status::get_me_idp_status),
		)
		.route(
			"/api/profiles/me/resend-activation",
			post(profile::idp_status::post_me_resend_activation),
		)

		// --- Community Profile Creation ---
		.route("/api/profiles/{id_tag}", put(profile::community::put_community_profile))

		// --- Explicit Profile Mirror Refresh ---
		// Forces an immediate re-sync of the caller's local mirror of {id_tag},
		// bypassing the scheduled staleness/abandonment window. Auth-only: the
		// handler checks the caller already tracks {id_tag} before refreshing
		// (mirrors the /api/files/{file_id}/refresh precedent).
		.route("/api/profiles/{id_tag}/refresh", post(profile::update::post_profile_refresh))

		// --- Read Markers (auth-only, reader's own node, forward-only) ---
		.route("/api/read-marker", put(action::handler::put_read_marker))

		// --- Thread Subscription Level (auth-only, reader's own cached row) ---
		.route("/api/actions/{action_id}/subscribe", put(action::handler::put_action_subscribe))

		// --- Action API (Create + Write) ---
		.merge(action_router_create)
		.merge(action_router_write)

		// --- Federation History Sync (peer-initiated pull) ---
		// Auth is enforced by the `Auth` extractor; non-related peers are rejected
		// with an empty list inside the handler before any action query runs.
		.route("/api/outbox", get(action::handler::get_outbox))

		// --- Profile API (Permission-Checked) ---
		// Note: All profile routes require auth (check_perm_profile uses Auth, not OptionalAuth)
		.merge(profile_router_read)
		.merge(profile_router_write)
		.merge(profile_router_admin)
		.merge(admin_tenant_router)

		// --- File API (Create + Write + Trash + User Data) ---
		.merge(file_router_create)
		.merge(file_router_write)
		.merge(trash_router)
		.merge(file_user_router)

		// --- App Store (Install/Uninstall) ---
		.merge(app_management_router)

		// --- Share Entry Queries ---
		.route("/api/shares", get(file::share::list_shares_by_subject))

		// --- File Share Management ---
		.route("/api/files/{file_id}/shares", get(file::share::list_shares))
		.route("/api/files/{file_id}/shares", post(file::share::create_share))
		.route(
			"/api/files/{file_id}/shares/{share_id}",
			delete(file::share::delete_share).patch(file::share::update_share),
		)

		// --- Tag API ---
		.route("/api/tags", get(file::tag::list_tags))

		// --- IDP Management ---
		.route("/api/idp/identities", get(idp::handler::list_identities))
		.route("/api/idp/identities", post(idp::handler::create_identity))
		.route("/api/idp/identities/{identity_id}", get(idp::handler::get_identity_by_id))
		.route("/api/idp/identities/{identity_id}", delete(idp::handler::delete_identity))
		.route("/api/idp/identities/{identity_id}", patch(idp::handler::update_identity_settings))
		.route("/api/idp/identities/{identity_id}/address", put(idp::handler::update_identity_address))
		// --- IDP Onboarding-Gate Endpoints (issuer-match auth) ---
		// Live status + activation-email resend, called by tenant homes via
		// proxy-token-authenticated DNS-discovered HTTP. Issuer must match
		// the requested identity.
		.route(
			"/api/idp/identities/{identity_id}/status",
			get(idp::handler::get_identity_status),
		)
		.route(
			"/api/idp/identities/{identity_id}/resend",
			post(idp::handler::resend_identity_activation),
		)

		// --- IDP API Key Management ---
		.route("/api/idp/api-keys", post(idp::api_keys::create_api_key))
		.route("/api/idp/api-keys", get(idp::api_keys::list_api_keys))
		.route("/api/idp/api-keys/{api_key_id}", get(idp::api_keys::get_api_key))
		.route("/api/idp/api-keys/{api_key_id}", delete(idp::api_keys::delete_api_key))

		// --- Push Notification Management ---
		.route("/api/notifications/subscription", post(push::handler::post_subscription))
		.route("/api/notifications/subscription/{subscription_id}", delete(push::handler::delete_subscription))

		// --- Address Books / Contacts (CardDAV sync lives under /dav/... elsewhere) ---
		.route("/api/address-books", get(contact::handler::list_address_books))
		.route("/api/address-books", post(contact::handler::create_address_book))
		.route("/api/address-books/{ab_id}", patch(contact::handler::patch_address_book))
		.route("/api/address-books/{ab_id}", delete(contact::handler::delete_address_book))
		.route("/api/contacts", get(contact::handler::list_all_contacts))
		.route("/api/address-books/{ab_id}/contacts", get(contact::handler::list_contacts))
		// Contacts and vCard imports may embed photos / many cards (> 1 MiB).
		.route(
			"/api/address-books/{ab_id}/contacts",
			post(contact::handler::create_contact).layer(upload_body_limit()),
		)
		.route(
			"/api/address-books/{ab_id}/import",
			post(contact::handler::import_contacts).layer(upload_body_limit()),
		)
		.route("/api/address-books/{ab_id}/contacts/{uid}", get(contact::handler::get_contact))
		.route(
			"/api/address-books/{ab_id}/contacts/{uid}",
			put(contact::handler::put_contact).layer(upload_body_limit()),
		)
		.route(
			"/api/address-books/{ab_id}/contacts/{uid}",
			patch(contact::handler::patch_contact).layer(upload_body_limit()),
		)
		.route("/api/address-books/{ab_id}/contacts/{uid}", delete(contact::handler::delete_contact))

		// --- Calendars / Events (CalDAV sync lives under /dav/... elsewhere) ---
		.route("/api/calendars", get(calendar::handler::list_calendars))
		.route("/api/calendars", post(calendar::handler::create_calendar))
		.route("/api/calendars/{cal_id}", get(calendar::handler::get_calendar))
		.route("/api/calendars/{cal_id}", patch(calendar::handler::patch_calendar))
		.route("/api/calendars/{cal_id}", delete(calendar::handler::delete_calendar))
		.route("/api/calendars/{cal_id}/objects", get(calendar::handler::list_objects))
		.route("/api/calendars/{cal_id}/objects", post(calendar::handler::create_object))
		.route("/api/calendars/{cal_id}/objects/{uid}", get(calendar::handler::get_object))
		.route("/api/calendars/{cal_id}/objects/{uid}", put(calendar::handler::put_object))
		.route("/api/calendars/{cal_id}/objects/{uid}", patch(calendar::handler::patch_object))
		.route("/api/calendars/{cal_id}/objects/{uid}", delete(calendar::handler::delete_object))
		.route("/api/calendars/{cal_id}/objects/{uid}/split", post(calendar::handler::split_series))
		.route("/api/calendars/{cal_id}/objects/{uid}/exceptions", get(calendar::handler::list_exceptions))
		.route("/api/calendars/{cal_id}/objects/{uid}/exceptions/{recurrence_id}", get(calendar::handler::get_exception))
		.route("/api/calendars/{cal_id}/objects/{uid}/exceptions/{recurrence_id}", put(calendar::handler::put_exception))
		.route("/api/calendars/{cal_id}/objects/{uid}/exceptions/{recurrence_id}", patch(calendar::handler::patch_exception))
		.route("/api/calendars/{cal_id}/objects/{uid}/exceptions/{recurrence_id}", delete(calendar::handler::delete_exception))

		.route_layer(middleware::from_fn_with_state(app, require_auth))
		.layer(SetResponseHeaderLayer::if_not_present(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store, no-cache")))
		.layer(SetResponseHeaderLayer::if_not_present(header::EXPIRES, header::HeaderValue::from_static("0")))
}

// ============================================================================
// PUBLIC ROUTES - Accessible without authentication
// optional_auth attempts token validation but doesn't require it
// ============================================================================
fn init_public_routes(app: App) -> Router<App> {
	// --- Permission-Checked Routes (ABAC with guest context) ---
	// These routes allow public access but check visibility attributes
	// Note: Only action/file use OptionalAuth (guest context) - profile requires auth

	// Action read routes (check_perm_action("read")) - uses OptionalAuth
	let action_router_read = Router::new()
		.route("/api/actions/{action_id}", get(action::handler::get_action_by_id))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_action("read")));

	// File read routes (check_perm_file("read")) - uses OptionalAuth
	let file_router_read = Router::new()
		.route("/api/files/variant/{variant_id}", get(file::handler::get_file_variant))
		.route("/api/files/{file_id}/descriptor", get(file::handler::get_file_descriptor))
		.route("/api/files/{file_id}/metadata", get(file::handler::get_file_metadata))
		.route("/api/files/{file_id}", get(file::handler::get_file_variant_file_id))
		.layer(middleware::from_fn_with_state(app.clone(), check_perm_file("read")));

	// --- CRITICAL: Authentication Endpoints (strict rate limiting) ---
	// Attack surface: credential stuffing, brute force, account enumeration
	let auth_public_router = Router::new()
		.route("/api/auth/login", post(auth::handler::post_login))
		.route("/api/auth/login-token", get(auth::handler::get_login_token))
		// WebAuthn login endpoints
		.route("/api/auth/wa/login/challenge", get(auth::webauthn::get_login_challenge))
		.route("/api/auth/wa/login", post(auth::webauthn::post_login))
		// QR login init (public endpoint, kept for manual refresh)
		.route("/api/auth/qr-login/init", post(auth::qr_login::post_init))
		// QR login status (long-poll)
		.route("/api/auth/qr-login/{session_id}/status", get(auth::qr_login::get_status))
		.layer(RateLimitLayer::new(app.rate_limiter.clone(), "auth", app.opts.mode));

	// --- CRITICAL: Profile Creation Endpoints (strict rate limiting) ---
	// Attack surface: account enumeration, spam registration
	let profile_creation_router = Router::new()
		.route("/api/profiles/register", post(profile::register::post_register))
		.route("/api/profiles/verify", post(profile::register::post_verify_profile))
		.layer(RateLimitLayer::new(app.rate_limiter.clone(), "auth", app.opts.mode));

	// --- Token Exchange (federation rate limiting) ---
	// access-token is called in batches during federation, needs higher limits than auth
	let token_exchange_router = Router::new()
		.route("/api/auth/access-token", get(auth::handler::get_access_token))
		.layer(RateLimitLayer::new(app.rate_limiter.clone(), "federation", app.opts.mode));

	// --- CRITICAL: Federation Inbox (moderate rate limiting) ---
	// Attack surface: spam, malicious payloads, resource exhaustion
	// Inbox payloads carry signed action tokens plus their related tokens; a
	// thread backfill can exceed the 1 MiB global cap, so raise it here.
	let federation_router = Router::new()
		.route("/api/inbox", post(action::handler::post_inbox))
		.route("/api/inbox/sync", post(action::handler::post_inbox_sync))
		.layer(upload_body_limit())
		.layer(RateLimitLayer::new(app.rate_limiter.clone(), "federation", app.opts.mode));

	// --- WebSocket Endpoints (separate rate limiting) ---
	// Attack surface: connection exhaustion, message flooding
	let websocket_router = Router::new()
		.route("/ws/bus", any(websocket::get_ws_bus))
		.route("/ws/rtdb/{file_id}", any(websocket::get_ws_rtdb))
		.route("/ws/crdt/{doc_id}", any(websocket::get_ws_crdt))
		.layer(RateLimitLayer::new(app.rate_limiter.clone(), "websocket", app.opts.mode));

	// --- Ref-Scoped Resend (auth bucket) ---
	// Sends an activation email on every call — gets the same tight bucket as
	// other email-sending unauthenticated endpoints (forgot-password etc.).
	// Per-tenant cooldown inside the handler stops same-tenant abuse from
	// rotated IPs; the auth bucket stops same-IP abuse against many tenants.
	let resend_activation_router = Router::new()
		.route(
			"/api/refs/{ref_id}/resend-activation",
			post(profile::idp_status::post_ref_resend_activation),
		)
		.layer(RateLimitLayer::new(app.rate_limiter.clone(), "auth", app.opts.mode));

	// --- General Public API (relaxed rate limiting) ---
	// Read-only endpoints with visibility-based access control
	let general_public_router = Router::new()
		// Tenant Discovery
		.route("/api/me", get(profile::handler::get_tenant_profile_base))
		.route("/api/me/app-domain", get(profile::handler::get_tenant_app_domain))

		// Ref-scoped IDP onboarding gate (read-only status check)
		// Gates the unauthenticated welcome (set-password) page on IDP
		// activation. The refId is the credential — same trust model as the
		// existing `/api/refs/{ref_id}` lookup and `/api/auth/set-password`.
		// The companion resend route is on its own tighter bucket above.
		.route(
			"/api/refs/{ref_id}/idp-status",
			get(profile::idp_status::get_ref_idp_status),
		)

		// IDP Discovery and Activation
		.route("/api/idp/info", get(idp::handler::get_idp_info))
		.route("/api/idp/check-availability", get(idp::handler::check_identity_availability))
		.route("/api/idp/activate", post(idp::handler::activate_identity))

		// Content with Visibility Checks (uses OptionalAuth/guest context)
		.route("/api/actions", get(action::handler::list_actions))
		.merge(action_router_read)
		.route("/api/files", get(file::handler::get_file_list))
		.merge(file_router_read)

		// App Discovery and Container Content
		.route("/api/apps", get(file::apkg::list_apps))
		.route("/api/files/{file_id}/content/{*path}", get(file::apkg::get_container_content))
		.layer(RateLimitLayer::new(app.rate_limiter.clone(), "general", app.opts.mode));

	// --- Recovery flow (auth bucket, ban bypassed) ---
	// A failed-login auto-ban must NOT lock a user out of account recovery.
	// These keep the strict "auth" rate limit (429) but skip the 403 ban:
	// set-password/forgot-password are gated by the secret ref token / per-tenant
	// app-level cap; login-init exposes only a login challenge. POST /api/auth/login
	// stays fully ban-enforced above.
	let recovery_auth_router = Router::new()
		.route("/api/auth/login-init", post(auth::handler::post_login_init))
		.route("/api/auth/set-password", post(auth::handler::post_set_password))
		.route("/api/auth/forgot-password", post(auth::handler::post_forgot_password))
		.layer(RateLimitLayer::new_skip_ban(app.rate_limiter.clone(), "auth", app.opts.mode));

	// --- Recovery flow (general bucket, ban bypassed) ---
	// Reset page loads ref data + profile display; no secrets exposed.
	let recovery_general_router = Router::new()
		.route("/api/refs/{ref_id}", get(r#ref::handler::get_ref))
		.route("/api/me/full", get(profile::handler::get_tenant_profile))
		.layer(RateLimitLayer::new_skip_ban(app.rate_limiter.clone(), "general", app.opts.mode));

	Router::new()
		.merge(auth_public_router)
		.merge(profile_creation_router)
		.merge(resend_activation_router)
		.merge(token_exchange_router)
		.merge(federation_router)
		.merge(websocket_router)
		.merge(general_public_router)
		.merge(recovery_auth_router)
		.merge(recovery_general_router)
		.route_layer(middleware::from_fn_with_state(app, optional_auth))
		.layer(SetResponseHeaderLayer::if_not_present(
			header::CACHE_CONTROL,
			header::HeaderValue::from_static("no-store, no-cache"),
		))
		.layer(SetResponseHeaderLayer::if_not_present(
			header::EXPIRES,
			header::HeaderValue::from_static("0"),
		))
}

// ============================================================================
// CARDDAV ROUTES - HTTP Basic auth with scoped API tokens, never passwords
// Clients: macOS Contacts, Thunderbird, iOS, DAVx5, Nextcloud clients, etc.
// ============================================================================
fn init_dav_routes(app: App) -> Router<App> {
	use axum::http::HeaderName;

	// The /.well-known/* redirects must stay unauthenticated — CardDAV / CalDAV clients
	// probe them without credentials and expect a 301 back, not a 401 challenge.
	let well_known = Router::new()
		.route("/.well-known/carddav", any(contact::carddav::well_known))
		.route("/.well-known/caldav", any(calendar::caldav::well_known));

	let rate_limiter = app.rate_limiter.clone();
	let mode = app.opts.mode;
	let dav = Router::new()
		.route("/dav/principal/", any(contact::carddav::handle_principal))
		.route("/dav/addressbooks/", any(contact::carddav::handle_home))
		.route("/dav/addressbooks/{ab_name}/", any(contact::carddav::handle_collection))
		.route("/dav/addressbooks/{ab_name}/{resource}", any(contact::carddav::handle_resource))
		.route("/dav/calendars/", any(calendar::caldav::handle_home))
		.route("/dav/calendars/{cal_name}/", any(calendar::caldav::handle_collection))
		.route("/dav/calendars/{cal_name}/{resource}", any(calendar::caldav::handle_resource))
		.route_layer(middleware::from_fn_with_state(app, cloudillo_dav::dav_basic_auth))
		// Basic-auth brute-force protection on its own bucket. The "auth" bucket is tuned
		// for login/register bursts and is far too tight for real DAV sync traffic —
		// DAVx5 fires PROPFIND/REPORT per collection per sync cycle.
		.layer(RateLimitLayer::new(rate_limiter, "dav", mode))
		// DAV discovery hinges on the `DAV:` response header on OPTIONS — force it onto every
		// response from the DAV router so no middleware or handler quirk can drop it.
		// `if_not_present` means handlers can still customize the value.
		.layer(SetResponseHeaderLayer::if_not_present(
			HeaderName::from_static("dav"),
			HeaderValue::from_static("1, 2, 3, addressbook, calendar-access"),
		));

	well_known.merge(dav)
}

// ============================================================================
// API SERVICE - Aggregates protected and public routes with global middleware
// ============================================================================
async fn api_not_found() -> Error {
	Error::NotFound
}

fn init_api_service(app: App) -> Router {
	let cors_layer = tower_http::cors::CorsLayer::very_permissive();

	// Browser-facing routes get the permissive CORS layer.
	let browser_routes = init_public_routes(app.clone())
		.merge(init_protected_routes(app.clone()))
		.layer(cors_layer);

	// DAV routes stay OUTSIDE CorsLayer: tower-http 0.6 treats every OPTIONS request as a
	// CORS preflight and short-circuits it with only CORS headers, stripping the `DAV:`
	// capability header that DAV clients need for discovery. These routes aren't called
	// from browsers anyway, so they don't need CORS.
	let router = browser_routes
		.merge(init_dav_routes(app.clone()))
		.fallback(api_not_found)
		.layer(middleware::from_fn(request_id_middleware))
		// Compress only an allowlist of text-based, genuinely-compressible media
		// types (default-deny — see `is_compressible_media_type`). SVG and other
		// text/structured types (HTML/JSON/JS/XML/wasm/`+json`/`+xml`) ARE
		// compressed on full (`200`) responses. When tower-http compresses, it
		// drops both `Accept-Ranges` and `Content-Length` and switches the body to
		// chunked `Content-Encoding` — so a compressed full response is simply not
		// range-advertised; there is no stale `Content-Length` and no broken range.
		//
		// Binary file blobs (`serve_file` emits octet-stream / video|audio/* / pdf /
		// non-svg image), archives and any unknown binary are NOT on the list →
		// left uncompressed so the headers `serve_file` sets survive. This:
		// (1) preserves `Content-Length` for the browser download-progress bar and
		// the shell SW's `/cl-download` stream that forwards the length, and
		// (2) avoids wasting CPU re-compressing already-compressed media.
		//
		// Range/seek: `get_file_variant{,_file_id}` answer a `Range` request with
		// `206`/`Content-Range`/`Accept-Ranges`. tower-http does NOT strip
		// `Content-Range` and does NOT skip `206` itself, so a compressed `206`
		// would carry a now-wrong `Content-Range` over a re-encoded body. The
		// predicate therefore vetoes ALL `206` partial responses → range/seek stays
		// uncompressed with intact `Content-Length`/`Content-Range`/`Accept-Ranges`.
		//
		// `SizeAbove(32)` mirrors `DefaultPredicate`'s tiny-body floor; the rest of
		// the gating lives in `is_compressible_media_type` so the policy is
		// self-contained (we no longer use `DefaultPredicate`, whose blanket
		// `image/*` exclusion would have kept SVG uncompressed).
		//
		// `.quality(Precise(4))` keeps on-the-fly compression cheap: tower-http
		// prefers zstd > br > gzip, so modern clients get zstd (level 4, fast,
		// dynamic-appropriate); the rare br-only client gets brotli q4 instead of
		// the q11 default (which is a slow static-precompression level); gzip
		// fallback at level 4. (Static JS/CSS are unaffected — they are served
		// pre-compressed by `ServeDir::precompressed_br()/_gzip()`, not here.)
		.layer(
			CompressionLayer::new()
				.quality(CompressionLevel::Precise(4))
				.compress_when(SizeAbove::new(32).and(is_compressible_media_type)),
		)
		// Global buffering-extractor body cap. Routes that need more override it
		// inline with `upload_body_limit()` / `DefaultBodyLimit::disable()`.
		.layer(DefaultBodyLimit::max(GLOBAL_BODY_LIMIT))
		.with_state(app);
	with_security_headers(router)
}

// ============================================================================
// DYNAMIC SERVICE WORKER - Serves SW with tenant-specific encryption key
// ============================================================================

/// Encryption key variable name for tenant
const SW_ENCRYPTION_KEY_VAR: &str = "sw_encryption_key";

/// Placeholder in SW template that gets replaced with the actual key
const SW_ENCRYPTION_KEY_PLACEHOLDER: &str = "__CLOUDILLO_SW_ENCRYPTION_KEY__";

/// Check if a path is a service worker file (sw-*.js pattern)
fn is_sw_file(path: &str) -> bool {
	let filename = path.trim_start_matches('/');
	filename.starts_with("sw-")
		&& std::path::Path::new(filename)
			.extension()
			.is_some_and(|ext| ext.eq_ignore_ascii_case("js"))
		&& !filename.contains('/')
}

/// Check if a path is in an app directory (microfrontend assets)
/// Apps are served from /apps/ directory and need CORS for sandboxed iframes
fn is_app_directory(path: &str) -> bool {
	let path = path.trim_start_matches('/');
	path.starts_with("apps/")
}

/// Check if a path is in the fonts directory
/// Fonts need CORS headers for sandboxed iframes (apps have opaque 'null' origin)
fn is_font_file(path: &str) -> bool {
	let path = path.trim_start_matches('/');
	path.starts_with("fonts/")
}

/// Check if a path should receive SPA fallback (serve shell's index.html for client routing)
///
/// Returns false for:
/// - API routes (start with /api/)
/// - WebSocket routes (start with /ws/)
/// - App routes (start with /apps/) - apps run in iframes, use hash fragments
/// - Known static asset directories (/fonts/, /sounds/, /assets-*/)
/// - Root-level files with extensions (e.g., /favicon.ico, /robots.txt)
fn should_serve_spa_fallback(path: &str) -> bool {
	// Never fallback for API routes
	if path.starts_with("/api/") {
		return false;
	}

	// Never fallback for WebSocket routes
	if path.starts_with("/ws/") {
		return false;
	}

	// Never fallback for app assets - apps run in iframes and use hash fragments
	if path.starts_with("/apps/") {
		return false;
	}

	// Never fallback for known static asset directories
	// These should 404 if the file doesn't exist
	if path.starts_with("/fonts/") || path.starts_with("/sounds/") {
		return false;
	}

	// Never fallback for versioned asset directories (pattern: /assets-{version}/)
	// The frontend uses versioned directories like /assets-0.8.6/
	let trimmed = path.trim_start_matches('/');
	if trimmed.starts_with("assets-")
		&& let Some(slash_pos) = trimmed.find('/')
	{
		// Has a slash after "assets-*", so it's a path into a versioned assets directory
		if slash_pos > 7 {
			// "assets-" is 7 chars, need at least one char for version
			return false;
		}
	}

	// Never fallback for root-level files with extensions
	// (e.g., /favicon.ico, /robots.txt, /manifest.json, /sw-0.8.6.js)
	if !trimmed.contains('/') {
		// It's a root-level path - check for file extension
		if let Some(dot_pos) = trimmed.rfind('.') {
			let ext = &trimmed[dot_pos + 1..];
			// Valid file extension: 2-5 alphanumeric chars
			if (2..=5).contains(&ext.len()) && ext.chars().all(|c| c.is_ascii_alphanumeric()) {
				return false;
			}
		}
	}

	// Everything else gets SPA fallback for client-side routing
	// This includes paths like /profile/home.w9.hu/szilard.hajba.eu
	true
}

/// Serve shell's index.html for SPA fallback (client-side routing)
///
/// Only used for shell routes (e.g., /app/feed, /settings) - apps use iframes with hash fragments.
async fn serve_shell_index_html(
	dist_dir: &std::path::Path,
	disable_cache: bool,
	if_none_match: Option<&str>,
) -> ClResult<axum::response::Response> {
	let file_path = dist_dir.join("index.html");

	// Read file metadata for ETag computation (length + mtime)
	let metadata = tokio::fs::metadata(&file_path).await.ok();
	let etag = metadata.as_ref().and_then(|m| {
		let len = m.len();
		let mtime = m.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?;
		Some(format!("\"{}{}\"", len, mtime.as_secs()))
	});

	// Check If-None-Match for conditional response
	if let (Some(etag), Some(inm)) = (&etag, if_none_match) {
		// Strip surrounding quotes and whitespace for comparison
		let inm_trimmed = inm.trim().trim_matches('"');
		let etag_trimmed = etag.trim_matches('"');
		if inm_trimmed == etag_trimmed {
			let cache_value = if disable_cache {
				HeaderValue::from_static("no-store, no-cache")
			} else {
				HeaderValue::from_static("no-cache, must-revalidate")
			};
			return Ok(Response::builder()
				.status(StatusCode::NOT_MODIFIED)
				.header(header::CACHE_CONTROL, cache_value)
				.header(header::ETAG, etag.as_str())
				.body(Body::empty())?);
		}
	}

	match tokio::fs::read(&file_path).await {
		Ok(content) => {
			let cache_value = if disable_cache {
				HeaderValue::from_static("no-store, no-cache")
			} else {
				// HTML files: ETag-only, must revalidate on every request
				HeaderValue::from_static("no-cache, must-revalidate")
			};

			let mut builder = Response::builder()
				.status(StatusCode::OK)
				.header(header::CONTENT_TYPE, "text/html; charset=utf-8")
				.header(header::CACHE_CONTROL, cache_value);
			if let Some(etag) = &etag {
				builder = builder.header(header::ETAG, etag.as_str());
			}
			Ok(builder.body(Body::from(content))?)
		}
		Err(_) => {
			// Shell index.html doesn't exist - critical deployment error
			Ok(Response::builder()
				.status(StatusCode::NOT_FOUND)
				.header(header::CONTENT_TYPE, "text/plain")
				.body(Body::from("Not Found"))?)
		}
	}
}

/// Serve the service worker with tenant-specific encryption key embedded
/// Key is only injected if:
/// 1. Service-Worker: script header is present (browser sets this, JS cannot fake it)
/// 2. Key in URL query matches the tenant's stored key
async fn serve_dynamic_sw(
	app: &App,
	sw_file: &str,
	host: &str,
	headers: &HeaderMap,
	query: Option<&str>,
) -> Result<Response, Error> {
	// 1. Check for Service-Worker header (browser sets this automatically, JS cannot fake it)
	let sw_header = headers.get("Service-Worker").and_then(|v| v.to_str().ok());
	let is_sw_registration = sw_header.is_some_and(|v| v == "script");
	info!("[SW] Service-Worker header: {:?}, is_registration: {}", sw_header, is_sw_registration);

	// 2. Extract key from query string (URL-safe base64, no decoding needed)
	let provided_key = query
		.and_then(|q| q.split('&').find(|p| p.starts_with("key=")).map(|p| p[4..].to_string()));
	info!(
		"[SW] Query: {:?}, provided_key: {:?}",
		query,
		provided_key.as_ref().map(|k| &k[..8.min(k.len())])
	);

	// 3. Determine if we should inject the key
	let should_inject_key = if is_sw_registration {
		if let Some(ref key) = provided_key {
			// Look up tenant and validate key
			match app.auth_adapter.read_cert_by_domain(host).await {
				Ok(cert_data) => {
					let tn_id = cert_data.tn_id;
					info!("[SW] Found tenant {} for host {}", tn_id.0, host);
					match app.auth_adapter.read_var(tn_id, SW_ENCRYPTION_KEY_VAR).await {
						Ok(stored_key) => {
							let matches = &*stored_key == key;
							info!(
								"[SW] Key validation: stored={}, provided={}, matches={}",
								&stored_key[..8.min(stored_key.len())],
								&key[..8.min(key.len())],
								matches
							);
							matches
						}
						Err(e) => {
							warn!("[SW] Failed to read stored key: {:?}", e);
							false
						}
					}
				}
				Err(e) => {
					warn!("[SW] Failed to lookup tenant for host {}: {:?}", host, e);
					false
				}
			}
		} else {
			false
		}
	} else {
		false
	};

	// 4. Read sw.js template — all versioned sw-*.js URLs map to the same file on disk
	info!("[SW] Serving sw.js for requested {}", sw_file);
	let sw_path = app.opts.dist_dir.join("sw.js");
	let sw_content = tokio::fs::read_to_string(&sw_path).await.map_err(|e| {
		warn!("Failed to read SW template {}: {}", sw_path.display(), e);
		Error::NotFound
	})?;

	// 5. Conditionally inject the key
	let modified_content = match (should_inject_key, provided_key.as_ref()) {
		(true, Some(key)) => {
			info!("Serving SW with encryption key for authenticated registration");
			sw_content.replace(SW_ENCRYPTION_KEY_PLACEHOLDER, key)
		}
		_ => sw_content,
	};

	// Build response with appropriate headers
	Ok(Response::builder()
		.status(StatusCode::OK)
		.header(header::CONTENT_TYPE, "application/javascript; charset=utf-8")
		.header(header::CACHE_CONTROL, "private, no-store, no-cache")
		.header(header::EXPIRES, "0")
		.body(Body::from(modified_content))?)
}

/// Fallback handler for static files with SW interception
async fn static_fallback_handler(
	State(app): State<App>,
	request: Request<Body>,
) -> axum::response::Response {
	let path = request.uri().path();
	let query = request.uri().query();
	let disable_cache = app.opts.disable_cache;

	// Check if this is a service worker request (sw-*.js)
	if is_sw_file(path) {
		// Extract host from request
		let host = request
			.uri()
			.host()
			.or_else(|| {
				request
					.headers()
					.get(header::HOST)
					.and_then(|h| h.to_str().ok())
					.map(|h| h.split(':').next().unwrap_or(h))
			})
			.unwrap_or_default();

		let sw_file = path.trim_start_matches('/');
		let headers = request.headers();

		// Try to serve dynamic SW, fall back to static if it fails
		match serve_dynamic_sw(&app, sw_file, host, headers, query).await {
			Ok(response) => return response,
			Err(e) => {
				warn!("Failed to serve dynamic SW {}: {:?}, falling back to static", sw_file, e);
				// Fall through to static file serving
			}
		}
	}

	// Check if this is an app directory or font (need CORS for sandboxed iframes)
	let needs_cors = is_app_directory(path) || is_font_file(path);

	// Store path for potential SPA fallback (request is moved by serve_dir.call)
	let path_owned = path.to_string();

	// Extract If-None-Match before request is consumed (needed for SPA fallback ETag)
	let if_none_match = request
		.headers()
		.get(header::IF_NONE_MATCH)
		.and_then(|v| v.to_str().ok())
		.map(ToString::to_string);

	// Serve static files - NO unconditional fallback; we handle 404s manually
	let dist_dir = &app.opts.dist_dir;
	let mut serve_dir = ServeDir::new(dist_dir).precompressed_gzip().precompressed_br();

	let response = match serve_dir.call(request).await {
		Ok(resp) => resp,
		Err(infallible) => match infallible {},
	};

	// Check if file was not found - apply smart SPA fallback
	if response.status() == StatusCode::NOT_FOUND {
		// Only serve shell's index.html for client routes (not API, WS, apps, or files with extensions)
		if should_serve_spa_fallback(&path_owned) {
			return serve_shell_index_html(dist_dir, disable_cache, if_none_match.as_deref())
				.await
				.unwrap_or_else(IntoResponse::into_response);
		}
		// Otherwise return the 404 as-is
		return response.map(Body::new);
	}

	let mut response = response;

	// Determine cache policy based on content type
	let cache_value = if disable_cache {
		HeaderValue::from_static("no-store, no-cache")
	} else {
		// Check content type to determine cache policy
		let is_html = response
			.headers()
			.get(header::CONTENT_TYPE)
			.and_then(|v| v.to_str().ok())
			.is_some_and(|ct| ct.starts_with("text/html"));

		if is_sw_file(&path_owned) {
			// SW files must never be long-cached even via static fallback
			HeaderValue::from_static("private, no-store, no-cache")
		} else if is_html {
			// index.html: ETag-only, must revalidate on every request
			HeaderValue::from_static("no-cache, must-revalidate")
		} else {
			// Assets (JS, CSS, images): long cache with immutable
			HeaderValue::from_static("public, max-age=31536000, immutable")
		}
	};

	response.headers_mut().insert(header::CACHE_CONTROL, cache_value);

	// Add CORS headers for app directories and fonts (sandboxed iframes have opaque 'null' origin)
	if needs_cors {
		response
			.headers_mut()
			.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
	}

	response.map(Body::new)
}

fn init_app_service(app: App) -> Router {
	let ws_router = Router::new()
		.route("/ws/bus", any(websocket::get_ws_bus))
		.route("/ws/rtdb/{file_id}", any(websocket::get_ws_rtdb))
		.route("/ws/crdt/{doc_id}", any(websocket::get_ws_crdt))
		.route_layer(middleware::from_fn_with_state(app.clone(), optional_auth));

	// Add CORS layer only to the id-tag discovery endpoint
	let well_known_router = Router::new()
		.route("/.well-known/cloudillo/id-tag", get(auth::handler::get_id_tag))
		// CardDAV / CalDAV discovery redirects to the API domain's /dav/principal/ — mounted
		// here so clients probing the app domain (what users actually type) can find it.
		.route("/.well-known/carddav", any(contact::carddav::well_known))
		.route("/.well-known/caldav", any(calendar::caldav::well_known))
		.layer(tower_http::cors::CorsLayer::very_permissive());

	let router = Router::new()
		.merge(well_known_router)
		.merge(ws_router)
		.fallback(static_fallback_handler)
		.with_state(app);
	with_security_headers(router)
}

fn init_http_service(app: App) -> Router {
	Router::new()
		.route("/test", get(async || "test\n"))
		.route("/.well-known/acme-challenge/{token}", get(acme::get_acme_challenge))
		.with_state(app)
}

pub fn init(app: App) -> (Router, Router, Router) {
	(init_api_service(app.clone()), init_app_service(app.clone()), init_http_service(app))
}

#[cfg(test)]
mod tests {
	use super::is_compressible_media_type;
	use axum::http::{Extensions, HeaderMap, StatusCode, Version, header};

	/// Run `is_compressible_media_type` for a given content-type header value at
	/// `200 OK`. `None` means no `content-type` header is set at all.
	fn check(content_type: Option<&str>) -> bool {
		check_status(StatusCode::OK, content_type)
	}

	/// As [`check`], but for an arbitrary response status (covers the 206 path).
	fn check_status(status: StatusCode, content_type: Option<&str>) -> bool {
		let mut headers = HeaderMap::new();
		if let Some(ct) = content_type {
			headers.insert(header::CONTENT_TYPE, ct.parse().unwrap());
		}
		is_compressible_media_type(status, Version::HTTP_11, &headers, &Extensions::default())
	}

	#[test]
	fn compressible_text_and_structured_types() {
		assert!(check(Some("text/html")));
		assert!(check(Some("text/html; charset=utf-8")));
		assert!(check(Some("text/plain")));
		assert!(check(Some("application/json")));
		assert!(check(Some("application/javascript")));
		assert!(check(Some("application/xml")));
		assert!(check(Some("application/xhtml+xml")));
		assert!(check(Some("application/wasm")));
		// `+json` / `+xml` suffix arms.
		assert!(check(Some("application/manifest+json")));
		// `image/svg+xml` matches the `+xml` arm and IS now actually compressed on
		// full (`200`) responses (we no longer use `DefaultPredicate`'s `image/*`
		// exclusion — see the layer comment).
		assert!(check(Some("image/svg+xml")));
	}

	#[test]
	fn non_compressible_binary_types() {
		assert!(!check(Some("application/octet-stream")));
		assert!(!check(Some("video/mp4")));
		assert!(!check(Some("audio/mpeg")));
		assert!(!check(Some("application/pdf")));
		assert!(!check(Some("image/png")));
		// Missing / empty content-type → not compressible.
		assert!(!check(None));
		assert!(!check(Some("")));
	}

	#[test]
	fn never_compress_sse_or_partial_responses() {
		// SSE must stay unbuffered/uncompressed even though it matches `text/`.
		assert!(!check(Some("text/event-stream")));
		// A 206 partial is never compressed, even for a normally-compressible type.
		assert!(!check_status(StatusCode::PARTIAL_CONTENT, Some("text/html")));
	}
}

// vim: ts=4
