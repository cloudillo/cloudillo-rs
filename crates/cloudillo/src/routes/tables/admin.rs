// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! `/api/admin/**` — server-administration surface.
//!
//! Note that **not** every `/api/admin/**` path lives here:
//! `/api/admin/profiles/{idTag}` is in [`super::profile::admin`], because it is
//! gated by `check_perm_profile("admin")` (a per-profile ABAC check) rather than
//! by `require_admin` (the server-wide SADM role). Grep by path, not by module.
//!
//! No method matrix: the single fn here holds every route in the file, so they
//! all share one guard (`require_admin`) and one mount policy.

use axum::{
	Router,
	routing::{get, patch, post},
};

use crate::admin;
use crate::file;
use crate::prelude::*;
use crate::proxy;

/// Server administration — gated by `admin::perm::require_admin`, which checks
/// for the server-wide `SADM` role.
pub(crate) fn tenant() -> Router<App> {
	Router::new()
		.route("/api/admin/tenants", get(admin::tenant::list_tenants))
		.route("/api/admin/tenants/{idTag}", patch(admin::tenant::patch_tenant))
		.route(
			"/api/admin/tenants/{idTag}/password/reset",
			post(admin::tenant::send_password_reset),
		)
		.route("/api/admin/tenants/{idTag}/mfa/reset", post(admin::tenant::reset_mfa))
		.route("/api/admin/tenants/{idTag}/signing-keys/rotations", post(admin::tenant::rotate_key))
		.route(
			"/api/admin/tenants/{idTag}/signing-keys/{keyId}/revoke",
			post(admin::tenant::revoke_key),
		)
		// Handler lives in `cloudillo-file` (admin does not depend on it).
		.route("/api/admin/tenants/{idTag}/export", post(file::export::post_admin_export))
		.route("/api/admin/tenants/{idTag}/suspend", post(admin::tenant::suspend_tenant))
		.route("/api/admin/tenants/{idTag}/resume", post(admin::tenant::resume_tenant))
		.route("/api/admin/tenants/{idTag}/purge", post(admin::tenant::purge_tenant_handler))
		// `Accept: text/csv` switches the answer to a CSV download.
		.route("/api/admin/audit", get(admin::audit::list_audit))
		.route("/api/admin/email/test", post(admin::email::send_test_email))
		.route("/api/admin/certificates", get(admin::cert::get_cert_status))
		.route("/api/admin/db/maintenance", post(admin::maintenance::post_db_maintenance))
		.route("/api/admin/backup", get(admin::backup::get_backup).post(admin::backup::post_backup))
		// Handlers live in `cloudillo-proxy`; kept here to match their URL prefix.
		.route(
			"/api/admin/proxy-sites",
			get(proxy::admin::list_proxy_sites).post(proxy::admin::create_proxy_site),
		)
		.route(
			"/api/admin/proxy-sites/{siteId}",
			get(proxy::admin::get_proxy_site)
				.patch(proxy::admin::update_proxy_site)
				.delete(proxy::admin::delete_proxy_site),
		)
		.route(
			"/api/admin/proxy-sites/{siteId}/renew",
			post(proxy::admin::trigger_cert_renewal),
		)
		.route("/api/admin/community-invites", post(admin::invite::post_invite_community))
}

// vim: ts=4
