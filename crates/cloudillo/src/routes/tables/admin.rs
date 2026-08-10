// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! `/api/admin/**` — server-administration surface.
//!
//! Note that **not** every `/api/admin/**` path lives here:
//! `/api/admin/profiles/{id_tag}` is in [`super::profile::admin`], because it is
//! gated by `check_perm_profile("admin")` (a per-profile ABAC check) rather than
//! by `require_admin` (the server-wide SADM role). Grep by path, not by module.
//!
//! No method matrix: the single fn here holds every route in the file, so they
//! all share one guard (`require_admin`) and one mount policy.

use axum::{
	Router,
	routing::{get, post},
};

use crate::admin;
use crate::prelude::*;
use crate::proxy;

/// Server administration — gated by `admin::perm::require_admin`, which checks
/// for the server-wide `SADM` role.
pub(crate) fn tenant() -> Router<App> {
	Router::new()
		.route("/api/admin/tenants", get(admin::tenant::list_tenants))
		.route(
			"/api/admin/tenants/{id_tag}/password-reset",
			post(admin::tenant::send_password_reset),
		)
		.route("/api/admin/tenants/{id_tag}/purge", post(admin::tenant::purge_tenant_handler))
		.route("/api/admin/email/test", post(admin::email::send_test_email))
		.route("/api/admin/cert-status", get(admin::cert::get_cert_status))
		.route("/api/admin/db-maintenance", post(admin::maintenance::post_db_maintenance))
		// Handlers live in `cloudillo-proxy`; kept here to match their URL prefix.
		.route(
			"/api/admin/proxy-sites",
			get(proxy::admin::list_proxy_sites).post(proxy::admin::create_proxy_site),
		)
		.route(
			"/api/admin/proxy-sites/{site_id}",
			get(proxy::admin::get_proxy_site)
				.patch(proxy::admin::update_proxy_site)
				.delete(proxy::admin::delete_proxy_site),
		)
		.route(
			"/api/admin/proxy-sites/{site_id}/renew-cert",
			post(proxy::admin::trigger_cert_renewal),
		)
		.route("/api/admin/invite-community", post(admin::invite::post_invite_community))
}

// vim: ts=4
