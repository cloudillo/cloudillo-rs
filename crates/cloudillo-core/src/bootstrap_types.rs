// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Bootstrap-related types shared between server and feature crates.

/// Options for creating a complete tenant with all necessary setup
pub struct CreateCompleteTenantOptions<'a> {
	pub id_tag: &'a str,
	pub email: Option<&'a str>,
	pub password: Option<&'a str>,
	pub roles: Option<&'a [&'a str]>,
	pub display_name: Option<&'a str>,
	pub create_acme_cert: bool,
	pub acme_email: Option<&'a str>,
	pub app_domain: Option<&'a str>,
	/// Initial value for `ui.onboarding`. Set to `Some("verify-idp")` for
	/// IDP-typed personal/community registrations to gate the user (or
	/// community context) on the IDP activation email being clicked.
	/// Domain-typed registrations and bootstrap should leave this `None`,
	/// which preserves the legacy unset-default behaviour (no onboarding
	/// redirect; the welcome ref-link flow drives the user instead).
	pub initial_onboarding: Option<&'a str>,
}

// vim: ts=4
