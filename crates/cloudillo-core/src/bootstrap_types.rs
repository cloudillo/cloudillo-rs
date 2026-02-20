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
}

// vim: ts=4
