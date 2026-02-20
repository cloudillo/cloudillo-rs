//! Internal service functions for ref management

use crate::prelude::*;
use cloudillo_types::meta_adapter::CreateRefOptions;
use cloudillo_types::types::Timestamp;
use cloudillo_types::utils;

/// Parameters for creating a ref internally
pub struct CreateRefInternalParams<'a> {
	/// The id_tag for constructing the URL
	pub id_tag: &'a str,
	/// Type of reference (e.g., "welcome", "email-verify")
	pub typ: &'a str,
	/// Optional human-readable description
	pub description: Option<&'a str>,
	/// Optional expiration timestamp
	pub expires_at: Option<Timestamp>,
	/// URL path prefix (e.g., "/onboarding/welcome")
	pub path_prefix: &'a str,
	/// Optional resource identifier to store with the ref
	pub resource_id: Option<&'a str>,
	/// Number of uses allowed (default: 1)
	pub count: Option<u32>,
}

/// Internal API function to create a ref programmatically
///
/// This is a helper function for internal use (not an HTTP endpoint).
/// It creates a ref with the given parameters and returns the ref_id and full URL.
///
/// # Arguments
/// * `app` - Application state
/// * `tn_id` - Tenant ID
/// * `params` - Parameters for creating the reference
///
/// # Returns
/// * `ref_id` - The generated reference ID
/// * `url` - The complete URL for the reference
pub async fn create_ref_internal(
	app: &App,
	tn_id: TnId,
	params: CreateRefInternalParams<'_>,
) -> ClResult<(String, String)> {
	// Generate random ref_id
	let ref_id = utils::random_id()?;

	// Create ref options
	let ref_opts = CreateRefOptions {
		typ: params.typ.to_string(),
		description: params.description.map(|s| s.to_string()),
		expires_at: params.expires_at,
		count: Some(params.count.unwrap_or(1)),
		resource_id: params.resource_id.map(|s| s.to_string()),
		access_level: None,
	};

	// Store the reference in database
	app.meta_adapter.create_ref(tn_id, &ref_id, &ref_opts).await.map_err(|e| {
		warn!(
			error = %e,
			tn_id = ?tn_id,
			ref_id = %ref_id,
			typ = %params.typ,
			"Failed to create reference"
		);
		e
	})?;

	// Construct the full URL
	let url = format!("https://{}{}/{}", params.id_tag, params.path_prefix, ref_id);

	info!(
		tn_id = ?tn_id,
		ref_id = %ref_id,
		typ = %params.typ,
		url = %url,
		"Created reference successfully"
	);

	Ok((ref_id, url))
}

// vim: ts=4
