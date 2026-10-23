// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Profile signing key rotation / revocation shared by the tenant and admin routes.

use cloudillo_types::auth_adapter::AuthKey;

use crate::prelude::*;

/// New active key; the previous active keys become verify-only.
pub async fn rotate_profile_key(app: &App, tn_id: TnId) -> ClResult<AuthKey> {
	let key = app.auth_adapter.rotate_profile_key(tn_id).await?;
	app.profile_me.invalidate(tn_id);
	Ok(key)
}

/// Stop publishing a key and evict it from this server's key cache, so it stops
/// verifying here at once.
pub async fn revoke_profile_key(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
	key_id: &str,
) -> ClResult<()> {
	app.auth_adapter.revoke_profile_key(tn_id, key_id).await?;
	app.profile_me.invalidate(tn_id);
	app.meta_adapter.delete_profile_public_key(id_tag, key_id).await
}

// vim: ts=4
