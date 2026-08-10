// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Search subsystem settings registration

use crate::prelude::*;
use cloudillo_core::settings::types::{
	PermissionLevel, SettingDefinition, SettingScope, SettingValue, SettingsRegistry,
};

/// Register all search settings
pub fn register_settings(registry: &mut SettingsRegistry) -> ClResult<()> {
	// Which of the two FTS indexes a tenant's rows live in. See
	// `crate::reindex::index_stamp` for how a flip is applied.
	registry.register(
		SettingDefinition::builder("search.store_text")
			.description(
				"Store the extracted plain text of documents and actions alongside the search \
				 index. Full-text search works either way; turning this off drops the stored copy \
				 to save disk, at the cost of highlighted result snippets. Changing it requires a \
				 reindex (POST /api/search/reindex).",
			)
			.default(SettingValue::Bool(true))
			.scope(SettingScope::Tenant)
			// Owner / community leader — matches `require_leader` on the prescribed reindex.
			.permission(PermissionLevel::User)
			.build()?,
	)?;

	Ok(())
}

// vim: ts=4
