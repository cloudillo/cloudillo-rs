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

	// How much of a document attachment's extracted text reaches the index. Every
	// char is stored twice — `search_docs.body` plus the FTS5 entry — which is what
	// the ceiling below is about, not the extraction cost.
	registry.register(
		SettingDefinition::builder("search.index_document_chars")
			.description(
				"Characters of extracted text to index per document (PDF and other document \
				 attachments). Text past this is not searchable; the file is still found by \
				 name and tags. 0 turns document extraction off entirely, and drops the \
				 already-stored text on the next reindex. Raising it re-extracts every \
				 document on the next reindex (POST /api/search/reindex), because the budget \
				 is part of the key the previous extraction is cached under.",
			)
			.default(SettingValue::Int(crate::DEFAULT_DOCUMENT_CHARS))
			.scope(SettingScope::Tenant)
			// Admin, unlike `search.store_text` above, which only ever *shrinks* what is
			// stored. This one multiplies it — up to `MAX_DOCUMENT_CHARS` per PDF, stored
			// twice, with no per-tenant total — and a change re-extracts every PDF in the
			// tenant on the node's worker pool. The cost lands on node disk and node CPU,
			// so the node operator holds the lever. Still `SettingScope::Tenant`: the value
			// is per tenant, only the permission to set it is not.
			.permission(PermissionLevel::Admin)
			.validator(|v| match v {
				SettingValue::Int(i)
					if (crate::MIN_DOCUMENT_CHARS..=crate::MAX_DOCUMENT_CHARS).contains(i) =>
				{
					Ok(())
				}
				_ => Err(Error::ValidationError(format!(
					"Document char budget must be between {} and {}",
					crate::MIN_DOCUMENT_CHARS,
					crate::MAX_DOCUMENT_CHARS
				))),
			})
			.build()?,
	)?;

	Ok(())
}

// vim: ts=4
