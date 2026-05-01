// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! `on_first_cert_issued` hook — flushes the deferred welcome email after
//! ACME issues the tenant's first certificate.

use crate::prelude::*;
use crate::register::{PENDING_WELCOME_EMAIL_SETTING, PendingWelcomeEmail, send_welcome_email};

/// Read the pending-welcome-email marker for `tn_id`, mint a fresh welcome
/// ref, queue the email, then clear the marker. Idempotent: if the setting
/// is missing we silently no-op so duplicate hook firings don't double-send.
///
/// idempotent: dedupes via the `welcome:{tn_id}` scheduler key plus the
/// PENDING_WELCOME_EMAIL_SETTING marker — the bootstrap and
/// AcmeEarlyRetryTask can both fire `OnFirstCertIssuedFn` for the same
/// tenant after a process restart, and this function must tolerate it.
pub async fn flush_deferred_welcome_email(
	app: &cloudillo_core::app::App,
	tn_id: TnId,
	id_tag: &str,
) -> ClResult<()> {
	let Some(json) = app.meta_adapter.read_setting(tn_id, PENDING_WELCOME_EMAIL_SETTING).await?
	else {
		return Ok(());
	};

	let pending: PendingWelcomeEmail = match serde_json::from_value(json) {
		Ok(p) => p,
		Err(e) => {
			warn!(error = %e, tn_id = ?tn_id,
				"Failed to deserialize pending welcome email; clearing setting");
			let _ = app
				.meta_adapter
				.update_setting(tn_id, PENDING_WELCOME_EMAIL_SETTING, None)
				.await;
			return Ok(());
		}
	};

	// Sanity check — the hook receives `(tn_id, id_tag)` from the caller
	// (bootstrap / AcmeEarlyRetryTask) and the persisted marker carries the
	// same id_tag; a mismatch would mean the marker was written for a
	// different tenant or the caller resolved the wrong row.
	debug_assert_eq!(id_tag, pending.id_tag.as_str());

	// Schedule first, then clear the marker. `send_welcome_email` calls
	// `schedule_email_task_with_key` with `welcome:{tn_id}` as `custom_key`,
	// which dedupes on the scheduler side — so a retry triggered by a still-
	// present marker is harmless. If clearing fails, the dedup keeps the next
	// firing from double-sending.
	send_welcome_email(
		app,
		tn_id,
		&pending.to,
		&pending.id_tag,
		pending.lang.clone(),
		pending.from_name_override,
		"deferred_welcome_hook",
	)
	.await?;

	if let Err(e) = app
		.meta_adapter
		.update_setting(tn_id, PENDING_WELCOME_EMAIL_SETTING, None)
		.await
	{
		warn!(error = %e, tn_id = ?tn_id,
			"Welcome email scheduled but failed to clear marker; \
			 dedup will prevent double-send on retry");
	}

	info!(email = %pending.to, tn_id = ?tn_id, lang = ?pending.lang,
		"Welcome email queued (deferred — first ACME cert issued)");

	Ok(())
}

// vim: ts=4
