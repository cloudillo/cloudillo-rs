// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Helpers shared by the adapter test binaries; each binary uses a subset.
#![allow(dead_code, clippy::expect_used)]

use cloudillo_meta_adapter_sqlite::MetaAdapterSqlite;
use cloudillo_types::meta_adapter::{CreateFile, CreatedFile, FileId, FileVariant, MetaAdapter};
use cloudillo_types::types::TnId;
use tempfile::TempDir;

/// One BLOB upload: dedups on (`preset`, `orig_variant_id`) against content of any origin,
/// otherwise goes pending → orig variant → finalized as `file_id`. `file` carries the
/// placement; preset, content type and file type default to a PNG blob.
pub async fn upload(
	adapter: &MetaAdapterSqlite,
	tn_id: TnId,
	file: CreateFile,
	file_id: &str,
) -> CreatedFile {
	let variant_id = file.orig_variant_id.clone().expect("upload needs an orig_variant_id");
	let file = CreateFile {
		preset: file.preset.or_else(|| Some("default".into())),
		content_type: if file.content_type.is_empty() {
			"image/png".into()
		} else {
			file.content_type
		},
		file_tp: file.file_tp.or_else(|| Some("BLOB".into())),
		..file
	};
	let created = adapter.create_file(tn_id, file).await.expect("create file");
	if let FileId::FId(f_id) = created.file_id {
		adapter
			.create_file_variant(
				tn_id,
				f_id,
				FileVariant {
					variant_id: &variant_id,
					variant: "orig",
					format: "png",
					size: 1,
					resolution: (1, 1),
					available: true,
					global: false,
					duration: None,
					bitrate: None,
					page_count: None,
				},
			)
			.await
			.expect("orig variant");
		adapter.finalize_file(tn_id, f_id, file_id).await.expect("finalize");
	}
	created
}

/// The `e_id` of entry `entry_id` — not on the adapter's public surface, so read it through a
/// second connection to the same `meta.db`.
pub async fn e_id_of_entry(temp: &TempDir, entry_id: &str) -> u64 {
	let pool = sqlx::sqlite::SqlitePoolOptions::new()
		.connect(&format!("sqlite://{}/meta.db", temp.path().display()))
		.await
		.expect("open meta.db");
	let e_id: i64 = sqlx::query_scalar("SELECT e_id FROM entries WHERE entry_id = ?")
		.bind(entry_id)
		.fetch_one(&pool)
		.await
		.expect("read e_id");
	pool.close().await;
	u64::try_from(e_id).expect("e_id")
}

// vim: ts=4
