// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Calendar adapter tests — focused on the transactional paths that aren't
//! trivially verifiable from reading the SQL.
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use cloudillo_meta_adapter_sqlite::MetaAdapterSqlite;
use cloudillo_types::meta_adapter::{
	CalendarObjectExtracted, CalendarObjectWrite, CreateCalendarData, MetaAdapter,
};
use cloudillo_types::types::{Timestamp, TnId};
use cloudillo_types::worker::WorkerPool;
use std::sync::Arc;
use tempfile::TempDir;

async fn create_test_adapter() -> (MetaAdapterSqlite, TempDir) {
	let temp_dir = TempDir::new().expect("Failed to create temp directory");
	let worker_pool = Arc::new(WorkerPool::new(1, 1, 1));
	let adapter = MetaAdapterSqlite::new(worker_pool, temp_dir.path())
		.await
		.expect("Failed to create adapter");
	(adapter, temp_dir)
}

/// Verifies the full contract of `split_calendar_object_series`:
///   - master row gets the new etag/ical,
///   - overrides whose `recurrence_id >= split_at` are soft-deleted,
///   - overrides before `split_at` are retained,
///   - tail row is inserted as an independent master under its own UID.
#[tokio::test]
async fn split_calendar_object_series_forks_atomically() {
	let (adapter, _temp) = create_test_adapter().await;
	let tn_id = TnId(1);
	adapter.create_tenant(tn_id, "alice").await.expect("create tenant");

	let cal = adapter
		.create_calendar(tn_id, &CreateCalendarData { name: "Work".into(), ..Default::default() })
		.await
		.expect("create calendar");

	// Master: weekly recurring event.
	let master_uid = "master-uid";
	let master_ext = CalendarObjectExtracted {
		component: "VEVENT".into(),
		summary: Some("Weekly sync".into()),
		dtstart: Some(Timestamp(1_700_000_000)),
		dtend: Some(Timestamp(1_700_003_600)),
		rrule: Some("FREQ=WEEKLY".into()),
		..Default::default()
	};
	adapter
		.upsert_calendar_object(
			tn_id,
			cal.cal_id,
			master_uid,
			"BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
			"master-etag-v1",
			&master_ext,
		)
		.await
		.expect("insert master");

	// Two overrides — one before split_at, one after.
	let early_rid = Timestamp(1_700_604_800);
	let late_rid = Timestamp(1_702_000_000);
	let split_at = Timestamp(1_701_000_000);

	for (rid, etag) in [(early_rid, "early-etag"), (late_rid, "late-etag")] {
		let ext = CalendarObjectExtracted {
			component: "VEVENT".into(),
			recurrence_id: Some(rid),
			..Default::default()
		};
		adapter
			.upsert_calendar_object(
				tn_id,
				cal.cal_id,
				master_uid,
				"BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
				etag,
				&ext,
			)
			.await
			.expect("insert override");
	}

	// Act: split at split_at.
	let new_master_ext = CalendarObjectExtracted {
		rrule: Some("FREQ=WEEKLY;UNTIL=20231126T000000Z".into()),
		..master_ext.clone()
	};
	let tail_uid = "tail-uid";
	let tail_ext = CalendarObjectExtracted {
		component: "VEVENT".into(),
		summary: Some("Weekly sync (edited)".into()),
		dtstart: Some(split_at),
		rrule: Some("FREQ=WEEKLY".into()),
		..Default::default()
	};

	let (m_etag, t_etag) = adapter
		.split_calendar_object_series(
			tn_id,
			cal.cal_id,
			CalendarObjectWrite {
				uid: master_uid,
				ical: "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
				etag: "master-etag-v2",
				extracted: &new_master_ext,
			},
			CalendarObjectWrite {
				uid: tail_uid,
				ical: "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
				etag: "tail-etag-v1",
				extracted: &tail_ext,
			},
			split_at,
		)
		.await
		.expect("split should succeed");

	// Returned etags round-trip the caller-supplied values (no read-back).
	assert_eq!(&*m_etag, "master-etag-v2");
	assert_eq!(&*t_etag, "tail-etag-v1");

	// Master now carries the v2 etag and updated RRULE.
	let master = adapter
		.get_calendar_object(tn_id, cal.cal_id, master_uid)
		.await
		.expect("read master")
		.expect("master exists");
	assert_eq!(&*master.etag, "master-etag-v2");
	assert!(master.extracted.rrule.as_deref().unwrap().contains("UNTIL="));

	// Tail exists as an independent master row.
	let tail = adapter
		.get_calendar_object(tn_id, cal.cal_id, tail_uid)
		.await
		.expect("read tail")
		.expect("tail exists");
	assert_eq!(&*tail.etag, "tail-etag-v1");
	assert!(tail.extracted.recurrence_id.is_none(), "tail must be a master, not an override");

	// Pre-split override retained.
	let early = adapter
		.get_calendar_object_override(tn_id, cal.cal_id, master_uid, early_rid)
		.await
		.expect("query early override");
	assert!(early.is_some(), "pre-split override must survive");

	// Post-split override soft-deleted (getter filters deleted_at IS NOT NULL).
	let late = adapter
		.get_calendar_object_override(tn_id, cal.cal_id, master_uid, late_rid)
		.await
		.expect("query late override");
	assert!(late.is_none(), "post-split override must be soft-deleted");

	// Only the pre-split override remains in the live override list.
	let overrides = adapter
		.list_calendar_object_overrides(tn_id, cal.cal_id, master_uid)
		.await
		.expect("list overrides");
	assert_eq!(overrides.len(), 1);
	assert_eq!(overrides[0].extracted.recurrence_id, Some(early_rid));
}
