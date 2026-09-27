// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Channel gate tests.
//!
//! This crate cannot reach `cloudillo_core::channels::enterable_channels`, so each test
//! builds the reader's enterable set by hand: `Some(vec![])` is a reader who clears no
//! room's floor, `None` is the tenant.

#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use cloudillo_meta_adapter_sqlite::MetaAdapterSqlite;
use cloudillo_types::{
	error::Error,
	meta_adapter::{
		Action, Channel, CreateFile, FileStatus, ListActionOptions, ListFileOptions, MetaAdapter,
		SearchOptions, SearchPart, UpdateChannelData,
	},
	types::{Patch, Timestamp, TnId},
	worker::WorkerPool,
};
use tempfile::TempDir;

const TN: TnId = TnId(1);
const OPS: &str = "@alice~ops";

/// Tenant `alice` with a porch-visible `ops` room floored at `moderator`, and one post and
/// one file on each side of it: `*~ops` stamped into the room, `*~lobby` on the open floor.
/// Every row is indexed under the word "report".
async fn setup() -> (MetaAdapterSqlite, TempDir) {
	let temp_dir = TempDir::new().expect("Failed to create temp directory");
	let worker_pool = Arc::new(WorkerPool::new(1, 1, 1));
	let adapter = MetaAdapterSqlite::new(worker_pool, temp_dir.path())
		.await
		.expect("Failed to create adapter");
	adapter.create_tenant(TN, "alice").await.ok();

	adapter
		.create_channel(
			TN,
			&Channel {
				name: "ops".into(),
				title: Some("Ops".into()),
				descr: Some("Where the moderators plan".into()),
				visibility: Some('P'),
				min_role: Some("moderator".into()),
				closed: false,
				created_at: Timestamp::now(),
				updated_at: Timestamp::now(),
			},
		)
		.await
		.expect("create channel");

	for (id, channel) in [("a1~ops", Some(OPS)), ("a1~lobby", None)] {
		adapter
			.create_action(
				TN,
				&Action {
					action_id: id,
					typ: "POST",
					sub_typ: None,
					issuer_tag: "alice",
					parent_id: None,
					root_id: None,
					audience_tag: None,
					content: Some(r#"{"text":"report"}"#),
					attachments: None,
					subject: None,
					created_at: Timestamp::now(),
					expires_at: None,
					visibility: Some('P'),
					flags: None,
					x: None,
					hat_tag: None,
					channel,
				},
				None,
			)
			.await
			.expect("create action");
		let part = SearchPart { body: Some("report"), ..Default::default() };
		adapter
			.replace_search_row(TN, 'A', id, &[part], false)
			.await
			.expect("index action");
	}

	for (id, channel) in [("f1~ops", Some(OPS)), ("f1~lobby", None)] {
		adapter
			.create_file(
				TN,
				CreateFile {
					file_id: Some(id.into()),
					content_type: "text/plain".into(),
					file_name: "report.txt".into(),
					file_tp: Some("BLOB".into()),
					status: Some(FileStatus::Active),
					visibility: Some('P'),
					channel: channel.map(Into::into),
					..Default::default()
				},
			)
			.await
			.expect("create file");
		let part = SearchPart { title: Some("report"), ..Default::default() };
		adapter
			.replace_search_row(TN, 'F', id, &[part], false)
			.await
			.expect("index file");
	}

	(adapter, temp_dir)
}

async fn action_ids(adapter: &MetaAdapterSqlite, opts: &ListActionOptions) -> Vec<String> {
	let rows = adapter.list_actions(TN, opts).await.expect("list actions");
	let mut ids: Vec<String> = rows.iter().map(|a| a.action_id.to_string()).collect();
	ids.sort_unstable();
	ids
}

async fn file_ids(adapter: &MetaAdapterSqlite, enterable: Option<Vec<Box<str>>>) -> Vec<String> {
	let opts = ListFileOptions { enterable_channels: enterable, ..Default::default() };
	let rows = adapter.list_files(TN, &opts).await.expect("list files");
	let mut ids: Vec<String> = rows.iter().map(|f| f.file_id.to_string()).collect();
	ids.sort_unstable();
	ids
}

/// Search as a follower (the tenant when `enterable` is `None`).
async fn search_ids(adapter: &MetaAdapterSqlite, enterable: Option<Vec<Box<str>>>) -> Vec<String> {
	let follower = enterable.is_some();
	let opts = SearchOptions {
		q: "report".into(),
		limit: 20,
		visible_levels: follower.then(|| vec!['P', 'V', '2', 'F']),
		viewer_id_tag: follower.then(|| "bob".into()),
		enterable_channels: enterable,
		..Default::default()
	};
	let rows = adapter.search(TN, &opts).await.expect("search");
	let mut ids: Vec<String> = rows.iter().map(|r| r.obj_id.to_string()).collect();
	ids.sort_unstable();
	ids.dedup();
	ids
}

fn gated(enterable: Option<Vec<Box<str>>>) -> ListActionOptions {
	ListActionOptions { enterable_channels: enterable, ..Default::default() }
}

/// The enterable set as `enterable_channels` builds it for a reader who clears every floor:
/// every room that still has a row.
async fn every_room(adapter: &MetaAdapterSqlite) -> Vec<Box<str>> {
	let rooms = adapter.list_channels(TN).await.expect("list channels");
	rooms.iter().map(|c| format!("@alice~{}", c.name).into()).collect()
}

/// The porch does not leak the room. A follower sees `ops` on the porch
/// (`porch_status_covers_each_outcome` in `cloudillo-profile`), but its enterable set is
/// empty, so the feed, the file listing and search return none of the room's rows.
#[tokio::test]
async fn the_porch_does_not_leak_the_room() {
	let (adapter, _dir) = setup().await;

	// The tenant sees both sides, so the fixtures are listable at all.
	assert_eq!(action_ids(&adapter, &gated(None)).await, ["a1~lobby", "a1~ops"]);
	assert_eq!(file_ids(&adapter, None).await, ["f1~lobby", "f1~ops"]);
	assert_eq!(search_ids(&adapter, None).await, ["a1~lobby", "a1~ops", "f1~lobby", "f1~ops"]);

	assert_eq!(action_ids(&adapter, &gated(Some(vec![]))).await, ["a1~lobby"]);
	assert_eq!(file_ids(&adapter, Some(vec![])).await, ["f1~lobby"]);
	assert_eq!(search_ids(&adapter, Some(vec![])).await, ["a1~lobby", "f1~lobby"]);
}

/// A deleted channel fails closed. Deleting the row leaves its content
/// stamped; the room drops out of every reader's enterable set, so even a reader who
/// cleared its floor sees nothing, while the tenant (no gate) still sees every row.
#[tokio::test]
async fn a_deleted_channel_fails_closed() {
	let (adapter, _dir) = setup().await;

	let before = every_room(&adapter).await;
	assert_eq!(action_ids(&adapter, &gated(Some(before))).await, ["a1~lobby", "a1~ops"]);

	adapter.delete_channel(TN, "ops").await.expect("delete channel");
	let after = every_room(&adapter).await;
	assert!(after.is_empty());

	assert_eq!(action_ids(&adapter, &gated(Some(after.clone()))).await, ["a1~lobby"]);
	assert_eq!(file_ids(&adapter, Some(after.clone())).await, ["f1~lobby"]);
	assert_eq!(search_ids(&adapter, Some(after)).await, ["a1~lobby", "f1~lobby"]);

	assert_eq!(action_ids(&adapter, &gated(None)).await, ["a1~lobby", "a1~ops"]);
	assert_eq!(file_ids(&adapter, None).await, ["f1~lobby", "f1~ops"]);
}

/// Mute is presentation only. A muted room yields no rows on an
/// unfiltered feed and all of them on `?channel=`. The handler (`cloudillo-action`
/// `handler.rs` list path) sets the mute only when `?channel=` is absent, so the two option
/// shapes are tested separately here. That the mute never leaves the reader's node holds
/// by construction: it is a local `chan.mute.*` setting, never part of an action.
#[tokio::test]
async fn mute_is_presentation_only() {
	let (adapter, _dir) = setup().await;

	let muted = ListActionOptions { muted_channels: Some(vec![OPS.into()]), ..Default::default() };
	assert_eq!(action_ids(&adapter, &muted).await, ["a1~lobby"]);

	let filtered = ListActionOptions { channel: Some(OPS.into()), ..Default::default() };
	assert_eq!(action_ids(&adapter, &filtered).await, ["a1~ops"]);
}

fn ops_channel() -> Channel {
	Channel {
		name: "ops".into(),
		title: None,
		descr: None,
		visibility: Some('P'),
		min_role: Some("moderator".into()),
		closed: false,
		created_at: Timestamp::now(),
		updated_at: Timestamp::now(),
	}
}

async fn closed(adapter: &MetaAdapterSqlite) -> bool {
	adapter.read_channel(TN, "ops").await.expect("read channel").closed
}

async fn members(adapter: &MetaAdapterSqlite) -> Vec<Box<str>> {
	let mut m = adapter.list_channel_members(TN, "ops").await.expect("list members");
	m.sort_unstable();
	m
}

#[tokio::test]
async fn creating_a_duplicate_channel_conflicts() {
	let (adapter, _dir) = setup().await;
	let res = adapter.create_channel(TN, &ops_channel()).await;
	assert!(matches!(res, Err(Error::Conflict(_))), "got {res:?}");
}

#[tokio::test]
async fn closed_null_reopens_the_room() {
	let (adapter, _dir) = setup().await;

	let close = UpdateChannelData { closed: Patch::Value(true), ..Default::default() };
	adapter.update_channel(TN, "ops", &close).await.expect("close");
	assert!(closed(&adapter).await);

	// `Undefined` leaves `closed` alone.
	let retitle = UpdateChannelData { title: Patch::Value("Ops 2".into()), ..Default::default() };
	adapter.update_channel(TN, "ops", &retitle).await.expect("retitle");
	assert!(closed(&adapter).await);

	let reopen = UpdateChannelData { closed: Patch::Null, ..Default::default() };
	adapter.update_channel(TN, "ops", &reopen).await.expect("reopen");
	assert!(!closed(&adapter).await);
}

#[tokio::test]
async fn roster_add_list_remove() {
	let (adapter, _dir) = setup().await;

	adapter.add_channel_member(TN, "ops", "bob").await.expect("add bob");
	adapter.add_channel_member(TN, "ops", "bob").await.expect("add bob again");
	adapter.add_channel_member(TN, "ops", "carol").await.expect("add carol");
	assert_eq!(members(&adapter).await, [Box::from("bob"), Box::from("carol")]);
	let bob = adapter.list_member_channels(TN, "bob").await.expect("bob's channels");
	assert_eq!(bob, [Box::from("ops")]);

	adapter.remove_channel_member(TN, "ops", "bob").await.expect("remove bob");
	let bob = adapter.list_member_channels(TN, "bob").await.expect("bob's channels");
	assert!(bob.is_empty());
	adapter.remove_channel_member(TN, "ops", "bob").await.expect("remove bob again");
}

#[tokio::test]
async fn deleting_a_channel_drops_its_roster() {
	let (adapter, _dir) = setup().await;

	adapter.add_channel_member(TN, "ops", "bob").await.expect("add bob");
	adapter.delete_channel(TN, "ops").await.expect("delete");
	assert!(matches!(adapter.read_channel(TN, "ops").await, Err(Error::NotFound)));
	let bob = adapter.list_member_channels(TN, "bob").await.expect("bob's channels");
	assert!(bob.is_empty());
	assert!(matches!(adapter.delete_channel(TN, "ops").await, Err(Error::NotFound)));

	adapter.create_channel(TN, &ops_channel()).await.expect("recreate");
	assert!(members(&adapter).await.is_empty());
}

// vim: ts=4
