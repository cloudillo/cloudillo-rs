// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Result of one adapter's online snapshot.

use std::path::PathBuf;

/// What an adapter's `snapshot` wrote under its `dest` directory.
#[derive(Debug, Clone, Default)]
pub struct SnapshotPart {
	/// Files written, relative to `dest`.
	pub files: Vec<PathBuf>,
	/// Total size of those files.
	pub bytes: u64,
}

// vim: ts=4
