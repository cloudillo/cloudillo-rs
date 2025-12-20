//! Action subsystem. Actions are small signed documents representing a user action (e.g. post, comment, connection request).

pub mod audience;
pub mod delivery;
pub mod dsl;
pub mod filter;
pub mod forward;
pub mod handler;
pub mod helpers;
pub mod hooks;
pub mod key_cache;
pub mod native_hooks;
pub mod perm;
mod process;
pub mod settings;
pub mod task;

/// Action status codes for tracking action lifecycle state
pub mod status {
	/// Active/Accepted/Approved - Unified status for actions in good standing
	/// Used for: new actions, manually accepted actions, auto-approved actions
	pub const ACTIVE: char = 'A';

	/// Confirmation required - Action awaits user decision (accept/reject)
	/// Used for: CONN requests without mutual, FSHR file shares
	pub const CONFIRMATION: char = 'C';

	/// Notification - Auto-processed, informational only
	/// Used for: mutual CONN auto-accepted, REACT notifications
	pub const NOTIFICATION: char = 'N';

	/// Deleted/Rejected - Action was rejected or deleted
	/// Used for: rejected requests, deleted content
	pub const DELETED: char = 'D';
}

pub use process::{decode_jwt_no_verify, verify_action_token};

use crate::prelude::*;

pub fn init(app: &App) -> ClResult<()> {
	app.scheduler.register::<task::ActionCreatorTask>()?;
	app.scheduler.register::<task::ActionVerifierTask>()?;
	app.scheduler.register::<delivery::ActionDeliveryTask>()?;

	// Register native hooks (must be called after app is fully initialized)
	// This is done asynchronously during bootstrap
	Ok(())
}

// vim: ts=4
