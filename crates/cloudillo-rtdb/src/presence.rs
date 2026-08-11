// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Presence rooms for RTDB connections.
//!
//! RTDB's counterpart to the CRDT awareness relay. A connection opts in at connect
//! time (`?presence=1`), publishes an ephemeral free-form `state`, and receives the
//! full roster plus live join/update/leave events for everyone else on the same
//! document.
//!
//! Three properties shape everything here:
//!
//! - **Nothing is persisted and nothing is validated against stored documents.** A
//!   room is in-memory only. The presence code path must never touch `RtdbAdapter`
//!   or open a `Transaction`: the redb maintenance barrier is a write-preferring
//!   `RwLock`, so an adapter call from a websocket command handler is a deadlock
//!   hazard.
//! - **The server stamps `state.user.idTag` and nothing else.** Every other field is
//!   peer-controlled and untrusted — see [`stamp_presence_identity`].
//! - **Rooms are never scoped to RTDB paths.** "Who is on which page / in which
//!   block" rides in the app's own free-form state and is filtered client-side, the
//!   way `apps/ideallo/src/components/Cursors.tsx` reads `presence.cursor` today.

use crate::prelude::*;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::Instant;
use tokio::sync::{Mutex, RwLock, mpsc};

/// Largest serialised presence state accepted from a client, in bytes.
///
/// Generous for a cursor, a viewport and a display name; far short of anything
/// worth using the roster as a data channel for. A room replays every stored state
/// to each joiner, so this cap times [`MAX_PRESENCE_MEMBERS`] bounds one `sync`.
pub const MAX_PRESENCE_STATE_BYTES: usize = 2048;

/// Largest number of connections in one room. Beyond this a joiner is refused
/// presence and simply runs without it — the document itself still works.
pub const MAX_PRESENCE_MEMBERS: usize = 100;

/// Burst allowance of presence frames per connection.
pub const PRESENCE_RATE_CAPACITY: u32 = 20;

/// Sustained presence frames per second per connection, once the burst is spent.
pub const PRESENCE_RATE_REFILL_PER_SEC: u32 = 5;

/// Events a member's channel will hold before the room starts dropping them.
///
/// Bounded on purpose. An unbounded queue behind a stalled `ws_tx` would grow at
/// the configured limits — [`MAX_PRESENCE_MEMBERS`] peers × [`PRESENCE_RATE_REFILL_PER_SEC`]
/// frames each, of up to [`MAX_PRESENCE_STATE_BYTES`] — with no backpressure and
/// nothing to reclaim it until the connection finally tears down.
pub const PRESENCE_QUEUE_DEPTH: usize = 64;

/// A room's identity: tenant plus file.
///
/// Keyed on both halves deliberately. The CRDT registry keys on a bare `doc_id`,
/// which lets two tenants that happen to share a file id share a document; that is a
/// known flaw and is not reproduced here.
pub type PresenceKey = (TnId, Box<str>);

/// Why a presence frame was refused, in the shape the wire `error` frame takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresenceRejection {
	pub code: u16,
	pub message: &'static str,
}

/// An event pushed down a member's channel.
///
/// `Join`/`Update` are upserts by `connId` and `Leave` is a delete, so all three are
/// idempotent; `Sync` replaces the roster wholesale. None is ever echoed to the
/// connection that caused it.
///
/// The payloads are behind an `Arc` because one publish fans out to every other
/// member of the room — up to [`MAX_PRESENCE_MEMBERS`] − 1 recipients, each of
/// which would otherwise deep-clone the whole JSON state.
#[derive(Debug, Clone, PartialEq)]
pub enum PresenceEvent {
	/// The whole roster, pushed once at join. `conn_id` is the *recipient's* own
	/// connection id — that is how a client learns which entry is itself.
	Sync {
		/// This connection's own id.
		conn_id: Box<str>,
		/// One `{ connId, state }` object per member that has published.
		users: Arc<[Value]>,
	},
	/// A member published for the first time and entered the roster.
	Join { conn_id: Box<str>, state: Arc<Value> },
	/// A member that is already in the roster published again.
	Update { conn_id: Box<str>, state: Arc<Value> },
	/// A member left the roster, by disconnecting or by clearing its state.
	Leave { conn_id: Box<str> },
}

impl PresenceEvent {
	/// The `event` object of a `presenceChange` frame.
	pub fn to_json(&self) -> Value {
		match self {
			Self::Sync { conn_id, users } => {
				json!({ "action": "sync", "connId": conn_id, "users": users.as_ref() })
			}
			Self::Join { conn_id, state } => {
				json!({ "action": "join", "connId": conn_id, "state": &**state })
			}
			Self::Update { conn_id, state } => {
				json!({ "action": "update", "connId": conn_id, "state": &**state })
			}
			Self::Leave { conn_id } => json!({ "action": "leave", "connId": conn_id }),
		}
	}
}

/// One roster entry, as it appears inside a `sync`.
pub fn presence_entry_json(conn_id: &str, state: &Value) -> Value {
	json!({ "connId": conn_id, "state": state })
}

/// Assert this connection's identity over a client-supplied presence state.
///
/// The whole point of presence is that a peer's avatar is looked up *from* the
/// `idTag`, so an `idTag` the sender chose is full impersonation: any collaborator
/// could appear in everyone's roster wearing a victim's real name and real face.
///
/// - `Some(tag)` (authenticated) -> `user.idTag` is overwritten with `tag`;
/// - `None` (anonymous share-link visitor) -> `user.idTag` is REMOVED. There is no
///   identity to assert on their behalf, and the shell hands such a visitor the
///   OWNER's tag client-side, so stamping here would *be* the impersonation rather
///   than the fix. `name` is left alone, so a guest still shows a display name.
///
/// Overwriting rather than rejecting keeps clients that legitimately send no `idTag`
/// valid and makes the invariant total: every `idTag` on this wire was put there by us.
/// Every other field (`name`, `cursor`, `page`, …) is app-specific and untouched.
///
/// Returns `false` when `user` is present but not an object (`{"user":"alice"}`) — no
/// identity can be asserted into that shape, so it must not be relayed; the caller
/// rejects the frame.
///
/// A state with no `user` field at all is left untouched and accepted — adding one would
/// conjure a nameless phantom into every roster.
pub fn stamp_presence_identity(state: &mut Value, id_tag: Option<&str>) -> bool {
	let Some(user) = state.get_mut("user") else { return true };
	let Some(user) = user.as_object_mut() else { return false };
	match id_tag {
		Some(tag) => {
			user.insert("idTag".to_owned(), Value::String(tag.to_owned()));
		}
		None => {
			user.remove("idTag");
		}
	}
	true
}

/// Refuse a presence state too large to keep and replay.
pub fn check_presence_limits(state: &Value) -> Option<PresenceRejection> {
	// A `Value` cannot fail to serialise; the fallback only has to be over the cap.
	let size = serde_json::to_string(state).map_or(usize::MAX, |s| s.len());
	(size > MAX_PRESENCE_STATE_BYTES)
		.then_some(PresenceRejection { code: 413, message: "Presence state too large" })
}

/// What a `presence` frame resolves to once identity, size and rate budget have
/// been decided. See [`presence_frame`].
#[derive(Debug, Clone, PartialEq)]
pub enum PresenceFrame {
	/// Store and broadcast this state. Already stamped — pass it to
	/// [`PresenceRegistry::publish`] unmodified.
	Publish(Value),
	/// Absent or null `state`: drop out of the roster, stay in the room.
	Clear,
	/// The rate budget is spent. Nothing is stored and nothing is broadcast, so
	/// the client must be told rather than silently acked.
	Throttled,
}

/// The whole decision behind one `presence` command frame, as a pure function.
///
/// Separate from the websocket command handler because **the order of these steps is
/// the security property**, and the handler itself needs an `App` and a live socket:
///
/// 1. **Stamp before storing.** What the room holds is what peers see *and* what every
///    future `sync` replays, so an unstamped `idTag` stored here impersonates for the
///    lifetime of the room, not for one frame.
/// 2. **Stamp before the size check.** The injected `idTag` is part of what gets stored
///    and replayed; measuring the unstamped state would let a client sit just under the
///    cap and cross it after stamping.
/// 3. **Size cap before the rate budget.** An oversized state is a client bug, and
///    spending a token on it would throttle the legitimate frames behind it.
///
/// A clear costs no token: it is idempotent and bounded by connection count rather than
/// by caret movement.
pub fn presence_frame(
	state: Option<&Value>,
	id_tag: Option<&str>,
	rate: &mut RateBucket,
	now: Instant,
) -> Result<PresenceFrame, PresenceRejection> {
	let Some(state) = state.filter(|v| !v.is_null()) else { return Ok(PresenceFrame::Clear) };
	let mut state = state.clone();

	if !stamp_presence_identity(&mut state, id_tag) {
		return Err(PresenceRejection {
			code: 400,
			message: "Presence state `user` must be an object",
		});
	}
	if let Some(rejection) = check_presence_limits(&state) {
		return Err(rejection);
	}
	if !rate.take(now) {
		return Ok(PresenceFrame::Throttled);
	}
	Ok(PresenceFrame::Publish(state))
}

/// Per-connection token bucket limiting presence frames.
///
/// Time is passed in rather than read, so the refill behaviour is testable without
/// sleeping.
#[derive(Debug)]
pub struct RateBucket {
	tokens: f64,
	last: Instant,
}

impl RateBucket {
	/// A full bucket as of `now`.
	pub fn new(now: Instant) -> Self {
		Self { tokens: f64::from(PRESENCE_RATE_CAPACITY), last: now }
	}

	/// Refill for the elapsed time, then spend one token. `false` means the bucket
	/// was empty and the caller should answer `throttled` without storing anything.
	pub fn take(&mut self, now: Instant) -> bool {
		let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
		self.last = now;
		self.tokens = (self.tokens + elapsed * f64::from(PRESENCE_RATE_REFILL_PER_SEC))
			.min(f64::from(PRESENCE_RATE_CAPACITY));
		if self.tokens >= 1.0 {
			self.tokens -= 1.0;
			true
		} else {
			false
		}
	}
}

/// One connection inside a room.
struct Member {
	tx: mpsc::Sender<PresenceEvent>,
	/// `None` until this connection publishes. A member is in the room from connect
	/// but *not* in the roster until then, so a passive watcher never appears to its
	/// peers.
	state: Option<Arc<Value>>,
}

/// The members sharing one document.
#[derive(Default)]
struct PresenceRoom {
	members: HashMap<Box<str>, Member>,
}

impl PresenceRoom {
	/// Every member that has published, in `sync` shape.
	fn roster(&self) -> Arc<[Value]> {
		self.members
			.iter()
			.filter_map(|(conn_id, member)| {
				member.state.as_ref().map(|state| presence_entry_json(conn_id, state))
			})
			.collect()
	}

	/// Push to everyone but `origin`, which already knows what it just did.
	///
	/// A closed channel is ignored: the owning connection is tearing down and its
	/// `leave` is on its way.
	///
	/// A **full** channel drops the event for that member alone. Presence is
	/// last-writer-wins state, so an intermediate frame lost to a stalled socket is
	/// superseded by the next `update` that member's peer publishes — and the
	/// alternative, awaiting capacity, would let one wedged connection stall the
	/// publisher (which holds the room lock) for the whole room.
	fn broadcast(&self, event: &PresenceEvent, origin: &str) {
		for (conn_id, member) in &self.members {
			if &**conn_id == origin {
				continue;
			}
			if let Err(mpsc::error::TrySendError::Full(_)) = member.tx.try_send(event.clone()) {
				debug!("Presence queue full for conn {}, dropping event", conn_id);
			}
		}
	}
}

/// Process-wide registry of presence rooms.
///
/// **Lock order is always registry -> room, never room -> registry.** Every method takes
/// the registry lock first *and holds it across the room lock*, which is what makes
/// [`PresenceRegistry::leave`]'s emptiness check exact rather than a TOCTOU race: a
/// `join` that released the registry lock in between could insert itself into a room
/// `leave` had already removed, leaving a member visible to nobody whose every later
/// `publish` and `leave` silently no-ops. `publish` only needs the read guard — `leave`
/// takes the write guard, so a read guard is enough to exclude it.
///
/// Membership is explicit — a `HashMap` of per-member `mpsc` senders rather than a
/// `broadcast` channel. The CRDT registry needs `broadcast` because its subscribers are
/// anonymous byte relays and its entry owns a live `Doc` worth preserving across a
/// reconnect grace period. Presence has neither property, and explicit membership buys
/// an exact emptiness check: no `receiver_count()`, no grace period, no `Lagged`.
pub struct PresenceRegistry {
	rooms: RwLock<HashMap<PresenceKey, Arc<Mutex<PresenceRoom>>>>,
}

impl PresenceRegistry {
	fn new() -> Self {
		Self { rooms: RwLock::new(HashMap::new()) }
	}

	/// Add a connection to its room and hand back its event receiver.
	///
	/// A `sync` carrying the current roster is queued onto the receiver before this
	/// returns, so it necessarily precedes every later event on that channel —
	/// which is why the roster is pushed rather than returned in a command response.
	///
	/// Returns `None` when the room is at [`MAX_PRESENCE_MEMBERS`]; the caller runs
	/// without presence rather than failing the connection.
	///
	/// The registry write guard is held across the room lock — see the type doc for
	/// why releasing it in between would orphan this joiner.
	pub async fn join(
		&self,
		key: &PresenceKey,
		conn_id: &str,
	) -> Option<mpsc::Receiver<PresenceEvent>> {
		let mut rooms = self.rooms.write().await;
		let room = Arc::clone(rooms.entry(key.clone()).or_default());
		let mut room = room.lock().await;
		// A room this call just created has no members, so it can never be the one
		// refused here — a refusal always leaves a populated room behind, never a
		// stranded empty one for `leave` to fail to collect.
		if room.members.len() >= MAX_PRESENCE_MEMBERS {
			return None;
		}
		let (tx, rx) = mpsc::channel(PRESENCE_QUEUE_DEPTH);
		let users = room.roster();
		room.members.insert(conn_id.into(), Member { tx: tx.clone(), state: None });
		// The one event that must never be dropped, and cannot be: the channel was
		// created two lines up, so all PRESENCE_QUEUE_DEPTH slots are free.
		let _ = tx.try_send(PresenceEvent::Sync { conn_id: conn_id.into(), users });
		Some(rx)
	}

	/// Store a connection's state and tell its peers.
	///
	/// `state` is expected to be already stamped — what the room holds is what `sync`
	/// replays to every future joiner, so an unstamped state stored here would leak
	/// for as long as the room lives.
	///
	/// `None` clears: the member stays in the room but leaves the roster.
	pub async fn publish(&self, key: &PresenceKey, conn_id: &str, state: Option<Value>) {
		// The read guard is held across the room lock: it excludes `leave`, which
		// needs the write guard, so the room cannot be dropped from the registry
		// between the lookup and the insert.
		let rooms = self.rooms.read().await;
		let Some(room) = rooms.get(key).map(Arc::clone) else { return };
		let mut room = room.lock().await;
		let Some(member) = room.members.get_mut(conn_id) else { return };
		let event = if let Some(state) = state {
			let entering = member.state.is_none();
			// Wrapped once here; the fan-out below then clones a pointer per peer.
			let state = Arc::new(state);
			member.state = Some(Arc::clone(&state));
			let conn_id = conn_id.into();
			if entering {
				PresenceEvent::Join { conn_id, state }
			} else {
				PresenceEvent::Update { conn_id, state }
			}
		} else {
			// Never published, or already cleared — nothing for peers to undo.
			if member.state.take().is_none() {
				return;
			}
			PresenceEvent::Leave { conn_id: conn_id.into() }
		};
		room.broadcast(&event, conn_id);
	}

	/// Remove a connection on disconnect, dropping the room once it is empty.
	pub async fn leave(&self, key: &PresenceKey, conn_id: &str) {
		let mut rooms = self.rooms.write().await;
		let Some(room) = rooms.get(key).map(Arc::clone) else { return };
		{
			let mut room = room.lock().await;
			// Only a member that reached the roster needs a `leave`; a watcher was
			// never visible to anyone.
			if room.members.remove(conn_id).is_some_and(|m| m.state.is_some()) {
				room.broadcast(&PresenceEvent::Leave { conn_id: conn_id.into() }, conn_id);
			}
			if !room.members.is_empty() {
				return;
			}
		}
		rooms.remove(key);
	}

	/// Test-only: nothing in production needs it, and exposing it would invite reads
	/// that race the registry lock.
	#[cfg(test)]
	async fn room_count(&self) -> usize {
		self.rooms.read().await.len()
	}

	/// Test-only, for the same reason as [`PresenceRegistry::room_count`].
	#[cfg(test)]
	async fn has_room(&self, key: &PresenceKey) -> bool {
		self.rooms.read().await.contains_key(key)
	}
}

/// The one registry, shared by every RTDB connection in the process.
pub static RTDB_PRESENCE: LazyLock<PresenceRegistry> = LazyLock::new(PresenceRegistry::new);

#[cfg(test)]
mod tests {
	use super::*;
	use std::time::Duration;

	fn key(tn_id: u32, file_id: &str) -> PresenceKey {
		(TnId(tn_id), file_id.into())
	}

	/// The state a stamped payload ends up with, or `None` if the frame is rejected.
	fn stamped(state: Value, id_tag: Option<&str>) -> Option<Value> {
		let mut state = state;
		stamp_presence_identity(&mut state, id_tag).then_some(state)
	}

	fn drain(rx: &mut mpsc::Receiver<PresenceEvent>) -> Vec<PresenceEvent> {
		let mut out = Vec::new();
		while let Ok(event) = rx.try_recv() {
			out.push(event);
		}
		out
	}

	// Identity stamping //
	//*******************//

	#[test]
	fn overwrites_a_forged_id_tag() {
		assert_eq!(
			stamped(
				json!({ "user": { "name": "Mallory", "idTag": "@victim.example.com" } }),
				Some("@mallory.example.com")
			),
			Some(json!({ "user": { "name": "Mallory", "idTag": "@mallory.example.com" } }))
		);
	}

	#[test]
	fn strips_the_id_tag_of_a_guest_and_keeps_the_name() {
		// The tag a share-link visitor sends is the OWNER's — that is what the shell
		// hands an unauthenticated app — so relaying it would give them the owner's
		// name and face in everyone else's roster.
		assert_eq!(
			stamped(json!({ "user": { "name": "Guest", "idTag": "@owner.example.com" } }), None),
			Some(json!({ "user": { "name": "Guest" } }))
		);
	}

	#[test]
	fn stamps_an_authenticated_tag_onto_a_user_without_one() {
		assert_eq!(
			stamped(
				json!({ "user": { "name": "Alice" }, "page": "pg-7" }),
				Some("@alice.example.com")
			),
			Some(json!({
				"user": { "name": "Alice", "idTag": "@alice.example.com" },
				"page": "pg-7"
			}))
		);
	}

	#[test]
	fn leaves_a_state_without_a_user_field_untouched() {
		// Inventing a `user` would put a nameless phantom into every roster.
		assert_eq!(
			stamped(json!({ "cursor": { "x": 1 } }), Some("@alice.example.com")),
			Some(json!({ "cursor": { "x": 1 } }))
		);
	}

	#[test]
	fn rejects_a_state_whose_user_is_not_an_object() {
		// A shape no identity can be asserted into is exactly the one that must not
		// be relayed.
		assert_eq!(stamped(json!({ "user": "alice" }), Some("@alice.example.com")), None);
		assert_eq!(stamped(json!({ "user": ["alice"] }), Some("@alice.example.com")), None);
	}

	// Limits //
	//********//

	/// A state whose serialised length is exactly `len`, padded inside `user.name`.
	fn state_of_len(len: usize) -> Value {
		let overhead = serde_json::to_string(&json!({ "user": { "name": "" } }))
			.map_or(usize::MAX, |s| s.len());
		let state = json!({ "user": { "name": "A".repeat(len - overhead) } });
		assert_eq!(serde_json::to_string(&state).map_or(0, |s| s.len()), len);
		state
	}

	#[test]
	fn rejects_a_state_over_the_size_cap() {
		let small = json!({ "user": { "name": "Alice" } });
		assert_eq!(check_presence_limits(&small), None);

		// The boundary itself, pinning `>` rather than `>=`.
		assert_eq!(check_presence_limits(&state_of_len(MAX_PRESENCE_STATE_BYTES)), None);
		assert_eq!(
			check_presence_limits(&state_of_len(MAX_PRESENCE_STATE_BYTES + 1)),
			Some(PresenceRejection { code: 413, message: "Presence state too large" })
		);

		let big = json!({ "user": { "name": "A".repeat(MAX_PRESENCE_STATE_BYTES) } });
		assert_eq!(
			check_presence_limits(&big),
			Some(PresenceRejection { code: 413, message: "Presence state too large" })
		);
	}

	#[test]
	fn refills_the_rate_bucket_over_time() {
		let start = Instant::now();
		let mut bucket = RateBucket::new(start);

		// The burst allowance, then empty.
		for _ in 0..PRESENCE_RATE_CAPACITY {
			assert!(bucket.take(start));
		}
		assert!(!bucket.take(start));

		// One second refills PRESENCE_RATE_REFILL_PER_SEC tokens, no more.
		let later = start + Duration::from_secs(1);
		for _ in 0..PRESENCE_RATE_REFILL_PER_SEC {
			assert!(bucket.take(later));
		}
		assert!(!bucket.take(later));

		// An idle connection banks nothing beyond the burst allowance: the refill is
		// clamped, so a tab left open all afternoon cannot come back with a
		// thousand-frame credit.
		let much_later = start + Duration::from_secs(1000);
		for _ in 0..PRESENCE_RATE_CAPACITY {
			assert!(bucket.take(much_later));
		}
		assert!(!bucket.take(much_later));
	}

	// Frame decision //
	//****************//

	/// `presence_frame` with a fresh, full bucket.
	fn frame(state: Option<&Value>) -> Result<PresenceFrame, PresenceRejection> {
		let now = Instant::now();
		presence_frame(state, Some("@alice.example.com"), &mut RateBucket::new(now), now)
	}

	#[test]
	fn a_published_frame_carries_the_stamped_state() {
		// Stamp *before* storing: what `publish` gets is what every future `sync`
		// replays, so a forged idTag surviving to here impersonates for the room's
		// whole lifetime rather than for one frame.
		assert_eq!(
			frame(Some(&json!({ "user": { "name": "M", "idTag": "@victim.example.com" } }))),
			Ok(PresenceFrame::Publish(
				json!({ "user": { "name": "M", "idTag": "@alice.example.com" } })
			))
		);
	}

	#[test]
	fn an_absent_or_null_state_clears_without_spending_a_token() {
		let now = Instant::now();
		let mut bucket = RateBucket::new(now);
		for state in [None, Some(Value::Null)] {
			assert_eq!(
				presence_frame(state.as_ref(), Some("@alice.example.com"), &mut bucket, now),
				Ok(PresenceFrame::Clear)
			);
		}
		// A clear is idempotent and bounded by connection count, so it is not
		// rate-limited — the full burst is still there.
		for _ in 0..PRESENCE_RATE_CAPACITY {
			assert!(bucket.take(now));
		}
	}

	#[test]
	fn a_user_that_is_not_an_object_is_refused() {
		assert_eq!(
			frame(Some(&json!({ "user": "alice" }))),
			Err(PresenceRejection {
				code: 400,
				message: "Presence state `user` must be an object"
			})
		);
	}

	#[test]
	fn the_size_cap_is_measured_after_stamping() {
		// Exactly at the cap unstamped, over it once the idTag is injected. Measuring
		// the state the client sent rather than the state the room will hold is how a
		// client parks just under the cap and stores something over it.
		let state = state_of_len(MAX_PRESENCE_STATE_BYTES);
		assert_eq!(check_presence_limits(&state), None, "the unstamped state is within the cap");
		assert_eq!(
			frame(Some(&state)),
			Err(PresenceRejection { code: 413, message: "Presence state too large" })
		);
	}

	#[test]
	fn an_oversized_frame_is_refused_before_it_spends_a_token() {
		// An oversized state is a client bug; charging it would throttle the
		// legitimate frames queued behind it.
		let now = Instant::now();
		let mut bucket = RateBucket::new(now);
		let big = json!({ "user": { "name": "A".repeat(MAX_PRESENCE_STATE_BYTES) } });

		for _ in 0..PRESENCE_RATE_CAPACITY {
			assert_eq!(
				presence_frame(Some(&big), Some("@alice.example.com"), &mut bucket, now),
				Err(PresenceRejection { code: 413, message: "Presence state too large" })
			);
		}
		// Untouched: the whole burst allowance is still available to good frames.
		for _ in 0..PRESENCE_RATE_CAPACITY {
			assert!(bucket.take(now));
		}
	}

	#[test]
	fn a_frame_past_the_rate_budget_is_throttled_rather_than_published() {
		let now = Instant::now();
		let mut bucket = RateBucket::new(now);
		let state = json!({ "user": { "name": "Alice" } });
		let stamped = json!({ "user": { "name": "Alice", "idTag": "@alice.example.com" } });

		for _ in 0..PRESENCE_RATE_CAPACITY {
			assert_eq!(
				presence_frame(Some(&state), Some("@alice.example.com"), &mut bucket, now),
				Ok(PresenceFrame::Publish(stamped.clone()))
			);
		}
		// Not an error: the client is told to resend, not that it did something wrong.
		assert_eq!(
			presence_frame(Some(&state), Some("@alice.example.com"), &mut bucket, now),
			Ok(PresenceFrame::Throttled)
		);
	}

	#[test]
	fn a_guests_frame_publishes_without_an_id_tag() {
		let now = Instant::now();
		assert_eq!(
			presence_frame(
				Some(&json!({ "user": { "name": "Guest", "idTag": "@owner.example.com" } })),
				None,
				&mut RateBucket::new(now),
				now
			),
			Ok(PresenceFrame::Publish(json!({ "user": { "name": "Guest" } })))
		);
	}

	// Room behaviour //
	//****************//

	#[tokio::test]
	async fn a_member_is_absent_from_the_roster_until_it_publishes() {
		let registry = PresenceRegistry::new();
		let key = key(1, "file-1");

		let mut watcher = registry.join(&key, "c1").await.expect("joined");
		assert_eq!(
			drain(&mut watcher),
			vec![PresenceEvent::Sync { conn_id: "c1".into(), users: vec![].into() }]
		);

		// c2 joins while c1 has published nothing: an empty roster.
		let mut second = registry.join(&key, "c2").await.expect("joined");
		assert_eq!(
			drain(&mut second),
			vec![PresenceEvent::Sync { conn_id: "c2".into(), users: vec![].into() }]
		);

		registry.publish(&key, "c1", Some(json!({ "user": { "name": "Alice" } }))).await;

		// Only now does a third joiner see c1.
		let mut third = registry.join(&key, "c3").await.expect("joined");
		assert_eq!(
			drain(&mut third),
			vec![PresenceEvent::Sync {
				conn_id: "c3".into(),
				users: vec![presence_entry_json("c1", &json!({ "user": { "name": "Alice" } }))]
					.into()
			}]
		);
	}

	#[tokio::test]
	async fn a_first_publish_broadcasts_join_and_a_second_broadcasts_update() {
		let registry = PresenceRegistry::new();
		let key = key(1, "file-1");

		let _writer = registry.join(&key, "c1").await.expect("joined");
		let mut peer = registry.join(&key, "c2").await.expect("joined");
		drain(&mut peer);

		let first = json!({ "user": { "name": "Alice" }, "block": "b1" });
		registry.publish(&key, "c1", Some(first.clone())).await;
		assert_eq!(
			drain(&mut peer),
			vec![PresenceEvent::Join { conn_id: "c1".into(), state: first.into() }]
		);

		let second = json!({ "user": { "name": "Alice" }, "block": "b2" });
		registry.publish(&key, "c1", Some(second.clone())).await;
		assert_eq!(
			drain(&mut peer),
			vec![PresenceEvent::Update { conn_id: "c1".into(), state: second.into() }]
		);
	}

	#[tokio::test]
	async fn a_null_state_broadcasts_leave_and_removes_the_entry() {
		let registry = PresenceRegistry::new();
		let key = key(1, "file-1");

		let _writer = registry.join(&key, "c1").await.expect("joined");
		let mut peer = registry.join(&key, "c2").await.expect("joined");
		registry.publish(&key, "c1", Some(json!({ "user": { "name": "Alice" } }))).await;
		drain(&mut peer);

		registry.publish(&key, "c1", None).await;
		assert_eq!(drain(&mut peer), vec![PresenceEvent::Leave { conn_id: "c1".into() }]);

		// Clearing twice says nothing the peers have not already been told.
		registry.publish(&key, "c1", None).await;
		assert!(drain(&mut peer).is_empty());

		// And the entry is gone from the roster a later joiner receives.
		let mut joiner = registry.join(&key, "c3").await.expect("joined");
		assert_eq!(
			drain(&mut joiner),
			vec![PresenceEvent::Sync { conn_id: "c3".into(), users: vec![].into() }]
		);
	}

	#[tokio::test]
	async fn an_event_is_not_echoed_to_its_originator() {
		let registry = PresenceRegistry::new();
		let key = key(1, "file-1");

		let mut writer = registry.join(&key, "c1").await.expect("joined");
		let mut peer = registry.join(&key, "c2").await.expect("joined");
		drain(&mut writer);
		drain(&mut peer);

		registry.publish(&key, "c1", Some(json!({ "user": { "name": "Alice" } }))).await;

		// The publisher already has its own state; only the peer is told.
		assert!(drain(&mut writer).is_empty());
		assert_eq!(drain(&mut peer).len(), 1);
	}

	#[tokio::test]
	async fn joining_queues_a_sync_before_any_later_event() {
		let registry = PresenceRegistry::new();
		let key = key(1, "file-1");

		let _alice = registry.join(&key, "c1").await.expect("joined");
		registry.publish(&key, "c1", Some(json!({ "user": { "name": "Alice" } }))).await;

		let mut joiner = registry.join(&key, "c2").await.expect("joined");
		registry
			.publish(&key, "c1", Some(json!({ "user": { "name": "Alice" }, "n": 2 })))
			.await;

		// `sync` is queued at join time onto the same channel every later event
		// uses, so it cannot arrive second and clobber a fresher `update`.
		let events = drain(&mut joiner);
		assert_eq!(events.len(), 2);
		assert!(matches!(events[0], PresenceEvent::Sync { .. }));
		assert!(matches!(events[1], PresenceEvent::Update { .. }));
	}

	#[tokio::test]
	async fn disconnecting_broadcasts_leave_to_the_remaining_members() {
		let registry = PresenceRegistry::new();
		let key = key(1, "file-1");

		let _alice = registry.join(&key, "c1").await.expect("joined");
		let mut peer = registry.join(&key, "c2").await.expect("joined");
		registry.publish(&key, "c1", Some(json!({ "user": { "name": "Alice" } }))).await;
		drain(&mut peer);

		registry.leave(&key, "c1").await;
		assert_eq!(drain(&mut peer), vec![PresenceEvent::Leave { conn_id: "c1".into() }]);
	}

	#[tokio::test]
	async fn a_room_is_dropped_when_its_last_member_leaves() {
		let registry = PresenceRegistry::new();
		let key = key(1, "file-1");

		let _alice = registry.join(&key, "c1").await.expect("joined");
		let _bob = registry.join(&key, "c2").await.expect("joined");
		assert_eq!(registry.room_count().await, 1);

		registry.leave(&key, "c1").await;
		assert_eq!(registry.room_count().await, 1);

		registry.leave(&key, "c2").await;
		assert_eq!(registry.room_count().await, 0);
	}

	#[tokio::test]
	async fn a_join_refused_at_the_cap_keeps_the_populated_room() {
		let registry = PresenceRegistry::new();
		let key = key(1, "file-1");
		let mut rooms = registry.rooms.write().await;
		let room = Arc::clone(rooms.entry(key.clone()).or_default());
		drop(rooms);

		// Fill the room to the cap without going through `join`.
		{
			let mut room = room.lock().await;
			for i in 0..MAX_PRESENCE_MEMBERS {
				let (tx, _rx) = mpsc::channel(PRESENCE_QUEUE_DEPTH);
				room.members
					.insert(format!("c{i}").into_boxed_str(), Member { tx, state: None });
			}
		}
		assert!(registry.join(&key, "late").await.is_none(), "refused at the cap");
		// The room is populated, so it must survive the refusal.
		assert!(registry.has_room(&key).await);
	}

	#[tokio::test]
	async fn a_full_queue_drops_events_without_blocking_the_publisher() {
		// Presence is last-writer-wins, so a stalled reader loses intermediate
		// frames rather than stalling every other member of the room.
		let registry = PresenceRegistry::new();
		let key = key(1, "file-1");

		let _writer = registry.join(&key, "c1").await.expect("joined");
		let mut stalled = registry.join(&key, "c2").await.expect("joined");

		// One `sync` plus PRESENCE_QUEUE_DEPTH-1 updates fill the channel; the rest
		// are dropped, and none of these calls blocks.
		for n in 0..PRESENCE_QUEUE_DEPTH * 2 {
			registry
				.publish(&key, "c1", Some(json!({ "user": { "name": "Alice" }, "n": n })))
				.await;
		}
		assert_eq!(drain(&mut stalled).len(), PRESENCE_QUEUE_DEPTH);

		// The room itself still holds the newest state, so the next joiner is exact.
		let mut joiner = registry.join(&key, "c3").await.expect("joined");
		let events = drain(&mut joiner);
		let [PresenceEvent::Sync { users, .. }] = events.as_slice() else {
			panic!("expected a single sync, got {events:?}");
		};
		assert_eq!(
			users.as_ref(),
			[presence_entry_json(
				"c1",
				&json!({ "user": { "name": "Alice" }, "n": PRESENCE_QUEUE_DEPTH * 2 - 1 })
			)]
		);
	}

	#[tokio::test]
	async fn two_tenants_with_the_same_file_id_do_not_share_a_room() {
		// Regression guard for the CRDT registry's bare-`doc_id` key.
		let registry = PresenceRegistry::new();
		let one = key(1, "file-1");
		let two = key(2, "file-1");

		let _alice = registry.join(&one, "c1").await.expect("joined");
		let mut bob = registry.join(&two, "c2").await.expect("joined");
		drain(&mut bob);

		registry.publish(&one, "c1", Some(json!({ "user": { "name": "Alice" } }))).await;

		assert!(drain(&mut bob).is_empty());
		assert_eq!(registry.room_count().await, 2);
	}
}

// vim: ts=4
