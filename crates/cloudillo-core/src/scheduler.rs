// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Scheduler subsystem. Handles async tasks, dependencies, fallbacks, repetitions, persistence..

use async_trait::async_trait;
use itertools::Itertools;
use std::{
	collections::{BTreeMap, HashMap},
	fmt::Debug,
	sync::Arc,
};

use parking_lot::{Mutex, RwLock};

use chrono::{DateTime, Utc};
use croner::Cron;
use std::str::FromStr;

use crate::prelude::*;
use cloudillo_types::meta_adapter;

pub type TaskId = u64;

/// Cron schedule wrapper using the croner crate
/// Stores the expression string for serialization
#[derive(Debug, Clone)]
pub struct CronSchedule {
	/// The original cron expression string
	expr: Box<str>,
	/// Parsed cron object
	cron: Cron,
}

impl CronSchedule {
	/// Parse a cron expression (5 fields: minute hour day month weekday)
	pub fn parse(expr: &str) -> ClResult<Self> {
		let cron = Cron::from_str(expr)
			.map_err(|e| Error::ValidationError(format!("invalid cron expression: {}", e)))?;
		Ok(Self { expr: expr.into(), cron })
	}

	/// Calculate the next execution time after the given timestamp
	///
	/// Returns an error if no next occurrence can be found (should be rare
	/// for valid expressions within reasonable time bounds).
	pub fn next_execution(&self, after: Timestamp) -> ClResult<Timestamp> {
		let dt = DateTime::<Utc>::from_timestamp(after.0, 0).unwrap_or_else(Utc::now);

		self.cron
			.find_next_occurrence(&dt, false)
			.map(|next| Timestamp(next.timestamp()))
			.map_err(|e| {
				tracing::error!("Failed to find next cron occurrence for '{}': {}", self.expr, e);
				Error::ValidationError(format!("cron next_execution failed: {}", e))
			})
	}

	/// Convert back to cron expression string
	pub fn to_cron_string(&self) -> String {
		self.expr.to_string()
	}
}

impl PartialEq for CronSchedule {
	fn eq(&self, other: &Self) -> bool {
		self.expr == other.expr
	}
}

impl Eq for CronSchedule {}

#[async_trait]
pub trait Task<S: Clone>: Send + Sync + Debug {
	fn kind() -> &'static str
	where
		Self: Sized;
	fn build(id: TaskId, context: &str) -> ClResult<Arc<dyn Task<S>>>
	where
		Self: Sized;
	fn serialize(&self) -> String;
	async fn run(&self, state: &S) -> ClResult<()>;

	fn kind_of(&self) -> &'static str;

	/// Called when the task transitions to `Failed` after exhausting retries
	/// (or on the very first failure when no retry policy is set). Lets the
	/// task perform irreversible cleanup — e.g. mark a related domain row as
	/// permanently failed — that should not happen on retryable failures.
	/// Default: no-op.
	async fn on_failed(&self, _state: &S, _attempts: u16, _last_error: &str) {}

	/// Called after a failure that **will** be retried, with the zero-based index
	/// of the attempt that just failed. Lets a task tell the user once, on the
	/// first failure, instead of once per retry. Default: no-op.
	///
	/// Mutually exclusive with [`Task::on_failed`] for any single failure: a
	/// failure either schedules a retry (this) or is terminal (that).
	async fn on_attempt_failed(&self, _state: &S, _attempt: u16, _last_error: &str) {}
}

#[derive(Debug)]
pub enum TaskStatus {
	Pending,
	Completed,
	Failed,
}

pub struct TaskData {
	id: TaskId,
	kind: Box<str>,
	status: TaskStatus,
	input: Box<str>,
	deps: Box<[TaskId]>,
	retry_data: Option<Box<str>>,
	cron_data: Option<Box<str>>,
	next_at: Option<Timestamp>,
}

#[async_trait]
pub trait TaskStore<S: Clone>: Send + Sync {
	async fn add(&self, task: &TaskMeta<S>, key: Option<&str>) -> ClResult<TaskId>;
	async fn finished(&self, id: TaskId, output: &str) -> ClResult<()>;
	async fn load(&self) -> ClResult<Vec<TaskData>>;
	async fn update_task_error(
		&self,
		task_id: TaskId,
		output: &str,
		next_at: Option<Timestamp>,
	) -> ClResult<()>;
	async fn find_by_key(&self, key: &str) -> ClResult<Option<(TaskId, TaskData)>>;
	async fn update_task(&self, id: TaskId, task: &TaskMeta<S>) -> ClResult<()>;
	async fn find_completed_deps(&self, deps: &[TaskId]) -> ClResult<Vec<TaskId>>;
}

// InMemoryTaskStore
//*******************
pub struct InMemoryTaskStore {
	last_id: Mutex<TaskId>,
}

impl InMemoryTaskStore {
	pub fn new() -> Arc<Self> {
		Arc::new(Self { last_id: Mutex::new(0) })
	}
}

#[async_trait]
impl<S: Clone> TaskStore<S> for InMemoryTaskStore {
	async fn add(&self, _task: &TaskMeta<S>, _key: Option<&str>) -> ClResult<TaskId> {
		let mut last_id = self.last_id.lock();
		*last_id += 1;
		Ok(*last_id)
	}

	async fn finished(&self, _id: TaskId, _output: &str) -> ClResult<()> {
		Ok(())
	}

	async fn load(&self) -> ClResult<Vec<TaskData>> {
		Ok(vec![])
	}

	async fn update_task_error(
		&self,
		_task_id: TaskId,
		_output: &str,
		_next_at: Option<Timestamp>,
	) -> ClResult<()> {
		Ok(())
	}

	async fn find_by_key(&self, _key: &str) -> ClResult<Option<(TaskId, TaskData)>> {
		// In-memory store doesn't support persistence or keys
		Ok(None)
	}

	async fn update_task(&self, _id: TaskId, _task: &TaskMeta<S>) -> ClResult<()> {
		// In-memory store doesn't support persistence
		Ok(())
	}

	async fn find_completed_deps(&self, _deps: &[TaskId]) -> ClResult<Vec<TaskId>> {
		Ok(vec![])
	}
}

// MetaAdapterTaskStore
//**********************
pub struct MetaAdapterTaskStore {
	meta_adapter: Arc<dyn meta_adapter::MetaAdapter>,
}

impl MetaAdapterTaskStore {
	pub fn new(meta_adapter: Arc<dyn meta_adapter::MetaAdapter>) -> Arc<Self> {
		Arc::new(Self { meta_adapter })
	}
}

#[async_trait]
impl<S: Clone> TaskStore<S> for MetaAdapterTaskStore {
	async fn add(&self, task: &TaskMeta<S>, key: Option<&str>) -> ClResult<TaskId> {
		let id = self
			.meta_adapter
			.create_task(task.task.kind_of(), key, &task.task.serialize(), &task.deps)
			.await?;

		// Store cron schedule if present
		if let Some(cron) = &task.cron {
			self.meta_adapter
				.update_task(
					id,
					&meta_adapter::TaskPatch {
						cron: Patch::Value(cron.to_cron_string()),
						..Default::default()
					},
				)
				.await?;
		}

		Ok(id)
	}

	async fn finished(&self, id: TaskId, output: &str) -> ClResult<()> {
		self.meta_adapter.update_task_finished(id, output).await
	}

	async fn load(&self) -> ClResult<Vec<TaskData>> {
		let tasks = self.meta_adapter.list_tasks(meta_adapter::ListTaskOptions::default()).await?;
		let tasks = tasks
			.into_iter()
			.map(|t| TaskData {
				id: t.task_id,
				kind: t.kind,
				status: match t.status {
					'P' => TaskStatus::Pending,
					'F' => TaskStatus::Completed,
					// 'E' or unknown status = Failed
					_ => TaskStatus::Failed,
				},
				input: t.input,
				deps: t.deps,
				retry_data: t.retry,
				cron_data: t.cron,
				next_at: t.next_at,
			})
			.collect();
		Ok(tasks)
	}

	async fn update_task_error(
		&self,
		task_id: TaskId,
		output: &str,
		next_at: Option<Timestamp>,
	) -> ClResult<()> {
		self.meta_adapter.update_task_error(task_id, output, next_at).await
	}

	async fn find_by_key(&self, key: &str) -> ClResult<Option<(TaskId, TaskData)>> {
		let task_opt = self.meta_adapter.find_task_by_key(key).await?;

		match task_opt {
			Some(t) => Ok(Some((
				t.task_id,
				TaskData {
					id: t.task_id,
					kind: t.kind,
					status: match t.status {
						'P' => TaskStatus::Pending,
						'F' => TaskStatus::Completed,
						// 'E' or unknown status = Failed
						_ => TaskStatus::Failed,
					},
					input: t.input,
					deps: t.deps,
					retry_data: t.retry,
					cron_data: t.cron,
					next_at: t.next_at,
				},
			))),
			None => Ok(None),
		}
	}

	async fn update_task(&self, id: TaskId, task: &TaskMeta<S>) -> ClResult<()> {
		use cloudillo_types::types::Patch;

		// Build TaskPatch from TaskMeta
		let mut patch = meta_adapter::TaskPatch {
			input: Patch::Value(task.task.serialize()),
			next_at: match task.next_at {
				Some(ts) => Patch::Value(ts),
				None => Patch::Null,
			},
			..Default::default()
		};

		// Update deps
		if !task.deps.is_empty() {
			patch.deps = Patch::Value(task.deps.clone());
		}

		// Update retry policy
		if let Some(ref retry) = task.retry {
			let retry_str = format!(
				"{},{},{},{}",
				task.retry_count, retry.wait_min_max.0, retry.wait_min_max.1, retry.times
			);
			patch.retry = Patch::Value(retry_str);
		}

		// Update cron schedule
		if let Some(ref cron) = task.cron {
			patch.cron = Patch::Value(cron.to_cron_string());
		}

		self.meta_adapter.update_task(id, &patch).await
	}

	async fn find_completed_deps(&self, deps: &[TaskId]) -> ClResult<Vec<TaskId>> {
		self.meta_adapter.find_completed_deps(deps).await
	}
}

// Task metadata
type TaskBuilder<S> = dyn Fn(TaskId, &str) -> ClResult<Arc<dyn Task<S>>> + Send + Sync;

#[derive(Debug, Clone)]
pub struct RetryPolicy {
	wait_min_max: (u64, u64),
	times: u16,
}

impl Default for RetryPolicy {
	fn default() -> Self {
		Self { wait_min_max: (60, 3600), times: 10 }
	}
}

impl RetryPolicy {
	/// Create a new RetryPolicy with custom min/max backoff and number of retries
	pub fn new(wait_min_max: (u64, u64), times: u16) -> Self {
		Self { wait_min_max, times }
	}

	/// Calculate exponential backoff in seconds: min * (2^attempt), capped at max
	///
	/// `times` is a `u16` and `new` is public, so a policy can ask for an attempt
	/// count past the width of the shift. Saturating there rather than shifting
	/// out is what keeps this panic-free in debug builds.
	pub fn calculate_backoff(&self, attempt_count: u16) -> u64 {
		let (min, max) = self.wait_min_max;
		let backoff = 1u64
			.checked_shl(u32::from(attempt_count))
			.map_or(u64::MAX, |factor| min.saturating_mul(factor));
		backoff.min(max)
	}

	/// Check if we should continue retrying
	pub fn should_retry(&self, attempt_count: u16) -> bool {
		attempt_count < self.times
	}
}

// TaskSchedulerBuilder - Fluent API for task scheduling
//************************************************************
pub struct TaskSchedulerBuilder<'a, S: Clone> {
	scheduler: &'a Scheduler<S>,
	task: Arc<dyn Task<S>>,
	key: Option<String>,
	next_at: Option<Timestamp>,
	deps: Vec<TaskId>,
	retry: Option<RetryPolicy>,
	cron: Option<CronSchedule>,
	run_on_startup: bool,
}

impl<'a, S: Clone + Send + Sync + 'static> TaskSchedulerBuilder<'a, S> {
	/// Create a new builder for scheduling a task
	fn new(scheduler: &'a Scheduler<S>, task: Arc<dyn Task<S>>) -> Self {
		Self {
			scheduler,
			task,
			key: None,
			next_at: None,
			deps: Vec::new(),
			retry: None,
			cron: None,
			run_on_startup: false,
		}
	}

	/// Set a string key for task identification
	pub fn key(mut self, key: impl Into<String>) -> Self {
		self.key = Some(key.into());
		self
	}

	/// Schedule for a specific absolute timestamp
	pub fn schedule_at(mut self, timestamp: Timestamp) -> Self {
		self.next_at = Some(timestamp);
		self
	}

	/// Schedule after a relative delay (in seconds)
	pub fn schedule_after(mut self, seconds: i64) -> Self {
		self.next_at = Some(Timestamp::from_now(seconds));
		self
	}

	/// Add task dependencies - task waits for all of these to complete
	pub fn depend_on(mut self, deps: Vec<TaskId>) -> Self {
		self.deps = deps;
		self
	}

	/// Add a single task dependency
	pub fn depends_on(mut self, dep: TaskId) -> Self {
		self.deps.push(dep);
		self
	}

	/// Enable automatic retry with exponential backoff
	pub fn with_retry(mut self, policy: RetryPolicy) -> Self {
		self.retry = Some(policy);
		self
	}

	// ===== Cron Scheduling Methods =====

	/// Schedule task with cron expression
	/// Example: `.cron("0 9 * * *")` for 9 AM daily
	///
	/// A bad expression is logged and ignored rather than propagated — the
	/// builder is infallible by design. But ignoring it silently degrades a
	/// recurring task into a one-shot: `add_queue` sees `next_at: None`, runs the
	/// task once immediately, and the finish handler retires the row as completed,
	/// so it never comes back. Expressions that reach here from a setting must
	/// also be validated at write time (see `core_settings::cron_validator`); the
	/// `error!` is what makes an already-stored bad value visible.
	pub fn cron(mut self, expr: impl Into<String>) -> Self {
		let expr = expr.into();
		match CronSchedule::parse(&expr) {
			Ok(cron_schedule) => {
				self.next_at = cron_schedule.next_execution(Timestamp::now()).ok();
				self.cron = Some(cron_schedule);
			}
			Err(e) => error!(
				"scheduler: task '{}' has an unusable cron expression {:?} ({}); it will run \
				 once instead of recurring",
				self.task.kind_of(),
				expr,
				e
			),
		}
		self
	}

	/// Schedule task daily at specified time
	/// Example: `.daily_at(2, 30)` for 2:30 AM daily
	pub fn daily_at(mut self, hour: u8, minute: u8) -> Self {
		if hour <= 23 && minute <= 59 {
			let expr = format!("{} {} * * *", minute, hour);
			if let Ok(cron_schedule) = CronSchedule::parse(&expr) {
				// Calculate initial next_at from cron schedule
				// Use .ok() - cron was just parsed successfully, should never fail
				self.next_at = cron_schedule.next_execution(Timestamp::now()).ok();
				self.cron = Some(cron_schedule);
			}
		}
		self
	}

	/// Schedule task weekly at specified day and time
	/// Example: `.weekly_at(1, 14, 30)` for Mondays at 2:30 PM
	/// weekday: 0=Sunday, 1=Monday, ..., 6=Saturday
	pub fn weekly_at(mut self, weekday: u8, hour: u8, minute: u8) -> Self {
		if weekday <= 6 && hour <= 23 && minute <= 59 {
			let expr = format!("{} {} * * {}", minute, hour, weekday);
			if let Ok(cron_schedule) = CronSchedule::parse(&expr) {
				// Calculate initial next_at from cron schedule
				// Use .ok() - cron was just parsed successfully, should never fail
				self.next_at = cron_schedule.next_execution(Timestamp::now()).ok();
				self.cron = Some(cron_schedule);
			}
		}
		self
	}

	/// Opt-in: if this is a cron task and a scheduled run was missed
	/// while the server was down (or this is the first time the task
	/// is being registered), run it once immediately on startup before
	/// resuming the normal cron schedule.
	pub fn run_on_startup(mut self) -> Self {
		self.run_on_startup = true;
		self
	}

	/// Execute the scheduled task immediately
	pub async fn now(self) -> ClResult<TaskId> {
		self.schedule().await
	}

	/// Execute the scheduled task at a specific timestamp
	pub async fn at(mut self, ts: Timestamp) -> ClResult<TaskId> {
		self.next_at = Some(ts);
		self.schedule().await
	}

	/// Execute the scheduled task after a delay (in seconds)
	pub async fn after(mut self, seconds: i64) -> ClResult<TaskId> {
		self.next_at = Some(Timestamp::from_now(seconds));
		self.schedule().await
	}

	/// Execute the scheduled task with automatic retry using default policy
	pub async fn with_automatic_retry(mut self) -> ClResult<TaskId> {
		self.retry = Some(RetryPolicy::default());
		self.schedule().await
	}

	/// Execute the task with all configured options - main terminal method
	pub async fn schedule(self) -> ClResult<TaskId> {
		self.scheduler
			.schedule_task_impl(
				self.task,
				self.key.as_deref(),
				self.next_at,
				if self.deps.is_empty() { None } else { Some(self.deps) },
				self.retry,
				self.cron,
				self.run_on_startup,
			)
			.await
	}
}

#[derive(Debug, Clone)]
pub struct TaskMeta<S: Clone> {
	pub task: Arc<dyn Task<S>>,
	pub next_at: Option<Timestamp>,
	pub deps: Vec<TaskId>,
	retry_count: u16,
	pub retry: Option<RetryPolicy>,
	pub cron: Option<CronSchedule>,
	/// Set while this task is running, by a keyed re-request that arrived in
	/// flight.
	///
	/// The re-request cannot start a second body — that is what the in-place
	/// metadata update in [`Scheduler::schedule_task_impl`] prevents — and, unlike
	/// a cron task, a one-shot has no reschedule step that would pick the request
	/// up. Without this the requested run is simply dropped, so the finish handler
	/// consults it and re-queues instead of finishing the task.
	///
	/// It lives here rather than in a side table so that reading it, reading the
	/// metadata the request wrote, and closing the request window are one
	/// operation under one lock. **Invariant:** true only for an entry currently
	/// in `tasks_running`.
	rerun_requested: bool,
}

type TaskBuilderRegistry<S> = HashMap<&'static str, Box<TaskBuilder<S>>>;
type ScheduledTaskMap<S> = BTreeMap<(Timestamp, TaskId), TaskMeta<S>>;

// Scheduler
#[derive(Clone)]
pub struct Scheduler<S: Clone> {
	task_builders: Arc<RwLock<TaskBuilderRegistry<S>>>,
	store: Arc<dyn TaskStore<S>>,
	tasks_running: Arc<Mutex<HashMap<TaskId, TaskMeta<S>>>>,
	tasks_waiting: Arc<Mutex<HashMap<TaskId, TaskMeta<S>>>>,
	task_dependents: Arc<Mutex<HashMap<TaskId, Vec<TaskId>>>>,
	tasks_scheduled: Arc<Mutex<ScheduledTaskMap<S>>>,
	tx_finish: flume::Sender<TaskId>,
	rx_finish: flume::Receiver<TaskId>,
	notify_schedule: Arc<tokio::sync::Notify>,
}

impl<S: Clone + Send + Sync + 'static> Scheduler<S> {
	pub fn new(store: Arc<dyn TaskStore<S>>) -> Arc<Self> {
		let (tx_finish, rx_finish) = flume::unbounded();

		let scheduler = Self {
			task_builders: Arc::new(RwLock::new(HashMap::new())),
			store,
			tasks_running: Arc::new(Mutex::new(HashMap::new())),
			tasks_waiting: Arc::new(Mutex::new(HashMap::new())),
			task_dependents: Arc::new(Mutex::new(HashMap::new())),
			tasks_scheduled: Arc::new(Mutex::new(BTreeMap::new())),
			tx_finish,
			rx_finish,
			notify_schedule: Arc::new(tokio::sync::Notify::new()),
		};

		//scheduler.run(rx_finish)?;

		Arc::new(scheduler)
	}

	pub fn start(&self, state: S) {
		// Handle finished tasks and dependencies
		let schedule = self.clone();
		let stat = state.clone();
		let rx_finish = self.rx_finish.clone();

		tokio::spawn(async move {
			while let Ok(id) = rx_finish.recv_async().await {
				debug!("Completed task {} (notified)", id);

				// Taken out of `tasks_running` up front, then decided. Safe because by
				// the time this event arrives the task body has *already returned* —
				// removing the id cannot let a second body start beside a running one,
				// which is what the old transition bookkeeping existed to police. It is
				// also what closes the re-request window atomically: once the id is out
				// of the map, `schedule_task_impl`'s in-place update misses and the
				// request queues itself through the ordinary path, so no request can be
				// recorded that this handler will not see.
				let Some(task_meta) = schedule.take_running(id) else {
					warn!("Completed task {} not found in running queue", id);
					continue;
				};

				// Before the cron test on purpose: a cron task re-requested as a
				// one-shot runs now, and since `rerun_meta` keeps the `cron` field the
				// run after it resumes recurring.
				if task_meta.rerun_requested {
					// A keyed task re-requested while this run was in flight was only
					// updated in place — `schedule_task_impl` deliberately does not start
					// a second body next to the running one. This is where the requested
					// run happens, and `task_meta` *is* whatever that update wrote.
					info!("Task {} was re-requested while running; running again", id);
					let mut rerun_meta = task_meta;
					rerun_meta.next_at = None;
					rerun_meta.retry_count = 0;
					rerun_meta.rerun_requested = false;
					if let Err(e) = schedule.add_queue(id, rerun_meta).await {
						error!(
							"Failed to re-queue task {} after in-flight update: {} - task lost!",
							id, e
						);
					}
				} else if let Some(cron) = &task_meta.cron {
					match cron.next_execution(Timestamp::now()) {
						Ok(next_at) => {
							info!(
								"Recurring task {} completed, scheduling next execution at {}",
								id, next_at
							);
							let mut updated_meta = task_meta.clone();
							updated_meta.next_at = Some(next_at);
							// Persist the new `next_at` and keep the row `'P'`.
							if let Err(e) = schedule.store.update_task(id, &updated_meta).await {
								error!("Failed to update recurring task {} next_at: {}", id, e);
							}
							if let Err(e) = schedule.add_queue(id, updated_meta).await {
								error!(
									"Failed to reschedule recurring task {}: {} - task lost!",
									id, e
								);
							}
						}
						Err(e) => {
							error!(
								"Failed to calculate next execution for recurring task {}: {} - task will not reschedule",
								id, e
							);
							// Cannot reschedule, so finish it. Falls through to the
							// dependents release rather than `continue`-ing past it: the run
							// did complete, so its dependents are owed their release.
							if let Err(e) = schedule.store.finished(id, "").await {
								error!("Failed to mark task {} as finished: {}", id, e);
							}
						}
					}
				} else if let Err(e) = schedule.store.finished(id, "").await {
					// Removal from `tasks_running` already happened, so a failure here
					// strands nothing in memory. Recovery is the persisted row, which
					// stays `status='P'` and is re-queued by `load()` at next start.
					//
					// Known open race: a request landing after the take but during this
					// await queues itself through the ordinary path, and `mark_finished`
					// then stamps the row `'F'` underneath it — so a further re-request
					// for that key mints a *new* id and row, a crash during the rerun
					// loses it, and the rerun's own `finished` is a silent no-op. Closing
					// it needs a store-level re-open (a patch back to `status='P'`, or
					// making `finished` conditional on no successor).
					error!("Failed to mark task {} as finished: {}", id, e);
				}

				// Handle dependencies of finished task using atomic release method
				for (dep_id, dep_task_meta) in schedule.release_dependents(id) {
					// Add to running queue before spawning
					schedule.tasks_running.lock().insert(dep_id, dep_task_meta.clone());
					schedule.spawn_task(
						stat.clone(),
						dep_task_meta.task.clone(),
						dep_id,
						dep_task_meta,
					);
				}
			}
		});

		// Handle scheduled tasks
		let schedule = self.clone();
		tokio::spawn(async move {
			loop {
				let is_empty = schedule.tasks_scheduled.lock().is_empty();
				if is_empty {
					schedule.notify_schedule.notified().await;
				}
				let time = Timestamp::now();
				if let Some((timestamp, _id)) = loop {
					let mut tasks_scheduled = schedule.tasks_scheduled.lock();
					if let Some((&(timestamp, id), _)) = tasks_scheduled.first_key_value() {
						let (timestamp, id) = (timestamp, id);
						if timestamp <= Timestamp::now() {
							debug!("Spawning task id {} (from schedule)", id);
							if let Some(task) = tasks_scheduled.remove(&(timestamp, id)) {
								let mut tasks_running = schedule.tasks_running.lock();
								tasks_running.insert(id, task.clone());
								schedule.spawn_task(state.clone(), task.task.clone(), id, task);
							} else {
								error!("Task disappeared while being removed from schedule");
								break None;
							}
						} else {
							break Some((timestamp, id));
						}
					} else {
						break None;
					}
				} {
					let diff = timestamp.0 - time.0;
					let wait =
						tokio::time::Duration::from_secs(u64::try_from(diff).unwrap_or_default());
					tokio::select! {
						() = tokio::time::sleep(wait) => (), () = schedule.notify_schedule.notified() => ()
					};
				}
			}
		});

		let schedule = self.clone();
		tokio::spawn(async move {
			// Only fatal failures reach here — `load` contains per-row ones itself.
			// A scheduler that loaded nothing must say so rather than start empty
			// and look healthy.
			if let Err(e) = schedule.load().await {
				error!("scheduler: failed to load persisted tasks: {}", e);
			}
		});
	}

	fn register_builder(&self, name: &'static str, builder: &'static TaskBuilder<S>) {
		let mut task_builders = self.task_builders.write();
		task_builders.insert(name, Box::new(builder));
	}

	pub fn register<T: Task<S>>(&self) -> ClResult<&Self> {
		info!("Registering task type {}", T::kind());
		self.register_builder(T::kind(), &|id: TaskId, params: &str| T::build(id, params));
		Ok(self)
	}

	/// Create a builder for scheduling a task using the fluent API
	pub fn task(&self, task: Arc<dyn Task<S>>) -> TaskSchedulerBuilder<'_, S> {
		TaskSchedulerBuilder::new(self, task)
	}

	/// Internal method to schedule a task with all options
	/// This is the core implementation used by the builder pattern
	#[allow(clippy::too_many_arguments)]
	async fn schedule_task_impl(
		&self,
		task: Arc<dyn Task<S>>,
		key: Option<&str>,
		next_at: Option<Timestamp>,
		deps: Option<Vec<TaskId>>,
		retry: Option<RetryPolicy>,
		cron: Option<CronSchedule>,
		run_on_startup: bool,
	) -> ClResult<TaskId> {
		// Look up any existing task by key once; reuse for both the
		// run_on_startup decision and the dedup branch below.
		let existing = if let Some(k) = key { self.store.find_by_key(k).await? } else { None };

		// Resolve effective next_at, factoring in run_on_startup for cron tasks.
		let effective_next_at = if run_on_startup && cron.is_some() {
			match &existing {
				Some((_existing_id, existing_data)) => {
					// Task exists from a previous run. If its persisted
					// next_at has already passed (or is missing), we missed
					// a run while down — fire now. Otherwise honor the
					// persisted future schedule.
					match existing_data.next_at {
						Some(persisted) if persisted > Timestamp::now() => next_at,
						_ => Some(Timestamp::now()),
					}
				}
				None => Some(Timestamp::now()), // fresh registration → run now
			}
		} else {
			next_at
		};

		let task_meta = TaskMeta {
			task: task.clone(),
			next_at: effective_next_at,
			deps: deps.clone().unwrap_or_default(),
			retry_count: 0,
			retry,
			cron,
			rerun_requested: false,
		};

		// Check if a task with this key already exists (key-based deduplication)
		if let Some(key) = key
			&& let Some((existing_id, existing_data)) = existing
		{
			let new_serialized = task.serialize();
			let existing_serialized = existing_data.input.as_ref();
			let params_changed = new_serialized != existing_serialized;

			if params_changed {
				info!(
					"Updating recurring task '{}' (id={}) - parameters changed",
					key, existing_id
				);
				debug!("  Old params: {}", existing_serialized);
				debug!("  New params: {}", new_serialized);
			} else {
				info!(
					"Recurring task '{}' already exists with identical parameters (id={})",
					key, existing_id
				);
			}

			// The running check comes before the identical/changed split, not inside
			// the changed branch: a re-request with *identical* parameters is the
			// common shape — `IndexDocumentTask { tn_id, file_id }` serializes the
			// same way on every edit of the same file — and carries exactly as much
			// "run it again" intent as a changed one.
			//
			// A *running* task is updated in place and left alone. Going through
			// `remove_from_queues` first would take it out of `tasks_running`, the
			// very map `add_queue`'s already-running check consults, so the check
			// would miss and a second body would start alongside the one still
			// executing — for `core.db_maintenance:manual`, two concurrent VACUUMs
			// and two `tx_finish` events for one task id.
			//
			// The run in flight then reschedules itself from the new parameters —
			// but only if it is a *cron* task. A keyed one-shot takes the
			// `store.finished` branch instead, so the requested run would never
			// happen; those mark the running entry `rerun_requested` and let the
			// finish handler re-queue.
			//
			// The guard is confined to this block: it is not `Send`, so holding it
			// across the `await` below would make the whole handler non-`Send`.
			let was_running = {
				let mut running = self.tasks_running.lock();
				match running.get_mut(&existing_id) {
					Some(existing_meta) => {
						debug!("Task {} is running; updating metadata in place", existing_id);
						let rerun = existing_meta.rerun_requested || task_meta.cron.is_none();
						*existing_meta = task_meta.clone();
						existing_meta.rerun_requested = rerun;
						true
					}
					None => false,
				}
			};
			if was_running {
				self.store.update_task(existing_id, &task_meta).await?;
				return Ok(existing_id);
			}

			if params_changed {
				self.remove_from_queues(existing_id);
			}

			// Update the task in database with the current parameters, cron and
			// next_at (any of which may differ from what is stored).
			self.store.update_task(existing_id, &task_meta).await?;

			// Ensure the task is queued — it may be loaded from the DB but not yet
			// in a queue — with the updated parameters.
			self.add_queue(existing_id, task_meta).await?;

			return Ok(existing_id);
		}

		// No existing task - create new one
		let id = self.store.add(&task_meta, key).await?;
		self.add_queue(id, task_meta).await
	}

	pub async fn add(&self, task: Arc<dyn Task<S>>) -> ClResult<TaskId> {
		self.task(task).now().await
	}

	pub async fn add_queue(&self, id: TaskId, task_meta: TaskMeta<S>) -> ClResult<TaskId> {
		debug_assert!(
			!task_meta.rerun_requested,
			"a queued task must not carry a pending rerun request"
		);
		// If task is already running, update its metadata (especially for cron updates)
		// but don't add to scheduled queue (it will reschedule on completion)
		{
			let mut running = self.tasks_running.lock();
			if let Some(existing_meta) = running.get_mut(&id) {
				debug!(
					"Task {} is already running, updating metadata (will reschedule on completion)",
					id
				);
				// Update the running task's metadata so it has the latest cron schedule.
				// The rerun flag records a request that has not run yet, so a metadata
				// refresh must carry it across rather than drop it.
				let rerun = existing_meta.rerun_requested;
				*existing_meta = task_meta;
				existing_meta.rerun_requested = rerun;
				return Ok(id);
			}
		}

		// Remove from other queues if present (prevents duplicate entries with different timestamps)
		{
			let mut scheduled = self.tasks_scheduled.lock();
			if let Some(key) = scheduled
				.iter()
				.find(|((_, tid), _)| *tid == id)
				.map(|((ts, tid), _)| (*ts, *tid))
			{
				scheduled.remove(&key);
				debug!("Removed existing scheduled entry for task {} before re-queueing", id);
			}
		}
		{
			let mut waiting = self.tasks_waiting.lock();
			if waiting.remove(&id).is_some() {
				debug!("Removed existing waiting entry for task {} before re-queueing", id);
			}
		}

		let deps = task_meta.deps.clone();

		// VALIDATION: Tasks with dependencies should NEVER be in tasks_scheduled
		if !deps.is_empty() && task_meta.next_at.is_some() {
			warn!(
				"Task {} has both dependencies and scheduled time - ignoring next_at, placing in waiting queue",
				id
			);
			// Force to tasks_waiting instead
			self.tasks_waiting.lock().insert(id, task_meta);
			debug!("Task {} is waiting for {:?}", id, &deps);
			for dep in &deps {
				self.task_dependents.lock().entry(*dep).or_default().push(id);
			}

			self.check_and_resolve_completed_deps(id, &deps).await?;
			return Ok(id);
		}

		if deps.is_empty() && task_meta.next_at.unwrap_or(Timestamp(0)) < Timestamp::now() {
			debug!("Spawning task {}", id);
			self.tasks_scheduled.lock().insert((Timestamp(0), id), task_meta);
			self.notify_schedule.notify_one();
		} else if let Some(next_at) = task_meta.next_at {
			debug!("Scheduling task {} for {}", id, next_at);
			self.tasks_scheduled.lock().insert((next_at, id), task_meta);
			self.notify_schedule.notify_one();
		} else {
			self.tasks_waiting.lock().insert(id, task_meta);
			debug!("Task {} is waiting for {:?}", id, &deps);
			for dep in &deps {
				self.task_dependents.lock().entry(*dep).or_default().push(id);
			}

			self.check_and_resolve_completed_deps(id, &deps).await?;
		}
		Ok(id)
	}

	/// After registering deps, check if any completed in the meantime.
	/// If all deps are satisfied, move the task from waiting → scheduled.
	async fn check_and_resolve_completed_deps(&self, id: TaskId, deps: &[TaskId]) -> ClResult<()> {
		let completed_deps = self.store.find_completed_deps(deps).await?;
		if completed_deps.is_empty() {
			return Ok(());
		}
		let mut waiting = self.tasks_waiting.lock();
		if let Some(task_meta) = waiting.get_mut(&id) {
			for dep in &completed_deps {
				task_meta.deps.retain(|d| *d != *dep);
			}
			if task_meta.deps.is_empty()
				&& let Some(ready_task) = waiting.remove(&id)
			{
				drop(waiting);
				let mut dependents = self.task_dependents.lock();
				for dep in deps {
					if let Some(dep_list) = dependents.get_mut(dep) {
						dep_list.retain(|d| *d != id);
						if dep_list.is_empty() {
							dependents.remove(dep);
						}
					}
				}
				drop(dependents);
				debug!("Task {} deps already completed, scheduling immediately", id);
				self.tasks_scheduled.lock().insert((Timestamp(0), id), ready_task);
				self.notify_schedule.notify_one();
			}
		}
		Ok(())
	}

	/// Remove a task from all internal queues (waiting, scheduled, running)
	/// Returns the removed TaskMeta if found
	fn remove_from_queues(&self, task_id: TaskId) -> Option<TaskMeta<S>> {
		// Try tasks_waiting
		if let Some(task_meta) = self.tasks_waiting.lock().remove(&task_id) {
			debug!("Removed task {} from waiting queue for update", task_id);
			return Some(task_meta);
		}

		// Try tasks_scheduled (need to find by task_id in BTreeMap)
		{
			let mut scheduled = self.tasks_scheduled.lock();
			if let Some(key) = scheduled
				.iter()
				.find(|((_, id), _)| *id == task_id)
				.map(|((ts, id), _)| (*ts, *id))
				&& let Some(task_meta) = scheduled.remove(&key)
			{
				debug!("Removed task {} from scheduled queue for update", task_id);
				return Some(task_meta);
			}
		}

		// Try tasks_running (should rarely happen, but handle it)
		if let Some(task_meta) = self.tasks_running.lock().remove(&task_id) {
			warn!("Removed task {} from running queue during update", task_id);
			return Some(task_meta);
		}

		None
	}

	/// Release all dependent tasks of a completed task
	/// This method safely handles dependency cleanup and spawning
	fn release_dependents(&self, completed_task_id: TaskId) -> Vec<(TaskId, TaskMeta<S>)> {
		// Get list of dependents (atomic removal to prevent re-processing)
		let dependents = {
			let mut deps_map = self.task_dependents.lock();
			deps_map.remove(&completed_task_id).unwrap_or_default()
		};

		if dependents.is_empty() {
			return Vec::new(); // No dependents to release
		}

		debug!("Releasing {} dependents of completed task {}", dependents.len(), completed_task_id);

		let mut ready_to_spawn = Vec::new();

		// For each dependent, check and remove dependency
		for dependent_id in dependents {
			// Try tasks_waiting first (most common case for dependent tasks)
			{
				let mut waiting = self.tasks_waiting.lock();
				if let Some(task_meta) = waiting.get_mut(&dependent_id) {
					// Remove the completed task from dependencies
					task_meta.deps.retain(|x| *x != completed_task_id);

					// If all dependencies are cleared, remove and queue for spawning
					if task_meta.deps.is_empty() {
						if let Some(task_to_spawn) = waiting.remove(&dependent_id) {
							debug!(
								"Dependent task {} ready to spawn (all dependencies cleared)",
								dependent_id
							);
							ready_to_spawn.push((dependent_id, task_to_spawn));
						}
					} else {
						debug!(
							"Task {} still has {} remaining dependencies",
							dependent_id,
							task_meta.deps.len()
						);
					}
					continue;
				}
			}

			// Try tasks_scheduled if not in waiting (shouldn't happen with validation, but be defensive)
			{
				let mut scheduled = self.tasks_scheduled.lock();
				if let Some(scheduled_key) = scheduled
					.iter()
					.find(|((_, id), _)| *id == dependent_id)
					.map(|((ts, id), _)| (*ts, *id))
				{
					if let Some(task_meta) = scheduled.get_mut(&scheduled_key) {
						task_meta.deps.retain(|x| *x != completed_task_id);
						let remaining = task_meta.deps.len();
						if remaining == 0 {
							debug!(
								"Task {} in scheduled queue has no remaining dependencies",
								dependent_id
							);
						} else {
							debug!(
								"Task {} in scheduled queue has {} remaining dependencies",
								dependent_id, remaining
							);
						}
					}
					continue;
				}
			}

			// Task not found in any queue
			warn!(
				"Dependent task {} of completed task {} not found in any queue",
				dependent_id, completed_task_id
			);
		}

		ready_to_spawn
	}

	/// Re-queue every pending task the store holds.
	///
	/// Per-row failures are contained: an unregistered task kind, a malformed
	/// `retry` column or a rejected `add_queue` costs exactly that one row. The
	/// store's ordering is not partitioned by kind, so propagating out of the loop
	/// would let one bad row — a task kind an older build persisted and this one
	/// does not register — discard every ACME renewal, action fanout and email
	/// task behind it.
	///
	/// Only genuinely fatal failures propagate: the store read itself, and a
	/// poisoned `task_builders` lock.
	async fn load(&self) -> ClResult<()> {
		let tasks = self.store.load().await?;
		debug!("Loaded {} tasks from store", tasks.len());
		let (mut seen, mut queued, mut skipped) = (0usize, 0usize, 0usize);
		for t in tasks {
			if !matches!(t.status, TaskStatus::Pending) {
				continue;
			}
			seen += 1;
			let (id, kind) = (t.id, t.kind.clone());
			match self.load_one(t).await {
				Ok(()) => queued += 1,
				Err(e) => {
					skipped += 1;
					error!("scheduler: skipping persisted task {} ({}): {}", id, kind, e);
				}
			}
		}
		info!("scheduler: loaded {} pending tasks, {} queued, {} skipped", seen, queued, skipped);
		Ok(())
	}

	/// Re-queue one persisted task. Every failure here is per-row — see [`Self::load`].
	async fn load_one(&self, t: TaskData) -> ClResult<()> {
		debug!("Loading task {} {}", t.id, t.kind);
		let task = {
			let builder_map = self.task_builders.read();
			let builder = builder_map
				.get(t.kind.as_ref())
				.ok_or(Error::Internal(format!("task builder not registered: {}", t.kind)))?;
			builder(t.id, &t.input)?
		};
		let (retry_count, retry) = match t.retry_data {
			Some(retry_str) => {
				let (retry_count, retry_min, retry_max, retry_times) = retry_str
					.split(',')
					.collect_tuple()
					.ok_or(Error::Internal("invalid retry policy format".into()))?;
				let retry_count: u16 = retry_count
					.parse()
					.map_err(|_| Error::Internal("retry count must be u16".into()))?;
				let retry = RetryPolicy {
					wait_min_max: (
						retry_min
							.parse()
							.map_err(|_| Error::Internal("retry_min must be u64".into()))?,
						retry_max
							.parse()
							.map_err(|_| Error::Internal("retry_max must be u64".into()))?,
					),
					times: retry_times
						.parse()
						.map_err(|_| Error::Internal("retry times must be u64".into()))?,
				};
				debug!("Loaded retry policy: {:?}", retry);
				(retry_count, Some(retry))
			}
			_ => (0, None),
		};
		// Parse cron data if present. A persisted expression that no longer parses
		// is logged rather than dropped silently: the task keeps its `next_at` but
		// stops recurring, which is otherwise invisible.
		let cron = match t.cron_data.as_deref() {
			Some(cron_str) => match CronSchedule::parse(cron_str) {
				Ok(cron) => Some(cron),
				Err(e) => {
					error!(
						"scheduler: persisted task {} ({}) has an unusable cron expression \
						 {:?} ({}); it will not recur",
						t.id, t.kind, cron_str, e
					);
					None
				}
			},
			None => None,
		};

		let task_meta = TaskMeta {
			task,
			next_at: t.next_at,
			deps: t.deps.into(),
			retry_count,
			retry,
			cron,
			rerun_requested: false,
		};
		self.add_queue(t.id, task_meta).await.map(|_| ())
	}

	/// Take `id`'s entry out of `tasks_running`, metadata and rerun flag together.
	///
	/// Atomicity is the point. [`Self::schedule_task_impl`] records a rerun
	/// request by writing into this very entry, under this very lock, and only
	/// while the id is in the map — so removing the entry *is* the act of closing
	/// the request window, and whatever came with it is what the caller must
	/// honour.
	///
	/// Recovers from a poisoned lock rather than propagating: the finish handler
	/// has no error channel, and dropping the event strands the task.
	fn take_running(&self, id: TaskId) -> Option<TaskMeta<S>> {
		self.tasks_running.lock().remove(&id)
	}

	/// Drop any in-flight "re-run when this finishes" request for `id`.
	///
	/// Both terminal paths in [`Self::spawn_task`] go through here, so they cannot
	/// drift apart again. The retry path does not: its entry is already out of the
	/// map, so it clears the flag on the metadata it carries instead. Recovers
	/// from a poisoned lock rather than propagating: a stale flag left set re-runs
	/// a task that must not run again.
	fn clear_rerun_request(&self, id: TaskId) {
		let mut running = self.tasks_running.lock();
		if let Some(meta) = running.get_mut(&id) {
			meta.rerun_requested = false;
		}
	}

	fn spawn_task(&self, state: S, task: Arc<dyn Task<S>>, id: TaskId, task_meta: TaskMeta<S>) {
		let tx_finish = self.tx_finish.clone();
		let store = self.store.clone();
		let scheduler = self.clone();
		//let state = self.state.clone();
		tokio::spawn(async move {
			match task.run(&state).await {
				Ok(()) => {
					debug!("Task {} completed successfully", id);
					tx_finish.send(id).unwrap_or(());
				}
				Err(e) => {
					let is_retryable = e.is_retryable();
					if let Some(retry_policy) = &task_meta.retry {
						if is_retryable && retry_policy.should_retry(task_meta.retry_count) {
							let backoff = retry_policy.calculate_backoff(task_meta.retry_count);
							let next_at = Timestamp::from_now(backoff.cast_signed());

							info!(
								"Task {} failed (attempt {}/{}). Scheduling retry in {} seconds: {}",
								id,
								task_meta.retry_count + 1,
								retry_policy.times,
								backoff,
								e
							);

							// Update database with error and reschedule
							if let Err(err) =
								store.update_task_error(id, &e.to_string(), Some(next_at)).await
							{
								error!(
									"Failed to persist error for task {}: {} - retry not durable",
									id, err
								);
							}

							task.on_attempt_failed(&state, task_meta.retry_count, &e.to_string())
								.await;

							// Remove from running tasks (we're not sending finish
							// event), and take the *current* metadata out with it:
							// `task_meta` is the snapshot captured when this run was
							// spawned, and a keyed re-request may have updated the
							// task in place since. Retrying from the snapshot would
							// run the old parameters while the persisted row holds
							// the new ones. Falls back to the snapshot only if the
							// entry is already gone. The removal also recovers any
							// pending rerun request along with the metadata, and the
							// retry satisfies it — it carries the new parameters.
							let current_meta = scheduler.tasks_running.lock().remove(&id);

							// Re-queue task with incremented retry count. Counted off
							// the snapshot, not off `current_meta`: an in-place update
							// carries `retry_count: 0`, and taking that as the base
							// would hand the task a fresh retry budget on every
							// re-request.
							let mut retry_meta = current_meta.unwrap_or_else(|| task_meta.clone());
							retry_meta.retry_count = task_meta.retry_count + 1;
							retry_meta.next_at = Some(next_at);
							// The retry carries the new parameters, so an in-flight
							// re-request is already satisfied — left set, the flag would
							// run the task a second time once the retry ends. Cleared on
							// the metadata rather than through
							// `Scheduler::clear_rerun_request`: the entry is already out
							// of the map above, so a map-clearing call would be a no-op.
							retry_meta.rerun_requested = false;

							if let Err(err) = scheduler.add_queue(id, retry_meta).await {
								error!(
									"Failed to queue retry for task {}: {} - task lost!",
									id, err
								);
							}
						} else {
							// Max retries exhausted OR error is permanent
							if is_retryable {
								error!(
									"Task {} failed after {} retries: {}",
									id, task_meta.retry_count, e
								);
							} else {
								error!("Task {} failed permanently (non-retryable): {}", id, e);
							}
							// A cron task is not finished when a run fails — the finish
							// handler below reschedules it, and the row must stay `'P'`
							// or `find_by_key` and `load()` will lose it and mint a
							// duplicate on the next boot, re-firing `run_on_startup`.
							// A one-shot keeps `next_at: None` and so keeps `'E'`: a
							// fresh request there should mint a fresh row.
							let next_at = task_meta
								.cron
								.as_ref()
								.and_then(|c| c.next_execution(Timestamp::now()).ok());
							if let Err(err) =
								store.update_task_error(id, &e.to_string(), next_at).await
							{
								error!(
									"Failed to persist error for task {}: {} - retry not durable",
									id, err
								);
							}
							task.on_failed(&state, task_meta.retry_count, &e.to_string()).await;
							// Cleared for a different reason than in the retry branch
							// above, and the difference matters: `on_failed` has just
							// run its irreversible cleanup — `ActionVerifierTask` marks
							// the action `'F'`, "failed after retry exhaustion". Left
							// set, the finish handler would re-queue the task with
							// `retry_count: 0` against a row already declared
							// permanently failed, and every re-request landing during a
							// final attempt would renew the whole retry budget. A caller
							// that still wants the work done schedules a fresh task.
							scheduler.clear_rerun_request(id);
							tx_finish.send(id).unwrap_or(());
						}
					} else {
						// No retry policy - fail immediately. Terminal in the same
						// sense as the exhausted branch above, so the same reasoning
						// applies to the rerun flag.
						error!("Task {} failed: {}", id, e);
						// Same as the exhausted branch above: a cron task's row must
						// stay `'P'` with a live `next_at`, or the next boot cannot
						// find it and mints a duplicate.
						let next_at = task_meta
							.cron
							.as_ref()
							.and_then(|c| c.next_execution(Timestamp::now()).ok());
						if let Err(err) = store.update_task_error(id, &e.to_string(), next_at).await
						{
							error!(
								"Failed to persist error for task {}: {} - retry not durable",
								id, err
							);
						}
						task.on_failed(&state, 0, &e.to_string()).await;
						scheduler.clear_rerun_request(id);
						tx_finish.send(id).unwrap_or(());
					}
				}
			}
		});
	}

	/// Get health status of the scheduler
	/// Returns information about tasks in each queue and detects anomalies
	pub async fn health_check(&self) -> ClResult<SchedulerHealth> {
		let waiting_count = self.tasks_waiting.lock().len();
		let scheduled_count = self.tasks_scheduled.lock().len();
		let running_count = self.tasks_running.lock().len();
		let dependents_count = self.task_dependents.lock().len();

		// Check for anomalies
		let mut stuck_tasks = Vec::new();
		let mut tasks_with_missing_deps = Vec::new();

		// Check tasks_waiting for tasks with no dependencies (stuck)
		{
			// INVARIANT: health_check must never hold two queue locks at once. The
			// dispatch loop holds `tasks_scheduled` while taking `tasks_running`, so
			// probing them in the opposite order under `tasks_waiting` would deadlock.
			// Snapshot ids first; this probe is warning-only and already tolerates a
			// stale view.
			let running_ids: std::collections::HashSet<TaskId> =
				self.tasks_running.lock().keys().copied().collect();
			let scheduled_ids: std::collections::HashSet<TaskId> =
				self.tasks_scheduled.lock().keys().map(|(_, id)| *id).collect();

			let waiting = self.tasks_waiting.lock();

			for (id, task_meta) in waiting.iter() {
				if task_meta.deps.is_empty() {
					stuck_tasks.push(*id);
					warn!("SCHEDULER HEALTH: Task {} in waiting with no dependencies", id);
				} else {
					// Check if all dependencies still exist. Warning-only, and it can
					// now fire for a dep that is merely mid-finish-handling: the finish
					// handler takes the entry out of `tasks_running` before awaiting
					// `store.finished`, so the window this probe can land in spans that
					// await instead of ending just before it.
					for dep in &task_meta.deps {
						let dep_exists = waiting.contains_key(dep)
							|| running_ids.contains(dep)
							|| scheduled_ids.contains(dep);

						if !dep_exists {
							tasks_with_missing_deps.push((*id, *dep));
							warn!(
								"SCHEDULER HEALTH: Task {} depends on non-existent task {}",
								id, dep
							);
						}
					}
				}
			}
		}

		Ok(SchedulerHealth {
			waiting: waiting_count,
			scheduled: scheduled_count,
			running: running_count,
			dependents: dependents_count,
			stuck_tasks,
			tasks_with_missing_deps,
		})
	}
}

/// Health status of the scheduler
#[derive(Debug, Clone)]
pub struct SchedulerHealth {
	/// Number of tasks waiting for dependencies
	pub waiting: usize,
	/// Number of tasks scheduled for future execution
	pub scheduled: usize,
	/// Number of tasks currently running
	pub running: usize,
	/// Number of task entries in dependents map
	pub dependents: usize,
	/// IDs of tasks with no dependencies but still in waiting queue
	pub stuck_tasks: Vec<TaskId>,
	/// Pairs of (task_id, missing_dependency_id) where dependency doesn't exist
	pub tasks_with_missing_deps: Vec<(TaskId, TaskId)>,
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde::{Deserialize, Serialize};

	type State = Arc<Mutex<Vec<u8>>>;

	#[derive(Debug, Serialize, Deserialize)]
	struct TestTask {
		num: u8,
	}

	impl TestTask {
		pub fn new(num: u8) -> Arc<Self> {
			Arc::new(Self { num })
		}
	}

	#[async_trait]
	impl Task<State> for TestTask {
		fn kind() -> &'static str {
			"test"
		}

		fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<State>>> {
			let num: u8 = ctx
				.parse()
				.map_err(|_| Error::Internal("test task context must be u8".into()))?;
			let task = TestTask::new(num);
			Ok(task)
		}

		fn serialize(&self) -> String {
			self.num.to_string()
		}

		fn kind_of(&self) -> &'static str {
			"test"
		}

		async fn run(&self, state: &State) -> ClResult<()> {
			info!("Running task {}", self.num);
			tokio::time::sleep(std::time::Duration::from_millis(200 * u64::from(self.num))).await;
			info!("Completed task {}", self.num);
			state.lock().push(self.num);
			Ok(())
		}
	}

	#[derive(Debug, Clone)]
	struct FailingTask {
		id: u8,
		fail_count: u8,
		attempt: Arc<Mutex<u8>>,
		/// `attempt` argument of every `on_attempt_failed` call, in order.
		retried: Arc<Mutex<Vec<u16>>>,
		/// `attempts` argument of every (terminal) `on_failed` call, in order.
		gave_up: Arc<Mutex<Vec<u16>>>,
	}

	impl FailingTask {
		pub fn new(id: u8, fail_count: u8) -> Arc<Self> {
			Arc::new(Self {
				id,
				fail_count,
				attempt: Arc::new(Mutex::new(0)),
				retried: Arc::new(Mutex::new(Vec::new())),
				gave_up: Arc::new(Mutex::new(Vec::new())),
			})
		}
	}

	#[async_trait]
	impl Task<State> for FailingTask {
		fn kind() -> &'static str {
			"failing"
		}

		fn build(_id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<State>>> {
			let parts: Vec<&str> = ctx.split(',').collect();
			if parts.len() != 2 {
				return Err(Error::Internal("failing task context must have 2 parts".into()));
			}
			let id: u8 = parts[0]
				.parse()
				.map_err(|_| Error::Internal("failing task id must be u8".into()))?;
			let fail_count: u8 = parts[1]
				.parse()
				.map_err(|_| Error::Internal("failing task fail_count must be u8".into()))?;
			Ok(FailingTask::new(id, fail_count))
		}

		fn serialize(&self) -> String {
			format!("{},{}", self.id, self.fail_count)
		}

		fn kind_of(&self) -> &'static str {
			"failing"
		}

		async fn run(&self, state: &State) -> ClResult<()> {
			let mut attempt = self.attempt.lock();
			*attempt += 1;
			let current_attempt = *attempt;

			info!("FailingTask {} - attempt {}/{}", self.id, current_attempt, self.fail_count + 1);

			if current_attempt <= self.fail_count {
				error!("FailingTask {} failed on attempt {}", self.id, current_attempt);
				return Err(Error::ServiceUnavailable(format!("Task {} failed", self.id)));
			}

			info!("FailingTask {} succeeded on attempt {}", self.id, current_attempt);
			state.lock().push(self.id);
			Ok(())
		}

		async fn on_attempt_failed(&self, _state: &State, attempt: u16, _last_error: &str) {
			self.retried.lock().push(attempt);
		}

		async fn on_failed(&self, _state: &State, attempts: u16, _last_error: &str) {
			self.gave_up.lock().push(attempts);
		}
	}

	#[test]
	fn test_calculate_backoff() {
		let policy = RetryPolicy::new((10, 43200), 50);
		assert_eq!(policy.calculate_backoff(0), 10);
		assert_eq!(policy.calculate_backoff(1), 20);
		assert_eq!(policy.calculate_backoff(4), 160);
		// Past the cap.
		assert_eq!(policy.calculate_backoff(20), 43200);

		// `times` is a `u16` and `new` is public, so an attempt count wider than
		// the shift is reachable. It must saturate to `max`, not panic.
		let wide = RetryPolicy::new((10, 43200), 200);
		assert_eq!(wide.calculate_backoff(63), 43200);
		assert_eq!(wide.calculate_backoff(64), 43200);
		assert_eq!(wide.calculate_backoff(200), 43200);
		assert_eq!(wide.calculate_backoff(u16::MAX), 43200);
	}

	#[tokio::test]
	pub async fn test_scheduler() {
		let _ = tracing_subscriber::fmt().try_init();

		let task_store: Arc<dyn TaskStore<State>> = InMemoryTaskStore::new();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<TestTask>().unwrap();

		let _task1 = TestTask::new(1);
		let task2 = TestTask::new(1);
		let task3 = TestTask::new(1);

		let task2_id = scheduler.task(task2).schedule_after(2).schedule().await.unwrap();
		let task3_id = scheduler.add(task3).await.unwrap();
		scheduler
			.task(TestTask::new(1))
			.depend_on(vec![task2_id, task3_id])
			.schedule()
			.await
			.unwrap();

		tokio::time::sleep(std::time::Duration::from_secs(4)).await;
		let task4 = TestTask::new(1);
		let task5 = TestTask::new(1);
		scheduler.task(task4).schedule_after(2).schedule().await.unwrap();
		scheduler.task(task5).schedule_after(1).schedule().await.unwrap();

		tokio::time::sleep(std::time::Duration::from_secs(3)).await;

		let st = state.lock();
		info!("res: {}", st.len());
		let str_vec = st.iter().map(std::string::ToString::to_string).collect::<Vec<String>>();
		assert_eq!(str_vec.join(":"), "1:1:1:1:1");
	}

	#[tokio::test]
	pub async fn test_retry_with_backoff() {
		let _ = tracing_subscriber::fmt().try_init();

		let task_store: Arc<dyn TaskStore<State>> = InMemoryTaskStore::new();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<FailingTask>().unwrap();

		// Create a task that fails twice, then succeeds
		// With retry policy: min=1s, max=3600s, max_attempts=3
		let failing_task = FailingTask::new(42, 2);
		let retried = failing_task.retried.clone();
		let gave_up = failing_task.gave_up.clone();
		let retry_policy = RetryPolicy { wait_min_max: (1, 3600), times: 3 };

		scheduler.task(failing_task).with_retry(retry_policy).schedule().await.unwrap();

		// Wait for retries: 1s (1st fail) + 1s (2nd fail) + time for success
		// First attempt: immediate fail
		// Wait 1s (min backoff)
		// Second attempt: fail
		// Wait 2s (min * 2)
		// Third attempt: success
		tokio::time::sleep(std::time::Duration::from_secs(6)).await;

		{
			let st = state.lock();
			assert_eq!(st.len(), 1, "Task should have succeeded after retries");
			assert_eq!(st[0], 42);
		}

		// A task that fails before it succeeds must be able to tell the difference
		// between "failed, retrying" and "failed for good": `on_attempt_failed` sees
		// each retried failure with its zero-based attempt index, `on_failed` none.
		assert_eq!(
			retried.lock().as_slice(),
			&[0, 1],
			"Both retried failures should report their zero-based attempt index"
		);
		assert!(gave_up.lock().is_empty(), "on_failed is only for terminal failures");
	}

	// ===== Builder Pattern Tests =====

	#[tokio::test]
	pub async fn test_builder_simple_schedule() {
		let task_store: Arc<dyn TaskStore<State>> = InMemoryTaskStore::new();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<TestTask>().unwrap();

		// Test basic builder usage: .now()
		let task = TestTask::new(1);
		let id = scheduler.task(task).now().await.unwrap();

		assert!(id > 0, "Task ID should be positive");

		tokio::time::sleep(std::time::Duration::from_millis(500)).await;

		let st = state.lock();
		assert_eq!(st.len(), 1, "Task should have executed");
		assert_eq!(st[0], 1);
	}

	#[tokio::test]
	pub async fn test_builder_with_key() {
		let task_store: Arc<dyn TaskStore<State>> = InMemoryTaskStore::new();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<TestTask>().unwrap();

		// Test builder with key
		let task = TestTask::new(1);
		let _id = scheduler.task(task).key("my-task-key").now().await.unwrap();

		tokio::time::sleep(std::time::Duration::from_millis(500)).await;

		let st = state.lock();
		assert_eq!(st.len(), 1);
		assert_eq!(st[0], 1);
	}

	#[tokio::test]
	pub async fn test_builder_with_delay() {
		let task_store: Arc<dyn TaskStore<State>> = InMemoryTaskStore::new();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<TestTask>().unwrap();

		// Test builder with .after() convenience method
		let task = TestTask::new(1);
		let _id = scheduler
			.task(task)
			.after(1)  // 1 second delay
			.await
			.unwrap();

		// Should not have executed yet
		tokio::time::sleep(std::time::Duration::from_millis(500)).await;
		{
			let st = state.lock();
			assert_eq!(st.len(), 0, "Task should not execute yet");
		}

		// Wait for execution (1 sec delay + 200ms task sleep + buffer)
		tokio::time::sleep(std::time::Duration::from_millis(800)).await;

		{
			let st = state.lock();
			assert_eq!(st.len(), 1, "Task should have executed");
			assert_eq!(st[0], 1);
		}
	}

	#[tokio::test]
	pub async fn test_builder_with_dependencies() {
		let task_store: Arc<dyn TaskStore<State>> = InMemoryTaskStore::new();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<TestTask>().unwrap();

		// Create first task (sleeps 200ms)
		let task1 = TestTask::new(1);
		let id1 = scheduler.task(task1).now().await.unwrap();

		// Create second task (sleeps 400ms)
		let task2 = TestTask::new(1);
		let id2 = scheduler.task(task2).now().await.unwrap();

		// Create third task that depends on first two (sleeps 600ms)
		let task3 = TestTask::new(1);
		let _id3 = scheduler.task(task3).depend_on(vec![id1, id2]).schedule().await.unwrap();

		// Wait for all tasks: task1 200ms, task2 400ms, task3 600ms = ~1200ms
		tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

		let st = state.lock();
		// Should have all three tasks in execution order: 1 finishes first (200ms), then 2 (200ms), then 3 (200ms after both)
		let str_vec = st.iter().map(std::string::ToString::to_string).collect::<Vec<String>>();
		assert_eq!(str_vec.join(":"), "1:1:1");
	}

	#[tokio::test]
	pub async fn test_builder_with_retry() {
		let task_store: Arc<dyn TaskStore<State>> = InMemoryTaskStore::new();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<FailingTask>().unwrap();

		// Create task using builder with retry policy
		let failing_task = FailingTask::new(55, 1); // Fails once, succeeds second time
		let retry_policy = RetryPolicy { wait_min_max: (1, 3600), times: 3 };

		let _id = scheduler.task(failing_task).with_retry(retry_policy).schedule().await.unwrap();

		// Wait for retry cycle: 1 fail + 1s wait + 1 success
		tokio::time::sleep(std::time::Duration::from_secs(3)).await;

		let st = state.lock();
		assert_eq!(st.len(), 1);
		assert_eq!(st[0], 55);
	}

	#[tokio::test]
	pub async fn test_builder_with_automatic_retry() {
		let task_store: Arc<dyn TaskStore<State>> = InMemoryTaskStore::new();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<FailingTask>().unwrap();

		// Create task using builder with automatic retry (default policy)
		let failing_task = FailingTask::new(66, 1);
		let _id = scheduler.task(failing_task).with_automatic_retry().await.unwrap();

		// Wait for retry cycle with default policy (min=60s would be too long for test)
		// but we already tested retry logic thoroughly, just verify builder integration
		tokio::time::sleep(std::time::Duration::from_millis(500)).await;

		// The important part is that this compiles and integrates correctly
		let st = state.lock();
		// With default policy (min=60s), task shouldn't succeed in test timeframe
		// Just verify builder chaining works
		let _ = st.len(); // Verify state is accessible, but don't assert on timeout-dependent result
	}

	#[tokio::test]
	pub async fn test_builder_fluent_chaining() {
		let task_store: Arc<dyn TaskStore<State>> = InMemoryTaskStore::new();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<TestTask>().unwrap();

		// Create first dependencies
		let dep1 = scheduler.task(TestTask::new(1)).now().await.unwrap();
		let dep2 = scheduler.task(TestTask::new(1)).now().await.unwrap();

		// Test fluent chaining with multiple methods
		let retry_policy = RetryPolicy { wait_min_max: (1, 3600), times: 3 };

		let task = TestTask::new(1);
		let _id = scheduler
			.task(task)
			.key("complex-task")
			.schedule_after(0)  // Schedule immediately
			.depend_on(vec![dep1, dep2])
			.with_retry(retry_policy)
			.schedule()
			.await
			.unwrap();

		tokio::time::sleep(std::time::Duration::from_millis(800)).await;

		let st = state.lock();
		// Should have all tasks: 20:10 (immediate deps) then 30 (after deps)
		let str_vec = st.iter().map(std::string::ToString::to_string).collect::<Vec<String>>();
		assert_eq!(str_vec.join(":"), "1:1:1");
	}

	#[tokio::test]
	pub async fn test_builder_backward_compatibility() {
		let task_store: Arc<dyn TaskStore<State>> = InMemoryTaskStore::new();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<TestTask>().unwrap();

		// Test that old API still works
		let _id1 = scheduler.add(TestTask::new(1)).await.unwrap();

		// Test that new builder API works
		let _id2 = scheduler.task(TestTask::new(1)).now().await.unwrap();

		tokio::time::sleep(std::time::Duration::from_millis(800)).await;

		let st = state.lock();
		// Both old and new API should have executed
		assert_eq!(st.len(), 2);
		let str_vec = st.iter().map(std::string::ToString::to_string).collect::<Vec<String>>();
		assert_eq!(str_vec.join(":"), "1:1");
	}

	// ===== Phase 2: Integration Tests - Real-world scenarios =====

	#[tokio::test]
	pub async fn test_builder_pipeline_scenario() {
		// Simulates: Task 1 -> Task 2 (depends on 1) -> Task 3 (depends on 2)
		let task_store: Arc<dyn TaskStore<State>> = InMemoryTaskStore::new();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<TestTask>().unwrap();

		// Stage 1: Create initial task
		let id1 = scheduler.task(TestTask::new(1)).key("stage-1").now().await.unwrap();

		// Stage 2: Create task that depends on stage 1
		let id2 = scheduler
			.task(TestTask::new(1))
			.key("stage-2")
			.depend_on(vec![id1])
			.schedule()
			.await
			.unwrap();

		// Stage 3: Create task that depends on stage 2
		let _id3 = scheduler
			.task(TestTask::new(1))
			.key("stage-3")
			.depend_on(vec![id2])
			.schedule()
			.await
			.unwrap();

		// Wait for pipeline: 1(200ms) + 2(200ms) + 3(200ms) = 600ms
		tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

		let st = state.lock();
		// Should execute in order: 1, 2, 3
		let str_vec = st.iter().map(std::string::ToString::to_string).collect::<Vec<String>>();
		assert_eq!(str_vec.join(":"), "1:1:1");
	}

	#[tokio::test]
	pub async fn test_builder_multi_dependency_join() {
		// Simulates: Task 1 parallel with Task 2, then Task 3 waits for both
		let task_store: Arc<dyn TaskStore<State>> = InMemoryTaskStore::new();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<TestTask>().unwrap();

		// Parallel tasks
		let id1 = scheduler.task(TestTask::new(1)).now().await.unwrap();
		let id2 = scheduler.task(TestTask::new(1)).now().await.unwrap();

		// Join task - waits for both
		let _id3 = scheduler
			.task(TestTask::new(1))
			.depend_on(vec![id1, id2])
			.schedule()
			.await
			.unwrap();

		tokio::time::sleep(std::time::Duration::from_secs(1)).await;

		let st = state.lock();
		// 1 and 2 execute in parallel, then 3 executes after both
		let str_vec = st.iter().map(std::string::ToString::to_string).collect::<Vec<String>>();
		assert_eq!(str_vec.join(":"), "1:1:1");
	}

	#[tokio::test]
	pub async fn test_builder_scheduled_task_with_dependencies() {
		// Simulates: Task depends on earlier task AND is scheduled for future time
		let task_store: Arc<dyn TaskStore<State>> = InMemoryTaskStore::new();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<TestTask>().unwrap();

		// Immediate task
		let dep_id = scheduler.task(TestTask::new(1)).now().await.unwrap();

		// Task that waits for dependency AND scheduled delay
		let ts = Timestamp::from_now(1);
		let _task_id = scheduler
			.task(TestTask::new(1))
			.schedule_at(ts)
			.depend_on(vec![dep_id])
			.schedule()
			.await
			.unwrap();

		// Wait for dependency to complete but before scheduled time
		tokio::time::sleep(std::time::Duration::from_millis(300)).await;
		{
			let st = state.lock();
			assert_eq!(st.len(), 1); // Only dependency executed
		}

		// Wait for scheduled time (1s total from initial schedule)
		tokio::time::sleep(std::time::Duration::from_millis(800)).await;

		{
			let st = state.lock();
			let str_vec = st.iter().map(std::string::ToString::to_string).collect::<Vec<String>>();
			assert_eq!(str_vec.join(":"), "1:1");
		}
	}

	#[tokio::test]
	pub async fn test_builder_mixed_features() {
		// Simulates: Complex real-world scenario with key, scheduling, deps, and retry
		let task_store: Arc<dyn TaskStore<State>> = InMemoryTaskStore::new();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<TestTask>().unwrap();
		scheduler.register::<FailingTask>().unwrap();

		// Create initial tasks
		let id1 = scheduler.task(TestTask::new(1)).now().await.unwrap();

		// Create complex task: scheduled + depends on id1 + has key
		let _id2 = scheduler
			.task(TestTask::new(1))
			.key("critical-task")
			.schedule_after(0)
			.depend_on(vec![id1])
			.schedule()
			.await
			.unwrap();

		// Create task with retry
		let _id3 = scheduler
			.task(FailingTask::new(1, 0))  // Fails 0 times, succeeds immediately
			.key("retryable-task")
			.with_retry(RetryPolicy {
				wait_min_max: (1, 3600),
				times: 3,
			})
			.schedule()
			.await
			.unwrap();

		// Wait for tasks: id1 (200ms) + id2 (200ms after id1) + id3 (200ms) = ~600ms
		tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

		let st = state.lock();
		// All three tasks should execute
		let str_vec = st.iter().map(std::string::ToString::to_string).collect::<Vec<String>>();
		assert_eq!(str_vec.join(":"), "1:1:1");
	}

	#[tokio::test]
	pub async fn test_builder_builder_reuse_not_possible() {
		// Verify that builder is consumed (moved) and can't be reused
		let task_store: Arc<dyn TaskStore<State>> = InMemoryTaskStore::new();
		let _state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);

		let task = TestTask::new(1);
		let builder = scheduler.task(task);

		// This would not compile if uncommented (builder is moved):
		// let _id1 = builder.now().await.unwrap();
		// let _id2 = builder.now().await.unwrap();  // Error: use of moved value

		// Can only call terminal method once
		let _id = builder.now().await.unwrap();
		// builder is now consumed, can't use again

		// Test passes if it compiles (verifying move semantics)
	}

	#[tokio::test]
	pub async fn test_builder_different_task_types() {
		// Test builder works with different task implementations
		let task_store: Arc<dyn TaskStore<State>> = InMemoryTaskStore::new();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<TestTask>().unwrap();
		scheduler.register::<FailingTask>().unwrap();

		// Mix of different task types
		let _id1 = scheduler.task(TestTask::new(1)).key("test-task").now().await.unwrap();

		let _id2 = scheduler
			.task(FailingTask::new(1, 0))  // Won't fail
			.key("failing-task")
			.now()
			.await
			.unwrap();

		let _id3 = scheduler.task(TestTask::new(1)).now().await.unwrap();

		tokio::time::sleep(std::time::Duration::from_secs(1)).await;

		let st = state.lock();
		assert_eq!(st.len(), 3);
		let str_vec = st.iter().map(std::string::ToString::to_string).collect::<Vec<String>>();
		// All three tasks should execute
		assert_eq!(str_vec.join(":"), "1:1:1");
	}

	// ===== Phase 3: Cron Placeholder Tests =====
	// These tests verify that cron methods compile and integrate
	// Actual cron functionality will be implemented in Phase 3

	#[tokio::test]
	pub async fn test_builder_cron_placeholder_syntax() {
		// Verify cron placeholder methods compile and chain properly
		let task_store: Arc<dyn TaskStore<State>> = InMemoryTaskStore::new();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<TestTask>().unwrap();

		// Test that cron methods compile (they're no-ops in Phase 2)
		let task = TestTask::new(1);
		let _id = scheduler
			.task(task)
			.key("cron-task")
			.cron("0 9 * * *")  // 9 AM daily
			.schedule()
			.await
			.unwrap();

		// Cron scheduling - task will execute at the next scheduled time
		// For cron "0 9 * * *", that's tomorrow at 9 AM, so task won't execute in this test
		// This test just verifies the methods compile and chain properly
		tokio::time::sleep(std::time::Duration::from_millis(500)).await;

		let st = state.lock();
		// Task is scheduled for future (9 AM), so it won't have executed yet
		// The important thing is that the cron methods compile and integrate
		assert_eq!(st.len(), 0); // Not executed yet since scheduled for future
	}

	#[tokio::test]
	pub async fn test_builder_weekly_at_placeholder() {
		// Verify weekly_at placeholder compiles and integrates
		let task_store: Arc<dyn TaskStore<State>> = InMemoryTaskStore::new();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<TestTask>().unwrap();

		// Test that weekly_at placeholder compiles
		let task = TestTask::new(1);
		let _id = scheduler
			.task(task)
			.key("weekly-task")
			.weekly_at(1, 9, 0)  // Monday at 9 AM
			.schedule()
			.await
			.unwrap();

		// Weekly_at scheduling - task will execute on Monday at 9 AM
		// Task is scheduled for future, so it won't execute in this test
		tokio::time::sleep(std::time::Duration::from_millis(500)).await;

		let st = state.lock();
		// Task is scheduled for future (Monday 9 AM), not executed yet
		// The important thing is that weekly_at compiles and integrates properly
		assert_eq!(st.len(), 0);
	}

	#[tokio::test]
	pub async fn test_builder_cron_with_retry() {
		// Verify cron methods chain with retry (future combined usage)
		let task_store: Arc<dyn TaskStore<State>> = InMemoryTaskStore::new();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<TestTask>().unwrap();

		// Test future usage pattern: cron + retry
		let task = TestTask::new(1);
		let _id = scheduler
			.task(task)
			.key("reliable-scheduled-task")
			.cron("0 2 * * *")  // 2 AM daily
			.with_retry(RetryPolicy {
				wait_min_max: (60, 3600),
				times: 5,
			})
			.schedule()
			.await
			.unwrap();

		// Verify cron+retry chain compiles properly
		// Task is scheduled for 2 AM, so won't execute in this test
		tokio::time::sleep(std::time::Duration::from_millis(500)).await;

		let st = state.lock();
		// Task scheduled for future (2 AM), not executed yet
		// The important thing is that chaining cron + retry works
		assert_eq!(st.len(), 0);
	}

	// ===== Cron Schedule Tests =====

	#[test]
	fn test_cron_to_string() {
		// Test that to_cron_string returns the original expression
		let cron = CronSchedule::parse("*/5 * * * *").unwrap();
		assert_eq!(cron.to_cron_string(), "*/5 * * * *");
	}

	#[tokio::test]
	pub async fn test_running_task_not_double_scheduled() {
		let _ = tracing_subscriber::fmt().try_init();

		let task_store: Arc<dyn TaskStore<State>> = InMemoryTaskStore::new();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<TestTask>().unwrap();

		// Create a task
		let task = TestTask::new(5); // Takes 1 second (5 * 200ms)
		let task_id = scheduler.add(task.clone()).await.unwrap();

		// Wait a bit for task to start running
		tokio::time::sleep(std::time::Duration::from_millis(100)).await;

		// Verify task is in tasks_running
		{
			let running = scheduler.tasks_running.lock();
			assert!(running.contains_key(&task_id), "Task should be in running queue");
		}

		// Try to add the same task again via add_queue
		let task_meta = TaskMeta {
			task: task.clone(),
			next_at: Some(Timestamp::now()),
			deps: vec![],
			retry_count: 0,
			retry: None,
			cron: None,
			rerun_requested: false,
		};
		let result = scheduler.add_queue(task_id, task_meta).await;

		// Should succeed but not actually add to scheduled queue
		assert!(result.is_ok(), "add_queue should succeed");

		// Verify task is NOT in tasks_scheduled (only in running)
		{
			let sched_queue = scheduler.tasks_scheduled.lock();
			let in_scheduled = sched_queue.iter().any(|((_, id), _)| *id == task_id);
			assert!(!in_scheduled, "Task should NOT be in scheduled queue while running");
		}

		// Wait for original task to complete
		tokio::time::sleep(std::time::Duration::from_secs(2)).await;

		// Verify task completed
		let st = state.lock();
		assert_eq!(st.len(), 1, "Only one task execution should have occurred");
		assert_eq!(st[0], 5);
	}

	#[tokio::test]
	pub async fn test_running_task_metadata_updated() {
		let _ = tracing_subscriber::fmt().try_init();

		let task_store: Arc<dyn TaskStore<State>> = InMemoryTaskStore::new();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<TestTask>().unwrap();

		// Create a task without cron
		let task = TestTask::new(5); // Takes 1 second (5 * 200ms)
		let task_id = scheduler.add(task.clone()).await.unwrap();

		// Wait a bit for task to start running
		tokio::time::sleep(std::time::Duration::from_millis(100)).await;

		// Verify task is running and has no cron
		{
			let running = scheduler.tasks_running.lock();
			let meta = running.get(&task_id).expect("Task should be running");
			assert!(meta.cron.is_none(), "Task should have no cron initially");
		}

		// Try to update the running task with a cron schedule
		let cron = CronSchedule::parse("*/5 * * * *").unwrap();
		let task_meta_with_cron = TaskMeta {
			task: task.clone(),
			next_at: Some(Timestamp::now()),
			deps: vec![],
			retry_count: 0,
			retry: None,
			cron: Some(cron.clone()),
			rerun_requested: false,
		};
		let result = scheduler.add_queue(task_id, task_meta_with_cron).await;

		// Should succeed
		assert!(result.is_ok(), "add_queue should succeed");

		// Verify the running task now has the cron schedule
		{
			let running = scheduler.tasks_running.lock();
			let meta = running.get(&task_id).expect("Task should still be running");
			assert!(meta.cron.is_some(), "Task should now have cron after update");
		}

		// Wait for task to complete
		tokio::time::sleep(std::time::Duration::from_secs(2)).await;
	}

	/// A store that actually remembers keys.
	///
	/// [`InMemoryTaskStore::find_by_key`] always answers `None`, so it can never
	/// reach the keyed-dedup branch of `schedule_task_impl` — the branch the test
	/// below is about. Only `input` has to be faithful: that is what the
	/// "parameters changed" comparison reads.
	struct KeyedTaskStore {
		last_id: Mutex<TaskId>,
		by_key: Mutex<HashMap<String, TaskId>>,
		input: Mutex<HashMap<TaskId, (String, String)>>,
		/// Every `finished` call, in order. The persisted row leaves `status='P'`
		/// only through this, so a run that never reaches it is a task stuck
		/// pending forever — re-run on every process restart, dependents never
		/// released.
		finished: Mutex<Vec<TaskId>>,
		/// Every `update_task_error` call, in order. `next_at` is what decides the
		/// persisted status: `Some` keeps the row `'P'` (a cron task is not
		/// finished by a failed run), `None` stamps it `'E'`.
		errors: Mutex<Vec<(TaskId, Option<Timestamp>)>>,
		/// Hold `finished` open so a test can land a re-request *inside* that
		/// await, which is where the race lives. Separate from `update_gate`
		/// because a test that parks one still needs the other to run: the
		/// re-request it lands does its own store call on the way in.
		finished_gate: Arc<tokio::sync::Semaphore>,
		/// Same, for `update_task` — the cron reschedule's await.
		update_gate: Arc<tokio::sync::Semaphore>,
		/// Fires as `finished` is entered, before it parks.
		finished_entered: Arc<tokio::sync::Notify>,
		/// Fires as `update_task` is entered, before it parks.
		updated_entered: Arc<tokio::sync::Notify>,
	}

	impl KeyedTaskStore {
		/// Both gates wide open — the ungated store every other test uses.
		fn new() -> Arc<Self> {
			Self::with_gates(
				tokio::sync::Semaphore::MAX_PERMITS,
				tokio::sync::Semaphore::MAX_PERMITS,
			)
		}

		/// A store whose `finished` blocks until the test releases it.
		fn new_gated_finished() -> Arc<Self> {
			Self::with_gates(0, tokio::sync::Semaphore::MAX_PERMITS)
		}

		/// A store whose `update_task` blocks until the test releases it.
		fn new_gated_update() -> Arc<Self> {
			Self::with_gates(tokio::sync::Semaphore::MAX_PERMITS, 0)
		}

		fn with_gates(finished_permits: usize, update_permits: usize) -> Arc<Self> {
			Arc::new(Self {
				last_id: Mutex::new(0),
				by_key: Mutex::new(HashMap::new()),
				input: Mutex::new(HashMap::new()),
				finished: Mutex::new(Vec::new()),
				errors: Mutex::new(Vec::new()),
				finished_gate: Arc::new(tokio::sync::Semaphore::new(finished_permits)),
				update_gate: Arc::new(tokio::sync::Semaphore::new(update_permits)),
				finished_entered: Arc::new(tokio::sync::Notify::new()),
				updated_entered: Arc::new(tokio::sync::Notify::new()),
			})
		}

		fn finished_ids(&self) -> Vec<TaskId> {
			self.finished.lock().clone()
		}

		fn error_calls(&self) -> Vec<(TaskId, Option<Timestamp>)> {
			self.errors.lock().clone()
		}

		fn release_finished(&self, n: usize) {
			self.finished_gate.add_permits(n);
		}

		fn release_updates(&self, n: usize) {
			self.update_gate.add_permits(n);
		}

		/// Await `finished` being entered. `notify_one` stores a permit when
		/// nobody is waiting, so this cannot miss the signal. The timeout only
		/// exists so a regression fails instead of hanging.
		async fn await_finished_entered(&self) {
			tokio::time::timeout(
				std::time::Duration::from_secs(5),
				self.finished_entered.notified(),
			)
			.await
			.expect("expected `finished` to be entered");
		}

		/// Same, for `update_task`.
		async fn await_updated_entered(&self) {
			tokio::time::timeout(
				std::time::Duration::from_secs(5),
				self.updated_entered.notified(),
			)
			.await
			.expect("expected `update_task` to be entered");
		}
	}

	#[async_trait]
	impl<S: Clone> TaskStore<S> for KeyedTaskStore {
		async fn add(&self, task: &TaskMeta<S>, key: Option<&str>) -> ClResult<TaskId> {
			let id = {
				let mut last = self.last_id.lock();
				*last += 1;
				*last
			};
			self.input
				.lock()
				.insert(id, (task.task.kind_of().to_owned(), task.task.serialize()));
			if let Some(key) = key {
				self.by_key.lock().insert(key.to_owned(), id);
			}
			Ok(id)
		}

		async fn find_by_key(&self, key: &str) -> ClResult<Option<(TaskId, TaskData)>> {
			let Some(id) = self.by_key.lock().get(key).copied() else { return Ok(None) };
			let Some((kind, input)) = self.input.lock().get(&id).cloned() else {
				return Ok(None);
			};
			Ok(Some((
				id,
				TaskData {
					id,
					kind: kind.into(),
					status: TaskStatus::Pending,
					input: input.into(),
					deps: Box::from([]),
					retry_data: None,
					cron_data: None,
					next_at: None,
				},
			)))
		}

		async fn update_task(&self, id: TaskId, task: &TaskMeta<S>) -> ClResult<()> {
			self.updated_entered.notify_one();
			self.update_gate
				.acquire()
				.await
				.map(tokio::sync::SemaphorePermit::forget)
				.map_err(|_| Error::Internal("store gate closed".into()))?;
			if let Some(entry) = self.input.lock().get_mut(&id) {
				entry.1 = task.task.serialize();
			}
			Ok(())
		}

		async fn finished(&self, id: TaskId, _output: &str) -> ClResult<()> {
			self.finished_entered.notify_one();
			self.finished_gate
				.acquire()
				.await
				.map(tokio::sync::SemaphorePermit::forget)
				.map_err(|_| Error::Internal("store gate closed".into()))?;
			self.finished.lock().push(id);
			Ok(())
		}
		async fn load(&self) -> ClResult<Vec<TaskData>> {
			Ok(vec![])
		}
		async fn update_task_error(
			&self,
			task_id: TaskId,
			_output: &str,
			next_at: Option<Timestamp>,
		) -> ClResult<()> {
			self.errors.lock().push((task_id, next_at));
			Ok(())
		}
		async fn find_completed_deps(&self, _deps: &[TaskId]) -> ClResult<Vec<TaskId>> {
			Ok(vec![])
		}
	}

	/// A task whose body a test drives directly: `entered` fires the moment a run
	/// starts, and the run then blocks until the test hands it a `gate` permit.
	///
	/// No clock is involved, in either direction — the tests below neither sleep
	/// on wall-clock time nor need `tokio::time::pause`, so they cannot be flaky
	/// on a loaded machine. `runs` records the parameters of every body entered,
	/// in order, which is what "the second run used the *new* parameters" means.
	#[derive(Debug)]
	struct GatedTask {
		param: u8,
		runs: Arc<Mutex<Vec<u8>>>,
		entered: Arc<tokio::sync::Notify>,
		gate: Arc<tokio::sync::Semaphore>,
		/// Return a retryable error once the gate opens.
		fail: bool,
	}

	#[async_trait]
	impl Task<State> for GatedTask {
		fn kind() -> &'static str {
			"gated"
		}
		fn kind_of(&self) -> &'static str {
			Self::kind()
		}
		fn build(_id: TaskId, _ctx: &str) -> ClResult<Arc<dyn Task<State>>> {
			Err(Error::Internal("not rebuilt in this test".into()))
		}
		fn serialize(&self) -> String {
			self.param.to_string()
		}
		async fn run(&self, _state: &State) -> ClResult<()> {
			self.runs.lock().push(self.param);
			self.entered.notify_one();
			let _permit = self.gate.acquire().await;
			if self.fail {
				// Retryable, so the retry path rather than `on_failed` runs.
				return Err(Error::Internal("gated failure".into()));
			}
			Ok(())
		}
	}

	struct Gated {
		runs: Arc<Mutex<Vec<u8>>>,
		entered: Arc<tokio::sync::Notify>,
		gate: Arc<tokio::sync::Semaphore>,
	}

	impl Gated {
		fn new() -> Self {
			Self {
				runs: Arc::new(Mutex::new(Vec::new())),
				entered: Arc::new(tokio::sync::Notify::new()),
				gate: Arc::new(tokio::sync::Semaphore::new(0)),
			}
		}

		fn task(&self, param: u8, fail: bool) -> Arc<GatedTask> {
			Arc::new(GatedTask {
				param,
				runs: Arc::clone(&self.runs),
				entered: Arc::clone(&self.entered),
				gate: Arc::clone(&self.gate),
				fail,
			})
		}

		fn params(&self) -> Vec<u8> {
			self.runs.lock().clone()
		}

		/// Await the next body being entered. The timeout only exists so a
		/// regression — a run that never happens — fails the test instead of
		/// hanging it; the happy path never reaches the clock.
		async fn await_run(&self) {
			tokio::time::timeout(std::time::Duration::from_secs(5), self.entered.notified())
				.await
				.expect("expected a task body to be entered");
		}
	}

	/// A keyed **one-shot** re-requested while it runs must still get its run.
	///
	/// The in-place metadata update is right — a second concurrent body would be
	/// two VACUUMs for `core.db_maintenance:manual` — but "the run in flight
	/// reschedules itself from the new parameters" only holds for a *cron* task.
	/// A one-shot takes the `store.finished` branch instead, so without the rerun
	/// flag the run the caller asked for is silently dropped.
	#[tokio::test]
	pub async fn a_running_keyed_one_shot_re_requested_in_flight_runs_again() {
		let _ = tracing_subscriber::fmt().try_init();

		let store = KeyedTaskStore::new();
		let task_store: Arc<dyn TaskStore<State>> = store.clone();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<GatedTask>().unwrap();

		let gated = Gated::new();
		let first_id = scheduler.task(gated.task(1, false)).key("test.gated").now().await.unwrap();
		gated.await_run().await;

		// Same key, new parameters, while the first body is still held open.
		let second_id = scheduler.task(gated.task(2, false)).key("test.gated").now().await.unwrap();
		assert_eq!(second_id, first_id, "the key must resolve to the running task");
		assert_eq!(gated.params(), vec![1], "no second body may start alongside the first");

		// Let the first run finish; the finish handler owes the caller a re-run.
		gated.gate.add_permits(1);
		gated.await_run().await;
		gated.gate.add_permits(1);

		assert_eq!(
			gated.params(),
			vec![1, 2],
			"the re-requested run must happen, with the new parameters"
		);

		// And it must be *accounted for*: the re-requested run has to reach
		// `finished`, or the persisted row stays `status='P'` forever — re-run on
		// every process restart, dependents never released.
		//
		// Polled rather than asserted straight away: the second body's completion
		// travels through the finish channel.
		for _ in 0..200 {
			if !store.finished_ids().is_empty() {
				break;
			}
			tokio::time::sleep(std::time::Duration::from_millis(10)).await;
		}
		assert_eq!(
			store.finished_ids(),
			vec![first_id],
			"the re-requested run must reach `finished`, or the task is stuck pending"
		);
		assert!(
			!scheduler.tasks_running.lock().contains_key(&first_id),
			"a finished task must not stay in the running map"
		);
	}

	/// The same, for a re-request whose parameters are **identical**.
	///
	/// This is the common shape, not the exotic one: `IndexDocumentTask { tn_id,
	/// file_id }` serializes the same way for every edit of the same file, so a
	/// second edit landing while the first index run is in flight takes the
	/// identical-parameters branch. Falling through to `add_queue` there absorbs
	/// the request — its already-running arm only *copies* an existing rerun flag
	/// and never sets one — leaving the document's index stale until the weekly
	/// sweep.
	#[tokio::test]
	pub async fn a_running_keyed_one_shot_re_requested_with_identical_params_runs_again() {
		let _ = tracing_subscriber::fmt().try_init();

		let store = KeyedTaskStore::new();
		let task_store: Arc<dyn TaskStore<State>> = store.clone();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<GatedTask>().unwrap();

		let gated = Gated::new();
		let first_id = scheduler.task(gated.task(1, false)).key("test.gated").now().await.unwrap();
		gated.await_run().await;

		// Same key, *same* parameters, while the first body is still held open.
		let second_id = scheduler.task(gated.task(1, false)).key("test.gated").now().await.unwrap();
		assert_eq!(second_id, first_id, "the key must resolve to the running task");
		assert_eq!(gated.params(), vec![1], "no second body may start alongside the first");

		gated.gate.add_permits(1);
		gated.await_run().await;
		gated.gate.add_permits(1);

		assert_eq!(
			gated.params(),
			vec![1, 1],
			"an identical re-request carries the same intent as a changed one"
		);

		for _ in 0..200 {
			if !store.finished_ids().is_empty() {
				break;
			}
			tokio::time::sleep(std::time::Duration::from_millis(10)).await;
		}
		assert_eq!(
			store.finished_ids(),
			vec![first_id],
			"the re-requested run must reach `finished`, or the task is stuck pending"
		);
	}

	/// A cron task with no retry policy must keep its row Pending when a run
	/// fails.
	///
	/// `update_task_error(id, err, None)` maps to `mark_error`'s `status='E'`
	/// arm. In memory the task is fine — the finish handler sees the cron and
	/// reschedules — but the reschedule persists through `update`, which has no
	/// status clause and never restores `'P'`. From then on `find_by_key` and
	/// `load()` (both `status='P'`-filtered) cannot see the row, the next boot
	/// mints a duplicate, and `run_on_startup` fires again: a full `VACUUM` of
	/// `meta.db` on every restart.
	#[tokio::test]
	pub async fn a_failing_cron_run_keeps_the_row_pending() {
		let _ = tracing_subscriber::fmt().try_init();

		let store = KeyedTaskStore::new();
		let task_store: Arc<dyn TaskStore<State>> = store.clone();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<GatedTask>().unwrap();

		let gated = Gated::new();
		// No retry policy, so the failure is terminal for this occurrence.
		let id = scheduler
			.task(gated.task(1, true))
			.key("test.cron.failing")
			.cron("*/5 * * * *")
			.run_on_startup()
			.schedule()
			.await
			.unwrap();
		gated.await_run().await;

		// Let the body fail.
		gated.gate.add_permits(1);
		for _ in 0..200 {
			if !store.error_calls().is_empty() {
				break;
			}
			tokio::time::sleep(std::time::Duration::from_millis(10)).await;
		}

		let errors = store.error_calls();
		assert_eq!(errors.len(), 1, "the failed run must be persisted");
		assert_eq!(errors[0].0, id);
		assert!(
			errors[0].1.is_some(),
			"a cron task's row must keep a live next_at, not be stamped 'E'"
		);
		assert!(store.finished_ids().is_empty(), "a failed run does not finish the task");
	}

	/// A retry after an in-flight update must carry the **new** parameters.
	///
	/// `spawn_task` captures its `TaskMeta` when the run starts, so building
	/// `retry_meta` from that snapshot would re-run the old parameters while the
	/// persisted row already holds the new ones.
	#[tokio::test]
	pub async fn a_retry_after_an_in_flight_update_uses_the_new_parameters() {
		let _ = tracing_subscriber::fmt().try_init();

		let task_store: Arc<dyn TaskStore<State>> = KeyedTaskStore::new();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<GatedTask>().unwrap();

		let gated = Gated::new();
		// Zero backoff, so the retry is re-queued for "now" and the scheduler's
		// notify path picks it up without any timer.
		let first_id = scheduler
			.task(gated.task(1, true))
			.key("test.gated")
			.with_retry(RetryPolicy::new((0, 0), 3))
			.now()
			.await
			.unwrap();
		gated.await_run().await;

		let second_id = scheduler
			.task(gated.task(2, false))
			.key("test.gated")
			.with_retry(RetryPolicy::new((0, 0), 3))
			.now()
			.await
			.unwrap();
		assert_eq!(second_id, first_id);

		// Release the first body; it fails retryably and the retry is queued.
		gated.gate.add_permits(1);
		gated.await_run().await;
		gated.gate.add_permits(1);

		assert_eq!(
			gated.params(),
			vec![1, 2],
			"the retry must run the parameters the in-flight update wrote"
		);
	}

	/// A re-request that lands **while `store.finished` is in flight** must still
	/// run.
	///
	/// The window: were the finish handler to read the rerun flag and only then
	/// await `store.finished` with the id still in `tasks_running`, a request
	/// arriving during that await would be absorbed by `schedule_task_impl`'s
	/// in-place update and thrown away when the handler removed the entry — and
	/// the leftover flag would make the *next* run of that id re-queue itself once
	/// more. Reachable at `worker_threads = 1` precisely because `store.finished`
	/// is an await; taking the entry out *before* the await is what closes it.
	///
	/// Driven by gates, not timing: with one worker every step below is forced,
	/// because awaiting an already-ready future does not yield. The flavour is
	/// pinned rather than left to `#[tokio::test]`'s default — on a multi-thread
	/// runtime the window this test exists to cover stops existing, and the test
	/// would pass while asserting nothing.
	#[tokio::test(flavor = "current_thread")]
	pub async fn a_re_request_landing_while_the_finish_handler_marks_finished_still_runs() {
		let _ = tracing_subscriber::fmt().try_init();

		let store = KeyedTaskStore::new_gated_finished();
		let task_store: Arc<dyn TaskStore<State>> = store.clone();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<GatedTask>().unwrap();

		let gated = Gated::new();
		// `add`/`find_by_key` are ungated, but the first schedule's `update_task`
		// is not reached (no existing row), so nothing parks here.
		let id = scheduler.task(gated.task(1, false)).key("test.gated").now().await.unwrap();
		gated.await_run().await;

		// Body 1 returns; the handler wakes, sees no cron and no rerun, takes the
		// id out of `tasks_running`, then enters `store.finished` and parks.
		gated.gate.add_permits(1);
		store.await_finished_entered().await;

		// The re-request lands inside that await.
		let second = scheduler.task(gated.task(2, false)).key("test.gated").now().await.unwrap();
		assert_eq!(second, id, "the key must resolve to the same task");

		// Release `finished`. The requested run must now happen.
		store.release_finished(8);
		gated.await_run().await;
		gated.gate.add_permits(1);

		assert_eq!(
			gated.params(),
			vec![1, 2],
			"the request that landed during `finished` must still run, with the new parameters"
		);

		for _ in 0..200 {
			if store.finished_ids().len() >= 2 {
				break;
			}
			tokio::time::sleep(std::time::Duration::from_millis(10)).await;
		}
		// Not `== vec![id]`: in this interleaving the row is legitimately marked
		// finished twice — the second run queued itself through the ordinary path
		// while the first `finished` was still in flight. That residual is
		// documented at the handler's terminal branch; closing it needs a
		// store-level re-open.
		assert!(
			store.finished_ids().contains(&id),
			"the re-requested run must reach `finished`, or the row stays 'P' forever"
		);
		assert!(
			!scheduler.tasks_running.lock().contains_key(&id),
			"a finished task must not stay in the running map"
		);
	}

	/// A cron task's reschedule must use the metadata an in-flight update wrote,
	/// not the snapshot the handler took before awaiting `store.update_task`.
	///
	/// Building `updated_meta` from a clone taken before the await discards a
	/// re-request landing during it twice over: the entry is deleted and the stale
	/// parameters re-queued. Reachable at one worker.
	#[tokio::test]
	pub async fn a_cron_reschedule_uses_the_parameters_an_in_flight_update_wrote() {
		let _ = tracing_subscriber::fmt().try_init();

		let store = KeyedTaskStore::new_gated_update();
		let task_store: Arc<dyn TaskStore<State>> = store.clone();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<GatedTask>().unwrap();

		let gated = Gated::new();
		let id = scheduler
			.task(gated.task(1, false))
			.key("test.cron")
			.cron("*/5 * * * *")
			.run_on_startup()
			.schedule()
			.await
			.unwrap();
		gated.await_run().await;

		// Body 1 returns; the handler takes the cron branch and parks in
		// `store.update_task`.
		gated.gate.add_permits(1);
		store.await_updated_entered().await;

		// The re-request lands inside that await — and parks on the same gate on
		// its own way in, so the release has to come from beside it. `notify_one`
		// stores a permit when nobody is waiting, so this releaser cannot miss the
		// second entry however the two are interleaved.
		let releaser = {
			let store = Arc::clone(&store);
			tokio::spawn(async move {
				store.await_updated_entered().await;
				store.release_updates(8);
			})
		};
		let second = scheduler
			.task(gated.task(2, false))
			.key("test.cron")
			.cron("*/5 * * * *")
			.schedule()
			.await
			.unwrap();
		assert_eq!(second, id, "the key must resolve to the running task");
		releaser.await.unwrap();
		// The reschedule is white-box and instant — no wall-clock wait, the next
		// cron firing is minutes away.
		for _ in 0..200 {
			let queued = {
				let scheduled = scheduler.tasks_scheduled.lock();
				scheduled.iter().any(|((_, tid), _)| *tid == id)
			};
			if queued {
				break;
			}
			tokio::time::sleep(std::time::Duration::from_millis(10)).await;
		}
		let scheduled = scheduler.tasks_scheduled.lock();
		let (_, meta) = scheduled
			.iter()
			.find(|((_, tid), _)| *tid == id)
			.expect("cron task must be rescheduled");
		assert_eq!(meta.task.serialize(), "2", "the cron reschedule used the stale snapshot");
	}
}

// vim: ts=4
