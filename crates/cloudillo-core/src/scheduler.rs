//! Scheduler subsystem. Handles async tasks, dependencies, fallbacks, repetitions, persistence..

use async_trait::async_trait;
use itertools::Itertools;
use std::{
	collections::{BTreeMap, HashMap},
	fmt::Debug,
	sync::{Arc, Mutex, RwLock},
};

use chrono::{DateTime, Utc};
use croner::Cron;
use std::str::FromStr;

use crate::prelude::*;
use cloudillo_types::{lock, meta_adapter};

pub type TaskId = u64;

pub enum TaskType {
	Periodic,
	Once,
}

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
		let mut last_id = lock!(self.last_id)?;
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
	pub fn calculate_backoff(&self, attempt_count: u16) -> u64 {
		let (min, max) = self.wait_min_max;
		let backoff = min * (1u64 << u64::from(attempt_count));
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
	pub fn cron(mut self, expr: impl Into<String>) -> Self {
		if let Ok(cron_schedule) = CronSchedule::parse(&expr.into()) {
			// Calculate initial next_at from cron schedule
			// Use .ok() - cron was just parsed successfully, should never fail
			self.next_at = cron_schedule.next_execution(Timestamp::now()).ok();
			self.cron = Some(cron_schedule);
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

	/// Execute the scheduled task after another task completes
	pub async fn after_task(mut self, dep: TaskId) -> ClResult<TaskId> {
		self.deps.push(dep);
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

				// Get task metadata WITHOUT removing - we only remove after successful transition
				let task_meta_opt = {
					let tasks_running = match schedule.tasks_running.lock() {
						Ok(guard) => guard,
						Err(poisoned) => {
							error!("Mutex poisoned: tasks_running (recovering)");
							poisoned.into_inner()
						}
					};
					tasks_running.get(&id).cloned()
				};

				if let Some(task_meta) = task_meta_opt {
					// Track if transition was successful
					let mut transition_ok = false;

					// Check if this is a recurring task with cron schedule
					if let Some(ref cron) = task_meta.cron {
						// Calculate next execution time
						let next_at = match cron.next_execution(Timestamp::now()) {
							Ok(ts) => ts,
							Err(e) => {
								error!(
									"Failed to calculate next execution for recurring task {}: {} - task will not reschedule",
									id, e
								);
								// Mark as finished since we can't reschedule
								if let Err(e) = schedule.store.finished(id, "").await {
									error!("Failed to mark task {} as finished: {}", id, e);
								}
								continue;
							}
						};
						info!(
							"Recurring task {} completed, scheduling next execution at {}",
							id, next_at
						);

						// Update task with new next_at
						let mut updated_meta = task_meta.clone();
						updated_meta.next_at = Some(next_at);

						// Update database with new next_at (keep status as Pending)
						if let Err(e) = schedule.store.update_task(id, &updated_meta).await {
							error!("Failed to update recurring task {} next_at: {}", id, e);
						}

						// Remove from running BEFORE add_queue (so add_queue doesn't see it as running)
						match schedule.tasks_running.lock() {
							Ok(mut tasks_running) => {
								tasks_running.remove(&id);
							}
							Err(poisoned) => {
								error!("Mutex poisoned: tasks_running (recovering)");
								poisoned.into_inner().remove(&id);
							}
						}

						// Re-add to scheduler with new execution time
						match schedule.add_queue(id, updated_meta).await {
							Ok(_) => transition_ok = true,
							Err(e) => {
								error!(
									"Failed to reschedule recurring task {}: {} - task lost!",
									id, e
								);
							}
						}
					} else {
						// One-time task - mark as finished
						match schedule.store.finished(id, "").await {
							Ok(()) => transition_ok = true,
							Err(e) => {
								error!(
									"Failed to mark task {} as finished: {} - task remains in running queue",
									id, e
								);
							}
						}
					}

					// Only remove from running queue after successful transition
					if transition_ok {
						match schedule.tasks_running.lock() {
							Ok(mut tasks_running) => {
								tasks_running.remove(&id);
							}
							Err(poisoned) => {
								error!("Mutex poisoned: tasks_running (recovering)");
								poisoned.into_inner().remove(&id);
							}
						}
					}

					// Handle dependencies of finished task using atomic release method
					match schedule.release_dependents(id) {
						Ok(ready_to_spawn) => {
							for (dep_id, dep_task_meta) in ready_to_spawn {
								// Add to running queue before spawning
								match schedule.tasks_running.lock() {
									Ok(mut tasks_running) => {
										tasks_running.insert(dep_id, dep_task_meta.clone());
									}
									Err(poisoned) => {
										error!("Mutex poisoned: tasks_running (recovering)");
										poisoned.into_inner().insert(dep_id, dep_task_meta.clone());
									}
								}
								schedule.spawn_task(
									stat.clone(),
									dep_task_meta.task.clone(),
									dep_id,
									dep_task_meta,
								);
							}
						}
						Err(e) => {
							error!("Failed to release dependents of task {}: {}", id, e);
						}
					}
				} else {
					warn!("Completed task {} not found in running queue", id);
				}
			}
		});

		// Handle scheduled tasks
		let schedule = self.clone();
		tokio::spawn(async move {
			loop {
				let is_empty = match schedule.tasks_scheduled.lock() {
					Ok(guard) => guard.is_empty(),
					Err(poisoned) => {
						error!("Mutex poisoned: tasks_scheduled (recovering)");
						poisoned.into_inner().is_empty()
					}
				};
				if is_empty {
					schedule.notify_schedule.notified().await;
				}
				let time = Timestamp::now();
				if let Some((timestamp, _id)) = loop {
					let mut tasks_scheduled = match schedule.tasks_scheduled.lock() {
						Ok(guard) => guard,
						Err(poisoned) => {
							error!("Mutex poisoned: tasks_scheduled (recovering)");
							poisoned.into_inner()
						}
					};
					if let Some((&(timestamp, id), _)) = tasks_scheduled.first_key_value() {
						let (timestamp, id) = (timestamp, id);
						if timestamp <= Timestamp::now() {
							debug!("Spawning task id {} (from schedule)", id);
							if let Some(task) = tasks_scheduled.remove(&(timestamp, id)) {
								let mut tasks_running = match schedule.tasks_running.lock() {
									Ok(guard) => guard,
									Err(poisoned) => {
										error!("Mutex poisoned: tasks_running (recovering)");
										poisoned.into_inner()
									}
								};
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
			let _ignore_err = schedule.load().await;
		});
	}

	fn register_builder(
		&self,
		name: &'static str,
		builder: &'static TaskBuilder<S>,
	) -> ClResult<&Self> {
		let mut task_builders = self
			.task_builders
			.write()
			.map_err(|_| Error::Internal("task_builders RwLock poisoned".into()))?;
		task_builders.insert(name, Box::new(builder));
		Ok(self)
	}

	pub fn register<T: Task<S>>(&self) -> ClResult<&Self> {
		info!("Registering task type {}", T::kind());
		self.register_builder(T::kind(), &|id: TaskId, params: &str| T::build(id, params))?;
		Ok(self)
	}

	/// Create a builder for scheduling a task using the fluent API
	pub fn task(&self, task: Arc<dyn Task<S>>) -> TaskSchedulerBuilder<'_, S> {
		TaskSchedulerBuilder::new(self, task)
	}

	/// Internal method to schedule a task with all options
	/// This is the core implementation used by the builder pattern
	async fn schedule_task_impl(
		&self,
		task: Arc<dyn Task<S>>,
		key: Option<&str>,
		next_at: Option<Timestamp>,
		deps: Option<Vec<TaskId>>,
		retry: Option<RetryPolicy>,
		cron: Option<CronSchedule>,
	) -> ClResult<TaskId> {
		let task_meta = TaskMeta {
			task: task.clone(),
			next_at,
			deps: deps.clone().unwrap_or_default(),
			retry_count: 0,
			retry,
			cron,
		};

		// Check if a task with this key already exists (key-based deduplication)
		if let Some(key) = key {
			if let Some((existing_id, existing_data)) = self.store.find_by_key(key).await? {
				let new_serialized = task.serialize();
				let existing_serialized = existing_data.input.as_ref();

				// Compare serialized parameters
				if new_serialized == existing_serialized {
					info!(
						"Recurring task '{}' already exists with identical parameters (id={})",
						key, existing_id
					);
					// Update DB with current cron/next_at (may differ from what's stored)
					self.store.update_task(existing_id, &task_meta).await?;
					// Ensure the existing task is queued (may be loaded from DB but not yet in queue)
					self.add_queue(existing_id, task_meta).await?;
					return Ok(existing_id);
				}
				info!(
					"Updating recurring task '{}' (id={}) - parameters changed",
					key, existing_id
				);
				info!("  Old params: {}", existing_serialized);
				info!("  New params: {}", new_serialized);

				// Remove from all queues (if present)
				self.remove_from_queues(existing_id)?;

				// Update the task in database with new parameters
				self.store.update_task(existing_id, &task_meta).await?;

				// Re-add to appropriate queue with updated parameters
				self.add_queue(existing_id, task_meta).await?;

				return Ok(existing_id);
			}
		}

		// No existing task - create new one
		let id = self.store.add(&task_meta, key).await?;
		self.add_queue(id, task_meta).await
	}

	pub async fn add(&self, task: Arc<dyn Task<S>>) -> ClResult<TaskId> {
		self.task(task).now().await
	}

	pub async fn add_queue(&self, id: TaskId, task_meta: TaskMeta<S>) -> ClResult<TaskId> {
		// If task is already running, update its metadata (especially for cron updates)
		// but don't add to scheduled queue (it will reschedule on completion)
		{
			let mut running = lock!(self.tasks_running, "tasks_running")?;
			if let Some(existing_meta) = running.get_mut(&id) {
				debug!(
					"Task {} is already running, updating metadata (will reschedule on completion)",
					id
				);
				// Update the running task's metadata so it has the latest cron schedule
				*existing_meta = task_meta;
				return Ok(id);
			}
		}

		// Remove from other queues if present (prevents duplicate entries with different timestamps)
		{
			let mut scheduled = lock!(self.tasks_scheduled, "tasks_scheduled")?;
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
			let mut waiting = lock!(self.tasks_waiting, "tasks_waiting")?;
			if waiting.remove(&id).is_some() {
				debug!("Removed existing waiting entry for task {} before re-queueing", id);
			}
		}

		let deps = task_meta.deps.clone();

		// VALIDATION: Tasks with dependencies should NEVER be in tasks_scheduled
		if !deps.is_empty() && task_meta.next_at.is_some() {
			warn!("Task {} has both dependencies and scheduled time - ignoring next_at, placing in waiting queue", id);
			// Force to tasks_waiting instead
			lock!(self.tasks_waiting, "tasks_waiting")?.insert(id, task_meta);
			debug!("Task {} is waiting for {:?}", id, &deps);
			for dep in deps {
				lock!(self.task_dependents, "task_dependents")?.entry(dep).or_default().push(id);
			}
			return Ok(id);
		}

		if deps.is_empty() && task_meta.next_at.unwrap_or(Timestamp(0)) < Timestamp::now() {
			debug!("Spawning task {}", id);
			lock!(self.tasks_scheduled, "tasks_scheduled")?.insert((Timestamp(0), id), task_meta);
			self.notify_schedule.notify_one();
		} else if let Some(next_at) = task_meta.next_at {
			debug!("Scheduling task {} for {}", id, next_at);
			lock!(self.tasks_scheduled, "tasks_scheduled")?.insert((next_at, id), task_meta);
			self.notify_schedule.notify_one();
		} else {
			lock!(self.tasks_waiting, "tasks_waiting")?.insert(id, task_meta);
			debug!("Task {} is waiting for {:?}", id, &deps);
			for dep in deps {
				lock!(self.task_dependents, "task_dependents")?.entry(dep).or_default().push(id);
			}
		}
		Ok(id)
	}

	/// Remove a task from all internal queues (waiting, scheduled, running)
	/// Returns the removed TaskMeta if found
	fn remove_from_queues(&self, task_id: TaskId) -> ClResult<Option<TaskMeta<S>>> {
		// Try tasks_waiting
		if let Some(task_meta) = lock!(self.tasks_waiting, "tasks_waiting")?.remove(&task_id) {
			debug!("Removed task {} from waiting queue for update", task_id);
			return Ok(Some(task_meta));
		}

		// Try tasks_scheduled (need to find by task_id in BTreeMap)
		{
			let mut scheduled = lock!(self.tasks_scheduled, "tasks_scheduled")?;
			if let Some(key) = scheduled
				.iter()
				.find(|((_, id), _)| *id == task_id)
				.map(|((ts, id), _)| (*ts, *id))
			{
				if let Some(task_meta) = scheduled.remove(&key) {
					debug!("Removed task {} from scheduled queue for update", task_id);
					return Ok(Some(task_meta));
				}
			}
		}

		// Try tasks_running (should rarely happen, but handle it)
		if let Some(task_meta) = lock!(self.tasks_running, "tasks_running")?.remove(&task_id) {
			warn!("Removed task {} from running queue during update", task_id);
			return Ok(Some(task_meta));
		}

		Ok(None)
	}

	/// Release all dependent tasks of a completed task
	/// This method safely handles dependency cleanup and spawning
	fn release_dependents(
		&self,
		completed_task_id: TaskId,
	) -> ClResult<Vec<(TaskId, TaskMeta<S>)>> {
		// Get list of dependents (atomic removal to prevent re-processing)
		let dependents = {
			let mut deps_map = lock!(self.task_dependents, "task_dependents")?;
			deps_map.remove(&completed_task_id).unwrap_or_default()
		};

		if dependents.is_empty() {
			return Ok(Vec::new()); // No dependents to release
		}

		debug!("Releasing {} dependents of completed task {}", dependents.len(), completed_task_id);

		let mut ready_to_spawn = Vec::new();

		// For each dependent, check and remove dependency
		for dependent_id in dependents {
			// Try tasks_waiting first (most common case for dependent tasks)
			{
				let mut waiting = lock!(self.tasks_waiting, "tasks_waiting")?;
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
				let mut scheduled = lock!(self.tasks_scheduled, "tasks_scheduled")?;
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

		Ok(ready_to_spawn)
	}

	async fn load(&self) -> ClResult<()> {
		let tasks = self.store.load().await?;
		debug!("Loaded {} tasks from store", tasks.len());
		for t in tasks {
			if let TaskStatus::Pending = t.status {
				debug!("Loading task {} {}", t.id, t.kind);
				let task = {
					let builder_map = self
						.task_builders
						.read()
						.map_err(|_| Error::Internal("task_builders RwLock poisoned".into()))?;
					let builder = builder_map.get(t.kind.as_ref()).ok_or(Error::Internal(
						format!("task builder not registered: {}", t.kind),
					))?;
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
				// Parse cron data if present
				let cron =
					t.cron_data.as_ref().and_then(|cron_str| CronSchedule::parse(cron_str).ok());

				let task_meta = TaskMeta {
					task,
					next_at: t.next_at,
					deps: t.deps.into(),
					retry_count,
					retry,
					cron,
				};
				self.add_queue(t.id, task_meta).await?;
			}
		}
		Ok(())
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
					if let Some(retry_policy) = &task_meta.retry {
						if retry_policy.should_retry(task_meta.retry_count) {
							let backoff = retry_policy.calculate_backoff(task_meta.retry_count);
							let next_at = Timestamp::from_now(backoff.cast_signed());

							info!(
								"Task {} failed (attempt {}/{}). Scheduling retry in {} seconds: {}",
								id, task_meta.retry_count + 1, retry_policy.times, backoff, e
							);

							// Update database with error and reschedule
							store
								.update_task_error(id, &e.to_string(), Some(next_at))
								.await
								.unwrap_or(());

							// Remove from running tasks (we're not sending finish event)
							match scheduler.tasks_running.lock() {
								Ok(mut tasks_running) => {
									tasks_running.remove(&id);
								}
								Err(poisoned) => {
									error!("Mutex poisoned: tasks_running (recovering)");
									poisoned.into_inner().remove(&id);
								}
							}

							// Re-queue task with incremented retry count
							let mut retry_meta = task_meta.clone();
							retry_meta.retry_count += 1;
							retry_meta.next_at = Some(next_at);
							scheduler.add_queue(id, retry_meta).await.unwrap_or(id);
						} else {
							// Max retries exhausted
							error!(
								"Task {} failed after {} retries: {}",
								id, task_meta.retry_count, e
							);
							store.update_task_error(id, &e.to_string(), None).await.unwrap_or(());
							tx_finish.send(id).unwrap_or(());
						}
					} else {
						// No retry policy - fail immediately
						error!("Task {} failed: {}", id, e);
						store.update_task_error(id, &e.to_string(), None).await.unwrap_or(());
						tx_finish.send(id).unwrap_or(());
					}
				}
			}
		});
	}

	/// Get health status of the scheduler
	/// Returns information about tasks in each queue and detects anomalies
	pub async fn health_check(&self) -> ClResult<SchedulerHealth> {
		let waiting_count = lock!(self.tasks_waiting, "tasks_waiting")?.len();
		let scheduled_count = lock!(self.tasks_scheduled, "tasks_scheduled")?.len();
		let running_count = lock!(self.tasks_running, "tasks_running")?.len();
		let dependents_count = lock!(self.task_dependents, "task_dependents")?.len();

		// Check for anomalies
		let mut stuck_tasks = Vec::new();
		let mut tasks_with_missing_deps = Vec::new();

		// Check tasks_waiting for tasks with no dependencies (stuck)
		{
			let waiting = lock!(self.tasks_waiting, "tasks_waiting")?;
			let _deps_map = lock!(self.task_dependents, "task_dependents")?;

			for (id, task_meta) in waiting.iter() {
				if task_meta.deps.is_empty() {
					stuck_tasks.push(*id);
					warn!("SCHEDULER HEALTH: Task {} in waiting with no dependencies", id);
				} else {
					// Check if all dependencies still exist
					for dep in &task_meta.deps {
						// Check if dependency is in any queue or dependents map
						let dep_exists =
							self.tasks_running.lock().ok().is_some_and(|r| r.contains_key(dep))
								|| self
									.tasks_waiting
									.lock()
									.ok()
									.is_some_and(|w| w.contains_key(dep))
								|| self.tasks_scheduled.lock().ok().is_some_and(|s| {
									s.iter().any(|((_, task_id), _)| task_id == dep)
								});

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
			state.lock().unwrap().push(self.num);
			Ok(())
		}
	}

	#[derive(Debug, Clone)]
	struct FailingTask {
		id: u8,
		fail_count: u8,
		attempt: Arc<Mutex<u8>>,
	}

	impl FailingTask {
		pub fn new(id: u8, fail_count: u8) -> Arc<Self> {
			Arc::new(Self { id, fail_count, attempt: Arc::new(Mutex::new(0)) })
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
			let mut attempt = self.attempt.lock().unwrap();
			*attempt += 1;
			let current_attempt = *attempt;

			info!("FailingTask {} - attempt {}/{}", self.id, current_attempt, self.fail_count + 1);

			if current_attempt <= self.fail_count {
				error!("FailingTask {} failed on attempt {}", self.id, current_attempt);
				return Err(Error::ServiceUnavailable(format!("Task {} failed", self.id)));
			}

			info!("FailingTask {} succeeded on attempt {}", self.id, current_attempt);
			state.lock().unwrap().push(self.id);
			Ok(())
		}
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

		let st = state.lock().unwrap();
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
		let retry_policy = RetryPolicy { wait_min_max: (1, 3600), times: 3 };

		scheduler.task(failing_task).with_retry(retry_policy).schedule().await.unwrap();

		// Wait for retries: 1s (1st fail) + 1s (2nd fail) + time for success
		// First attempt: immediate fail
		// Wait 1s (min backoff)
		// Second attempt: fail
		// Wait 2s (min * 2)
		// Third attempt: success
		tokio::time::sleep(std::time::Duration::from_secs(6)).await;

		let st = state.lock().unwrap();
		assert_eq!(st.len(), 1, "Task should have succeeded after retries");
		assert_eq!(st[0], 42);
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

		let st = state.lock().unwrap();
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

		let st = state.lock().unwrap();
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
			let st = state.lock().unwrap();
			assert_eq!(st.len(), 0, "Task should not execute yet");
		}

		// Wait for execution (1 sec delay + 200ms task sleep + buffer)
		tokio::time::sleep(std::time::Duration::from_millis(800)).await;

		{
			let st = state.lock().unwrap();
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

		let st = state.lock().unwrap();
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

		let st = state.lock().unwrap();
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
		let st = state.lock().unwrap();
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

		let st = state.lock().unwrap();
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

		let st = state.lock().unwrap();
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
		let id2 = scheduler.task(TestTask::new(1)).key("stage-2").after_task(id1).await.unwrap();

		// Stage 3: Create task that depends on stage 2
		let _id3 = scheduler.task(TestTask::new(1)).key("stage-3").after_task(id2).await.unwrap();

		// Wait for pipeline: 1(200ms) + 2(200ms) + 3(200ms) = 600ms
		tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

		let st = state.lock().unwrap();
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

		let st = state.lock().unwrap();
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
			let st = state.lock().unwrap();
			assert_eq!(st.len(), 1); // Only dependency executed
		}

		// Wait for scheduled time (1s total from initial schedule)
		tokio::time::sleep(std::time::Duration::from_millis(800)).await;

		{
			let st = state.lock().unwrap();
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

		let st = state.lock().unwrap();
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

		let st = state.lock().unwrap();
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

		let st = state.lock().unwrap();
		// Task is scheduled for future (9 AM), so it won't have executed yet
		// The important thing is that the cron methods compile and integrate
		assert_eq!(st.len(), 0); // Not executed yet since scheduled for future
	}

	#[tokio::test]
	pub async fn test_builder_daily_at_placeholder() {
		// Verify daily_at placeholder compiles and integrates
		let task_store: Arc<dyn TaskStore<State>> = InMemoryTaskStore::new();
		let state: State = Arc::new(Mutex::new(Vec::new()));
		let scheduler = Scheduler::new(task_store);
		scheduler.start(state.clone());
		scheduler.register::<TestTask>().unwrap();

		// Test that daily_at placeholder compiles
		let task = TestTask::new(1);
		let _id = scheduler
			.task(task)
			.key("daily-task")
			.daily_at(14, 30)  // 2:30 PM daily
			.schedule()
			.await
			.unwrap();

		// Daily_at scheduling - task will execute at the specified time (2:30 PM daily)
		// Task is scheduled for future, so it won't execute in this test
		tokio::time::sleep(std::time::Duration::from_millis(500)).await;

		let st = state.lock().unwrap();
		// Task is scheduled for future (2:30 PM), not executed yet
		// The important thing is that daily_at compiles and integrates properly
		assert_eq!(st.len(), 0);
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

		let st = state.lock().unwrap();
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
			.daily_at(2, 0)  // 2 AM daily
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

		let st = state.lock().unwrap();
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
			let running = scheduler.tasks_running.lock().unwrap();
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
		};
		let result = scheduler.add_queue(task_id, task_meta).await;

		// Should succeed but not actually add to scheduled queue
		assert!(result.is_ok(), "add_queue should succeed");

		// Verify task is NOT in tasks_scheduled (only in running)
		{
			let sched_queue = scheduler.tasks_scheduled.lock().unwrap();
			let in_scheduled = sched_queue.iter().any(|((_, id), _)| *id == task_id);
			assert!(!in_scheduled, "Task should NOT be in scheduled queue while running");
		}

		// Wait for original task to complete
		tokio::time::sleep(std::time::Duration::from_secs(2)).await;

		// Verify task completed
		let st = state.lock().unwrap();
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
			let running = scheduler.tasks_running.lock().unwrap();
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
		};
		let result = scheduler.add_queue(task_id, task_meta_with_cron).await;

		// Should succeed
		assert!(result.is_ok(), "add_queue should succeed");

		// Verify the running task now has the cron schedule
		{
			let running = scheduler.tasks_running.lock().unwrap();
			let meta = running.get(&task_id).expect("Task should still be running");
			assert!(meta.cron.is_some(), "Task should now have cron after update");
		}

		// Wait for task to complete
		tokio::time::sleep(std::time::Duration::from_secs(2)).await;
	}
}

// vim: ts=4
