//! Scheduler subsystem. Handles async tasks, dependencies, fallbacks, repetitions, persistence..

use async_trait::async_trait;
use flume;
use std::{collections::{BTreeMap, HashMap}, fmt::Debug, future::Future, pin::Pin, sync::{Arc, Mutex, RwLock}};
use serde::{Serialize, Deserialize, de::DeserializeOwned};

use crate::{
	prelude::*,
	meta_adapter,
};

pub type TaskId = u64;

pub enum TaskType {
	Periodic,
	Once,
}

#[async_trait]
pub trait Task<S: Clone>: Send + Sync + Debug {
	fn kind() -> &'static str
		where Self: Sized;
	fn build(id: TaskId, context: &str) -> ClResult<Arc<dyn Task<S>>>
		where Self: Sized;
	fn serialize(&self) -> String;
	async fn run(&self, state: &S) -> ClResult<()>;

	fn kind_of(&self) -> &'static str;
}

#[derive(Debug)]
pub enum TaskStatus {
	Pending,
	Finished,
	Error,
}

pub struct TaskData {
	id: TaskId,
	kind: Box<str>,
	status: TaskStatus,
	input: Box<str>,
	deps: Box<[TaskId]>,
	next_at: Option<Timestamp>,
}

#[async_trait]
pub trait TaskStore<S: Clone>: Send + Sync {
	async fn add(&self, task: &TaskMeta<S>, key: Option<&str>) -> ClResult<TaskId>;
	async fn finished(&self, id: TaskId, output: &str) -> ClResult<()>;
	async fn load(&self) -> ClResult<Vec<TaskData>>;
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
	async fn add(&self, task: &TaskMeta<S>, key: Option<&str>) -> ClResult<TaskId> {
		let mut last_id = self.last_id.lock().map_err(|_| Error::Unknown)?;
		*last_id += 1;
		Ok(*last_id)
	}

	async fn finished(&self, id: TaskId, output: &str) -> ClResult<()> {
		Ok(())
	}

	async fn load(&self) -> ClResult<Vec<TaskData>> {
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
		let id = self.meta_adapter.create_task(task.task.kind_of(), key, &task.task.serialize(), &task.deps).await?;
		Ok(id)
	}

	async fn finished(&self, id: TaskId, output: &str) -> ClResult<()> {
		self.meta_adapter.update_task_finished(id, output).await
	}

	async fn load(&self) -> ClResult<Vec<TaskData>> {
		let tasks = self.meta_adapter.list_tasks(meta_adapter::ListTaskOptions::default()).await?;
		let tasks = tasks.into_iter().map(|t| TaskData {
			id: t.task_id,
			kind: t.kind,
			status: match t.status {
				'P' => TaskStatus::Pending,
				'F' => TaskStatus::Finished,
				'E' => TaskStatus::Error,
				_ => TaskStatus::Error,
			},
			input: t.input,
			deps: t.deps,
			next_at: t.next_at,
		}).collect();
		Ok(tasks)
	}
}

type TaskBuilder<S> = dyn Fn(TaskId, &str) -> ClResult<Arc<dyn Task<S>>> + Send + Sync;

#[derive(Debug, Clone)]
pub struct TaskMeta<S: Clone> {
	pub task: Arc<dyn Task<S>>,
	pub next_at: Option<Timestamp>,
	pub deps: Vec<TaskId>,
}

#[derive(Clone)]
pub struct Scheduler<S: Clone> {
	task_builders: Arc<RwLock<HashMap<&'static str, Box<TaskBuilder<S>>>>>,
	store: Arc<dyn TaskStore<S>>,
	tasks_running: Arc<Mutex<HashMap<TaskId, TaskMeta<S>>>>,
	tasks_waiting: Arc<Mutex<HashMap<TaskId, TaskMeta<S>>>>,
	task_dependents: Arc<Mutex<HashMap<TaskId, Vec<TaskId>>>>,
	tasks_scheduled: Arc<Mutex<BTreeMap<(Timestamp, TaskId), TaskMeta<S>>>>,
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
				info!("Finished task {}", id);
				schedule.store.finished(id, "").await.unwrap_or(());
				schedule.tasks_running.lock().unwrap().remove(&id);
				if let Some(dependents) = schedule.task_dependents.lock().unwrap().remove(&id) {
					for dep in dependents {
						if let Some(task) = schedule.tasks_waiting.lock().unwrap().get_mut(&dep) {
							task.deps.retain(|x| *x != id);
							if task.deps.is_empty() {
								schedule.spawn_task(stat.clone(), task.task.clone(), dep);
							}
						}
					}
				}
			}
		});

		// Handle scheduled tasks
		let schedule = self.clone();
		tokio::spawn(async move {
			loop {
				if schedule.tasks_scheduled.lock().unwrap().is_empty() {
					schedule.notify_schedule.notified().await;
					info!("NOTIFY: tasks_scheduled");
				}
				let time = Timestamp::now();
				if let Some((timestamp, id)) = loop {
					//info!("first task: {:?}", schedule.tasks_scheduled.lock().unwrap().first_key_value());
					let mut tasks_scheduled = schedule.tasks_scheduled.lock().unwrap();
					if let Some((&(timestamp, id), _)) = tasks_scheduled.first_key_value() {
						let (timestamp, id) = (timestamp, id);
						if timestamp <= Timestamp::now() {
							info!("Spawning task id {}", id);
							let task = tasks_scheduled.remove(&(timestamp, id)).unwrap();
							schedule.tasks_running.lock().unwrap().insert(id, task.clone());
							schedule.spawn_task(state.clone(), task.task.clone(), id);
						} else {
							break Some((timestamp, id));
						}
					} else {
						break None;
					}
				} {
					let wait = tokio::time::Duration::from_secs((timestamp.0 - time.0) as u64);
					info!("wait: {}", wait.as_secs());
					tokio::select! {
						_ = tokio::time::sleep(wait) => (), _ = schedule.notify_schedule.notified() => ()
					};
					info!("wait finished");
				}
			}
		});

		let schedule = self.clone();
		tokio::spawn(async move {
			schedule.load().await;
		});
	}

	fn register_builder(&self, name: &'static str, builder: &'static TaskBuilder<S>) -> ClResult<&Self> {
		let mut task_builders = self.task_builders.write().map_err(|_| Error::Unknown)?;
		task_builders.insert(name, Box::new(builder));
		Ok(self)
	}

	pub fn register<T: Task<S>>(&self) -> ClResult<&Self> {
		info!("Registering task type {}", T::kind());
		self.register_builder(T::kind(), &|id: TaskId, params: &str| {
			T::build(id, params)
		})?;
		Ok(self)
	}

	pub async fn add_full(&self, task: Arc<dyn Task<S>>, key: Option<&str>, next_at: Option<Timestamp>, deps: Option<Vec<TaskId>>) -> ClResult<TaskId> {
		let task_meta = TaskMeta { task: task.clone(), next_at, deps: deps.clone().unwrap_or_default() };
		let id = self.store.add(&task_meta, key).await?;
		self.add_queue(id, task_meta).await
	}

	pub async fn add(&self, task: Arc<dyn Task<S>>) -> ClResult<TaskId> {
		self.add_full(task, None, None, None).await
	}

	pub async fn add_with_deps(&self, task: Arc<dyn Task<S>>, deps: Option<Vec<TaskId>>) -> ClResult<TaskId> {
		self.add_full(task, None, None, deps).await
	}

	pub async fn add_queue(&self, id: TaskId, task_meta: TaskMeta<S>) -> ClResult<TaskId> {
		let deps = task_meta.deps.clone();

		if deps.len() == 0 && task_meta.next_at.unwrap_or(Timestamp(0)) < Timestamp::now() {
			info!("Spawning task {}", id);
			self.tasks_scheduled.lock().map_err(|_| Error::Unknown)?.insert((Timestamp(0), id), task_meta);
			self.notify_schedule.notify_one();
		} else if let Some(next_at) = task_meta.next_at {
			info!("Scheduling task {} for {}", id, next_at);
			self.tasks_scheduled.lock().map_err(|_| Error::Unknown)?.insert((next_at, id), task_meta);
			self.notify_schedule.notify_one();
		} else {
			self.tasks_waiting.lock().map_err(|_| Error::Unknown)?.insert(id, task_meta);
			info!("Task {} is waiting for {:?}", id, &deps);
			for dep in deps {
				self.task_dependents.lock().map_err(|_| Error::Unknown)?.entry(dep).or_default().push(id);
			}
		}
		Ok(id)
	}

	async fn load(&self) -> ClResult<()> {
		let tasks = self.store.load().await?;
		info!("Loaded {} tasks from store", tasks.len());
		for t in tasks {
			match t.status {
				TaskStatus::Pending => {
					info!("Loading task {} {}", t.id, t.kind);
					let task = {
						let builder_map = self.task_builders.read().map_err(|_| Error::Unknown)?;
						let builder = builder_map.get(t.kind.as_ref()).ok_or(Error::Unknown)?;
						builder(t.id, &t.input)?
					};
					let task_meta = TaskMeta { task, next_at: t.next_at, deps: t.deps.into() };
					self.add_queue(t.id, task_meta).await?;
				},
				_ => (),
			}
		}
		Ok(())
	}

	fn spawn_task(&self, state: S, task: Arc<dyn Task<S>>, id: TaskId) {
		let tx_finish = self.tx_finish.clone();
		//let state = self.state.clone();
		tokio::spawn(async move {
			let _ = task.run(&state).await;
			tx_finish.send(id).unwrap_or(());
		});
	}
}

#[cfg(test)]
mod tests {
	use super::*;

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
		fn kind() -> &'static str { "test" }

		fn build(id: TaskId, ctx: &str) -> ClResult<Arc<dyn Task<State>>> {
			let num: u8 = ctx.parse().map_err(|_| Error::Unknown)?;
			let task = TestTask::new(num);
			Ok(task)
		}

		async fn run(&self, state: &State) -> ClResult<()> {
			info!("Running task {}", self.num);
			tokio::time::sleep(std::time::Duration::from_millis(200 * self.num as u64)).await;
			info!("Finished task {}", self.num);
			state.lock().unwrap().push(self.num);
			Ok(())
		}
	}

	#[tokio::test]
	pub async fn test_scheduler() {
		tracing_subscriber::fmt()
			.init();

		let mut task_store: Arc<dyn TaskStore<State>> = InMemoryTaskStore::new();
		let mut state: State = Arc::new(Mutex::new(Vec::new()));
		let mut scheduler = Scheduler::new(task_store).unwrap();
		scheduler.start(state.clone());
		scheduler.register::<TestTask>();

		let task1 = TestTask::new(1);
		let task2 = TestTask::new(2);
		let task3 = TestTask::new(3);

		let task2_id = scheduler.add(task2, Some(now() + 2), None).await.unwrap();
		let task3_id = scheduler.add(task3, None, None).await.unwrap();
		scheduler.add(TestTask::new(1) , None, Some(vec![task2_id, task3_id])).await.unwrap();

		tokio::time::sleep(std::time::Duration::from_secs(4)).await;
		let task4 = TestTask::new(4);
		let task5 = TestTask::new(5);
		scheduler.add(task4, Some(now() + 2), None).await.unwrap();
		scheduler.add(task5, Some(now() + 1), None).await.unwrap();

		tokio::time::sleep(std::time::Duration::from_secs(3)).await;

		let st = state.lock().unwrap();
		info!("res: {}", st.len());
		let str_vec = st.iter().map(|x| x.to_string()).collect::<Vec<String>>();
		assert_eq!(str_vec.join(":"), "3:2:1:5:4");
	}
}

// vim: ts=4
