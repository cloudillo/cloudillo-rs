use async_trait::async_trait;
use flume;
use std::{collections::{BTreeMap, HashMap}, future::Future, pin::Pin, sync::{Arc, Mutex}};
use serde::{Serialize, Deserialize, de::DeserializeOwned};

use crate::{
	prelude::*,
	types::{Timestamp, TimestampExt},
};

type TaskId = u32;

enum TaskType {
	Periodic,
	Once,
}

#[async_trait]
pub trait Task: Send + Sync + std::fmt::Debug {
	fn kind() -> &'static str
		where Self: Sized;
	fn build(id: TaskId, state: &str) -> ClResult<Arc<dyn Task>>
		where Self: Sized;
	async fn run(&self) -> ClResult<()>;
}

#[async_trait]
pub trait TaskStore: Send + Sync {
	async fn add(&self, task: &TaskMeta) -> ClResult<TaskId>;
}

pub struct InMemoryTaskStore {
	last_id: Mutex<TaskId>,
}

impl InMemoryTaskStore {
	pub fn new() -> Arc<Self> {
		Arc::new(Self { last_id: Mutex::new(0) })
	}
}

#[async_trait]
impl TaskStore for InMemoryTaskStore {
	async fn add(&self, task: &TaskMeta) -> ClResult<TaskId> {
		let mut last_id = self.last_id.lock().map_err(|_| Error::Unknown)?;
		*last_id += 1;
		Ok(*last_id)
	}
}

type TaskBuilder = dyn Fn(TaskId, &str) -> ClResult<Arc<dyn Task>> + Send + Sync;

#[derive(Clone, Debug)]
pub struct TaskMeta {
	pub task: Arc<dyn Task>,
	pub next: Option<Timestamp>,
	pub deps: Vec<TaskId>,
}

#[derive(Clone)]
pub struct Scheduler {
	task_builders: HashMap<&'static str, Arc<TaskBuilder>>,
	store: Arc<dyn TaskStore>,
	tasks_running: Arc<Mutex<HashMap<TaskId, TaskMeta>>>,
	tasks_waiting: Arc<Mutex<HashMap<TaskId, TaskMeta>>>,
	task_dependents: Arc<Mutex<HashMap<TaskId, Vec<TaskId>>>>,
	tasks_scheduled: Arc<Mutex<BTreeMap<(Timestamp, TaskId), TaskMeta>>>,
	tx_finish: flume::Sender<TaskId>,
	notify_schedule: Arc<tokio::sync::Notify>,
}

impl Scheduler {
	pub fn new(store: Arc<dyn TaskStore>) -> ClResult<Self> {
		let (tx_finish, rx_finish) = flume::unbounded();

		let scheduler = Self {
			task_builders: HashMap::new(),
			store,
			tasks_running: Arc::new(Mutex::new(HashMap::new())),
			tasks_waiting: Arc::new(Mutex::new(HashMap::new())),
			task_dependents: Arc::new(Mutex::new(HashMap::new())),
			tasks_scheduled: Arc::new(Mutex::new(BTreeMap::new())),
			tx_finish,
			notify_schedule: Arc::new(tokio::sync::Notify::new()),
		};

		scheduler.run(rx_finish)?;

		Ok(scheduler)
	}

	fn run(&self, rx_finish: flume::Receiver<TaskId>) -> ClResult<()> {

		// Handle finished tasks and dependencies
		let schedule = self.clone();
		tokio::spawn(async move {
			while let Ok(id) = rx_finish.recv_async().await {
				schedule.tasks_running.lock().unwrap().remove(&id);
				if let Some(dependents) = schedule.task_dependents.lock().unwrap().remove(&id) {
					for dep in dependents {
						if let Some(task) = schedule.tasks_waiting.lock().unwrap().get_mut(&dep) {
							task.deps.retain(|x| *x != id);
							if task.deps.is_empty() {
								schedule.spawn(task.task.clone(), dep);
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
				let now = Timestamp::now();
				if let Some((timestamp, id)) = loop {
					//info!("first task: {:?}", schedule.tasks_scheduled.lock().unwrap().first_key_value());
					let mut tasks_scheduled = schedule.tasks_scheduled.lock().unwrap();
					if let Some((&(timestamp, id), _)) = tasks_scheduled.first_key_value() {
						let (timestamp, id) = (timestamp, id);
						if timestamp <= Timestamp::now() {
							info!("Spawning task id {}", id);
							let task = tasks_scheduled.remove(&(timestamp, id)).unwrap();
							schedule.tasks_running.lock().unwrap().insert(id, task.clone());
							schedule.spawn(task.task.clone(), id);
						} else {
							break Some((timestamp, id));
						}
					} else {
						break None;
					}
				} {
					let wait = tokio::time::Duration::from_secs((timestamp - now) as u64);
					info!("wait: {}", wait.as_secs());
					tokio::select! {
						_ = tokio::time::sleep(wait) => (), _ = schedule.notify_schedule.notified() => ()
					};
					info!("wait finished");
				}
			}
		});

		Ok(())
	}

	fn register_builder(&mut self, name: &'static str, builder: &'static TaskBuilder) -> &mut Self {
		self.task_builders.insert(name, Arc::new(builder));
		self
	}

	pub fn register<T: Task>(&mut self) -> &mut Self {
		self.register_builder(T::kind(), &|id: TaskId, params: &str| {
			T::build(id, params)
		});
		self
	}

	pub async fn add(&mut self, task: Arc<dyn Task>, not_before: Option<Timestamp>, dependencies: Option<Vec<TaskId>>) -> ClResult<TaskId> {
		let deps = dependencies.clone();
		let task_meta = TaskMeta { task: task.clone(), next: not_before, deps: dependencies.unwrap_or_default() };
		let id = self.store.add(&task_meta).await?;

		if deps.is_none() && not_before.unwrap_or(0) < Timestamp::now() {
			self.tasks_running.lock().map_err(|_| Error::Unknown)?.insert(id, task_meta);
			info!("Spawning task {}", id);
			self.spawn(task, id);
		} else if let Some(not_before) = not_before {
			info!("Scheduling task {} for {}", id, not_before);
			self.tasks_scheduled.lock().map_err(|_| Error::Unknown)?.insert((not_before, id), task_meta);
			self.notify_schedule.notify_one();
		} else {
			self.tasks_waiting.lock().map_err(|_| Error::Unknown)?.insert(id, task_meta);
			if let Some(ref deps) = deps {
				info!("Task {} is waiting for {:?}", id, &deps);
				for dep in deps {
					self.task_dependents.lock().map_err(|_| Error::Unknown)?.entry(*dep).or_default().push(id);
				}
			}
		}
		Ok(id)
	}

	fn spawn(&self, task: Arc<dyn Task>, id: TaskId) {
		let tx_finish = self.tx_finish.clone();
		tokio::spawn(async move {
			let _ = task.run().await;
			tx_finish.send(id).unwrap_or(());
		});
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[derive(Debug, Serialize, Deserialize)]
	struct TestTask {
		num: u8,
		res: Arc<Mutex<Vec<u8>>>,
	}

	impl TestTask {
		pub fn new(num: u8, res: Arc<Mutex<Vec<u8>>>) -> Arc<Self> {
			Arc::new(Self { num, res })
		}
	}

	#[async_trait]
	impl Task for TestTask {
		fn kind() -> &'static str { "test" }

		fn build(id: TaskId, state: &str) -> ClResult<Arc<dyn Task>> {
			let res: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
			let num: u8 = state.parse().map_err(|_| Error::Unknown)?;
			let task = TestTask::new(num, res.clone());
			Ok(task)
		}

		async fn run(&self) -> ClResult<()> {
			info!("Running task {}", self.num);
			tokio::time::sleep(std::time::Duration::from_millis(200 * self.num as u64)).await;
			info!("Finished task {}", self.num);
			self.res.lock().unwrap().push(self.num);
			Ok(())
		}
	}

	#[tokio::test]
	pub async fn test_scheduler() {
		tracing_subscriber::fmt()
			.init();

		let mut task_store = InMemoryTaskStore::new();
		let mut scheduler = Scheduler::new(task_store).unwrap();
		scheduler.register::<TestTask>();
		let res: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));

		let task1 = TestTask::new(1, res.clone());
		let task2 = TestTask::new(2, res.clone());
		let task3 = TestTask::new(3, res.clone());

		let task2_id = scheduler.add(task2, Some(Timestamp::now() + 2), None).await.unwrap();
		let task3_id = scheduler.add(task3, None, None).await.unwrap();
		scheduler.add(TestTask::new(1, res.clone()) , None, Some(vec![task2_id, task3_id])).await.unwrap();

		tokio::time::sleep(std::time::Duration::from_secs(4)).await;
		let task4 = TestTask::new(4, res.clone());
		let task5 = TestTask::new(5, res.clone());
		scheduler.add(task4, Some(Timestamp::now() + 2), None).await.unwrap();
		scheduler.add(task5, Some(Timestamp::now() + 1), None).await.unwrap();

		tokio::time::sleep(std::time::Duration::from_secs(3)).await;

		let res = res.lock().unwrap();
		info!("res: {}", res.len());
		let str_vec = res.iter().map(|x| x.to_string()).collect::<Vec<String>>();
		assert_eq!(str_vec.join(":"), "3:2:1:5:4");
	}
}

// vim: ts=4
