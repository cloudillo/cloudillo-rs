use async_trait::async_trait;
use flume;
use lazy_static::lazy_static;
use std::any::Any;
use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::sync::{Arc, Mutex};
use std::thread;
use tokio::sync::{Mutex as AsyncMutex, Notify};

lazy_static! {
	static ref WORKER_POOL: Mutex<WorkerPool> = Mutex::new(WorkerPool::new());
}

pub trait Task: Sync + Send + Any + Debug + 'static {
	fn run(&mut self) -> Result<(), Box<dyn std::error::Error>>;
	fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

/*
//impl<T: Sync + Send + Any + Debug + 'static> Task for T {
#[async_trait]
impl dyn Task {
	fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
	fn into_any(self: Box<Self>) -> Box<dyn Any> { self }
}
*/

#[derive(Debug)]
struct TaskData {
	task: Arc<Mutex<Box<dyn Task + 'static>>>,
	notify: Arc<Notify>,
}

pub struct WorkerPool {
	id: u32,
	tasks: Mutex<HashMap<u32, Box<TaskData>>>,
	tx: flume::Sender<(u32, Arc<Mutex<Box<dyn Task>>>)>,
	re_rx: flume::Receiver<(u32, Arc<Mutex<Box<dyn Task>>>)>,
}

impl WorkerPool {
	pub fn new() -> Self {
		let (tx, rx) = flume::unbounded::<(u32, Arc<Mutex<Box<dyn Task>>>)>();
		let (re_tx, re_rx) = flume::unbounded::<(u32, Arc<Mutex<Box<dyn Task>>>)>();
		let threads = std::thread::available_parallelism().unwrap().get();
		println!("Starting {} workers", threads);
		for thread_id in 0..threads {
			let (rx, re_tx) = (rx.clone(), re_tx.clone());
			//thread::spawn(move || {
			thread::Builder::new()
				.name(format!("worker-{}", thread_id))
				.spawn(move || {
					//println!("[{}] started", std::thread::current().name().unwrap_or(""));
					while let Ok((id, task_data)) = rx.recv() {
						{
							let mut task = task_data.lock().unwrap();
							let _ = task.run();
						}
						re_tx.send((id, task_data)).unwrap();
					}
				});
		}
		//WorkerPool { id: 0, tasks: Mutex::new(HashMap::new()), tx, re_rx }
		WorkerPool {
			id: 0,
			tasks: Mutex::new(HashMap::new()),
			tx,
			re_rx,
		}
	}

	pub fn get_re_rx(&self) -> flume::Receiver<(u32, Arc<Mutex<Box<dyn Task>>>)> {
		self.re_rx.clone()
	}

	pub fn start_task(
		&mut self,
		task: Arc<Mutex<Box<dyn Task>>>,
	) -> Result<Arc<Notify>, Box<dyn std::error::Error>> {
		let notify = Arc::new(Notify::new());
		{
			self.id = self.id.wrapping_add(1);
			self.tasks.lock().unwrap().insert(
				self.id,
				Box::new(TaskData {
					task: task.clone(),
					notify: notify.clone(),
				}),
			);
		}
		self.tx.send((self.id, task))?;
		Ok(notify)
	}
}

fn get_re_rx() -> flume::Receiver<(u32, Arc<Mutex<Box<dyn Task>>>)> {
	WORKER_POOL.lock().unwrap().get_re_rx()
}
pub async fn run_worker() {
	//let re_rx = { WORKER_POOL.lock().await.get_re_rx() };
	let re_rx = get_re_rx();
	while let Ok((id, recv)) = re_rx.recv_async().await {
		let worker_pool = WORKER_POOL.lock().unwrap();
		let mut tasks = worker_pool.tasks.lock().unwrap();
		println!("TASKS {:?}", tasks.keys());
		if let Some(task_data) = tasks.remove(&id) {
			println!("data {}", id);
			task_data.notify.notify_one();
		} else {
		}
	}
}

//#![allow(trait_upcasting)]
pub async fn run<T: Task + 'static>(task: Box<T>) -> Result<Box<T>, Box<dyn std::error::Error>> {
	let task: Arc<Mutex<Box<dyn Task + 'static>>> = Arc::new(Mutex::new(task));
	let notify = {
		WORKER_POOL
			.lock()
			.unwrap()
			.start_task(task.clone())
			.unwrap()
	};
	notify.notified().await;

	match Arc::try_unwrap(task) {
		Ok(mutex) => {
			let t = mutex.into_inner().unwrap();
			let task = <Box<dyn Any>>::downcast::<T>(t.into_any()).unwrap();
			Ok(task)
		}
		Err(_) => Err(Box::new(std::io::Error::from(std::io::ErrorKind::NotFound))),
	}
}

// vim: ts=4
