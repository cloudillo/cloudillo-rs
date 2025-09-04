use std::{sync::Arc, thread};
use flume::{Receiver, Sender};
use futures::channel::oneshot;

#[derive(Clone, Copy, Debug)]
pub enum Priority {
	High,
	Medium,
	Low,
}

pub struct WorkerPool {
	tx_high: Sender<Box<dyn FnOnce() + Send>>,
	tx_med: Sender<Box<dyn FnOnce() + Send>>,
	tx_low: Sender<Box<dyn FnOnce() + Send>>,
}

impl WorkerPool {
	pub fn new(n1: usize, n2: usize, n3: usize) -> Self {
		let (tx_high, rx_high) = flume::unbounded();
		let (tx_med, rx_med) = flume::unbounded();
		let (tx_low, rx_low) = flume::unbounded();

		let rx_high = Arc::new(rx_high);
		let rx_med = Arc::new(rx_med);
		let rx_low = Arc::new(rx_low);

		// Workers dedicated to High only
		for _ in 0..n1 {
			let rx_high = Arc::clone(&rx_high);
			thread::spawn(move || worker_loop(vec![rx_high]));
		}

		// Workers for High + Medium
		for _ in 0..n2 {
			let rx_high = Arc::clone(&rx_high);
			let rx_med = Arc::clone(&rx_med);
			thread::spawn(move || worker_loop(vec![rx_high, rx_med]));
		}

		// Workers for High + Medium + Low
		for _ in 0..n3 {
			let rx_high = Arc::clone(&rx_high);
			let rx_med = Arc::clone(&rx_med);
			let rx_low = Arc::clone(&rx_low);
			thread::spawn(move || worker_loop(vec![rx_high, rx_med, rx_low]));
		}

		Self {
			tx_high,
			tx_med,
			tx_low,
		}
	}

	/// Submit a closure with arguments → returns a Future for the result
	pub fn spawn<F, T>(&self, priority: Priority, f: F) -> impl std::future::Future<Output = T>
	where
		F: FnOnce() -> T + Send + 'static,
		T: Send + 'static,
	{
		let (res_tx, res_rx) = oneshot::channel();

		let job = Box::new(move || {
			let result = f();
			let _ = res_tx.send(result);
		});

		match priority {
			Priority::High => self.tx_high.send(job).unwrap(),
			Priority::Medium => self.tx_med.send(job).unwrap(),
			Priority::Low => self.tx_low.send(job).unwrap(),
		}

		async move { res_rx.await.expect("worker dropped result") }
	}

	pub fn run<F, T>(&self, f: F) -> impl std::future::Future<Output = T>
	where
		F: FnOnce() -> T + Send + 'static,
		T: Send + 'static,
	{
		let (res_tx, res_rx) = oneshot::channel();

		let job = Box::new(move || {
			let result = f();
			res_tx.send(result);
		});

		self.tx_med.send(job).unwrap();

		async move { res_rx.await.expect("worker dropped result") }
	}

	pub fn run_immed<F, T>(&self, f: F) -> impl std::future::Future<Output = T>
	where
		F: FnOnce() -> T + Send + 'static,
		T: Send + 'static,
	{
		let (res_tx, res_rx) = oneshot::channel();

		let job = Box::new(move || {
			let result = f();
			res_tx.send(result);
		});

		self.tx_med.send(job).unwrap();

		async move { res_rx.await.expect("worker dropped result") }
	}

	pub fn run_slow<F, T>(&self, f: F) -> impl std::future::Future<Output = T>
	where
		F: FnOnce() -> T + Send + 'static,
		T: Send + 'static,
	{
		let (res_tx, res_rx) = oneshot::channel();

		let job = Box::new(move || {
			let result = f();
			res_tx.send(result);
		});

		self.tx_low.send(job).unwrap();

		async move { res_rx.await.expect("worker dropped result") }
	}
}

fn worker_loop(queues: Vec<Arc<Receiver<Box<dyn FnOnce() + Send>>>>) {
	loop {
		// Try higher-priority queues first (non-blocking)
		let mut job = None;
		for rx in &queues {
			if let Ok(j) = rx.try_recv() {
				job = Some(j);
				break;
			}
		}

		if let Some(job) = job {
			job();
			continue;
		}

		// Wait for next job
		let mut selector = flume::Selector::new();
		for rx in &queues {
			selector = selector.recv(&rx, |res| res);
		}

		let job: Result<Box<dyn FnOnce() + Send>, flume::RecvError> = selector.wait();
		if let Ok(job) = job {
			job()
		}
	}
}

// vim: ts=4
