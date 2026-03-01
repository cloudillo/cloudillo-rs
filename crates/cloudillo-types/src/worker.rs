//! Worker pool. Handles synchronous tasks with 3 priority levels, configurable worker threads.

use flume::{Receiver, Sender};
use futures::channel::oneshot;
use std::{sync::Arc, thread};

use crate::prelude::*;

#[derive(Clone, Copy, Debug)]
pub enum Priority {
	High,
	Medium,
	Low,
}

#[derive(Debug)]
pub struct WorkerPool {
	high: Sender<Box<dyn FnOnce() + Send>>,
	med: Sender<Box<dyn FnOnce() + Send>>,
	low: Sender<Box<dyn FnOnce() + Send>>,
}

impl WorkerPool {
	pub fn new(n1: usize, n2: usize, n3: usize) -> Self {
		let (high, rx_high) = flume::unbounded();
		let (med, rx_med) = flume::unbounded();
		let (low, rx_low) = flume::unbounded();

		let rx_high = Arc::new(rx_high);
		let rx_med = Arc::new(rx_med);
		let rx_low = Arc::new(rx_low);

		// Workers dedicated to High only
		for _ in 0..n1 {
			let rx_high = Arc::clone(&rx_high);
			thread::spawn(move || worker_loop(&[rx_high]));
		}

		// Workers for High + Medium
		for _ in 0..n2 {
			let rx_high = Arc::clone(&rx_high);
			let rx_med = Arc::clone(&rx_med);
			thread::spawn(move || worker_loop(&[rx_high, rx_med]));
		}

		// Workers for High + Medium + Low
		for _ in 0..n3 {
			let rx_high = Arc::clone(&rx_high);
			let rx_med = Arc::clone(&rx_med);
			let rx_low = Arc::clone(&rx_low);
			thread::spawn(move || worker_loop(&[rx_high, rx_med, rx_low]));
		}

		Self { high, med, low }
	}

	/// Submit a closure with arguments → returns a Future for the result
	pub fn spawn<F, T>(
		&self,
		priority: Priority,
		f: F,
	) -> impl std::future::Future<Output = ClResult<T>>
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
			Priority::High => {
				if self.high.send(job).is_err() {
					error!("Failed to send job to high priority worker queue");
				}
			}
			Priority::Medium => {
				if self.med.send(job).is_err() {
					error!("Failed to send job to medium priority worker queue");
				}
			}
			Priority::Low => {
				if self.low.send(job).is_err() {
					error!("Failed to send job to low priority worker queue");
				}
			}
		}

		async move {
			res_rx.await.map_err(|_| {
				error!("Worker dropped result channel (task may have panicked)");
				Error::Internal("worker task failed".into())
			})
		}
	}

	pub fn run<F, T>(&self, f: F) -> impl std::future::Future<Output = ClResult<T>>
	where
		F: FnOnce() -> T + Send + 'static,
		T: Send + 'static,
	{
		info!("[RUN normal]");
		let (res_tx, res_rx) = oneshot::channel();

		let job = Box::new(move || {
			let result = f();
			let _ignore = res_tx.send(result);
		});

		if self.med.send(job).is_err() {
			error!("Failed to send job to medium priority worker queue");
		}

		async move {
			res_rx.await.map_err(|_| {
				error!("Worker dropped result channel (task may have panicked)");
				Error::Internal("worker task failed".into())
			})
		}
	}

	pub fn run_immed<F, T>(&self, f: F) -> impl std::future::Future<Output = ClResult<T>>
	where
		F: FnOnce() -> T + Send + 'static,
		T: Send + 'static,
	{
		let (res_tx, res_rx) = oneshot::channel();

		let job = Box::new(move || {
			let result = f();
			let _ignore = res_tx.send(result);
		});

		if self.high.send(job).is_err() {
			error!("Failed to send job to high priority worker queue");
		}

		async move {
			res_rx.await.map_err(|_| {
				error!("Worker dropped result channel (task may have panicked)");
				Error::Internal("worker task failed".into())
			})
		}
	}

	pub fn run_slow<F, T>(&self, f: F) -> impl std::future::Future<Output = ClResult<T>>
	where
		F: FnOnce() -> T + Send + 'static,
		T: Send + 'static,
	{
		info!("[RUN slow]");
		let (res_tx, res_rx) = oneshot::channel();

		let job = Box::new(move || {
			let result = f();
			let _ignore = res_tx.send(result);
		});

		if self.low.send(job).is_err() {
			error!("Failed to send job to low priority worker queue");
		}

		async move {
			res_rx.await.map_err(|_| {
				error!("Worker dropped result channel (task may have panicked)");
				Error::Internal("worker task failed".into())
			})
		}
	}

	/// Like `run`, but flattens `ClResult<ClResult<T>>` into `ClResult<T>`.
	/// Use when the closure itself returns `ClResult<T>`.
	pub fn try_run<F, T>(&self, f: F) -> impl std::future::Future<Output = ClResult<T>>
	where
		F: FnOnce() -> ClResult<T> + Send + 'static,
		T: Send + 'static,
	{
		let fut = self.run(f);
		async move { fut.await? }
	}

	/// Like `run_immed`, but flattens `ClResult<ClResult<T>>` into `ClResult<T>`.
	/// Use when the closure itself returns `ClResult<T>`.
	pub fn try_run_immed<F, T>(&self, f: F) -> impl std::future::Future<Output = ClResult<T>>
	where
		F: FnOnce() -> ClResult<T> + Send + 'static,
		T: Send + 'static,
	{
		let fut = self.run_immed(f);
		async move { fut.await? }
	}

	/// Like `run_slow`, but flattens `ClResult<ClResult<T>>` into `ClResult<T>`.
	/// Use when the closure itself returns `ClResult<T>`.
	pub fn try_run_slow<F, T>(&self, f: F) -> impl std::future::Future<Output = ClResult<T>>
	where
		F: FnOnce() -> ClResult<T> + Send + 'static,
		T: Send + 'static,
	{
		let fut = self.run_slow(f);
		async move { fut.await? }
	}
}

type JobQueue = Arc<Receiver<Box<dyn FnOnce() + Send>>>;

fn worker_loop(queues: &[JobQueue]) {
	loop {
		// Try higher-priority queues first (non-blocking)
		let mut job = None;
		for rx in queues {
			if let Ok(j) = rx.try_recv() {
				job = Some(j);
				break;
			}
		}

		if let Some(job) = job {
			if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job)) {
				error!("Worker thread caught panic: {:?}", e);
			}
			continue;
		}

		// Wait for next job
		let mut selector = flume::Selector::new();
		for rx in queues {
			selector = selector.recv(rx, |res| res);
		}

		let job: Result<Box<dyn FnOnce() + Send>, flume::RecvError> = selector.wait();
		if let Ok(job) = job {
			if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job)) {
				error!("Worker thread caught panic: {:?}", e);
			}
		}
	}
}

// vim: ts=4
