// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

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
		Self::build(n1, n2, n3).0
	}

	/// `new`, plus a witness whose strong count is the number of live worker threads —
	/// each worker holds a clone until `worker_loop` returns.
	fn build(n1: usize, n2: usize, n3: usize) -> (Self, std::sync::Weak<()>) {
		let (high, rx_high) = flume::unbounded();
		let (med, rx_med) = flume::unbounded();
		let (low, rx_low) = flume::unbounded();

		let rx_high = Arc::new(rx_high);
		let rx_med = Arc::new(rx_med);
		let rx_low = Arc::new(rx_low);

		let alive = Arc::new(());
		let witness = Arc::downgrade(&alive);

		// Workers dedicated to High only
		for _ in 0..n1 {
			let rx_high = Arc::clone(&rx_high);
			let alive = Arc::clone(&alive);
			thread::spawn(move || {
				worker_loop(&[rx_high]);
				drop(alive);
			});
		}

		// Workers for High + Medium
		for _ in 0..n2 {
			let rx_high = Arc::clone(&rx_high);
			let rx_med = Arc::clone(&rx_med);
			let alive = Arc::clone(&alive);
			thread::spawn(move || {
				worker_loop(&[rx_high, rx_med]);
				drop(alive);
			});
		}

		// Workers for High + Medium + Low
		for _ in 0..n3 {
			let rx_high = Arc::clone(&rx_high);
			let rx_med = Arc::clone(&rx_med);
			let rx_low = Arc::clone(&rx_low);
			let alive = Arc::clone(&alive);
			thread::spawn(move || {
				worker_loop(&[rx_high, rx_med, rx_low]);
				drop(alive);
			});
		}

		drop(alive);
		(Self { high, med, low }, witness)
	}

	/// Submit a closure with arguments → returns a Future for the result
	pub fn spawn<F, T>(
		&self,
		priority: Priority,
		f: F,
	) -> impl std::future::Future<Output = ClResult<T>> + use<F, T>
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

	pub fn run<F, T>(&self, f: F) -> impl std::future::Future<Output = ClResult<T>> + use<F, T>
	where
		F: FnOnce() -> T + Send + 'static,
		T: Send + 'static,
	{
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

	pub fn run_immed<F, T>(
		&self,
		f: F,
	) -> impl std::future::Future<Output = ClResult<T>> + use<F, T>
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

	pub fn run_slow<F, T>(&self, f: F) -> impl std::future::Future<Output = ClResult<T>> + use<F, T>
	where
		F: FnOnce() -> T + Send + 'static,
		T: Send + 'static,
	{
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
	pub fn try_run<F, T>(&self, f: F) -> impl std::future::Future<Output = ClResult<T>> + use<F, T>
	where
		F: FnOnce() -> ClResult<T> + Send + 'static,
		T: Send + 'static,
	{
		let fut = self.run(f);
		async move { fut.await? }
	}

	/// Like `run_immed`, but flattens `ClResult<ClResult<T>>` into `ClResult<T>`.
	/// Use when the closure itself returns `ClResult<T>`.
	pub fn try_run_immed<F, T>(
		&self,
		f: F,
	) -> impl std::future::Future<Output = ClResult<T>> + use<F, T>
	where
		F: FnOnce() -> ClResult<T> + Send + 'static,
		T: Send + 'static,
	{
		let fut = self.run_immed(f);
		async move { fut.await? }
	}

	/// Like `run_slow`, but flattens `ClResult<ClResult<T>>` into `ClResult<T>`.
	/// Use when the closure itself returns `ClResult<T>`.
	pub fn try_run_slow<F, T>(
		&self,
		f: F,
	) -> impl std::future::Future<Output = ClResult<T>> + use<F, T>
	where
		F: FnOnce() -> ClResult<T> + Send + 'static,
		T: Send + 'static,
	{
		let fut = self.run_slow(f);
		async move { fut.await? }
	}
}

type JobQueue = Arc<Receiver<Box<dyn FnOnce() + Send>>>;

fn run_job(job: Box<dyn FnOnce() + Send>) {
	if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job)) {
		error!("Worker thread caught panic: {:?}", e);
	}
}

fn worker_loop(queues: &[JobQueue]) {
	// Queues still worth waiting on. flume reports a disconnected channel as *ready*, so a
	// dead queue left in the wait set turns `Selector::wait` into a busy spin that outlives
	// the pool. Drop each one once its sender is gone and its buffer drained; stop when the
	// set empties.
	let mut live: Vec<&JobQueue> = queues.iter().collect();

	loop {
		// Try higher-priority queues first (non-blocking)
		let mut job = None;
		for rx in &live {
			if let Ok(j) = rx.try_recv() {
				job = Some(j);
				break;
			}
		}
		if let Some(job) = job {
			run_job(job);
			continue;
		}

		live.retain(|rx| !rx.is_disconnected() || !rx.is_empty());
		if live.is_empty() {
			break;
		}

		// Wait for next job
		let mut selector = flume::Selector::new();
		for &rx in &live {
			selector = selector.recv(rx, |res| res);
		}
		match selector.wait() {
			Ok(job) => run_job(job),
			// A sender dropped while we waited. Loop: the `try_recv` sweep drains what is
			// left and `retain` prunes the dead queue.
			Err(flume::RecvError::Disconnected) => (),
		}
	}
}

#[cfg(test)]
mod tests {
	#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

	use super::*;
	use std::sync::{
		Weak,
		atomic::{AtomicBool, Ordering},
	};
	use std::time::{Duration, Instant};

	/// Poll `alive` until every worker thread has returned, or the deadline expires.
	fn wait_for_exit(alive: &Weak<()>, timeout: Duration) -> usize {
		let deadline = Instant::now() + timeout;
		loop {
			let count = alive.strong_count();
			if count == 0 || Instant::now() >= deadline {
				return count;
			}
			thread::sleep(Duration::from_millis(5));
		}
	}

	#[test]
	fn workers_exit_when_pool_is_dropped() {
		let (pool, alive) = WorkerPool::build(1, 1, 1);
		assert_eq!(alive.strong_count(), 3, "expected 3 worker threads");

		drop(pool);

		assert_eq!(
			wait_for_exit(&alive, Duration::from_secs(2)),
			0,
			"worker threads did not exit after the pool was dropped"
		);
	}

	#[test]
	fn queued_jobs_run_before_workers_exit() {
		// A single worker serving [high, med], so the two jobs below are strictly ordered.
		let (pool, alive) = WorkerPool::build(0, 1, 0);

		// Occupy the worker so the second job is still buffered when the pool drops.
		let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
		let blocker = pool.run(move || {
			let _ignore = release_rx.recv();
		});

		let ran = Arc::new(AtomicBool::new(false));
		let flag = Arc::clone(&ran);
		let queued = pool.run(move || flag.store(true, Ordering::SeqCst));

		drop(pool);
		drop(blocker);
		drop(queued);

		// Let the worker go; it must drain the buffered job before exiting.
		let _ignore = release_tx.send(());
		drop(release_tx);

		assert_eq!(
			wait_for_exit(&alive, Duration::from_secs(2)),
			0,
			"worker thread did not exit after the pool was dropped"
		);
		assert!(ran.load(Ordering::SeqCst), "job queued before the pool dropped was never run");
	}
}

// vim: ts=4
