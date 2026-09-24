// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! The text of a PDF, flattened for indexing.
//!
//! `pdftotext` from poppler-utils does the parsing. It is already a deployment
//! dependency — `cloudillo_file::pdf` shells out to `pdfinfo` and `pdftoppm` for
//! page counts and thumbnails — so this costs one more binary in the image and no
//! crate that would have to parse untrusted PDFs inside a `#![forbid(unsafe_code)]`
//! tree.
//!
//! The input is a path, not a buffer: `pdftotext` wants a seekable input, so feeding
//! a PDF in on stdin while draining stdout is a pipe-buffer deadlock waiting to
//! happen. Materialising the blob is the caller's job, which also matches
//! `cloudillo_file::pdf`, where `get_pdf_info` and `generate_pdf_thumbnail` already
//! take a `&Path`.
//!
//! OCR is out of scope: an image-only scan yields no text and is left to be found
//! by its name and tags.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use cloudillo_types::prelude::*;

use crate::text::{Acc, ExtractedText};

/// Largest PDF this extractor will hand to `pdftotext`.
///
/// Mirrors `html::MAX_INPUT_BYTES` and is much larger, because a PDF is a whole
/// document rather than one page fragment. The caller is expected to check the
/// stored size before materialising the blob — uploads run with `DefaultBodyLimit`
/// disabled, so a file this big exists — and the `metadata` check below is the
/// backstop for the paths that do not.
pub const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;

/// Whether `pdftotext` can be started at all, probed once per process.
///
/// A missing binary is an operator condition, not a property of any one PDF: without
/// this the same spawn failure would surface as a per-file `Internal` on every index
/// run. Probed once and cached, so installing poppler needs a restart to take effect.
pub fn available() -> bool {
	static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
	*AVAILABLE.get_or_init(|| {
		Command::new("pdftotext")
			.arg("-v")
			.stdin(Stdio::null())
			.stdout(Stdio::null())
			.stderr(Stdio::null())
			.status()
			.is_ok()
	})
}

/// Whether util-linux `prlimit` can be started, probed once per process. Without it the
/// child runs with no address-space or CPU limit.
fn prlimit_available() -> bool {
	static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
	*AVAILABLE.get_or_init(|| {
		let ok = Command::new("prlimit")
			.arg("--version")
			.stdin(Stdio::null())
			.stdout(Stdio::null())
			.stderr(Stdio::null())
			.status()
			.is_ok();
		if !ok {
			warn!("prlimit is not available; pdftotext runs without resource limits");
		}
		ok
	})
}

/// Address-space limit for the `pdftotext` child.
const MAX_CHILD_AS_BYTES: u64 = 1024 * 1024 * 1024;

/// Output bytes read per indexed character before the child is killed.
///
/// Four is UTF-8's widest encoding; the rest is slack for the whitespace the
/// accumulator collapses, which costs bytes and no budget. Hitting the derived cap
/// only sets [`ExtractedText::truncated`], which is the honest answer for a document
/// that really does run past the budget.
const BYTES_PER_CHAR: usize = 8;
/// Floor under the derived cap, so a tiny `max_chars` still reads a whole page of
/// `pdftotext` preamble rather than cutting mid-word.
const MIN_OUTPUT_BYTES: usize = 64 * 1024;
/// Ceiling over it. PDF content streams are deflate-compressed, so a file inside
/// [`MAX_INPUT_BYTES`] can expand to gigabytes of text.
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// Wall clock a single `pdftotext` run may take before it is killed.
///
/// Not a performance budget — the ceiling on a crafted PDF that makes poppler
/// spin. The pool that runs this has three Medium-queue threads
/// (`WorkerPool::new(1, 2, 1)` in `server/src/main.rs`), all of which also serve High,
/// so a child that never returns costs far more than this job. A legitimate document
/// that needs more than 30s of `pdftotext` is pathological.
// ponytail: no per-sweep extraction budget — the first sweep over a PDF-heavy tenant is
// bounded only by the caller's one-permit semaphore. Every later sweep re-extracts nothing
// (the stamp part caches both outcomes), so a budget only pays off if first-sweep latency
// matters.
const EXTRACT_TIMEOUT: Duration = Duration::from_secs(30);

/// How often the watchdog rechecks a child that has closed stdout but not yet exited.
/// Only ever runs in the window between EOF and exit, which is normally microseconds.
const EXIT_POLL: Duration = Duration::from_millis(50);

/// Output bytes worth reading for a `max_chars` budget.
///
/// Split out of [`extract_text`] so the clamp can be tested without poppler.
fn output_cap(max_chars: usize) -> usize {
	max_chars
		.saturating_mul(BYTES_PER_CHAR)
		.clamp(MIN_OUTPUT_BYTES, MAX_OUTPUT_BYTES)
}

/// Extract the text of the PDF at `path`.
///
/// `max_chars` bounds the answer in characters; the whole document is still parsed,
/// and reaching the budget sets [`ExtractedText::truncated`], as does the child
/// producing more than [`output_cap`] bytes for it.
///
/// Everything that is a permanent property of *this blob* comes back as
/// [`Error::ValidationError`], which callers treat as "index it without a body"
/// rather than retrying it forever: past [`MAX_INPUT_BYTES`], past
/// [`EXTRACT_TIMEOUT`], or a non-zero `pdftotext` exit — which is what an encrypted
/// file, a damaged content stream, or something that is not really a PDF produces.
/// Only `pdftotext` failing to start stays [`Error::Internal`]: a binary missing
/// from the image is an operator problem and must keep failing loudly.
///
/// The child's stderr is discarded rather than reported — an unread stderr pipe can
/// fill and block the child, `-q` already suppresses poppler's chatter, and the exit
/// status is the whole diagnosis.
///
/// Blocking: it spawns a process and waits. Callers on the async runtime put it on the
/// worker pool.
///
/// Plain reading order, not `-layout` — column padding buys a tokenizer nothing. The
/// form feeds poppler writes between pages normalise away like any other whitespace.
pub fn extract_text(path: &Path, max_chars: usize) -> ClResult<ExtractedText> {
	if std::fs::metadata(path)?.len() > MAX_INPUT_BYTES as u64 {
		return Err(Error::ValidationError("PDF input exceeds the extraction limit".into()));
	}

	// `prlimit` execs `pdftotext`, so the watchdog's kill still lands on it.
	let mut cmd = if prlimit_available() {
		let mut cmd = Command::new("prlimit");
		cmd.arg(format!("--as={MAX_CHILD_AS_BYTES}"))
			.arg(format!("--cpu={}", EXTRACT_TIMEOUT.as_secs()))
			.args(["--", "pdftotext"]);
		cmd
	} else {
		Command::new("pdftotext")
	};
	// `stdin` must be set explicitly: unlike `output()`, `spawn()` leaves it inherited.
	let mut child = cmd
		.args(["-q", "-enc", "UTF-8"])
		.arg(path)
		.arg("-")
		.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::null())
		.spawn()
		.map_err(|e| Error::Internal(format!("pdftotext failed to start: {e}")))?;
	let stdout = child.stdout.take().ok_or_else(|| Error::Internal("pdftotext stdout".into()))?;

	// The watchdog *owns* the child, so killing it needs no shared lock. The channel
	// is the only signal it takes: a timeout fires the kill, a send asks for one, and
	// a disconnect means this thread read to EOF.
	//
	// The deadline is absolute and no branch escapes it. EOF on stdout is not proof of
	// exit, so a child that finishes writing and then hangs would otherwise block
	// `wait()` forever — holding one of the pool's three Medium threads, which also serve
	// High, and that is the exact failure this watchdog exists to prevent.
	let deadline = Instant::now() + EXTRACT_TIMEOUT;
	let (tx, rx) = mpsc::channel::<()>();
	let timed_out = Arc::new(AtomicBool::new(false));
	let overstayed = Arc::new(AtomicBool::new(false));
	let watchdog = {
		let timed_out = Arc::clone(&timed_out);
		let overstayed = Arc::clone(&overstayed);
		std::thread::spawn(move || {
			match rx.recv_timeout(EXTRACT_TIMEOUT) {
				Err(RecvTimeoutError::Timeout) => {
					timed_out.store(true, Ordering::Relaxed);
					let _ = child.kill();
				}
				Ok(()) => {
					let _ = child.kill();
				}
				// Clean EOF: the output is already in hand, so the child is given the
				// rest of the deadline to exit on its own and killed if it will not.
				Err(RecvTimeoutError::Disconnected) => {
					while !matches!(child.try_wait(), Ok(Some(_)) | Err(_)) {
						if Instant::now() >= deadline {
							overstayed.store(true, Ordering::Relaxed);
							let _ = child.kill();
							break;
						}
						std::thread::sleep(EXIT_POLL);
					}
				}
			}
			child.wait()
		})
	};

	let cap = output_cap(max_chars);
	let mut buf = Vec::new();
	// One byte past the cap, so "cap hit" and "whole output, then EOF" are distinguishable.
	let mut limited = stdout.take(cap as u64 + 1);
	let read = limited.read_to_end(&mut buf);
	// Closes the read end, so a child still writing gets EPIPE rather than blocking.
	drop(limited);
	let hit_cap = matches!(read, Ok(n) if n > cap);
	// Asked for either reason, because returning the read error while the watchdog
	// still holds the child would leave both alive for the whole timeout.
	if hit_cap || read.is_err() {
		let _ = tx.send(());
	} else {
		drop(tx);
	}
	let status = watchdog
		.join()
		.map_err(|_| Error::Internal("pdftotext watchdog panicked".into()))?
		.map_err(|e| Error::Internal(format!("pdftotext wait failed: {e}")))?;
	read?;

	// Checked before the status, which is meaningless once we killed the child: what
	// was read is a valid prefix of the document's text.
	if hit_cap {
		let mut out = accumulate(&buf, max_chars);
		out.truncated = true;
		return Ok(out);
	}
	// Same reason as `hit_cap`, and deliberately *not* `timed_out`: the output was read
	// in full and only the child overstayed, so the text is the whole document's and
	// throwing it away would cost a good PDF its body.
	if overstayed.load(Ordering::Relaxed) {
		return Ok(accumulate(&buf, max_chars));
	}
	if timed_out.load(Ordering::Relaxed) {
		return Err(Error::ValidationError("PDF extraction timed out".into()));
	}
	if !status.success() {
		return Err(Error::ValidationError(format!(
			"pdftotext cannot read this PDF (exit {})",
			status.code().map_or_else(|| "signal".to_owned(), |c| c.to_string())
		)));
	}
	Ok(accumulate(&buf, max_chars))
}

fn accumulate(out: &[u8], max_chars: usize) -> ExtractedText {
	// The buffer is cut at a *byte* cap, so its last character is usually split in
	// half; decoding that tail would put a U+FFFD in the index. Everything before the
	// break is valid UTF-8, which is what poppler wrote with `-enc UTF-8`.
	let valid = std::str::from_utf8(out).map_or_else(|e| e.valid_up_to(), |_| out.len());
	let mut acc = Acc::new(max_chars);
	acc.push(std::str::from_utf8(&out[..valid]).unwrap_or_default());
	acc.take()
}

#[cfg(test)]
mod tests {
	use super::*;

	/// One page, uncompressed content stream, literal text — see
	/// `tests/fixtures/hello.pdf`. Byte-exact: its xref entries are 20 bytes each,
	/// trailing space included, which is why `.gitattributes` marks it binary.
	const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/hello.pdf");

	/// The extraction tests need poppler. A machine without it skips them rather than
	/// failing the suite — `pdftotext` is a deployment dependency, not a build one — but
	/// says so on stdout, so a skip is never mistaken for a pass.
	fn skipped_without_poppler(test: &str) -> bool {
		let missing = !available();
		if missing {
			eprintln!("skipping {test}: pdftotext is not installed");
		}
		missing
	}

	#[test]
	fn an_oversized_pdf_is_refused_rather_than_parsed() {
		// Sparse: `set_len` allocates no blocks, and the size check comes before the
		// spawn, so this needs neither 64 MiB of disk nor poppler.
		let file = tempfile::NamedTempFile::new().expect("temp file");
		file.as_file().set_len(MAX_INPUT_BYTES as u64 + 1).expect("set_len");
		let result = extract_text(file.path(), 16);
		assert!(matches!(result, Err(Error::ValidationError(_))), "got {result:?}");
	}

	#[test]
	fn a_pdf_is_extracted_down_to_its_words() {
		if skipped_without_poppler("a_pdf_is_extracted_down_to_its_words") {
			return;
		}
		let out = extract_text(Path::new(FIXTURE), 16_000).expect("extracted");
		assert_eq!(out.text, "Arvizturo tukorfurogep");
		// The form feed poppler writes after the page normalised away with the rest of
		// the whitespace, and nothing was cut.
		assert!(!out.truncated);
	}

	#[test]
	fn a_budget_smaller_than_the_document_truncates_and_says_so() {
		if skipped_without_poppler("a_budget_smaller_than_the_document_truncates_and_says_so") {
			return;
		}
		let out = extract_text(Path::new(FIXTURE), 5).expect("extracted");
		assert_eq!(out.text, "Arviz");
		assert!(out.truncated);
	}

	#[test]
	fn something_that_is_not_a_pdf_is_a_permanent_property_of_the_blob() {
		if skipped_without_poppler(
			"something_that_is_not_a_pdf_is_a_permanent_property_of_the_blob",
		) {
			return;
		}
		// `ValidationError`, not `Internal`: the caller indexes the file without a body
		// and writes the stamp, rather than retrying this blob on every sweep.
		let file = tempfile::NamedTempFile::new().expect("temp file");
		std::fs::write(file.path(), b"not a pdf at all").expect("write");
		let result = extract_text(file.path(), 16_000);
		assert!(matches!(result, Err(Error::ValidationError(_))), "got {result:?}");
	}

	#[test]
	fn the_output_cap_follows_the_budget_between_its_floor_and_ceiling() {
		// A tiny budget still reads a whole page of preamble.
		assert_eq!(output_cap(1), MIN_OUTPUT_BYTES);
		// In between it tracks `max_chars`.
		let mid = MIN_OUTPUT_BYTES * 2 / BYTES_PER_CHAR + 1;
		assert_eq!(output_cap(mid), mid * BYTES_PER_CHAR);
		// And a budget past the ceiling — or one that would overflow the multiply —
		// stops there rather than wrapping.
		assert_eq!(output_cap(MAX_OUTPUT_BYTES), MAX_OUTPUT_BYTES);
		assert_eq!(output_cap(usize::MAX), MAX_OUTPUT_BYTES);
	}
}

// vim: ts=4
