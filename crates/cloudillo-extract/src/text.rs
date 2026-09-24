// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! What every extractor in this crate answers with, and the accumulator that
//! builds it.
//!
//! Whitespace normalisation and the character budget are the same job whatever the
//! source format — an HTML walk's text chunks, a `pdftotext` dump's lines and form
//! feeds — so they live here rather than with either extractor.

/// Flattened visible text, plus whether the budget cut the walk short.
#[derive(Debug, Default, Clone)]
pub struct ExtractedText {
	/// Whitespace-normalised text: no run of blanks, no leading or trailing one.
	pub text: String,
	/// `true` when `max_chars` was reached before the end of the input, so the
	/// caller knows the text is a prefix rather than the whole document.
	pub truncated: bool,
}

/// Whitespace-normalising text accumulator with a character budget.
pub(crate) struct Acc {
	out: String,
	budget: usize,
	chars: usize,
	truncated: bool,
	/// A boundary is owed before the next visible character. Held rather than
	/// written so the result never opens or closes with a blank.
	pending: bool,
	/// A trailing fragment of what may be a character reference, waiting for the
	/// rest of it to arrive in the next chunk. See `html::Acc::push_chunk`; only
	/// the HTML path ever fills it.
	pub(crate) held: String,
}

impl Acc {
	pub(crate) fn new(budget: usize) -> Self {
		Self {
			out: String::new(),
			budget,
			chars: 0,
			truncated: false,
			pending: false,
			held: String::new(),
		}
	}

	/// The boundary alone, for [`Acc::push`] — flushing the held tail from there
	/// would re-enter `push` on its own input.
	pub(crate) fn mark_boundary(&mut self) {
		if self.chars > 0 {
			self.pending = true;
		}
	}

	pub(crate) fn flush_held(&mut self) {
		if !self.held.is_empty() {
			let held = std::mem::take(&mut self.held);
			self.push(&held);
		}
	}

	pub(crate) fn push(&mut self, text: &str) {
		for c in text.chars() {
			if self.chars >= self.budget {
				self.truncated = true;
				return;
			}
			// A control character is a word boundary, not text. The HTML side refuses
			// them at the one place they can appear (`html::decode_ref`); a PDF text
			// layer carries whatever the producer wrote, and `search_docs.body` feeds
			// the `snippet` API verbatim.
			if c.is_whitespace() || c.is_control() {
				self.mark_boundary();
				continue;
			}
			if self.pending {
				self.out.push(' ');
				self.chars += 1;
				self.pending = false;
				if self.chars >= self.budget {
					self.truncated = true;
					return;
				}
			}
			self.out.push(c);
			self.chars += 1;
		}
	}

	pub(crate) fn take(&mut self) -> ExtractedText {
		// A candidate reference the document ended in the middle of never was one:
		// it is a bare `&` and whatever followed it, and it is page text.
		self.flush_held();
		ExtractedText { text: std::mem::take(&mut self.out), truncated: self.truncated }
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn run(budget: usize, chunks: &[&str]) -> ExtractedText {
		let mut acc = Acc::new(budget);
		for chunk in chunks {
			acc.push(chunk);
		}
		acc.take()
	}

	#[test]
	fn whitespace_collapses_and_never_reaches_an_edge() {
		let out = run(64, &["  hello \n\n  world  "]);
		assert_eq!(out.text, "hello world");
		assert!(!out.truncated);
	}

	#[test]
	fn a_form_feed_is_just_another_blank() {
		// What `pdftotext` writes between pages; nothing downstream should see it.
		let out = run(64, &["page one\x0Cpage two"]);
		assert_eq!(out.text, "page one page two");
	}

	#[test]
	fn a_control_character_is_a_boundary_rather_than_indexed_text() {
		// A PDF text layer carries whatever its producer wrote; `strip_marks` in the
		// meta adapter only removes the two snippet markers, so the filter is here.
		let out = run(64, &["bal\u{1}oldal\u{7}jobb"]);
		assert_eq!(out.text, "bal oldal jobb");
	}

	#[test]
	fn the_budget_cuts_at_exactly_its_count_and_says_so() {
		let out = run(4, &["hello world"]);
		assert_eq!(out.text, "hell");
		assert!(out.truncated);
	}

	#[test]
	fn multi_byte_characters_cost_one_character_each() {
		// Four chars, eight bytes: a byte budget would cut this in half.
		let out = run(4, &["árvíztűrő"]);
		assert_eq!(out.text, "árví");
		assert!(out.truncated);
	}
}

// vim: ts=4
