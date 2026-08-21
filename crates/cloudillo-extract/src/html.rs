// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! The visible text of an HTML document, flattened for indexing.

use std::cell::RefCell;
use std::rc::Rc;

use cloudillo_types::prelude::*;
use lol_html::html_content::TextType;
use lol_html::{EndTagHandler, HtmlRewriter, Settings, doc_text, element};

/// Flattened visible text, plus whether the budget cut the walk short.
#[derive(Debug, Default, Clone)]
pub struct ExtractedText {
	/// Whitespace-normalised text: no run of blanks, no leading or trailing one.
	pub text: String,
	/// `true` when `max_chars` was reached before the end of the input, so the
	/// caller knows the text is a prefix rather than the whole document.
	pub truncated: bool,
}

/// Elements whose start is a word boundary.
///
/// Inline marks are deliberately absent: separating on `<em>` would tokenise
/// `<em>Cloud</em>illo` as two words. Splitting where the reader sees a line
/// break and joining where they see none is the closest a flat string gets to
/// what was on the page.
const BLOCK_ELEMENTS: &str = "address, article, aside, blockquote, br, dd, div, dl, dt, \
	 figcaption, figure, footer, form, h1, h2, h3, h4, h5, h6, header, hr, li, main, nav, ol, \
	 option, p, pre, section, table, tbody, td, tfoot, th, thead, tr, ul";

/// Largest document this extractor will parse.
///
/// `max_chars` bounds the answer, not the work: the tokenizer walks the whole input
/// regardless, and a container entry is a page fragment. Doubles as the parser arena's
/// hard limit, so a pathological document that fits the input cap still cannot grow the
/// rewriter's buffers without bound.
pub const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;

/// Extract the visible text of an HTML document or fragment.
///
/// The walk is structural, not heuristic. `<script>` and `<style>` content is skipped
/// because the tokenizer hands it over as [`TextType::ScriptData`] and
/// [`TextType::RawText`] rather than [`TextType::Data`] — no tag list to keep in step.
/// Attribute values never reach a text handler, so a serialized island's `data-props`
/// payload is skipped for free while the visible text *inside* the placeholder is taken,
/// which is what a snippet needs to match what the reader sees.
///
/// `max_chars` bounds the answer in characters; reaching it stops the walk and sets
/// [`ExtractedText::truncated`], though the parse still runs to completion. The *input*
/// is bounded separately by [`MAX_INPUT_BYTES`].
pub fn extract_text(html: &str, max_chars: usize) -> ClResult<ExtractedText> {
	if html.len() > MAX_INPUT_BYTES {
		return Err(Error::ValidationError("HTML input exceeds the extraction limit".into()));
	}

	let acc = Rc::new(RefCell::new(Acc::new(max_chars)));
	let text_acc = Rc::clone(&acc);
	let sep_acc = Rc::clone(&acc);

	let mut rewriter = HtmlRewriter::new(
		Settings {
			element_content_handlers: vec![element!(BLOCK_ELEMENTS, move |el| {
				if let Ok(mut acc) = sep_acc.try_borrow_mut() {
					acc.separate();
				}
				// A block's *end* is a word boundary too: without this `</p>text`
				// concatenates. Void elements have no end tag and need none — they
				// already separated on the way in.
				if let Some(handlers) = el.end_tag_handlers() {
					let end_acc = Rc::clone(&sep_acc);
					// Typed rather than inferred: the vec holds boxed trait objects,
					// and a bare `Box::new` infers the closure's own type.
					let handler: EndTagHandler<'static> = Box::new(move |_end| {
						if let Ok(mut acc) = end_acc.try_borrow_mut() {
							acc.separate();
						}
						Ok(())
					});
					handlers.push(handler);
				}
				Ok(())
			})],
			document_content_handlers: vec![doc_text!(move |chunk| {
				if matches!(chunk.text_type(), TextType::Data | TextType::CDataSection)
					&& let Ok(mut acc) = text_acc.try_borrow_mut()
				{
					acc.push_chunk(chunk.as_str());
				}
				Ok(())
			})],
			// `Settings::default()` leaves the arena at `usize::MAX`, so a
			// document that fits [`MAX_INPUT_BYTES`] could still make the
			// rewriter's internal buffers grow without bound.
			memory_settings: lol_html::MemorySettings {
				max_allowed_memory_usage: MAX_INPUT_BYTES,
				..lol_html::MemorySettings::default()
			},
			..Settings::default()
		},
		|_: &[u8]| {},
	);
	rewriter
		.write(html.as_bytes())
		.map_err(|e| Error::Internal(format!("HTML text extraction failed: {e}")))?;
	// Consumes the rewriter, releasing the handlers and the two `Rc` clones they captured.
	rewriter
		.end()
		.map_err(|e| Error::Internal(format!("HTML text extraction failed: {e}")))?;

	let mut acc = acc
		.try_borrow_mut()
		.map_err(|_| Error::Internal("HTML text accumulator is still borrowed".into()))?;
	Ok(acc.take())
}

/// Whitespace-normalising text accumulator with a character budget.
struct Acc {
	out: String,
	budget: usize,
	chars: usize,
	truncated: bool,
	/// A boundary is owed before the next visible character. Held rather than
	/// written so the result never opens or closes with a blank.
	pending: bool,
	/// A trailing fragment of what may be a character reference, waiting for the
	/// rest of it to arrive in the next chunk. See [`Acc::push_chunk`].
	held: String,
}

impl Acc {
	fn new(budget: usize) -> Self {
		Self {
			out: String::new(),
			budget,
			chars: 0,
			truncated: false,
			pending: false,
			held: String::new(),
		}
	}

	/// Take one text chunk, resolving its character references *before* they
	/// reach the whitespace normaliser and the budget.
	///
	/// Decoding here rather than over the finished string is what makes `&nbsp;` normalise
	/// like the blank it decodes to, and `&#128512;` cost one character of budget, not nine.
	///
	/// `lol_html` may split a reference across two chunks, so a trailing candidate — a `&`
	/// followed only by name or numeric characters, with no `;` yet — is held back and
	/// prepended to the next chunk. One that never completes is flushed verbatim at the next
	/// element boundary or at the end: `Tom & Jerry` is page text, not a cut-off reference.
	fn push_chunk(&mut self, chunk: &str) {
		let mut text = std::mem::take(&mut self.held);
		text.push_str(chunk);

		let split = text.rfind('&').filter(|&at| {
			text.len() - at < MAX_ENTITY_LEN
				&& text[at + 1..].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'#')
		});
		if let Some(at) = split {
			text[at..].clone_into(&mut self.held);
			text.truncate(at);
		}
		self.push(&decode_entities(&text));
	}

	/// A word boundary from the document's structure. Any held reference candidate
	/// ends here too: a character reference cannot span an element boundary, so
	/// whatever is held is page text and belongs *before* the boundary.
	fn separate(&mut self) {
		self.flush_held();
		self.mark_boundary();
	}

	/// The boundary alone, for [`Acc::push`] — flushing the held tail from there
	/// would re-enter `push` on its own input.
	fn mark_boundary(&mut self) {
		if self.chars > 0 {
			self.pending = true;
		}
	}

	fn flush_held(&mut self) {
		if !self.held.is_empty() {
			let held = std::mem::take(&mut self.held);
			self.push(&held);
		}
	}

	fn push(&mut self, text: &str) {
		for c in text.chars() {
			if self.chars >= self.budget {
				self.truncated = true;
				return;
			}
			if c.is_whitespace() {
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

	fn take(&mut self) -> ExtractedText {
		// A candidate reference the document ended in the middle of never was one:
		// it is a bare `&` and whatever followed it, and it is page text.
		self.flush_held();
		ExtractedText { text: std::mem::take(&mut self.out), truncated: self.truncated }
	}
}

/// Resolve character references left in the text.
///
/// `lol_html` hands text over exactly as it appeared in the source, so the serializer's
/// escaping has to be undone here or `&amp;` is indexed as three tokens. Unknown
/// references are kept verbatim: an unrecognised `&foo;` is far more likely page text
/// than a reference this table is missing.
fn decode_entities(input: &str) -> String {
	if !input.contains('&') {
		return input.to_owned();
	}
	let mut out = String::with_capacity(input.len());
	let mut rest = input;
	while let Some(start) = rest.find('&') {
		out.push_str(&rest[..start]);
		let tail = &rest[start..];
		// A reference is ASCII and short; anything longer is a stray ampersand.
		let limit = tail.len().min(MAX_ENTITY_LEN);
		let semi = tail.as_bytes()[..limit].iter().position(|&b| b == b';');
		if let Some((c, end)) = semi.and_then(|end| decode_ref(&tail[1..end]).map(|c| (c, end))) {
			out.push(c);
			rest = &tail[end + 1..];
		} else {
			out.push('&');
			rest = &tail[1..];
		}
	}
	out.push_str(rest);
	out
}

/// Longest reference this decoder will look for, `&` and `;` included.
const MAX_ENTITY_LEN: usize = 12;

fn decode_ref(name: &str) -> Option<char> {
	match name {
		"amp" => Some('&'),
		"lt" => Some('<'),
		"gt" => Some('>'),
		"quot" => Some('"'),
		"apos" => Some('\''),
		"nbsp" => Some(' '),
		_ => {
			let digits = name.strip_prefix('#')?;
			let code = match digits.strip_prefix(['x', 'X']) {
				Some(hex) => u32::from_str_radix(hex, 16).ok()?,
				None => digits.parse::<u32>().ok()?,
			};
			// A numeric reference is the only way a control character reaches the index —
			// `&#0;` would go straight into `search_docs.body`. Refusing it leaves the source
			// text verbatim, as for any unknown reference. Tab/newline/CR are kept: decoding
			// them before normalisation is why references resolve per chunk.
			char::from_u32(code).filter(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A numeric reference is the only way a control character could reach
	/// `search_docs.body` and the FTS entry built from it, so it stays source text.
	#[test]
	fn a_reference_naming_a_control_character_is_not_decoded() {
		let out = extract_text("<p>a&#0;b&#x1b;c</p>", 64).expect("extract");
		assert_eq!(out.text, "a&#0;b&#x1b;c");
		// The whitespace controls still decode — normalising them is the point.
		let ws = extract_text("<p>a&#10;b</p>", 64).expect("extract");
		assert_eq!(ws.text, "a b");
	}

	#[test]
	fn script_and_style_content_is_skipped() {
		let html = r#"<script type="application/cloudillo-page+json">{"title":"secret"}</script>
			<style>.a { color: red }</style><p>Visible</p>"#;
		let out = extract_text(html, 1024).expect("extract");
		assert_eq!(out.text, "Visible");
	}

	#[test]
	fn island_placeholder_text_is_taken_but_its_props_are_not() {
		let html = r#"<div class="cl-site-embed" data-cl-block="documentEmbed"
			data-cl-id="b1" data-props='{"fileId":"abc"}'>Quarterly report</div>"#;
		let out = extract_text(html, 1024).expect("extract");
		assert_eq!(out.text, "Quarterly report");
	}

	#[test]
	fn block_elements_separate_words_and_inline_marks_do_not() {
		let html = "<p>one</p><p>two</p><p><em>Cloud</em>illo</p>";
		let out = extract_text(html, 1024).expect("extract");
		assert_eq!(out.text, "one two Cloudillo");
	}

	/// The start tag is not the only boundary: `</p>text` ran together before the
	/// end-tag handler existed.
	#[test]
	fn a_block_end_is_a_word_boundary_too() {
		let out = extract_text("<p>one</p>two<li>a</li>b", 1024).expect("extract");
		assert_eq!(out.text, "one two a b");
	}

	#[test]
	fn character_references_are_resolved() {
		let html = "<p>Tom &amp; Jerry &lt;3 &#233;t&#xe9;</p>";
		let out = extract_text(html, 1024).expect("extract");
		assert_eq!(out.text, "Tom & Jerry <3 été");
	}

	#[test]
	fn the_budget_truncates_and_says_so() {
		let out = extract_text("<p>abcdefghij</p>", 4).expect("extract");
		assert_eq!(out.text, "abcd");
		assert!(out.truncated);
		let whole = extract_text("<p>abcd</p>", 4).expect("extract");
		assert!(!whole.truncated);
	}

	/// References are resolved per chunk, before the budget sees them, so a
	/// reference costs what it decodes to — one character — and the budget can no
	/// longer cut one in half.
	#[test]
	fn a_reference_costs_the_budget_what_it_decodes_to() {
		let out = extract_text("<p>ab&amp;cd</p>", 6).expect("extract");
		assert_eq!(out.text, "ab&cd");
		assert!(!out.truncated);
		// Nine source characters, one indexed one.
		let emoji = extract_text("<p>&#128512;x</p>", 2).expect("extract");
		assert_eq!(emoji.text, "\u{1f600}x");
		assert!(!emoji.truncated);
	}

	/// A bare `&` in running text is page text: the old end-of-string trim dropped
	/// `& Jerry` from the index because it looked like a cut-off reference.
	#[test]
	fn a_bare_ampersand_keeps_the_text_after_it() {
		let out = extract_text("<p>Tom & Jerry</p>", 11).expect("extract");
		assert_eq!(out.text, "Tom & Jerry");
		assert!(!out.truncated);
		// And one the document really does end on survives as itself.
		let dangling = extract_text("<p>a&am</p>", 64).expect("extract");
		assert_eq!(dangling.text, "a&am");
	}

	/// `&nbsp;` decodes to a blank, and a blank is normalised — which it was not
	/// while decoding happened after normalisation, leaving a leading space and a
	/// run of them in the middle.
	#[test]
	fn a_reference_that_decodes_to_whitespace_is_normalised_like_one() {
		let out = extract_text("<p>&nbsp;&nbsp;x</p>", 64).expect("extract");
		assert_eq!(out.text, "x");
		let inner = extract_text("<p>a&nbsp;&#10;&nbsp;b</p>", 64).expect("extract");
		assert_eq!(inner.text, "a b");
	}

	/// `lol_html` hands long text over in pieces, and a reference can straddle two
	/// of them — the tail is held back and rejoined rather than decoded twice as
	/// two halves of nothing.
	#[test]
	fn a_reference_split_across_two_chunks_still_decodes() {
		// Well past the tokenizer's chunk size, with the reference deep inside the
		// run so the split cannot be arranged to miss it.
		let filler = "a".repeat(200_000);
		let html = format!("<p>{filler}&amp;{filler}</p>");
		let out = extract_text(&html, 1_000_000).expect("extract");
		assert_eq!(out.text.matches('&').count(), 1, "reference not decoded exactly once");
		assert!(!out.text.contains("amp"), "a half-decoded reference leaked");
		assert_eq!(out.text.len(), filler.len() * 2 + 1);
	}

	/// The character budget bounds the answer, not the parse — the input needs its
	/// own cap, and a container entry is a page fragment.
	#[test]
	fn an_oversized_document_is_refused_rather_than_parsed() {
		let html = "x".repeat(MAX_INPUT_BYTES + 1);
		assert!(extract_text(&html, 16).is_err());
		// One byte under is still an ordinary document.
		let ok = "y".repeat(MAX_INPUT_BYTES);
		assert!(extract_text(&ok, 16).is_ok());
	}
}

// vim: ts=4
