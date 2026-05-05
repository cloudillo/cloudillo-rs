// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Custom tracing event formatter and request-id capture layer.
//!
//! `CloudilloFormat` prefixes each event line with `REQ:<short>` when the
//! current span scope contains a `request` span (created by
//! `RequestId::install` in `extract.rs`). When no `request` span is in scope
//! (background tasks, startup, scheduler ticks), no prefix is added.
//!
//! `RequestSpanLayer` captures the `id` field of every newly created
//! `request` span into the span's extensions as a `RequestShortId`. The
//! formatter then reads that value with no string parsing or ANSI stripping.
//!
//! The `request` span is created at `Level::ERROR`, so it remains in scope
//! even when the global filter is set to `warn` or `error`.
//!
//! Output shape:
//! ```text
//! 2026-05-05T12:00:00.123Z  INFO REQ:a1b2 message body
//! 2026-05-05T12:00:00.456Z  INFO startup line without REQ prefix
//! ```

use std::fmt;

use tracing_subscriber::{
	fmt::{FmtContext, FormatEvent, FormatFields, format::Writer},
	layer::Context,
	registry::LookupSpan,
};

/// Span name matched by the formatter and the layer — the public constant
/// `RequestId::install` (in `extract.rs`) produces spans with this exact name.
pub const REQUEST_SPAN_NAME: &str = "request";

/// Captured `id` field of a `request` span. Stored in the span's extensions
/// by `RequestSpanLayer` at span creation time and read by `CloudilloFormat`
/// at event format time.
#[derive(Clone, Debug)]
pub struct RequestShortId(pub String);

/// `tracing` Layer that snapshots the `id` field of `request` spans into the
/// span's extensions, so the formatter does not need to re-parse the
/// pre-formatted span fields string.
pub struct RequestSpanLayer;

impl<S> tracing_subscriber::Layer<S> for RequestSpanLayer
where
	S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
	fn on_new_span(
		&self,
		attrs: &tracing::span::Attributes<'_>,
		id: &tracing::span::Id,
		ctx: Context<'_, S>,
	) {
		if attrs.metadata().name() != REQUEST_SPAN_NAME {
			return;
		}
		let mut visitor = IdVisitor(None);
		attrs.record(&mut visitor);
		if let (Some(short), Some(span)) = (visitor.0, ctx.span(id)) {
			span.extensions_mut().insert(RequestShortId(short));
		}
	}
}

struct IdVisitor(Option<String>);

impl tracing::field::Visit for IdVisitor {
	fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
		if field.name() == "id" {
			self.0 = Some(value.to_string());
		}
	}

	fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
		// `info_span!("request", id = %short)` routes through `record_debug`
		// with a Display-as-Debug wrapper, so `format!("{:?}", value)` yields
		// the bare display form (no surrounding quotes).
		if field.name() == "id" && self.0.is_none() {
			self.0 = Some(format!("{:?}", value));
		}
	}
}

/// Custom event formatter. Writes each line as
/// `<timestamp>  <LEVEL> [REQ:<id> ]<fields>\n` and delegates field formatting
/// to the inner `FormatFields`.
pub struct CloudilloFormat;

impl CloudilloFormat {
	pub fn new() -> Self {
		Self
	}
}

impl Default for CloudilloFormat {
	fn default() -> Self {
		Self::new()
	}
}

impl<S, N> FormatEvent<S, N> for CloudilloFormat
where
	S: tracing::Subscriber + for<'a> LookupSpan<'a>,
	N: for<'a> FormatFields<'a> + 'static,
{
	fn format_event(
		&self,
		ctx: &FmtContext<'_, S, N>,
		mut writer: Writer<'_>,
		event: &tracing::Event<'_>,
	) -> fmt::Result {
		let now = chrono::Utc::now();
		write!(writer, "{}  ", now.format("%Y-%m-%dT%H:%M:%S%.3fZ"))?;

		let level = event.metadata().level();
		write!(writer, "{:>5} ", level)?;

		if let Some(id) = find_request_short_id(ctx) {
			write!(writer, "REQ:{} ", id)?;
		}

		ctx.field_format().format_fields(writer.by_ref(), event)?;
		writeln!(writer)
	}
}

/// Walk the current event scope, find the named request span, and return the
/// `id` captured into its extensions by `RequestSpanLayer`.
fn find_request_short_id<S, N>(ctx: &FmtContext<'_, S, N>) -> Option<String>
where
	S: tracing::Subscriber + for<'a> LookupSpan<'a>,
	N: for<'a> FormatFields<'a> + 'static,
{
	let scope = ctx.event_scope()?;
	for span in scope.from_root() {
		if span.name() == REQUEST_SPAN_NAME
			&& let Some(rsid) = span.extensions().get::<RequestShortId>()
		{
			return Some(rsid.0.clone());
		}
	}
	None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
	use super::*;
	use std::io::Write;
	use std::sync::{Arc, Mutex};
	use tracing::{info, info_span};
	use tracing_subscriber::fmt::MakeWriter;
	use tracing_subscriber::layer::SubscriberExt;

	#[derive(Clone, Default)]
	struct BufWriter(Arc<Mutex<Vec<u8>>>);

	struct BufWriterGuard(Arc<Mutex<Vec<u8>>>);

	impl Write for BufWriterGuard {
		fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
			match self.0.lock() {
				Ok(mut g) => g.write(buf),
				Err(_) => Ok(buf.len()),
			}
		}
		fn flush(&mut self) -> std::io::Result<()> {
			Ok(())
		}
	}

	impl<'a> MakeWriter<'a> for BufWriter {
		type Writer = BufWriterGuard;
		fn make_writer(&'a self) -> Self::Writer {
			BufWriterGuard(self.0.clone())
		}
	}

	impl BufWriter {
		fn snapshot(&self) -> String {
			let g = self.0.lock().unwrap();
			String::from_utf8(g.clone()).unwrap()
		}
	}

	fn build_subscriber(buf: BufWriter) -> impl tracing::Subscriber + Send + Sync {
		let fmt_layer = tracing_subscriber::fmt::layer()
			.with_writer(buf)
			.event_format(CloudilloFormat::new());
		tracing_subscriber::registry().with(RequestSpanLayer).with(fmt_layer)
	}

	#[test]
	fn request_span_prefixes_with_req_id() {
		let buf = BufWriter::default();
		let subscriber = build_subscriber(buf.clone());

		tracing::subscriber::with_default(subscriber, || {
			info_span!("request", id = "abcd").in_scope(|| {
				info!("hello world");
			});
		});

		let out = buf.snapshot();
		assert_eq!(out.matches(" REQ:abcd ").count(), 1, "output: {out:?}");

		let req_pos = out.find("REQ:").unwrap();
		let level_pos = out.find("INFO").unwrap();
		assert!(level_pos < req_pos, "REQ before level: {out:?}");
		assert!(out.contains("hello world"), "missing message: {out:?}");
	}

	#[test]
	fn request_span_with_display_value_captures_correctly() {
		let buf = BufWriter::default();
		let subscriber = build_subscriber(buf.clone());

		let short = String::from("abcd");
		tracing::subscriber::with_default(subscriber, || {
			info_span!("request", id = %short).in_scope(|| {
				info!("display value");
			});
		});

		let out = buf.snapshot();
		assert!(out.contains(" REQ:abcd "), "output: {out:?}");
	}

	#[test]
	fn no_span_means_no_prefix() {
		let buf = BufWriter::default();
		let subscriber = build_subscriber(buf.clone());

		tracing::subscriber::with_default(subscriber, || {
			info!("startup");
		});

		let out = buf.snapshot();
		assert!(!out.contains("REQ:"), "unexpected prefix: {out:?}");
		assert!(out.contains("startup"), "missing message: {out:?}");
	}

	#[test]
	fn other_span_names_do_not_get_captured() {
		let buf = BufWriter::default();
		let subscriber = build_subscriber(buf.clone());

		tracing::subscriber::with_default(subscriber, || {
			info_span!("background", id = "abcd").in_scope(|| {
				info!("background work");
			});
		});

		let out = buf.snapshot();
		assert!(!out.contains("REQ:"), "unexpected prefix: {out:?}");
	}
}

// vim: ts=4
