// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Shared XML-namespace bookkeeping helpers used by `propfind` and `report` parsers.

use quick_xml::events::BytesStart;

/// Defence-in-depth: reject DAV bodies carrying inline DTDs or entity declarations.
///
/// `quick_xml` does not resolve external entities and does not expand entity references
/// by default, so billion-laughs and XXE are already mitigated at the parser layer.
/// This substring check adds a cheap early-reject so we never even hand such a body to
/// the parser. Legitimate DAV clients do not emit `<!DOCTYPE` or `<!ENTITY`, and both
/// tokens must appear before the root element per the XML spec — so they cannot hide
/// inside CDATA or elements. Comments containing the literal tokens cause a harmless
/// false positive (the body is treated as `AllProp` / empty instead of parsed).
pub(crate) fn has_doctype_or_entity(body: &str) -> bool {
	body.contains("<!DOCTYPE") || body.contains("<!ENTITY")
}

pub(crate) fn push_ns_scope(stack: &mut Vec<Vec<(String, String)>>, e: &BytesStart<'_>) {
	let mut scope = stack.last().cloned().unwrap_or_default();
	for attr in e.attributes().with_checks(false).flatten() {
		let key = attr.key.as_ref();
		let val = String::from_utf8_lossy(&attr.value).to_string();
		if key == b"xmlns" {
			upsert_prefix(&mut scope, "", &val);
		} else if let Some(prefix) = key.strip_prefix(b"xmlns:") {
			let prefix = String::from_utf8_lossy(prefix).to_string();
			upsert_prefix(&mut scope, &prefix, &val);
		}
	}
	stack.push(scope);
}

fn upsert_prefix(scope: &mut Vec<(String, String)>, prefix: &str, ns: &str) {
	if let Some(slot) = scope.iter_mut().find(|(p, _)| p == prefix) {
		slot.1 = ns.to_string();
	} else {
		scope.push((prefix.to_string(), ns.to_string()));
	}
}

pub(crate) fn resolve_name(stack: &[Vec<(String, String)>], qname: &[u8]) -> (String, String) {
	let qname_str = String::from_utf8_lossy(qname);
	let (prefix, local) = match qname_str.split_once(':') {
		Some((p, l)) => (p.to_string(), l.to_string()),
		None => (String::new(), qname_str.to_string()),
	};
	let ns = stack
		.last()
		.and_then(|scope| scope.iter().find(|(p, _)| *p == prefix))
		.map(|(_, n)| n.clone())
		.unwrap_or_default();
	(ns, local)
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
	use super::*;
	use quick_xml::{Reader, events::Event};

	// Helper: pull the first Start event out of a synthetic XML fragment so we can
	// exercise `push_ns_scope` against real `BytesStart` values.
	fn first_start(xml: &str) -> quick_xml::events::BytesStart<'static> {
		let mut reader = Reader::from_str(xml);
		reader.config_mut().trim_text(true);
		loop {
			match reader.read_event() {
				Ok(Event::Start(e) | Event::Empty(e)) => return e.into_owned(),
				Ok(Event::Eof) => panic!("no start element in fragment"),
				_ => {}
			}
		}
	}

	#[test]
	fn upsert_prefix_inserts_and_updates() {
		let mut scope: Vec<(String, String)> = Vec::new();
		upsert_prefix(&mut scope, "D", "DAV:");
		upsert_prefix(&mut scope, "C", "urn:ietf:params:xml:ns:carddav");
		assert_eq!(scope.len(), 2);

		upsert_prefix(&mut scope, "D", "http://example.invalid/other");
		assert_eq!(scope.len(), 2);
		assert_eq!(
			scope.iter().find(|(p, _)| p == "D").map(|(_, n)| n.as_str()),
			Some("http://example.invalid/other")
		);
	}

	#[test]
	fn push_ns_scope_tracks_default_and_prefixed_bindings() {
		let start = first_start(r#"<root xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav"/>"#);
		let mut stack: Vec<Vec<(String, String)>> = vec![Vec::new()];
		push_ns_scope(&mut stack, &start);
		assert_eq!(stack.len(), 2);

		// Use resolve_name to verify both bindings land on the top-of-stack scope.
		let (ns_default, _) = resolve_name(&stack, b"anything");
		assert_eq!(ns_default, "DAV:");
		let (ns_carddav, _) = resolve_name(&stack, b"C:anything");
		assert_eq!(ns_carddav, "urn:ietf:params:xml:ns:carddav");
	}

	#[test]
	fn resolve_name_with_empty_stack_returns_no_namespace() {
		let (ns, local) = resolve_name(&[], b"displayname");
		assert!(ns.is_empty());
		assert_eq!(local, "displayname");
	}

	#[test]
	fn resolve_name_uses_default_binding() {
		let stack = vec![vec![(String::new(), "DAV:".to_string())]];
		let (ns, local) = resolve_name(&stack, b"displayname");
		assert_eq!(ns, "DAV:");
		assert_eq!(local, "displayname");
	}

	#[test]
	fn resolve_name_uses_prefix_binding() {
		let stack = vec![vec![
			(String::new(), "DAV:".to_string()),
			("C".to_string(), "urn:ietf:params:xml:ns:carddav".to_string()),
		]];
		let (ns, local) = resolve_name(&stack, b"C:addressbook-home-set");
		assert_eq!(ns, "urn:ietf:params:xml:ns:carddav");
		assert_eq!(local, "addressbook-home-set");
	}

	#[test]
	fn resolve_name_unknown_prefix_falls_back_to_empty() {
		let stack = vec![vec![(String::new(), "DAV:".to_string())]];
		let (ns, local) = resolve_name(&stack, b"X:unknown");
		assert!(ns.is_empty());
		assert_eq!(local, "unknown");
	}
}

// vim: ts=4
