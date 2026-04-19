// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Parse PROPFIND request bodies.
//!
//! PROPFIND bodies come in four flavors (RFC 4918 §9.1):
//! - `<propfind><allprop/></propfind>` — "give me everything"
//! - `<propfind><propname/></propfind>` — "list property names only"
//! - `<propfind><prop>…</prop></propfind>` — named properties
//! - empty body — treated as `<allprop/>`

use quick_xml::{Reader, events::Event};

use crate::propfind_util::{has_doctype_or_entity, push_ns_scope, resolve_name};

/// A property name with its namespace (expanded form, à la XML Namespaces).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PropName {
	pub ns: String,
	pub local: String,
}

impl PropName {
	pub fn new(ns: impl Into<String>, local: impl Into<String>) -> Self {
		Self { ns: ns.into(), local: local.into() }
	}

	/// Check if this property matches a given (namespace, local-name) pair.
	pub fn is(&self, ns: &str, local: &str) -> bool {
		self.ns == ns && self.local == local
	}
}

/// Parsed PROPFIND body.
#[derive(Debug, Default, Clone)]
pub enum Propfind {
	/// `<allprop/>` — return every known live property.
	#[default]
	AllProp,
	/// `<propname/>` — return names only, no values.
	PropName,
	/// Named properties.
	Prop(Vec<PropName>),
}

/// Parse a PROPFIND request body. Empty / unrecognized bodies default to AllProp.
pub fn parse(body: &str) -> Propfind {
	if body.trim().is_empty() || has_doctype_or_entity(body) {
		return Propfind::AllProp;
	}

	let mut reader = Reader::from_str(body);
	reader.config_mut().trim_text(true);

	// Track namespace prefixes in scope, plus the resolved (ns, local) name of each open
	// element so End events can match their opening Start by name (not by position).
	let mut ns_stack: Vec<Vec<(String, String)>> = vec![vec![(String::new(), String::new())]];
	let mut element_stack: Vec<(String, String)> = Vec::new();
	let mut in_propfind = false;
	// Depth at which `<prop>` was opened (element_stack.len() at that moment). Its direct
	// children sit at element_stack.len() == prop_start_depth + 1 and are the property names.
	// None means we're not inside a `<prop>`.
	let mut prop_start_depth: Option<usize> = None;
	let mut collected: Vec<PropName> = Vec::new();
	let mut explicit_kind: Option<Propfind> = None;

	loop {
		match reader.read_event() {
			Ok(Event::Start(e)) => {
				push_ns_scope(&mut ns_stack, &e);
				let (ns, local) = resolve_name(&ns_stack, e.name().as_ref());
				element_stack.push((ns.clone(), local.clone()));

				if !in_propfind {
					if ns == super::consts::NS_DAV && local == "propfind" {
						in_propfind = true;
					}
				} else if prop_start_depth.is_none() {
					match (ns.as_str(), local.as_str()) {
						(super::consts::NS_DAV, "prop") => {
							prop_start_depth = Some(element_stack.len());
						}
						(super::consts::NS_DAV, "allprop") => {
							explicit_kind = Some(Propfind::AllProp);
						}
						(super::consts::NS_DAV, "propname") => {
							explicit_kind = Some(Propfind::PropName);
						}
						_ => {}
					}
				} else if prop_start_depth == Some(element_stack.len() - 1) {
					// Direct child of <prop> — its name is a requested property. Nested
					// grandchildren are skipped.
					collected.push(PropName::new(ns, local));
				}
			}
			Ok(Event::Empty(e)) => {
				push_ns_scope(&mut ns_stack, &e);
				let (ns, local) = resolve_name(&ns_stack, e.name().as_ref());
				if in_propfind && prop_start_depth.is_none() {
					match (ns.as_str(), local.as_str()) {
						(super::consts::NS_DAV, "allprop") => {
							explicit_kind = Some(Propfind::AllProp);
						}
						(super::consts::NS_DAV, "propname") => {
							explicit_kind = Some(Propfind::PropName);
						}
						_ => {}
					}
				} else if prop_start_depth == Some(element_stack.len()) {
					// Empty-element shorthand as a direct child of <prop>.
					collected.push(PropName::new(ns, local));
				}
				ns_stack.pop();
			}
			Ok(Event::End(_)) => {
				ns_stack.pop();
				let closed = element_stack.pop();
				if let Some(depth) = prop_start_depth
					&& element_stack.len() < depth
				{
					// We just popped the `<prop>` (or something enclosing it, which
					// shouldn't happen for well-formed input but keeps us safe).
					let _ = closed;
					prop_start_depth = None;
				}
			}
			Ok(Event::Eof) | Err(_) => break,
			_ => {}
		}
	}

	if collected.is_empty() {
		explicit_kind.unwrap_or(Propfind::AllProp)
	} else {
		Propfind::Prop(collected)
	}
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
	use super::super::consts::{NS_CARDDAV, NS_DAV};
	use super::*;

	#[test]
	fn empty_body_is_allprop() {
		assert!(matches!(parse(""), Propfind::AllProp));
	}

	#[test]
	fn allprop_element() {
		let body = r#"<?xml version="1.0" encoding="utf-8"?>
			<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>"#;
		assert!(matches!(parse(body), Propfind::AllProp));
	}

	#[test]
	fn named_props_mixed_namespaces() {
		let body = r#"<?xml version="1.0" encoding="utf-8"?>
			<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
				<D:prop>
					<D:displayname/>
					<D:getetag/>
					<C:addressbook-home-set/>
				</D:prop>
			</D:propfind>"#;
		let Propfind::Prop(props) = parse(body) else {
			panic!("expected named props");
		};
		assert_eq!(props.len(), 3);
		assert!(props.iter().any(|p| p.is(NS_DAV, "displayname")));
		assert!(props.iter().any(|p| p.is(NS_DAV, "getetag")));
		assert!(props.iter().any(|p| p.is(NS_CARDDAV, "addressbook-home-set")));
	}

	#[test]
	fn doctype_is_rejected_as_allprop() {
		// Entity-bearing bodies must be rejected before the XML parser sees them.
		let body = r#"<?xml version="1.0"?>
			<!DOCTYPE propfind [<!ENTITY x "aaaaaaaaaaaaaaa">]>
			<propfind xmlns="DAV:"><prop><displayname>&x;</displayname></prop></propfind>"#;
		assert!(matches!(parse(body), Propfind::AllProp));
	}

	#[test]
	fn default_namespace_propfind() {
		let body = r#"<?xml version="1.0" encoding="utf-8"?>
			<propfind xmlns="DAV:">
				<prop><displayname/></prop>
			</propfind>"#;
		let Propfind::Prop(props) = parse(body) else {
			panic!("expected named props");
		};
		assert_eq!(props.len(), 1);
		assert!(props[0].is(NS_DAV, "displayname"));
	}

	#[test]
	fn propfind_without_xmlns_is_rejected_as_allprop() {
		// No xmlns declared: <propfind> is in the null namespace, so it doesn't match
		// the DAV: namespace and the parser falls back to AllProp. Behaviour is defined
		// by XML Namespaces 1.0 — an unprefixed element with no default namespace
		// declaration is in no namespace. This is the correct, spec-compliant outcome.
		let body = r#"<?xml version="1.0" encoding="utf-8"?>
			<propfind><prop><displayname/></prop></propfind>"#;
		assert!(matches!(parse(body), Propfind::AllProp));
	}

	#[test]
	fn prop_with_nested_child_still_collects_siblings() {
		// An element inside <prop> may itself contain child elements (uncommon but legal).
		// The End tag of the nested child must not turn off property collection early.
		let body = r#"<?xml version="1.0" encoding="utf-8"?>
			<D:propfind xmlns:D="DAV:">
				<D:prop>
					<D:getetag/>
					<D:custom><D:inner/></D:custom>
					<D:displayname/>
				</D:prop>
			</D:propfind>"#;
		let Propfind::Prop(props) = parse(body) else {
			panic!("expected named props");
		};
		// We expect the three direct children of <prop>; the nested <D:inner/> must not
		// appear, and <D:displayname/> after the nested element must still be collected.
		assert!(props.iter().any(|p| p.is(NS_DAV, "getetag")));
		assert!(props.iter().any(|p| p.is(NS_DAV, "custom")));
		assert!(props.iter().any(|p| p.is(NS_DAV, "displayname")));
		assert!(!props.iter().any(|p| p.is(NS_DAV, "inner")));
	}

	#[test]
	fn nested_prefix_shadowing() {
		// Inner xmlns:C rebinds C: to CardDAV, overriding the outer binding.
		let body = r#"<?xml version="1.0" encoding="utf-8"?>
			<D:propfind xmlns:D="DAV:" xmlns:C="http://example.invalid/ns">
				<D:prop xmlns:C="urn:ietf:params:xml:ns:carddav">
					<C:addressbook-home-set/>
				</D:prop>
			</D:propfind>"#;
		let Propfind::Prop(props) = parse(body) else {
			panic!("expected named props");
		};
		assert_eq!(props.len(), 1);
		assert!(props[0].is(NS_CARDDAV, "addressbook-home-set"));
	}
}

// vim: ts=4
