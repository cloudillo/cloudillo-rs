// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Subject reference parsing for actions.
//!
//! An action's `subject` field can hold one of four forms:
//!
//! - `a<digits>~<hash>` — a federated, content-addressed action ID (e.g.
//!   `a1~abcdef...`). This is the canonical resolved form.
//! - `@<digits>` — an in-batch placeholder that references another action
//!   created in the same request. Resolved to an action ID by
//!   [`crate::task::resolve_subject`] before federation.
//! - `@<id_tag>` — an identity reference. The subject IS a tenant
//!   (e.g. `@community.example.com`), not an action. Used by
//!   community-membership invitations where the "subject" is the community
//!   itself rather than any specific action inside it.
//! - `@<id_tag>~<name>` — a channel of a tenant (always absolute). Split on
//!   the **last** `~`; a name failing `validate_channel_name` makes the whole
//!   subject `None`, never `Identity`.
//!
//! The forms are unambiguous because:
//! - `a<digits>~…` always starts with `a` followed by a digit and `~`.
//! - `@<digits>` is wholly numeric after the `@`.
//! - `@<id_tag>` always contains non-digit characters (id_tags are
//!   domain-form and contain at least one `.`), so it never parses as
//!   `u64`, and never contains `~`.
//! - `@…~…` is a channel; id_tags cannot contain `~`.

use cloudillo_types::validation::validate_channel_name;

/// A parsed subject reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectRef<'a> {
	/// A content-addressed action ID, e.g. `a1~abc...`. Always of the form
	/// `a<digits>~<hash>`; never an id_tag.
	Action(&'a str),
	/// In-batch placeholder for an action created in the same request, e.g.
	/// `@42`. The numeric portion is the database `a_id`; resolved to an
	/// `Action(...)` before federation.
	Placeholder(u64),
	/// Identity reference; the subject IS a tenant, e.g.
	/// `@community.example.com`.
	Identity(&'a str),
	/// Channel of a tenant, e.g. `@team.example~club`. `name` is the bare,
	/// validated channel name.
	Channel { tenant: &'a str, name: &'a str },
}

/// Parse a subject string into a [`SubjectRef`].
///
/// Returns `None` for the empty string, for `"@"` alone and for a channel
/// subject with an invalid name.
pub fn parse_subject_ref(s: &str) -> Option<SubjectRef<'_>> {
	if let Some(rest) = s.strip_prefix('@') {
		if rest.is_empty() {
			None
		} else if let Ok(n) = rest.parse::<u64>() {
			Some(SubjectRef::Placeholder(n))
		} else if let Some((tenant, name)) = rest.rsplit_once('~') {
			(!tenant.is_empty() && validate_channel_name(name))
				.then_some(SubjectRef::Channel { tenant, name })
		} else {
			Some(SubjectRef::Identity(rest))
		}
	} else if s.is_empty() {
		None
	} else {
		Some(SubjectRef::Action(s))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_action_id() {
		assert_eq!(parse_subject_ref("a1~abcdef"), Some(SubjectRef::Action("a1~abcdef")));
		assert_eq!(parse_subject_ref("a17~xyz"), Some(SubjectRef::Action("a17~xyz")));
	}

	#[test]
	fn parses_placeholder() {
		assert_eq!(parse_subject_ref("@42"), Some(SubjectRef::Placeholder(42)));
		assert_eq!(parse_subject_ref("@1"), Some(SubjectRef::Placeholder(1)));
		assert_eq!(parse_subject_ref("@0"), Some(SubjectRef::Placeholder(0)));
	}

	#[test]
	fn parses_identity() {
		assert_eq!(
			parse_subject_ref("@community.example.com"),
			Some(SubjectRef::Identity("community.example.com"))
		);
		assert_eq!(
			parse_subject_ref("@alice.example.com"),
			Some(SubjectRef::Identity("alice.example.com"))
		);
		// Anything non-numeric without `~` after @ is an identity, even if it
		// looks odd — id_tags are validated elsewhere.
		assert_eq!(parse_subject_ref("@a1"), Some(SubjectRef::Identity("a1")));
		assert_eq!(parse_subject_ref("@team.example"), Some(SubjectRef::Identity("team.example")));
	}

	#[test]
	fn parses_channel() {
		assert_eq!(
			parse_subject_ref("@team.example~club"),
			Some(SubjectRef::Channel { tenant: "team.example", name: "club" })
		);
		// Split on the last `~`.
		assert_eq!(
			parse_subject_ref("@a~b~club"),
			Some(SubjectRef::Channel { tenant: "a~b", name: "club" })
		);
		// A bad name is `None`, never an identity.
		assert_eq!(parse_subject_ref("@team.example~Club"), None);
		assert_eq!(parse_subject_ref("@team.example~"), None);
		assert_eq!(parse_subject_ref("@~club"), None);
		// Relative form is not a channel.
		assert!(!matches!(parse_subject_ref("~club"), Some(SubjectRef::Channel { .. })));
	}

	#[test]
	fn rejects_empty_forms() {
		assert_eq!(parse_subject_ref(""), None);
		assert_eq!(parse_subject_ref("@"), None);
	}
}

// vim: ts=4
