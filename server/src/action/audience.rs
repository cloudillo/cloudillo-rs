//! Unified audience resolution for action types
//!
//! This module provides a single function to resolve the audience for any action type,
//! eliminating scattered ad-hoc logic throughout the codebase.
//!
//! Resolution priority:
//! 1. Explicit audience (always takes precedence)
//! 2. Subject action's owner (for REACT, APRV, SUBS, INVT, FSHR, STAT, PRES)
//! 3. Parent action's audience or issuer (for CMNT, MSG)
//! 4. None

use crate::meta_adapter::MetaAdapter;
use crate::prelude::*;

/// Resolution source - indicates where the audience was resolved from
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudienceSource {
	/// Explicitly provided in the action
	Explicit,
	/// Resolved from subject action's issuer
	Subject,
	/// Resolved from parent action's audience
	ParentAudience,
	/// Resolved from parent action's issuer
	ParentIssuer,
	/// No audience could be determined
	None,
}

/// Result of audience resolution
#[derive(Debug, Clone)]
pub struct ResolvedAudience {
	/// The resolved audience id_tag (if any)
	pub audience: Option<Box<str>>,
	/// How the audience was resolved
	pub source: AudienceSource,
}

impl ResolvedAudience {
	fn explicit(audience: Box<str>) -> Self {
		Self { audience: Some(audience), source: AudienceSource::Explicit }
	}

	fn from_subject(audience: Box<str>) -> Self {
		Self { audience: Some(audience), source: AudienceSource::Subject }
	}

	fn from_parent_audience(audience: Box<str>) -> Self {
		Self { audience: Some(audience), source: AudienceSource::ParentAudience }
	}

	fn from_parent_issuer(issuer: Box<str>) -> Self {
		Self { audience: Some(issuer), source: AudienceSource::ParentIssuer }
	}

	fn none() -> Self {
		Self { audience: None, source: AudienceSource::None }
	}
}

/// Resolve audience for an action based on type-specific semantics
///
/// # Arguments
/// * `meta_adapter` - Database adapter for looking up related actions
/// * `tn_id` - Tenant ID
/// * `action_type` - The action type (e.g., "REACT", "CMNT", "MSG")
/// * `explicit_audience` - Explicitly provided audience (takes precedence)
/// * `parent_id` - Parent action ID (for CMNT, MSG)
/// * `subject` - Subject action/resource ID (for REACT, APRV, SUBS, etc.)
///
/// # Returns
/// Resolved audience with source information
pub async fn resolve_audience<M: MetaAdapter + ?Sized>(
	meta_adapter: &M,
	tn_id: TnId,
	action_type: &str,
	explicit_audience: Option<&str>,
	parent_id: Option<&str>,
	subject: Option<&str>,
) -> ClResult<ResolvedAudience> {
	// 1. Explicit audience always takes precedence
	if let Some(audience) = explicit_audience {
		return Ok(ResolvedAudience::explicit(audience.into()));
	}

	// 2. Subject-based resolution for non-hierarchical references
	//    REACT, APRV, SUBS, INVT, FSHR, STAT, PRES use subject
	if uses_subject_for_audience(action_type) {
		if let Some(subject_id) = subject {
			// Skip @reference placeholders - they're not resolved yet
			if !subject_id.starts_with('@') {
				if let Ok(Some(subject_action)) = meta_adapter.get_action(tn_id, subject_id).await {
					return Ok(ResolvedAudience::from_subject(subject_action.issuer.id_tag));
				}
			}
		}
	}

	// 3. Parent-based resolution for hierarchical references
	//    CMNT, MSG (replies) use parent
	if uses_parent_for_audience(action_type) {
		if let Some(parent_id) = parent_id {
			if let Ok(Some(parent_action)) = meta_adapter.get_action(tn_id, parent_id).await {
				// Prefer parent's audience, fall back to parent's issuer
				if let Some(audience) = parent_action.audience {
					return Ok(ResolvedAudience::from_parent_audience(audience.id_tag));
				}
				return Ok(ResolvedAudience::from_parent_issuer(parent_action.issuer.id_tag));
			}
		}
	}

	// 4. No audience resolution possible
	Ok(ResolvedAudience::none())
}

/// Check if action type uses subject for audience resolution
fn uses_subject_for_audience(action_type: &str) -> bool {
	matches!(action_type, "REACT" | "APRV" | "SUBS" | "INVT" | "FSHR" | "STAT" | "PRES")
}

/// Check if action type uses parent for audience resolution
fn uses_parent_for_audience(action_type: &str) -> bool {
	matches!(action_type, "CMNT" | "MSG" | "REPOST")
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_uses_subject_for_audience() {
		assert!(uses_subject_for_audience("REACT"));
		assert!(uses_subject_for_audience("APRV"));
		assert!(uses_subject_for_audience("SUBS"));
		assert!(uses_subject_for_audience("INVT"));
		assert!(uses_subject_for_audience("FSHR"));
		assert!(uses_subject_for_audience("STAT"));
		assert!(uses_subject_for_audience("PRES"));
		assert!(!uses_subject_for_audience("POST"));
		assert!(!uses_subject_for_audience("CMNT"));
		assert!(!uses_subject_for_audience("CONN"));
	}

	#[test]
	fn test_uses_parent_for_audience() {
		assert!(uses_parent_for_audience("CMNT"));
		assert!(uses_parent_for_audience("MSG"));
		assert!(uses_parent_for_audience("REPOST"));
		assert!(!uses_parent_for_audience("POST"));
		assert!(!uses_parent_for_audience("REACT"));
		assert!(!uses_parent_for_audience("CONN"));
	}

	#[test]
	fn test_explicit_audience_precedence() {
		// Explicit audience should always be used
		let result = ResolvedAudience::explicit("explicit@example.com".into());
		assert_eq!(result.audience.as_deref(), Some("explicit@example.com"));
		assert_eq!(result.source, AudienceSource::Explicit);
	}
}

// vim: ts=4
