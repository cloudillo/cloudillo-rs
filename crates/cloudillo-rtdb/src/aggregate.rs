//! Incremental aggregate computation for RTDB subscriptions.
//!
//! Instead of recomputing the full aggregate on every document change,
//! this module maintains per-group counters and adjusts them incrementally
//! by comparing old vs new document data from change events.

use cloudillo_types::rtdb_adapter::{
	value_to_group_string, AggregateOp, AggregateOptions, ChangeEvent, QueryFilter,
};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

/// Per-group aggregate accumulator.
#[derive(Debug, Clone)]
struct GroupState {
	count: u64,
	sums: HashMap<String, f64>,
	avg_sums: HashMap<String, f64>,
	avg_counts: HashMap<String, u64>,
}

impl GroupState {
	fn new(ops: &[AggregateOp]) -> Self {
		let mut sums = HashMap::new();
		let mut avg_sums = HashMap::new();
		let mut avg_counts = HashMap::new();
		for op in ops {
			match op {
				AggregateOp::Sum { field } => {
					sums.insert(field.clone(), 0.0);
				}
				AggregateOp::Avg { field } => {
					avg_sums.insert(field.clone(), 0.0);
					avg_counts.insert(field.clone(), 0);
				}
				AggregateOp::Min { .. } | AggregateOp::Max { .. } => {}
			}
		}
		Self { count: 0, sums, avg_sums, avg_counts }
	}

	fn to_value(&self, group_key: &str, ops: &[AggregateOp]) -> Value {
		let mut obj = serde_json::Map::new();
		obj.insert("group".to_string(), Value::String(group_key.to_string()));
		obj.insert("count".to_string(), json!(self.count));
		for op in ops {
			match op {
				AggregateOp::Sum { field } => {
					if let Some(&v) = self.sums.get(field) {
						obj.insert(format!("sum_{}", field), json!(v));
					}
				}
				AggregateOp::Avg { field } => {
					if let (Some(&sum), Some(&cnt)) =
						(self.avg_sums.get(field), self.avg_counts.get(field))
					{
						let avg = if cnt > 0 { sum / cnt as f64 } else { 0.0 };
						obj.insert(format!("avg_{}", field), json!(avg));
					}
				}
				AggregateOp::Min { .. } | AggregateOp::Max { .. } => {}
			}
		}
		Value::Object(obj)
	}

	/// Add a document's contributions to this group.
	fn add(&mut self, data: &Value, ops: &[AggregateOp]) {
		self.count += 1;
		for op in ops {
			match op {
				AggregateOp::Sum { field } => {
					if let Some(v) = extract_f64(data, field) {
						*self.sums.entry(field.clone()).or_insert(0.0) += v;
					}
				}
				AggregateOp::Avg { field } => {
					if let Some(v) = extract_f64(data, field) {
						*self.avg_sums.entry(field.clone()).or_insert(0.0) += v;
						*self.avg_counts.entry(field.clone()).or_insert(0) += 1;
					}
				}
				AggregateOp::Min { .. } | AggregateOp::Max { .. } => {}
			}
		}
	}

	/// Remove a document's contributions from this group.
	fn remove(&mut self, data: &Value, ops: &[AggregateOp]) {
		self.count = self.count.saturating_sub(1);
		for op in ops {
			match op {
				AggregateOp::Sum { field } => {
					if let Some(v) = extract_f64(data, field) {
						*self.sums.entry(field.clone()).or_insert(0.0) -= v;
					}
				}
				AggregateOp::Avg { field } => {
					if let Some(v) = extract_f64(data, field) {
						*self.avg_sums.entry(field.clone()).or_insert(0.0) -= v;
						let cnt = self.avg_counts.entry(field.clone()).or_insert(0);
						*cnt = cnt.saturating_sub(1);
					}
				}
				AggregateOp::Min { .. } | AggregateOp::Max { .. } => {}
			}
		}
	}
}

/// Extract an f64 value from a JSON document field.
fn extract_f64(data: &Value, field: &str) -> Option<f64> {
	data.get(field).and_then(|v| v.as_f64())
}

/// Extract group key strings from a document's group_by field.
/// Arrays produce multiple group keys; scalars produce one; null/missing produces none.
fn extract_group_keys(data: &Value, group_by: &str) -> Vec<String> {
	match data.get(group_by) {
		Some(Value::Array(arr)) => arr
			.iter()
			.filter(|v| !v.is_array() && !v.is_object())
			.map(value_to_group_string)
			.collect(),
		Some(Value::Null) | None => Vec::new(),
		Some(v) => vec![value_to_group_string(v)],
	}
}

/// Incremental aggregate state — tracks per-group totals without per-doc memory.
pub struct IncrementalAggState {
	aggregate: AggregateOptions,
	filter: Option<QueryFilter>,
	has_min_max: bool,
	groups: HashMap<String, GroupState>,
}

impl IncrementalAggState {
	/// Create a new incremental aggregate state.
	pub fn new(aggregate: AggregateOptions, filter: Option<QueryFilter>) -> Self {
		let has_min_max = aggregate
			.ops
			.iter()
			.any(|op| matches!(op, AggregateOp::Min { .. } | AggregateOp::Max { .. }));
		Self { aggregate, filter, has_min_max, groups: HashMap::new() }
	}

	/// Returns true if Min/Max ops are present, requiring full recompute fallback.
	pub fn needs_full_recompute(&self) -> bool {
		self.has_min_max
	}

	/// Feed a document during initial load (from Create events before Ready).
	pub fn add_doc(&mut self, data: &Value) {
		if let Some(ref f) = self.filter {
			if !f.matches(data) {
				return;
			}
		}

		let group_keys = extract_group_keys(data, &self.aggregate.group_by);
		for key in &group_keys {
			let state = self
				.groups
				.entry(key.clone())
				.or_insert_with(|| GroupState::new(&self.aggregate.ops));
			state.add(data, &self.aggregate.ops);
		}
	}

	/// Get the full sorted aggregate result.
	pub fn get_full_result(&self) -> Vec<Value> {
		let mut result: Vec<Value> = self
			.groups
			.iter()
			.filter(|(_, gs)| gs.count > 0)
			.map(|(key, gs)| gs.to_value(key, &self.aggregate.ops))
			.collect();
		result.sort_by(|a, b| {
			let ca = a.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
			let cb = b.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
			cb.cmp(&ca)
		});
		result
	}

	/// Process a live change event and return a delta of affected groups.
	///
	/// Returns `None` if the event is irrelevant to this aggregate.
	/// Groups with count=0 in the result signal removal.
	pub fn process_change(&mut self, event: &ChangeEvent) -> Option<Vec<Value>> {
		match event {
			ChangeEvent::Create { data, .. } => self.handle_create(data),
			ChangeEvent::Update { data, old_data, .. } => {
				self.handle_update(data, old_data.as_ref())
			}
			ChangeEvent::Delete { old_data, .. } => self.handle_delete(old_data.as_ref()),
			_ => None,
		}
	}

	fn handle_create(&mut self, data: &Value) -> Option<Vec<Value>> {
		if let Some(ref f) = self.filter {
			if !f.matches(data) {
				return None;
			}
		}

		let group_keys = extract_group_keys(data, &self.aggregate.group_by);
		if group_keys.is_empty() {
			return None;
		}

		let mut affected = Vec::new();
		for key in &group_keys {
			let state = self
				.groups
				.entry(key.clone())
				.or_insert_with(|| GroupState::new(&self.aggregate.ops));
			state.add(data, &self.aggregate.ops);
			affected.push(state.to_value(key, &self.aggregate.ops));
		}
		Some(affected)
	}

	fn handle_update(&mut self, data: &Value, old_data: Option<&Value>) -> Option<Vec<Value>> {
		let old_match = old_data
			.map(|od| self.filter.as_ref().is_none_or(|f| f.matches(od)))
			.unwrap_or(false);
		let new_match = self.filter.as_ref().is_none_or(|f| f.matches(data));

		if !old_match && !new_match {
			return None;
		}

		let old_groups: HashSet<String> = if old_match {
			old_data
				.map(|od| extract_group_keys(od, &self.aggregate.group_by))
				.unwrap_or_default()
				.into_iter()
				.collect()
		} else {
			HashSet::new()
		};

		let new_groups: HashSet<String> = if new_match {
			extract_group_keys(data, &self.aggregate.group_by).into_iter().collect()
		} else {
			HashSet::new()
		};

		// Early exit: if same groups and same op field values, no aggregate change
		if old_match && new_match && old_groups == new_groups {
			if let Some(od) = old_data {
				let op_fields_changed = self.aggregate.ops.iter().any(|op| {
					let field = match op {
						AggregateOp::Sum { field }
						| AggregateOp::Avg { field }
						| AggregateOp::Min { field }
						| AggregateOp::Max { field } => field,
					};
					data.get(field) != od.get(field)
				});
				if !op_fields_changed {
					return None;
				}
			}
		}

		let removed: Vec<&String> = old_groups.difference(&new_groups).collect();
		let added: Vec<&String> = new_groups.difference(&old_groups).collect();
		let stable: Vec<&String> = old_groups.intersection(&new_groups).collect();

		let mut affected = Vec::new();

		// Remove contributions from groups the doc left
		for key in &removed {
			if let Some(od) = old_data {
				let state = self
					.groups
					.entry((*key).clone())
					.or_insert_with(|| GroupState::new(&self.aggregate.ops));
				state.remove(od, &self.aggregate.ops);
				affected.push(state.to_value(key, &self.aggregate.ops));
			}
		}

		// Add contributions to groups the doc entered
		for key in &added {
			let state = self
				.groups
				.entry((*key).clone())
				.or_insert_with(|| GroupState::new(&self.aggregate.ops));
			state.add(data, &self.aggregate.ops);
			affected.push(state.to_value(key, &self.aggregate.ops));
		}

		// Adjust contributions in groups the doc stayed in (if op values changed)
		for key in &stable {
			if let Some(od) = old_data {
				let state = self
					.groups
					.entry((*key).clone())
					.or_insert_with(|| GroupState::new(&self.aggregate.ops));
				state.remove(od, &self.aggregate.ops);
				state.add(data, &self.aggregate.ops);
				affected.push(state.to_value(key, &self.aggregate.ops));
			}
		}

		if affected.is_empty() {
			None
		} else {
			Some(affected)
		}
	}

	fn handle_delete(&mut self, old_data: Option<&Value>) -> Option<Vec<Value>> {
		let od = old_data?;

		if let Some(ref f) = self.filter {
			if !f.matches(od) {
				return None;
			}
		}

		let group_keys = extract_group_keys(od, &self.aggregate.group_by);
		if group_keys.is_empty() {
			return None;
		}

		let mut affected = Vec::new();
		for key in &group_keys {
			let state = self
				.groups
				.entry(key.clone())
				.or_insert_with(|| GroupState::new(&self.aggregate.ops));
			state.remove(od, &self.aggregate.ops);
			affected.push(state.to_value(key, &self.aggregate.ops));
		}
		Some(affected)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use cloudillo_types::rtdb_adapter::{AggregateOp, AggregateOptions, QueryFilter};
	use serde_json::json;

	fn count_only_agg(group_by: &str) -> AggregateOptions {
		AggregateOptions { group_by: group_by.to_string(), ops: Vec::new() }
	}

	fn sum_agg(group_by: &str, sum_field: &str) -> AggregateOptions {
		AggregateOptions {
			group_by: group_by.to_string(),
			ops: vec![AggregateOp::Sum { field: sum_field.to_string() }],
		}
	}

	fn avg_agg(group_by: &str, avg_field: &str) -> AggregateOptions {
		AggregateOptions {
			group_by: group_by.to_string(),
			ops: vec![AggregateOp::Avg { field: avg_field.to_string() }],
		}
	}

	fn find_group<'a>(result: &'a [Value], group: &str) -> Option<&'a Value> {
		result.iter().find(|v| v.get("group").and_then(|g| g.as_str()) == Some(group))
	}

	#[test]
	fn count_only_create_and_verify() {
		let mut state = IncrementalAggState::new(count_only_agg("category"), None);

		state.add_doc(&json!({"id": "1", "category": "rust"}));
		state.add_doc(&json!({"id": "2", "category": "rust"}));
		state.add_doc(&json!({"id": "3", "category": "go"}));

		let result = state.get_full_result();
		assert_eq!(result.len(), 2);

		let rust = find_group(&result, "rust");
		assert!(rust.is_some());
		assert_eq!(rust.and_then(|v| v.get("count")).and_then(|v| v.as_u64()), Some(2));

		let go = find_group(&result, "go");
		assert!(go.is_some());
		assert_eq!(go.and_then(|v| v.get("count")).and_then(|v| v.as_u64()), Some(1));
	}

	#[test]
	fn update_changes_group() {
		let mut state = IncrementalAggState::new(count_only_agg("category"), None);

		state.add_doc(&json!({"id": "1", "category": "rust"}));
		state.add_doc(&json!({"id": "2", "category": "rust"}));

		// Update doc 1: change category from "rust" to "go"
		let delta = state.process_change(&ChangeEvent::Update {
			path: "items/1".into(),
			data: json!({"id": "1", "category": "go"}),
			old_data: Some(json!({"id": "1", "category": "rust"})),
		});

		assert!(delta.is_some());
		let delta = delta.unwrap_or_default();
		assert_eq!(delta.len(), 2); // rust affected, go affected

		let rust = find_group(&delta, "rust");
		assert_eq!(rust.and_then(|v| v.get("count")).and_then(|v| v.as_u64()), Some(1));

		let go = find_group(&delta, "go");
		assert_eq!(go.and_then(|v| v.get("count")).and_then(|v| v.as_u64()), Some(1));
	}

	#[test]
	fn filter_transition_old_matched_new_doesnt() {
		let filter = QueryFilter::equals_one("status", json!("active"));
		let mut state = IncrementalAggState::new(count_only_agg("category"), Some(filter));

		state.add_doc(&json!({"id": "1", "category": "rust", "status": "active"}));
		state.add_doc(&json!({"id": "2", "category": "rust", "status": "active"}));

		// Update doc 1: status changes from "active" to "archived" → no longer matches
		let delta = state.process_change(&ChangeEvent::Update {
			path: "items/1".into(),
			data: json!({"id": "1", "category": "rust", "status": "archived"}),
			old_data: Some(json!({"id": "1", "category": "rust", "status": "active"})),
		});

		assert!(delta.is_some());
		let delta = delta.unwrap_or_default();
		let rust = find_group(&delta, "rust");
		assert_eq!(rust.and_then(|v| v.get("count")).and_then(|v| v.as_u64()), Some(1));
	}

	#[test]
	fn filter_transition_old_didnt_match_new_does() {
		let filter = QueryFilter::equals_one("status", json!("active"));
		let mut state = IncrementalAggState::new(count_only_agg("category"), Some(filter));

		state.add_doc(&json!({"id": "1", "category": "rust", "status": "active"}));

		// Update doc 2: status changes from "archived" to "active" → now matches
		let delta = state.process_change(&ChangeEvent::Update {
			path: "items/2".into(),
			data: json!({"id": "2", "category": "rust", "status": "active"}),
			old_data: Some(json!({"id": "2", "category": "rust", "status": "archived"})),
		});

		assert!(delta.is_some());
		let delta = delta.unwrap_or_default();
		let rust = find_group(&delta, "rust");
		assert_eq!(rust.and_then(|v| v.get("count")).and_then(|v| v.as_u64()), Some(2));
	}

	#[test]
	fn delete_with_old_data() {
		let mut state = IncrementalAggState::new(count_only_agg("category"), None);

		state.add_doc(&json!({"id": "1", "category": "rust"}));
		state.add_doc(&json!({"id": "2", "category": "rust"}));

		let delta = state.process_change(&ChangeEvent::Delete {
			path: "items/1".into(),
			old_data: Some(json!({"id": "1", "category": "rust"})),
		});

		assert!(delta.is_some());
		let delta = delta.unwrap_or_default();
		let rust = find_group(&delta, "rust");
		assert_eq!(rust.and_then(|v| v.get("count")).and_then(|v| v.as_u64()), Some(1));
	}

	#[test]
	fn delete_without_old_data_returns_none() {
		let mut state = IncrementalAggState::new(count_only_agg("category"), None);
		state.add_doc(&json!({"id": "1", "category": "rust"}));

		let delta =
			state.process_change(&ChangeEvent::Delete { path: "items/1".into(), old_data: None });

		assert!(delta.is_none());
	}

	#[test]
	fn array_group_by_multiple_groups() {
		let mut state = IncrementalAggState::new(count_only_agg("tags"), None);

		state.add_doc(&json!({"id": "1", "tags": ["rust", "web"]}));

		let result = state.get_full_result();
		assert_eq!(result.len(), 2);
		assert_eq!(
			find_group(&result, "rust")
				.and_then(|v| v.get("count"))
				.and_then(|v| v.as_u64()),
			Some(1)
		);
		assert_eq!(
			find_group(&result, "web").and_then(|v| v.get("count")).and_then(|v| v.as_u64()),
			Some(1)
		);
	}

	#[test]
	fn array_group_by_update_removes_and_adds_tag() {
		let mut state = IncrementalAggState::new(count_only_agg("tags"), None);

		state.add_doc(&json!({"id": "1", "tags": ["rust", "web"]}));

		// Remove "web", add "cli"
		let delta = state.process_change(&ChangeEvent::Update {
			path: "items/1".into(),
			data: json!({"id": "1", "tags": ["rust", "cli"]}),
			old_data: Some(json!({"id": "1", "tags": ["rust", "web"]})),
		});

		assert!(delta.is_some());
		let delta = delta.unwrap_or_default();

		// "web" should have count=0, "cli" should have count=1
		let web = find_group(&delta, "web");
		assert_eq!(web.and_then(|v| v.get("count")).and_then(|v| v.as_u64()), Some(0));

		let cli = find_group(&delta, "cli");
		assert_eq!(cli.and_then(|v| v.get("count")).and_then(|v| v.as_u64()), Some(1));
	}

	#[test]
	fn group_drops_to_zero() {
		let mut state = IncrementalAggState::new(count_only_agg("category"), None);

		state.add_doc(&json!({"id": "1", "category": "go"}));

		let delta = state.process_change(&ChangeEvent::Delete {
			path: "items/1".into(),
			old_data: Some(json!({"id": "1", "category": "go"})),
		});

		assert!(delta.is_some());
		let delta = delta.unwrap_or_default();
		let go = find_group(&delta, "go");
		assert_eq!(go.and_then(|v| v.get("count")).and_then(|v| v.as_u64()), Some(0));
	}

	#[test]
	fn sum_ops_adjusted_incrementally() {
		let mut state = IncrementalAggState::new(sum_agg("category", "price"), None);

		state.add_doc(&json!({"id": "1", "category": "a", "price": 10}));
		state.add_doc(&json!({"id": "2", "category": "a", "price": 20}));

		let result = state.get_full_result();
		let a = find_group(&result, "a");
		assert_eq!(a.and_then(|v| v.get("sum_price")).and_then(|v| v.as_f64()), Some(30.0));

		// Update doc 1 price from 10 to 15
		let delta = state.process_change(&ChangeEvent::Update {
			path: "items/1".into(),
			data: json!({"id": "1", "category": "a", "price": 15}),
			old_data: Some(json!({"id": "1", "category": "a", "price": 10})),
		});

		assert!(delta.is_some());
		let delta = delta.unwrap_or_default();
		let a = find_group(&delta, "a");
		assert_eq!(a.and_then(|v| v.get("sum_price")).and_then(|v| v.as_f64()), Some(35.0));
	}

	#[test]
	fn avg_ops_adjusted_incrementally() {
		let mut state = IncrementalAggState::new(avg_agg("category", "score"), None);

		state.add_doc(&json!({"id": "1", "category": "a", "score": 10}));
		state.add_doc(&json!({"id": "2", "category": "a", "score": 20}));

		let result = state.get_full_result();
		let a = find_group(&result, "a");
		assert_eq!(a.and_then(|v| v.get("avg_score")).and_then(|v| v.as_f64()), Some(15.0));

		// Update doc 1 score from 10 to 30
		let delta = state.process_change(&ChangeEvent::Update {
			path: "items/1".into(),
			data: json!({"id": "1", "category": "a", "score": 30}),
			old_data: Some(json!({"id": "1", "category": "a", "score": 10})),
		});

		assert!(delta.is_some());
		let delta = delta.unwrap_or_default();
		let a = find_group(&delta, "a");
		assert_eq!(a.and_then(|v| v.get("avg_score")).and_then(|v| v.as_f64()), Some(25.0));
	}

	#[test]
	fn early_exit_no_group_or_op_change() {
		let mut state = IncrementalAggState::new(sum_agg("category", "price"), None);

		state.add_doc(&json!({"id": "1", "category": "a", "price": 10, "title": "hello"}));

		// Update only the title — group_by and op fields unchanged
		let delta = state.process_change(&ChangeEvent::Update {
			path: "items/1".into(),
			data: json!({"id": "1", "category": "a", "price": 10, "title": "world"}),
			old_data: Some(json!({"id": "1", "category": "a", "price": 10, "title": "hello"})),
		});

		assert!(delta.is_none());
	}

	#[test]
	fn irrelevant_field_change_returns_none() {
		let mut state = IncrementalAggState::new(count_only_agg("tags"), None);

		state.add_doc(&json!({"id": "1", "tags": ["rust"], "title": "old"}));

		// Change title, tags unchanged — no ops → count-only, same groups
		let delta = state.process_change(&ChangeEvent::Update {
			path: "items/1".into(),
			data: json!({"id": "1", "tags": ["rust"], "title": "new"}),
			old_data: Some(json!({"id": "1", "tags": ["rust"], "title": "old"})),
		});

		// Count-only agg with no ops → early exit since group_by didn't change
		// and there are no op fields to compare
		assert!(delta.is_none());
	}

	#[test]
	fn create_event_incremental() {
		let mut state = IncrementalAggState::new(count_only_agg("category"), None);

		state.add_doc(&json!({"id": "1", "category": "rust"}));

		let delta = state.process_change(&ChangeEvent::Create {
			path: "items/2".into(),
			data: json!({"id": "2", "category": "rust"}),
		});

		assert!(delta.is_some());
		let delta = delta.unwrap_or_default();
		let rust = find_group(&delta, "rust");
		assert_eq!(rust.and_then(|v| v.get("count")).and_then(|v| v.as_u64()), Some(2));
	}

	#[test]
	fn create_event_filtered_out_returns_none() {
		let filter = QueryFilter::equals_one("status", json!("active"));
		let mut state = IncrementalAggState::new(count_only_agg("category"), Some(filter));

		let delta = state.process_change(&ChangeEvent::Create {
			path: "items/1".into(),
			data: json!({"id": "1", "category": "rust", "status": "archived"}),
		});

		assert!(delta.is_none());
	}

	#[test]
	fn needs_full_recompute_with_min_max() {
		let agg = AggregateOptions {
			group_by: "category".to_string(),
			ops: vec![AggregateOp::Min { field: "price".to_string() }],
		};
		let state = IncrementalAggState::new(agg, None);
		assert!(state.needs_full_recompute());
	}

	#[test]
	fn no_full_recompute_without_min_max() {
		let state = IncrementalAggState::new(count_only_agg("category"), None);
		assert!(!state.needs_full_recompute());
	}

	#[test]
	fn null_group_by_field_skipped() {
		let mut state = IncrementalAggState::new(count_only_agg("category"), None);

		state.add_doc(&json!({"id": "1", "category": null}));
		state.add_doc(&json!({"id": "2"})); // missing field

		let result = state.get_full_result();
		assert!(result.is_empty());
	}

	#[test]
	fn delete_with_filter_not_matched_returns_none() {
		let filter = QueryFilter::equals_one("status", json!("active"));
		let mut state = IncrementalAggState::new(count_only_agg("category"), Some(filter));

		state.add_doc(&json!({"id": "1", "category": "rust", "status": "active"}));

		// Delete a doc that wasn't matching the filter
		let delta = state.process_change(&ChangeEvent::Delete {
			path: "items/2".into(),
			old_data: Some(json!({"id": "2", "category": "rust", "status": "archived"})),
		});

		assert!(delta.is_none());
	}
}

// vim: ts=4
