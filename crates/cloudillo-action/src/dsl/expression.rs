//! Expression evaluator for the Action DSL
//!
//! Evaluates expressions in hook contexts, supporting:
//! - Variable references with path traversal
//! - Template string interpolation
//! - Comparison operations
//! - Logical operations
//! - Arithmetic operations
//! - String operations
//! - Ternary expressions
//! - Null coalescing

use super::types::{
	ArithmeticExpr, CoalesceExpr, ComparisonExpr, Expression, LogicalExpr, StringOpExpr,
	TernaryExpr,
};
use crate::hooks::HookContext;
use crate::prelude::*;
use serde_json::Value;

/// Maximum expression nesting depth to prevent stack overflow
const MAX_DEPTH: usize = 50;
/// Maximum expression node count to prevent resource exhaustion
const MAX_NODES: usize = 100;

/// Expression evaluator with depth and node count tracking
#[derive(Debug)]
pub struct ExpressionEvaluator {
	depth: usize,
	node_count: usize,
}

impl ExpressionEvaluator {
	/// Create a new expression evaluator
	pub fn new() -> Self {
		Self { depth: 0, node_count: 0 }
	}

	/// Evaluate an expression in the given context
	pub fn evaluate(&mut self, expr: &Expression, context: &HookContext) -> ClResult<Value> {
		self.depth += 1;
		self.node_count += 1;

		if self.depth > MAX_DEPTH {
			return Err(Error::ValidationError(format!(
				"Maximum expression depth exceeded ({})",
				MAX_DEPTH
			)));
		}
		if self.node_count > MAX_NODES {
			return Err(Error::ValidationError(format!(
				"Maximum expression nodes exceeded ({})",
				MAX_NODES
			)));
		}

		let result = self.evaluate_inner(expr, context)?;

		self.depth -= 1;
		Ok(result)
	}

	fn evaluate_inner(&mut self, expr: &Expression, context: &HookContext) -> ClResult<Value> {
		match expr {
			// Literals
			Expression::Null => Ok(Value::Null),
			Expression::Bool(b) => Ok(Value::Bool(*b)),
			Expression::Number(n) => {
				serde_json::Number::from_f64(*n).map(Value::Number).ok_or_else(|| {
					Error::ValidationError("Invalid number (NaN or infinity)".to_string())
				})
			}
			Expression::String(s) => Self::evaluate_template(s, context),

			// Complex expressions
			Expression::Comparison(c) => self.evaluate_comparison(c, context),
			Expression::Logical(l) => self.evaluate_logical(l, context),
			Expression::Arithmetic(a) => self.evaluate_arithmetic(a, context),
			Expression::StringOp(s) => self.evaluate_string_op(s, context),
			Expression::Ternary(t) => self.evaluate_ternary(t, context),
			Expression::Coalesce(c) => self.evaluate_coalesce(c, context),
		}
	}

	/// Evaluate template string with variable interpolation
	/// Supports:
	/// - Simple variables: "{variable}"
	/// - Nested paths: "{context.tenant.type}"
	/// - Template strings: "Key: {type}:{issuer}:{audience}"
	fn evaluate_template(template: &str, context: &HookContext) -> ClResult<Value> {
		// Check if it's a simple variable reference: "{variable}"
		if template.starts_with('{')
			&& template.ends_with('}')
			&& template.matches('{').count() == 1
		{
			let var_name = &template[1..template.len() - 1];
			return Self::get_variable(var_name, context);
		}

		// Template with embedded variables: "Key: {type}:{issuer}"
		let mut result = String::new();
		let mut chars = template.chars().peekable();

		while let Some(ch) = chars.next() {
			if ch == '{' {
				// Extract variable name
				let mut var_name = String::new();
				while let Some(&next_ch) = chars.peek() {
					if next_ch == '}' {
						chars.next(); // consume '}'
						break;
					}
					// Safe: we just peeked and confirmed there's a character
					if let Some(ch) = chars.next() {
						var_name.push(ch);
					}
				}

				// Get variable value
				let value = Self::get_variable(&var_name, context)?;
				let replacement = match value {
					Value::Null => String::new(),
					Value::String(s) => s,
					v => v.to_string(),
				};
				result.push_str(&replacement);
			} else {
				result.push(ch);
			}
		}

		Ok(Value::String(result))
	}

	/// Get variable from context by path
	/// Supports:
	/// - Direct fields: "issuer", "type", "subtype"
	/// - Nested paths: "context.tenant.type"
	/// - User variables: any name set by Set operation
	fn get_variable(path: &str, context: &HookContext) -> ClResult<Value> {
		let parts: Vec<&str> = path.split('.').collect();

		// Start with the root value
		let mut current = match parts[0] {
			// Action fields
			"action_id" => Value::String(context.action_id.clone()),
			"type" => Value::String(context.r#type.clone()),
			"subtype" => context.subtype.as_ref().map_or(Value::Null, |s| Value::String(s.clone())),
			"issuer" => Value::String(context.issuer.clone()),
			"audience" => {
				context.audience.as_ref().map_or(Value::Null, |s| Value::String(s.clone()))
			}
			"parent" => context.parent.as_ref().map_or(Value::Null, |s| Value::String(s.clone())),
			"subject" => context.subject.as_ref().map_or(Value::Null, |s| Value::String(s.clone())),
			"content" => context.content.clone().unwrap_or(Value::Null),
			"attachments" => context.attachments.as_ref().map_or(Value::Null, |a| {
				Value::Array(a.iter().map(|s| Value::String(s.clone())).collect())
			}),

			// Timestamps
			"created_at" => Value::String(context.created_at.clone()),
			"expires_at" => {
				context.expires_at.as_ref().map_or(Value::Null, |s| Value::String(s.clone()))
			}

			// Context object
			"context" => {
				let mut obj = serde_json::Map::new();
				obj.insert("tenant_id".to_string(), Value::Number(context.tenant_id.into()));
				obj.insert("tenant_tag".to_string(), Value::String(context.tenant_tag.clone()));
				obj.insert("tenant_type".to_string(), Value::String(context.tenant_type.clone()));
				Value::Object(obj)
			}

			// Flags
			"is_inbound" => Value::Bool(context.is_inbound),
			"is_outbound" => Value::Bool(context.is_outbound),

			// User variables
			var_name => context.vars.get(var_name).cloned().ok_or_else(|| {
				Error::ValidationError(format!("Variable not found: {}", var_name))
			})?,
		};

		// Traverse nested paths
		for part in &parts[1..] {
			match &current {
				Value::Object(map) => {
					current = map.get(*part).cloned().unwrap_or(Value::Null);
				}
				Value::Null => return Ok(Value::Null),
				_ => {
					return Err(Error::ValidationError(format!(
						"Cannot access property '{}' on non-object",
						part
					)))
				}
			}
		}

		Ok(current)
	}

	/// Evaluate comparison expression
	fn evaluate_comparison(
		&mut self,
		comp: &ComparisonExpr,
		context: &HookContext,
	) -> ClResult<Value> {
		match comp {
			ComparisonExpr::Eq([left, right]) => {
				let l = self.evaluate(left, context)?;
				let r = self.evaluate(right, context)?;
				Ok(Value::Bool(l == r))
			}
			ComparisonExpr::Ne([left, right]) => {
				let l = self.evaluate(left, context)?;
				let r = self.evaluate(right, context)?;
				Ok(Value::Bool(l != r))
			}
			ComparisonExpr::Gt([left, right]) => {
				let l_val = self.evaluate(left, context)?;
				let r_val = self.evaluate(right, context)?;
				let l = Self::to_number(&l_val)?;
				let r = Self::to_number(&r_val)?;
				Ok(Value::Bool(l > r))
			}
			ComparisonExpr::Gte([left, right]) => {
				let l_val = self.evaluate(left, context)?;
				let r_val = self.evaluate(right, context)?;
				let l = Self::to_number(&l_val)?;
				let r = Self::to_number(&r_val)?;
				Ok(Value::Bool(l >= r))
			}
			ComparisonExpr::Lt([left, right]) => {
				let l_val = self.evaluate(left, context)?;
				let r_val = self.evaluate(right, context)?;
				let l = Self::to_number(&l_val)?;
				let r = Self::to_number(&r_val)?;
				Ok(Value::Bool(l < r))
			}
			ComparisonExpr::Lte([left, right]) => {
				let l_val = self.evaluate(left, context)?;
				let r_val = self.evaluate(right, context)?;
				let l = Self::to_number(&l_val)?;
				let r = Self::to_number(&r_val)?;
				Ok(Value::Bool(l <= r))
			}
		}
	}

	/// Evaluate logical expression
	fn evaluate_logical(
		&mut self,
		logical: &LogicalExpr,
		context: &HookContext,
	) -> ClResult<Value> {
		match logical {
			LogicalExpr::And(exprs) => {
				for expr in exprs {
					let value = self.evaluate(expr, context)?;
					if !Self::to_bool(&value) {
						return Ok(Value::Bool(false));
					}
				}
				Ok(Value::Bool(true))
			}
			LogicalExpr::Or(exprs) => {
				for expr in exprs {
					let value = self.evaluate(expr, context)?;
					if Self::to_bool(&value) {
						return Ok(Value::Bool(true));
					}
				}
				Ok(Value::Bool(false))
			}
			LogicalExpr::Not(expr) => {
				let value = self.evaluate(expr, context)?;
				Ok(Value::Bool(!Self::to_bool(&value)))
			}
		}
	}

	/// Evaluate arithmetic expression
	fn evaluate_arithmetic(
		&mut self,
		arith: &ArithmeticExpr,
		context: &HookContext,
	) -> ClResult<Value> {
		match arith {
			ArithmeticExpr::Add(exprs) => {
				let mut sum = 0.0;
				for expr in exprs {
					let val = self.evaluate(expr, context)?;
					sum += Self::to_number(&val)?;
				}
				serde_json::Number::from_f64(sum).map(Value::Number).ok_or_else(|| {
					Error::ValidationError("Invalid number result (NaN or infinity)".to_string())
				})
			}
			ArithmeticExpr::Subtract([left, right]) => {
				let l_val = self.evaluate(left, context)?;
				let r_val = self.evaluate(right, context)?;
				let l = Self::to_number(&l_val)?;
				let r = Self::to_number(&r_val)?;
				serde_json::Number::from_f64(l - r).map(Value::Number).ok_or_else(|| {
					Error::ValidationError("Invalid number result (NaN or infinity)".to_string())
				})
			}
			ArithmeticExpr::Multiply(exprs) => {
				let mut product = 1.0;
				for expr in exprs {
					let val = self.evaluate(expr, context)?;
					product *= Self::to_number(&val)?;
				}
				serde_json::Number::from_f64(product).map(Value::Number).ok_or_else(|| {
					Error::ValidationError("Invalid number result (NaN or infinity)".to_string())
				})
			}
			ArithmeticExpr::Divide([left, right]) => {
				let l_val = self.evaluate(left, context)?;
				let r_val = self.evaluate(right, context)?;
				let l = Self::to_number(&l_val)?;
				let r = Self::to_number(&r_val)?;
				serde_json::Number::from_f64(l / r).map(Value::Number).ok_or_else(|| {
					Error::ValidationError("Invalid number result (NaN or infinity)".to_string())
				})
			}
		}
	}

	/// Evaluate string operation
	fn evaluate_string_op(
		&mut self,
		string_op: &StringOpExpr,
		context: &HookContext,
	) -> ClResult<Value> {
		match string_op {
			StringOpExpr::Concat(exprs) => {
				let mut result = String::new();
				for expr in exprs {
					let value = self.evaluate(expr, context)?;
					result.push_str(&Self::to_string(&value));
				}
				Ok(Value::String(result))
			}
			StringOpExpr::Contains([haystack, needle]) => {
				let h_val = self.evaluate(haystack, context)?;
				let n_val = self.evaluate(needle, context)?;
				let h = Self::to_string(&h_val);
				let n = Self::to_string(&n_val);
				Ok(Value::Bool(h.contains(&n)))
			}
			StringOpExpr::StartsWith([string, prefix]) => {
				let s_val = self.evaluate(string, context)?;
				let p_val = self.evaluate(prefix, context)?;
				let s = Self::to_string(&s_val);
				let p = Self::to_string(&p_val);
				Ok(Value::Bool(s.starts_with(&p)))
			}
			StringOpExpr::EndsWith([string, suffix]) => {
				let s_val = self.evaluate(string, context)?;
				let suf_val = self.evaluate(suffix, context)?;
				let s = Self::to_string(&s_val);
				let suf = Self::to_string(&suf_val);
				Ok(Value::Bool(s.ends_with(&suf)))
			}
		}
	}

	/// Evaluate ternary expression (if-then-else)
	fn evaluate_ternary(
		&mut self,
		ternary: &TernaryExpr,
		context: &HookContext,
	) -> ClResult<Value> {
		let condition = self.evaluate(&ternary.r#if, context)?;
		if Self::to_bool(&condition) {
			self.evaluate(&ternary.then, context)
		} else {
			self.evaluate(&ternary.r#else, context)
		}
	}

	/// Evaluate coalesce expression (return first non-null value)
	fn evaluate_coalesce(
		&mut self,
		coalesce: &CoalesceExpr,
		context: &HookContext,
	) -> ClResult<Value> {
		for expr in &coalesce.coalesce {
			let value = self.evaluate(expr, context)?;
			if !value.is_null() {
				return Ok(value);
			}
		}
		Ok(Value::Null)
	}

	/// Convert value to boolean (truthy/falsy)
	fn to_bool(value: &Value) -> bool {
		match value {
			Value::Null => false,
			Value::Bool(b) => *b,
			Value::Number(n) => n.as_f64().unwrap_or(0.0) != 0.0,
			Value::String(s) => !s.is_empty(),
			Value::Array(a) => !a.is_empty(),
			Value::Object(o) => !o.is_empty(),
		}
	}

	/// Convert value to string
	fn to_string(value: &Value) -> String {
		match value {
			Value::Null => String::new(),
			Value::Bool(b) => b.to_string(),
			Value::Number(n) => n.to_string(),
			Value::String(s) => s.clone(),
			v => v.to_string(),
		}
	}

	/// Convert value to number
	fn to_number(value: &Value) -> ClResult<f64> {
		match value {
			Value::Number(n) => n.as_f64().ok_or_else(|| {
				Error::ValidationError(
					"Invalid number value (not representable as f64)".to_string(),
				)
			}),
			Value::String(s) => s.parse::<f64>().map_err(|_| {
				Error::ValidationError(format!(
					"Type mismatch: expected number, got string '{}'",
					s
				))
			}),
			_ => Err(Error::ValidationError(format!(
				"Type mismatch: expected number, got {:?}",
				value
			))),
		}
	}
}

impl Default for ExpressionEvaluator {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::HashMap;

	fn create_test_context() -> HookContext {
		HookContext {
			action_id: "test-action-id".to_string(),
			r#type: "CONN".to_string(),
			subtype: None,
			issuer: "alice".to_string(),
			audience: Some("bob".to_string()),
			parent: None,
			subject: None,
			content: Some(Value::String("Hello".to_string())),
			attachments: None,
			created_at: "2024-01-01T00:00:00Z".to_string(),
			expires_at: None,
			tenant_id: 1,
			tenant_tag: "example".to_string(),
			tenant_type: "person".to_string(),
			is_inbound: false,
			is_outbound: true,
			client_address: None,
			vars: HashMap::new(),
		}
	}

	#[test]
	fn test_simple_variable() {
		let mut eval = ExpressionEvaluator::new();
		let context = create_test_context();
		let expr = Expression::String("{issuer}".to_string());

		let result = eval.evaluate(&expr, &context).expect("evaluation should succeed");
		assert_eq!(result, Value::String("alice".to_string()));
	}

	#[test]
	fn test_nested_path() {
		let mut eval = ExpressionEvaluator::new();
		let context = create_test_context();
		let expr = Expression::String("{context.tenant_type}".to_string());

		let result = eval.evaluate(&expr, &context).expect("evaluation should succeed");
		assert_eq!(result, Value::String("person".to_string()));
	}

	#[test]
	fn test_template_string() {
		let mut eval = ExpressionEvaluator::new();
		let context = create_test_context();
		let expr = Expression::String("{type}:{issuer}:{audience}".to_string());

		let result = eval.evaluate(&expr, &context).expect("evaluation should succeed");
		assert_eq!(result, Value::String("CONN:alice:bob".to_string()));
	}

	#[test]
	fn test_comparison_eq() {
		let mut eval = ExpressionEvaluator::new();
		let context = create_test_context();
		let expr = Expression::Comparison(Box::new(ComparisonExpr::Eq([
			Expression::String("{subtype}".to_string()),
			Expression::Null,
		])));

		let result = eval.evaluate(&expr, &context).expect("evaluation should succeed");
		assert_eq!(result, Value::Bool(true));
	}

	#[test]
	fn test_logical_and() {
		let mut eval = ExpressionEvaluator::new();
		let context = create_test_context();
		let expr = Expression::Logical(Box::new(LogicalExpr::And(vec![
			Expression::Bool(true),
			Expression::String("{issuer}".to_string()),
		])));

		let result = eval.evaluate(&expr, &context).expect("evaluation should succeed");
		assert_eq!(result, Value::Bool(true)); // Both truthy
	}
}

// vim: ts=4
