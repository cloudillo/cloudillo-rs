use async_trait::async_trait;

use crate::AppState;

pub struct TokenData {
	pub issuer: Box<str>,
}

#[async_trait]
pub trait AuthAdapter: Send + Sync {
	async fn create_key(
		&self,
		state: &AppState,
		tn_id: u32,
	) -> Result<(Box<str>, Box<str>), Box<dyn std::error::Error>>;
	async fn create_token(
		&self,
		state: &AppState,
		tn_id: u32,
		data: TokenData,
	) -> Result<Box<str>, Box<dyn std::error::Error>>;
}

// vim: ts=4
