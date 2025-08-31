use async_trait::async_trait;

pub struct TokenData {
	pub issuer: Box<str>,
}

#[async_trait]
pub trait AuthAdapter: Send + Sync {
	async fn create_key(
		&self,
		tn_id: u32,
	) -> Result<(Box<str>, Box<str>), Box<dyn std::error::Error>>;
	async fn create_token(
		&self,
		tn_id: u32,
		data: TokenData,
	) -> Result<Box<str>, Box<dyn std::error::Error>>;
}

// vim: ts=4
