#![allow(unused)]

use std::path::Path;
use async_trait::async_trait;
use async_sqlite as sqlite;

use cloudillo::auth_adapter;

mod token;

pub struct AuthAdapterSqlite {
	db: sqlite::Client
}

impl AuthAdapterSqlite {
	pub async fn new<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
		let db = sqlite::ClientBuilder::new()
			.path(path.as_ref())
			.journal_mode(sqlite::JournalMode::Wal)
			.open()
			.await?;

		Ok(Self { db })
	}

}

#[async_trait]
impl auth_adapter::AuthAdapter for AuthAdapterSqlite {
	async fn create_key(&self, tn_id: u32) -> Result<(Box<str>, Box<str>), Box<dyn std::error::Error>> {
		let (private_key, public_key) = token::generate_key().await?;
		Ok((private_key, public_key))
	}

	async fn create_token(&self, tn_id: u32, data: auth_adapter::TokenData) -> Result<Box<str>, Box<dyn std::error::Error>> {
		let value: String = self.db.conn(|conn| {
			conn.query_row("SELECT '1'", [], |row| row.get(0))
		}).await?;
		println!("[auth-adapter-sqlite] initialized");
		let key = token::generate_key();
		Ok(Box::from(value))
	}
}

// vim: ts=4
