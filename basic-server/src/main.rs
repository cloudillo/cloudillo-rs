#![allow(unused)]

use std::{env, path};
use tokio::fs;

use cloudillo::auth_adapter::TokenData;
use auth_adapter_sqlite::AuthAdapterSqlite;

pub struct Config {
	pub db_dir: path::PathBuf,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
	let config = Config {
		db_dir: path::PathBuf::from(env::var("DB_DIR").unwrap_or("./data".to_string()))
	};
	//tracing_subscriber::fmt::init();

	fs::create_dir_all(&config.db_dir).await.unwrap();
	let auth_adapter = Box::new(AuthAdapterSqlite::new(config.db_dir.join("auth.db")).await.unwrap());
	//let auth_adapter = &AuthAdapterSqlite::new("auth.db").await.unwrap();

	//let token = cld.create_token(1, TokenData { issuer: "test".into() }).await.unwrap();
	//cloudillo::run(auth_adapter).await.unwrap();
	cloudillo::run(cloudillo::CloudilloOpts { auth_adapter }).await.unwrap();

	//println!("token: {}", token);
}

// vim: ts=4
