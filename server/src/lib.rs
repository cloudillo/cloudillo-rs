#![allow(unused)]

use axum::{
	extract::{State, Query},
	routing::{get, post},
	Router
};
use std::rc::Rc;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::Mutex;

pub mod action;
pub mod file;
pub mod auth_adapter;
pub mod worker;

use crate::action::handler as action_handler;
use crate::file::handler as file_handler;
use auth_adapter::AuthAdapter;

pub struct Cloudillo {
	auth_adapter: Box<dyn auth_adapter::AuthAdapter>,
}

//pub struct AppState<'a> {
//	cloudillo: &'a Cloudillo<'a>
//}
pub struct AppState {
	pub worker: worker::WorkerPool,
	//cloudillo: &'a Cloudillo,
	//auth_adapter: &'static dyn AuthAdapter,
	pub auth_adapter: Box<dyn auth_adapter::AuthAdapter>,
}

/*
impl<'a> Cloudillo {
	//pub async fn new(auth_adapter: &'static dyn AuthAdapter) -> Result<Self, Box<dyn std::error::Error>> {
	pub async fn new(auth_adapter: Box<dyn AuthAdapter>) -> Result<Self, Box<dyn std::error::Error>> {
		Ok(Self {
			auth_adapter
		})
	}

	pub async fn run(&self) {
		//let state = Rc::new(AppState { cloudillo: &self });
		//let state = Arc::new(Mutex::new(AppState { cloudillo: &self }));
		//let state = Arc::new(AppState { cloudillo: &self });
		let state = Arc::new(AppState { auth_adapter: self.auth_adapter });

		let router = Router::new()
			.route("/", get(get_root))
			//.route("/action", get(action_handler::list_actions))
			//.route("/action", post(action_handler::post_action))
			.with_state(state);

		let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
		axum::serve(listener, router).await.unwrap();
	}

	pub async fn create_token(&self, tn_id: u32, data: auth_adapter::TokenData) -> Result<Box<str>, Box<dyn std::error::Error>> {
		return self.auth_adapter.create_token(tn_id, data).await
	}
}
*/

pub struct CloudilloOpts {
	//pub auth_adapter: Box<dyn auth_adapter::AuthAdapter>,
	pub auth_adapter: Box<dyn auth_adapter::AuthAdapter>,
}

pub async fn run(opts: CloudilloOpts) -> Result<(), std::io::Error> {
	/*
	let state = Arc::new(AppState {
		worker: worker::WorkerPool::new(1, 2, 1),
		auth_adapter: opts.auth_adapter,
	});
	*/
	let state = AppState {
		worker: worker::WorkerPool::new(1, 2, 1),
		auth_adapter: opts.auth_adapter,
	};

	let router = Router::new()
		.route("/", get(get_root))
		.route("/key", get(action_handler::create_key))
		.route("/action", get(action_handler::list_actions))
		.route("/action", post(action_handler::post_action))
		.route("/file", post(file_handler::post_file))
		.with_state(state.into());

	let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
		.await
		.unwrap();

	print!("Listening on http://127.0.0.1:3000\n");
	axum::serve(listener, router).await
}

async fn get_root(
	Query(query): Query<HashMap<String, String>>,
	State(state): State<Arc<AppState>>,
	//) -> &'static str {
) -> Box<str> {
	let token = state
		.auth_adapter
		.create_token(
			&state,
			1,
			auth_adapter::TokenData {
				issuer: "test".into(),
			},
		)
		.await
		.unwrap();
	token
}

// vim: ts=4
