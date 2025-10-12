//! Request client implementation

use serde::{de::DeserializeOwned, Serialize};

use crate::prelude::*;

#[derive(Debug, Clone)]
pub struct Request(reqwest::Client);

impl Request {
	pub fn new() -> Self {
		let client = reqwest::Client::new();
		Request(client)
	}

	pub async fn post<Res>(&self, state: &App, path: &str, data: &impl Serialize) -> Result<Res, Error>
	where Res: DeserializeOwned {
		let res = self.0.post("https://cl-o.nikita.cloudillo.net/api/inbox")
			.json(&data)
			.send()
			.await.map_err(|_| Error::Unknown)?;
		let res: Res = res.json().await.inspect_err(|err| error!("Failed to deserialize response: {}", err)).map_err(|_| Error::Unknown)?;
		Ok(res)
	}
}

// vim: ts=4
