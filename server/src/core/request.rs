//! Request client implementation

use futures_core::stream::Stream;
use hyper::http::StatusCode;
use http_body_util::{BodyDataStream, BodyExt, Empty, Full, StreamBody, combinators::BoxBody};
use hyper::{body::Body, body::Bytes, Method};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::sync::Arc;

use crate::prelude::*;
use crate::auth_adapter::AuthAdapter;
use crate::meta_adapter;
use crate::action::action;

fn to_boxed<B>(body: B) -> BoxBody<Bytes, Error>
where
	B: Body<Data = Bytes> + Send + Sync + 'static,
	B::Error: Send + 'static,
{
	body.map_err(|err| { Error::Unknown }).boxed()
}

#[derive(Deserialize)]
struct TokenRes {
	token: Box<str>
}

#[derive(Debug, Clone)]
pub struct Request {
	pub auth_adapter: Arc<dyn AuthAdapter>,
	client: Client<HttpsConnector<HttpConnector>, BoxBody<Bytes, Error>>,
}

impl Request {
	pub fn new(auth_adapter: Arc<dyn AuthAdapter>) -> Self {
		let client = HttpsConnectorBuilder::new()
			.with_native_roots()
			.expect("no native root CA certificates found")
			.https_only()
			.enable_http1()
			.build();

		Request {
			auth_adapter,
			client: Client::builder(TokioExecutor::new()).build(client),
		}
	}

	async fn create_proxy_token(&self, tn_id: TnId, id_tag: &str, subject: Option<&str>) -> ClResult<Box<str>> {
		let auth_token = self.auth_adapter.create_action_token(tn_id, action::CreateAction {
			typ: "PROXY".into(),
			audience_tag: Some(id_tag.into()),
			expires_at: Some(Timestamp::from_now(60)), // 1 min
			..Default::default()
		}).await?;
		let req = hyper::Request::builder()
			.method(Method::GET)
			.uri(format!("https://cl-o.{}/api/auth/access-token?token={}{}",
				id_tag,
				auth_token,
				if let Some(subject) = subject { format!("&subject={}", subject) } else { "".into() }
			))
			.body(to_boxed(Empty::new()))?;
		let res = self.client.request(req).await?;
		if !res.status().is_success() {
			return Err(Error::PermissionDenied);
		}
		let parsed: TokenRes = serde_json::from_slice(&res.into_body().collect().await?.to_bytes())?;

		Ok(parsed.token)
	}

	pub async fn get_bin(&self, id_tag: &str, path: &str, auth: bool) -> ClResult<Bytes> {
		// FIXME TnId
		let req = hyper::Request::builder()
			.method(Method::GET)
			.uri(format!("https://cl-o.{}/api{}", id_tag, path));
		let req = if auth {
			req.header("Authorization", format!("Bearer {}", self.create_proxy_token(TnId(1), id_tag, None).await?))
		} else {
			req
		};
		let req = req.body(to_boxed(Empty::new()))?;
		let res = self.client.request(req).await?;
		info!("Got response: {}", res.status());
		match res.status() {
			StatusCode::OK => Ok(res.into_body().collect().await?.to_bytes()),
			StatusCode::NOT_FOUND => Err(Error::NotFound),
			StatusCode::FORBIDDEN => Err(Error::PermissionDenied),
			_ => Err(Error::Unknown),
		}
	}

	pub async fn get_stream(&self, id_tag: &str, path: &str) -> ClResult<BodyDataStream<hyper::body::Incoming>> {
		// FIXME
		let token = self.create_proxy_token(TnId(1), id_tag, None).await?;
		info!("Got proxy token: {}", token);
		let req = hyper::Request::builder()
			.method(Method::GET)
			.uri(format!("https://cl-o.{}/api{}", id_tag, path))
			.header("Authorization", format!("Bearer {}", token))
			.body(to_boxed(Empty::new()))?;
		let res = self.client.request(req).await?;
		match res.status() {
			StatusCode::OK => Ok(res.into_body().into_data_stream()),
			StatusCode::NOT_FOUND => Err(Error::NotFound),
			StatusCode::FORBIDDEN => Err(Error::PermissionDenied),
			_ => Err(Error::Unknown),
		}
	}

	pub async fn get<Res>(&self, id_tag: &str, path: &str) -> ClResult<Res>
	where Res: DeserializeOwned {
		let res = self.get_bin(id_tag, path, true).await?;
		let parsed: Res = serde_json::from_slice(&res)?;
		Ok(parsed)
	}

	pub async fn get_noauth<Res>(&self, id_tag: &str, path: &str) -> ClResult<Res>
	where Res: DeserializeOwned {
		let res = self.get_bin(id_tag, path, false).await?;
		let parsed: Res = serde_json::from_slice(&res)?;
		Ok(parsed)
	}

	pub async fn post_bin(&self, id_tag: &str, path: &str, data: Bytes) -> ClResult<Bytes> {
		let req = hyper::Request::builder()
			.method(Method::POST)
			.uri(format!("https://cl-o.{}/api{}", id_tag, path))
			.body(to_boxed(Full::from(data)))?;
		let res = self.client.request(req).await?;
		let body = res.into_body().collect().await?.to_bytes();
		Ok(body)
	}

	pub async fn post_stream<S>(&self, id_tag: &str, path: &str, stream: S) -> ClResult<Bytes>
	where
		S: Stream<Item = Result<hyper::body::Frame<Bytes>, hyper::Error>> + Send + Sync + 'static
	{
		let req = hyper::Request::builder()
			.method(Method::POST)
			.uri(format!("https://cl-o.{}/api{}", id_tag, path))
			.body(to_boxed(StreamBody::new(stream)))?;
		let res = self.client.request(req).await?;
		let body = res.into_body().collect().await?.to_bytes();
		Ok(body)
	}

	pub async fn post<Res>(&self, id_tag: &str, path: &str, data: &impl Serialize) -> ClResult<Res>
	where Res: DeserializeOwned {
		let res = self.post_bin(id_tag, path, serde_json::to_vec(data)?.into()).await?;
		let parsed: Res = serde_json::from_slice(&res)?;
		Ok(parsed)
	}
}

// vim: ts=4
