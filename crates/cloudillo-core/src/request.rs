// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Request client implementation

use futures::TryStreamExt;
use futures_core::stream::Stream;
use http_body_util::{BodyExt, Empty, Full, StreamBody, combinators::BoxBody};
use hyper::http::StatusCode;
use hyper::{Method, body::Body, body::Bytes};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncRead;
use tokio::time::timeout;

/// Default HTTP request timeout (10 seconds)
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

use crate::prelude::*;
use cloudillo_types::action_types::CreateAction;
use cloudillo_types::auth_adapter::AuthAdapter;

fn to_boxed<B>(body: B) -> BoxBody<Bytes, Error>
where
	B: Body<Data = Bytes> + Send + Sync + 'static,
	B::Error: Send + 'static,
{
	body.map_err(|_err| Error::NetworkError("body stream error".into())).boxed()
}

#[derive(Deserialize)]
struct TokenData {
	token: Box<str>,
}

#[derive(Deserialize)]
struct TokenRes {
	data: TokenData,
}

/// Result of a conditional GET request
#[derive(Debug)]
pub enum ConditionalResult<T> {
	/// 200 OK - new data with new etag
	Modified { data: T, etag: Option<Box<str>> },
	/// 304 Not Modified - etag unchanged
	NotModified,
}

#[derive(Debug, Clone)]
pub struct Request {
	pub auth_adapter: Arc<dyn AuthAdapter>,
	client: Client<HttpsConnector<HttpConnector>, BoxBody<Bytes, Error>>,
	proxy_tokens: Arc<crate::ProxyTokenCache>,
}

impl Request {
	pub fn new(
		auth_adapter: Arc<dyn AuthAdapter>,
		proxy_tokens: Arc<crate::ProxyTokenCache>,
	) -> ClResult<Self> {
		let client = HttpsConnectorBuilder::new()
			.with_native_roots()
			.map_err(|_| Error::ConfigError("no native root CA certificates found".into()))?
			.https_only()
			.enable_http1()
			.build();

		Ok(Request {
			auth_adapter,
			client: Client::builder(TokioExecutor::new()).build(client),
			proxy_tokens,
		})
	}

	/// Execute an HTTP request with timeout wrapper
	async fn timed_request(
		&self,
		req: hyper::Request<BoxBody<Bytes, Error>>,
	) -> ClResult<hyper::Response<hyper::body::Incoming>> {
		timeout(REQUEST_TIMEOUT, self.client.request(req))
			.await
			.map_err(|_| Error::Timeout)?
			.map_err(Error::from)
	}

	/// Collect response body with timeout
	async fn collect_body(body: hyper::body::Incoming) -> ClResult<Bytes> {
		timeout(REQUEST_TIMEOUT, body.collect())
			.await
			.map_err(|_| Error::Timeout)?
			.map_err(|_| Error::NetworkError("body collection error".into()))
			.map(http_body_util::Collected::to_bytes)
	}

	// NOTE: Despite the name, this returns the **HS256 access token** the
	// remote signs back, NOT the PROXY action token (the PROXY token is a
	// short-lived bearer for the access-token endpoint only). Most callers
	// should go through `get_or_mint_proxy_token` to benefit from caching
	// and the 401-retry path.
	pub async fn create_proxy_token(
		&self,
		tn_id: TnId,
		id_tag: &str,
		subject: Option<&str>,
	) -> ClResult<Box<str>> {
		let auth_token = self
			.auth_adapter
			.create_action_token(
				tn_id,
				CreateAction {
					typ: "PROXY".into(),
					audience_tag: Some(id_tag.into()),
					expires_at: Some(Timestamp::from_now(60)), // 1 min
					..Default::default()
				},
			)
			.await?;
		let req = hyper::Request::builder()
			.method(Method::GET)
			.uri(format!(
				"https://cl-o.{}/api/auth/access-token?token={}{}",
				id_tag,
				auth_token,
				if let Some(subject) = subject {
					format!("&subject={}", subject)
				} else {
					String::new()
				}
			))
			.body(to_boxed(Empty::new()))?;
		let res = self.timed_request(req).await?;
		if !res.status().is_success() {
			return Err(Error::PermissionDenied);
		}
		let parsed: TokenRes = serde_json::from_slice(&Self::collect_body(res.into_body()).await?)?;

		Ok(parsed.data.token)
	}

	/// Returns a cached access token, minting one via `create_proxy_token`
	/// and inserting on miss. Callers that hit 401/403 should call
	/// `self.proxy_tokens.invalidate(tn_id, id_tag)` and retry once.
	async fn get_or_mint_proxy_token(&self, tn_id: TnId, id_tag: &str) -> ClResult<Box<str>> {
		if let Some(token) = self.proxy_tokens.get(tn_id, id_tag) {
			return Ok(token);
		}
		let token = self.create_proxy_token(tn_id, id_tag, None).await?;
		self.proxy_tokens.insert(tn_id, id_tag, token.clone());
		Ok(token)
	}

	pub async fn get_bin(
		&self,
		tn_id: TnId,
		id_tag: &str,
		path: &str,
		auth: bool,
	) -> ClResult<Bytes> {
		let mut attempt = 0u8;
		loop {
			let req = hyper::Request::builder()
				.method(Method::GET)
				.uri(format!("https://cl-o.{}/api{}", id_tag, path));
			let req = if auth {
				req.header(
					"Authorization",
					format!("Bearer {}", self.get_or_mint_proxy_token(tn_id, id_tag).await?),
				)
			} else {
				req
			};
			let req = req.body(to_boxed(Empty::new()))?;
			let res = self.timed_request(req).await?;
			debug!(status = %res.status(), "federated GET response");
			match res.status() {
				StatusCode::OK => return Self::collect_body(res.into_body()).await,
				StatusCode::NOT_FOUND => return Err(Error::NotFound),
				StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN if auth && attempt == 0 => {
					debug!(id_tag = %id_tag, path = %path,
						"auth rejected, refreshing cached token and retrying");
					self.proxy_tokens.invalidate(tn_id, id_tag);
					attempt += 1;
				}
				StatusCode::FORBIDDEN => return Err(Error::PermissionDenied),
				code => {
					return Err(Error::NetworkError(format!("unexpected HTTP status: {}", code)));
				}
			}
		}
	}

	//pub async fn get_stream(&self, id_tag: &str, path: &str) -> ClResult<BodyDataStream<hyper::body::Incoming>> {
	//pub async fn get_stream(&self, id_tag: &str, path: &str) -> ClResult<BodyDataStream<ClResult<Bytes>>> {
	//pub async fn get_stream(&self, id_tag: &str, path: &str) -> ClResult<impl Stream<Item = ClResult<Bytes>>> {
	//pub async fn get_stream(&self, id_tag: &str, path: &str) -> ClResult<TokioIo<BodyDataStream<hyper::body::Incoming>>> {
	//pub async fn get_stream(&self, id_tag: &str, path: &str) -> ClResult<StreamReader<BodyDataStream<hyper::body::Incoming>, Bytes>> {
	pub async fn get_stream(
		&self,
		tn_id: TnId,
		id_tag: &str,
		path: &str,
		auth: bool,
	) -> ClResult<impl AsyncRead + Send + Unpin + use<>> {
		let mut attempt = 0u8;
		loop {
			let req = hyper::Request::builder()
				.method(Method::GET)
				.uri(format!("https://cl-o.{}/api{}", id_tag, path));
			let req = if auth {
				let token = self.get_or_mint_proxy_token(tn_id, id_tag).await?;
				debug!("Got proxy token (len={})", token.len());
				req.header("Authorization", format!("Bearer {}", token))
			} else {
				req
			};
			let req = req.body(to_boxed(Empty::new()))?;
			let res = self.timed_request(req).await?;
			match res.status() {
				StatusCode::OK => {
					let stream = res.into_body().into_data_stream().map_err(std::io::Error::other);
					return Ok(tokio_util::io::StreamReader::new(stream));
				}
				StatusCode::NOT_FOUND => return Err(Error::NotFound),
				StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN if auth && attempt == 0 => {
					debug!(id_tag = %id_tag, path = %path,
						"auth rejected on stream, refreshing cached token and retrying");
					self.proxy_tokens.invalidate(tn_id, id_tag);
					attempt += 1;
				}
				StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
					return Err(Error::PermissionDenied);
				}
				code => {
					return Err(Error::NetworkError(format!("unexpected HTTP status: {}", code)));
				}
			}
		}
	}

	pub async fn get<Res>(&self, tn_id: TnId, id_tag: &str, path: &str) -> ClResult<Res>
	where
		Res: DeserializeOwned,
	{
		let res = self.get_bin(tn_id, id_tag, path, true).await?;
		let parsed: Res = serde_json::from_slice(&res)?;
		Ok(parsed)
	}

	pub async fn get_noauth<Res>(&self, tn_id: TnId, id_tag: &str, path: &str) -> ClResult<Res>
	where
		Res: DeserializeOwned,
	{
		let res = self.get_bin(tn_id, id_tag, path, false).await?;
		let parsed: Res = serde_json::from_slice(&res)?;
		Ok(parsed)
	}

	/// Make a public GET request without authentication or tenant context
	pub async fn get_public<Res>(&self, id_tag: &str, path: &str) -> ClResult<Res>
	where
		Res: DeserializeOwned,
	{
		let req = hyper::Request::builder()
			.method(Method::GET)
			.uri(format!("https://cl-o.{}/api{}", id_tag, path))
			.body(to_boxed(Empty::new()))?;
		let res = self.timed_request(req).await?;
		match res.status() {
			StatusCode::OK => {
				let bytes = Self::collect_body(res.into_body()).await?;
				let parsed: Res = serde_json::from_slice(&bytes)?;
				Ok(parsed)
			}
			StatusCode::NOT_FOUND => Err(Error::NotFound),
			StatusCode::FORBIDDEN => Err(Error::PermissionDenied),
			code => Err(Error::NetworkError(format!("unexpected HTTP status: {}", code))),
		}
	}

	/// Make a conditional GET request with If-None-Match header for etag support
	///
	/// Returns `ConditionalResult::NotModified` if server returns 304,
	/// or `ConditionalResult::Modified` with data and new etag if content changed.
	pub async fn get_conditional<Res>(
		&self,
		id_tag: &str,
		path: &str,
		etag: Option<&str>,
	) -> ClResult<ConditionalResult<Res>>
	where
		Res: DeserializeOwned,
	{
		let mut builder = hyper::Request::builder()
			.method(Method::GET)
			.uri(format!("https://cl-o.{}/api{}", id_tag, path));

		// Add If-None-Match header if we have an etag
		if let Some(etag) = etag {
			builder = builder.header("If-None-Match", etag);
		}

		let req = builder.body(to_boxed(Empty::new()))?;
		let res = self.timed_request(req).await?;

		match res.status() {
			StatusCode::NOT_MODIFIED => Ok(ConditionalResult::NotModified),
			StatusCode::OK => {
				// Extract ETag from response headers
				let new_etag = res
					.headers()
					.get("etag")
					.and_then(|v| v.to_str().ok())
					.map(|s| s.trim_matches('"').into());

				let bytes = Self::collect_body(res.into_body()).await?;
				let parsed: Res = serde_json::from_slice(&bytes)?;
				Ok(ConditionalResult::Modified { data: parsed, etag: new_etag })
			}
			StatusCode::NOT_FOUND => Err(Error::NotFound),
			StatusCode::FORBIDDEN => Err(Error::PermissionDenied),
			code => Err(Error::NetworkError(format!("unexpected HTTP status: {}", code))),
		}
	}

	/// Make a public POST request without authentication or tenant context
	pub async fn post_public<Req, Res>(&self, id_tag: &str, path: &str, data: &Req) -> ClResult<Res>
	where
		Req: Serialize,
		Res: DeserializeOwned,
	{
		let json_data = serde_json::to_vec(data)?;
		let req = hyper::Request::builder()
			.method(Method::POST)
			.uri(format!("https://cl-o.{}/api{}", id_tag, path))
			.header("Content-Type", "application/json")
			.body(to_boxed(Full::from(json_data)))?;
		let res = self.timed_request(req).await?;
		match res.status() {
			StatusCode::OK | StatusCode::CREATED => {
				let bytes = Self::collect_body(res.into_body()).await?;
				let parsed: Res = serde_json::from_slice(&bytes)?;
				Ok(parsed)
			}
			StatusCode::NOT_FOUND => Err(Error::NotFound),
			StatusCode::FORBIDDEN => Err(Error::PermissionDenied),
			StatusCode::UNPROCESSABLE_ENTITY => Err(Error::ValidationError(
				"IDP registration failed - validation error".to_string(),
			)),
			code => Err(Error::NetworkError(format!("unexpected HTTP status: {}", code))),
		}
	}

	/// Unauthenticated POST to a remote tenant.
	///
	/// Callers (e.g. IDP registration/resend, action federation inbox) authenticate
	/// via signed tokens carried in the request body, not via an `Authorization`
	/// header — `tn_id` is therefore unused at the transport layer.
	pub async fn post_bin(
		&self,
		_tn_id: TnId,
		id_tag: &str,
		path: &str,
		data: Bytes,
	) -> ClResult<Bytes> {
		let req = hyper::Request::builder()
			.method(Method::POST)
			.uri(format!("https://cl-o.{}/api{}", id_tag, path))
			.header("Content-Type", "application/json")
			.body(to_boxed(Full::from(data)))?;
		let res = self.timed_request(req).await?;
		Self::collect_body(res.into_body()).await
	}

	/// Unauthenticated streaming POST to a remote tenant. See [`Self::post_bin`]
	/// for why no `Authorization` header is attached.
	pub async fn post_stream<S>(
		&self,
		_tn_id: TnId,
		id_tag: &str,
		path: &str,
		stream: S,
	) -> ClResult<Bytes>
	where
		S: Stream<Item = Result<hyper::body::Frame<Bytes>, hyper::Error>> + Send + Sync + 'static,
	{
		let req = hyper::Request::builder()
			.method(Method::POST)
			.uri(format!("https://cl-o.{}/api{}", id_tag, path))
			.body(to_boxed(StreamBody::new(stream)))?;
		let res = self.timed_request(req).await?;
		Self::collect_body(res.into_body()).await
	}

	pub async fn post<Res>(
		&self,
		tn_id: TnId,
		id_tag: &str,
		path: &str,
		data: &impl Serialize,
	) -> ClResult<Res>
	where
		Res: DeserializeOwned,
	{
		let res = self.post_bin(tn_id, id_tag, path, serde_json::to_vec(data)?.into()).await?;
		let parsed: Res = serde_json::from_slice(&res)?;
		Ok(parsed)
	}
}

// vim: ts=4
