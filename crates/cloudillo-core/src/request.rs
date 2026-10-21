// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: MPL-2.0

//! Request client implementation

use futures::TryStreamExt;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::http::StatusCode;
use hyper::{Method, body::Body, body::Bytes};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncRead;
use tokio::time::timeout;

/// Default HTTP request timeout (10 seconds)
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Cap on a collected response body; blobs go through `get_stream`, not `collect_body`.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

use crate::prelude::*;
use cloudillo_types::action_types::CreateAction;
use cloudillo_types::auth_adapter::AuthAdapter;
use cloudillo_types::validation::{id_tag_to_ascii, validate_id_tag};

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

impl<T> ConditionalResult<T> {
	pub fn map<U>(self, f: impl FnOnce(T) -> U) -> ConditionalResult<U> {
		match self {
			Self::Modified { data, etag } => ConditionalResult::Modified { data: f(data), etag },
			Self::NotModified => ConditionalResult::NotModified,
		}
	}
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

	/// Validate an `id_tag` and return its A-label for URL construction.
	///
	/// `id_tag` ultimately originates from attacker-controllable action-token
	/// `iss`/`aud` fields, so without this guard a crafted value could inject a
	/// path, query, fragment, userinfo or port into the request target (SSRF /
	/// request smuggling). [`validate_id_tag`] forbids `/`, `@`, `:`, whitespace,
	/// `_` and uppercase, leaving only a canonical DNS-style name; the A-label
	/// returned here is pure LDH ASCII by construction.
	///
	/// Stored id_tags are UTS #46 U-labels, so an IDN identity must be punycoded
	/// before it goes on the wire — DNS and TLS only speak the A-label.
	fn host_for(id_tag: &str) -> ClResult<Cow<'_, str>> {
		if !validate_id_tag(id_tag) {
			return Err(Error::ValidationError(format!(
				"invalid id_tag for federation request: {id_tag}"
			)));
		}
		id_tag_to_ascii(id_tag)
	}

	/// Collect response body with timeout, capped at [`MAX_RESPONSE_BYTES`]
	async fn collect_body(body: hyper::body::Incoming) -> ClResult<Bytes> {
		timeout(REQUEST_TIMEOUT, http_body_util::Limited::new(body, MAX_RESPONSE_BYTES).collect())
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
		let host = Self::host_for(id_tag)?;
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
				host,
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

	/// A body-less GET to `uri`, with a bearer `token` and an `If-None-Match` `etag` when given.
	fn get_request(
		uri: &str,
		token: Option<&str>,
		etag: Option<&str>,
	) -> ClResult<hyper::Request<BoxBody<Bytes, Error>>> {
		let mut req = hyper::Request::builder().method(Method::GET).uri(uri);
		if let Some(token) = token {
			req = req.header("Authorization", format!("Bearer {}", token));
		}
		if let Some(etag) = etag {
			req = req.header("If-None-Match", etag);
		}
		Ok(req.body(to_boxed(Empty::new()))?)
	}

	/// Send `build(token)` with the tenant's cached proxy token; on 401/403 invalidate it and
	/// retry once with a fresh one. The last response is returned whatever its status.
	async fn send_authed(
		&self,
		tn_id: TnId,
		id_tag: &str,
		build: impl Fn(&str) -> ClResult<hyper::Request<BoxBody<Bytes, Error>>>,
	) -> ClResult<hyper::Response<hyper::body::Incoming>> {
		let mut attempt = 0u8;
		loop {
			let token = self.get_or_mint_proxy_token(tn_id, id_tag).await?;
			let res = self.timed_request(build(&token)?).await?;
			if matches!(res.status(), StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
				&& attempt == 0
			{
				debug!(id_tag = %id_tag, "auth rejected, refreshing cached token and retrying");
				self.proxy_tokens.invalidate(tn_id, id_tag);
				attempt += 1;
				continue;
			}
			return Ok(res);
		}
	}

	pub async fn get_bin(
		&self,
		tn_id: TnId,
		id_tag: &str,
		path: &str,
		auth: bool,
	) -> ClResult<Bytes> {
		let uri = format!("https://cl-o.{}/api{}", Self::host_for(id_tag)?, path);
		let res = if auth {
			self.send_authed(tn_id, id_tag, |t| Self::get_request(&uri, Some(t), None))
				.await?
		} else {
			self.timed_request(Self::get_request(&uri, None, None)?).await?
		};
		debug!(status = %res.status(), "federated GET response");
		match res.status() {
			StatusCode::OK => Self::collect_body(res.into_body()).await,
			StatusCode::NOT_FOUND => Err(Error::NotFound),
			StatusCode::GONE => Err(Error::Gone),
			StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(Error::PermissionDenied),
			code => Err(Error::NetworkError(format!("unexpected HTTP status: {}", code))),
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
		let uri = format!("https://cl-o.{}/api{}", Self::host_for(id_tag)?, path);
		let res = if auth {
			self.send_authed(tn_id, id_tag, |t| Self::get_request(&uri, Some(t), None))
				.await?
		} else {
			self.timed_request(Self::get_request(&uri, None, None)?).await?
		};
		match res.status() {
			StatusCode::OK => {
				let stream = res.into_body().into_data_stream().map_err(std::io::Error::other);
				Ok(tokio_util::io::StreamReader::new(stream))
			}
			StatusCode::NOT_FOUND => Err(Error::NotFound),
			StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(Error::PermissionDenied),
			code => Err(Error::NetworkError(format!("unexpected HTTP status: {}", code))),
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
		let host = Self::host_for(id_tag)?;
		let req = hyper::Request::builder()
			.method(Method::GET)
			.uri(format!("https://cl-o.{}/api{}", host, path))
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
		let uri = format!("https://cl-o.{}/api{}", Self::host_for(id_tag)?, path);
		let req = Self::get_request(&uri, None, etag)?;
		Self::conditional_result(self.timed_request(req).await?).await
	}

	/// [`Self::get_conditional`] with the tenant's proxy token, retried once on 401/403 with a
	/// fresh token (like [`Self::get_bin`]).
	pub async fn get_conditional_auth<Res>(
		&self,
		tn_id: TnId,
		id_tag: &str,
		path: &str,
		etag: Option<&str>,
	) -> ClResult<ConditionalResult<Res>>
	where
		Res: DeserializeOwned,
	{
		let uri = format!("https://cl-o.{}/api{}", Self::host_for(id_tag)?, path);
		let res = self
			.send_authed(tn_id, id_tag, |t| Self::get_request(&uri, Some(t), etag))
			.await?;
		Self::conditional_result(res).await
	}

	/// Map a conditional GET response: 304 → `NotModified`, 200 → body + `ETag`.
	async fn conditional_result<Res>(
		res: hyper::Response<hyper::body::Incoming>,
	) -> ClResult<ConditionalResult<Res>>
	where
		Res: DeserializeOwned,
	{
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
			StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(Error::PermissionDenied),
			code => Err(Error::NetworkError(format!("unexpected HTTP status: {}", code))),
		}
	}

	/// Make a public POST request without authentication or tenant context
	pub async fn post_public<Req, Res>(&self, id_tag: &str, path: &str, data: &Req) -> ClResult<Res>
	where
		Req: Serialize,
		Res: DeserializeOwned,
	{
		let host = Self::host_for(id_tag)?;
		let json_data = serde_json::to_vec(data)?;
		let req = hyper::Request::builder()
			.method(Method::POST)
			.uri(format!("https://cl-o.{}/api{}", host, path))
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
		let host = Self::host_for(id_tag)?;
		let req = hyper::Request::builder()
			.method(Method::POST)
			.uri(format!("https://cl-o.{}/api{}", host, path))
			.header("Content-Type", "application/json")
			.body(to_boxed(Full::from(data)))?;
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

	/// Authenticated JSON POST to a remote tenant. Mirrors [`Self::get_bin`]:
	/// attaches a cached proxy token in the `Authorization` header and retries
	/// once on 401/403 after invalidating the cached token. Branches on
	/// response status so callers see a typed `Error` (NotFound / Gone /
	/// PermissionDenied / NetworkError) instead of a downstream JSON-
	/// deserialization failure when the upstream returns an error envelope.
	///
	/// Hard-codes `Content-Type: application/json`; for binary authed POSTs
	/// add a separate helper that takes an explicit content-type parameter.
	pub async fn post_json_authed(
		&self,
		tn_id: TnId,
		id_tag: &str,
		path: &str,
		data: Bytes,
	) -> ClResult<Bytes> {
		let uri = format!("https://cl-o.{}/api{}", Self::host_for(id_tag)?, path);
		let res = self
			.send_authed(tn_id, id_tag, |token| {
				Ok(hyper::Request::builder()
					.method(Method::POST)
					.uri(&uri)
					.header("Content-Type", "application/json")
					.header("Authorization", format!("Bearer {}", token))
					.body(to_boxed(Full::from(data.clone())))?)
			})
			.await?;
		debug!(status = %res.status(), "federated POST response");
		match res.status() {
			StatusCode::NOT_FOUND => Err(Error::NotFound),
			StatusCode::GONE => Err(Error::Gone),
			StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(Error::PermissionDenied),
			// Any 2xx: the wire shape is the caller's. A `204` yields empty bytes, which
			// `post_authed` surfaces as a JSON parse error.
			code if code.is_success() => Self::collect_body(res.into_body()).await,
			code => Err(Error::NetworkError(format!("unexpected HTTP status: {}", code))),
		}
	}

	/// Typed JSON wrapper around [`Self::post_json_authed`].
	pub async fn post_authed<Res>(
		&self,
		tn_id: TnId,
		id_tag: &str,
		path: &str,
		data: &impl Serialize,
	) -> ClResult<Res>
	where
		Res: DeserializeOwned,
	{
		let res = self
			.post_json_authed(tn_id, id_tag, path, serde_json::to_vec(data)?.into())
			.await?;
		let parsed: Res = serde_json::from_slice(&res)?;
		Ok(parsed)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn host_for_accepts_valid() {
		assert_eq!(Request::host_for("alice").unwrap(), "alice");
		assert_eq!(Request::host_for("home.w9.hu").unwrap(), "home.w9.hu");
		assert_eq!(Request::host_for("user-name-123").unwrap(), "user-name-123");
	}

	#[test]
	fn host_for_punycodes_idn() {
		// Storage holds the U-label; the wire needs the A-label.
		assert_eq!(Request::host_for("münchen.example.com").unwrap(), "xn--mnchen-3ya.example.com");
	}

	#[test]
	fn host_for_rejects_url_injection() {
		// Each of these would corrupt the `https://cl-o.{id_tag}/api...` target
		// if it were allowed through.
		for bad in [
			"alice/../../etc",
			"alice/admin",
			"alice@evil.com",
			"alice:8080",
			"alice evil",
			"alice?x=1",
			"alice#frag",
			"alice_123",
			"Alice.Example.com",
			"",
		] {
			let err = Request::host_for(bad);
			assert!(matches!(err, Err(Error::ValidationError(_))), "expected reject for {bad:?}");
		}
	}
}

// vim: ts=4
