use async_trait::async_trait;
use axum::{
	body::Body,
	extract::{FromRequestParts, State},
	http::{request::Parts, response::Response, Request, header, StatusCode},
};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time};

use crate::prelude::*;
use crate::{App, auth_adapter, types};

// Extractors //
//************//

// IdTag //
//*******//
#[derive(Clone, Debug)]
pub struct IdTag(pub Box<str>);

impl IdTag {
	pub fn new(id_tag: &str) -> IdTag {
		IdTag(Box::from(id_tag))
	}
}

impl<S> FromRequestParts<S> for IdTag
where
	S: Send + Sync,
{
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, _state: &S,) -> Result<Self, Self::Rejection> {
		if let Some(id_tag) = parts.extensions.get::<IdTag>().cloned() {
			Ok(id_tag)
		} else {
			Err(Error::PermissionDenied)
		}
	}
}

// TnId //
//******//
//#[derive(Clone, Debug)]
//pub struct TnId(pub types::TnId);

impl FromRequestParts<App> for TnId

where
{
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, state: &App) -> Result<Self, Self::Rejection> {
		if let Some(id_tag) = parts.extensions.get::<IdTag>().cloned() {
			//info!("idTag: {}", &id_tag.0);
			let tn_id = state.auth_adapter.read_tn_id(&id_tag.0).await.map_err(|_| Error::PermissionDenied)?;
			//info!("tnId: {:?}", &tn_id);
			Ok(tn_id)
		} else {
			Err(Error::PermissionDenied)
		}
	}
}

// Auth //
//******//
#[derive(Debug, Clone)]
pub struct Auth(pub auth_adapter::AuthCtx);

impl<S> FromRequestParts<S> for Auth
where
	S: Send + Sync,
{
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, _state: &S,) -> Result<Self, Self::Rejection> {
		info!("Auth extractor: {:?}", &parts.extensions.get::<Auth>());
		if let Some(auth) = parts.extensions.get::<Auth>().cloned() {
			Ok(auth)
		} else {
			Err(Error::PermissionDenied)
		}
	}
}

// vim: ts=4
