// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Shared, lazily built fixture: two tenants, remote identities, routers.
//!
//! Seeding is by direct adapter writes only; credentials are minted through
//! the real exchange endpoints.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{Method, Request, StatusCode, header};
use axum::{Json, Router, routing::get};
use p384::SecretKey;
use p384::elliptic_curve::Generate;
use p384::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::sync::OnceCell;
use tower::ServiceExt;
use tracing_subscriber::EnvFilter;

use cloudillo::bootstrap::{CreateCompleteTenantOptions, create_complete_tenant};
use cloudillo::error::ClResult;
use cloudillo::identity_provider_adapter::{
	AddressType, ApiKey, CreateApiKeyOptions, CreateIdentityOptions, CreatedApiKey, Identity,
	IdentityProviderAdapter, IdentityStatus, ListApiKeyOptions, ListIdentityOptions,
	RegistrarQuota, UpdateIdentityOptions,
};
use cloudillo::meta_adapter::{
	Channel, ProfileConnectionStatus, ProfileType, UpdateTenantData, UpsertProfileFields,
};
use cloudillo::settings::SettingValue;
use cloudillo::types::{Patch, Timestamp, TnId};
use cloudillo::websocket::{
	AccessQuery, WsKind, ws_bus_admission, ws_file_access, ws_prepare_store,
};
use cloudillo::{App, AppBuilder, worker};
use cloudillo_auth_adapter_sqlite::AuthAdapterSqlite;
use cloudillo_blob_adapter_fs::BlobAdapterFs;
use cloudillo_core::extract::{IdTag, OptionalAuth};
use cloudillo_crdt_adapter_redb::{AdapterConfig as CrdtConfig, CrdtAdapterRedb};
use cloudillo_meta_adapter_sqlite::MetaAdapterSqlite;
use cloudillo_rtdb_adapter_redb::{AdapterConfig as RtdbConfig, RtdbAdapterRedb};

pub const ALICE: &str = "alice.test";
pub const CLUB: &str = "club.test";
/// Personal tenant whose owner also holds `SADM` (kept apart so `alice` stays a plain owner).
pub const ADMIN: &str = "admin.test";
/// Disposable community whose trash the `DELETE /api/trash` cells may purge.
pub const TRASH: &str = "trash.test";
/// Password of every tenant owner.
pub const PASSWORD: &str = "matrix-pass-0";

/// An `idp_` key [`StubIdp`] accepts; it names alice's account.
pub const IDP_KEY: &str = "idp_zqmatrix-alice";
/// An `idp_` key naming [`IDP_IDENT`], an identity alice hosts as its IdP.
pub const IDP_IDENT_KEY: &str = "idp_zqmatrix-ident";
pub const IDP_IDENT: &str = "zqm-ident.alice.test";
/// Another identity alice hosts, registered by someone else.
pub const IDP_OTHER: &str = "zqm-other.alice.test";

/// Identities [`StubIdp`] was asked to create; a refused registration leaves it unchanged.
pub static IDP_CREATED: AtomicUsize = AtomicUsize::new(0);

fn stub() -> cloudillo::error::Error {
	cloudillo::error::Error::ServiceUnavailable("stub".into())
}

/// Identity provider that verifies [`IDP_KEY`] and [`IDP_IDENT_KEY`]; every write is refused.
#[derive(Debug)]
struct StubIdp;

#[async_trait::async_trait]
impl IdentityProviderAdapter for StubIdp {
	async fn verify_api_key(&self, key: &str) -> ClResult<Option<String>> {
		Ok(match key {
			IDP_KEY => Some(ALICE.to_owned()),
			IDP_IDENT_KEY => Some(IDP_IDENT.to_owned()),
			_ => None,
		})
	}
	async fn create_identity(&self, _: CreateIdentityOptions<'_>) -> ClResult<Identity> {
		IDP_CREATED.fetch_add(1, Ordering::Relaxed);
		Err(stub())
	}
	async fn read_identity(&self, prefix: &str, domain: &str) -> ClResult<Option<Identity>> {
		let id_tag = format!("{prefix}.{domain}");
		if id_tag != IDP_IDENT && id_tag != IDP_OTHER {
			return Ok(None);
		}
		Ok(Some(Identity {
			id_tag_prefix: prefix.into(),
			id_tag_domain: domain.into(),
			email: Some("zqm@zqm.test".into()),
			registrar_id_tag: "zqm-registrar.test".into(),
			owner_id_tag: None,
			address: None,
			address_type: None,
			address_updated_at: None,
			dyndns: false,
			lang: None,
			status: IdentityStatus::Active,
			created_at: Timestamp::now(),
			updated_at: Timestamp::now(),
			expires_at: Timestamp::from_now(86400),
		}))
	}
	async fn read_identity_by_email(&self, _: &str) -> ClResult<Option<Identity>> {
		Ok(None)
	}
	async fn update_identity(
		&self,
		_: &str,
		_: &str,
		_: UpdateIdentityOptions,
	) -> ClResult<Identity> {
		Err(stub())
	}
	async fn update_identity_address(
		&self,
		_: &str,
		_: &str,
		_: &str,
		_: AddressType,
	) -> ClResult<Identity> {
		Err(stub())
	}
	async fn delete_identity(&self, _: &str, _: &str) -> ClResult<()> {
		Err(stub())
	}
	async fn list_identities(&self, _: ListIdentityOptions) -> ClResult<Vec<Identity>> {
		Ok(Vec::new())
	}
	async fn cleanup_expired_identities(&self) -> ClResult<u32> {
		Ok(0)
	}
	async fn renew_identity(&self, _: &str, _: &str, _: Timestamp) -> ClResult<Identity> {
		Err(stub())
	}
	async fn create_api_key(&self, _: CreateApiKeyOptions<'_>) -> ClResult<CreatedApiKey> {
		Err(stub())
	}
	async fn list_api_keys(&self, _: ListApiKeyOptions) -> ClResult<Vec<ApiKey>> {
		Ok(Vec::new())
	}
	async fn delete_api_key(&self, _: i32) -> ClResult<()> {
		Err(stub())
	}
	async fn delete_api_key_for_identity(&self, _: i32, _: &str, _: &str) -> ClResult<bool> {
		Err(stub())
	}
	async fn cleanup_expired_api_keys(&self) -> ClResult<u32> {
		Ok(0)
	}
	async fn list_identities_by_registrar(
		&self,
		_: &str,
		_: Option<u32>,
		_: Option<u32>,
	) -> ClResult<Vec<Identity>> {
		Ok(Vec::new())
	}
	async fn get_quota(&self, _: &str) -> ClResult<RegistrarQuota> {
		Err(stub())
	}
	async fn set_quota_limits(&self, _: &str, _: i32, _: i64) -> ClResult<RegistrarQuota> {
		Err(stub())
	}
	async fn check_quota(&self, _: &str, _: i64) -> ClResult<bool> {
		Err(stub())
	}
	async fn increment_quota(&self, _: &str, _: i64) -> ClResult<RegistrarQuota> {
		Err(stub())
	}
	async fn decrement_quota(&self, _: &str, _: i64) -> ClResult<RegistrarQuota> {
		Err(stub())
	}
	async fn update_quota_on_status_change(
		&self,
		_: &str,
		_: IdentityStatus,
		_: IdentityStatus,
	) -> ClResult<RegistrarQuota> {
		Err(stub())
	}
}

pub struct Tenant {
	pub id_tag: &'static str,
	pub tn_id: TnId,
}

pub struct Tenants {
	/// Personal tenant.
	pub alice: Tenant,
	/// Community tenant (`typ = Community`, `profile.auto_approve_actions = true`).
	pub club: Tenant,
	/// Personal tenant, owner roles `["SADM"]`.
	pub admin: Tenant,
	/// Community (`typ = Community`); members `m_moderator`, `m_contributor`.
	pub trash: Tenant,
}

/// A remote identity with a test-generated P384 signing key.
#[derive(Clone)]
pub struct RemoteId {
	pub id_tag: String,
	pub key_id: String,
	/// PKCS8 private key PEM (with armour lines), for `EncodingKey::from_ec_pem`.
	pub pem: String,
	/// SPKI public key, base64 body only (the stored format).
	pub spki_b64: String,
}

/// Remote roster. Relations are relative to the tenant named in each comment.
pub struct Remotes {
	/// No relation anywhere.
	pub stranger: RemoteId,
	/// alice: follows alice (`follower = true`).
	pub follower: RemoteId,
	/// alice: alice follows them only (`following = true`).
	pub we_follow: RemoteId,
	/// alice: connected (both directions + `Connected`).
	pub connected: RemoteId,
	/// club: connected members with roles follower..leader.
	pub m_follower: RemoteId,
	pub m_supporter: RemoteId,
	pub m_contributor: RemoteId,
	pub m_moderator: RemoteId,
	pub m_leader: RemoteId,
	/// club: connected peer community, `hat_roles = PEER_HAT_ROLES`.
	pub peer: RemoteId,
	/// Member of `peer` (hat role `contributor` on `peer`); no direct relation to club.
	pub hatted: RemoteId,
	/// U-share grantees.
	pub g_read: RemoteId,
	pub g_comment: RemoteId,
	pub g_write: RemoteId,
	pub g_admin: RemoteId,
	pub g_folder: RemoteId,
	pub g_expired: RemoteId,
	/// Audience of Direct actions.
	pub direct: RemoteId,
	/// Holder of `SUBS` rows.
	pub subscriber: RemoteId,
}

impl Remotes {
	pub fn all(&self) -> [&RemoteId; 19] {
		[
			&self.stranger,
			&self.follower,
			&self.we_follow,
			&self.connected,
			&self.m_follower,
			&self.m_supporter,
			&self.m_contributor,
			&self.m_moderator,
			&self.m_leader,
			&self.peer,
			&self.hatted,
			&self.g_read,
			&self.g_comment,
			&self.g_write,
			&self.g_admin,
			&self.g_folder,
			&self.g_expired,
			&self.direct,
			&self.subscriber,
		]
	}
}

/// club's role map for `peer.test` members (`peer_role:local_role`).
pub const PEER_HAT_ROLES: &str = "contributor:contributor";

/// Room `(tenant, name, min_role, visibility, closed)`.
type Room = (&'static str, &'static str, Option<&'static str>, Option<char>, bool);

/// Rooms; each gets `cur-chan-{name}-*` objects.
pub const CHANNELS: [Room; 5] = [
	(CLUB, "open-contrib", Some("contributor"), Some('P'), false),
	(CLUB, "mods", Some("moderator"), Some('P'), false),
	// Secret and closed; roster = `m_contributor`.
	(CLUB, "closed-w", Some("supporter"), None, true),
	(CLUB, GONE_CHANNEL, Some("supporter"), Some('P'), false),
	(ALICE, "close-friends", Some("supporter"), Some('P'), false),
];
/// Deleted after its objects are seeded and indexed (their `channel` stays stamped).
pub const GONE_CHANNEL: &str = "gone";

pub use crate::objects::Obj;
use crate::objects::{index_all, seed_actions, seed_api_keys, seed_files, seed_proxy_site};
use crate::subjects::mint_subjects;
pub use crate::subjects::{MintCell, Subject};

pub struct Fixture {
	pub app: App,
	pub api: Router,
	/// ws probe router: `/ws/{crdt|rtdb}/{file_id}` → `{"ok": level}` / `{"deny": "..."}`;
	/// `/ws/bus` → 200 / 403.
	pub ws: Router,
	pub tenants: Tenants,
	pub objs: Vec<Obj>,
	pub subjects: Vec<Subject>,
	pub mints: Vec<MintCell>,
	/// club's hat community; signs the inbox hat-endorsement cells.
	pub peer: RemoteId,
	/// Member of `peer`; signs the hatted APRV the inbox hat-subject cell bundles.
	pub hatted: RemoteId,
	/// Key-cached identity a forged bundled subject claims to be.
	pub stranger: RemoteId,
	_tmp: TempDir,
}

impl Fixture {
	pub fn subject(&self, name: &str) -> &Subject {
		self.subjects
			.iter()
			.find(|s| s.name == name)
			.unwrap_or_else(|| panic!("subject {name}"))
	}
}

static FIXTURE: OnceCell<Fixture> = OnceCell::const_new();

pub async fn fixture() -> &'static Fixture {
	FIXTURE.get_or_init(build).await
}

async fn build() -> Fixture {
	let _ = tracing_subscriber::fmt()
		// Plain stderr bypasses libtest capture, so the per-family summary always shows.
		.with_writer(std::io::stderr)
		.with_env_filter(
			EnvFilter::try_from_default_env()
				.unwrap_or_else(|_| EnvFilter::new("off,access_matrix=info")),
		)
		.try_init();

	let tmp = tempfile::tempdir().unwrap();
	let dir = tmp.path();
	let worker = Arc::new(worker::WorkerPool::new(1, 2, 1));
	let auth = Arc::new(AuthAdapterSqlite::new(worker.clone(), &dir.join("auth")).await.unwrap());
	let meta = Arc::new(MetaAdapterSqlite::new(worker.clone(), &dir.join("meta")).await.unwrap());
	let blob = Arc::new(BlobAdapterFs::new(dir.join("blob").into()).await.unwrap());
	let crdt = Arc::new(
		CrdtAdapterRedb::new(dir.join("crdt"), true, CrdtConfig::default())
			.await
			.unwrap(),
	);
	let rtdb = Arc::new(
		RtdbAdapterRedb::new(dir.join("rtdb"), true, RtdbConfig::default())
			.await
			.unwrap(),
	);

	let mut builder = AppBuilder::new();
	builder
		.base_id_tag(ALICE)
		.base_app_domain(ALICE)
		.dist_dir(dir.join("dist"))
		.tmp_dir(dir.join("tmp"))
		.auth_adapter(auth)
		.meta_adapter(meta)
		.blob_adapter(blob)
		.crdt_adapter(crdt)
		.rtdb_adapter(rtdb)
		.idp_adapter(Arc::new(StubIdp))
		.worker(worker);
	let (app, api, _app_router, _http_router) = builder.build().await.unwrap();

	let tenants = Tenants {
		alice: tenant(&app, ALICE, None).await,
		club: tenant(&app, CLUB, None).await,
		admin: tenant(&app, ADMIN, Some(&["SADM"])).await,
		trash: tenant(&app, TRASH, None).await,
	};
	for tn in [tenants.club.tn_id, tenants.trash.tn_id] {
		app.meta_adapter
			.update_tenant(
				tn,
				&UpdateTenantData {
					typ: Patch::Value(ProfileType::Community),
					..Default::default()
				},
			)
			.await
			.unwrap();
		app.profile_me.invalidate(tn);
	}
	app.settings
		.set(
			tenants.club.tn_id,
			"profile.auto_approve_actions",
			SettingValue::Bool(true),
			&["SADM"],
		)
		.await
		.unwrap();
	// The outbox serves the newest `federation.history_sync.limit` wall actions (default 10);
	// at the protocol cap, actions other layers add do not push the seeded ones out (SE-07).
	let limit = SettingValue::Int(100);
	let key = "federation.history_sync.limit";
	app.settings.set(tenants.alice.tn_id, key, limit, &["SADM"]).await.unwrap();

	let remotes = Remotes {
		stranger: remote("stranger"),
		follower: remote("follower"),
		we_follow: remote("wefollow"),
		connected: remote("connected"),
		m_follower: remote("m-follower"),
		m_supporter: remote("m-supporter"),
		m_contributor: remote("m-contributor"),
		m_moderator: remote("m-moderator"),
		m_leader: remote("m-leader"),
		peer: remote("peer"),
		hatted: remote("hatted"),
		g_read: remote("g-read"),
		g_comment: remote("g-comment"),
		g_write: remote("g-write"),
		g_admin: remote("g-admin"),
		g_folder: remote("g-folder"),
		g_expired: remote("g-expired"),
		direct: remote("direct"),
		subscriber: remote("subscriber"),
	};
	seed_remotes(&app, &tenants, &remotes).await;
	seed_channels(&app, &tenants, &remotes).await;
	let mut objs = seed_files(&app, &tenants, &remotes).await;
	objs.extend(seed_actions(&app, &tenants, &remotes).await);
	index_all(&app, &objs).await;
	app.meta_adapter.delete_channel(tenants.club.tn_id, GONE_CHANNEL).await.unwrap();
	let api_keys = seed_api_keys(&app, &tenants).await;
	seed_proxy_site(&app).await;
	let (subjects, mints) = mint_subjects(&app, &api, &tenants, &remotes, &objs, &api_keys).await;

	let ws = ws_probe(app.clone());
	let (peer, hatted, stranger) =
		(remotes.peer.clone(), remotes.hatted.clone(), remotes.stranger.clone());
	Fixture { app, api, ws, tenants, objs, subjects, mints, peer, hatted, stranger, _tmp: tmp }
}

pub async fn tenant(app: &App, id_tag: &'static str, roles: Option<&[&str]>) -> Tenant {
	let tn_id = create_complete_tenant(
		app,
		CreateCompleteTenantOptions {
			id_tag,
			email: None,
			password: Some(PASSWORD),
			roles,
			display_name: None,
			create_acme_cert: false,
			acme_email: None,
			app_domain: None,
			initial_onboarding: None,
		},
	)
	.await
	.unwrap();
	Tenant { id_tag, tn_id }
}

pub fn remote(name: &str) -> RemoteId {
	fn body(pem: &str) -> String {
		pem.lines().filter(|l| !l.starts_with('-')).map(str::trim).collect()
	}
	let key = SecretKey::generate();
	let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
	let spki = key.public_key().to_public_key_pem(LineEnding::LF).unwrap();
	RemoteId { id_tag: format!("{name}.test"), key_id: "k1".into(), spki_b64: body(&spki), pem }
}

/// The `hats` entry seeded on alice's `connected.test` and club's `peer.test`.
const HAT_SEED: &str = "zqm-hat.test";

/// Profile row fields for a remote; every remote is `synced` so nothing is fetched.
pub fn prof(typ: ProfileType) -> UpsertProfileFields {
	UpsertProfileFields { typ: Patch::Value(typ), synced: Patch::Value(true), ..Default::default() }
}

fn linked(mut f: UpsertProfileFields) -> UpsertProfileFields {
	f.follower = Patch::Value(true);
	f.following = Patch::Value(true);
	f.connected = Patch::Value(ProfileConnectionStatus::Connected);
	f
}

async fn seed_remotes(app: &App, t: &Tenants, r: &Remotes) {
	let meta = &app.meta_adapter;
	// Baseline: every remote known (synced, no relation) on every tenant, key cached.
	for id in r.all() {
		let typ =
			if id.id_tag == r.peer.id_tag { ProfileType::Community } else { ProfileType::Person };
		meta.add_profile_public_key(&id.id_tag, &id.key_id, &id.spki_b64, None)
			.await
			.unwrap();
		for tn in [&t.alice, &t.club, &t.admin, &t.trash] {
			let mut f = prof(typ);
			f.name = Patch::Value(id.id_tag.clone().into());
			meta.upsert_profile(tn.tn_id, &id.id_tag, &f).await.unwrap();
		}
	}

	// alice relations.
	let alice = t.alice.tn_id;
	let mut f = prof(ProfileType::Person);
	f.follower = Patch::Value(true);
	meta.upsert_profile(alice, &r.follower.id_tag, &f).await.unwrap();
	let mut f = prof(ProfileType::Person);
	f.following = Patch::Value(true);
	meta.upsert_profile(alice, &r.we_follow.id_tag, &f).await.unwrap();
	// `hats` is the tenant account's alone: seeded so a leak shows.
	let mut f = linked(prof(ProfileType::Person));
	f.hats = Patch::Value(vec![HAT_SEED.into()]);
	meta.upsert_profile(alice, &r.connected.id_tag, &f).await.unwrap();

	// club members.
	let club = t.club.tn_id;
	for (id, role) in [
		(&r.m_follower, "follower"),
		(&r.m_supporter, "supporter"),
		(&r.m_contributor, "contributor"),
		(&r.m_moderator, "moderator"),
		(&r.m_leader, "leader"),
	] {
		let mut f = linked(prof(ProfileType::Person));
		f.roles = Patch::Value(Some(vec![role.into()]));
		meta.upsert_profile(club, &id.id_tag, &f).await.unwrap();
	}

	// trash members.
	for (id, role) in [(&r.m_moderator, "moderator"), (&r.m_contributor, "contributor")] {
		let mut f = linked(prof(ProfileType::Person));
		f.roles = Patch::Value(Some(vec![role.into()]));
		meta.upsert_profile(t.trash.tn_id, &id.id_tag, &f).await.unwrap();
	}

	// club ↔ peer community, with a hat map for peer's members.
	let mut f = linked(prof(ProfileType::Community));
	f.hat_roles = Patch::Value(Some(PEER_HAT_ROLES.into()));
	f.hats = Patch::Value(vec![HAT_SEED.into()]);
	meta.upsert_profile(club, &r.peer.id_tag, &f).await.unwrap();
}

async fn seed_channels(app: &App, t: &Tenants, r: &Remotes) {
	let meta = &app.meta_adapter;
	for (tn, name, min_role, visibility, closed) in CHANNELS {
		let tn_id = if tn == CLUB { t.club.tn_id } else { t.alice.tn_id };
		let ch = Channel {
			name: name.into(),
			title: None,
			descr: None,
			visibility,
			min_role: min_role.map(Into::into),
			closed,
			created_at: Timestamp::now(),
			updated_at: Timestamp::now(),
		};
		meta.create_channel(tn_id, &ch).await.unwrap();
	}
	meta.add_channel_member(t.club.tn_id, "closed-w", &r.m_contributor.id_tag)
		.await
		.unwrap();
}

/// ES384-sign any claims (action tokens, PROXY tokens) with a remote's key.
pub fn sign<T: serde::Serialize>(r: &RemoteId, claims: &T) -> String {
	jsonwebtoken::encode(
		&jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES384),
		claims,
		&jsonwebtoken::EncodingKey::from_ec_pem(r.pem.as_bytes()).unwrap(),
	)
	.unwrap()
}

static NEXT_NET: AtomicU32 = AtomicU32::new(1);

/// Build a request as the real server would hand it to `api_router`: `IdTag(tenant)` plus a
/// `ConnectInfo` from a fresh IPv6 /48 (rate limiting keys by /64 and /48).
pub fn req(
	tenant: &str,
	method: Method,
	uri: &str,
	bearer: Option<&str>,
	body: Body,
) -> Request<Body> {
	let n = NEXT_NET.fetch_add(1, Ordering::Relaxed);
	#[allow(clippy::cast_possible_truncation)]
	let ip = Ipv6Addr::new(0xfd00, (n >> 16) as u16, n as u16, 0, 0, 0, 0, 1);
	let mut b = Request::builder()
		.method(method)
		.uri(uri)
		.header(header::CONTENT_TYPE, "application/json");
	if let Some(tok) = bearer {
		b = b.header(header::AUTHORIZATION, format!("Bearer {tok}"));
	}
	let mut r = b.body(body).unwrap();
	r.extensions_mut().insert(IdTag(tenant.into()));
	r.extensions_mut().insert(ConnectInfo(SocketAddr::new(IpAddr::V6(ip), 443)));
	r
}

/// Send one request; body parsed as JSON (`Null` if empty, `String` if not JSON).
pub async fn call(router: &Router, req: Request<Body>) -> (StatusCode, Value) {
	let res = router.clone().oneshot(req).await.unwrap();
	let status = res.status();
	let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
	let body = if bytes.is_empty() {
		Value::Null
	} else {
		serde_json::from_slice(&bytes)
			.unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
	};
	(status, body)
}

/// First string value under `key`, searched depth-first.
pub fn find_str(v: &Value, key: &str) -> Option<String> {
	match v {
		Value::Object(m) => m
			.get(key)
			.and_then(Value::as_str)
			.map(str::to_owned)
			.or_else(|| m.values().find_map(|c| find_str(c, key))),
		Value::Array(a) => a.iter().find_map(|c| find_str(c, key)),
		_ => None,
	}
}

fn ws_probe(app: App) -> Router {
	Router::new()
		.route("/ws/{kind}/{id}", get(ws_probe_handler))
		.route("/ws/bus", get(ws_bus_probe))
		.route_layer(axum::middleware::from_fn_with_state(
			app.clone(),
			cloudillo_core::middleware::optional_auth,
		))
		.with_state(app)
}

/// `get_ws_bus`'s pre-upgrade decision.
async fn ws_bus_probe(IdTag(tenant): IdTag, OptionalAuth(auth): OptionalAuth) -> StatusCode {
	let admitted = auth.as_ref().is_some_and(|a| ws_bus_admission(a, &tenant));
	if admitted { StatusCode::OK } else { StatusCode::FORBIDDEN }
}

async fn ws_probe_handler(
	State(app): State<App>,
	tn_id: TnId,
	IdTag(id_tag): IdTag,
	OptionalAuth(auth): OptionalAuth,
	Path((kind, id)): Path<(String, String)>,
	Query(query): Query<AccessQuery>,
) -> (StatusCode, Json<Value>) {
	let kind = match kind.as_str() {
		"crdt" => WsKind::Crdt,
		"rtdb" => WsKind::Rtdb,
		_ => return (StatusCode::NOT_FOUND, Json(json!({ "deny": "bad_kind" }))),
	};
	if let Err(deny) = ws_prepare_store(&app, tn_id, auth.as_ref(), &id, kind).await {
		return (StatusCode::OK, Json(json!({ "deny": deny.to_string() })));
	}
	match ws_file_access(&app, tn_id, &id_tag, auth.as_ref(), &id, &query, kind).await {
		Ok((level, _)) => (StatusCode::OK, Json(json!({ "ok": level }))),
		Err(deny) => (StatusCode::OK, Json(json!({ "deny": deny.to_string() }))),
	}
}

// vim: ts=4
