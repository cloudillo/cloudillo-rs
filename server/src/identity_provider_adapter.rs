//! Adapter that manages identity registration and DNS modifications.
//!
//! The Identity Provider Adapter is responsible for handling DNS modifications
//! for identity registration. Each identity (id_tag) is associated with an email
//! address and has lifecycle timestamps.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

pub use crate::core::address::AddressType;
use crate::prelude::*;

/// Status of an identity in the registration lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityStatus {
	/// Identity is awaiting activation/validation
	Pending,
	/// Identity is active and can be used
	Active,
	/// Identity is suspended and cannot be used
	Suspended,
}

impl std::fmt::Display for IdentityStatus {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			IdentityStatus::Pending => write!(f, "pending"),
			IdentityStatus::Active => write!(f, "active"),
			IdentityStatus::Suspended => write!(f, "suspended"),
		}
	}
}

impl std::str::FromStr for IdentityStatus {
	type Err = Error;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"pending" => Ok(IdentityStatus::Pending),
			"active" => Ok(IdentityStatus::Active),
			"suspended" => Ok(IdentityStatus::Suspended),
			_ => Err(Error::ValidationError(format!("invalid identity status: {}", s))),
		}
	}
}

/// Quota tracking for identity registrations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrarQuota {
	/// The registrar's id_tag
	pub registrar_id_tag: Box<str>,
	/// Maximum number of identities this registrar can create
	pub max_identities: i32,
	/// Maximum total storage for all identities (in bytes)
	pub max_storage_bytes: i64,
	/// Current count of identities created by this registrar
	pub current_identities: i32,
	/// Current storage used by this registrar (in bytes)
	pub current_storage_bytes: i64,
	/// Timestamp when the quota was last updated
	pub updated_at: Timestamp,
}

/// Represents an identity registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
	/// Unique identifier prefix (local part) for this identity
	pub id_tag_prefix: Box<str>,
	/// Domain part of the identity (e.g., cloudillo.net)
	pub id_tag_domain: Box<str>,
	/// Email address associated with this identity
	pub email: Box<str>,
	/// ID tag of the registrar who created this identity
	pub registrar_id_tag: Box<str>,
	/// Current address (DNS record, server address, or other routing info)
	pub current_address: Option<Box<str>>,
	/// Timestamp when the address was last updated
	pub address_updated_at: Option<Timestamp>,
	/// Status of this identity in its lifecycle
	pub status: IdentityStatus,
	/// Timestamp when the identity was created
	pub created_at: Timestamp,
	/// Timestamp when the identity was last updated
	pub updated_at: Timestamp,
	/// Timestamp when the identity expires
	pub expires_at: Timestamp,
}

/// Options for creating a new identity
#[derive(Debug, Clone)]
pub struct CreateIdentityOptions<'a> {
	/// The unique identifier prefix (local part) for this identity
	pub id_tag_prefix: &'a str,
	/// The domain part of the identity identifier
	pub id_tag_domain: &'a str,
	/// Email address to associate with this identity
	pub email: &'a str,
	/// The id_tag of the registrar creating this identity
	pub registrar_id_tag: &'a str,
	/// Initial status of the identity (default: Pending)
	pub status: IdentityStatus,
	/// Initial address for this identity (optional)
	pub current_address: Option<&'a str>,
	/// When the identity should expire (optional, can have default)
	pub expires_at: Option<Timestamp>,
}

/// Options for updating an existing identity
#[derive(Debug, Clone, Default)]
pub struct UpdateIdentityOptions {
	/// New email address (if changing)
	pub email: Option<Box<str>>,
	/// New address (if changing)
	pub current_address: Option<Box<str>>,
	/// Type of the address being set (if current_address is provided)
	pub address_type: Option<AddressType>,
	/// New status (if changing)
	pub status: Option<IdentityStatus>,
	/// New expiration timestamp (if changing)
	pub expires_at: Option<Timestamp>,
}

/// Options for listing identities
#[derive(Debug, Clone, Default)]
pub struct ListIdentityOptions {
	/// Filter by email address (partial match)
	pub email: Option<String>,
	/// Filter by registrar id_tag
	pub registrar_id_tag: Option<String>,
	/// Filter by identity status
	pub status: Option<IdentityStatus>,
	/// Only include identities that expire after this timestamp
	pub expires_after: Option<Timestamp>,
	/// Only include expired identities
	pub expired_only: bool,
	/// Limit the number of results
	pub limit: Option<u32>,
	/// Offset for pagination
	pub offset: Option<u32>,
}

/// Represents an API key in the system
#[derive(Debug, Clone)]
pub struct ApiKey {
	pub id: i32,
	pub id_tag_prefix: String,
	pub id_tag_domain: String,
	pub key_prefix: String,
	pub name: Option<String>,
	pub created_at: Timestamp,
	pub last_used_at: Option<Timestamp>,
	pub expires_at: Option<Timestamp>,
}

/// Options for creating a new API key
#[derive(Debug)]
pub struct CreateApiKeyOptions<'a> {
	pub id_tag_prefix: &'a str,
	pub id_tag_domain: &'a str,
	pub name: Option<&'a str>,
	pub expires_at: Option<Timestamp>,
}

/// Result of creating a new API key - includes the plaintext key (shown only once)
#[derive(Debug)]
pub struct CreatedApiKey {
	pub api_key: ApiKey,
	pub plaintext_key: String,
}

/// Options for listing API keys
#[derive(Debug, Default)]
pub struct ListApiKeyOptions {
	pub id_tag_prefix: Option<String>,
	pub id_tag_domain: Option<String>,
	pub limit: Option<u32>,
	pub offset: Option<u32>,
}

/// A `Cloudillo` identity provider adapter
///
/// Every `IdentityProviderAdapter` implementation is required to implement this trait.
/// An `IdentityProviderAdapter` is responsible for managing identity registrations
/// and handling DNS modifications for identity registration.
#[async_trait]
pub trait IdentityProviderAdapter: Debug + Send + Sync {
	/// Creates a new identity registration
	///
	/// This method registers a new identity with the given id_tag and email address.
	/// It should also handle any necessary DNS modifications for the identity.
	///
	/// # Arguments
	/// * `opts` - Options containing id_tag, email, and optional expiration
	///
	/// # Returns
	/// The newly created `Identity` with all timestamps populated
	///
	/// # Errors
	/// Returns an error if:
	/// - The id_tag already exists
	/// - The email is invalid or already in use
	/// - DNS modifications fail
	async fn create_identity(&self, opts: CreateIdentityOptions<'_>) -> ClResult<Identity>;

	/// Reads an identity by its id_tag
	///
	/// # Arguments
	/// * `id_tag` - The unique identifier tag to look up
	///
	/// # Returns
	/// `Some(Identity)` if found, `None` otherwise
	async fn read_identity(
		&self,
		id_tag_prefix: &str,
		id_tag_domain: &str,
	) -> ClResult<Option<Identity>>;

	/// Reads an identity by its email address
	///
	/// # Arguments
	/// * `email` - The email address to look up
	///
	/// # Returns
	/// `Some(Identity)` if found, `None` otherwise
	async fn read_identity_by_email(&self, email: &str) -> ClResult<Option<Identity>>;

	/// Updates an existing identity
	///
	/// # Arguments
	/// * `id_tag` - The identifier of the identity to update
	/// * `opts` - Options containing fields to update
	///
	/// # Errors
	/// Returns an error if the identity doesn't exist or the update fails
	async fn update_identity(
		&self,
		id_tag_prefix: &str,
		id_tag_domain: &str,
		opts: UpdateIdentityOptions,
	) -> ClResult<Identity>;

	/// Updates only the address of an identity (optimized for performance)
	///
	/// This method is optimized for updating just the address and address type,
	/// avoiding unnecessary updates to other fields. Useful for frequent address updates.
	///
	/// # Arguments
	/// * `id_tag` - The identifier of the identity to update
	/// * `address` - The new address to set
	/// * `address_type` - The type of the address (IPv4, IPv6, or Hostname)
	///
	/// # Returns
	/// The updated `Identity` with the new address
	///
	/// # Errors
	/// Returns an error if the identity doesn't exist or the update fails
	async fn update_identity_address(
		&self,
		id_tag_prefix: &str,
		id_tag_domain: &str,
		address: &str,
		address_type: AddressType,
	) -> ClResult<Identity>;

	/// Deletes an identity and cleans up associated DNS records
	///
	/// # Arguments
	/// * `id_tag` - The identifier of the identity to delete
	///
	/// # Errors
	/// Returns an error if the identity doesn't exist or DNS cleanup fails
	async fn delete_identity(&self, id_tag_prefix: &str, id_tag_domain: &str) -> ClResult<()>;

	/// Lists identities matching the given criteria
	///
	/// # Arguments
	/// * `opts` - Filtering and pagination options
	///
	/// # Returns
	/// A vector of matching identities
	async fn list_identities(&self, opts: ListIdentityOptions) -> ClResult<Vec<Identity>>;

	/// Checks if an identity exists
	///
	/// # Arguments
	/// * `id_tag` - The identifier to check
	///
	/// # Returns
	/// `true` if the identity exists, `false` otherwise
	async fn identity_exists(&self, id_tag_prefix: &str, id_tag_domain: &str) -> ClResult<bool> {
		Ok(self.read_identity(id_tag_prefix, id_tag_domain).await?.is_some())
	}

	/// Cleans up expired identities
	///
	/// This method should be called periodically to remove identities that have expired.
	/// It should also clean up any associated DNS records.
	///
	/// # Returns
	/// The number of identities that were cleaned up
	async fn cleanup_expired_identities(&self) -> ClResult<u32>;

	/// Renews an identity's expiration timestamp
	///
	/// # Arguments
	/// * `id_tag` - The identifier of the identity to renew
	/// * `new_expires_at` - The new expiration timestamp
	///
	/// # Errors
	/// Returns an error if the identity doesn't exist
	async fn renew_identity(
		&self,
		id_tag_prefix: &str,
		id_tag_domain: &str,
		new_expires_at: Timestamp,
	) -> ClResult<Identity>;

	/// Creates a new API key for an identity
	///
	/// Returns the created API key with the plaintext key (shown only once)
	async fn create_api_key(&self, opts: CreateApiKeyOptions<'_>) -> ClResult<CreatedApiKey>;

	/// Verifies an API key and returns the associated identity if valid
	///
	/// Returns None if the key is invalid or expired
	/// Updates the last_used_at timestamp on successful verification
	async fn verify_api_key(&self, key: &str) -> ClResult<Option<String>>;

	/// Lists API keys with optional filtering
	///
	/// Note: Only returns metadata, not the actual keys
	async fn list_api_keys(&self, opts: ListApiKeyOptions) -> ClResult<Vec<ApiKey>>;

	/// Deletes an API key by ID
	async fn delete_api_key(&self, id: i32) -> ClResult<()>;

	/// Deletes an API key by ID, ensuring it belongs to the specified identity
	///
	/// Returns true if a key was deleted, false if no matching key was found
	async fn delete_api_key_for_identity(
		&self,
		id: i32,
		id_tag_prefix: &str,
		id_tag_domain: &str,
	) -> ClResult<bool>;

	/// Cleans up expired API keys
	///
	/// Returns the number of keys deleted
	async fn cleanup_expired_api_keys(&self) -> ClResult<u32>;

	/// Lists identities registered by a specific registrar
	///
	/// # Arguments
	/// * `registrar_id_tag` - The registrar's id_tag
	/// * `limit` - Optional limit on results
	/// * `offset` - Optional pagination offset
	///
	/// # Returns
	/// A vector of identities created by this registrar
	async fn list_identities_by_registrar(
		&self,
		registrar_id_tag: &str,
		limit: Option<u32>,
		offset: Option<u32>,
	) -> ClResult<Vec<Identity>>;

	/// Gets the quota for a specific registrar
	///
	/// # Arguments
	/// * `registrar_id_tag` - The registrar's id_tag
	///
	/// # Returns
	/// The quota information, or an error if not found
	async fn get_quota(&self, registrar_id_tag: &str) -> ClResult<RegistrarQuota>;

	/// Sets quota limits for a registrar
	///
	/// # Arguments
	/// * `registrar_id_tag` - The registrar's id_tag
	/// * `max_identities` - Maximum number of identities allowed
	/// * `max_storage_bytes` - Maximum storage in bytes
	///
	/// # Errors
	/// Returns an error if the quota doesn't exist or update fails
	async fn set_quota_limits(
		&self,
		registrar_id_tag: &str,
		max_identities: i32,
		max_storage_bytes: i64,
	) -> ClResult<RegistrarQuota>;

	/// Checks if a registrar has quota available for a new identity
	///
	/// # Arguments
	/// * `registrar_id_tag` - The registrar's id_tag
	/// * `storage_bytes` - Storage required for the new identity
	///
	/// # Returns
	/// `true` if quota is available, `false` otherwise
	async fn check_quota(&self, registrar_id_tag: &str, storage_bytes: i64) -> ClResult<bool>;

	/// Increments the quota usage for a registrar
	///
	/// # Arguments
	/// * `registrar_id_tag` - The registrar's id_tag
	/// * `storage_bytes` - Storage bytes to add
	///
	/// # Errors
	/// Returns an error if the quota doesn't exist or update fails
	async fn increment_quota(
		&self,
		registrar_id_tag: &str,
		storage_bytes: i64,
	) -> ClResult<RegistrarQuota>;

	/// Decrements the quota usage for a registrar
	///
	/// # Arguments
	/// * `registrar_id_tag` - The registrar's id_tag
	/// * `storage_bytes` - Storage bytes to subtract
	///
	/// # Errors
	/// Returns an error if the quota doesn't exist or update fails
	async fn decrement_quota(
		&self,
		registrar_id_tag: &str,
		storage_bytes: i64,
	) -> ClResult<RegistrarQuota>;

	/// Updates quota counts when an identity changes status
	///
	/// Used when an identity is activated, suspended, or deleted to adjust quota tracking.
	///
	/// # Arguments
	/// * `registrar_id_tag` - The registrar's id_tag
	/// * `old_status` - The identity's previous status
	/// * `new_status` - The identity's new status
	///
	/// # Errors
	/// Returns an error if the quota doesn't exist or update fails
	async fn update_quota_on_status_change(
		&self,
		registrar_id_tag: &str,
		old_status: IdentityStatus,
		new_status: IdentityStatus,
	) -> ClResult<RegistrarQuota>;
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_identity_structure() {
		let now = Timestamp::now();
		let identity = Identity {
			id_tag_prefix: "test_user".into(),
			id_tag_domain: "cloudillo.net".into(),
			email: "test@example.com".into(),
			registrar_id_tag: "registrar".into(),
			current_address: Some("192.168.1.1".into()),
			address_updated_at: Some(now),
			status: IdentityStatus::Active,
			created_at: now,
			updated_at: now,
			expires_at: now.add_seconds(86400), // 1 day later
		};

		assert_eq!(identity.id_tag_prefix.as_ref(), "test_user");
		assert_eq!(identity.id_tag_domain.as_ref(), "cloudillo.net");
		assert_eq!(identity.email.as_ref(), "test@example.com");
		assert_eq!(identity.registrar_id_tag.as_ref(), "registrar");
		assert_eq!(identity.status, IdentityStatus::Active);
		assert!(identity.expires_at > identity.created_at);
	}

	#[test]
	fn test_identity_status_display() {
		assert_eq!(IdentityStatus::Pending.to_string(), "pending");
		assert_eq!(IdentityStatus::Active.to_string(), "active");
		assert_eq!(IdentityStatus::Suspended.to_string(), "suspended");
	}

	#[test]
	fn test_identity_status_from_str() {
		use std::str::FromStr;
		assert_eq!(IdentityStatus::from_str("pending").unwrap(), IdentityStatus::Pending);
		assert_eq!(IdentityStatus::from_str("active").unwrap(), IdentityStatus::Active);
		assert_eq!(IdentityStatus::from_str("suspended").unwrap(), IdentityStatus::Suspended);
		assert!(IdentityStatus::from_str("invalid").is_err());
	}

	#[test]
	fn test_create_identity_options() {
		let opts = CreateIdentityOptions {
			id_tag_prefix: "test_user",
			id_tag_domain: "cloudillo.net",
			email: "test@example.com",
			registrar_id_tag: "registrar",
			status: IdentityStatus::Pending,
			current_address: Some("192.168.1.1"),
			expires_at: Some(Timestamp::now().add_seconds(86400)),
		};

		assert_eq!(opts.id_tag_prefix, "test_user");
		assert_eq!(opts.id_tag_domain, "cloudillo.net");
		assert_eq!(opts.email, "test@example.com");
		assert_eq!(opts.registrar_id_tag, "registrar");
		assert_eq!(opts.status, IdentityStatus::Pending);
		assert!(opts.expires_at.is_some());
	}

	#[test]
	fn test_registrar_quota() {
		let now = Timestamp::now();
		let quota = RegistrarQuota {
			registrar_id_tag: "registrar".into(),
			max_identities: 1000,
			max_storage_bytes: 1_000_000_000,
			current_identities: 50,
			current_storage_bytes: 50_000_000,
			updated_at: now,
		};

		assert_eq!(quota.registrar_id_tag.as_ref(), "registrar");
		assert_eq!(quota.max_identities, 1000);
		assert!(quota.current_identities < quota.max_identities);
	}
}

// vim: ts=4
