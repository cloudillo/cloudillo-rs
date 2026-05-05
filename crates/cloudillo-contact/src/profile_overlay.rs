// SPDX-FileCopyrightText: Szilárd Hajba
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Smart profile merge — fills contact gaps from a linked Cloudillo profile.
//!
//! Applied at two points:
//! - **Write path**: before vCard generation, so external CardDAV clients see a populated
//!   snapshot even if the web JSON input was sparse.
//! - **Read path (JSON only)**: against the *current* live profile, so REST responses stay
//!   fresh without touching the stored vCard blob (which would break CardDAV ETag stability).
//!
//! Explicit contact-level values always win; we only fill fields the contact left empty.

use cloudillo_core::App;
use cloudillo_types::{
	meta_adapter::{Profile, ProfileConnectionStatus, ProfileType},
	prelude::*,
};

use crate::types::{ContactInput, ContactName, ProfileOverlay};

/// Fetch a profile by id_tag, returning `None` on NotFound (which is fine — the link is a
/// hint, not a FK). Other errors bubble up.
pub async fn resolve_profile(
	app: &App,
	tn_id: TnId,
	id_tag: &str,
) -> ClResult<Option<Profile<Box<str>>>> {
	match app.meta_adapter.read_profile(tn_id, id_tag).await {
		Ok((_etag, profile)) => Ok(Some(profile)),
		Err(Error::NotFound) => Ok(None),
		Err(e) => Err(e),
	}
}

/// Build the public file URL for a profile's picture, or `None` if the profile has no pic.
/// URL scheme: `https://cl-o.{idTag}/api/files/{file_id}?variant=vis.sd`.
///
/// Note the `@` in `idTag` (e.g. `alice@example.com`) makes the authority technically
/// `userinfo@host` per RFC 3986, but this is Cloudillo's documented URL scheme — the
/// server config and cert provisioning assume it. Don't "fix" this by URL-encoding the
/// `@`; CardDAV clients store the raw URL in the vCard PHOTO property and some are
/// lenient enough to accept it as-is.
///
/// `vis.sd` (640 px) is the right size for vCard `PHOTO`: vCard 3.0/4.0 PHOTO is
/// single-valued (no srcset/conneg in CardDAV), and 640 px covers retina contact-detail
/// views in Apple Contacts (~512 px), Android Contacts (~300 px), and Thunderbird
/// without bloating the address-book DB on every sync.
///
/// The file ID is percent-encoded to keep the URL well-formed against future file-ID
/// formats that could introduce reserved characters.
fn profile_pic_url(id_tag: &str, profile_pic: Option<&str>) -> Option<String> {
	let pic = profile_pic?;
	let encoded_pic = cloudillo_dav::urlencode_path(pic);
	Some(format!("https://cl-o.{id_tag}/api/files/{encoded_pic}?variant=vis.sd"))
}

/// Split a display name into (given, family) — naive whitespace split. Only used when the
/// profile is a person and the contact has no N property at all.
fn split_name(name: &str) -> (Option<String>, Option<String>) {
	let trimmed = name.trim();
	if trimmed.is_empty() {
		return (None, None);
	}
	match trimmed.rsplit_once(char::is_whitespace) {
		Some((given, family)) => (Some(given.to_string()), Some(family.to_string())),
		None => (Some(trimmed.to_string()), None),
	}
}

/// Fill missing fields in `input` from the live profile. No-op when `input.profile_id_tag`
/// is unset or `profile` is `None`.
pub fn merge_profile_into_input(input: &mut ContactInput, profile: Option<&Profile<Box<str>>>) {
	let Some(profile) = profile else { return };
	if input.profile_id_tag.as_deref() != Some(profile.id_tag.as_ref()) {
		return;
	}

	if input.formatted_name.as_deref().is_none_or(str::is_empty) {
		input.formatted_name = Some(profile.name.to_string());
	}

	if input.n.is_none() && matches!(profile.typ, ProfileType::Person) {
		let (given, family) = split_name(profile.name.as_ref());
		if given.is_some() || family.is_some() {
			input.n = Some(ContactName { given, family, ..Default::default() });
		}
	}

	if input.photo.as_deref().is_none_or(str::is_empty)
		&& let Some(url) = profile_pic_url(profile.id_tag.as_ref(), profile.profile_pic.as_deref())
	{
		input.photo = Some(url);
	}
}

/// Build a `ProfileOverlay` object for the JSON response, combining live profile state with
/// the same derived fields that drive the smart merge.
pub fn build_overlay(profile: &Profile<Box<str>>) -> ProfileOverlay {
	let r#type = match profile.typ {
		ProfileType::Person => "person",
		ProfileType::Community => "community",
	};
	ProfileOverlay {
		id_tag: profile.id_tag.to_string(),
		name: Some(profile.name.to_string()),
		r#type: Some(r#type.to_string()),
		profile_pic: profile_pic_url(profile.id_tag.as_ref(), profile.profile_pic.as_deref()),
		status: profile.status,
		connected: Some(matches!(profile.connected, ProfileConnectionStatus::Connected)),
		following: Some(profile.following),
	}
}

// Tests
//*******

#[cfg(test)]
mod tests {
	use super::*;

	fn profile(name: &str, pic: Option<&str>) -> Profile<Box<str>> {
		Profile {
			id_tag: "alice@example.com".into(),
			name: name.into(),
			typ: ProfileType::Person,
			profile_pic: pic.map(Into::into),
			status: None,
			synced_at: None,
			following: true,
			connected: ProfileConnectionStatus::Connected,
			roles: None,
			trust: None,
		}
	}

	#[test]
	fn fills_missing_fn_and_photo() {
		let mut input =
			ContactInput { profile_id_tag: Some("alice@example.com".into()), ..Default::default() };
		merge_profile_into_input(&mut input, Some(&profile("Alice Doe", Some("f1~abc"))));
		assert_eq!(input.formatted_name.as_deref(), Some("Alice Doe"));
		assert_eq!(
			input.photo.as_deref(),
			Some("https://cl-o.alice@example.com/api/files/f1~abc?variant=vis.sd"),
		);
		let n = input.n.expect("N filled from name split");
		assert_eq!(n.given.as_deref(), Some("Alice"));
		assert_eq!(n.family.as_deref(), Some("Doe"));
	}

	#[test]
	fn explicit_values_win() {
		let mut input = ContactInput {
			profile_id_tag: Some("alice@example.com".into()),
			formatted_name: Some("Alice At Work".into()),
			photo: Some("https://custom.example/photo.jpg".into()),
			..Default::default()
		};
		merge_profile_into_input(&mut input, Some(&profile("Alice Doe", Some("f1~abc"))));
		assert_eq!(input.formatted_name.as_deref(), Some("Alice At Work"));
		assert_eq!(input.photo.as_deref(), Some("https://custom.example/photo.jpg"));
	}

	#[test]
	fn no_merge_without_profile() {
		let mut input =
			ContactInput { profile_id_tag: Some("alice@example.com".into()), ..Default::default() };
		merge_profile_into_input(&mut input, None);
		assert!(input.formatted_name.is_none());
	}

	#[test]
	fn no_merge_when_id_tag_mismatches() {
		let mut input =
			ContactInput { profile_id_tag: Some("bob@example.com".into()), ..Default::default() };
		merge_profile_into_input(&mut input, Some(&profile("Alice Doe", None)));
		assert!(input.formatted_name.is_none());
	}
}

// vim: ts=4
