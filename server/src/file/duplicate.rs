//! File duplication logic for CRDT and RTDB documents.
//!
//! CRDT duplication uses `AsPrelim` to recursively deep-copy all nested Yjs shared types
//! (Y.Map, Y.Text, Y.Array, etc.), preserving their type information. This is critical for
//! apps like Calcillo whose data model relies on nested shared types — a naive `to_json()`
//! approach would flatten them into plain `Any` values, losing type information.

use crate::{crdt_adapter::CrdtUpdate, prelude::*};

/// Duplicate CRDT document content by reconstructing state and deep-copying into a fresh document.
///
/// Uses `AsPrelim` for recursive deep copy of nested Yjs shared types, preserving Y.Map,
/// Y.Text, Y.Array, Y.XmlFragment, etc. — unlike `to_json()` which flattens them into plain
/// values.
pub async fn duplicate_crdt_content(
	app: &App,
	tn_id: TnId,
	src_doc_id: &str,
	dst_doc_id: &str,
) -> ClResult<()> {
	use yrs::types::text::{Diff, YChange};
	use yrs::types::xml::{XmlFragment, XmlIn, XmlOut};
	use yrs::types::{AsPrelim, Delta};
	use yrs::updates::decoder::Decode;
	use yrs::{Array, In, Map, Out, ReadTxn, Text, Transact, Update};

	let updates = app.crdt_adapter.get_updates(tn_id, src_doc_id).await?;

	info!("CRDT duplicate: {} updates for source doc {}", updates.len(), src_doc_id);

	if updates.is_empty() {
		return Ok(());
	}

	let new_update = tokio::task::spawn_blocking(move || -> ClResult<Vec<u8>> {
		// Phase 1: Reconstruct source document state
		let src_doc = yrs::Doc::new();
		{
			let mut txn = src_doc.transact_mut();
			for update in &updates {
				if let Ok(decoded) = Update::decode_v1(&update.data) {
					if let Err(e) = txn.apply_update(decoded) {
						warn!("Failed to apply update during CRDT duplication: {}", e);
					}
				}
			}
		}

		// Phase 2: Discover root refs with correct type detection via Out variants.
		// Note: get_map/get_text/get_array don't validate types in yrs — they return Some
		// for ANY existing root ref. We must use the Out variant from root_refs() instead.
		let src_txn = src_doc.transact();

		let mut root_maps: Vec<String> = Vec::new();
		let mut root_texts: Vec<String> = Vec::new();
		let mut root_arrays: Vec<String> = Vec::new();
		let mut root_xml_fragments: Vec<String> = Vec::new();

		for (name, root_value) in src_txn.root_refs() {
			match &root_value {
				Out::YMap(_) => {
					info!("CRDT duplicate: root ref '{}' is YMap", name);
					root_maps.push(name.to_string());
				}
				Out::YText(_) => {
					info!("CRDT duplicate: root ref '{}' is YText", name);
					root_texts.push(name.to_string());
				}
				Out::YArray(_) => {
					info!("CRDT duplicate: root ref '{}' is YArray", name);
					root_arrays.push(name.to_string());
				}
				Out::YXmlFragment(_) => {
					info!("CRDT duplicate: root ref '{}' is YXmlFragment", name);
					root_xml_fragments.push(name.to_string());
				}
				Out::UndefinedRef(_) => {
					// Root refs reconstructed from Yjs binary updates often have
					// TypeRef::Undefined. Infer the actual type from content structure.
					match root_value.as_prelim(&src_txn) {
						In::Map(_) => {
							info!("CRDT duplicate: root ref '{}' inferred as Map", name);
							root_maps.push(name.to_string());
						}
						In::Array(_) => {
							info!("CRDT duplicate: root ref '{}' inferred as Array", name);
							root_arrays.push(name.to_string());
						}
						In::Text(_) => {
							info!("CRDT duplicate: root ref '{}' inferred as Text", name);
							root_texts.push(name.to_string());
						}
						In::XmlFragment(_) => {
							info!("CRDT duplicate: root ref '{}' inferred as XmlFragment", name);
							root_xml_fragments.push(name.to_string());
						}
						_ => {
							warn!("Skipping root '{}' (UndefinedRef, could not infer type)", name);
						}
					}
				}
				other => {
					warn!(
						"Skipping unsupported root type '{}' ({}) during CRDT duplication",
						name, other
					);
				}
			}
		}

		info!(
			"CRDT duplicate: found {} maps, {} texts, {} arrays, {} xml fragments",
			root_maps.len(),
			root_texts.len(),
			root_arrays.len(),
			root_xml_fragments.len()
		);

		// Phase 3: Create fresh doc and deep-copy content
		let new_doc = yrs::Doc::new();

		// Pre-create root type refs on the new doc (must be done before transaction)
		let dst_map_refs: Vec<_> = root_maps
			.iter()
			.map(|name| (name.clone(), new_doc.get_or_insert_map(name.as_str())))
			.collect();
		let dst_text_refs: Vec<_> = root_texts
			.iter()
			.map(|name| (name.clone(), new_doc.get_or_insert_text(name.as_str())))
			.collect();
		let dst_array_refs: Vec<_> = root_arrays
			.iter()
			.map(|name| (name.clone(), new_doc.get_or_insert_array(name.as_str())))
			.collect();
		let dst_xml_fragment_refs: Vec<_> = root_xml_fragments
			.iter()
			.map(|name| (name.clone(), new_doc.get_or_insert_xml_fragment(name.as_str())))
			.collect();

		// Deep-copy content in a single transaction
		{
			let mut dst_txn = new_doc.transact_mut();

			// Deep-copy maps: iterate entries and use as_prelim for recursive deep copy
			for (name, dst_map) in &dst_map_refs {
				if let Some(src_map) = src_txn.get_map(name.as_str()) {
					let mut count = 0u32;
					for (key, value) in src_map.iter(&src_txn) {
						let prelim = value.as_prelim(&src_txn);
						dst_map.insert(&mut dst_txn, key, prelim);
						count += 1;
					}
					info!("CRDT duplicate: copied {} entries from map '{}'", count, name);
				}
			}

			// Deep-copy texts: use diff() to preserve formatting and embeds
			for (name, dst_text) in &dst_text_refs {
				if let Some(src_text) = src_txn.get_text(name.as_str()) {
					let deltas: Vec<Delta<yrs::In>> = src_text
						.diff(&src_txn, YChange::identity)
						.into_iter()
						.map(|diff: Diff<YChange>| {
							Delta::Inserted(diff.insert.as_prelim(&src_txn), diff.attributes)
						})
						.collect();
					info!(
						"CRDT duplicate: copied {} delta chunks for text '{}'",
						deltas.len(),
						name
					);
					dst_text.apply_delta(&mut dst_txn, deltas);
				}
			}

			// Deep-copy arrays: iterate elements and use as_prelim for recursive deep copy
			for (name, dst_array) in &dst_array_refs {
				if let Some(src_array) = src_txn.get_array(name.as_str()) {
					let mut count = 0u32;
					for value in src_array.iter(&src_txn) {
						let prelim = value.as_prelim(&src_txn);
						dst_array.push_back(&mut dst_txn, prelim);
						count += 1;
					}
					info!("CRDT duplicate: copied {} items from array '{}'", count, name);
				}
			}

			// Deep-copy XML fragments: iterate children and use as_prelim for deep copy
			for (name, dst_frag) in &dst_xml_fragment_refs {
				if let Some(src_frag) = src_txn.get_xml_fragment(name.as_str()) {
					let mut count = 0u32;
					for child in src_frag.children(&src_txn) {
						let xml_in = match child {
							XmlOut::Element(el) => XmlIn::Element(el.as_prelim(&src_txn)),
							XmlOut::Fragment(frag) => XmlIn::Fragment(frag.as_prelim(&src_txn)),
							XmlOut::Text(txt) => XmlIn::Text(txt.as_prelim(&src_txn)),
						};
						dst_frag.push_back(&mut dst_txn, xml_in);
						count += 1;
					}
					info!("CRDT duplicate: copied {} children from xml fragment '{}'", count, name);
				}
			}
		}

		drop(src_txn);

		// Phase 4: Encode fresh state
		let sv = yrs::StateVector::default();
		let txn = new_doc.transact();
		let encoded = txn.encode_state_as_update_v1(&sv);
		info!("CRDT duplicate: encoded update size = {} bytes", encoded.len());
		Ok(encoded)
	})
	.await??;

	if !new_update.is_empty() {
		let update = CrdtUpdate::with_client(new_update, "system".to_string());
		app.crdt_adapter.store_update(tn_id, dst_doc_id, update).await?;
	}

	Ok(())
}

/// Duplicate RTDB content by exporting all documents and importing into a new database.
pub async fn duplicate_rtdb_content(
	app: &App,
	tn_id: TnId,
	src_db_id: &str,
	dst_db_id: &str,
) -> ClResult<()> {
	let docs = app.rtdb_adapter.export_all(tn_id, src_db_id).await?;

	if docs.is_empty() {
		return Ok(());
	}

	let mut tx = app.rtdb_adapter.transaction(tn_id, dst_db_id).await?;
	for (path, data) in docs {
		tx.update(&path, data).await?;
	}
	drop(tx); // Auto-commits via Drop implementation

	Ok(())
}

// vim: ts=4
