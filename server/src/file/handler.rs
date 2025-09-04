use axum::{extract, response, body::{Body, to_bytes}, http::StatusCode, Json};
use image::ImageReader;
use serde::{Deserialize, Serialize};
use serde_json;
use std::any::Any;
use std::io::Cursor;
use std::rc::Rc;
use std::sync::Arc;

use crate::action::action;
use crate::auth_adapter::TokenData;
use crate::AppState;

//fn resize_image(orig_buf: &axum::body::Bytes, resize: (u32, u32)) -> Result<Box<[u8]>, impl std::error::Error> {
fn resize_image<'a>(orig_buf: impl AsRef<[u8]> + 'a, resize: (u32, u32)) -> Result<Box<[u8]>, image::error::ImageError> {
	print!("decoding...");
	let now = std::time::Instant::now();
	let original = ImageReader::new(Cursor::new(&orig_buf.as_ref()))
		.with_guessed_format()?
		.decode()?;
	println!(" [{:.2}ms]", now.elapsed().as_millis());

	print!("resizing...");
	let now = std::time::Instant::now();
	let resized = original.resize(200, 200, image::imageops::FilterType::Lanczos3);
	println!(" [{:.2}ms]", now.elapsed().as_millis());

	print!("writing...");
	let mut output = Cursor::new(Vec::new());
	let now = std::time::Instant::now();

	let encoder = image::codecs::avif::AvifEncoder::new_with_speed_quality(&mut output, 4, 80).with_num_threads(Some(1));
	resized.write_with_encoder(encoder)?;
	//resized.write_to(&mut output, image::ImageFormat::Avif)?;
	println!(" [{:.2}ms]", now.elapsed().as_millis());
	Ok(output.into_inner().into())
	//resized_buf
		//Ok(_) => resized_buf = Some(output.into_inner().into()),
		//Err(err) => resized_buf = None,
}

#[derive(Serialize, Deserialize)]
pub struct FileRes {
	#[serde(rename = "fileId")]
	file_id: Box<str>
}

pub async fn post_file(
	extract::State(state): extract::State<Arc<AppState>>,
	body: Body,
) -> Result<impl response::IntoResponse, StatusCode> {
	let bytes = to_bytes(body, 50000000).await.map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
	println!("{} bytes", bytes.len());

	let task = state.worker.run(move || {
		return resize_image(bytes, (1000, 1000))
	});

	let res: Result<Box<[u8]>, image::error::ImageError> = task.await;

	match res {
		Err(err) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
		Ok(resized_buf) => Ok(([
			("Content-Type", "image/avif"),
			//("Content-Length", Box::from(resized_buf.len().to_string().as_str()))
		], resized_buf))
	}
}

// vim: ts=4
