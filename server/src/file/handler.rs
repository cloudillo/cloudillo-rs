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
use crate::worker::{Task, run};

#[derive(Default, Debug)]
struct ImageResizeTask {
    orig_buf: axum::body::Bytes,
	resize: (u32, u32),
	resized_buf: Option<Box<[u8]>>
	//resized_buf: Result<Box<[u8]>, ()>>,
}

impl Task for ImageResizeTask {
    fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
		println!("decoding...");
		let original = ImageReader::new(Cursor::new(&self.orig_buf))
			.with_guessed_format().unwrap()
			.decode().unwrap();

		print!("resizing...");
		let now = std::time::Instant::now();
		let resized = original.resize(1000, 1000, image::imageops::FilterType::Lanczos3);
		println!(" [{:.2}ms]", now.elapsed().as_millis());

		print!("writing...");
		let mut output = Cursor::new(Vec::new());
		let now = std::time::Instant::now();
		match resized.write_to(&mut output, image::ImageFormat::Avif)
			.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR) {
			Ok(_) => self.resized_buf = Some(output.into_inner().into()),
			Err(err) => self.resized_buf = None,
			//Err(err) => self.resized_buf = Err(err),
		}
		println!(" [{:.2}ms]", now.elapsed().as_millis());
        Ok(())
    }
	fn into_any(self: Box<Self>) -> Box<dyn Any> { self }
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

    if let Ok(task) = run(Box::new(ImageResizeTask {
		orig_buf: bytes,
		resize: (1000, 1000),
		..Default::default()
	})).await {
		Ok(([
			("Content-Type", "image/avif"),
			//("Content-Length", Box::from(output.get_ref().len().to_string().as_str()))
		], task.resized_buf.unwrap()))
    } else {
        Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

// vim: ts=4
