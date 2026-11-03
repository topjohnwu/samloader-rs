// Copyright 2026 John "topjohnwu" Wu
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Readers for flash inputs passed from JavaScript.

use std::future::Future;
use std::io::{self, SeekFrom};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::io::{AsyncRead, AsyncSeek, Cursor};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

const BLOB_STREAM_CHUNK_SIZE: u64 = 8 * 1024 * 1024; // 8 MiB read-ahead for sequential streaming
const BLOB_SMALL_CHUNK_SIZE: u64 = 64 * 1024; // 64 KiB read-ahead for small random-access reads

type ReadChunkFuture = Pin<Box<dyn Future<Output = io::Result<(u64, Vec<u8>)>>>>;

pub(crate) struct BlobReader {
    blob: web_sys::Blob,
    size: u64,
    pos: u64,
    sequential: u64,
    buf: Vec<u8>,
    buf_start: u64,
    pending_read: Option<ReadChunkFuture>,
}

impl BlobReader {
    fn new(blob: web_sys::Blob) -> Self {
        let size = blob.size() as u64;
        Self {
            blob,
            size,
            pos: 0,
            sequential: 0,
            buf: Vec::new(),
            buf_start: 0,
            pending_read: None,
        }
    }
}

impl AsyncSeek for BlobReader {
    fn poll_seek(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        let next_pos = match pos {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(delta) => self.size.checked_add_signed(delta),
            SeekFrom::Current(delta) => self.pos.checked_add_signed(delta),
        };

        let Some(new_pos) = next_pos else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid seek to a negative or overflowing position",
            )));
        };

        if new_pos != self.pos {
            self.pos = new_pos;
            self.sequential = 0;
            self.pending_read = None;
        }

        Poll::Ready(Ok(self.pos))
    }
}

impl AsyncRead for BlobReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if self.pos >= self.size || out.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let buf_end = self.buf_start + self.buf.len() as u64;
        if self.pos >= self.buf_start && self.pos < buf_end {
            let offset = (self.pos - self.buf_start) as usize;
            let available = self.buf.len() - offset;
            let to_copy = out.len().min(available);
            out[..to_copy].copy_from_slice(&self.buf[offset..offset + to_copy]);
            self.pos += to_copy as u64;
            self.sequential += to_copy as u64;
            return Poll::Ready(Ok(to_copy));
        }

        if self.pending_read.is_none() {
            let start = self.pos;
            let chunk_len = if self.sequential + out.len() as u64 >= BLOB_SMALL_CHUNK_SIZE {
                (out.len() as u64).max(BLOB_STREAM_CHUNK_SIZE)
            } else {
                BLOB_SMALL_CHUNK_SIZE
            };
            let end = (start + chunk_len).min(self.size);
            let slice = match self.blob.slice_with_f64_and_f64(start as f64, end as f64) {
                Ok(s) => s,
                Err(e) => {
                    return Poll::Ready(Err(io::Error::other(format!("Blob.slice failed: {e:?}"))));
                }
            };
            let promise = slice.array_buffer();
            let fut = async move {
                let ab = JsFuture::from(promise)
                    .await
                    .map_err(|e| io::Error::other(format!("Blob.arrayBuffer failed: {e:?}")))?;
                let uint8_arr = js_sys::Uint8Array::new(&ab);
                Ok((start, uint8_arr.to_vec()))
            };
            self.pending_read = Some(Box::pin(fut));
        }

        let res = match self.pending_read.as_mut().unwrap().as_mut().poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(res) => res,
        };
        self.pending_read = None;

        let (start, data) = res?;
        self.buf_start = start;
        self.buf = data;

        if self.buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let to_copy = out.len().min(self.buf.len());
        out[..to_copy].copy_from_slice(&self.buf[..to_copy]);
        self.pos += to_copy as u64;
        self.sequential += to_copy as u64;
        Poll::Ready(Ok(to_copy))
    }
}

/// A seekable reader over a `Blob`/`File` or in-memory bytes from JavaScript.
pub(crate) enum JsReader {
    Blob(BlobReader),
    Memory(Cursor<Vec<u8>>),
}

impl AsyncRead for JsReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Blob(r) => Pin::new(r).poll_read(cx, buf),
            Self::Memory(r) => Pin::new(r).poll_read(cx, buf),
        }
    }
}

impl AsyncSeek for JsReader {
    fn poll_seek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        match &mut *self {
            Self::Blob(r) => Pin::new(r).poll_seek(cx, pos),
            Self::Memory(r) => Pin::new(r).poll_seek(cx, pos),
        }
    }
}

pub(crate) fn extract_reader_from_js(val: &JsValue) -> Result<JsReader, JsValue> {
    if let Some(blob) = val.dyn_ref::<web_sys::Blob>() {
        return Ok(JsReader::Blob(BlobReader::new(blob.clone())));
    }
    if val.is_instance_of::<js_sys::Uint8Array>() {
        let uint8_arr: js_sys::Uint8Array = val.clone().unchecked_into();
        return Ok(JsReader::Memory(Cursor::new(uint8_arr.to_vec())));
    }
    if val.is_instance_of::<js_sys::ArrayBuffer>() {
        let uint8_arr = js_sys::Uint8Array::new(val);
        return Ok(JsReader::Memory(Cursor::new(uint8_arr.to_vec())));
    }
    if val.is_object() {
        let obj: &js_sys::Object = val.unchecked_ref();
        for key in ["file", "blob", "data"] {
            if let Ok(inner) = js_sys::Reflect::get(obj, &JsValue::from_str(key))
                && !inner.is_undefined()
                && !inner.is_null()
            {
                if let Some(blob) = inner.dyn_ref::<web_sys::Blob>() {
                    return Ok(JsReader::Blob(BlobReader::new(blob.clone())));
                }
                if inner.is_instance_of::<js_sys::Uint8Array>() {
                    let uint8_arr: js_sys::Uint8Array = inner.unchecked_into();
                    return Ok(JsReader::Memory(Cursor::new(uint8_arr.to_vec())));
                }
                if inner.is_instance_of::<js_sys::ArrayBuffer>() {
                    let uint8_arr = js_sys::Uint8Array::new(&inner);
                    return Ok(JsReader::Memory(Cursor::new(uint8_arr.to_vec())));
                }
            }
        }
        return Err(JsValue::from_str("Invalid file data object property"));
    }
    Err(JsValue::from_str(
        "Expected File, Blob, Uint8Array, ArrayBuffer, or file object",
    ))
}

pub(crate) fn extract_explicit_name_from_js(val: &JsValue) -> Option<String> {
    if let Some(file) = val.dyn_ref::<web_sys::File>() {
        let name = file.name();
        if !name.is_empty() {
            return Some(name);
        }
    }
    if val.is_object() {
        let obj: &js_sys::Object = val.unchecked_ref();
        if let Some(s) = js_sys::Reflect::get(obj, &JsValue::from_str("name"))
            .ok()
            .and_then(|v| v.as_string())
            .filter(|s| !s.is_empty())
        {
            return Some(s);
        }
        if let Ok(inner) = js_sys::Reflect::get(obj, &JsValue::from_str("file"))
            && let Some(file) = inner.dyn_ref::<web_sys::File>()
        {
            let name = file.name();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

pub(crate) fn extract_explicit_partition_from_js(val: &JsValue) -> Option<String> {
    if val.is_object() {
        let obj: &js_sys::Object = val.unchecked_ref();
        if let Some(s) = js_sys::Reflect::get(obj, &JsValue::from_str("partition"))
            .ok()
            .and_then(|v| v.as_string())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            return Some(s);
        }
    }
    None
}
