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

//! `samloader-fus` [`HttpClient`] implementation backed by a JavaScript transport callback.

use futures::future::{Either, select};
use futures::io::{AsyncRead, AsyncReadExt, Cursor};
use futures::stream::{TryStreamExt, try_unfold};
use futures_timer::Delay;
use samloader_fus::{HttpClient, HttpError, HttpMethod, HttpRequest, HttpResponse};
use std::io;
use std::pin::Pin;
use std::time::Duration;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[wasm_bindgen]
extern "C" {
    type JsFetchHandle;

    #[wasm_bindgen(structural, method, getter)]
    fn response(this: &JsFetchHandle) -> JsValue;

    #[wasm_bindgen(structural, method, getter)]
    fn abort(this: &JsFetchHandle) -> JsValue;

    type JsFetchResponse;

    #[wasm_bindgen(structural, method, getter)]
    fn status(this: &JsFetchResponse) -> Option<f64>;

    #[wasm_bindgen(structural, method, getter)]
    fn headers(this: &JsFetchResponse) -> JsValue;

    #[wasm_bindgen(structural, method, getter)]
    fn body(this: &JsFetchResponse) -> JsValue;

    #[wasm_bindgen(structural, method, getter)]
    fn next(this: &JsFetchResponse) -> JsValue;
}

#[derive(Debug)]
struct JsTransportError(String);

impl From<JsValue> for JsTransportError {
    fn from(e: JsValue) -> Self {
        Self(crate::js_err_string(&e))
    }
}

impl std::fmt::Display for JsTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for JsTransportError {}

fn js_backend_err(err: JsValue) -> HttpError {
    HttpError::backend(JsTransportError::from(err))
}

struct AbortOnDrop(Option<js_sys::Function>);

impl AbortOnDrop {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(abort) = self.0.take() {
            let _ = abort.call0(&JsValue::NULL);
        }
    }
}

struct StreamState {
    next: js_sys::Function,
    abort: AbortOnDrop,
}

fn js_chunk_to_vec(val: JsValue) -> io::Result<Option<Vec<u8>>> {
    crate::js_value_to_bytes(val).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "FUS HTTP stream yielded non-byte chunk",
        )
    })
}

async fn next_stream_chunk(mut state: StreamState) -> io::Result<Option<(Vec<u8>, StreamState)>> {
    loop {
        let raw = state
            .next
            .call0(&JsValue::NULL)
            .map_err(|e| io::Error::other(JsTransportError::from(e)))?;

        // Fast path: prefetched chunk or EOF returned synchronously without a Promise/timer.
        let val = match raw.dyn_into::<js_sys::Promise>() {
            Ok(promise) => {
                match select(JsFuture::from(promise), Delay::new(READ_IDLE_TIMEOUT)).await {
                    Either::Left((Ok(v), _)) => v,
                    Either::Left((Err(e), _)) => {
                        return Err(io::Error::other(JsTransportError::from(e)));
                    }
                    Either::Right(((), _)) => {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "FUS HTTP body read timed out after 30s",
                        ));
                    }
                }
            }
            Err(val) => val,
        };

        match js_chunk_to_vec(val)? {
            None => {
                state.abort.disarm();
                return Ok(None);
            }
            Some(bytes) if bytes.is_empty() => continue,
            Some(bytes) => return Ok(Some((bytes, state))),
        }
    }
}

/// [`HttpClient`] backed by a JS transport callback:
/// `(method, url, headers, body) => { response: Promise<{ status, headers, body?, next? }>, abort() }`.
pub(crate) struct JsHttpClient(js_sys::Function);

impl JsHttpClient {
    pub(crate) fn new(transport: js_sys::Function) -> Self {
        Self(transport)
    }
}

enum JsBody {
    Bytes(Vec<u8>),
    Stream(StreamState),
}

pub(crate) struct JsHttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: JsBody,
}

impl HttpResponse for JsHttpResponse {
    fn status(&self) -> u16 {
        self.status
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    async fn into_text(self) -> Result<String, HttpError> {
        let bytes = match self.body {
            JsBody::Bytes(bytes) => bytes,
            JsBody::Stream(_) => {
                let mut bytes = Vec::new();
                self.into_reader()
                    .read_to_end(&mut bytes)
                    .await
                    .map_err(HttpError::backend)?;
                bytes
            }
        };
        String::from_utf8(bytes).map_err(HttpError::backend)
    }

    fn into_reader(self) -> impl AsyncRead + Unpin {
        let reader: Pin<Box<dyn AsyncRead + Unpin>> = match self.body {
            JsBody::Bytes(bytes) => Box::pin(Cursor::new(bytes)),
            JsBody::Stream(state) => {
                let stream = Box::pin(try_unfold(state, next_stream_chunk));
                Box::pin(stream.into_async_read())
            }
        };
        reader
    }
}

fn parse_headers(val: &JsValue) -> Vec<(String, String)> {
    let Some(arr) = val.dyn_ref::<js_sys::Array>() else {
        return Vec::new();
    };
    let mut headers = Vec::with_capacity((arr.length() as usize).min(1024));
    for entry in arr.iter() {
        if let Some(pair) = entry.dyn_ref::<js_sys::Array>()
            && pair.length() >= 2
            && let (Some(k), Some(v)) = (pair.get(0).as_string(), pair.get(1).as_string())
        {
            headers.push((k, v));
        }
    }
    headers
}

impl HttpClient for JsHttpClient {
    type Response = JsHttpResponse;

    async fn send(&self, request: HttpRequest<'_>) -> Result<Self::Response, HttpError> {
        let method = match request.method {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
        };
        let headers_js = js_sys::Array::new();
        for &(name, value) in request.headers {
            headers_js.push(&js_sys::Array::of2(&name.into(), &value.into()));
        }
        let body_js = request
            .body
            .map_or(JsValue::NULL, |b| js_sys::Uint8Array::from(b).into());

        let args = js_sys::Array::of4(&method.into(), &request.url.into(), &headers_js, &body_js);
        let handle_val = self
            .0
            .apply(&JsValue::NULL, &args)
            .map_err(js_backend_err)?;
        if handle_val.is_null() || !handle_val.is_object() {
            return Err(HttpError::backend(io::Error::new(
                io::ErrorKind::InvalidData,
                "FUS HTTP transport returned invalid handle",
            )));
        }
        let handle: JsFetchHandle = handle_val.unchecked_into();
        let mut abort = AbortOnDrop(handle.abort().dyn_into::<js_sys::Function>().ok());
        let promise = js_sys::Promise::resolve(&handle.response());

        let resp_val = match select(JsFuture::from(promise), Delay::new(CONNECT_TIMEOUT)).await {
            Either::Left((Ok(val), _)) => val,
            Either::Left((Err(err), _)) => return Err(js_backend_err(err)),
            Either::Right(((), _)) => {
                return Err(HttpError::backend(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "FUS HTTP request connect timed out after 15s",
                )));
            }
        };
        if resp_val.is_null() || !resp_val.is_object() {
            return Err(HttpError::backend(io::Error::new(
                io::ErrorKind::InvalidData,
                "FUS HTTP transport returned non-object response",
            )));
        }
        let resp: JsFetchResponse = resp_val.unchecked_into();

        let status = resp
            .status()
            .filter(|n| n.is_finite() && n.fract() == 0.0 && (100.0..=599.0).contains(n))
            .map(|n| n as u16)
            .ok_or_else(|| {
                HttpError::backend(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "FUS HTTP response is missing valid numeric status (100-599)",
                ))
            })?;

        let headers = parse_headers(&resp.headers());
        let next_val = resp.next();
        let body = if let Ok(next) = next_val.dyn_into::<js_sys::Function>() {
            JsBody::Stream(StreamState { next, abort })
        } else {
            abort.disarm();
            let bytes = js_chunk_to_vec(resp.body())
                .map_err(HttpError::backend)?
                .unwrap_or_default();
            JsBody::Bytes(bytes)
        };

        Ok(JsHttpResponse {
            status,
            headers,
            body,
        })
    }
}
