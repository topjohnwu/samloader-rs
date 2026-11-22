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

//! Native HTTP client backend backed by `reqwest`.

use super::{HttpClient, HttpMethod, HttpRequest, HttpResponse};
use crate::error::HttpError;
use futures::io::AsyncRead;
use futures::stream::TryStreamExt;
use reqwest::header::CONTENT_LENGTH;
use std::io;
use std::time::Duration;

/// Native [`HttpClient`] implementation backed by `reqwest`.
pub struct ReqwestClient(reqwest::Client);

/// Response returned by [`ReqwestClient`].
pub struct ReqwestResponse(reqwest::Response);

impl HttpResponse for ReqwestResponse {
    fn status(&self) -> u16 {
        self.0.status().as_u16()
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.0.headers().get(name).and_then(|v| v.to_str().ok())
    }

    async fn into_text(self) -> Result<String, HttpError> {
        self.0.text().await.map_err(HttpError::backend)
    }

    fn into_reader(self) -> impl AsyncRead + Send + Unpin {
        self.0
            .bytes_stream()
            .map_err(io::Error::other)
            .into_async_read()
    }
}

impl ReqwestClient {
    /// Creates a new `ReqwestClient` configured with a cookie store and FUS timeouts.
    pub fn new() -> Result<Self, HttpError> {
        let client = reqwest::Client::builder()
            .cookie_store(true)
            // `read_timeout` resets on every body chunk read rather than capping
            // the total download duration, flagging stalled connections after 30s
            // so the caller's retry loop can resume.
            .read_timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(15))
            .build()
            .map_err(HttpError::backend)?;
        Ok(Self(client))
    }
}

impl HttpClient for ReqwestClient {
    type Response = ReqwestResponse;

    async fn send(&self, request: HttpRequest<'_>) -> Result<Self::Response, HttpError> {
        let mut builder = match request.method {
            HttpMethod::Get => self.0.get(request.url),
            HttpMethod::Post => self.0.post(request.url),
        };
        for &(name, value) in request.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = request.body {
            // Hyper omits `Content-Length` on empty POST bodies unless set
            // explicitly, which FUS rejects with `411 Length Required`.
            builder = builder
                .header(CONTENT_LENGTH, body.len())
                .body(body.to_vec());
        }

        let resp = builder.send().await.map_err(HttpError::backend)?;
        Ok(ReqwestResponse(resp))
    }
}
