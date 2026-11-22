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

//! HTTP transport abstraction and platform backend.

#[cfg(not(target_arch = "wasm32"))]
mod reqwest;

use crate::compat::{MaybeSend, MaybeSync};
use crate::error::HttpError;
use futures::io::AsyncRead;
use std::future::Future;

#[cfg(not(target_arch = "wasm32"))]
pub use self::reqwest::{ReqwestClient, ReqwestResponse};

#[cfg(test)]
pub(crate) use self::mock::{MockClient, MockResponse};

/// HTTP method used by FUS requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    /// HTTP `GET` request.
    Get,
    /// HTTP `POST` request.
    Post,
}

/// Outgoing HTTP request executed by an [`HttpClient`].
pub struct HttpRequest<'a> {
    /// HTTP method (`GET` or `POST`).
    pub method: HttpMethod,
    /// Full request URL.
    pub url: &'a str,
    /// Request headers as `(name, value)` pairs.
    pub headers: &'a [(&'a str, &'a str)],
    /// Optional request body bytes.
    pub body: Option<&'a [u8]>,
}

#[cfg(test)]
impl HttpRequest<'_> {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|&&(k, _)| k.eq_ignore_ascii_case(name))
            .map(|&(_, v)| v)
    }
}

/// Response returned by an [`HttpClient`].
pub trait HttpResponse: Sized + MaybeSend {
    /// Returns the HTTP status code.
    fn status(&self) -> u16;

    /// Looks up the first response header matching `name` (case-insensitively).
    fn header(&self, name: &str) -> Option<&str>;

    /// Consumes the response body as a UTF-8 string.
    fn into_text(self) -> impl Future<Output = Result<String, HttpError>> + MaybeSend;

    /// Consumes the response body as an asynchronous byte stream.
    fn into_reader(self) -> impl AsyncRead + MaybeSend + Unpin;

    /// Returns `Ok(self)` if the status code is in `200..300`, or `Err(HttpError::Status(_))`.
    fn ensure_success(self) -> Result<Self, HttpError> {
        let status = self.status();
        if (200..300).contains(&status) {
            Ok(self)
        } else {
            Err(HttpError::Status(status))
        }
    }
}

/// Asynchronous HTTP transport backend for [`crate::FusClient`].
pub trait HttpClient: Sized + MaybeSend + MaybeSync {
    /// Response type yielded by [`HttpClient::send`].
    type Response: HttpResponse;

    /// Sends an HTTP request and resolves once the response headers are received.
    fn send(
        &self,
        request: HttpRequest<'_>,
    ) -> impl Future<Output = Result<Self::Response, HttpError>> + MaybeSend;
}

#[cfg(test)]
mod mock {
    use super::{HttpClient, HttpRequest, HttpResponse};
    use crate::error::HttpError;
    use futures::future::BoxFuture;
    use futures::io::{AsyncRead, AsyncReadExt, Cursor};
    use std::pin::Pin;
    use std::sync::Arc;

    pub(crate) struct MockResponse {
        status: u16,
        headers: Vec<(String, String)>,
        reader: Pin<Box<dyn AsyncRead + Send + Unpin>>,
    }

    impl MockResponse {
        pub(crate) fn from_reader(
            status: u16,
            reader: impl AsyncRead + Send + Unpin + 'static,
        ) -> Self {
            Self {
                status,
                headers: Vec::new(),
                reader: Box::pin(reader),
            }
        }

        pub(crate) fn with_status(status: u16, bytes: Vec<u8>) -> Self {
            Self::from_reader(status, Cursor::new(bytes))
        }

        pub(crate) fn ok_bytes(bytes: Vec<u8>) -> Self {
            Self::with_status(200, bytes)
        }

        pub(crate) fn partial_bytes(bytes: Vec<u8>) -> Self {
            Self::with_status(206, bytes)
        }

        pub(crate) fn with_header(
            mut self,
            name: impl Into<String>,
            value: impl Into<String>,
        ) -> Self {
            self.headers.push((name.into(), value.into()));
            self
        }
    }

    impl HttpResponse for MockResponse {
        fn status(&self) -> u16 {
            self.status
        }

        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }

        async fn into_text(mut self) -> Result<String, HttpError> {
            let mut s = String::new();
            self.reader
                .read_to_string(&mut s)
                .await
                .map_err(HttpError::backend)?;
            Ok(s)
        }

        fn into_reader(self) -> impl AsyncRead + Send + Unpin {
            self.reader
        }
    }

    type MockFn = dyn Fn(&HttpRequest<'_>) -> BoxFuture<'static, Result<MockResponse, HttpError>>
        + Send
        + Sync;

    pub(crate) struct MockClient(Arc<MockFn>);

    impl MockClient {
        pub(crate) fn from_handler<F>(handler: F) -> Self
        where
            F: Fn(&HttpRequest<'_>) -> BoxFuture<'static, Result<MockResponse, HttpError>>
                + Send
                + Sync
                + 'static,
        {
            Self(Arc::new(handler))
        }
    }

    impl HttpClient for MockClient {
        type Response = MockResponse;

        async fn send(&self, request: HttpRequest<'_>) -> Result<Self::Response, HttpError> {
            let handler = &self.0;
            handler(&request).await
        }
    }
}
