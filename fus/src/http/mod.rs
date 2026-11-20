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

//! Internal HTTP transport abstraction and platform backend selection.

#[cfg(not(target_arch = "wasm32"))]
mod reqwest;

use crate::compat::{MaybeSend, MaybeSync};
use crate::error::HttpError;
use futures::io::AsyncRead;
use std::future::Future;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) use self::reqwest::ReqwestClient as PlatformClient;

#[cfg(target_arch = "wasm32")]
pub(crate) use self::wasm_stub::WasmStubClient as PlatformClient;

#[cfg(all(not(target_arch = "wasm32"), test))]
pub(crate) use self::mock::{MockClient, MockResponse};

pub(crate) enum HttpMethod {
    Get,
    Post,
}

pub(crate) struct HttpRequest<'a> {
    pub method: HttpMethod,
    pub url: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: Option<&'a [u8]>,
}

#[cfg(all(not(target_arch = "wasm32"), test))]
impl HttpRequest<'_> {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|&&(k, _)| k.eq_ignore_ascii_case(name))
            .map(|&(_, v)| v)
    }
}

pub(crate) trait HttpResponse: Sized + MaybeSend {
    fn status(&self) -> u16;
    fn header(&self, name: &str) -> Option<&str>;
    fn into_text(self) -> impl Future<Output = Result<String, HttpError>> + MaybeSend;
    fn into_reader(self) -> impl AsyncRead + MaybeSend + Unpin;

    fn ensure_success(self) -> Result<Self, HttpError> {
        let status = self.status();
        if (200..300).contains(&status) {
            Ok(self)
        } else {
            Err(HttpError::Status(status))
        }
    }
}

pub(crate) trait HttpClient: Sized + MaybeSend + MaybeSync {
    type Response: HttpResponse;

    fn send(
        &self,
        request: HttpRequest<'_>,
    ) -> impl Future<Output = Result<Self::Response, HttpError>> + MaybeSend;
}

#[cfg(target_arch = "wasm32")]
mod wasm_stub {
    use super::{HttpClient, HttpRequest, HttpResponse};
    use crate::error::HttpError;
    use futures::io::{AsyncRead, empty};
    use std::io;

    pub(crate) struct WasmStubClient;
    pub(crate) enum WasmStubResponse {}

    impl WasmStubClient {
        pub(crate) fn new() -> Result<Self, HttpError> {
            Err(HttpError::backend(io::Error::new(
                io::ErrorKind::Unsupported,
                "FUS HTTP client is not yet implemented on WebAssembly",
            )))
        }
    }

    impl HttpResponse for WasmStubResponse {
        fn status(&self) -> u16 {
            match *self {}
        }

        fn header(&self, _name: &str) -> Option<&str> {
            match *self {}
        }

        async fn into_text(self) -> Result<String, HttpError> {
            match self {}
        }

        fn into_reader(self) -> impl AsyncRead + Unpin {
            match self {}
            #[allow(unreachable_code)]
            empty()
        }
    }

    impl HttpClient for WasmStubClient {
        type Response = WasmStubResponse;

        async fn send(&self, request: HttpRequest<'_>) -> Result<Self::Response, HttpError> {
            let _ = (&request.method, request.url, request.headers, request.body);
            Err(HttpError::backend(io::Error::new(
                io::ErrorKind::Unsupported,
                "FUS HTTP client is not yet implemented on WebAssembly",
            )))
        }
    }
}

#[cfg(all(not(target_arch = "wasm32"), test))]
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
