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

mod reqwest;

use crate::error::HttpError;
use futures::io::AsyncRead;
use std::future::Future;

pub(crate) use self::reqwest::ReqwestClient as PlatformClient;

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

pub(crate) trait HttpResponse: Sized + Send {
    fn status(&self) -> u16;
    fn header(&self, name: &str) -> Option<&str>;
    fn into_text(self) -> impl Future<Output = Result<String, HttpError>> + Send;
    fn into_reader(self) -> impl AsyncRead + Send + Unpin;

    fn ensure_success(self) -> Result<Self, HttpError> {
        let status = self.status();
        if (200..300).contains(&status) {
            Ok(self)
        } else {
            Err(HttpError::Status(status))
        }
    }
}

pub(crate) trait HttpClient: Sized + Send + Sync {
    type Response: HttpResponse;

    fn new() -> Result<Self, HttpError>;

    fn send(
        &self,
        request: HttpRequest<'_>,
    ) -> impl Future<Output = Result<Self::Response, HttpError>> + Send;
}
