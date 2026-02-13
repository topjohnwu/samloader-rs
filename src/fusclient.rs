// Copyright 2026 Google LLC
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

use crate::auth;
use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, COOKIE, USER_AGENT};

pub struct FusClient {
    client: Client,
    pub auth: String,
    pub sessid: String,
    pub nonce: String,
    pub encnonce: String,
}

impl FusClient {
    pub fn new() -> Self {
        let mut client = FusClient {
            client: Client::new(),
            auth: String::new(),
            sessid: String::new(),
            nonce: String::new(),
            encnonce: String::new(),
        };
        // Initialize nonce
        let _ = client.makereq("NF_DownloadGenerateNonce.do", "");
        client
    }

    pub fn makereq(&mut self, path: &str, data: &str) -> Result<String, reqwest::Error> {
        let auth_header_val = format!(
            "FUS nonce=\"\", signature=\"{}\", nc=\"\", type=\"\", realm=\"\", newauth=\"1\"",
            self.auth
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_header_val).unwrap(),
        );
        headers.insert(USER_AGENT, HeaderValue::from_static("Kies2.0_FUS"));
        if !self.sessid.is_empty() {
            headers.insert(
                COOKIE,
                HeaderValue::from_str(&format!("JSESSIONID={}", self.sessid)).unwrap(),
            );
        }

        let url = format!("https://neofussvr.sslcs.cdngc.net/{}", path);
        let resp = self
            .client
            .post(&url)
            .headers(headers)
            .body(data.to_string())
            .send()?;

        if let Some(nonce_header) = resp.headers().get("NONCE") {
            let nonce_str = nonce_header.to_str().unwrap().to_string();
            self.encnonce = nonce_str;
            self.nonce = auth::decryptnonce(&self.encnonce);
            self.auth = auth::getauth(&self.nonce);
        }

        if let Some(cookie) = resp.headers().get("SET-COOKIE") {
            let cookie_str = cookie.to_str().unwrap();
            if cookie_str.contains("JSESSIONID") {
                let parts: Vec<&str> = cookie_str.split(';').collect();
                for part in parts {
                    if part.trim().starts_with("JSESSIONID=") {
                        self.sessid = part.trim().split('=').nth(1).unwrap().to_string();
                    }
                }
            }
        }

        resp.error_for_status()?.text()
    }

    pub fn downloadfile(&self, filename: &str, start: u64) -> Result<Response, reqwest::Error> {
        let auth_val = format!(
            "FUS nonce=\"{}\", signature=\"{}\", nc=\"\", type=\"\", realm=\"\", newauth=\"1\"",
            self.encnonce, self.auth
        );

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_val).unwrap());
        headers.insert(USER_AGENT, HeaderValue::from_static("Kies2.0_FUS"));
        if start > 0 {
            headers.insert(
                "Range",
                HeaderValue::from_str(&format!("bytes={}-", start)).unwrap(),
            );
        }

        let url = format!(
            "http://cloud-neofussvr.samsungmobile.com/NF_DownloadBinaryForMass.do?file={filename}"
        );
        self.client
            .get(url)
            .headers(headers)
            .send()?
            .error_for_status()
    }
}
