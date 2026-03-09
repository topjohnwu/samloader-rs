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

use crate::{auth, xml};
use md5::{Digest, Md5};
use reqwest::blocking::{Client, Response};
use reqwest::header::{AUTHORIZATION, COOKIE, HeaderMap, HeaderValue, USER_AGENT};
use std::collections::HashMap;

#[derive(Default)]
pub struct FusClient {
    client: Client,
    pub auth: String,
    pub sessid: String,
    pub nonce: String,
    pub encnonce: String,
    pub info: BinaryInform,
}

#[derive(Default)]
pub struct BinaryInform {
    pub version: String,
    pub filename: String,
    pub path: String,
    pub size: u64,
    pub key: Vec<u8>,
}

impl BinaryInform {
    fn new(mut kv: HashMap<String, String>) -> Option<BinaryInform> {
        let size: u64 = kv.get("BINARY_BYTE_SIZE")?.parse().ok()?;
        let fw_ver = kv.remove("LATEST_FW_VERSION")?;
        let logic_val = kv.remove("LOGIC_VALUE_FACTORY")?;
        let key = xml::getlogiccheck(&fw_ver, &logic_val);

        Some(Self {
            version: fw_ver,
            filename: kv.remove("BINARY_NAME").unwrap(),
            path: kv.remove("MODEL_PATH").unwrap(),
            size,
            key: Md5::digest(key.as_bytes()).to_vec(),
        })
    }
}

impl FusClient {
    pub fn new() -> Self {
        let mut client = FusClient::default();
        // Initialize nonce
        let _ = client.make_req("NF_DownloadGenerateNonce.do", "");
        client
    }

    pub fn fetch_binary_info(&mut self, model: &str, region: &str) {
        let req_xml = xml::binary_inform_req_xml(model, region);

        let xml = self
            .make_req("NF_DownloadBinaryInform.do", &req_xml)
            .expect("Info request failed");

        let kv = xml::parse_xml_data(&xml).expect("Info request invalid");

        self.info = BinaryInform::new(kv).expect("Info request invalid");
    }

    fn make_req(&mut self, path: &str, data: &str) -> Result<String, reqwest::Error> {
        let auth_header_val = format!(
            "FUS nonce=\"{}\", signature=\"{}\", nc=\"\", type=\"\", realm=\"\", newauth=\"1\"",
            self.encnonce, self.auth
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
                    let part = part.trim();
                    if part.starts_with("JSESSIONID=") || part.starts_with("JSESSIONID_SVR=") {
                        self.sessid = part.split('=').nth(1).unwrap().to_string();
                    }
                }
            }
        }

        resp.error_for_status()?.text()
    }

    pub fn init_download(&mut self) {
        let init_xml = xml::binary_init_req_xml(&self.info.filename, &self.nonce);
        self.make_req("NF_DownloadBinaryInitForMass.do", &init_xml)
            .expect("Download init failed");
    }

    pub fn download_file(
        &self,
        start: Option<u64>,
        end: Option<u64>,
    ) -> Result<Response, reqwest::Error> {
        let auth_val = format!(
            "FUS nonce=\"{}\", signature=\"{}\", nc=\"\", type=\"\", realm=\"\", newauth=\"1\"",
            self.encnonce, self.auth
        );

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_val).unwrap());
        headers.insert(USER_AGENT, HeaderValue::from_static("Kies2.0_FUS"));
        match (start, end) {
            (Some(s), Some(e)) => headers.insert(
                "Range",
                HeaderValue::from_str(&format!("bytes={}-{}", s, e)).unwrap(),
            ),
            (None, Some(e)) => headers.insert(
                "Range",
                HeaderValue::from_str(&format!("bytes=0-{}", e)).unwrap(),
            ),
            (Some(s), None) => headers.insert(
                "Range",
                HeaderValue::from_str(&format!("bytes={}-", s)).unwrap(),
            ),
            _ => None,
        };

        let url = format!(
            "http://cloud-neofussvr.samsungmobile.com/NF_DownloadBinaryForMass.do?file={}{}",
            self.info.path, self.info.filename
        );
        self.client
            .get(url)
            .headers(headers)
            .send()?
            .error_for_status()
    }
}
