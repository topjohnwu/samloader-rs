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
use reqwest::blocking::{Client, Response};
use reqwest::header::{AUTHORIZATION, COOKIE, HeaderMap, HeaderValue, RANGE, USER_AGENT};
use xml::BinaryInform;

pub struct FusClient {
    client: Client,
    auth: String,
    sessid: String,
    nonce: String,
    encnonce: String,
    pub info: BinaryInform,
}

impl FusClient {
    pub fn new() -> reqwest::Result<Self> {
        let mut client = FusClient {
            client: Default::default(),
            auth: Default::default(),
            sessid: Default::default(),
            nonce: Default::default(),
            encnonce: Default::default(),
            info: Default::default(),
        };

        // Initialize nonce
        let resp = client.make_req("NF_DownloadGenerateNonce.do", "")?;

        if let Some(nonce) = resp.headers().get("NONCE").and_then(|n| n.to_str().ok()) {
            client.encnonce = nonce.to_string();
            client.nonce = auth::decryptnonce(&client.encnonce);
            client.auth = auth::getauth(&client.nonce);
        }

        client.sessid = resp
            .cookies()
            .find(|c| c.name().starts_with("JSESSIONID"))
            .map(|c| c.value().to_string())
            .unwrap_or_default();

        Ok(client)
    }

    pub fn fetch_binary_info(&mut self, model: &str, region: &str) {
        let req_xml = xml::binary_inform_req_xml(model, region);

        let xml = self
            .make_req("NF_DownloadBinaryInform.do", &req_xml)
            .and_then(Response::text)
            .expect("Info request failed");

        self.info = BinaryInform::parse(&xml).expect("Info request invalid");
    }

    fn make_headers(&self) -> HeaderMap {
        let auth_val = format!(
            "FUS nonce=\"{}\", signature=\"{}\", nc=\"\", type=\"\", realm=\"\", newauth=\"1\"",
            self.encnonce, self.auth
        );

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_val).unwrap());
        headers.insert(USER_AGENT, HeaderValue::from_static("Kies2.0_FUS"));
        if !self.sessid.is_empty() {
            headers.insert(
                COOKIE,
                HeaderValue::from_str(&format!("JSESSIONID={}", self.sessid)).unwrap(),
            );
        }
        headers
    }

    fn make_req(&self, path: &str, data: &str) -> reqwest::Result<Response> {
        let url = format!("https://neofussvr.sslcs.cdngc.net/{}", path);
        self.client
            .post(&url)
            .headers(self.make_headers())
            .body(data.to_string())
            .send()?
            .error_for_status()
    }

    pub fn init_download(&self) {
        let init_xml = xml::binary_init_req_xml(&self.info.filename, &self.nonce);
        self.make_req("NF_DownloadBinaryInitForMass.do", &init_xml)
            .expect("Download init failed");
    }

    pub fn download_file(
        &self,
        start: Option<u64>,
        end: Option<u64>,
    ) -> Result<Response, reqwest::Error> {
        let mut headers = self.make_headers();
        match (start, end) {
            (Some(s), Some(e)) => headers.insert(
                RANGE,
                HeaderValue::from_str(&format!("bytes={}-{}", s, e)).unwrap(),
            ),
            (None, Some(e)) => headers.insert(
                RANGE,
                HeaderValue::from_str(&format!("bytes=0-{}", e)).unwrap(),
            ),
            (Some(s), None) => headers.insert(
                RANGE,
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
