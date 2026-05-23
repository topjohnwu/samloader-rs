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
use aes::cipher::KeyInit;
use reqwest::blocking::{Client, Response};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue, RANGE, USER_AGENT};
use xml::BinaryInform;

type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

pub struct FusClient {
    client: Client,
    auth: String,
    nonce: String,
    encnonce: String,
    pub info: BinaryInform,
}

impl FusClient {
    pub fn new() -> reqwest::Result<Self> {
        let client = Client::builder().cookie_store(true).build()?;
        let mut fus = FusClient {
            client,
            auth: Default::default(),
            nonce: Default::default(),
            encnonce: Default::default(),
            info: Default::default(),
        };

        // Initialize nonce
        fus.make_req("NF_SmartDownloadGenerateNonce.do", "")?;

        Ok(fus)
    }

    pub fn fetch_binary_info(&mut self, model: &str, region: &str) {
        // 1. Fetch latest version from version.xml
        let version_url = format!(
            "https://fota-cloud-dn.ospserver.net:443/firmware/{}/{}/version.xml",
            region, model
        );
        let version_xml = self
            .client
            .get(&version_url)
            .header(USER_AGENT, "Kies2.0_FUS")
            .send()
            .expect("Failed to fetch version.xml")
            .text()
            .expect("Failed to read version.xml text");

        let latest_fw = xml::parse_version_xml(&version_xml).expect("Failed to parse version.xml");

        // 2. Compute Binary Inform req using actual latest_fw
        let req_xml = xml::binary_inform_req_xml(model, region, &latest_fw, &self.nonce);

        let xml = self
            .make_req("NF_SmartDownloadBinaryInform.do", &req_xml)
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
        headers.insert(USER_AGENT, HeaderValue::from_static("SMART 2.0"));
        headers
    }

    fn make_req(&mut self, path: &str, data: &str) -> reqwest::Result<Response> {
        let url = format!("https://neofussvr.sslcs.cdngc.net/{}", path);
        let resp = self
            .client
            .post(&url)
            .headers(self.make_headers())
            .body(data.to_string())
            .send()?
            .error_for_status()?;

        if let Some(nonce) = resp
            .headers()
            .get("NONCE")
            .or_else(|| resp.headers().get("nonce"))
            .and_then(|n| n.to_str().ok())
        {
            let nonce_str = nonce.to_string();
            if !nonce_str.is_empty() && nonce_str != self.encnonce {
                self.encnonce = nonce_str;
                self.nonce = self.encnonce.clone();
                self.auth = auth::decrypt_nonce(&self.encnonce);
            }
        }

        Ok(resp)
    }

    pub fn init_download(&mut self) {
        let init_xml = xml::binary_init_req_xml(
            &self.info.filename,
            &self.nonce,
            &self.info.version,
            &self.info.model_type,
            &self.info.region,
        );
        self.make_req("NF_SmartDownloadBinaryInitForMass.do", &init_xml)
            .expect("Download init failed");
    }

    pub fn download_file(&self, start: Option<u64>, end: Option<u64>) -> reqwest::Result<Response> {
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
            "http://cloud-neofussvr.samsungmobile.com/NF_SmartDownloadBinaryForMass.do?file={}{}",
            self.info.path, self.info.filename
        );
        self.client
            .get(url)
            .headers(headers)
            .send()?
            .error_for_status()
    }

    pub fn get_decryptor(&self) -> Aes128EcbDec {
        Aes128EcbDec::new_from_slice(self.info.key.as_slice()).unwrap()
    }
}
