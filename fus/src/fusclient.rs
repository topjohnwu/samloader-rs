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
use std::sync::Mutex;
use std::time::Duration;
use xml::BinaryInform;

pub type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

/// Authentication token state. The download GET signs every request with
/// `encnonce`/`auth`; these expire, so they live behind a lock and are shared
/// by reference across all download threads (which only read them) and the
/// occasional reauthentication (which rewrites them). See [`FusClient`].
#[derive(Default)]
struct AuthState {
    auth: String,
    nonce: String,
    encnonce: String,
}

pub struct FusClient {
    client: Client,
    auth_state: Mutex<AuthState>,
    /// Reauthentication generation counter. It also serves as the lock that
    /// serializes reauth: a token expiry observed by many download threads at
    /// once triggers a single refresh, and the rest reuse its result.
    reauth_gen: Mutex<u64>,
    pub info: BinaryInform,
}

impl FusClient {
    pub fn new() -> reqwest::Result<Self> {
        let client = Client::builder()
            .cookie_store(true)
            // For the blocking client, `timeout` is applied per I/O operation with
            // a fresh deadline each call (see its `Read` impl) — so it flags a
            // stalled transfer (no data for 30s) without capping total download
            // time. This is the timeout that surfaces as `Decode/TimedOut`; the
            // download loop now resumes on it instead of aborting. 30s is also the
            // library default, made explicit here so it can be tuned.
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(15))
            .build()?;
        let fus = FusClient {
            client,
            auth_state: Mutex::new(AuthState::default()),
            reauth_gen: Mutex::new(0),
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

        let version_info =
            xml::parse_version_xml(&version_xml).expect("Failed to parse version.xml");
        let latest_fw = version_info.latest;

        // 2. Compute Binary Inform req using actual latest_fw
        let nonce = self.auth_state.lock().unwrap().nonce.clone();
        let req_xml = xml::binary_inform_req_xml(model, region, &latest_fw, &nonce);

        let xml = self
            .make_req("NF_SmartDownloadBinaryInform.do", &req_xml)
            .and_then(Response::text)
            .expect("Info request failed");

        self.info = BinaryInform::parse(&xml).expect("Info request invalid");
    }

    pub fn fetch_binary_info_for_version(&mut self, model: &str, region: &str, version: &str) {
        let mut parts: Vec<&str> = version.split('/').collect();
        if parts.len() == 3 {
            parts.push(parts[0]);
        }
        let fw = parts.join("/");
        let nonce = self.auth_state.lock().unwrap().nonce.clone();
        let req_xml = xml::binary_inform_req_xml(model, region, &fw, &nonce);

        let xml = self
            .make_req("NF_SmartDownloadBinaryInform.do", &req_xml)
            .and_then(Response::text)
            .expect("Info request failed");

        self.info = BinaryInform::parse(&xml).expect("Info request invalid");
    }

    pub fn fetch_all_versions(&self, model: &str, region: &str) -> Vec<String> {
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

        if let Some(info) = xml::parse_version_xml(&version_xml) {
            let mut versions = info.upgrade;
            versions.push(info.latest);
            let mut seen = std::collections::HashSet::new();
            versions.retain(|v| seen.insert(v.clone()));
            versions
        } else {
            Vec::new()
        }
    }

    fn make_headers(&self) -> HeaderMap {
        let (encnonce, auth) = {
            let state = self.auth_state.lock().unwrap();
            (state.encnonce.clone(), state.auth.clone())
        };
        let auth_val = format!(
            "FUS nonce=\"{}\", signature=\"{}\", nc=\"\", type=\"\", realm=\"\", newauth=\"1\"",
            encnonce, auth
        );

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_val).unwrap());
        headers.insert(USER_AGENT, HeaderValue::from_static("SMART 2.0"));
        headers
    }

    fn make_req(&self, path: &str, data: &str) -> reqwest::Result<Response> {
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
            if !nonce_str.is_empty() {
                let mut state = self.auth_state.lock().unwrap();
                if nonce_str != state.encnonce {
                    state.encnonce = nonce_str;
                    state.nonce = state.encnonce.clone();
                    state.auth = auth::decrypt_nonce(&state.encnonce);
                }
            }
        }

        Ok(resp)
    }

    pub fn init_download(&self) -> reqwest::Result<()> {
        let nonce = self.auth_state.lock().unwrap().nonce.clone();
        let init_xml = xml::binary_init_req_xml(
            &self.info.filename,
            &nonce,
            &self.info.version,
            &self.info.model_type,
            &self.info.region,
        );
        self.make_req("NF_SmartDownloadBinaryInitForMass.do", &init_xml)?;
        Ok(())
    }

    pub fn download_file(&self, start: Option<u64>, end: Option<u64>) -> reqwest::Result<Response> {
        // Capture the token generation backing this request. If the request is
        // rejected as unauthorized, this lets the refresh tell whether another
        // thread has already rotated the token in the meantime.
        let gen_used = *self.reauth_gen.lock().unwrap();

        match self.download_file_once(start, end) {
            Err(e) if e.status() == Some(reqwest::StatusCode::UNAUTHORIZED) => {
                // The download token expired mid-transfer. Refresh it (at most
                // once per expiry across all threads) and retry the request once
                // with the new token. If it still fails, the caller's retry loop
                // takes over.
                self.reauthenticate(gen_used);
                self.download_file_once(start, end)
            }
            other => other,
        }
    }

    fn download_file_once(
        &self,
        start: Option<u64>,
        end: Option<u64>,
    ) -> reqwest::Result<Response> {
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

    /// Re-establish the session after the auth token expired (HTTP 401),
    /// rewriting the shared `nonce`/`encnonce`/`auth`.
    ///
    /// `gen_seen` is the generation the failed request was signed with. Holding
    /// `reauth_gen` serializes refreshes, and the generation check makes the
    /// refresh idempotent: the first thread to react to an expiry does the work
    /// and bumps the counter, so the others — which were waiting on the same
    /// lock with the same `gen_seen` — simply return and retry with the token
    /// that is now fresh. The new generation is published only on full success,
    /// so a failed refresh leaves the counter untouched and is retried.
    fn reauthenticate(&self, gen_seen: u64) {
        let mut generation = self.reauth_gen.lock().unwrap();
        if *generation != gen_seen {
            return;
        }
        if self
            .make_req("NF_SmartDownloadGenerateNonce.do", "")
            .is_ok()
            && self.init_download().is_ok()
        {
            *generation += 1;
        }
    }

    pub fn get_decryptor(&self) -> Aes128EcbDec {
        Aes128EcbDec::new_from_slice(self.info.key.as_slice()).unwrap()
    }
}
