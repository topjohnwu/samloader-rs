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

use reqwest::blocking::Client;
use roxmltree::Document;

pub fn normalizevercode(vercode: &str) -> String {
    let mut parts: Vec<&str> = vercode.split('/').collect();
    if parts.len() == 3 {
        parts.push(parts[0]);
    }
    if parts[2].is_empty() {
        parts[2] = parts[0];
    }
    parts.join("/")
}

pub fn getlatestver(model: &str, region: &str) -> String {
    let client = Client::new();
    let url = format!(
        "https://fota-cloud-dn.ospserver.net/firmware/{}/{}/version.xml",
        region, model
    );
    let resp = client
        .get(&url)
        .header("User-Agent", "Kies2.0_FUS")
        .send()
        .expect("Network error");

    if resp.status() == 403 {
        panic!("Error 403: Model or region not found");
    }

    let text = resp.text().unwrap();
    let doc = Document::parse(&text).expect("Invalid XML");
    let vercode = doc
        .descendants()
        .find(|n| n.has_tag_name("latest"))
        .and_then(|n| n.text())
        .expect("No latest firmware available");

    normalizevercode(vercode)
}
