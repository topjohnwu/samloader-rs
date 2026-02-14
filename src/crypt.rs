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

use crate::{fusclient::FusClient, request, versionfetch};
use md5::{Digest, Md5};
use roxmltree::Document;

pub fn getv4key(version: &str, model: &str, region: &str, imei: &str) -> Vec<u8> {
    let mut client = FusClient::new();
    let norm_ver = versionfetch::normalizevercode(version);
    let req_xml = request::binaryinform(&norm_ver, model, region, imei, &client.nonce);
    let resp = client
        .makereq("NF_DownloadBinaryInform.do", &req_xml)
        .expect("Request failed");

    let doc = Document::parse(&resp).expect("Malformed XML");
    let fwver = doc
        .descendants()
        .find(|n| n.has_tag_name("LATEST_FW_VERSION"))
        .and_then(|n| n.descendants().find(|d| d.has_tag_name("Data")))
        .and_then(|n| n.text())
        .expect("FW Version not found in response");

    let logicval = doc
        .descendants()
        .find(|n| n.has_tag_name("LOGIC_VALUE_FACTORY"))
        .and_then(|n| n.descendants().find(|d| d.has_tag_name("Data")))
        .and_then(|n| n.text())
        .expect("Logic Value not found");

    // FIX: Use the public wrapper or public function from request.rs
    let deckey_str = request::getlogiccheck(fwver, logicval);
    Md5::digest(deckey_str.as_bytes()).to_vec()
}

pub fn getv2key(version: &str, model: &str, region: &str) -> Vec<u8> {
    let deckey = format!("{}:{}:{}", region, model, version);
    Md5::digest(deckey.as_bytes()).to_vec()
}
