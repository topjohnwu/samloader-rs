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

use md5::{Digest, Md5};
use roxmltree::Document;
use std::collections::HashMap;

fn get_logic_check(inp: &str, nonce: &str) -> String {
    let mut out = String::new();
    for c in nonce.chars() {
        let idx = (c as u32) & 0xf;
        out.push(inp.chars().nth(idx as usize).unwrap());
    }
    out
}

pub fn binary_inform_req_xml(model: &str, region: &str) -> String {
    format!(
        r#"<FUSMsg>
<FUSHdr><ProtoVer>1.0</ProtoVer></FUSHdr>
<FUSBody>
    <Put>
        <ACCESS_MODE><Data>5</Data></ACCESS_MODE>
        <BINARY_NATURE><Data>1</Data></BINARY_NATURE>
        <CLIENT_PRODUCT><Data>Smart Switch</Data></CLIENT_PRODUCT>
        <CLIENT_VERSION><Data>5.0.0.0</Data></CLIENT_VERSION>
        <DEVICE_FW_VERSION><Data>................</Data></DEVICE_FW_VERSION>
        <DEVICE_LOCAL_CODE><Data>{region}</Data></DEVICE_LOCAL_CODE>
        <DEVICE_AID_CODE><Data>{region}</Data></DEVICE_AID_CODE>
        <DEVICE_CC_CODE><Data>DE</Data></DEVICE_CC_CODE>
        <DEVICE_MODEL_NAME><Data>{model}</Data></DEVICE_MODEL_NAME>
        <LOGIC_CHECK><Data>................</Data></LOGIC_CHECK>
        <DEVICE_INITIALIZE><Data>2</Data></DEVICE_INITIALIZE>
    </Put>
</FUSBody>
</FUSMsg>"#
    )
}

pub fn binary_init_req_xml(filename: &str, nonce: &str) -> String {
    let name_part = filename.split('.').next().unwrap_or(filename);
    let start = if name_part.len() > 16 {
        name_part.len() - 16
    } else {
        0
    };
    let checkinp = &name_part[start..];

    let logic_check = get_logic_check(checkinp, nonce);

    format!(
        r#"<FUSMsg>
<FUSHdr><ProtoVer>1.0</ProtoVer></FUSHdr>
<FUSBody>
    <Put>
        <BINARY_FILE_NAME><Data>{filename}</Data></BINARY_FILE_NAME>
        <LOGIC_CHECK><Data>{logic_check}</Data></LOGIC_CHECK>
    </Put>
</FUSBody>
</FUSMsg>"#
    )
}

fn parse_xml_data(xml: &str) -> Option<HashMap<String, String>> {
    let doc = Document::parse(xml).expect("Invalid XML");

    let status: i32 = doc
        .root_element()
        .children()
        .find(|n| n.has_tag_name("FUSBody"))?
        .children()
        .find(|n| n.has_tag_name("Results"))?
        .children()
        .find(|n| n.has_tag_name("Status"))?
        .text()?
        .parse()
        .ok()?;

    if status != 200 {
        return None;
    }

    let mut kv = HashMap::new();
    doc.descendants()
        .filter(|n| n.has_tag_name("Data"))
        .for_each(|n| match n.text() {
            None => {}
            Some(v) => {
                let parent = n.parent().unwrap();
                kv.insert(parent.tag_name().name().to_string(), v.to_string());
            }
        });
    Some(kv)
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
    pub fn parse(xml: &str) -> Option<BinaryInform> {
        let mut kv = parse_xml_data(xml)?;
        let size: u64 = kv.get("BINARY_BYTE_SIZE")?.parse().ok()?;
        let fw_ver = kv.remove("LATEST_FW_VERSION")?;
        let logic_val = kv.remove("LOGIC_VALUE_FACTORY")?;
        let key = get_logic_check(&fw_ver, &logic_val);

        Some(Self {
            version: fw_ver,
            filename: kv.remove("BINARY_NAME")?,
            path: kv.remove("MODEL_PATH")?,
            size,
            key: Md5::digest(key.as_bytes()).to_vec(),
        })
    }
}
