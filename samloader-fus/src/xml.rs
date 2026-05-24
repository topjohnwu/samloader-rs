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
        if let Some(ch) = inp.chars().nth(idx as usize) {
            out.push(ch);
        } else {
            out.push('.');
        }
    }
    out
}

pub(crate) fn parse_version_xml(xml: &str) -> Option<String> {
    let doc = Document::parse(xml).ok()?;
    let latest = doc
        .descendants()
        .find(|n| n.has_tag_name("latest"))?
        .text()?;
    let mut parts: Vec<&str> = latest.split('/').collect();
    if parts.len() == 3 {
        parts.push(parts[0]);
    }
    if parts.len() >= 3 && parts[2].is_empty() {
        parts[2] = parts[0];
    }
    Some(parts.join("/"))
}

pub(crate) fn binary_inform_req_xml(model: &str, region: &str, fw: &str, nonce: &str) -> String {
    let logic_check = get_logic_check(fw, nonce);

    format!(
        r#"<FUSMsg>
<FUSHdr><ProtoVer>1.0</ProtoVer><SessionID>0</SessionID><MsgID>1</MsgID></FUSHdr>
<FUSBody>
    <Put>
        <CmdID>1</CmdID>
        <ACCESS_MODE><Data>1</Data></ACCESS_MODE>
        <BINARY_NATURE><Data>1</Data></BINARY_NATURE>
        <REQUEST_TYPE><Data>2</Data></REQUEST_TYPE>
        <LOGIC_CHECK><Data>{logic_check}</Data></LOGIC_CHECK>
        <BINARY_SW_VERSION><Data>{fw}</Data></BINARY_SW_VERSION>
        <BINARY_LOCAL_CODE><Data>{region}</Data></BINARY_LOCAL_CODE>
        <BINARY_MODEL_NAME><Data>{model}</Data></BINARY_MODEL_NAME>
    </Put>
    <Get>
        <CmdID>2</CmdID>
        <BINARY_SW_VERSION></BINARY_SW_VERSION>
    </Get>
</FUSBody>
</FUSMsg>"#
    )
}

pub(crate) fn binary_init_req_xml(
    filename: &str,
    nonce: &str,
    fw: &str,
    model_type: &str,
    region: &str,
) -> String {
    let start = filename.len().saturating_sub(25);
    let end = filename.len().saturating_sub(9);
    let checkinp = &filename[start..end];

    let logic_check = get_logic_check(checkinp, nonce);

    format!(
        r#"<FUSMsg>
<FUSHdr><ProtoVer>1.0</ProtoVer><SessionID>0</SessionID><MsgID>1</MsgID></FUSHdr>
<FUSBody>
    <Put>
        <BINARY_NAME><Data>{filename}</Data></BINARY_NAME>
        <BINARY_SW_VERSION><Data>{fw}</Data></BINARY_SW_VERSION>
        <DEVICE_LOCAL_CODE><Data>{region}</Data></DEVICE_LOCAL_CODE>
        <DEVICE_MODEL_TYPE><Data>{model_type}</Data></DEVICE_MODEL_TYPE>
        <LOGIC_CHECK><Data>{logic_check}</Data></LOGIC_CHECK>
    </Put>
</FUSBody>
</FUSMsg>"#
    )
}

fn parse_xml_data(xml: &str) -> Option<HashMap<String, String>> {
    let doc = Document::parse(xml).ok()?;

    let status_str = doc
        .root_element()
        .children()
        .find(|n| n.has_tag_name("FUSBody"))?
        .children()
        .find(|n| n.has_tag_name("Results"))?
        .children()
        .find(|n| n.has_tag_name("Status"))?
        .text()?;

    if status_str != "200" && status_str != "S00" {
        return None;
    }

    let mut kv = HashMap::new();
    doc.descendants()
        .filter(|n| n.has_tag_name("Data"))
        .for_each(|n| {
            if let Some(v) = n.text() {
                let parent = n.parent().unwrap();
                kv.insert(parent.tag_name().name().to_string(), v.to_string());
            }
        });
    Some(kv)
}

#[derive(Default, Clone)]
pub struct BinaryInform {
    pub version: String,
    pub filename: String,
    pub path: String,
    pub size: u64,
    pub key: Vec<u8>,
    pub model_type: String,
    pub region: String,
}

impl BinaryInform {
    pub(crate) fn parse(xml: &str) -> Option<BinaryInform> {
        let mut kv = parse_xml_data(xml)?;
        let size: u64 = kv.get("BINARY_BYTE_SIZE")?.parse().ok()?;
        let fw_ver = kv
            .get("BINARY_SW_VERSION")
            .cloned()
            .or_else(|| kv.get("LATEST_FW_VERSION").cloned())?;
        let logic_val = kv
            .remove("LOGIC_VALUE_FACTORY")
            .or_else(|| kv.remove("LOGIC_VALUE_HOME"))?;
        let key = get_logic_check(&fw_ver, &logic_val);

        Some(Self {
            version: fw_ver,
            filename: kv.remove("BINARY_NAME")?,
            path: kv.remove("MODEL_PATH")?,
            size,
            key: Md5::digest(key.as_bytes()).to_vec(),
            model_type: kv.remove("DEVICE_MODEL_TYPE")?,
            region: kv.remove("BINARY_LOCAL_CODE")?,
        })
    }
}
