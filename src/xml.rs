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

use roxmltree::Document;
use std::collections::HashMap;

pub fn getlogiccheck(inp: &str, nonce: &str) -> String {
    if inp.len() < 16 {
        panic!("getlogiccheck() input too short");
    }
    let mut out = String::new();
    for c in nonce.chars() {
        let idx = (c as u32) & 0xf;
        out.push(inp.chars().nth(idx as usize).unwrap());
    }
    out
}

pub fn binary_inform_req_xml(
    fwv: &str,
    model: &str,
    region: &str,
    imei: &str,
    nonce: &str,
) -> String {
    let logic_check = getlogiccheck(fwv, nonce);

    let (mcc, mnc, cc_code) = if region == "EUX" {
        ("262", "01", "DE")
    } else if region == "EUY" {
        ("220", "01", "RS")
    } else {
        ("", "", "")
    };

    let extra_fields = if region == "EUX" || region == "EUY" {
        format!(
            "<DEVICE_AID_CODE><Data>{region}</Data></DEVICE_AID_CODE>\
             <DEVICE_CC_CODE><Data>{cc_code}</Data></DEVICE_CC_CODE>\
             <MCC_NUM><Data>{mcc}</Data></MCC_NUM>\
             <MNC_NUM><Data>{mnc}</Data></MNC_NUM>",
            region = region,
            cc_code = cc_code,
            mcc = mcc,
            mnc = mnc
        )
    } else {
        String::new()
    };

    format!(
        r#"<FUSMsg>
<FUSHdr><ProtoVer>1.0</ProtoVer></FUSHdr>
<FUSBody>
    <Put>
        <ACCESS_MODE><Data>2</Data></ACCESS_MODE>
        <BINARY_NATURE><Data>1</Data></BINARY_NATURE>
        <CLIENT_PRODUCT><Data>Smart Switch</Data></CLIENT_PRODUCT>
        <DEVICE_FW_VERSION><Data>{fwv}</Data></DEVICE_FW_VERSION>
        <DEVICE_LOCAL_CODE><Data>{region}</Data></DEVICE_LOCAL_CODE>
        <DEVICE_MODEL_NAME><Data>{model}</Data></DEVICE_MODEL_NAME>
        <UPGRADE_VARIABLE><Data>0</Data></UPGRADE_VARIABLE>
        <OBEX_SUPPORT><Data>0</Data></OBEX_SUPPORT>
        <DEVICE_IMEI_PUSH><Data>{imei}</Data></DEVICE_IMEI_PUSH>
        <DEVICE_PLATFORM><Data>Android</Data></DEVICE_PLATFORM>
        <CLIENT_VERSION><Data>4.3.23123_1</Data></CLIENT_VERSION>
        <LOGIC_CHECK><Data>{logic_check}</Data></LOGIC_CHECK>
        {extra_fields}
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

    let logic_check = getlogiccheck(checkinp, nonce);

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

pub fn parse_xml_data(xml: &str) -> Option<HashMap<String, String>> {
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
