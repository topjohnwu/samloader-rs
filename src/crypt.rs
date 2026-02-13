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
use aes::cipher::{BlockDecryptMut, KeyInit}; // FIX: Use BlockDecryptMut instead of BlockDecrypt
use indicatif::{ProgressBar, ProgressStyle};
use md5::{Digest, Md5};
use roxmltree::Document;
use std::fs::File;
use std::io::{Read, Write};

pub type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

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

pub fn get_decryptor(key: &[u8]) -> Aes128EcbDec {
    Aes128EcbDec::new(key.into())
}

pub fn decrypt_progress(mut inf: File, mut outf: File, key: &[u8], length: u64) {
    let mut decryptor = Aes128EcbDec::new(key.into()); // FIX: decryptor must be mutable
    let chunks = (length as usize / 4096) + 1;

    let pb = ProgressBar::new(length);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
        .unwrap()
        .progress_chars("#>-"));

    let mut buffer = [0u8; 4096];

    for i in 0..chunks {
        let bytes_read = inf.read(&mut buffer).unwrap();
        if bytes_read == 0 {
            break;
        }

        let mut decrypted_chunk = Vec::new();
        for chunk in buffer[..bytes_read].chunks(16) {
            if chunk.len() == 16 {
                let mut block = *aes::Block::from_slice(chunk);
                // FIX: Use decrypt_block_mut which corresponds to BlockDecryptMut
                decryptor.decrypt_block_mut(&mut block);
                decrypted_chunk.extend_from_slice(block.as_slice());
            }
        }

        if i == chunks - 1 {
            if let Some(&last_byte) = decrypted_chunk.last() {
                let pad_len = last_byte as usize;
                if pad_len > 0 && pad_len <= 16 {
                    let new_len = decrypted_chunk.len().saturating_sub(pad_len);
                    decrypted_chunk.truncate(new_len);
                }
            }
        }

        outf.write_all(&decrypted_chunk).unwrap();
        pb.inc(bytes_read as u64);
    }
    pb.finish_with_message("Decryption complete");
}
