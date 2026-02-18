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

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use base64::{Engine as _, engine::general_purpose};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

const KEY_1: &str = "vicopx7dqu06emacgpnpy8j8zwhduwlh";
const KEY_2: &str = "9u7qab84rpc16gvk";

fn derive_key(nonce: &str) -> Vec<u8> {
    let mut key = String::new();
    for c in nonce.chars().take(16) {
        let idx = (c as usize) % 16;
        key.push(KEY_1.chars().nth(idx).unwrap());
    }
    key.push_str(KEY_2);
    key.into_bytes()
}

fn aes_encrypt(inp: &[u8], key: &[u8]) -> Vec<u8> {
    let iv = &key[..16];
    let encryptor = Aes256CbcEnc::new(key.into(), iv.into());

    // FIX: Allocate buffer explicitly to avoid dependency on alloc feature for _vec methods
    let mut buf = vec![0u8; inp.len() + 16];
    buf[..inp.len()].copy_from_slice(inp);

    let ct_len = encryptor
        .encrypt_padded_mut::<Pkcs7>(&mut buf, inp.len())
        .expect("Encryption failed")
        .len();

    buf.truncate(ct_len);
    buf
}

fn aes_decrypt(inp: &[u8], key: &[u8]) -> Vec<u8> {
    let iv = &key[..16];
    let decryptor = Aes256CbcDec::new(key.into(), iv.into());

    let mut buf = inp.to_vec();

    // FIX: Use decrypt_padded_mut which works on a mutable slice
    let pt_len = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .expect("Decryption failed")
        .len();

    buf.truncate(pt_len);
    buf
}

pub fn getauth(nonce: &str) -> String {
    let nkey = derive_key(nonce);
    let auth_data = aes_encrypt(nonce.as_bytes(), &nkey);
    general_purpose::STANDARD.encode(auth_data)
}

pub fn decryptnonce(inp: &str) -> String {
    let inp_data = general_purpose::STANDARD
        .decode(inp)
        .expect("Invalid base64");
    let decrypted = aes_decrypt(&inp_data, KEY_1.as_bytes());
    String::from_utf8(decrypted).expect("Invalid UTF-8")
}
