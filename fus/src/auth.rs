// Copyright 2026 John "topjohnwu" Wu
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

// The code was not reverse engineered by the author of this project (@topjohnwu), but
// ported from the Bifrost project (https://github.com/zacharee/Bifrost).
// The original implementation is licensed under MIT license.
// Copyright (c) 2021 Zachary Wander

use aes::cipher::{Block, BlockCipherEncrypt, KeyInit};

const AUTH_AES_KEY: [u8; 16] = [
    0x42, 0x2e, 0x73, 0x73, 0x36, 0x17, 0xae, 0x2b, 0x19, 0x89, 0x40, 0xfd, 0x4e, 0x32, 0xb0,
    0xa5,
];

fn authenticate_block(in_block: &[u8; 16]) -> [u8; 16] {
    let cipher = aes::Aes128::new_from_slice(&AUTH_AES_KEY).unwrap();
    let mut block = Block::<aes::Aes128>::default();
    block.copy_from_slice(in_block);
    cipher.encrypt_block(&mut block);

    let mut out_block = [0u8; 16];
    out_block.copy_from_slice(&block);
    out_block
}

pub(crate) fn decrypt_nonce(inp: &str) -> String {
    let mut block = [b'0'; 16];
    let bytes = inp.as_bytes();
    let len = bytes.len().min(16);
    block[..len].copy_from_slice(&bytes[..len]);

    let authenticated = authenticate_block(&block);

    let mut hex = String::with_capacity(32);
    for b in authenticated {
        hex.push_str(&format!("{:02x}", b));
    }
    hex
}
