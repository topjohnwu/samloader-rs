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

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use std::fmt::Write as _;

// This auth key is provided by @henr1kas and @ducthoe
const AUTH_AES_KEY: [u8; 16] = [
    0x42, 0x2e, 0x73, 0x73, 0x36, 0x17, 0xae, 0x2b, 0x19, 0x89, 0x40, 0xfd, 0x4e, 0x32, 0xb0, 0xa5,
];

fn authenticate_block(in_block: &[u8; 16]) -> [u8; 16] {
    let cipher = aes::Aes128::new(&AUTH_AES_KEY.into());
    let mut block = (*in_block).into();
    cipher.encrypt_block(&mut block);
    block.into()
}

pub(crate) fn decrypt_nonce(inp: &str) -> String {
    let mut block = [b'0'; 16];
    let bytes = inp.as_bytes();
    let len = bytes.len().min(16);
    block[..len].copy_from_slice(&bytes[..len]);

    let authenticated = authenticate_block(&block);
    to_hex_string(&authenticated)
}

fn client_nonce_seed() -> u64 {
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::SystemTime;
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(42) as u64
    }
    #[cfg(target_arch = "wasm32")]
    {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0x9e37_79b9_7f4a_7c15);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }
}

fn generate_client_nonce() -> String {
    let mut seed = client_nonce_seed();

    let mut nonce = String::with_capacity(16);
    let chars = b"abcdefghijklmnopqrstuvwxyz0123456789";
    for _ in 0..16 {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let idx = (seed >> 32) as usize % chars.len();
        nonce.push(chars[idx] as char);
    }
    nonce
}

fn to_hex_string(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let _ = write!(&mut hex, "{b:02x}");
    }
    hex
}

pub(crate) fn format_auth_header(nonce: &str, signature: &str) -> String {
    format!(
        "FUS nonce=\"{nonce}\", signature=\"{signature}\", nc=\"\", type=\"\", realm=\"\", newauth=\"1\""
    )
}

pub(crate) fn format_history_auth_header(model: &str) -> String {
    let client_nonce = generate_client_nonce();

    let auth_str = format!("auth:{client_nonce}:00000001");
    let auth_hash = to_hex_string(&fast_md5::digest(auth_str.as_bytes()));

    let interface_str = format!("interface:{}", model.to_uppercase());
    let interface_hash = to_hex_string(&fast_md5::digest(interface_str.as_bytes()));

    let final_str = format!("{auth_hash}:FUS:{interface_hash}");
    let signature = to_hex_string(&fast_md5::digest(final_str.as_bytes()));

    format!(
        "FUS nonce=\"{client_nonce}\", signature=\"{signature}\", \
         nc=\"00000001\", type=\"auth\", realm=\"interface\""
    )
}
