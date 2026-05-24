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

// The code was not reverse engineered by the author of this project (@topjohnwu), but
// ported from the Bifrost project (https://github.com/zacharee/Bifrost).
// The original implementation is licensed under MIT license.
// Copyright (c) 2021 Zachary Wander

const AUTH_PARAM: &[u8] = include_bytes!("auth_param.dat");
const SHIFT_INDICES: [usize; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];

struct AuthHeader {
    block1_size: u32,
    block2_size: u32,
    block3_size: u32,
}

fn parse_header(bytes: &[u8]) -> AuthHeader {
    let read_u32 = |offset: usize| -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    };
    AuthHeader {
        block1_size: read_u32(12),
        block2_size: read_u32(20),
        block3_size: read_u32(44),
    }
}

fn authenticate_block(in_block: &[u8; 16]) -> [u8; 16] {
    let header = parse_header(&AUTH_PARAM[..56]);
    let stream = &AUTH_PARAM[56..];

    let mut temp_block = [0u32; 320];
    for i in 0..16 {
        temp_block[i] = in_block[i] as u32;
    }

    let mut out_block = [0u8; 16];
    let mut v15 = [0u32; 64];
    let base_final = header.block1_size as usize;
    let final_src_start = 288;

    for j in 0..9 {
        let src_start = j * 32;
        let next_src_start = (j + 1) * 32;
        let blk_id_base = j * 16;
        let src_mid = src_start + 16;

        for idx in 0..16 {
            temp_block[src_start + 16 + idx] = temp_block[src_start + SHIFT_INDICES[idx]];
        }

        for i in 0..4 {
            let i4 = i << 2;
            let i16 = i << 4;
            let blk_id_row = blk_id_base + i4;
            let base262 = base_final
                + header.block2_size as usize
                + header.block3_size as usize
                + (6144 * (i + (j << 2)));

            for k in 0..4 {
                let idx_val = temp_block[src_mid + i4 + k] as usize;
                let blk_id = blk_id_row + k;
                let base257 = (blk_id << 12) + (idx_val << 4);
                let sel_offset = base_final + header.block2_size as usize + (blk_id << 5);

                let src16_ptr = &stream[base257..base257 + 16];
                let selector_ptr = &stream[sel_offset..sel_offset + 32];
                let out_start = i16 + (k << 2);

                for out_idx in 0..4 {
                    let mut acc = 0u32;
                    let sel_base = out_idx << 3;

                    for bit_idx in 0..8 {
                        let sel_byte = selector_ptr[sel_base + bit_idx] as usize;
                        let src_idx = (sel_byte >> 3) & 0x1F;
                        let bit_pos = 7 - (sel_byte & 0x7);
                        let src_byte = if src_idx < 16 {
                            src16_ptr[src_idx] as u32
                        } else {
                            0
                        };

                        acc |= ((src_byte >> bit_pos) & 1) << (7 - bit_idx);
                    }

                    v15[out_start + out_idx] = acc & 0xFF;
                }
            }

            for k2 in 0..4 {
                let a1 = v15[i16 + k2] as usize;
                let a2 = v15[i16 + k2 + 4] as usize;
                let a3 = v15[i16 + k2 + 8] as usize;
                let a4 = v15[i16 + k2 + 12] as usize;
                let tbl_base = base262 + 1536 * k2;
                let tbl = &stream[tbl_base..tbl_base + 1536];
                let hi1 = ((a1 & 0xF0) | (a2 >> 4)) & 0xFF;
                let lo1 = (((a1 & 0x0F) << 4) | (a2 & 0x0F)) & 0xFF;
                let v6 = ((16 * tbl[hi1] as u32) ^ tbl[256 + lo1] as u32) & 0xFF;
                let hi2 = ((a3 & 0xF0) | (a4 >> 4)) & 0xFF;
                let lo2 = (((a3 & 0x0F) << 4) | (a4 & 0x0F)) & 0xFF;
                let v7 = ((16 * tbl[512 + hi2] as u32) ^ tbl[768 + lo2] as u32) & 0xFF;
                let hi3 = ((v6 as usize & 0xF0) | (v7 as usize >> 4)) & 0xFF;
                let lo3 = (((v6 & 0x0F) << 4) | (v7 & 0x0F)) & 0xFF;

                temp_block[next_src_start + i4 + k2] =
                    ((16 * tbl[1024 + hi3] as u32) ^ tbl[1280 + lo3 as usize] as u32) & 0xFF;
            }
        }
    }

    for idx in 0..16 {
        let pos =
            base_final + (idx << 8) + temp_block[SHIFT_INDICES[idx] + final_src_start] as usize;
        out_block[idx] = stream[pos];
    }

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
