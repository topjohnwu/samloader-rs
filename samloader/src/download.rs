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

use indicatif::{ProgressBar, ProgressStyle};
use memmap2::MmapMut;
use samloader_fus::FusClient;
use samloader_fus::aes::cipher::BlockModeDecrypt;
use samloader_fus::aes::cipher::inout::InOutBuf;
use std::fs::OpenOptions;
use std::io::Read;
use std::thread;
use std::time::Duration;

const PROGRESS_TEMPLATE: &str =
    "[{elapsed_precise}] [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}) [{eta_precise}]";

pub(crate) struct DownloadArgs {
    /// The model name (e.g. SM-S931U1)
    pub(crate) model: String,

    /// Region CSC code (e.g. XAA)
    pub(crate) region: String,

    /// Optional: firmware version. If None, downloads the latest.
    pub(crate) version: Option<String>,

    /// Number of parallel connections
    pub(crate) threads: u64,

    /// Optional: the output directory
    pub(crate) out_dir: Option<String>,

    /// Optional: the output file name
    pub(crate) out_file: Option<String>,
}

pub(crate) fn download_latest_firmware(args: DownloadArgs) {
    let mut client = FusClient::new().expect("Unable to establish FusClient");

    match &args.version {
        Some(version) => {
            client.fetch_binary_info_for_version(&args.model, &args.region, version);
        }
        None => {
            client.fetch_binary_info(&args.model, &args.region);
        }
    }

    println!("Firmware Version: {}", client.info.version);

    let default_name = client
        .info
        .filename
        .strip_suffix(".enc4")
        .unwrap_or(client.info.filename.as_str());

    let final_out = match (args.out_file, args.out_dir) {
        (Some(name), _) => name,
        (None, Some(dir)) => format!("{}/{}", dir, default_name),
        _ => default_name.to_string(),
    };

    println!("Downloading {} to {}", client.info.filename, final_out);

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&final_out)
        .unwrap();

    // Pre-allocate file
    file.set_len(client.info.size)
        .expect("Cannot pre-allocate file");

    let mut map = unsafe { MmapMut::map_mut(&file).expect("Cannot map file") };

    client.init_download();

    // Round up to the nearest 16 byte boundary
    let chunk_size = (client.info.size / args.threads / 16 + 1) * 16;

    let progress = ProgressBar::new(client.info.size)
        .with_style(ProgressStyle::with_template(PROGRESS_TEMPLATE).unwrap());
    progress.enable_steady_tick(Duration::from_secs(1));

    thread::scope(|s| {
        let progress = &progress;
        let client = &client;
        let mut chunks = map.chunks_mut(chunk_size as usize).enumerate().peekable();
        while let Some((i, chunk)) = chunks.next() {
            let is_last = chunks.peek().is_none();

            let start = i as u64 * chunk_size;
            // Ensure the last thread covers the remainder of the file
            let end = if is_last {
                None
            } else {
                Some(start + chunk_size - 1)
            };

            s.spawn(move || download_chunk(client, chunk, start, end, progress));

            // Stagger connection setup to avoid hammering the server
            thread::sleep(Duration::from_millis(100));
        }
    });

    let last_byte = *map.last().unwrap();
    map.flush().ok();
    drop(map);

    // Handle padding removal if needed
    if last_byte > 0 && last_byte <= 16 {
        let file_len = file
            .metadata()
            .ok()
            .map(|m| m.len())
            .unwrap_or(client.info.size);
        file.set_len(file_len - last_byte as u64)
            .expect("Failed to truncate file");
    }

    progress.finish();
}

/// Maximum number of *consecutive* network failures tolerated while fetching a
/// single chunk. The counter resets whenever a read makes forward progress, so
/// this bounds stalls, not the total number of blips over a long download.
const MAX_RETRIES: u32 = 8;

/// Download the byte range `[start, end]` (or `[start, EOF]` when `end` is
/// `None`) into `chunk`, decrypting in place as bytes arrive.
///
/// On a network error the request is re-issued from the last decrypted 16-byte
/// boundary instead of restarting the chunk. This resume is correct because:
///   * the firmware is served via HTTP range requests over static content, and
///   * decryption is AES-ECB, which is position-independent — every 16-byte
///     block decrypts on its own, so resuming at any block boundary is exact.
///
/// The re-fetched overlap is therefore at most the <16-byte undecrypted tail.
fn download_chunk(
    client: &FusClient,
    chunk: &mut [u8],
    start: u64,
    end: Option<u64>,
    progress: &ProgressBar,
) {
    // ECB keeps no state between blocks, so one decryptor is reused across every
    // (re)connection.
    let mut dec = client.get_decryptor();
    let mut dec_pos = 0_usize; // bytes decrypted so far (always a multiple of 16)
    let mut retries = 0_u32;

    loop {
        let mut resp = match client.download_file(Some(start + dec_pos as u64), end) {
            Ok(resp) => resp,
            Err(e) => {
                retries += 1;
                if retries > MAX_RETRIES {
                    panic!("Download failed after {MAX_RETRIES} retries: {e:?}");
                }
                progress.println(format!(
                    "Request error ({e}); retry {retries}/{MAX_RETRIES} at offset {}",
                    start + dec_pos as u64
                ));
                thread::sleep(backoff(retries));
                continue;
            }
        };

        // We re-requested from `dec_pos`; discard the undecrypted tail and resume
        // writing there. Progress only counts decrypted bytes, so the re-fetched
        // overlap is never double-counted and there is nothing to roll back.
        let resume_from = dec_pos;
        let mut dl_pos = dec_pos; // bytes received into `chunk` this connection

        let stall = loop {
            match resp.read(&mut chunk[dl_pos..]) {
                Ok(0) => return, // chunk fully received and decrypted
                Ok(n) => dl_pos += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => break e, // connection dropped: resume the outer loop
            }

            let prev_dec = dec_pos;
            let (blocks, tail) = InOutBuf::from(&mut chunk[dec_pos..dl_pos]).into_chunks();
            dec.decrypt_blocks_inout(blocks);
            dec_pos = dl_pos - tail.len();
            progress.inc((dec_pos - prev_dec) as u64);
        };

        // Reset the budget only on real decryption progress (a whole new block),
        // not on raw bytes read. This keeps isolated blips from exhausting the
        // retries while guaranteeing that a chunk which never advances still
        // terminates — `dec_pos` can only climb so many times.
        if dec_pos > resume_from {
            retries = 0;
        }
        retries += 1;
        if retries > MAX_RETRIES {
            panic!("Download failed after {MAX_RETRIES} retries: {stall:?}");
        }
        progress.println(format!(
            "Download error ({stall}); retry {retries}/{MAX_RETRIES}, resuming at offset {}",
            start + dec_pos as u64
        ));
        thread::sleep(backoff(retries));
    }
}

/// Exponential backoff capped at 30s: 1s, 2s, 4s, 8s, 16s, 30s, ...
fn backoff(attempt: u32) -> Duration {
    Duration::from_secs((1u64 << (attempt - 1).min(5)).min(30))
}
