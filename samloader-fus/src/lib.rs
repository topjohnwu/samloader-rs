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

mod auth;
mod fusclient;
mod xml;

pub use fusclient::FusClient;
pub use xml::BinaryInform;

use aes::cipher::BlockModeDecrypt;
use aes::cipher::inout::InOutBuf;
use memmap2::MmapMut;
use std::fs::OpenOptions;
use std::io::Read;
use std::thread;
use std::time::Duration;

pub struct DownloadArgs {
    /// The model name (e.g. SM-S931U1)
    pub model: String,

    /// Region CSC code (e.g. XAA)
    pub region: String,

    /// Number of parallel connections
    pub threads: u64,

    /// Optional: the output directory
    pub out_dir: Option<String>,

    /// Optional: the output file name
    pub out_file: Option<String>,
}

pub trait ProgressReporter: Sync {
    fn init_length(&self, len: u64);
    fn increment(&self, bytes: u64);
    fn finish(&self);
}

struct StubProgressReporter;

impl ProgressReporter for StubProgressReporter {
    fn init_length(&self, _: u64) {}
    fn increment(&self, _: u64) {}
    fn finish(&self) {}
}

static STUB_PROGRESS_REPORTER: StubProgressReporter = StubProgressReporter {};

pub fn download_latest_firmware(args: DownloadArgs, progress: Option<&dyn ProgressReporter>) {
    let mut client = FusClient::new().expect("Unable to establish FusClient");
    client.fetch_binary_info(&args.model, &args.region);

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

    let progress = progress.unwrap_or(&STUB_PROGRESS_REPORTER);
    progress.init_length(client.info.size);
    thread::scope(|s| {
        for (i, chunk) in map.chunks_mut(chunk_size as usize).enumerate() {
            let i = i as u64;
            let is_last_worker = i == args.threads - 1;

            let start = i * chunk_size;
            // Ensure the last thread covers the remainder of the file
            let end = if is_last_worker {
                None
            } else {
                Some(start + chunk_size - 1)
            };

            let mut resp = client
                .download_file(Some(start), end)
                .expect("Download request failed");

            let mut dec = client.get_decryptor();
            s.spawn(move || {
                let mut dl_pos = 0_usize;
                let mut dec_pos = 0_usize;

                loop {
                    match resp.read(&mut chunk[dl_pos..]) {
                        Ok(0) => break, // EOF
                        Ok(n) => {
                            dl_pos += n;
                            progress.increment(n as u64);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                            continue;
                        }
                        Err(e) => panic!("Download failed: {e:?}"),
                    }

                    let encrypted = InOutBuf::from(&mut chunk[dec_pos..dl_pos]);
                    let (blocks, tail) = encrypted.into_chunks();
                    dec.decrypt_blocks_inout(blocks);
                    dec_pos = dl_pos - tail.len();
                }
            });
            // Wait 100ms between each request
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
