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
mod imei;
mod versionfetch;
mod xml;

use aes::cipher::inout::InOutBuf;
use aes::cipher::{BlockDecryptMut, KeyInit};
use clap::{Parser, Subcommand};
use file::ParallelFile;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs::OpenOptions;
use std::io::Read;
use std::thread;
use std::time::Duration;

type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;
const PROGRESS_TEMPLATE: &str =
    "[{elapsed_precise}] [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}) [{eta_precise}]";

#[derive(Parser)]
#[command(name = "samloader")]
#[command(about = "Download firmware for Samsung devices", long_about = None)]
struct Cli {
    #[arg(short = 'm', long)]
    model: String,

    #[arg(short = 'r', long)]
    region: String,

    #[arg(short = 'i', long)]
    imei: Option<String>,

    #[arg(short = 's', long)]
    serial: Option<String>,

    #[arg(short = 't', long, default_value_t = 8)]
    threads: u64,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Download {
        #[arg(short = 'O', long)]
        out_dir: Option<String>,
        #[arg(short = 'o', long)]
        out_file: Option<String>,
    },
    Check,
}

pub enum DeviceId {
    Imei(String),
    Tac(String),
    Serial(String),
}

#[cfg(not(unix))]
mod file {
    use std::fs::File;
    use std::io::{Seek, SeekFrom, Write};
    use std::sync::Mutex;

    struct Inner {
        file: File,
        len: usize,
    }

    pub struct ParallelFile {
        inner: Mutex<Inner>,
    }

    impl ParallelFile {
        pub fn new(file: File) -> Self {
            Self {
                inner: Mutex::new(Inner { file, len: 0 }),
            }
        }

        pub fn write_all_at(&self, buf: &[u8], offset: u64) -> std::io::Result<()> {
            let mut inner = self.inner.lock().unwrap();
            inner.file.seek(SeekFrom::Start(offset))?;
            inner.file.write_all(buf)?;
            inner.len += buf.len();
            Ok(())
        }

        pub fn truncate(&self) -> std::io::Result<()> {
            let inner = self.inner.lock().unwrap();
            inner.file.set_len(inner.len as u64)
        }
    }
}

#[cfg(unix)]
mod file {
    use std::fs::File;
    use std::os::unix::fs::FileExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub struct ParallelFile {
        file: File,
        len: AtomicUsize,
    }

    impl ParallelFile {
        pub fn new(file: File) -> Self {
            Self {
                file,
                len: AtomicUsize::new(0),
            }
        }

        pub fn write_all_at(&self, mut buf: &[u8], mut offset: u64) -> std::io::Result<()> {
            let len = buf.len();
            while !buf.is_empty() {
                match self.file.write_at(buf, offset) {
                    Ok(0) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "failed to write whole buffer",
                        ));
                    }
                    Ok(n) => {
                        offset += n as u64;
                        buf = &buf[n..]
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            self.len.fetch_add(len, Ordering::AcqRel);
            Ok(())
        }

        pub fn truncate(&self) -> std::io::Result<()> {
            self.file.set_len(self.len.load(Ordering::Acquire) as u64)
        }
    }
}

fn fill_buf(mut file: impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total_read = 0;
    while total_read < buf.len() {
        match file.read(&mut buf[total_read..]) {
            Ok(0) => break, // EOF
            Ok(n) => total_read += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total_read)
}

fn decrypt_bytes(dec: &mut Aes128EcbDec, buf: &mut [u8], is_last: bool) -> usize {
    let bytes: InOutBuf<u8> = buf.into();
    let (blocks, tail) = bytes.into_chunks();
    if !tail.is_empty() {
        panic!("Download corrupted, cannot decrypt");
    }
    dec.decrypt_blocks_inout_mut(blocks);

    // Handle padding removal on the very last chunk
    if is_last {
        let last_byte = *buf.last().unwrap();
        let pad_len = last_byte as usize;
        if pad_len > 0 && pad_len <= 16 {
            return buf.len().saturating_sub(pad_len);
        }
    }
    buf.len()
}

fn main() {
    let args = Cli::parse();

    let imei = match (args.imei, args.serial) {
        (Some(imei), _) => {
            if imei.len() == 8 {
                DeviceId::Tac(imei)
            } else {
                DeviceId::Imei(imei)
            }
        }
        (None, Some(serial)) => DeviceId::Serial(serial),
        _ => panic!("IMEI or Serial required (use -i or -s)"),
    };

    match args.command {
        Commands::Check => {
            let ver = versionfetch::getlatestver(&args.model, &args.region);
            println!("{}", ver);
        }
        Commands::Download { out_dir, out_file } => {
            let version = versionfetch::getlatestver(&args.model, &args.region);
            println!("Firmware Version: {}", version);

            let mut client = fusclient::FusClient::new();

            client.fetch_binary_info(&version, &args.model, &args.region, &imei);

            let mut decrypt = false;
            let default_name = if client.info.filename.ends_with(".enc4") {
                decrypt = true;
                client.info.filename.replace(".enc4", "")
            } else {
                client.info.filename.clone()
            };

            let final_out = match (out_file, out_dir) {
                (Some(name), _) => name,
                (None, Some(dir)) => format!("{}/{}", dir, default_name),
                _ => default_name,
            };

            println!("Downloading {} to {}", client.info.filename, final_out);

            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&final_out)
                .unwrap();

            // Pre-allocate file
            file.set_len(client.info.size)
                .expect("Cannot pre-allocate file");
            let file = ParallelFile::new(file);

            let chunk_size = (client.info.size / args.threads / 16) * 16;

            let pb = ProgressBar::new(client.info.size)
                .with_style(ProgressStyle::with_template(PROGRESS_TEMPLATE).unwrap());
            pb.enable_steady_tick(Duration::from_secs(1));

            client.init_download();

            thread::scope(|s| {
                for i in 0..args.threads {
                    let is_last_worker = i == args.threads - 1;

                    let start = i * chunk_size;
                    // Ensure the last thread covers the remainder of the file
                    let end = if is_last_worker {
                        None
                    } else {
                        Some((i + 1) * chunk_size - 1)
                    };

                    let mut resp = client
                        .download_file(Some(start), end)
                        .expect("Download request failed");

                    let mut decryptor = if decrypt {
                        Some(Aes128EcbDec::new(client.info.key.as_slice().into()))
                    } else {
                        None
                    };

                    let file = &file;
                    let pb = &pb;
                    let file_size = client.info.size;

                    s.spawn(move || {
                        let mut buf = [0u8; 65536];
                        let mut current_pos = start;

                        loop {
                            let dl_len = fill_buf(&mut resp, &mut buf).expect("Download failed");
                            if dl_len == 0 {
                                break;
                            }

                            // Decrypt if required
                            let write_len = if let Some(dec) = &mut decryptor {
                                let is_last = current_pos + dl_len as u64 == file_size;
                                decrypt_bytes(dec, &mut buf[..dl_len], is_last)
                            } else {
                                dl_len
                            };

                            file.write_all_at(&buf[..write_len], current_pos)
                                .expect("Failed to write to output file");
                            current_pos += dl_len as u64;
                            pb.inc(dl_len as u64);
                        }
                    });

                    // Wait 100ms between each request
                    thread::sleep(Duration::from_millis(100));
                }
            });

            // Truncate file if needed
            file.truncate().expect("Failed to truncate file");
            pb.finish();
        }
    }
}
