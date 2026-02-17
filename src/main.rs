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

    pub struct ParallelFile {
        file: Mutex<File>,
    }

    impl ParallelFile {
        pub fn new(file: File) -> Self {
            Self {
                file: Mutex::new(file),
            }
        }

        pub fn write_all_at(&self, buf: &[u8], offset: u64) -> std::io::Result<()> {
            let mut file = self.file.lock().unwrap();
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(buf)
        }

        pub fn set_len(&self, size: u64) -> std::io::Result<()> {
            let file = self.file.lock().unwrap();
            file.set_len(size)
        }
    }
}

#[cfg(unix)]
mod file {
    use std::fs::File;
    use std::os::unix::fs::FileExt;

    pub struct ParallelFile(File);

    impl ParallelFile {
        pub fn new(file: File) -> Self {
            Self(file)
        }

        pub fn write_all_at(&self, mut buf: &[u8], mut offset: u64) -> std::io::Result<()> {
            while !buf.is_empty() {
                match self.0.write_at(buf, offset) {
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
                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        }

        pub fn set_len(&self, size: u64) -> std::io::Result<()> {
            self.0.set_len(size)
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

            // Pre-allocate file size
            file.set_len(client.info.size).unwrap();
            let file = ParallelFile::new(file);

            let chunk_size = (client.info.size / args.threads / 16) * 16;

            let pb = ProgressBar::new(client.info.size);
            pb.set_style(ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}) ({eta})")
                .unwrap());
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

                        while let Ok(n) = fill_buf(&mut resp, &mut buf) {
                            if n == 0 {
                                break;
                            }

                            let mut write_len = n;

                            // Decrypt if key is present
                            if let Some(dec) = &mut decryptor {
                                let bytes: InOutBuf<u8> = buf[..n].as_mut().into();
                                let (blocks, tail) = bytes.into_chunks();
                                if !tail.is_empty() {
                                    panic!("Download corrupted, cannot decrypt");
                                }
                                dec.decrypt_blocks_inout_mut(blocks);

                                // Handle padding removal on the very last chunk
                                if current_pos + n as u64 == file_size {
                                    let last_byte = buf[n - 1];
                                    let pad_len = last_byte as usize;
                                    if pad_len > 0 && pad_len <= 16 {
                                        write_len = n.saturating_sub(pad_len);
                                    }
                                }
                            }

                            file.write_all_at(&buf[..write_len], current_pos).unwrap();
                            // Truncate file if we removed padding
                            if write_len < n {
                                file.set_len(current_pos + write_len as u64).unwrap();
                            }
                            current_pos += n as u64;
                            pb.inc(n as u64);
                        }
                    });

                    // Wait 100ms between each request
                    thread::sleep(Duration::from_millis(100));
                }
            });

            pb.disable_steady_tick();
            pb.finish_with_message("Download complete");
        }
    }
}
