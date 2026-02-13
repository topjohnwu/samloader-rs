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
mod crypt;
mod fusclient;
mod imei;
mod request;
mod versionfetch;

use clap::{Parser, Subcommand};
use roxmltree::Document;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::time::Duration;
use indicatif::{ProgressBar, ProgressStyle};

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

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Download {
        #[arg(short = 'v', long)]
        fw_ver: Option<String>,
        #[arg(short = 'O', long)]
        out_dir: Option<String>,
        #[arg(short = 'o', long)]
        out_file: Option<String>,
    },
    Checkupdate,
    Decrypt {
        #[arg(short = 'v', long)]
        fw_ver: String,
        #[arg(short = 'V', long, default_value_t = 4)]
        enc_ver: i32,
        #[arg(short = 'i', long)]
        in_file: String,
        #[arg(short = 'o', long)]
        out_file: String,
    },
}

fn main() {
    let args = Cli::parse();

    let imei_val = if let Some(i) = args.imei {
        if i.len() == 8 {
            println!("Generating random IMEI from TAC...");
            imei::generate_random_imei(&i)
        } else {
            i
        }
    } else if let Some(s) = args.serial {
        s
    } else {
        panic!("IMEI or Serial required (use -i or -s)");
    };

    match args.command {
        Commands::Checkupdate => {
            let ver = versionfetch::getlatestver(&args.model, &args.region);
            println!("{}", ver);
        }
        Commands::Decrypt {
            fw_ver,
            enc_ver,
            in_file,
            out_file,
        } => {
            let key = if enc_ver == 4 {
                crypt::getv4key(&fw_ver, &args.model, &args.region, &imei_val)
            } else {
                crypt::getv2key(&fw_ver, &args.model, &args.region)
            };

            let inf = File::open(&in_file).expect("Input file not found");
            let outf = File::create(&out_file).expect("Cannot create output file");
            let len = inf.metadata().unwrap().len();

            crypt::decrypt_progress(inf, outf, &key, len);
        }
        Commands::Download {
            fw_ver,
            out_dir,
            out_file,
        } => {
            let version =
                fw_ver.unwrap_or_else(|| versionfetch::getlatestver(&args.model, &args.region));
            println!("Firmware Version: {}", version);

            let mut client = fusclient::FusClient::new();
            let req_xml = request::binaryinform(
                &version,
                &args.model,
                &args.region,
                &imei_val,
                &client.nonce,
            );
            let resp = client
                .makereq("NF_DownloadBinaryInform.do", &req_xml)
                .expect("Info request failed");

            let doc = Document::parse(&resp).expect("Invalid XML");
            let filename = doc
                .descendants()
                .find(|n| n.has_tag_name("BINARY_NAME"))
                .and_then(|n| n.descendants().find(|d| d.has_tag_name("Data")))
                .and_then(|n| n.text())
                .expect("Filename not found");
            let path = doc
                .descendants()
                .find(|n| n.has_tag_name("MODEL_PATH"))
                .and_then(|n| n.descendants().find(|d| d.has_tag_name("Data")))
                .and_then(|n| n.text())
                .expect("Path not found");
            let size: u64 = doc
                .descendants()
                .find(|n| n.has_tag_name("BINARY_BYTE_SIZE"))
                .and_then(|n| n.descendants().find(|d| d.has_tag_name("Data")))
                .and_then(|n| n.text())
                .unwrap()
                .parse()
                .unwrap();

            let final_out = out_file.unwrap_or_else(|| {
                let dir = out_dir.unwrap_or_else(|| ".".to_string());
                format!("{}/{}", dir, filename)
            });

            println!("Downloading {} to {}", filename, final_out);

            let init_xml = request::binaryinit(filename, &client.nonce);
            client
                .makereq("NF_DownloadBinaryInitForMass.do", &init_xml)
                .expect("Init failed");

            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .append(true)
                .open(&final_out)
                .unwrap();

            let existing_size = file.metadata().unwrap().len();

            let mut resp = client
                .downloadfile(&format!("{}{}", path, filename), existing_size)
                .unwrap();

            let pb = ProgressBar::new(size);
            pb.set_style(ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}) ({eta})")
                .unwrap());

            pb.set_position(existing_size);
            pb.reset_eta();
            pb.enable_steady_tick(Duration::from_secs(1));

            let mut buf = [0; 16384];
            while let Ok(n) = resp.read(&mut buf) {
                if n == 0 {
                    break;
                }
                file.write_all(&buf[..n]).unwrap();
                pb.inc(n as u64);
            }
            pb.finish();
            println!("Download complete.");

            if final_out.ends_with(".enc4") {
                let decrypted_name = final_out.replace(".enc4", "");
                println!("Decrypting to {}", decrypted_name);
                let key = crypt::getv4key(&version, &args.model, &args.region, &imei_val);
                let inf = File::open(&final_out).unwrap();
                let outf = File::create(&decrypted_name).unwrap();
                crypt::decrypt_progress(inf, outf, &key, size);
                fs::remove_file(final_out).unwrap();
            }
        }
    }
}
