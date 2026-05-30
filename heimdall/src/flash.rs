// Copyright 2026 Google LLC
// Copyright 2010-2017 Benjamin Dobell, Glass Echidna
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

use crate::PartitionArg;
use crate::print_error;
use samloader_odin::{
    FirmwareFile, FirmwareInfo, FirmwareLz4File, FirmwareSource, Lz4FrameHeader, OdinManager,
};
use samloader_pit::PitData;
use std::borrow::Cow;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

pub(crate) fn init_session_and_get_pit(
    verbose: bool,
    wait: bool,
    usb_log_level: &str,
    pit_file_bytes: Option<&[u8]>,
) -> Result<(OdinManager, PitData), i32> {
    let mut odin_manager = OdinManager::new(verbose, wait);
    odin_manager.set_usb_log_level(usb_log_level);

    if let Err(e) = odin_manager.initialise() {
        print_error!("{}", e);
        return Err(1);
    }

    if let Err(e) = odin_manager.begin_session() {
        print_error!("{}", e);
        return Err(1);
    }

    let pit_data = if let Some(bytes) = pit_file_bytes {
        match PitData::new(bytes) {
            Ok(data) => Some(data),
            Err(_) => {
                print_error!("Failed to unpack PIT file!");
                None
            }
        }
    } else {
        match odin_manager.download_pit_file() {
            Ok(pit_buffer) => match PitData::new(&pit_buffer) {
                Ok(device_pit_data) => Some(device_pit_data),
                Err(_) => {
                    print_error!("Failed to unpack device's PIT file!");
                    None
                }
            },
            Err(e) => {
                print_error!("{}", e);
                None
            }
        }
    };

    let Some(pit_data) = pit_data else {
        return Err(1);
    };

    Ok((odin_manager, pit_data))
}

pub(crate) fn execute_flash_pipeline(
    odin_manager: OdinManager,
    pit_data: &PitData,
    mut partition_infos: Vec<FirmwareInfo>,
    repartition: bool,
    pit_file_bytes: Option<&[u8]>,
) -> i32 {
    let mut total_bytes: u64 = 0;

    for part in &partition_infos {
        match part {
            FirmwareInfo::Normal(f) => total_bytes += f.file_size,
            FirmwareInfo::Lz4(f) => total_bytes += f.header.content_size,
        }
    }

    if repartition && let Some(bytes) = pit_file_bytes {
        total_bytes += bytes.len() as u64;
    }

    if let Err(e) = odin_manager.set_total_bytes(total_bytes) {
        print_error!("{}", e);
        return 1;
    }

    if repartition {
        println!("Uploading PIT");
        if let Err(e) = odin_manager.send_pit_data(pit_data) {
            print_error!("{}", e);
            return 1;
        }
        println!("PIT upload successful\n");
    }

    for info in &mut partition_infos {
        match info {
            FirmwareInfo::Normal(f) => {
                println!("Uploading {}", f.pit_entry.partition_name);
                if let Err(e) = odin_manager.send_file(f) {
                    print_error!("{}", e);
                    return 1;
                }
                println!("{} upload successful\n", f.pit_entry.partition_name);
            }
            FirmwareInfo::Lz4(f) => {
                println!("Uploading {}", f.pit_entry.partition_name);
                if let Err(e) = odin_manager.send_lz4_file(f) {
                    print_error!("{}", e);
                    return 1;
                }
                println!("{} upload successful\n", f.pit_entry.partition_name);
            }
        }
    }

    if let Err(e) = odin_manager.end_session() {
        print_error!("{}", e);
        return 1;
    }

    0
}

pub(crate) fn action_flash(
    repartition: bool,
    verbose: bool,
    wait: bool,
    usb_log_level: &str,
    skip_size_check: bool,
    pit: Option<&str>,
    partitions: &[PartitionArg],
) -> i32 {
    if repartition && pit.is_none() {
        println!("If you wish to repartition then a PIT file must be specified.\n");
        return 0;
    }

    // Open files
    let mut pit_file_bytes = None;
    if let Some(pit_path) = pit {
        let mut f = match File::open(pit_path) {
            Ok(file) => file,
            Err(_) => {
                print_error!("Failed to open file \"{}\"", pit_path);
                return 1;
            }
        };
        let mut buffer = Vec::new();
        if f.read_to_end(&mut buffer).is_err() {
            print_error!("Failed to read PIT file.");
            return 1;
        }
        pit_file_bytes = Some(buffer);
    }

    let (odin_manager, pit_data) =
        match init_session_and_get_pit(verbose, wait, usb_log_level, pit_file_bytes.as_deref()) {
            Ok(res) => res,
            Err(code) => return code,
        };

    let mut partition_infos = Vec::new();

    for part in partitions {
        let entry = if part.name == "@" {
            let mut filename = std::path::Path::new(&part.filename)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_default();
            if filename.to_lowercase().ends_with(".lz4") {
                filename.truncate(filename.len() - 4);
            }
            let Some(entry) = pit_data.entries.iter().find(|e| {
                let flash_fn = e.flash_filename.to_string_lossy();
                flash_fn.eq_ignore_ascii_case(&filename)
            }) else {
                print_error!(
                    "File \"{}\" does not match any partition in the specified PIT.",
                    part.filename
                );
                return 1;
            };
            entry
        } else if let Ok(id) = part.name.parse::<u32>() {
            let Some(entry) = pit_data.find_entry_by_id(id) else {
                print_error!("Partition identifier {id} does not exist in the specified PIT.");
                return 1;
            };
            entry
        } else {
            let Some(entry) = pit_data.find_entry_by_name(&part.name) else {
                print_error!(
                    "Partition \"{}\" does not exist in the specified PIT.",
                    part.name
                );
                return 1;
            };
            entry
        };

        let Ok((file, file_size)) = File::open(&part.filename).and_then(|f| {
            let file_size = f.metadata()?.len();
            Ok((f, file_size))
        }) else {
            print_error!("Failed to open file \"{}\"", part.filename);
            return 1;
        };

        let mut source = FirmwareSource::File(file);

        let is_lz4 = {
            let pos = source.stream_position().unwrap_or(0);
            match Lz4FrameHeader::from_read(&mut source) {
                Ok(header) => Some(header),
                Err(_) => {
                    let _ = source.seek(SeekFrom::Start(pos));
                    None
                }
            }
        };

        if !skip_size_check {
            let partition_size = entry.partition_size();
            let check_size = if let Some(ref h) = is_lz4 {
                h.content_size
            } else {
                file_size
            };

            if partition_size > 0 && check_size > partition_size {
                let name = if part.name == "@" {
                    entry.partition_name.to_string_lossy()
                } else {
                    Cow::Borrowed(part.name.as_str())
                };
                print_error!(
                    "{} partition is too small for given file. Use --skip-size-check to flash anyways.",
                    name
                );
                return 1;
            }
        }

        if let Some(header) = is_lz4 {
            partition_infos.push(FirmwareInfo::Lz4(FirmwareLz4File {
                pit_entry: entry,
                file: source,
                header,
            }));
        } else {
            partition_infos.push(FirmwareInfo::Normal(FirmwareFile {
                pit_entry: entry,
                file: source,
                file_size,
            }));
        }
    }

    execute_flash_pipeline(
        odin_manager,
        &pit_data,
        partition_infos,
        repartition,
        pit_file_bytes.as_deref(),
    )
}
