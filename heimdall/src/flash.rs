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

use crate::bridge_manager::BridgeManager;
use crate::print_error;
use crate::version;
use crate::PartitionArg;
use libpit::{PitData, PitEntry};
use std::borrow::Cow;
use std::fs::File;
use std::io::Read;
use std::thread::sleep;
use std::time::Duration;

pub(crate) struct Lz4FrameHeader {
    pub content_size: u64,
    pub block_max_size: usize,
}

impl Lz4FrameHeader {
    pub(crate) fn from_read<R: Read>(reader: &mut R) -> Result<Self, String> {
        let mut magic_bytes = [0u8; 4];
        reader
            .read_exact(&mut magic_bytes)
            .map_err(|_| "Failed to read magic number")?;
        let magic = u32::from_le_bytes(magic_bytes);

        if magic != 0x184D2204 {
            // We only support the standard LZ4 frame magic in this context,
            // not the skippable frames (0x184D2A50 - 0x184D2A5F)
            return Err(format!("Not a valid LZ4 frame. Magic: 0x{:08X}", magic));
        }

        let mut flg_byte = [0u8; 1];
        reader
            .read_exact(&mut flg_byte)
            .map_err(|_| "Failed to read FLG byte")?;
        let flg = flg_byte[0];

        let version = (flg >> 6) & 0x03;
        if version != 1 {
            return Err(format!("Unsupported LZ4 version: {}", version));
        }

        let block_independence = ((flg >> 5) & 0x01) == 1;
        let block_checksum = ((flg >> 4) & 0x01) == 1;
        let content_size_flag = ((flg >> 3) & 0x01) == 1;
        let dict_id_flag = (flg & 0x01) == 1;

        if !content_size_flag {
            return Err("LZ4 content size must be enabled".to_string());
        }
        if block_checksum {
            return Err("LZ4 block checksum must be disabled".to_string());
        }
        if !block_independence {
            return Err("LZ4 block independence must be enabled".to_string());
        }

        let mut bd_byte = [0u8; 1];
        reader
            .read_exact(&mut bd_byte)
            .map_err(|_| "Failed to read BD byte")?;
        let bd = bd_byte[0];

        let block_max_size_code = (bd >> 4) & 0x07;
        let block_max_size = match block_max_size_code {
            4 => 64 * 1024,
            5 => 256 * 1024,
            6 => 1024 * 1024,
            7 => 4 * 1024 * 1024,
            _ => {
                return Err(format!(
                    "Invalid block max size code: {}",
                    block_max_size_code
                ))
            }
        };

        let mut content_size_bytes = [0u8; 8];
        reader
            .read_exact(&mut content_size_bytes)
            .map_err(|_| "Failed to read content size")?;
        let content_size = u64::from_le_bytes(content_size_bytes);

        if dict_id_flag {
            let mut dict_id_bytes = [0u8; 4];
            reader
                .read_exact(&mut dict_id_bytes)
                .map_err(|_| "Failed to read dictionary ID")?;
        }

        let mut hc_byte = [0u8; 1];
        reader
            .read_exact(&mut hc_byte)
            .map_err(|_| "Failed to read header checksum")?;

        Ok(Self {
            content_size,
            block_max_size,
        })
    }
}

pub(crate) struct FirmwareFile<'a> {
    pub(crate) pit_entry: &'a PitEntry,
    pub(crate) file: File,
    pub(crate) file_size: u64,
}

pub(crate) struct FirmwareLz4File<'a> {
    pub(crate) pit_entry: &'a PitEntry,
    pub(crate) file: File,
    pub(crate) header: Lz4FrameHeader,
}

pub(crate) enum FirmwareInfo<'a> {
    Normal(FirmwareFile<'a>),
    Lz4(FirmwareLz4File<'a>),
}

pub(crate) struct SequenceIterator<'a> {
    file: &'a File,
    file_size: u64,
    packet_size: usize,
    sequence_max_length: usize,
    bytes_read: u64,
}

impl<'a> Iterator for SequenceIterator<'a> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes_read >= self.file_size {
            return None;
        }

        let remaining = self.file_size - self.bytes_read;
        let sequence_byte_count = std::cmp::min(
            remaining,
            (self.sequence_max_length * self.packet_size) as u64,
        ) as usize;

        let mut data = vec![0u8; sequence_byte_count];
        let mut reader = self.file;
        if reader.read_exact(&mut data).is_err() {
            return None;
        }

        self.bytes_read += sequence_byte_count as u64;

        Some(data)
    }
}

impl<'a> FirmwareFile<'a> {
    pub(crate) fn sequences(
        &self,
        packet_size: usize,
        sequence_max_length: usize,
    ) -> SequenceIterator<'_> {
        SequenceIterator {
            file: &self.file,
            file_size: self.file_size,
            packet_size,
            sequence_max_length,
            bytes_read: 0,
        }
    }
}

pub(crate) struct Lz4SequenceIterator<'a> {
    file: &'a File,
    header: &'a Lz4FrameHeader,
    packet_size: usize,
    sequence_max_length: usize,
    remaining_decompressed: u64,
    finished: bool,
}

impl<'a> Iterator for Lz4SequenceIterator<'a> {
    type Item = (usize, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        let sequence_bytes = self.sequence_max_length * self.packet_size;
        let next_decompressed_size = if self.remaining_decompressed >= sequence_bytes as u64 {
            sequence_bytes
        } else {
            self.remaining_decompressed as usize
        };
        self.remaining_decompressed -= next_decompressed_size as u64;

        let mut decompressed_size_upper_bound = 0;
        let mut sequence_data = Vec::new();
        let mut reader = self.file;

        loop {
            let mut block_size_bytes = [0u8; 4];
            if reader.read_exact(&mut block_size_bytes).is_err() {
                self.finished = true;
                break;
            }
            let block_size = u32::from_le_bytes(block_size_bytes);

            if block_size == 0 {
                // EndMark
                self.finished = true;
                break;
            }

            decompressed_size_upper_bound += self.header.block_max_size;
            sequence_data.extend_from_slice(&block_size_bytes);

            let data_size = (block_size & 0x7FFF_FFFF) as usize;
            let mut data = vec![0u8; data_size];
            if reader.read_exact(&mut data).is_err() {
                self.finished = true;
                break;
            }
            sequence_data.extend_from_slice(&data);

            if decompressed_size_upper_bound >= next_decompressed_size {
                break;
            }
        }

        if sequence_data.is_empty() {
            return None;
        }

        Some((next_decompressed_size, sequence_data))
    }
}

impl<'a> FirmwareLz4File<'a> {
    pub(crate) fn sequences(
        &self,
        packet_size: usize,
        sequence_max_length: usize,
    ) -> Lz4SequenceIterator<'_> {
        Lz4SequenceIterator {
            file: &self.file,
            header: &self.header,
            packet_size,
            sequence_max_length,
            remaining_decompressed: self.header.content_size,
            finished: false,
        }
    }
}

pub(crate) fn action_flash(
    repartition: bool,
    verbose: bool,
    wait: bool,
    usb_log_level: &str,
    skip_size_check: bool,
    pit: &str,
    partitions: &[PartitionArg],
) -> i32 {
    if repartition && pit.is_empty() {
        println!("If you wish to repartition then a PIT file must be specified.\n");
        return 0;
    }

    // Open files
    let mut pit_file = None;
    if !pit.is_empty() {
        match File::open(pit) {
            Ok(f) => pit_file = Some(f),
            Err(_) => {
                print_error!("Failed to open file \"{}\"", pit);
                return 1;
            }
        }
    }

    // Info
    version::print_release_info();
    sleep(Duration::from_millis(1000));

    // Perform flash
    let mut bridge_manager = BridgeManager::new(verbose, wait);
    bridge_manager.set_usb_log_level(usb_log_level);

    if let Err(e) = bridge_manager.initialise() {
        print_error!("{}", e);
        return 1;
    }

    if let Err(e) = bridge_manager.begin_session() {
        print_error!("{}", e);
        return 1;
    }

    let Some(pit_data) = get_pit_data(&bridge_manager, pit_file.as_ref(), repartition) else {
        return 1;
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

        let Ok((mut file, file_size)) = File::open(&part.filename).and_then(|f| {
            let file_size = f.metadata()?.len();
            Ok((f, file_size))
        }) else {
            print_error!("Failed to open file \"{}\"", part.filename);
            return 1;
        };

        let is_lz4 = {
            use std::io::{Seek, SeekFrom};
            let pos = file.stream_position().unwrap_or(0);
            match Lz4FrameHeader::from_read(&mut file) {
                Ok(header) => Some(header),
                Err(_) => {
                    let _ = file.seek(SeekFrom::Start(pos));
                    None
                }
            }
        };

        // Size check
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
                file,
                header,
            }));
        } else {
            partition_infos.push(FirmwareInfo::Normal(FirmwareFile {
                pit_entry: entry,
                file,
                file_size,
            }));
        }
    }

    if let Err(e) = send_total_transfer_size(
        &bridge_manager,
        &partition_infos,
        pit_file.as_ref(),
        repartition,
    ) {
        print_error!("{}", e);
        return 1;
    }

    if let Err(e) = flash_partitions(&bridge_manager, partition_infos, &pit_data, repartition) {
        print_error!("{}", e);
        return 1;
    }

    if let Err(e) = bridge_manager.end_session() {
        print_error!("{}", e);
        return 1;
    }

    0
}

fn send_total_transfer_size(
    bridge_manager: &BridgeManager,
    partition_files: &[FirmwareInfo],
    pit_file: Option<&File>,
    repartition: bool,
) -> Result<(), String> {
    let mut total_bytes: u64 = 0;

    for part in partition_files {
        match part {
            FirmwareInfo::Normal(f) => total_bytes += f.file_size,
            FirmwareInfo::Lz4(f) => total_bytes += f.header.content_size,
        }
    }

    if repartition {
        if let Some(f) = pit_file {
            let pit_size = f.metadata().map_err(|e| e.to_string())?.len();
            total_bytes += pit_size;
        }
    }

    bridge_manager.set_total_bytes(total_bytes)?;

    Ok(())
}

fn get_pit_data(
    bridge_manager: &BridgeManager,
    pit_file: Option<&File>,
    repartition: bool,
) -> Option<PitData> {
    let mut local_pit_data = None;

    if let Some(mut f) = pit_file {
        let mut buffer = Vec::new();
        if f.read_to_end(&mut buffer).is_ok() {
            match PitData::new(&buffer) {
                Ok(data) => local_pit_data = Some(data),
                Err(_) => {
                    print_error!("Failed to unpack PIT file!");
                    return None;
                }
            }
        } else {
            print_error!("Failed to read PIT file.");
            return None;
        }
    }

    if repartition {
        local_pit_data
    } else {
        match bridge_manager.download_pit_file() {
            Ok(pit_buffer) => match PitData::new(&pit_buffer) {
                Ok(device_pit_data) => {
                    if let Some(local_pit) = local_pit_data {
                        if device_pit_data != local_pit {
                            println!("Local and device PIT files don't match and repartition wasn't specified!");
                            print_error!("Flash aborted!");
                            return None;
                        }
                    }
                    Some(device_pit_data)
                }
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
    }
}

fn flash_partitions(
    bridge_manager: &BridgeManager,
    partition_files: Vec<FirmwareInfo>,
    pit_data: &PitData,
    repartition: bool,
) -> Result<(), String> {
    if repartition {
        println!("Uploading PIT");
        bridge_manager.send_pit_data(pit_data)?;
        println!("PIT upload successful\n");
    }

    for info in partition_files {
        match info {
            FirmwareInfo::Normal(f) => {
                println!("Uploading {}", f.pit_entry.partition_name);
                bridge_manager.send_file(&f)?;
                println!("{} upload successful\n", f.pit_entry.partition_name);
            }
            FirmwareInfo::Lz4(f) => {
                println!("Uploading {}", f.pit_entry.partition_name);
                bridge_manager.send_lz4_file(&f)?;
                println!("{} upload successful\n", f.pit_entry.partition_name);
            }
        }
    }

    Ok(())
}
