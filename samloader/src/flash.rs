// Copyright 2026 John "topjohnwu" Wu
// Copyright 2021-2024 Henrik Grimler
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
use memmap2::{Mmap, MmapOptions};
use samloader_odin::{
    FirmwareFile, FirmwareInfo, FirmwareLz4File, OdinManager, create_backend,
    parse_lz4_frame_header, verify_md5_footer,
};
use samloader_pit::{PitData, PitEntry};
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use tar::Archive;

struct IndexedEntry {
    original_name: String,
    normalized_name: String,
    mmap: Mmap,
    is_lz4: bool,
}

fn normalize_basename(path_str: &str) -> (String, bool) {
    let mut filename = Path::new(path_str)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();

    if filename.to_lowercase().ends_with(".lz4") {
        filename.truncate(filename.len() - 4);
        (filename, true)
    } else {
        (filename, false)
    }
}

fn scan_tar_packages(
    packages: &[String],
    skip_md5: bool,
) -> Result<(Vec<IndexedEntry>, Option<Vec<u8>>), i32> {
    // MD5 verification of .tar.md5 packages
    if !skip_md5 {
        for pkg in packages {
            if pkg.to_lowercase().ends_with(".md5") {
                println!("Verifying MD5 checksum for {}...", pkg);
                if let Err(e) = verify_md5_footer(pkg) {
                    print_error!("{}", e);
                    return Err(1);
                }
                println!("MD5 verification successful!\n");
            }
        }
    }

    // Scan and index TAR containers
    let mut archives_download_lists: Vec<HashSet<String>> = Vec::new();
    let mut all_packages_entries: Vec<Vec<IndexedEntry>> = Vec::new();

    for pkg in packages {
        let file = match File::open(pkg) {
            Ok(f) => f,
            Err(_) => {
                print_error!("Failed to open package file \"{}\"", pkg);
                return Err(1);
            }
        };

        let mut archive = Archive::new(&file);
        let entries = match archive.entries() {
            Ok(e) => e,
            Err(e) => {
                print_error!("Failed to read archive entries for \"{}\": {}", pkg, e);
                return Err(1);
            }
        };

        let mut package_entries = Vec::new();

        for entry_res in entries {
            let entry = match entry_res {
                Ok(e) => e,
                Err(e) => {
                    print_error!("Corrupted archive entry in \"{}\": {}", pkg, e);
                    return Err(1);
                }
            };

            let entry_path = match entry.path() {
                Ok(p) => p.to_string_lossy().to_string(),
                Err(_) => continue,
            };

            let offset = entry.raw_file_position();
            let size = entry.size();

            let (normalized_name, is_lz4) = normalize_basename(&entry_path);

            if normalized_name == "download-list.txt" {
                // Read the allowlist manifest
                let mut reader = entry;
                let mut content = String::new();
                if reader.read_to_string(&mut content).is_ok() {
                    let download_list = content
                        .lines()
                        .filter_map(|s| {
                            let s = s.trim();
                            if s.is_empty() {
                                None
                            } else {
                                Some(s.to_string())
                            }
                        })
                        .collect();
                    archives_download_lists.push(download_list);
                }
            } else {
                let mmap = match unsafe {
                    MmapOptions::new()
                        .offset(offset)
                        .len(size as usize)
                        .map(&file)
                } {
                    Ok(m) => m,
                    Err(_) => {
                        print_error!(
                            "Failed to memory map entry \"{}\" in package \"{}\"",
                            entry_path,
                            pkg
                        );
                        return Err(1);
                    }
                };

                package_entries.push(IndexedEntry {
                    original_name: entry_path,
                    normalized_name,
                    mmap,
                    is_lz4,
                });
            }
        }

        all_packages_entries.push(package_entries);
    }

    // If any package contained a manifest, we use it as our global download allowlist
    let download_allowlist = if let Some((first, rest)) = archives_download_lists.split_first() {
        // Cross-archive manifest consistency check
        if !rest.iter().all(|m| m == first) {
            print_error!("Cross-archive consistency check failed! download-list.txt do not match.");
            return Err(1);
        }
        Some(first)
    } else {
        None
    };

    let mut resolved_entries: Vec<IndexedEntry> = Vec::new();
    let mut pit_entry: Option<IndexedEntry> = None;

    // Apply manifest filtering and positional precedence (last-writer-wins)
    for package_entries in all_packages_entries {
        for entry in package_entries {
            if entry.normalized_name.ends_with(".pit") {
                pit_entry = Some(entry);
            } else if let Some(allowlist) = download_allowlist {
                if allowlist.contains(&entry.normalized_name) {
                    resolved_entries.push(entry);
                } else {
                    println!(
                        "Skipping {} (not in download-list.txt)",
                        entry.original_name
                    );
                }
            } else {
                resolved_entries.push(entry);
            }
        }
    }

    // Extract PIT local bytes if any from TAR archives
    let mut local_pit_file = None;

    if let Some(entry) = pit_entry {
        local_pit_file = Some(entry.mmap.to_vec());
    }

    Ok((resolved_entries, local_pit_file))
}

fn execute_flash_pipeline(
    mut odin_manager: OdinManager,
    mut partition_infos: Vec<FirmwareInfo>,
    reboot_device: bool,
) -> i32 {
    let total_bytes: u64 = partition_infos
        .iter()
        .map(|part| match part {
            FirmwareInfo::Normal(f) => f.file.len() as u64,
            FirmwareInfo::Lz4(f) => f.content_size,
        })
        .sum();

    if let Err(e) = odin_manager.set_total_bytes(total_bytes) {
        print_error!("{}", e);
        return 1;
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

    if reboot_device && let Err(e) = odin_manager.reboot_device() {
        print_error!("{}", e);
        return 1;
    }

    0
}

fn find_pit_entry_by_filename<'a>(pit_data: &'a PitData, filename: &str) -> Option<&'a PitEntry> {
    pit_data.entries.iter().find(|e| {
        let flash_fn = e.flash_filename.to_string_lossy();
        flash_fn.eq_ignore_ascii_case(filename)
    })
}

fn create_firmware_info<'a>(
    mmap: Mmap,
    source_size: u64,
    is_lz4_suffix: bool,
    pit_entry: &'a PitEntry,
    skip_size_check: bool,
    file_display_name: &str,
) -> Option<FirmwareInfo<'a>> {
    let lz4_frame_header = if is_lz4_suffix {
        let cursor = std::io::Cursor::new(&mmap);
        match parse_lz4_frame_header(cursor) {
            Ok(fh) => Some(fh),
            Err(e) => {
                print_error!(
                    "Failed to parse LZ4 header for {}: {}",
                    file_display_name,
                    e
                );
                return None;
            }
        }
    } else {
        None
    };

    if !skip_size_check {
        let partition_size = pit_entry.partition_size();
        let check_size = if let Some(fh) = &lz4_frame_header {
            fh.content_size
        } else {
            source_size
        };

        if partition_size > 0 && check_size > partition_size {
            print_error!(
                "{} partition is too small for given file. Use --skip-size-check to flash anyways.",
                pit_entry.partition_name
            );
            return None;
        }
    }

    if let Some(fh) = &lz4_frame_header {
        Some(FirmwareInfo::Lz4(FirmwareLz4File {
            pit_entry,
            file: mmap,
            content_size: fh.content_size,
            block_max_size: fh.block_max_size,
        }))
    } else {
        Some(FirmwareInfo::Normal(FirmwareFile {
            pit_entry,
            file: mmap,
        }))
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn action_flash(
    usb_backend: &str,
    repartition: bool,
    verbose: bool,
    reboot_device: bool,
    wait: bool,
    skip_size_check: bool,
    skip_md5: bool,
    pit: Option<&str>,
    packages: &[String],
    partitions: &[PartitionArg],
) -> i32 {
    // 1. Resolve explicit PIT file first if provided
    let mut pit_file_bytes = None;
    if let Some(pit_path) = pit {
        let mut f = match File::open(pit_path) {
            Ok(file) => file,
            Err(_) => {
                print_error!("Failed to open explicit PIT file \"{}\"", pit_path);
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

    // 2. Scan TAR packages next
    let mut resolved_entries = Vec::new();
    if !packages.is_empty() {
        let (entries, local_pit) = match scan_tar_packages(packages, skip_md5) {
            Ok(res) => res,
            Err(code) => return code,
        };
        resolved_entries = entries;
        if pit_file_bytes.is_none() {
            pit_file_bytes = local_pit;
        }
    }

    if repartition && pit_file_bytes.is_none() {
        print_error!("If you wish to repartition then a PIT file must be specified.");
        return 1;
    }

    // 3. Initialize connection session and parse the PIT data
    let usb = match create_backend(usb_backend, verbose, wait) {
        Ok(u) => u,
        Err(e) => {
            print_error!("{}", e);
            return 1;
        }
    };
    let mut odin_manager = OdinManager::new(usb, verbose);

    if let Err(e) = odin_manager.init() {
        print_error!("{}", e);
        return 1;
    }

    if let Err(e) = odin_manager.begin_session() {
        print_error!("{}", e);
        return 1;
    }

    if repartition {
        println!("Uploading PIT");
        if let Err(e) = odin_manager.send_pit_data(pit_file_bytes.as_ref().unwrap()) {
            print_error!("{}", e);
            return 1;
        }
        println!("PIT upload successful\n");
    }

    let pit_buffer = match odin_manager.download_pit_file() {
        Ok(buf) => buf,
        Err(e) => {
            print_error!("{}", e);
            return 1;
        }
    };

    let pit_data = match PitData::new(&pit_buffer) {
        Ok(data) => data,
        Err(_) => {
            print_error!("Failed to unpack device's PIT file!");
            return 1;
        }
    };

    let mut partition_infos = Vec::new();

    // 4. Build firmware partition infos from TAR packages (keeping package order)
    for entry in resolved_entries {
        let Some(pit_entry) = find_pit_entry_by_filename(&pit_data, &entry.normalized_name) else {
            println!(
                "Skipping orphan file \"{}\" (no matching partition in PIT)",
                entry.original_name
            );
            continue;
        };

        let size = entry.mmap.len() as u64;
        let Some(info) = create_firmware_info(
            entry.mmap,
            size,
            entry.is_lz4,
            pit_entry,
            skip_size_check,
            &entry.original_name,
        ) else {
            return 1;
        };
        partition_infos.push(info);
    }

    // 5. Build firmware partition infos from individual files
    for part in partitions {
        let (filename, is_lz4_suffix) = normalize_basename(&part.filename);
        let entry = match &part.name {
            None => {
                let Some(entry) = find_pit_entry_by_filename(&pit_data, &filename) else {
                    print_error!(
                        "File \"{}\" does not match any partition in the specified PIT.",
                        part.filename
                    );
                    return 1;
                };
                entry
            }
            Some(name) => {
                if let Ok(id) = name.parse::<u32>() {
                    let Some(entry) = pit_data.find_entry_by_id(id) else {
                        print_error!(
                            "Partition identifier {id} does not exist in the specified PIT."
                        );
                        return 1;
                    };
                    entry
                } else {
                    let Some(entry) = pit_data.find_entry_by_name(name) else {
                        print_error!(
                            "Partition \"{}\" does not exist in the specified PIT.",
                            name
                        );
                        return 1;
                    };
                    entry
                }
            }
        };

        let Ok((mmap, file_size)) = File::open(&part.filename).and_then(|f| {
            let file_size = f.metadata()?.len();
            let mmap = unsafe { MmapOptions::new().len(file_size as usize).map(&f)? };
            Ok((mmap, file_size))
        }) else {
            print_error!("Failed to open or memory map file \"{}\"", part.filename);
            return 1;
        };

        let Some(info) = create_firmware_info(
            mmap,
            file_size,
            is_lz4_suffix,
            entry,
            skip_size_check,
            &part.filename,
        ) else {
            return 1;
        };
        partition_infos.push(info);
    }

    // 6. Partition deduplication: last writer wins
    let mut mapped_partition_ids = HashSet::new();
    let mut unique_partition_infos = Vec::new();
    for info in partition_infos.into_iter().rev() {
        let id = match &info {
            FirmwareInfo::Normal(f) => f.pit_entry.identifier,
            FirmwareInfo::Lz4(f) => f.pit_entry.identifier,
        };
        if mapped_partition_ids.insert(id) {
            unique_partition_infos.push(info);
        }
    }
    unique_partition_infos.reverse();
    let partition_infos = unique_partition_infos;

    // 7. Execute flash pipeline
    execute_flash_pipeline(odin_manager, partition_infos, reboot_device)
}
