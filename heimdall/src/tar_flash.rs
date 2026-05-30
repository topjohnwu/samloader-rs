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

use crate::print_error;
use samloader_odin::{
    FirmwareFile, FirmwareInfo, FirmwareLz4File, FirmwareSource, Lz4FrameHeader, TarEntryReader,
    verify_md5_footer,
};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use tar::Archive;

struct IndexedEntry {
    package_path: String,
    original_name: String,
    normalized_name: String,
    offset: u64,
    size: u64,
    is_lz4: bool,
}

fn normalize_basename(path_str: &str) -> (String, bool) {
    let filename = Path::new(path_str)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();

    if filename.to_lowercase().ends_with(".lz4") {
        (filename[..filename.len() - 4].to_string(), true)
    } else {
        (filename, false)
    }
}

pub(crate) fn action_tar_flash(
    repartition: bool,
    verbose: bool,
    wait: bool,
    usb_log_level: &str,
    skip_size_check: bool,
    pit: Option<&str>,
    packages: &[String],
) -> i32 {
    // MD5 verification of .tar.md5 packages
    for pkg in packages {
        if pkg.to_lowercase().ends_with(".md5")
            && let Err(e) = verify_md5_footer(pkg)
        {
            print_error!("{}", e);
            return 1;
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
                return 1;
            }
        };

        let mut archive = Archive::new(file);
        let entries = match archive.entries() {
            Ok(e) => e,
            Err(e) => {
                print_error!("Failed to read archive entries for \"{}\": {}", pkg, e);
                return 1;
            }
        };

        let mut package_entries = Vec::new();

        for entry_res in entries {
            let entry = match entry_res {
                Ok(e) => e,
                Err(e) => {
                    print_error!("Corrupted archive entry in \"{}\": {}", pkg, e);
                    return 1;
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
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(|s| normalize_basename(s).0)
                        .collect();
                    archives_download_lists.push(download_list);
                }
            } else {
                package_entries.push(IndexedEntry {
                    package_path: pkg.clone(),
                    original_name: entry_path,
                    normalized_name,
                    offset,
                    size,
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
            return 1;
        }
        Some(first)
    } else {
        None
    };

    let mut resolved_entries: HashMap<String, IndexedEntry> = HashMap::new();

    // Apply manifest filtering and positional precedence (last-writer-wins)
    for package_entries in all_packages_entries {
        for entry in package_entries {
            if entry.normalized_name.ends_with(".pit") {
                // PIT files are always retained
                resolved_entries.insert(entry.normalized_name.clone(), entry);
            } else if let Some(allowlist) = download_allowlist {
                if allowlist.contains(&entry.normalized_name) {
                    resolved_entries.insert(entry.normalized_name.clone(), entry);
                } else {
                    println!(
                        "Skipping {} (not in download-list.txt)",
                        entry.original_name
                    );
                }
            } else {
                resolved_entries.insert(entry.normalized_name.clone(), entry);
            }
        }
    }

    // Extract PIT local bytes if any
    let mut local_pit_file = None;

    if let Some(pit_path) = pit {
        // Explicit PIT file passed via CLI takes precedence
        let mut f = match File::open(pit_path) {
            Ok(file) => file,
            Err(_) => {
                print_error!("Failed to open explicit PIT file \"{}\"", pit_path);
                return 1;
            }
        };
        let mut buffer = Vec::new();
        if f.read_to_end(&mut buffer).is_ok() {
            local_pit_file = Some(buffer);
        } else {
            print_error!("Failed to read explicit PIT file.");
            return 1;
        }
    } else {
        // Fallback to discovering the PIT file inside the TAR archives
        let local_pit_entry = resolved_entries
            .values()
            .find(|e| e.normalized_name.ends_with(".pit"));
        if let Some(entry) = local_pit_entry {
            let f = match File::open(&entry.package_path) {
                Ok(file) => file,
                Err(_) => {
                    print_error!(
                        "Failed to open package containing PIT \"{}\"",
                        entry.package_path
                    );
                    return 1;
                }
            };
            match TarEntryReader::new(f, entry.offset, entry.size) {
                Ok(reader) => {
                    let mut buffer = vec![0u8; entry.size as usize];
                    let mut r = reader;
                    if r.read_exact(&mut buffer).is_ok() {
                        local_pit_file = Some(buffer);
                    }
                }
                Err(_) => {
                    print_error!("Failed to extract PIT from archive");
                    return 1;
                }
            }
        }
    }

    if repartition && local_pit_file.is_none() {
        print_error!("If you wish to repartition then a PIT file must be provided.");
        return 1;
    }

    let (odin_manager, pit_data) = match crate::flash::init_session_and_get_pit(
        verbose,
        wait,
        usb_log_level,
        local_pit_file.as_deref(),
    ) {
        Ok(res) => res,
        Err(code) => return code,
    };

    // Map files to partition records
    let mut partition_infos = Vec::new();
    let mut mapped_partition_ids = HashSet::new();

    for entry in resolved_entries.values() {
        if entry.normalized_name.ends_with(".pit") {
            continue;
        }

        let pit_entry = pit_data.entries.iter().find(|e| {
            let flash_fn = e.flash_filename.to_string_lossy();
            flash_fn.eq_ignore_ascii_case(&entry.normalized_name)
        });

        let Some(pit_entry) = pit_entry else {
            println!(
                "Skipping orphan file \"{}\" (no matching partition in PIT)",
                entry.original_name
            );
            continue;
        };

        // Partition ID Deduplication: keep only final physical partition ID mapping
        if !mapped_partition_ids.insert(pit_entry.identifier) {
            partition_infos.retain(|info: &FirmwareInfo| match info {
                FirmwareInfo::Normal(f) => f.pit_entry.identifier != pit_entry.identifier,
                FirmwareInfo::Lz4(f) => f.pit_entry.identifier != pit_entry.identifier,
            });
        }

        let pkg_file = match File::open(&entry.package_path) {
            Ok(f) => f,
            Err(_) => {
                print_error!("Failed to open package file \"{}\"", entry.package_path);
                return 1;
            }
        };

        let reader = match TarEntryReader::new(pkg_file, entry.offset, entry.size) {
            Ok(r) => r,
            Err(_) => {
                print_error!("Failed to seek to TAR entry \"{}\"", entry.original_name);
                return 1;
            }
        };

        let mut source = FirmwareSource::Tar(reader);

        // Parse LZ4 header if it is LZ4
        let is_lz4 = if entry.is_lz4 {
            match Lz4FrameHeader::from_read(&mut source) {
                Ok(header) => Some(header),
                Err(e) => {
                    print_error!(
                        "Failed to parse LZ4 header for {}: {}",
                        entry.original_name,
                        e
                    );
                    return 1;
                }
            }
        } else {
            None
        };

        // LZ4 compatibility check
        if is_lz4.is_some() && !odin_manager.is_lz4_supported() {
            print_error!(
                "Device does not support LZ4 compression, but file \"{}\" is LZ4 compressed.",
                entry.original_name
            );
            return 1;
        }

        // Size check
        if !skip_size_check {
            let partition_size = pit_entry.partition_size();
            let check_size = if let Some(ref h) = is_lz4 {
                h.content_size
            } else {
                entry.size
            };

            if partition_size > 0 && check_size > partition_size {
                print_error!(
                    "{} partition is too small for given file. Use --skip-size-check to flash anyways.",
                    pit_entry.partition_name
                );
                return 1;
            }
        }

        if let Some(header) = is_lz4 {
            partition_infos.push(FirmwareInfo::Lz4(FirmwareLz4File {
                pit_entry,
                file: source,
                header,
            }));
        } else {
            partition_infos.push(FirmwareInfo::Normal(FirmwareFile {
                pit_entry,
                file: source,
                file_size: entry.size,
            }));
        }
    }

    crate::flash::execute_flash_pipeline(
        odin_manager,
        &pit_data,
        partition_infos,
        repartition,
        local_pit_file.as_deref(),
    )
}
