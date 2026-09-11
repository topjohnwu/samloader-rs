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

use crate::FlashError;
use crate::firmware::{
    FirmwareFile, FirmwareInfo, FirmwareLz4File, Lz4FrameHeader, verify_md5_footer,
};
use crate::odin::OdinSession;
use crate::progress::{self, FlashEvent};
use memmap2::{Mmap, MmapOptions};
use samloader_pit::{PitData, PitEntry};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use tar::Archive;

struct IndexedEntry<'a> {
    original_name: String,
    normalized_name: String,
    file: &'a File,
    offset: u64,
    size: u64,
    is_lz4: bool,
}

impl<'a> IndexedEntry<'a> {
    fn map(&self) -> Result<Mmap, FlashError> {
        // SAFETY: The archive file is opened read-only and is assumed not to be
        // concurrently modified or truncated during the flashing operation.
        let mmap = unsafe {
            MmapOptions::new()
                .offset(self.offset)
                .len(self.size as usize)
                .map(self.file)
        }
        .map_err(|e| FlashError::MmapFailed(self.original_name.clone(), e))?;
        Ok(mmap)
    }
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
) -> Result<FirmwareInfo<'a>, FlashError> {
    let lz4_frame_header = if is_lz4_suffix {
        let cursor = std::io::Cursor::new(&mmap);
        match Lz4FrameHeader::parse(cursor) {
            Ok(fh) => Some(fh),
            Err(e) => {
                return Err(FlashError::Lz4Header(file_display_name.to_string(), e));
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
            return Err(FlashError::PartitionTooSmall(
                pit_entry.partition_name.to_string_lossy().into_owned(),
            ));
        }
    }

    if let Some(header) = lz4_frame_header {
        Ok(FirmwareInfo::Lz4(FirmwareLz4File {
            pit_entry,
            file: mmap,
            header,
        }))
    } else {
        Ok(FirmwareInfo::Normal(FirmwareFile {
            pit_entry,
            file: mmap,
        }))
    }
}

/// Orchestrates the flashing pipeline, processing package and partition sources
/// and executing the Loke flash protocol.
pub struct FlashManager<'a> {
    session: &'a mut OdinSession,
    pit_file_bytes: Option<Vec<u8>>,

    repartition: bool,
    auto_reboot: bool,
    skip_size_check: bool,
    skip_md5: bool,
    pit_path: Option<&'a str>,
    packages: Vec<String>,
    partitions: Vec<(Option<String>, String)>,
    super_used_size: Option<u32>,
    has_download_list: bool,
    sales_code: Option<&'a str>,
}

impl<'a> FlashManager<'a> {
    /// Creates a new `FlashManager` associated with an active `OdinSession`.
    pub fn new(session: &'a mut OdinSession) -> Self {
        Self {
            session,
            pit_file_bytes: None,
            repartition: false,
            auto_reboot: false,
            skip_size_check: false,
            skip_md5: false,
            pit_path: None,
            packages: Vec::new(),
            partitions: Vec::new(),
            super_used_size: None,
            has_download_list: false,
            sales_code: None,
        }
    }

    /// Sets an optional 3-letter CSC / Sales Code to configure on the device.
    pub fn sales_code(mut self, sales_code: Option<&'a str>) -> Self {
        self.sales_code = sales_code;
        self
    }

    /// Sets whether to perform repartitioning.
    pub fn repartition(mut self, enabled: bool) -> Self {
        self.repartition = enabled;
        self
    }

    /// Sets whether to automatically reboot after flashing.
    pub fn auto_reboot(mut self, enabled: bool) -> Self {
        self.auto_reboot = enabled;
        self
    }

    /// Sets whether to skip partition size checks.
    pub fn skip_size_check(mut self, enabled: bool) -> Self {
        self.skip_size_check = enabled;
        self
    }

    /// Sets whether to skip MD5 package verification.
    pub fn skip_md5(mut self, enabled: bool) -> Self {
        self.skip_md5 = enabled;
        self
    }

    /// Sets an explicit PIT file path.
    pub fn pit(mut self, pit_path: &'a str) -> Self {
        self.pit_path = Some(pit_path);
        self
    }

    /// Sets the list of TAR packages to flash.
    pub fn packages(mut self, packages: &[impl AsRef<str>]) -> Self {
        self.packages = packages.iter().map(|p| p.as_ref().to_string()).collect();
        self
    }

    /// Sets the list of individual partition files to flash.
    pub fn partitions(mut self, partitions: &[(Option<String>, String)]) -> Self {
        self.partitions = partitions.to_vec();
        self
    }

    /// Executes the flashing pipeline sequence.
    pub fn execute(&mut self) -> Result<(), FlashError> {
        // Step 0: Set device sales code if configured
        if let Some(sales_code) = self.sales_code {
            progress::println(&format!("Setting device sales code to {}...", sales_code));
            self.session.set_sales_code(sales_code)?;
        }

        // If no packages, partitions, or explicit PIT are specified, complete session and return
        if self.packages.is_empty() && self.partitions.is_empty() && self.pit_path.is_none() {
            if self.auto_reboot {
                self.session.reboot_device()?;
            } else {
                self.session.end_session()?;
            }
            return Ok(());
        }

        // Step 1: Resolve explicit PIT file if provided
        if let Some(pit_path) = self.pit_path {
            let mut f = File::open(pit_path)
                .map_err(|e| FlashError::FileOpenFailed(pit_path.to_string(), e))?;
            let mut buffer = Vec::new();
            f.read_to_end(&mut buffer)
                .map_err(|e| FlashError::FileReadFailed(pit_path.to_string(), e))?;
            self.pit_file_bytes = Some(buffer);
        }

        // Step 2: Open packages and scan TAR containers to index entries
        let opened_packages = self.open_and_verify_packages()?;
        let resolved_entries = self.scan_tar_packages(&opened_packages)?;

        // Step 3: Handle repartitioning and download active PIT data from the device
        let pit_data = self.download_and_parse_pit(self.repartition)?;

        // Step 4: Map entries and individual files to FirmwareInfo payloads
        let partition_infos = self.build_partition_infos(
            &pit_data,
            resolved_entries,
            &self.partitions,
            self.skip_size_check,
        )?;

        // Step 5: Flash payloads to the device
        self.flash_partitions(partition_infos, self.auto_reboot)?;

        Ok(())
    }

    // Helper 1: Open TAR packages and optionally verify MD5 footers
    fn open_and_verify_packages(&self) -> Result<Vec<(String, File)>, FlashError> {
        if self.packages.is_empty() {
            return Ok(Vec::new());
        }

        let mut opened_packages = Vec::new();
        for pkg in &self.packages {
            let file = File::open(pkg).map_err(|e| FlashError::FileOpenFailed(pkg.clone(), e))?;
            opened_packages.push((pkg.clone(), file));
        }

        if !self.skip_md5 {
            for (pkg, file) in &mut opened_packages {
                if pkg.to_lowercase().ends_with(".md5") {
                    verify_md5_footer(&*file, pkg)
                        .map_err(|e| FlashError::Md5VerificationFailed(pkg.clone(), e))?;

                    file.seek(SeekFrom::Start(0))
                        .map_err(|e| FlashError::FileSeekFailed(pkg.clone(), e))?;
                }
            }
        }

        Ok(opened_packages)
    }

    // Helper 2: Scan TAR packages to find resolved entries and pull package PIT if needed
    fn scan_tar_packages<'p>(
        &mut self,
        opened_packages: &'p [(String, File)],
    ) -> Result<Vec<IndexedEntry<'p>>, FlashError> {
        if opened_packages.is_empty() {
            return Ok(Vec::new());
        }

        // Scan and index TAR containers
        let mut archives_download_lists: Vec<HashSet<String>> = Vec::new();
        let mut all_packages_entries: Vec<Vec<IndexedEntry<'p>>> = Vec::new();

        for (pkg, file) in opened_packages {
            let mut archive = Archive::new(file);
            let entries = archive
                .entries()
                .map_err(|e| FlashError::ArchiveReadFailed(pkg.clone(), e))?;

            let mut package_entries = Vec::new();

            for entry_res in entries {
                let entry = entry_res.map_err(|e| FlashError::ArchiveCorrupted(pkg.clone(), e))?;

                let entry_path = match entry.path() {
                    Ok(p) => p.to_string_lossy().to_string(),
                    Err(_) => continue,
                };

                let offset = entry.raw_file_position();
                let size = entry.size();

                let (normalized_name, is_lz4) = normalize_basename(&entry_path);

                if normalized_name == "download-list.txt" {
                    self.has_download_list = true;
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
                } else if normalized_name == "super_used_size.txt" {
                    let mut reader = entry;
                    let mut content = String::new();
                    if reader.read_to_string(&mut content).is_ok()
                        && let Ok(val) = content.trim().parse::<u32>()
                    {
                        self.super_used_size = Some(val);
                    }
                } else {
                    package_entries.push(IndexedEntry {
                        original_name: entry_path,
                        normalized_name,
                        file,
                        offset,
                        size,
                        is_lz4,
                    });
                }
            }

            all_packages_entries.push(package_entries);
        }

        // If any package contained a manifest, we use it as our global download allowlist
        let download_allowlist = if let Some((first, rest)) = archives_download_lists.split_first()
        {
            // Cross-archive manifest consistency check
            if !rest.iter().all(|m| m == first) {
                return Err(FlashError::CrossArchiveInconsistency);
            }
            Some(first)
        } else {
            None
        };

        let mut resolved_entries: Vec<IndexedEntry<'p>> = Vec::new();
        let mut pit_entry: Option<IndexedEntry<'p>> = None;

        // Apply manifest filtering and positional precedence (last-writer-wins)
        for package_entries in all_packages_entries {
            for entry in package_entries {
                if entry.normalized_name.ends_with(".pit") {
                    pit_entry = Some(entry);
                } else if let Some(allowlist) = download_allowlist {
                    if allowlist.contains(&entry.normalized_name) {
                        resolved_entries.push(entry);
                    } else {
                        progress::println(&format!(
                            "Skipping {} (not in download-list.txt)",
                            entry.original_name
                        ));
                    }
                } else {
                    resolved_entries.push(entry);
                }
            }
        }

        // Extract PIT local bytes if any from TAR archives and set internal field if still None
        if self.pit_file_bytes.is_none()
            && let Some(entry) = pit_entry
        {
            let mmap = entry.map()?;
            self.pit_file_bytes = Some(mmap.to_vec());
        }

        Ok(resolved_entries)
    }

    // Helper 3: Download and parse active PIT data
    fn download_and_parse_pit(&mut self, repartition: bool) -> Result<PitData, FlashError> {
        if repartition && self.pit_file_bytes.is_none() {
            return Err(FlashError::RepartitionPitRequired);
        }

        if repartition {
            progress::println("Flashing PIT");
            self.session
                .send_pit_data(self.pit_file_bytes.as_ref().unwrap())?;
            progress::println("PIT flash successful\n");
        }

        progress::println("Downloading device's PIT file");
        let pit_buffer = self.session.download_pit_file()?;

        let pit_data = PitData::new(&pit_buffer).map_err(FlashError::PitUnpackFailed)?;
        Ok(pit_data)
    }

    // Helper 4: Map package entries and individual files into FirmwareInfo
    fn build_partition_infos<'c>(
        &self,
        pit_data: &'c PitData,
        resolved_entries: Vec<IndexedEntry<'_>>,
        partitions: &[(Option<String>, String)],
        skip_size_check: bool,
    ) -> Result<Vec<FirmwareInfo<'c>>, FlashError> {
        enum PartitionSource<'p> {
            Archive(IndexedEntry<'p>),
            File { path: String, is_lz4: bool },
        }

        struct PlannedPartition<'p, 'pit> {
            pit_entry: &'pit PitEntry,
            source: PartitionSource<'p>,
        }

        let mut planned_partitions = Vec::new();

        // 1. Collect candidate entries from TAR packages
        for entry in resolved_entries {
            let Some(pit_entry) = find_pit_entry_by_filename(pit_data, &entry.normalized_name)
            else {
                progress::println(&format!(
                    "Skipping orphan file \"{}\" (no matching partition in PIT)",
                    entry.original_name
                ));
                continue;
            };

            planned_partitions.push(PlannedPartition {
                pit_entry,
                source: PartitionSource::Archive(entry),
            });
        }

        // 2. Collect candidate individual files
        for (part_name, part_filename) in partitions {
            let (filename, is_lz4_suffix) = normalize_basename(part_filename);
            let entry = match part_name {
                None => {
                    let Some(entry) = find_pit_entry_by_filename(pit_data, &filename) else {
                        return Err(FlashError::PartitionNotFound(part_filename.clone()));
                    };
                    entry
                }
                Some(name) => {
                    if let Ok(id) = name.parse::<u32>() {
                        let Some(entry) = pit_data.find_entry_by_id(id) else {
                            return Err(FlashError::PartitionIdNotFound(id));
                        };
                        entry
                    } else {
                        let Some(entry) = pit_data.find_entry_by_name(name) else {
                            return Err(FlashError::PartitionNotFound(name.clone()));
                        };
                        entry
                    }
                }
            };

            planned_partitions.push(PlannedPartition {
                pit_entry: entry,
                source: PartitionSource::File {
                    path: part_filename.clone(),
                    is_lz4: is_lz4_suffix,
                },
            });
        }

        // 3. Partition deduplication: last writer wins
        let mut mapped_partition_ids = HashSet::new();
        let mut unique_planned = Vec::new();
        for planned in planned_partitions.into_iter().rev() {
            if mapped_partition_ids.insert(planned.pit_entry.identifier) {
                unique_planned.push(planned);
            }
        }
        unique_planned.reverse();

        // 4. Lazily map and build FirmwareInfo only for unique planned partitions
        let mut unique_partition_infos = Vec::with_capacity(unique_planned.len());
        for planned in unique_planned {
            let (mmap, file_size, is_lz4, display_name) = match planned.source {
                PartitionSource::Archive(entry) => {
                    let mmap = entry.map()?;
                    (mmap, entry.size, entry.is_lz4, entry.original_name)
                }
                PartitionSource::File { path, is_lz4 } => {
                    let (mmap, file_size) = File::open(&path)
                        .and_then(|f| {
                            let file_size = f.metadata()?.len();
                            // SAFETY: The partition file is opened read-only and is assumed not to be
                            // concurrently modified or truncated during the flashing operation.
                            let mmap =
                                unsafe { MmapOptions::new().len(file_size as usize).map(&f)? };
                            Ok((mmap, file_size))
                        })
                        .map_err(|e| FlashError::MmapFailed(path.clone(), e))?;
                    (mmap, file_size, is_lz4, path)
                }
            };

            let info = create_firmware_info(
                mmap,
                file_size,
                is_lz4,
                planned.pit_entry,
                skip_size_check,
                &display_name,
            )?;
            unique_partition_infos.push(info);
        }

        Ok(unique_partition_infos)
    }

    // Helper 5: Flash deduplicated partition payloads to the device
    fn flash_partitions(
        &mut self,
        partition_infos: Vec<FirmwareInfo<'_>>,
        reboot_device: bool,
    ) -> Result<(), FlashError> {
        let total_bytes: u64 = partition_infos
            .iter()
            .map(|part| match part {
                FirmwareInfo::Normal(f) => f.file.len() as u64,
                FirmwareInfo::Lz4(f) => f.header.content_size,
            })
            .sum();

        self.session.set_total_bytes(total_bytes)?;

        if let Some(super_used_size) = self.super_used_size
            && super_used_size > 0
            && self.session.bootloader_protocol_version() >= 3
        {
            let check_size = if self.has_download_list {
                super_used_size
            } else {
                0
            };
            progress::println("Checking available super partition size...");
            self.session
                .check_super_size(check_size)
                .map_err(FlashError::SuperSizeCheckFailed)?;
        }

        for info in partition_infos {
            let name = match &info {
                FirmwareInfo::Normal(f) => f.pit_entry.partition_name.to_string_lossy(),
                FirmwareInfo::Lz4(f) => f.pit_entry.partition_name.to_string_lossy(),
            };

            let partition_size = match &info {
                FirmwareInfo::Normal(f) => f.file.len() as u64,
                FirmwareInfo::Lz4(f) => f.header.content_size,
            };

            progress::on_event(FlashEvent::PartitionStart {
                name: &name,
                size: partition_size,
            });

            let res = match info {
                FirmwareInfo::Normal(f) => self.session.send_file(&f),
                FirmwareInfo::Lz4(f) => self.session.send_lz4_file(&f),
            };

            if let Err(e) = res {
                progress::on_event(FlashEvent::PartitionFail(&name));
                return Err(FlashError::Odin(e));
            }

            progress::on_event(FlashEvent::PartitionEnd(&name));
        }

        self.session.end_session()?;

        if reboot_device {
            self.session.reboot_device()?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::odin::OdinConnection;
    use crate::usb::MockBackend;

    #[test]
    fn test_scan_tar_packages_metadata_and_manifest() {
        let temp_dir = std::env::temp_dir().join("samloader_test_tar");
        let _ = std::fs::create_dir_all(&temp_dir);
        let tar_path = temp_dir.join("test_package.tar");

        {
            let tar_file = File::create(&tar_path).unwrap();
            let mut builder = tar::Builder::new(tar_file);

            // 1. Add meta-data/super_used_size.txt
            let mut header = tar::Header::new_gnu();
            let size_content = b"27276104\n";
            header.set_size(size_content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    "meta-data/super_used_size.txt",
                    &size_content[..],
                )
                .unwrap();

            // 2. Add meta-data/download-list.txt
            let mut header = tar::Header::new_gnu();
            let list_content = b"boot.img\n";
            header.set_size(list_content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    "meta-data/download-list.txt",
                    &list_content[..],
                )
                .unwrap();

            // 3. Add boot.img
            let mut header = tar::Header::new_gnu();
            let boot_content = b"DUMMY BOOT IMAGE DATA";
            header.set_size(boot_content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "boot.img", &boot_content[..])
                .unwrap();

            builder.finish().unwrap();
        }

        let backend = Box::new(MockBackend::new(false));
        let mut connection = OdinConnection::new(backend);
        connection.init().unwrap();
        let mut session = connection.begin_session().unwrap();

        let tar_file = File::open(&tar_path).unwrap();
        let opened_packages = vec![(tar_path.to_string_lossy().to_string(), tar_file)];

        let mut manager = FlashManager::new(&mut session);
        let resolved = manager.scan_tar_packages(&opened_packages).unwrap();

        assert_eq!(manager.super_used_size, Some(27276104));
        assert!(manager.has_download_list);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].normalized_name, "boot.img");

        let _ = std::fs::remove_file(tar_path);
        let _ = std::fs::remove_dir(temp_dir);
    }

    #[test]
    fn test_flash_partitions_super_size_preflight_success() {
        let backend = Box::new(MockBackend::new(false).with_protocol_version(3));
        let mut connection = OdinConnection::new(backend);
        connection.init().unwrap();
        let mut session = connection.begin_session().unwrap();

        let mut manager = FlashManager::new(&mut session);
        manager.super_used_size = Some(27276104);
        manager.has_download_list = true;

        assert!(manager.flash_partitions(Vec::new(), false).is_ok());
    }

    #[test]
    fn test_flash_partitions_super_size_preflight_rejection() {
        let backend = Box::new(
            MockBackend::new(false)
                .with_protocol_version(3)
                .with_fail_check_super_size(-1),
        );
        let mut connection = OdinConnection::new(backend);
        connection.init().unwrap();
        let mut session = connection.begin_session().unwrap();

        let mut manager = FlashManager::new(&mut session);
        manager.super_used_size = Some(27276104);
        manager.has_download_list = true;

        let res = manager.flash_partitions(Vec::new(), false);
        assert!(matches!(res, Err(FlashError::SuperSizeCheckFailed(_))));
    }

    #[test]
    fn test_flash_partitions_super_size_preflight_skipped_on_legacy_protocol() {
        // Even if fail_check_super_size is set, legacy protocol version 2 must skip opcode 0x6a
        let backend = Box::new(
            MockBackend::new(false)
                .with_protocol_version(2)
                .with_fail_check_super_size(-1),
        );
        let mut connection = OdinConnection::new(backend);
        connection.init().unwrap();
        let mut session = connection.begin_session().unwrap();

        let mut manager = FlashManager::new(&mut session);
        manager.super_used_size = Some(27276104);
        manager.has_download_list = true;

        assert!(manager.flash_partitions(Vec::new(), false).is_ok());
    }

    #[test]
    fn test_flash_manager_standalone_sales_code() {
        let backend = Box::new(MockBackend::new(false));
        let mut connection = OdinConnection::new(backend);
        connection.init().unwrap();
        let mut session = connection.begin_session().unwrap();

        let mut manager = FlashManager::new(&mut session).sales_code(Some("TUR"));
        assert!(manager.execute().is_ok());
    }
}
