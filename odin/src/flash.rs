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
    FirmwareFile, FirmwareInfo, FirmwareLz4File, Lz4FrameHeader, expanded_android_image_size,
    verify_md5_footer,
};
use crate::lp::inspect_super_firmware_info;
use crate::odin::OdinSession;
use crate::progress::{self, FlashEvent};
use lz4_flex::frame::FrameDecoder;
use memmap2::{Mmap, MmapOptions};
use samloader_pit::{PitData, PitEntry};
use std::collections::{HashMap, HashSet};
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
    prevalidated_expanded_size: Option<u64>,
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

    let expanded_size = if let Some(size) = prevalidated_expanded_size {
        size
    } else if let Some(fh) = &lz4_frame_header {
        expanded_android_image_size(FrameDecoder::new(&mmap[..]), fh.content_size)
            .map_err(|e| FlashError::ImageSize(file_display_name.to_string(), e))?
    } else {
        expanded_android_image_size(&mmap[..], source_size)
            .map_err(|e| FlashError::ImageSize(file_display_name.to_string(), e))?
    };

    if !skip_size_check {
        let partition_size = pit_entry.partition_size();

        if partition_size > 0 && expanded_size > partition_size {
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
            expanded_size,
        }))
    } else {
        Ok(FirmwareInfo::Normal(FirmwareFile {
            pit_entry,
            file: mmap,
            expanded_size,
        }))
    }
}

/// Specifies the device reboot behavior after a flash session concludes.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum RebootMode {
    /// Do not reboot the device; end the session and remain in download mode.
    #[default]
    None,
    /// Reboot the device normally out of Download Mode.
    Normal,
    /// Reboot the device back into Download Mode.
    Download,
}

/// One partition selected by an offline firmware preflight.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreflightPartition {
    /// PIT partition name.
    pub name: String,
    /// Filename expected by the PIT for this partition.
    pub flash_filename: String,
    /// Logical bytes that will be written after decompression.
    pub image_size: u64,
    /// Capacity of the target partition according to the supplied PIT.
    pub partition_size: u64,
}

/// Results from an offline firmware preflight.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreflightReport {
    /// Deduplicated partitions selected for flashing, in transfer order.
    pub partitions: Vec<PreflightPartition>,
    /// Whether Samsung download-list metadata controlled archive selection.
    pub has_download_list: bool,
}

/// Orchestrates the flashing pipeline, processing package and partition sources
/// and executing the Loke flash protocol.
pub struct FlashManager<'a> {
    session: Option<&'a mut OdinSession>,
    pit_file_bytes: Option<Vec<u8>>,

    reboot_mode: RebootMode,
    skip_size_check: bool,
    skip_md5: bool,
    pit_path: Option<&'a str>,
    packages: Vec<String>,
    partitions: Vec<(Option<String>, String)>,
    super_used_size: Option<u32>,
    has_download_list: bool,
    prevalidated_sizes: HashMap<String, u64>,
    sales_code: Option<&'a str>,
    erase: bool,
}

impl<'a> FlashManager<'a> {
    /// Creates a new `FlashManager` associated with an active `OdinSession`.
    pub fn new(session: &'a mut OdinSession) -> Self {
        Self {
            session: Some(session),
            pit_file_bytes: None,
            reboot_mode: RebootMode::None,
            skip_size_check: false,
            skip_md5: false,
            pit_path: None,
            packages: Vec::new(),
            partitions: Vec::new(),
            super_used_size: None,
            has_download_list: false,
            prevalidated_sizes: HashMap::new(),
            sales_code: None,
            erase: false,
        }
    }

    /// Creates a manager for a strictly offline preflight with no device session.
    pub fn new_offline() -> Self {
        Self {
            session: None,
            pit_file_bytes: None,
            reboot_mode: RebootMode::None,
            skip_size_check: false,
            skip_md5: false,
            pit_path: None,
            packages: Vec::new(),
            partitions: Vec::new(),
            super_used_size: None,
            has_download_list: false,
            prevalidated_sizes: HashMap::new(),
            sales_code: None,
            erase: false,
        }
    }

    /// Validates packages, resolves their payloads against an explicit local PIT,
    /// and checks every logical image size without opening a USB device.
    pub fn preflight(&mut self) -> Result<PreflightReport, FlashError> {
        let pit_path = self.pit_path.ok_or(FlashError::PitRequiredForPreflight)?;
        let mut pit_bytes = Vec::new();
        File::open(pit_path)
            .map_err(|e| FlashError::FileOpenFailed(pit_path.to_string(), e))?
            .read_to_end(&mut pit_bytes)
            .map_err(|e| FlashError::FileReadFailed(pit_path.to_string(), e))?;
        self.pit_file_bytes = Some(pit_bytes.clone());

        let opened_packages = self.open_and_verify_packages()?;
        let resolved_entries = self.scan_tar_packages(&opened_packages)?;
        let pit_data = PitData::new(&pit_bytes).map_err(FlashError::PitUnpackFailed)?;
        let partition_infos =
            self.build_partition_infos(&pit_data, resolved_entries, &self.partitions, false)?;

        let partitions = partition_infos
            .iter()
            .map(|info| {
                let (entry, image_size) = match info {
                    FirmwareInfo::Normal(f) => (f.pit_entry, f.expanded_size),
                    FirmwareInfo::Lz4(f) => (f.pit_entry, f.expanded_size),
                };
                PreflightPartition {
                    name: entry.partition_name.to_string_lossy().into_owned(),
                    flash_filename: entry.flash_filename.to_string_lossy().into_owned(),
                    image_size,
                    partition_size: entry.partition_size(),
                }
            })
            .collect();

        Ok(PreflightReport {
            partitions,
            has_download_list: self.has_download_list,
        })
    }

    /// Sets whether to perform a low-level NAND hardware erase on the `USERDATA` partition
    /// prior to flashing or as a standalone wipe operation.
    pub fn erase(mut self, enabled: bool) -> Self {
        self.erase = enabled;
        self
    }

    /// Sets an optional 3-letter CSC / Sales Code to configure on the device.
    pub fn sales_code(mut self, sales_code: Option<&'a str>) -> Self {
        self.sales_code = sales_code;
        self
    }

    /// Sets the reboot mode to perform after flashing completes.
    pub fn reboot_mode(mut self, mode: RebootMode) -> Self {
        self.reboot_mode = mode;
        self
    }

    /// Sets whether to automatically reboot normally out of Download Mode after flashing.
    pub fn auto_reboot(mut self, enabled: bool) -> Self {
        self.reboot_mode = if enabled {
            RebootMode::Normal
        } else {
            RebootMode::None
        };
        self
    }

    /// Sets whether to reboot the device back into Download Mode after flashing.
    pub fn redownload(mut self, enabled: bool) -> Self {
        if enabled {
            self.reboot_mode = RebootMode::Download;
        }
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

    /// Reuses expanded image sizes established by a successful offline preflight in the
    /// same process. This avoids lengthy LZ4 decompression while a live Odin session is idle.
    pub fn prevalidated(mut self, report: &PreflightReport) -> Self {
        self.prevalidated_sizes = report
            .partitions
            .iter()
            .map(|part| (part.name.clone(), part.image_size))
            .collect();
        self
    }

    /// Executes the flashing pipeline sequence.
    pub fn execute(&mut self) -> Result<(), FlashError> {
        let session = self
            .session
            .as_deref_mut()
            .expect("device execution requires an Odin session");

        // Step 0: Set device sales code if configured
        if let Some(sales_code) = self.sales_code {
            progress::println(&format!("Setting device sales code to {}...", sales_code));
            session.set_sales_code(sales_code)?;
        }

        // If no packages, partitions, or explicit PIT are specified, complete session and return
        if self.packages.is_empty() && self.partitions.is_empty() && self.pit_path.is_none() {
            if self.erase {
                session.nand_erase()?;
            }
            match self.reboot_mode {
                RebootMode::Normal => session.reboot_device()?,
                RebootMode::Download => session.reboot_to_download()?,
                RebootMode::None => session.end_session()?,
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

        // Step 3: Flash PIT if available and download active PIT data from the device
        let pit_data = self.download_and_parse_pit()?;

        // Step 4: Map entries and individual files to FirmwareInfo payloads
        let partition_infos = self.build_partition_infos(
            &pit_data,
            resolved_entries,
            &self.partitions,
            self.skip_size_check,
        )?;

        // Auto-detect super_used_size if not specified in TAR metadata
        if self.super_used_size.is_none()
            && let Some(super_info) = partition_infos.iter().find(|info| {
                let entry = match info {
                    FirmwareInfo::Normal(f) => f.pit_entry,
                    FirmwareInfo::Lz4(f) => f.pit_entry,
                };
                entry.partition_name == "SUPER"
                    || entry
                        .flash_filename
                        .to_string_lossy()
                        .eq_ignore_ascii_case("super.img")
            })
        {
            self.super_used_size = inspect_super_firmware_info(super_info);
        }

        // Step 5: Flash payloads to the device
        self.flash_partitions(partition_infos, self.reboot_mode)?;

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
                    // Read the allowlist manifest
                    let mut reader = entry;
                    let mut content = String::new();
                    reader
                        .read_to_string(&mut content)
                        .map_err(|e| FlashError::ArchiveCorrupted(pkg.clone(), e))?;

                    self.has_download_list = true;
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
                } else if normalized_name == "super_used_size.txt" {
                    let mut reader = entry;
                    let mut content = String::new();
                    reader
                        .read_to_string(&mut content)
                        .map_err(|e| FlashError::ArchiveCorrupted(pkg.clone(), e))?;
                    let val = content.trim().parse::<u32>().map_err(|e| {
                        FlashError::ArchiveCorrupted(
                            pkg.clone(),
                            std::io::Error::new(std::io::ErrorKind::InvalidData, e),
                        )
                    })?;
                    self.super_used_size = Some(val);
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

        // Never silently combine an explicit repartition layout with a package built for a
        // different layout. If no explicit PIT was supplied, retain the package PIT as before.
        if let Some(entry) = pit_entry {
            let mmap = entry.map()?;
            if let Some(explicit_pit) = &self.pit_file_bytes {
                if explicit_pit.as_slice() != &mmap[..] {
                    return Err(FlashError::PitMismatch(entry.original_name));
                }
            } else {
                self.pit_file_bytes = Some(mmap.to_vec());
            }
        }

        Ok(resolved_entries)
    }

    // Helper 3: Flash PIT if available and download active PIT data
    fn download_and_parse_pit(&mut self) -> Result<PitData, FlashError> {
        let session = self
            .session
            .as_deref_mut()
            .expect("PIT transfer requires an Odin session");
        if self.erase {
            session.nand_erase()?;
        }

        if let Some(pit_bytes) = &self.pit_file_bytes {
            progress::println("Flashing PIT");
            session.send_pit_info(pit_bytes)?;
            progress::println("PIT flash successful\n");
        }

        progress::println("Downloading device's PIT file");
        let pit_buffer = session.receive_pit_info()?;

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
            if mapped_partition_ids.insert(planned.pit_entry.partition_id) {
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
                self.prevalidated_sizes
                    .get(planned.pit_entry.partition_name.to_string_lossy().as_ref())
                    .copied(),
            )?;
            unique_partition_infos.push(info);
        }

        Ok(unique_partition_infos)
    }

    // Helper 5: Flash deduplicated partition payloads to the device
    fn flash_partitions(
        &mut self,
        partition_infos: Vec<FirmwareInfo<'_>>,
        reboot_mode: RebootMode,
    ) -> Result<(), FlashError> {
        let session = self
            .session
            .as_deref_mut()
            .expect("partition flashing requires an Odin session");
        let total_bytes: u64 = partition_infos
            .iter()
            .map(|part| match part {
                FirmwareInfo::Normal(f) => f.file.len() as u64,
                FirmwareInfo::Lz4(f) => f.header.content_size,
            })
            .sum();

        session.set_total_bytes(total_bytes)?;

        if let Some(super_used_size) = self.super_used_size
            && super_used_size > 0
            && session.bootloader_protocol_version() >= 3
        {
            let check_size = if self.has_download_list || self.packages.is_empty() {
                super_used_size
            } else {
                0
            };
            progress::println("Checking available super partition size...");
            session
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
                FirmwareInfo::Normal(f) => session.send_file(&f),
                FirmwareInfo::Lz4(f) => session.send_lz4_file(&f),
            };

            if let Err(e) = res {
                progress::on_event(FlashEvent::PartitionFail(&name));
                return Err(FlashError::Odin(e));
            }

            progress::on_event(FlashEvent::PartitionEnd(&name));
        }

        session.end_session()?;

        match reboot_mode {
            RebootMode::Normal => {
                session.reboot_device()?;
            }
            RebootMode::Download => {
                session.reboot_to_download()?;
            }
            RebootMode::None => {}
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

        assert!(
            manager
                .flash_partitions(Vec::new(), RebootMode::None)
                .is_ok()
        );
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

        let res = manager.flash_partitions(Vec::new(), RebootMode::None);
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

        assert!(
            manager
                .flash_partitions(Vec::new(), RebootMode::None)
                .is_ok()
        );
    }

    #[test]
    fn test_scan_tar_packages_corrupt_manifest_fails() {
        let temp_dir = std::env::temp_dir().join("samloader_test_tar_corrupt_manifest");
        let _ = std::fs::create_dir_all(&temp_dir);
        let tar_path = temp_dir.join("corrupt_manifest.tar");

        {
            let tar_file = File::create(&tar_path).unwrap();
            let mut builder = tar::Builder::new(tar_file);

            // Add meta-data/download-list.txt with invalid UTF-8 bytes
            let mut header = tar::Header::new_gnu();
            let corrupt_content = [0xFF, 0xFE, 0xFD];
            header.set_size(corrupt_content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    "meta-data/download-list.txt",
                    &corrupt_content[..],
                )
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
        let result = manager.scan_tar_packages(&opened_packages);

        assert!(matches!(result, Err(FlashError::ArchiveCorrupted(_, _))));

        let _ = std::fs::remove_file(tar_path);
        let _ = std::fs::remove_dir(temp_dir);
    }

    #[test]
    fn test_explicit_pit_must_match_package_pit() {
        let temp_dir =
            std::env::temp_dir().join(format!("samloader_test_pit_match_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let tar_path = temp_dir.join("package.tar");
        let pit_bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-data/M3_EUR_OPEN_4G.pit"
        ));

        {
            let tar_file = File::create(&tar_path).unwrap();
            let mut builder = tar::Builder::new(tar_file);
            let mut header = tar::Header::new_gnu();
            header.set_size(pit_bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "layout.pit", &pit_bytes[..])
                .unwrap();
            builder.finish().unwrap();
        }

        let tar_file = File::open(&tar_path).unwrap();
        let opened_packages = vec![(tar_path.to_string_lossy().to_string(), tar_file)];
        let mut matching = FlashManager::new_offline();
        matching.pit_file_bytes = Some(pit_bytes.to_vec());
        assert!(matching.scan_tar_packages(&opened_packages).is_ok());

        let tar_file = File::open(&tar_path).unwrap();
        let opened_packages = vec![(tar_path.to_string_lossy().to_string(), tar_file)];
        let mut mismatching = FlashManager::new_offline();
        mismatching.pit_file_bytes = Some(vec![0u8; pit_bytes.len()]);
        let result = mismatching.scan_tar_packages(&opened_packages);
        assert!(matches!(result, Err(FlashError::PitMismatch(_))));

        let _ = std::fs::remove_file(tar_path);
        let _ = std::fs::remove_dir(temp_dir);
    }

    #[test]
    fn test_download_and_parse_pit_flashes_available_pit() {
        let backend = Box::new(MockBackend::new(false));
        let mut connection = OdinConnection::new(backend);
        connection.init().unwrap();
        let mut session = connection.begin_session().unwrap();

        let mut manager = FlashManager::new(&mut session);
        manager.pit_file_bytes = Some(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/test-data/M3_EUR_OPEN_4G.pit"
            ))
            .to_vec(),
        );

        let pit_data = manager.download_and_parse_pit().unwrap();
        // M3_EUR_OPEN_4G.pit has Mx-MDM, verifying PIT was sent and updated device state
        assert_eq!(pit_data.cpu_bl_id.to_string_lossy(), "Mx-MDM");
    }
}
