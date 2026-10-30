// Copyright 2026 John "topjohnwu" Wu
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

//! TAR firmware packages: MD5 footer verification and indexing of their files.

use super::tar::TarArchive;
use crate::FlashError;
use crate::progress::{self, FlashEvent};
use fast_md5::Md5;
use futures::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt};
use std::collections::HashSet;
use std::io::{self, SeekFrom};
use std::path::Path;

/// Verifies the trailing MD5 checksum appended to `.tar.md5` package files.
pub async fn verify_md5_footer<R: AsyncRead + AsyncSeek + Unpin>(
    mut reader: R,
    name: &str,
) -> io::Result<()> {
    let file_size = reader.seek(SeekFrom::End(0)).await?;

    if file_size < 34 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "File is too small to contain a valid MD5 footer",
        ));
    }

    // Read the last 512 bytes of the file. Since the TAR file must end with at least
    // two blocks of zeroes, the last null byte (0x00) marks the exact boundary
    // between the TAR payload and the appended plain-text MD5 footer.
    let seek_pos = file_size.saturating_sub(512);
    reader.seek(SeekFrom::Start(seek_pos)).await?;
    let mut last_bytes = vec![0u8; (file_size - seek_pos) as usize];
    reader.read_exact(&mut last_bytes).await?;

    // Find the last null byte (0x00)
    let mut last_null_idx = None;
    for i in (0..last_bytes.len()).rev() {
        if last_bytes[i] == 0 {
            last_null_idx = Some(i);
            break;
        }
    }

    let Some(null_idx) = last_null_idx else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Could not find a valid null separator for the MD5 footer",
        ));
    };

    let footer_start = null_idx + 1;
    let footer_bytes = &last_bytes[footer_start..];
    let footer_str = String::from_utf8_lossy(footer_bytes);
    let footer_line = footer_str.lines().last().unwrap_or_default();

    if footer_line.len() < 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Could not find a valid MD5 checksum at the end of the file",
        ));
    }

    let expected_hex = &footer_line[..32];
    let mut expected_bytes = [0u8; 16];
    for i in 0..16 {
        let hex_byte = &expected_hex[i * 2..i * 2 + 2];
        expected_bytes[i] = u8::from_str_radix(hex_byte, 16)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    }

    // The payload size is the exact position up to the MD5 footer text
    let payload_size = file_size - footer_line.len() as u64 - 1;

    crate::progress::on_event(FlashEvent::Md5Start {
        name,
        size: payload_size,
    });

    let res: io::Result<()> = async {
        // Reset file pointer and compute MD5 over the payload only
        reader.seek(SeekFrom::Start(0)).await?;
        let mut hasher = Md5::new();
        let mut buffer = [0u8; 128 * 1024];
        let mut remaining = payload_size;

        while remaining > 0 {
            let to_read = std::cmp::min(remaining, buffer.len() as u64) as usize;
            reader.read_exact(&mut buffer[..to_read]).await?;
            hasher.update(&buffer[..to_read]);
            crate::progress::inc(to_read as u64);
            remaining -= to_read as u64;
        }

        let calculated_digest = hasher.finalize();
        if calculated_digest != expected_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MD5 verification failed! File is corrupted or modified.",
            ));
        }

        Ok(())
    }
    .await;

    if res.is_err() {
        crate::progress::on_event(FlashEvent::Md5Fail(name));
    } else {
        crate::progress::on_event(FlashEvent::Md5End(name));
    }

    res
}

/// A file inside a TAR package.
#[derive(Clone, Debug)]
pub(crate) struct PackageEntry {
    /// Path of the file inside the archive.
    pub(crate) original_name: String,
    /// File name with any directory and `.lz4` suffix stripped.
    pub(crate) normalized_name: String,
    /// Index of the containing package.
    pub(crate) package_index: usize,
    /// Byte offset of the file's data within the package.
    pub(crate) offset: u64,
    /// Size of the file's data in bytes.
    pub(crate) size: u64,
    /// Whether the file name has a `.lz4` suffix.
    pub(crate) is_lz4: bool,
}

/// The flashable contents of a set of TAR packages, honoring `download-list.txt`.
pub(crate) struct PackageIndex {
    /// Files to consider for flashing, in package order. Metadata and PIT files
    /// are excluded.
    pub(crate) entries: Vec<PackageEntry>,
    /// Whether any package contained a `download-list.txt`.
    pub(crate) has_download_list: bool,
    /// Value of `super_used_size.txt`, if present.
    pub(crate) super_used_size: Option<u32>,
    /// The first PIT file found, if requested.
    pub(crate) pit_bytes: Option<Vec<u8>>,
}

impl PackageIndex {
    /// Indexes the files in `packages`. Readers are only accessed through
    /// absolute seeks. If `want_pit` is set, the first PIT file found is read.
    pub(crate) async fn scan<R: AsyncRead + AsyncSeek + Unpin>(
        packages: &mut [(String, R)],
        want_pit: bool,
    ) -> Result<Self, FlashError> {
        if packages.is_empty() {
            return Ok(Self {
                entries: Vec::new(),
                has_download_list: false,
                super_used_size: None,
                pit_bytes: None,
            });
        }

        let mut archives_download_lists: Vec<HashSet<String>> = Vec::new();
        let mut all_packages_entries: Vec<Vec<PackageEntry>> = Vec::new();
        let mut pit_from_tar: Option<Vec<u8>> = None;
        let mut has_download_list = false;
        let mut super_used_size = None;

        for (package_index, (pkg_name, reader)) in packages.iter_mut().enumerate() {
            let mut archive = TarArchive::new(&mut *reader);
            let mut package_entries = Vec::new();

            while let Some(mut entry) = archive
                .next_entry()
                .await
                .map_err(|e| FlashError::ArchiveCorrupted(pkg_name.clone(), e))?
            {
                let entry_path = entry.path().to_string();
                let offset = entry.raw_file_position();
                let size = entry.size();

                let (normalized_name, is_lz4) = normalize_basename(&entry_path);

                if normalized_name == "download-list.txt" {
                    let mut content = String::new();
                    entry
                        .read_to_string(&mut content)
                        .await
                        .map_err(|e| FlashError::ArchiveCorrupted(pkg_name.clone(), e))?;

                    has_download_list = true;
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
                    let mut content = String::new();
                    entry
                        .read_to_string(&mut content)
                        .await
                        .map_err(|e| FlashError::ArchiveCorrupted(pkg_name.clone(), e))?;
                    let val = content.trim().parse::<u32>().map_err(|e| {
                        FlashError::ArchiveCorrupted(
                            pkg_name.clone(),
                            io::Error::new(io::ErrorKind::InvalidData, e),
                        )
                    })?;
                    super_used_size = Some(val);
                } else if normalized_name.ends_with(".pit") {
                    if want_pit && pit_from_tar.is_none() {
                        let mut bytes = Vec::new();
                        entry
                            .read_to_end(&mut bytes)
                            .await
                            .map_err(|e| FlashError::ArchiveCorrupted(pkg_name.clone(), e))?;
                        pit_from_tar = Some(bytes);
                    }
                } else {
                    package_entries.push(PackageEntry {
                        original_name: entry_path,
                        normalized_name,
                        package_index,
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
            if !rest.iter().all(|m| m == first) {
                return Err(FlashError::CrossArchiveInconsistency);
            }
            Some(first)
        } else {
            None
        };

        let mut resolved_entries: Vec<PackageEntry> = Vec::new();

        // Apply manifest filtering and positional precedence (last-writer-wins)
        for package_entries in all_packages_entries {
            for entry in package_entries {
                if let Some(allowlist) = download_allowlist {
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

        Ok(Self {
            entries: resolved_entries,
            has_download_list,
            super_used_size,
            pit_bytes: pit_from_tar,
        })
    }
}

/// Strips the directory and `.lz4` suffix from a file name, also returning
/// whether the suffix was present.
pub(crate) fn normalize_basename(path_str: &str) -> (String, bool) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FlashProgress;
    use crate::test_util::build_tar;
    use futures::io::Cursor;
    use std::fmt::Write;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    #[derive(Clone)]
    struct TestProgress {
        started_total: Arc<AtomicU64>,
        inc_bytes: Arc<AtomicU64>,
        ended: Arc<AtomicBool>,
        failed: Arc<AtomicBool>,
    }

    impl TestProgress {
        fn new() -> Self {
            Self {
                started_total: Arc::new(AtomicU64::new(0)),
                inc_bytes: Arc::new(AtomicU64::new(0)),
                ended: Arc::new(AtomicBool::new(false)),
                failed: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    impl FlashProgress for TestProgress {
        fn set_length(&self, _len: u64) {}

        fn inc(&self, bytes: u64) {
            self.inc_bytes.fetch_add(bytes, Ordering::Relaxed);
        }

        fn on_event(&self, event: FlashEvent<'_>) {
            match event {
                FlashEvent::Md5Start {
                    size: total_bytes, ..
                } => {
                    self.started_total.store(total_bytes, Ordering::Relaxed);
                }
                FlashEvent::Md5End(_) => {
                    self.ended.store(true, Ordering::Relaxed);
                }
                FlashEvent::Md5Fail(_) => {
                    self.failed.store(true, Ordering::Relaxed);
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_verify_md5_footer_success() {
        let _guard = crate::progress::TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // Construct a synthetic TAR payload with zeroes padding and MD5 footer
        let payload = b"Hello, Odin TAR payload with some content!";
        let mut data = Vec::new();
        data.extend_from_slice(payload);
        // Null byte separating payload from MD5 footer text
        data.push(0);

        let mut hasher = Md5::new();
        hasher.update(&data);
        let digest = hasher.finalize();

        let hex_str = digest.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{:02x}", b);
            s
        });
        let footer = format!("{}  test.tar\n", hex_str);
        data.extend_from_slice(footer.as_bytes());

        let progress = TestProgress::new();
        crate::progress::set_progress(progress.clone());
        let res = futures::executor::block_on(verify_md5_footer(Cursor::new(&data), "test.tar"));
        crate::progress::clear_progress();

        assert!(res.is_ok());
        let expected_total = (payload.len() + 1) as u64;
        assert_eq!(
            progress.started_total.load(Ordering::Relaxed),
            expected_total
        );
        assert_eq!(progress.inc_bytes.load(Ordering::Relaxed), expected_total);
        assert!(progress.ended.load(Ordering::Relaxed));
        assert!(!progress.failed.load(Ordering::Relaxed));
    }

    #[test]
    fn test_verify_md5_footer_corruption() {
        let _guard = crate::progress::TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let payload = b"Hello, Odin TAR payload with some content!";
        let mut data = Vec::new();
        data.extend_from_slice(payload);
        data.push(0);

        // Intentionally wrong hash
        let footer = "0123456789abcdef0123456789abcdef  test.tar\n";
        data.extend_from_slice(footer.as_bytes());

        let progress = TestProgress::new();
        crate::progress::set_progress(progress.clone());
        let res = futures::executor::block_on(verify_md5_footer(Cursor::new(&data), "test.tar"));
        crate::progress::clear_progress();

        assert!(res.is_err());
        assert!(progress.failed.load(Ordering::Relaxed));
        assert!(!progress.ended.load(Ordering::Relaxed));
    }

    #[test]
    fn test_package_index_corrupt_manifest_fails() {
        let tar_bytes = build_tar(&[("meta-data/download-list.txt", &[0xFF, 0xFE, 0xFD])]);

        futures::executor::block_on(async {
            let mut packages = [(
                "corrupt_manifest.tar".to_string(),
                Cursor::new(tar_bytes.as_slice()),
            )];
            let result = PackageIndex::scan(&mut packages, true).await;

            assert!(matches!(result, Err(FlashError::ArchiveCorrupted(_, _))));
        });
    }

    #[test]
    fn test_package_index_filtering_and_truncation() {
        let pit_bytes = b"PIT DATA";
        let tar_bytes = build_tar(&[
            ("meta-data/download-list.txt", b"boot.img\nsuper.img\n"),
            ("meta-data/super_used_size.txt", b"12345\n"),
            ("device.pit", pit_bytes),
            ("boot.img.lz4", b"BOOT DATA"),
            ("recovery.img.lz4", b"RECOVERY DATA"),
        ]);

        futures::executor::block_on(async {
            let mut packages = [("AP.tar".to_string(), Cursor::new(tar_bytes.as_slice()))];
            let index = PackageIndex::scan(&mut packages, true).await.unwrap();
            assert!(index.has_download_list);
            // recovery.img is omitted (not in download-list), metadata & pit are omitted
            let names: Vec<_> = index.entries.iter().map(|e| &e.normalized_name).collect();
            assert_eq!(names, ["boot.img"]);
            assert!(index.entries[0].is_lz4);
            assert_eq!(index.super_used_size, Some(12345));
            assert_eq!(index.pit_bytes.as_deref(), Some(&pit_bytes[..]));

            // The PIT is only read when requested
            let index = PackageIndex::scan(&mut packages, false).await.unwrap();
            assert_eq!(index.pit_bytes, None);

            // Truncated package errors on scan
            let truncated = &tar_bytes[..tar_bytes.len() - 600];
            let mut bad_packages = [("AP.tar".to_string(), Cursor::new(truncated))];
            let res = PackageIndex::scan(&mut bad_packages, true).await;
            assert!(matches!(res, Err(FlashError::ArchiveCorrupted(pkg, _)) if pkg == "AP.tar"));
        });
    }
}
