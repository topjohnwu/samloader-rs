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

//! Streaming ZIP / ZIP64 Central Directory indexing and entry access over any [`DataSource`].

use crate::data::DataSource;
use crate::decoder::{StreamCheckpoint, StreamDecoder, ZipEntryReader};
use crate::error::{Error, Result};
use rawzip::{CompressionMethod, ReaderAt, ZipArchiveEntryWayfinder, ZipLocator};
use std::io;
use std::ops::Range;

// Covers max 65,535-byte ZIP comment + 22-byte EOCD + 20-byte ZIP64 Locator + 56-byte ZIP64 EOCD.
const TAIL_FETCH_BYTES: u64 = 65_536 + 128;
const MAX_CD_PREFIX_BYTES: u64 = 64 * 1024 * 1024;
const LOCAL_HEADER_FIXED_SIZE: usize = 30;

/// Recognized Samsung Odin firmware component of an archive entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OdinComponent {
    /// Bootloader component (`BL_*`).
    Bl,
    /// Application processor / system component (`AP_*`, `CODE_*`, `PDA_*`, or `*_HOME.tar*`).
    Ap,
    /// Modem / baseband component (`CP_*`, `MODEM_*`, `PHONE_*`).
    Cp,
    /// Clean-flash region/carrier configuration component (`CSC_*`).
    Csc,
    /// Non-wiping region/carrier configuration component (`HOME_CSC_*`).
    HomeCsc,
    /// Carrier/user data component (`USERDATA_*`).
    Userdata,
}

impl OdinComponent {
    /// Classifies an archive entry file name by its Samsung prefix, if recognized.
    pub fn from_entry_name(name: &str) -> Option<Self> {
        let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
        let upper = base.to_ascii_uppercase();

        if upper.starts_with("HOME_CSC_") {
            Some(Self::HomeCsc)
        } else if upper.starts_with("CSC_") {
            Some(Self::Csc)
        } else if upper.starts_with("BL_") || upper.starts_with("BOOTLOADER_") {
            Some(Self::Bl)
        } else if upper.starts_with("AP_")
            || upper.starts_with("CODE_")
            || upper.starts_with("PDA_")
        {
            Some(Self::Ap)
        } else if upper.starts_with("CP_")
            || upper.starts_with("MODEM_")
            || upper.starts_with("PHONE_")
        {
            Some(Self::Cp)
        } else if upper.starts_with("USERDATA_") {
            Some(Self::Userdata)
        } else if upper.ends_with("_HOME.TAR.MD5") || upper.ends_with("_HOME.TAR") {
            Some(Self::Ap)
        } else {
            None
        }
    }
}

/// Metadata for a single file entry parsed from a [`ZipArchive`] Central Directory.
#[derive(Debug, Clone)]
pub struct ZipEntry {
    name: String,
    compression: CompressionMethod,
    crc32: u32,
    local_header_offset: u64,
    wayfinder: ZipArchiveEntryWayfinder,
}

impl ZipEntry {
    /// Sanitized file name inside the archive (guaranteed single normal path component).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Compressed payload size in bytes.
    pub fn compressed_size(&self) -> u64 {
        self.wayfinder.compressed_size_hint()
    }

    /// Uncompressed payload size in bytes.
    pub fn uncompressed_size(&self) -> u64 {
        self.wayfinder.uncompressed_size_hint()
    }

    /// Validates `checkpoint` against this entry and returns the number of trailing
    /// uncompressed bytes (ending at `checkpoint.uncompressed_offset()`) required as
    /// the decompression dictionary for [`ZipEntrySession::resume`].
    ///
    /// Returns `None` if `checkpoint` is out of bounds or incompatible with this
    /// entry's compression method.
    pub fn resume_dict_len(&self, checkpoint: &StreamCheckpoint) -> Option<usize> {
        checkpoint.resume_dict_len(
            self.compression,
            self.compressed_size(),
            self.uncompressed_size(),
        )
    }
}

/// Non-zero-based byte window delegating [`ReaderAt`] to `rawzip`'s `[u8]` implementation.
#[derive(Clone, Default)]
struct OffsetSlice {
    base: u64,
    bytes: Vec<u8>,
}

impl ReaderAt for OffsetSlice {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        match offset.checked_sub(self.base) {
            Some(rel) => ReaderAt::read_at(&self.bytes, buf, rel),
            None => Err(io::Error::from(io::ErrorKind::InvalidInput)),
        }
    }
}

fn map_zip_error(err: rawzip::Error) -> Error {
    match err.into_kind() {
        rawzip::ErrorKind::IO(io_err) => Error::Io(io_err),
        other => Error::InvalidArchive(other.to_string()),
    }
}

/// Parsed Central Directory index over any [`DataSource`].
pub struct ZipArchive<S: DataSource> {
    source: S,
    archive_len: u64,
    raw: rawzip::ZipArchive<OffsetSlice>,
    entries: Vec<ZipEntry>,
}

impl<S: DataSource> ZipArchive<S> {
    /// Reads and parses the trailing ZIP / ZIP64 Central Directory from `source`.
    pub async fn open(source: S) -> Result<Self> {
        let max_size = source.size_bounds().1;
        let tail_start = max_size.saturating_sub(TAIL_FETCH_BYTES);
        let max_tail = (max_size - tail_start) as usize;

        let mut tail = vec![0u8; max_tail];
        let n = source.read_at(&mut tail, tail_start).await?;
        tail.truncate(n);

        let archive_len = tail_start + tail.len() as u64;
        let locator = ZipLocator::new().max_search_space(TAIL_FETCH_BYTES);
        let mut scratch = vec![0u8; rawzip::MAX_CENTRAL_DIRECTORY_RECORD_SIZE];

        let mut raw = locator
            .locate_in_reader(
                OffsetSlice {
                    base: tail_start,
                    bytes: tail,
                },
                &mut scratch,
                archive_len,
            )
            .map_err(|(_, e)| map_zip_error(e))?;

        let cd_offset = raw.directory_offset();
        if cd_offset < tail_start {
            let prefix_len = tail_start - cd_offset;
            if prefix_len > MAX_CD_PREFIX_BYTES {
                return Err(Error::InvalidArchive(
                    "Central Directory exceeds maximum supported size".into(),
                ));
            }
            let prefix_usize = usize::try_from(prefix_len).map_err(|_| {
                Error::InvalidArchive("Central Directory exceeds address space".into())
            })?;
            let tail = std::mem::take(&mut raw.get_mut().bytes);
            let mut full = vec![0u8; prefix_usize + tail.len()];
            if source.read_at(&mut full[..prefix_usize], cd_offset).await? != prefix_usize {
                return Err(Error::InvalidArchive(
                    "truncated ZIP Central Directory".into(),
                ));
            }
            full[prefix_usize..].copy_from_slice(&tail);
            raw = locator
                .locate_in_reader(
                    OffsetSlice {
                        base: cd_offset,
                        bytes: full,
                    },
                    &mut scratch,
                    archive_len,
                )
                .map_err(|(_, e)| map_zip_error(e))?;
        }

        let entries = parse_entries(&raw, &mut scratch)?;
        *raw.get_mut() = OffsetSlice::default();

        Ok(Self {
            source,
            archive_len,
            raw,
            entries,
        })
    }

    /// Lists all file entries in Central Directory order (directory entries ending in `/` are skipped).
    pub fn entries(&self) -> &[ZipEntry] {
        &self.entries
    }

    /// Reads the 30-byte Local File Header for `entry` to resolve its exact payload offset
    /// and returns a [`ZipEntrySession`].
    pub async fn open_entry<'a>(&'a self, entry: &'a ZipEntry) -> Result<ZipEntrySession<'a, S>> {
        if entry
            .local_header_offset
            .checked_add(LOCAL_HEADER_FIXED_SIZE as u64)
            .is_none_or(|end| end > self.archive_len)
        {
            return Err(Error::InvalidArchive(format!(
                "local file header offset out of bounds for '{}'",
                entry.name
            )));
        }

        let mut lh = vec![0u8; LOCAL_HEADER_FIXED_SIZE];
        if self
            .source
            .read_at(&mut lh, entry.local_header_offset)
            .await?
            != lh.len()
        {
            return Err(Error::InvalidArchive(format!(
                "truncated Local File Header for '{}'",
                entry.name
            )));
        }

        let mut raw = self.raw.clone();
        *raw.get_mut() = OffsetSlice {
            base: entry.local_header_offset,
            bytes: lh,
        };
        let raw_entry = raw.get_entry(entry.wayfinder).map_err(map_zip_error)?;
        let (data_offset, data_end) = raw_entry.compressed_data_range();

        if data_end > self.archive_len {
            return Err(Error::InvalidArchive(format!(
                "compressed payload out of bounds for '{}'",
                entry.name
            )));
        }

        Ok(ZipEntrySession {
            source: &self.source,
            entry,
            data_offset,
        })
    }
}

fn parse_entries(
    raw: &rawzip::ZipArchive<OffsetSlice>,
    scratch: &mut [u8],
) -> Result<Vec<ZipEntry>> {
    let mut entries: Vec<ZipEntry> = Vec::new();
    let mut parsed_count = 0u64;
    let mut iter = raw.entries(scratch);

    while let Some(rec) = iter.next_entry().map_err(map_zip_error)? {
        parsed_count += 1;

        let name = std::str::from_utf8(rec.file_path().as_bytes())
            .map_err(|_| Error::InvalidArchive("non-UTF-8 ZIP entry name".into()))?;

        if rec.is_dir() && rec.uncompressed_size_hint() == 0 && rec.compressed_size_hint() == 0 {
            continue;
        }

        let flags = rec.flags();
        if flags.is_encrypted() || flags.has_strong_encryption() {
            return Err(Error::InvalidArchive(
                "encrypted ZIP entry not supported".into(),
            ));
        }

        let compression = rec.compression_method();
        if !matches!(
            compression,
            CompressionMethod::STORE | CompressionMethod::DEFLATE
        ) {
            return Err(Error::InvalidArchive(format!(
                "unsupported ZIP compression method {compression} for '{name}'"
            )));
        }

        if name.is_empty() || name.contains(['/', '\\', '\0', ':']) || name == "." || name == ".." {
            return Err(Error::InvalidArchive(format!(
                "unsafe ZIP entry path: {name}"
            )));
        }

        if entries.iter().any(|e| e.name.eq_ignore_ascii_case(name)) {
            return Err(Error::InvalidArchive(format!(
                "duplicate ZIP entry name: {name}"
            )));
        }

        entries.push(ZipEntry {
            name: name.to_owned(),
            compression,
            crc32: rec.crc32(),
            local_header_offset: rec.local_header_offset(),
            wayfinder: rec.wayfinder(),
        });
    }

    if parsed_count != raw.entries_hint() {
        return Err(Error::InvalidArchive(format!(
            "Central Directory entry count mismatch: expected {}, found {parsed_count}",
            raw.entries_hint()
        )));
    }

    Ok(entries)
}

/// Handle to a resolved entry inside a [`ZipArchive`], providing transparent and
/// resumable async streaming over the underlying [`DataSource`].
pub struct ZipEntrySession<'a, S: DataSource> {
    source: &'a S,
    entry: &'a ZipEntry,
    data_offset: u64,
}

impl<'a, S: DataSource> ZipEntrySession<'a, S> {
    /// Metadata of the opened ZIP entry.
    pub fn entry(&self) -> &'a ZipEntry {
        self.entry
    }

    fn compressed_range_from(&self, comp_offset: u64) -> Range<u64> {
        let compressed_size = self.entry.compressed_size();
        let clamped = comp_offset.min(compressed_size);
        self.data_offset + clamped..self.data_offset + compressed_size
    }

    /// Transparently streams, decompresses, and CRC-verifies the entire entry over `S`.
    pub async fn fetch(&self) -> io::Result<ZipEntryReader<'a>> {
        let decoder = StreamDecoder::new(
            self.entry.compression,
            self.entry.crc32,
            self.entry.uncompressed_size(),
        )?;
        let source: &'a S = self.source;
        let reader = source.fetch_range(self.compressed_range_from(0)).await?;
        Ok(decoder.into_reader(Box::new(reader)))
    }

    /// Resumes streaming, decompressing, and CRC-verifying this entry from `checkpoint`.
    ///
    /// `dict` must contain at least `entry.resume_dict_len(checkpoint)` trailing
    /// uncompressed bytes ending at `checkpoint.uncompressed_offset()`.
    pub async fn resume(
        &self,
        checkpoint: &StreamCheckpoint,
        dict: &[u8],
    ) -> io::Result<ZipEntryReader<'a>> {
        let decoder = StreamDecoder::resume(
            self.entry.compression,
            self.entry.crc32,
            self.entry.compressed_size(),
            self.entry.uncompressed_size(),
            *checkpoint,
            dict,
        )?;
        let source: &'a S = self.source;
        let reader = source
            .fetch_range(self.compressed_range_from(checkpoint.compressed_offset()))
            .await?;
        Ok(decoder.into_reader(Box::new(reader)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parallel::ParallelDataSource;
    use futures::executor::block_on;
    use futures::io::AsyncReadExt;
    use rawzip::extra_fields::ExtraFieldId;
    use rawzip::path::EntryPath;
    use rawzip::{Header, ZipArchiveWriter};
    use std::io::Write;
    use zlib_rs::{Deflate, DeflateFlush, Status};

    fn raw_deflate_multi_block(data: &[u8]) -> Vec<u8> {
        let mut def = Deflate::new(6, false, 15);
        let mut out = vec![0u8; zlib_rs::compress_bound(data.len()) + 512];
        let mut in_off = 0usize;
        let mut out_off = 0usize;
        while in_off < data.len() {
            let chunk = (16 * 1024).min(data.len() - in_off);
            let is_last = in_off + chunk == data.len();
            let prev_in = def.total_in();
            let prev_out = def.total_out();
            let flush = if is_last {
                DeflateFlush::Finish
            } else {
                DeflateFlush::Block
            };
            let status = def
                .compress(&data[in_off..in_off + chunk], &mut out[out_off..], flush)
                .unwrap();
            in_off += (def.total_in() - prev_in) as usize;
            out_off += (def.total_out() - prev_out) as usize;
            if is_last {
                assert_eq!(status, Status::StreamEnd);
            }
        }
        out.truncate(out_off);
        out
    }

    #[test]
    fn test_odin_component_classification() {
        assert_eq!(
            OdinComponent::from_entry_name("BL_S931U1UES1AXB2.tar.md5"),
            Some(OdinComponent::Bl)
        );
        assert_eq!(
            OdinComponent::from_entry_name("AP_S931U1UEU1AXB2.tar.md5"),
            Some(OdinComponent::Ap)
        );
        assert_eq!(
            OdinComponent::from_entry_name("CP_S931U1UEU1AXB2.tar.md5"),
            Some(OdinComponent::Cp)
        );
        assert_eq!(
            OdinComponent::from_entry_name("CSC_OYM_S931U1OYM1AXB2.tar.md5"),
            Some(OdinComponent::Csc)
        );
        assert_eq!(
            OdinComponent::from_entry_name("HOME_CSC_OYM_S931U1OYM1AXB2.tar.md5"),
            Some(OdinComponent::HomeCsc)
        );
        assert_eq!(
            OdinComponent::from_entry_name("USERDATA_XAA_S931U1.tar.md5"),
            Some(OdinComponent::Userdata)
        );
        assert_eq!(
            OdinComponent::from_entry_name("I9305XXUEML8_I9305QLBEML4_HOME.tar.md5"),
            Some(OdinComponent::Ap)
        );
        assert_eq!(OdinComponent::from_entry_name("SS_DL.dll"), None);
    }

    #[test]
    fn test_zip_archive_streaming_and_large_central_directory() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ZipArchive<Vec<u8>>>();

        let bl_data = b"bootloader raw stored payload";
        let ap_data: Vec<u8> = (0..96_000).map(|i| (i * 31) as u8).collect();
        let ap_deflated = raw_deflate_multi_block(&ap_data);

        let mut zip_bytes = Vec::new();
        let mut writer = ZipArchiveWriter::new(&mut zip_bytes);
        let custom_id = ExtraFieldId::new(0xCAFE);
        let pad_extra = vec![0u8; 40_000];

        // Directory entry (should be skipped)
        writer.new_dir("meta/").create().unwrap();

        // Stored entry + large Central Directory extra field
        let (mut entry, config) = writer
            .new_file("BL_test.tar.md5")
            .extra_field(custom_id, &pad_extra, Header::CENTRAL)
            .unwrap()
            .extra_field(custom_id, b"local-only", Header::LOCAL)
            .unwrap()
            .start()
            .unwrap();
        let mut w = config.wrap(&mut entry);
        w.write_all(bl_data).unwrap();
        let (_, desc) = w.finish().unwrap();
        entry.finish(desc).unwrap();

        // Deflate entry + second 40 KiB Central Directory extra field so total CD > TAIL_FETCH_BYTES
        let (mut entry, config) = writer
            .new_file("AP_test.tar.md5")
            .compression_method(CompressionMethod::DEFLATE)
            .extra_field(custom_id, &pad_extra, Header::CENTRAL)
            .unwrap()
            .start()
            .unwrap();
        entry.write_all(&ap_deflated).unwrap();
        let mut w = config.wrap(io::sink());
        w.write_all(&ap_data).unwrap();
        let (_, desc) = w.finish().unwrap();
        entry.finish(desc).unwrap();

        writer.finish().unwrap();
        assert!(zip_bytes.len() as u64 > TAIL_FETCH_BYTES);

        block_on(async {
            let source = ParallelDataSource::new(zip_bytes, 4);
            let archive = ZipArchive::open(&source).await.unwrap();
            assert_eq!(archive.entries().len(), 2);
            assert_eq!(
                OdinComponent::from_entry_name(archive.entries()[0].name()),
                Some(OdinComponent::Bl)
            );
            assert_eq!(
                OdinComponent::from_entry_name(archive.entries()[1].name()),
                Some(OdinComponent::Ap)
            );

            let bl_sess = archive.open_entry(&archive.entries()[0]).await.unwrap();
            let ap_sess = archive.open_entry(&archive.entries()[1]).await.unwrap();

            // Full AsyncRead via fetch()
            let mut out = Vec::new();
            ap_sess
                .fetch()
                .await
                .unwrap()
                .read_to_end(&mut out)
                .await
                .unwrap();
            assert_eq!(out, ap_data);

            // Mid-entry checkpoint + resume() for Stored entry
            let mut bl_reader = bl_sess.fetch().await.unwrap();
            let mut head = [0u8; 10];
            let (n, cp) = bl_reader.read_chunk(&mut head, true).await.unwrap();
            assert_eq!(n, 10);
            let cp = cp.expect("Stored read_chunk returns checkpoint");
            assert_eq!(bl_sess.entry().resume_dict_len(&cp), Some(0));
            let mut resumed_bl = head[..n].to_vec();
            bl_sess
                .resume(&cp, &[])
                .await
                .unwrap()
                .read_to_end(&mut resumed_bl)
                .await
                .unwrap();
            assert_eq!(resumed_bl, bl_data);

            // Mid-entry checkpoint + resume() for Deflate entry
            let mut ap_reader = ap_sess.fetch().await.unwrap();
            let mut partial = Vec::new();
            let mut buf = vec![0u8; 8192];
            let cp = loop {
                let (n, cp) = ap_reader.read_chunk(&mut buf, true).await.unwrap();
                assert!(n > 0);
                partial.extend_from_slice(&buf[..n]);
                if let Some(cp) = cp {
                    break cp;
                }
            };
            let uncomp = cp.uncompressed_offset() as usize;
            let dict_len = ap_sess.entry().resume_dict_len(&cp).unwrap();
            let mut resumed_ap = partial[..uncomp].to_vec();
            ap_sess
                .resume(&cp, &partial[uncomp - dict_len..uncomp])
                .await
                .unwrap()
                .read_to_end(&mut resumed_ap)
                .await
                .unwrap();
            assert_eq!(resumed_ap, ap_data);
        });
    }

    #[test]
    fn test_entry_validation_rejects_invalid_archives() {
        for bad_name in [&b"../evil"[..], b"/abs", b"sub/file"] {
            let mut zip_bytes = Vec::new();
            let mut writer = ZipArchiveWriter::new(&mut zip_bytes);
            let (mut entry, config) = writer
                .new_file(EntryPath::verbatim(bad_name))
                .start()
                .unwrap();
            let mut w = config.wrap(&mut entry);
            w.write_all(b"x").unwrap();
            let (_, desc) = w.finish().unwrap();
            entry.finish(desc).unwrap();
            writer.finish().unwrap();

            block_on(async {
                let err = ZipArchive::open(zip_bytes.as_slice()).await.err().unwrap();
                assert!(matches!(err, Error::InvalidArchive(_)));
            });
        }

        // Duplicate entry names (case-insensitive) must be rejected
        let mut dup_bytes = Vec::new();
        let mut writer = ZipArchiveWriter::new(&mut dup_bytes);
        for name in ["BL_test.tar.md5", "bl_test.tar.md5"] {
            let (mut entry, config) = writer.new_file(name).start().unwrap();
            let mut w = config.wrap(&mut entry);
            w.write_all(b"x").unwrap();
            let (_, desc) = w.finish().unwrap();
            entry.finish(desc).unwrap();
        }
        writer.finish().unwrap();
        block_on(async {
            let err = ZipArchive::open(dup_bytes.as_slice()).await.err().unwrap();
            assert!(matches!(err, Error::InvalidArchive(_)));
        });

        // Unsupported compression method must be rejected
        let mut zstd_bytes = Vec::new();
        let mut writer = ZipArchiveWriter::new(&mut zstd_bytes);
        let (mut entry, config) = writer
            .new_file("BL_zstd.tar.md5")
            .compression_method(CompressionMethod::ZSTD)
            .start()
            .unwrap();
        let mut w = config.wrap(&mut entry);
        w.write_all(b"x").unwrap();
        let (_, desc) = w.finish().unwrap();
        entry.finish(desc).unwrap();
        writer.finish().unwrap();

        block_on(async {
            let err = ZipArchive::open(zstd_bytes.as_slice()).await.err().unwrap();
            assert!(matches!(err, Error::InvalidArchive(_)));
        });
    }
}
