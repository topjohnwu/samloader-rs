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
use crate::decoder::{ZipCheckpoint, ZipEntryReader};
use crate::error::{Error, Result};
use crate::stream::{Checkpoint, ResumableAsyncRead, ResumableStream};
use rawzip::{CompressionMethod, ReaderAt, ZipArchiveEntryWayfinder, ZipLocator};
use std::io;
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};

// Covers max 65,535-byte ZIP comment + 22-byte EOCD + 20-byte ZIP64 Locator + 56-byte ZIP64 EOCD.
const TAIL_FETCH_BYTES: u64 = 65_536 + 128;
const MAX_CD_PREFIX_BYTES: u64 = 64 * 1024 * 1024;
const LOCAL_HEADER_FIXED_SIZE: usize = 30;

static NEXT_ARCHIVE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Compression {
    Stored,
    Deflate,
}

/// Metadata for a single file entry parsed from a [`ZipArchive`] Central Directory.
#[derive(Debug, Clone)]
pub struct ZipEntry {
    archive_id: u64,
    name: String,
    compression: Compression,
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
    id: u64,
    source: S,
    raw: rawzip::ZipArchive<OffsetSlice>,
    entries: Vec<ZipEntry>,
}

impl<S: DataSource> ZipArchive<S> {
    /// Reads and parses the trailing ZIP / ZIP64 Central Directory from `source`.
    pub async fn open(source: S) -> Result<Self> {
        let archive_len = source.size();
        let tail_start = archive_len.saturating_sub(TAIL_FETCH_BYTES);
        let tail_len = (archive_len - tail_start) as usize;

        let mut tail = vec![0u8; tail_len];
        if source.read_at(&mut tail, tail_start).await? != tail_len {
            return Err(Error::InvalidArchive("truncated ZIP archive tail".into()));
        }

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
            *raw.get_mut() = OffsetSlice {
                base: cd_offset,
                bytes: full,
            };
        }

        let id = NEXT_ARCHIVE_ID.fetch_add(1, Ordering::Relaxed);
        let entries = parse_entries(&raw, &mut scratch, id)?;
        *raw.get_mut() = OffsetSlice::default();

        Ok(Self {
            id,
            source,
            raw,
            entries,
        })
    }

    /// Lists all file entries in Central Directory order (directory entries ending in `/` are skipped).
    pub fn entries(&self) -> &[ZipEntry] {
        &self.entries
    }

    /// Reads the 30-byte Local File Header for `entry` to resolve its exact payload offset
    /// and returns a [`ZipEntryStream`].
    pub async fn open_entry<'a>(&'a self, entry: &'a ZipEntry) -> Result<ZipEntryStream<'a, S>> {
        if entry.archive_id != self.id {
            return Err(Error::InvalidArchive(format!(
                "ZIP entry '{}' does not belong to this archive",
                entry.name
            )));
        }

        let archive_len = self.source.size();
        if entry
            .local_header_offset
            .checked_add(LOCAL_HEADER_FIXED_SIZE as u64)
            .is_none_or(|end| end > archive_len)
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

        if data_end > archive_len {
            return Err(Error::InvalidArchive(format!(
                "compressed payload out of bounds for '{}'",
                entry.name
            )));
        }

        Ok(ZipEntryStream {
            source: &self.source,
            entry,
            data_offset,
        })
    }
}

fn parse_entries(
    raw: &rawzip::ZipArchive<OffsetSlice>,
    scratch: &mut [u8],
    archive_id: u64,
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

        let compression = match rec.compression_method() {
            CompressionMethod::STORE => Compression::Stored,
            CompressionMethod::DEFLATE => Compression::Deflate,
            other => {
                return Err(Error::InvalidArchive(format!(
                    "unsupported ZIP compression method {other} for '{name}'"
                )));
            }
        };

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
            archive_id,
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
pub struct ZipEntryStream<'a, S: DataSource> {
    source: &'a S,
    entry: &'a ZipEntry,
    data_offset: u64,
}

impl<'a, S: DataSource> ZipEntryStream<'a, S> {
    /// Metadata of the opened ZIP entry.
    pub fn entry(&self) -> &'a ZipEntry {
        self.entry
    }

    fn compressed_range_from(&self, comp_offset: u64) -> Range<u64> {
        let compressed_size = self.entry.compressed_size();
        let clamped = comp_offset.min(compressed_size);
        self.data_offset + clamped..self.data_offset + compressed_size
    }
}

impl<'s, S: DataSource> ResumableStream for ZipEntryStream<'s, S> {
    type Checkpoint = ZipCheckpoint;

    fn output_size(&self) -> u64 {
        self.entry.uncompressed_size()
    }

    fn source_size(&self) -> u64 {
        self.entry.compressed_size()
    }

    fn resume_dict_len(&self, checkpoint: &ZipCheckpoint) -> Option<usize> {
        checkpoint.resume_dict_len(
            self.entry.compression,
            self.entry.compressed_size(),
            self.entry.uncompressed_size(),
        )
    }

    async fn open(&self) -> io::Result<impl ResumableAsyncRead<Checkpoint = ZipCheckpoint>> {
        let reader = self
            .source
            .fetch_range(self.compressed_range_from(0))
            .await?;
        ZipEntryReader::new(
            reader,
            self.entry.compression,
            self.entry.crc32,
            self.entry.uncompressed_size(),
        )
    }

    async fn resume<'a>(
        &'a self,
        checkpoint: &ZipCheckpoint,
        dict: &[u8],
    ) -> io::Result<impl ResumableAsyncRead<Checkpoint = ZipCheckpoint> + use<'a, 's, S>> {
        // Validate checkpoint before opening a source range request.
        if self.resume_dict_len(checkpoint).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid or incompatible stream checkpoint metadata",
            ));
        }
        let reader = self
            .source
            .fetch_range(self.compressed_range_from(checkpoint.source_offset()))
            .await?;
        ZipEntryReader::resume(
            reader,
            self.entry.compression,
            self.entry.crc32,
            self.entry.compressed_size(),
            self.entry.uncompressed_size(),
            *checkpoint,
            dict,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parallel::ParallelDataSource;
    use crate::test_util::{block_on_tokio, compress_multi_block};
    use futures::executor::block_on;
    use futures::io::AsyncReadExt;
    use rawzip::extra_fields::ExtraFieldId;
    use rawzip::path::EntryPath;
    use rawzip::{Header, ZipArchiveWriter};
    use std::io::Write;

    #[test]
    fn test_zip_archive_streaming_and_large_central_directory() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ZipArchive<Vec<u8>>>();

        let bl_data = b"bootloader raw stored payload";
        let ap_data: Vec<u8> = (0..96_000).map(|i| (i * 31) as u8).collect();
        let ap_deflated = compress_multi_block(&ap_data, &[16 * 1024]);

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

        block_on_tokio(async {
            let source = ParallelDataSource::new(zip_bytes, 4);
            let archive = ZipArchive::open(&source).await.unwrap();
            assert_eq!(archive.entries().len(), 2);
            assert_eq!(archive.entries()[0].name(), "BL_test.tar.md5");
            assert_eq!(archive.entries()[1].name(), "AP_test.tar.md5");

            let bl_stream = archive.open_entry(&archive.entries()[0]).await.unwrap();
            let ap_stream = archive.open_entry(&archive.entries()[1]).await.unwrap();
            assert_eq!(ap_stream.output_size(), ap_data.len() as u64);
            assert_eq!(ap_stream.source_size(), ap_deflated.len() as u64);

            // Full AsyncRead via open()
            let mut out = Vec::new();
            ap_stream
                .open()
                .await
                .unwrap()
                .read_to_end(&mut out)
                .await
                .unwrap();
            assert_eq!(out, ap_data);

            // Mid-entry checkpoint + resume() for Stored entry
            let mut bl_reader = bl_stream.open().await.unwrap();
            let mut head = [0u8; 10];
            let n = bl_reader.read(&mut head).await.unwrap();
            assert_eq!(n, 10);
            let cp = bl_reader
                .checkpoint()
                .expect("Stored reader exposes checkpoint");
            assert_eq!(bl_stream.resume_dict_len(&cp), Some(0));
            let mut resumed_bl = head[..n].to_vec();
            bl_stream
                .resume(&cp, &[])
                .await
                .unwrap()
                .read_to_end(&mut resumed_bl)
                .await
                .unwrap();
            assert_eq!(resumed_bl, bl_data);

            // Mid-entry checkpoint + resume() for Deflate entry
            let mut ap_reader = ap_stream.open().await.unwrap();
            let mut partial = Vec::new();
            let mut buf = vec![0u8; 8192];
            let cp = loop {
                let n = ap_reader.read(&mut buf).await.unwrap();
                assert!(n > 0);
                partial.extend_from_slice(&buf[..n]);
                if let Some(cp) = ap_reader.checkpoint() {
                    break cp;
                }
            };
            let uncomp = cp.output_offset() as usize;
            let dict_len = ap_stream.resume_dict_len(&cp).unwrap();
            let mut resumed_ap = partial[..uncomp].to_vec();
            ap_stream
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
        let assert_invalid = |bytes: &[u8]| {
            block_on(async {
                let err = ZipArchive::open(bytes).await.err().unwrap();
                assert!(matches!(err, Error::InvalidArchive(_)));
            });
        };

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
            assert_invalid(&zip_bytes);
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
        assert_invalid(&dup_bytes);

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
        assert_invalid(&zstd_bytes);

        // Entry belonging to a different ZipArchive must be rejected
        let mut valid_zip = Vec::new();
        let mut writer = ZipArchiveWriter::new(&mut valid_zip);
        let (mut entry, config) = writer.new_file("BL_test.tar.md5").start().unwrap();
        let mut w = config.wrap(&mut entry);
        w.write_all(b"x").unwrap();
        let (_, desc) = w.finish().unwrap();
        entry.finish(desc).unwrap();
        writer.finish().unwrap();

        block_on(async {
            let archive_a = ZipArchive::open(valid_zip.as_slice()).await.unwrap();
            let archive_b = ZipArchive::open(valid_zip.as_slice()).await.unwrap();
            let err = archive_a
                .open_entry(&archive_b.entries()[0])
                .await
                .err()
                .unwrap();
            assert!(matches!(err, Error::InvalidArchive(_)));
        });
    }
}
