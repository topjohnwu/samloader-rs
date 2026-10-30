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

//! Firmware images: where their bytes are stored and how to read them.

use super::lp;
use super::lz4::{self, Lz4FrameHeader};
use futures::StreamExt;
use futures::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, Cursor};
use futures::stream::{self, Stream};
use std::io::{self, SeekFrom};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Where the bytes of a firmware image are stored.
///
/// Rather than owning or borrowing a reader, `Package` and `Image` store indices into
/// [`FirmwareReaders`]. Multiple images typically come from the same TAR package, and
/// reading requires `&mut R`, so they could not each hold a mutable borrow of it.
/// [`FirmwareReaders::open`] instead borrows and seeks the reader on demand, one image
/// at a time.
#[derive(Clone)]
pub(crate) enum ImageSource {
    /// Entry inside a TAR package.
    Package {
        /// Index into [`FirmwareReaders::packages`].
        index: usize,
        /// Byte offset where the entry's data starts within the package.
        offset: u64,
        /// Size of the entry's data in bytes.
        size: u64,
    },
    /// Standalone partition image.
    Image {
        /// Index into [`FirmwareReaders::partitions`].
        index: usize,
        /// Size of the image in bytes.
        size: u64,
    },
    /// In-memory buffer (e.g. a rewritten vbmeta image).
    Memory(Vec<u8>),
}

impl ImageSource {
    /// Returns the size of the stored bytes.
    pub(crate) fn size(&self) -> u64 {
        match self {
            Self::Package { size, .. } | Self::Image { size, .. } => *size,
            Self::Memory(data) => data.len() as u64,
        }
    }
}

/// The readers backing firmware images: TAR packages and standalone partition images.
pub(crate) struct FirmwareReaders<P, I> {
    /// TAR packages as `(name, reader)`.
    pub(crate) packages: Vec<(String, P)>,
    /// Standalone partition images as `(target_partition, filename, reader)`.
    pub(crate) partitions: Vec<(Option<String>, String, I)>,
}

impl<P, I> Default for FirmwareReaders<P, I> {
    fn default() -> Self {
        Self {
            packages: Vec::new(),
            partitions: Vec::new(),
        }
    }
}

impl<P, I> FirmwareReaders<P, I> {
    /// Returns whether there are no packages and no partition images.
    pub(crate) fn is_empty(&self) -> bool {
        self.packages.is_empty() && self.partitions.is_empty()
    }
}

impl<P: AsyncRead + AsyncSeek + Unpin, I: AsyncRead + AsyncSeek + Unpin> FirmwareReaders<P, I> {
    /// Positions and returns a size-bounded reader over the bytes stored in `source`.
    pub(crate) async fn open<'a>(
        &'a mut self,
        source: &'a ImageSource,
    ) -> io::Result<impl AsyncRead + Unpin + 'a> {
        let reader = match source {
            ImageSource::Package { index, offset, .. } => {
                let reader = &mut self.packages[*index].1;
                reader.seek(SeekFrom::Start(*offset)).await?;
                SourceReader::Package(reader)
            }
            ImageSource::Image { index, .. } => {
                let reader = &mut self.partitions[*index].2;
                reader.seek(SeekFrom::Start(0)).await?;
                SourceReader::Image(reader)
            }
            ImageSource::Memory(data) => SourceReader::Memory(Cursor::new(data.as_slice())),
        };
        Ok(reader.take(source.size()))
    }
}

enum SourceReader<'a, P, I> {
    Package(&'a mut P),
    Image(&'a mut I),
    Memory(Cursor<&'a [u8]>),
}

impl<P: AsyncRead + Unpin, I: AsyncRead + Unpin> AsyncRead for SourceReader<'_, P, I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Package(r) => Pin::new(r).poll_read(cx, buf),
            Self::Image(r) => Pin::new(r).poll_read(cx, buf),
            Self::Memory(c) => Pin::new(c).poll_read(cx, buf),
        }
    }
}

/// The bytes of a partition image and how they are encoded, independent of any PIT.
#[derive(Clone)]
pub(crate) struct FirmwareImage {
    /// Backing source for the image bytes.
    pub(crate) source: ImageSource,
    /// Metadata header of the LZ4 frame if the image is LZ4-compressed.
    pub(crate) lz4_header: Option<Lz4FrameHeader>,
}

impl FirmwareImage {
    /// Inspects the image stored in `source`, parsing its LZ4 frame header if
    /// `is_lz4` is set.
    pub(crate) async fn inspect<P, I>(
        source: ImageSource,
        is_lz4: bool,
        readers: &mut FirmwareReaders<P, I>,
    ) -> io::Result<Self>
    where
        P: AsyncRead + AsyncSeek + Unpin,
        I: AsyncRead + AsyncSeek + Unpin,
    {
        let lz4_header = if is_lz4 {
            let reader = readers.open(&source).await?;
            Some(Lz4FrameHeader::parse(reader).await?)
        } else {
            None
        };
        Ok(Self { source, lz4_header })
    }

    /// Opens a size-bounded reader over the raw (possibly compressed) bytes of the image.
    pub(crate) async fn open<'a, P, I>(
        &'a self,
        readers: &'a mut FirmwareReaders<P, I>,
    ) -> io::Result<impl AsyncRead + Unpin + 'a>
    where
        P: AsyncRead + AsyncSeek + Unpin,
        I: AsyncRead + AsyncSeek + Unpin,
    {
        readers.open(&self.source).await
    }

    /// Reads Samsung's DDP `super_used_size` (in 512-byte sectors) from the
    /// header of a super image, returning `None` if it is absent or cannot be read.
    pub(crate) async fn super_used_size<P, I>(
        &self,
        readers: &mut FirmwareReaders<P, I>,
    ) -> Option<u32>
    where
        P: AsyncRead + AsyncSeek + Unpin,
        I: AsyncRead + AsyncSeek + Unpin,
    {
        let prefix = self
            .read_prefix(readers, lp::SUPER_METADATA_PREFIX_SIZE)
            .await
            .ok()?;
        lp::inspect_super_bytes(&prefix)
    }

    /// Reads up to `limit` bytes from the start of the image, decompressing it if needed.
    async fn read_prefix<P, I>(
        &self,
        readers: &mut FirmwareReaders<P, I>,
        limit: usize,
    ) -> io::Result<Vec<u8>>
    where
        P: AsyncRead + AsyncSeek + Unpin,
        I: AsyncRead + AsyncSeek + Unpin,
    {
        let mut reader = self.open(readers).await?;
        let prefix = if self.lz4_header.is_some() {
            std::pin::pin!(self.decompressed_slices(&mut reader, limit))
                .next()
                .await
        } else {
            std::pin::pin!(self.slices(&mut reader, limit)).next().await
        };
        prefix.unwrap_or_else(|| Ok(Vec::new()))
    }

    /// Raw (possibly compressed) size of the image in bytes.
    pub(crate) fn size(&self) -> u64 {
        self.source.size()
    }

    /// Uncompressed size of the image in bytes.
    pub(crate) fn uncompressed_size(&self) -> u64 {
        self.lz4_header
            .as_ref()
            .map_or_else(|| self.size(), |h| h.content_size)
    }

    /// Streams raw slices of an uncompressed image.
    pub(crate) fn slices<'r, R: AsyncRead + Unpin>(
        &self,
        reader: &'r mut R,
        slice_max_bytes: usize,
    ) -> impl Stream<Item = io::Result<Vec<u8>>> + 'r {
        stream::unfold(
            (reader, self.size()),
            move |(reader, mut remaining)| async move {
                if remaining == 0 {
                    return None;
                }
                let to_read = remaining.min(slice_max_bytes as u64) as usize;
                let mut buffer = vec![0u8; to_read];
                if let Err(e) = reader.read_exact(&mut buffer).await {
                    return Some((Err(e), (reader, 0)));
                }
                remaining -= to_read as u64;
                Some((Ok(buffer), (reader, remaining)))
            },
        )
    }

    /// Streams LZ4-compressed block slices along with their uncompressed byte sizes.
    pub(crate) fn compressed_slices<'r, R: AsyncRead + Unpin>(
        &self,
        reader: &'r mut R,
        slice_max_bytes: usize,
    ) -> impl Stream<Item = io::Result<(usize, Vec<u8>)>> + 'r {
        lz4::compressed_slices(reader, self.lz4_header.as_ref(), slice_max_bytes)
    }

    /// Streams decompressed byte slices of an LZ4-compressed image.
    pub(crate) fn decompressed_slices<'r, R: AsyncRead + Unpin>(
        &self,
        reader: &'r mut R,
        slice_max_bytes: usize,
    ) -> impl Stream<Item = io::Result<Vec<u8>>> + 'r {
        lz4::decompressed_slices(reader, self.lz4_header.as_ref(), slice_max_bytes)
    }

    /// Reads the entire image, decompressing it if needed.
    pub(crate) async fn read_all<P, I>(
        &self,
        readers: &mut FirmwareReaders<P, I>,
    ) -> io::Result<Vec<u8>>
    where
        P: AsyncRead + AsyncSeek + Unpin,
        I: AsyncRead + AsyncSeek + Unpin,
    {
        let mut reader = self.open(readers).await?;
        let reader = &mut reader;
        if let Some(header) = &self.lz4_header {
            let mut data = Vec::new();
            let content_size = header.content_size;
            let slice_size = (header.block_max_size as usize).max(64 * 1024);
            let mut slices = std::pin::pin!(self.decompressed_slices(reader, slice_size));
            while let Some(slice) = slices.next().await {
                data.extend_from_slice(&slice?);
            }
            if data.len() as u64 != content_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "LZ4 content size mismatch: expected {}, got {}",
                        content_size,
                        data.len()
                    ),
                ));
            }
            Ok(data)
        } else {
            let size = self.size();
            let mut data = Vec::new();
            reader.take(size).read_to_end(&mut data).await?;
            if data.len() as u64 != size {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF while reading partition payload",
                ));
            }
            Ok(data)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lz4_decompressed_slices_reseek_and_truncation() {
        use futures::StreamExt;
        use lz4_flex::frame::BlockSize;

        // 150 KB payload spanning 3 independent 64 KB LZ4 blocks (64K + 64K + 22K)
        let original: Vec<u8> = (0..150 * 1024).map(|i| (i % 251) as u8).collect();
        let (compressed, header) =
            crate::test_util::lz4_compress_with(&original, BlockSize::Max64KB);
        assert_eq!(header.content_size, original.len() as u64);
        assert_eq!(header.block_max_size, 64 * 1024);

        futures::executor::block_on(async {
            let mut cursor = futures::io::Cursor::new(compressed.as_slice());
            // Start away from the frame, so opening the image must seek back to it
            cursor.seek(SeekFrom::End(0)).await.unwrap();

            let image = FirmwareImage {
                source: ImageSource::Image {
                    index: 0,
                    size: compressed.len() as u64,
                },
                lz4_header: Some(header),
            };
            let mut readers: FirmwareReaders<Cursor<&[u8]>, _> = FirmwareReaders {
                packages: Vec::new(),
                partitions: vec![(None, "test.img.lz4".to_string(), cursor)],
            };

            // 1. Read a partial prefix and drop the stream (like reading super metadata)
            {
                let mut reader = image.open(&mut readers).await.unwrap();
                let prefix = std::pin::pin!(image.decompressed_slices(&mut reader, 10 * 1024))
                    .next()
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(prefix, &original[..10 * 1024]);
            }

            // 2. Consume full stream with a 50 KB slice limit (unaligned with 64 KB blocks,
            // exercising both the rewind when opening and leftover buffering)
            let mut reassembled = Vec::new();
            {
                let mut reader = image.open(&mut readers).await.unwrap();
                let mut slices = std::pin::pin!(image.decompressed_slices(&mut reader, 50 * 1024));
                while let Some(res) = slices.next().await {
                    let slice = res.unwrap();
                    assert!(slice.len() <= 50 * 1024);
                    reassembled.extend_from_slice(&slice);
                }
            }
            assert_eq!(reassembled, original);

            // 3. Truncated LZ4 stream must yield Err rather than silently ending with Ok
            let truncated = &compressed[..compressed.len() - 10];
            let mut truncated_reader = futures::io::Cursor::new(truncated);
            let results: Vec<io::Result<Vec<u8>>> = image
                .decompressed_slices(&mut truncated_reader, 50 * 1024)
                .collect()
                .await;
            assert!(results.iter().any(|r| r.is_err()));
        });
    }
}
