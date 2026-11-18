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

//! Stateful streaming ZIP entry decoder supporting `Stored` and `Z_BLOCK`-checkpointed `Deflate`.

use crate::compat::BoxAsyncRead;
use binrw::binrw;
use core::ffi::c_int;
use futures::future::poll_fn;
use futures::io::AsyncRead;
use rawzip::CompressionMethod;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

const DEFLATE_OUT_BUF_SIZE: usize = 256 * 1024;
const DECODER_IN_BUF_SIZE: usize = 64 * 1024;
const MAX_DICT_SIZE: usize = 32_768;

/// Opaque, serializable mid-stream resume checkpoint captured by [`ZipEntryReader`].
///
/// Implements [`binrw::BinRead`] and [`binrw::BinWrite`] in a fixed little-endian
/// format, and can be passed to [`ZipEntrySession::resume`](crate::ZipEntrySession::resume)
/// along with the trailing uncompressed dictionary bytes indicated by
/// [`ZipEntry::resume_dict_len`](crate::ZipEntry::resume_dict_len).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamCheckpoint {
    comp_offset: u64,
    uncomp_offset: u64,
    crc32: u32,
    #[br(assert(
        prime_bits <= 7
            && (comp_offset > 0 || (uncomp_offset == 0 && crc32 == 0 && prime_bits == 0))
    ))]
    prime_bits: u8,
    #[br(assert(prime_value < (1u8 << prime_bits)))]
    prime_value: u8,
}

impl StreamCheckpoint {
    /// Consumed byte offset in the entry's compressed payload stream.
    pub const fn compressed_offset(&self) -> u64 {
        self.comp_offset
    }

    /// Produced byte offset in the entry's decompressed output stream.
    pub const fn uncompressed_offset(&self) -> u64 {
        self.uncomp_offset
    }

    const fn is_valid(&self) -> bool {
        self.prime_bits <= 7
            && self.prime_value < (1u8 << self.prime_bits)
            && (self.comp_offset > 0
                || (self.uncomp_offset == 0 && self.crc32 == 0 && self.prime_bits == 0))
    }

    pub(crate) fn resume_dict_len(
        &self,
        compression: CompressionMethod,
        comp_size: u64,
        uncomp_size: u64,
    ) -> Option<usize> {
        if !self.is_valid() || self.comp_offset > comp_size || self.uncomp_offset > uncomp_size {
            return None;
        }
        match compression {
            CompressionMethod::STORE => {
                if self.prime_bits != 0
                    || self.prime_value != 0
                    || self.comp_offset != self.uncomp_offset
                {
                    return None;
                }
                Some(0)
            }
            CompressionMethod::DEFLATE => {
                Some(self.uncomp_offset.min(MAX_DICT_SIZE as u64) as usize)
            }
            _ => None,
        }
    }
}

struct RawDeflate {
    strm: libz_rs_sys::z_stream,
    out_buf: Vec<u8>,
    last_in_byte: u8,
    ended: bool,
}

// SAFETY: `z_stream` uses `zlib-rs`'s Rust global allocator (`rust-allocator`)
// and exclusively owns its heap-allocated `state` and `out_buf`.
unsafe impl Send for RawDeflate {}

impl Drop for RawDeflate {
    fn drop(&mut self) {
        // SAFETY: `self.strm` was successfully initialized by `inflateInit2_`.
        unsafe {
            libz_rs_sys::inflateEnd(&mut self.strm);
        }
    }
}

impl RawDeflate {
    fn new() -> io::Result<Self> {
        let mut strm = libz_rs_sys::z_stream::default();
        // SAFETY: `strm` is a valid `z_stream` configured with the Rust allocator,
        // `-15` selects raw RFC 1951 Deflate with a 32 KiB window, and `zlibVersion()`
        // returns a static NUL-terminated version string matching `sizeof(z_stream)`.
        let rc = unsafe {
            libz_rs_sys::inflateInit2_(
                &mut strm,
                -15,
                libz_rs_sys::zlibVersion(),
                size_of::<libz_rs_sys::z_stream>() as c_int,
            )
        };
        if rc != libz_rs_sys::Z_OK {
            return Err(io::Error::other(format!("inflateInit2_ failed: {rc}")));
        }
        Ok(Self {
            strm,
            out_buf: vec![0u8; DEFLATE_OUT_BUF_SIZE],
            last_in_byte: 0,
            ended: false,
        })
    }
}

/// Stateful ZIP entry decoder supporting `Stored` and `Z_BLOCK`-checkpointed `Deflate`,
/// with continuous uncompressed size enforcement and end-of-stream CRC-32 verification.
pub(crate) struct StreamDecoder {
    expected_crc32: u32,
    expected_size: u64,
    comp_offset: u64,
    uncomp_offset: u64,
    crc32: u32,
    raw: Option<Box<RawDeflate>>,
}

fn check_uncomp_add(uncomp_offset: u64, expected_size: u64, len: usize) -> io::Result<u64> {
    uncomp_offset
        .checked_add(len as u64)
        .filter(|&end| end <= expected_size)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("decoded stream exceeded expected size ({expected_size} bytes)"),
            )
        })
}

impl StreamDecoder {
    pub(crate) fn new(
        compression: CompressionMethod,
        expected_crc32: u32,
        expected_size: u64,
    ) -> io::Result<Self> {
        let raw = match compression {
            CompressionMethod::DEFLATE => Some(Box::new(RawDeflate::new()?)),
            CompressionMethod::STORE => None,
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("unsupported ZIP compression method: {other}"),
                ));
            }
        };
        Ok(Self {
            expected_crc32,
            expected_size,
            comp_offset: 0,
            uncomp_offset: 0,
            crc32: 0,
            raw,
        })
    }

    pub(crate) fn resume(
        compression: CompressionMethod,
        expected_crc32: u32,
        expected_comp_size: u64,
        expected_size: u64,
        checkpoint: StreamCheckpoint,
        dict: &[u8],
    ) -> io::Result<Self> {
        let Some(required_dict) =
            checkpoint.resume_dict_len(compression, expected_comp_size, expected_size)
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid or incompatible stream checkpoint metadata",
            ));
        };

        if dict.len() < required_dict {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "resume dictionary too short: need at least {required_dict} bytes, got {}",
                    dict.len()
                ),
            ));
        }

        let raw = match compression {
            CompressionMethod::STORE => None,
            CompressionMethod::DEFLATE => {
                let mut raw = RawDeflate::new()?;
                if checkpoint.prime_bits > 0 {
                    raw.last_in_byte = checkpoint.prime_value << (8 - checkpoint.prime_bits);
                    // SAFETY: `raw.strm` is freshly initialized and `prime_bits` is in `1..=7`.
                    let rc = unsafe {
                        libz_rs_sys::inflatePrime(
                            &mut raw.strm,
                            c_int::from(checkpoint.prime_bits),
                            c_int::from(checkpoint.prime_value),
                        )
                    };
                    if rc != libz_rs_sys::Z_OK {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("inflatePrime failed: {rc}"),
                        ));
                    }
                }
                if required_dict > 0 {
                    let tail = &dict[dict.len() - required_dict..];
                    // SAFETY: `raw.strm` is raw inflate (`-15`) and `tail` is at most 32_768 bytes.
                    let rc = unsafe {
                        libz_rs_sys::inflateSetDictionary(
                            &mut raw.strm,
                            tail.as_ptr(),
                            tail.len() as libz_rs_sys::uInt,
                        )
                    };
                    if rc != libz_rs_sys::Z_OK {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("inflateSetDictionary failed: {rc}"),
                        ));
                    }
                }
                Some(Box::new(raw))
            }
            _ => unreachable!("compression method validated by resume_dict_len"),
        };

        Ok(Self {
            expected_crc32,
            expected_size,
            comp_offset: checkpoint.comp_offset,
            uncomp_offset: checkpoint.uncomp_offset,
            crc32: checkpoint.crc32,
            raw,
        })
    }

    fn feed_stored(
        &mut self,
        input: &[u8],
        want_checkpoint: bool,
    ) -> io::Result<Option<StreamCheckpoint>> {
        if !input.is_empty() {
            let new_uncomp = check_uncomp_add(self.uncomp_offset, self.expected_size, input.len())?;
            self.crc32 = zlib_rs::crc32::crc32(self.crc32, input);
            self.comp_offset += input.len() as u64;
            self.uncomp_offset = new_uncomp;
        }
        Ok(want_checkpoint.then_some(StreamCheckpoint {
            comp_offset: self.comp_offset,
            uncomp_offset: self.uncomp_offset,
            crc32: self.crc32,
            prime_bits: 0,
            prime_value: 0,
        }))
    }

    fn feed_deflate(
        &mut self,
        input: &[u8],
        want_checkpoint: bool,
        mut on_output: impl FnMut(&[u8]),
    ) -> io::Result<Option<StreamCheckpoint>> {
        let raw = self
            .raw
            .as_mut()
            .expect("Deflate mode always has RawDeflate");
        if raw.ended {
            if !input.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "trailing data after Deflate stream end",
                ));
            }
            return Ok(None);
        }

        let mut rem = input;
        let mut out_was_full = false;
        let mut seeking_block = want_checkpoint;
        let mut captured = None;

        while (!rem.is_empty() || out_was_full) && !raw.ended {
            let flush = if seeking_block {
                libz_rs_sys::Z_BLOCK
            } else {
                libz_rs_sys::Z_NO_FLUSH
            };
            let prev_avail_in = rem.len().min(u32::MAX as usize);
            raw.strm.next_in = rem.as_ptr();
            raw.strm.avail_in = prev_avail_in as libz_rs_sys::uInt;
            raw.strm.next_out = raw.out_buf.as_mut_ptr();
            raw.strm.avail_out = raw.out_buf.len() as libz_rs_sys::uInt;

            // SAFETY: `raw.strm` is initialized; `next_in`/`avail_in` point to `rem`,
            // and `next_out`/`avail_out` point to `raw.out_buf`.
            let rc = unsafe { libz_rs_sys::inflate(&mut raw.strm, flush) };
            let consumed = prev_avail_in - raw.strm.avail_in as usize;
            let produced = raw.out_buf.len() - raw.strm.avail_out as usize;

            if consumed > 0 {
                raw.last_in_byte = rem[consumed - 1];
                rem = &rem[consumed..];
                self.comp_offset += consumed as u64;
            }

            if produced > 0 {
                let new_uncomp =
                    check_uncomp_add(self.uncomp_offset, self.expected_size, produced)?;
                let slice = &raw.out_buf[..produced];
                self.crc32 = zlib_rs::crc32::crc32(self.crc32, slice);
                self.uncomp_offset = new_uncomp;
                on_output(slice);
            }

            match rc {
                libz_rs_sys::Z_STREAM_END => {
                    raw.ended = true;
                    if !rem.is_empty() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "trailing data after Deflate stream end",
                        ));
                    }
                }
                libz_rs_sys::Z_OK => {
                    if seeking_block
                        && (raw.strm.data_type & 0x80) != 0
                        && (raw.strm.data_type & 0x40) == 0
                    {
                        let prime_bits = (raw.strm.data_type & 7) as u8;
                        let prime_value = if prime_bits > 0 {
                            raw.last_in_byte >> (8 - prime_bits)
                        } else {
                            0
                        };
                        captured = Some(StreamCheckpoint {
                            comp_offset: self.comp_offset,
                            uncomp_offset: self.uncomp_offset,
                            crc32: self.crc32,
                            prime_bits,
                            prime_value,
                        });
                        seeking_block = false;
                    }
                }
                libz_rs_sys::Z_BUF_ERROR if rem.is_empty() && raw.strm.avail_out > 0 => {
                    break;
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Deflate decompression error ({rc})"),
                    ));
                }
            }

            out_was_full = raw.strm.avail_out == 0;
        }

        Ok(captured)
    }

    fn finish(mut self) -> io::Result<()> {
        if let Some(raw) = &mut self.raw
            && !raw.ended
        {
            raw.strm.next_in = core::ptr::null();
            raw.strm.avail_in = 0;
            raw.strm.next_out = raw.out_buf.as_mut_ptr();
            raw.strm.avail_out = raw.out_buf.len() as libz_rs_sys::uInt;
            // SAFETY: `raw.strm` is initialized and `out_buf` is valid writable memory.
            let rc = unsafe { libz_rs_sys::inflate(&mut raw.strm, libz_rs_sys::Z_FINISH) };
            let produced = raw.out_buf.len() - raw.strm.avail_out as usize;
            if rc != libz_rs_sys::Z_STREAM_END || produced != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated Deflate stream",
                ));
            }
            raw.ended = true;
        }

        if self.uncomp_offset != self.expected_size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "uncompressed length mismatch: expected {} bytes, got {}",
                    self.expected_size, self.uncomp_offset
                ),
            ));
        }

        if self.crc32 != self.expected_crc32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "CRC-32 mismatch: expected {:#010x}, got {:#010x}",
                    self.expected_crc32, self.crc32
                ),
            ));
        }

        Ok(())
    }

    pub(crate) fn into_reader<'a>(self, reader: BoxAsyncRead<'a>) -> ZipEntryReader<'a> {
        let delivered_uncomp = self.uncomp_offset;
        let in_buf = if self.raw.is_some() {
            vec![0u8; DECODER_IN_BUF_SIZE]
        } else {
            Vec::new()
        };
        ZipEntryReader {
            reader,
            decoder: Some(self),
            in_buf,
            out_buf: Vec::new(),
            out_pos: 0,
            delivered_uncomp,
            pending_checkpoint: None,
            eof: false,
        }
    }
}

/// Async streaming reader for a single [`ZipArchive`](crate::ZipArchive) entry.
///
/// Transparently decompresses `Stored` and `Deflate` payloads, enforces the declared
/// uncompressed length continuously, and verifies the IEEE CRC-32 checksum at EOF.
/// Implements [`AsyncRead`] for standard streaming consumption, and provides
/// [`read_chunk`](Self::read_chunk) for capturing mid-stream [`StreamCheckpoint`]s.
pub struct ZipEntryReader<'a> {
    reader: BoxAsyncRead<'a>,
    decoder: Option<StreamDecoder>,
    in_buf: Vec<u8>,
    out_buf: Vec<u8>,
    out_pos: usize,
    delivered_uncomp: u64,
    pending_checkpoint: Option<StreamCheckpoint>,
    eof: bool,
}

impl ZipEntryReader<'_> {
    /// Reads the next chunk of decompressed bytes into `buf`, returning `(bytes_read, checkpoint)`.
    ///
    /// A return of `(0, None)` indicates verified EOF (exact uncompressed length and IEEE CRC-32
    /// matched). When `want_checkpoint` is `true`, `Some(cp)` is returned once a clean checkpoint
    /// boundary has been reached **and** every uncompressed byte in `[0..cp.uncompressed_offset())`
    /// has been delivered to the caller (including the bytes in `buf[..bytes_read]`).
    pub async fn read_chunk(
        &mut self,
        buf: &mut [u8],
        want_checkpoint: bool,
    ) -> io::Result<(usize, Option<StreamCheckpoint>)> {
        poll_fn(|cx| self.poll_read_chunk(cx, buf, want_checkpoint)).await
    }

    fn take_ready_checkpoint(&mut self) -> Option<StreamCheckpoint> {
        if let Some(cp) = self.pending_checkpoint
            && self.delivered_uncomp >= cp.uncomp_offset
        {
            self.pending_checkpoint = None;
            return Some(cp);
        }
        None
    }

    fn fail(&mut self, err: io::Error) -> Poll<io::Result<(usize, Option<StreamCheckpoint>)>> {
        self.decoder = None;
        self.eof = true;
        self.out_buf.clear();
        self.out_pos = 0;
        self.pending_checkpoint = None;
        Poll::Ready(Err(err))
    }

    fn finish_eof(&mut self) -> Poll<io::Result<(usize, Option<StreamCheckpoint>)>> {
        self.eof = true;
        self.pending_checkpoint = None;
        if let Some(dec) = self.decoder.take()
            && let Err(e) = dec.finish()
        {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok((0, None)))
    }

    fn poll_read_chunk(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
        want_checkpoint: bool,
    ) -> Poll<io::Result<(usize, Option<StreamCheckpoint>)>> {
        if buf.is_empty() {
            return Poll::Ready(Ok((0, None)));
        }

        if self.out_pos < self.out_buf.len() {
            let n = (self.out_buf.len() - self.out_pos).min(buf.len());
            buf[..n].copy_from_slice(&self.out_buf[self.out_pos..self.out_pos + n]);
            self.out_pos += n;
            self.delivered_uncomp += n as u64;
            if self.out_pos == self.out_buf.len() {
                self.out_buf.clear();
                if self.out_buf.capacity() > 4 * DEFLATE_OUT_BUF_SIZE {
                    self.out_buf.shrink_to(DEFLATE_OUT_BUF_SIZE);
                }
                self.out_pos = 0;
            }
            let cp = self.take_ready_checkpoint();
            return Poll::Ready(Ok((n, cp)));
        }

        if self.eof {
            return Poll::Ready(Ok((0, None)));
        }

        let is_stored = self
            .decoder
            .as_ref()
            .expect("ZipEntryReader cannot read after completion")
            .raw
            .is_none();

        loop {
            let dst = if is_stored {
                &mut *buf
            } else {
                &mut self.in_buf[..]
            };
            let n = match Pin::new(&mut *self.reader).poll_read(cx, dst) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => return self.finish_eof(),
                Poll::Ready(Ok(n)) => n,
            };

            if is_stored {
                let dec = self
                    .decoder
                    .as_mut()
                    .expect("ZipEntryReader cannot read after completion");
                return match dec.feed_stored(&buf[..n], want_checkpoint) {
                    Ok(cp) => {
                        self.delivered_uncomp += n as u64;
                        Poll::Ready(Ok((n, cp)))
                    }
                    Err(e) => self.fail(e),
                };
            }

            let capture = want_checkpoint && self.pending_checkpoint.is_none();
            let dec = self
                .decoder
                .as_mut()
                .expect("ZipEntryReader cannot read after completion");
            let mut filled = 0usize;
            let out_buf = &mut self.out_buf;

            let res = dec.feed_deflate(&self.in_buf[..n], capture, |out| {
                let direct = (buf.len() - filled).min(out.len());
                if direct > 0 {
                    buf[filled..filled + direct].copy_from_slice(&out[..direct]);
                    filled += direct;
                }
                if direct < out.len() {
                    out_buf.extend_from_slice(&out[direct..]);
                }
            });

            match res {
                Ok(Some(cp)) => self.pending_checkpoint = Some(cp),
                Ok(None) => {}
                Err(e) => return self.fail(e),
            }

            if filled > 0 {
                self.delivered_uncomp += filled as u64;
                let cp = self.take_ready_checkpoint();
                return Poll::Ready(Ok((filled, cp)));
            }
        }
    }
}

impl AsyncRead for ZipEntryReader<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_read_chunk(cx, buf, false).map_ok(|(n, _)| n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use futures::io::{AsyncReadExt, Cursor};
    use zlib_rs::{Deflate, DeflateFlush, Status};

    fn make_cross_32k_payload() -> Vec<u8> {
        let mut out = Vec::with_capacity(4 * 1024 * 1024);
        let mut state: u64 = 0x1234_5678_9abc_def0;
        let mut next_u8 = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        };

        // First block: > 300 KiB of repetitive pattern to saturate `out_buf` and exercise
        // `consumed == 0` block boundaries.
        let pattern = b"SAMSUNG_FIRMWARE_CROSS_32K_REFERENCE_PATTERN_0123456789abcdef_";
        while out.len() < 320 * 1024 {
            out.extend_from_slice(pattern);
        }

        // Subsequent blocks: interleaved pseudo-random bytes and back-references > 24 KiB away.
        for blk in 0..40 {
            for _ in 0..(24 * 1024) {
                out.push(next_u8());
            }
            if blk % 2 == 0 {
                let start = out.len() - 32_000;
                let slice = out[start..start + 4096].to_vec();
                out.extend_from_slice(&slice);
            }
            for _ in 0..200 {
                out.extend_from_slice(pattern);
            }
        }
        out
    }

    fn compress_multi_block(data: &[u8], chunk_sizes: &[usize]) -> Vec<u8> {
        let mut def = Deflate::new(6, false, 15);
        let mut out = vec![0u8; zlib_rs::compress_bound(data.len()) + 4096];
        let mut in_off = 0usize;
        let mut out_off = 0usize;
        let mut idx = 0;
        while in_off < data.len() {
            let chunk = chunk_sizes[idx % chunk_sizes.len()].min(data.len() - in_off);
            idx += 1;
            let prev_in = def.total_in();
            let prev_out = def.total_out();
            let is_last = in_off + chunk == data.len();
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
    fn test_checkpoint_wire_round_trip_and_validation() {
        use binrw::{BinRead, BinWrite};

        let cp = StreamCheckpoint {
            comp_offset: 1024,
            uncomp_offset: 3072,
            crc32: 0x1234_5678,
            prime_bits: 5,
            prime_value: 0x1A,
        };
        let mut bytes = Vec::new();
        cp.write(&mut std::io::Cursor::new(&mut bytes)).unwrap();
        assert_eq!(bytes.len(), 22);
        let decoded = StreamCheckpoint::read(&mut std::io::Cursor::new(&bytes)).unwrap();
        assert_eq!(decoded, cp);
        assert_eq!(decoded.compressed_offset(), 1024);
        assert_eq!(decoded.uncompressed_offset(), 3072);

        // Invalid prime_bits (> 7) and prime_value (>= 1 << prime_bits)
        let mut bad_bits = bytes.clone();
        bad_bits[20] = 8;
        assert!(StreamCheckpoint::read(&mut std::io::Cursor::new(&bad_bits)).is_err());

        let mut bad_val = bytes;
        bad_val[21] = 0x20;
        assert!(StreamCheckpoint::read(&mut std::io::Cursor::new(&bad_val)).is_err());

        // comp_offset == 0 with non-zero uncomp_offset / crc32 / prime_bits
        let mut zero_comp_dirty = [0u8; 22];
        zero_comp_dirty[8..16].copy_from_slice(&10u64.to_le_bytes());
        assert!(StreamCheckpoint::read(&mut std::io::Cursor::new(&zero_comp_dirty)).is_err());

        // Stored vs Deflate compatibility checks
        assert_eq!(
            cp.resume_dict_len(CompressionMethod::DEFLATE, 2048, 4096),
            Some(3072)
        );
        assert_eq!(
            cp.resume_dict_len(CompressionMethod::STORE, 2048, 4096),
            None
        );
        assert_eq!(
            cp.resume_dict_len(CompressionMethod::DEFLATE, 1023, 4096),
            None
        );
        assert_eq!(
            cp.resume_dict_len(CompressionMethod::DEFLATE, 2048, 3071),
            None
        );
    }

    #[test]
    fn test_deflate_z_block_checkpoints_and_resume() {
        let payload = make_cross_32k_payload();
        let compressed = compress_multi_block(
            &payload,
            &[320 * 1024, 17_321, 29_113, 35_003, 19_997, 41_117],
        );
        let expected_crc = zlib_rs::crc32::crc32(0, &payload);
        let expected_size = payload.len() as u64;
        let expected_comp = compressed.len() as u64;

        let mut dec =
            StreamDecoder::new(CompressionMethod::DEFLATE, expected_crc, expected_size).unwrap();
        let mut full_out = Vec::with_capacity(payload.len());
        let mut checkpoints = Vec::new();
        let mut pos = 0usize;
        let mut step_idx = 0usize;
        let steps = [7, 131, 4093, 65535, 19, 8191];

        while pos < compressed.len() {
            let step = steps[step_idx % steps.len()].min(compressed.len() - pos);
            step_idx += 1;
            if let Some(cp) = dec
                .feed_deflate(&compressed[pos..pos + step], true, |out| {
                    full_out.extend_from_slice(out);
                })
                .unwrap()
            {
                checkpoints.push(cp);
            }
            pos += step;
        }
        let verify_resume = |cp: StreamCheckpoint| {
            let dict_len = cp
                .resume_dict_len(CompressionMethod::DEFLATE, expected_comp, expected_size)
                .unwrap();
            let uncomp = cp.uncompressed_offset() as usize;
            let dict = &payload[uncomp - dict_len..uncomp];
            let mut resumed = StreamDecoder::resume(
                CompressionMethod::DEFLATE,
                expected_crc,
                expected_comp,
                expected_size,
                cp,
                dict,
            )
            .unwrap();
            let mut resumed_out = payload[..uncomp].to_vec();
            for chunk in compressed[cp.compressed_offset() as usize..].chunks(11_113) {
                resumed
                    .feed_deflate(chunk, false, |out| {
                        resumed_out.extend_from_slice(out);
                    })
                    .unwrap();
            }
            resumed.finish().unwrap();
            assert_eq!(resumed_out, payload);
        };

        dec.finish().unwrap();
        assert_eq!(full_out, payload);

        assert!(checkpoints.iter().any(|cp| cp.prime_bits == 0));
        assert!(
            checkpoints
                .iter()
                .any(|cp| (1..=7).contains(&cp.prime_bits))
        );

        // Short dictionary must be rejected explicitly rather than silently corrupting
        if let Some(&cp) = checkpoints.iter().find(|cp| cp.uncompressed_offset() > 0) {
            let dict_len = cp
                .resume_dict_len(CompressionMethod::DEFLATE, expected_comp, expected_size)
                .unwrap();
            assert_eq!(
                StreamDecoder::resume(
                    CompressionMethod::DEFLATE,
                    expected_crc,
                    expected_comp,
                    expected_size,
                    cp,
                    &vec![0u8; dict_len - 1],
                )
                .err()
                .unwrap()
                .kind(),
                io::ErrorKind::InvalidInput
            );
        }

        for &cp in checkpoints.iter().step_by((checkpoints.len() / 8).max(1)) {
            verify_resume(cp);
        }

        // Explicitly exercise a consumed == 0 block boundary by feeding a single large slice.
        let mut zero_consumed_dec =
            StreamDecoder::new(CompressionMethod::DEFLATE, expected_crc, expected_size).unwrap();
        let cp = zero_consumed_dec
            .feed_deflate(&compressed, true, |_| {})
            .unwrap()
            .expect("checkpoint inside multi-block stream");
        zero_consumed_dec.finish().unwrap();
        verify_resume(cp);
    }

    #[test]
    fn test_reader_streaming_checkpoints_and_errors() {
        struct TrickleReader {
            data: Vec<u8>,
            pos: usize,
            reads: usize,
        }

        impl AsyncRead for TrickleReader {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut [u8],
            ) -> Poll<io::Result<usize>> {
                self.reads += 1;
                if self.reads.is_multiple_of(5) {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                if self.reads.is_multiple_of(3) {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "eintr")));
                }
                let n = (self.data.len() - self.pos).min(97).min(buf.len());
                buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                self.pos += n;
                Poll::Ready(Ok(n))
            }
        }

        async fn read_varied_with_checkpoints(
            mut reader: ZipEntryReader<'_>,
        ) -> io::Result<(Vec<u8>, Option<StreamCheckpoint>)> {
            let sizes = [1, 3, 7, 19, 131, 4099, 65537];
            let mut out = Vec::new();
            let mut first_cp = None;
            let mut idx = 0usize;
            loop {
                let mut buf = vec![0u8; sizes[idx % sizes.len()]];
                idx += 1;
                let (n, cp) = reader.read_chunk(&mut buf, first_cp.is_none()).await?;
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
                if let Some(cp) = cp {
                    assert!(
                        out.len() as u64 >= cp.uncompressed_offset(),
                        "checkpoint emitted ahead of delivered bytes"
                    );
                    if first_cp.is_none() {
                        first_cp = Some(cp);
                    }
                }
            }
            Ok((out, first_cp))
        }

        let payload: Vec<u8> = (0..128_000).map(|i| ((i * 31) ^ (i >> 7)) as u8).collect();
        let compressed = compress_multi_block(&payload, &[16 * 1024]);
        let crc = zlib_rs::crc32::crc32(0, &payload);
        let size = payload.len() as u64;

        block_on(async {
            // Stored & Deflate with tiny/varied read buffers exercising staging out_buf
            // and the checkpoint delivery invariant.
            let stored_reader = StreamDecoder::new(CompressionMethod::STORE, crc, size)
                .unwrap()
                .into_reader(Box::new(TrickleReader {
                    data: payload.clone(),
                    pos: 0,
                    reads: 0,
                }));
            let (out, cp) = read_varied_with_checkpoints(stored_reader).await.unwrap();
            assert_eq!(out, payload);
            assert!(cp.is_some());

            let def_reader = StreamDecoder::new(CompressionMethod::DEFLATE, crc, size)
                .unwrap()
                .into_reader(Box::new(TrickleReader {
                    data: compressed.clone(),
                    pos: 0,
                    reads: 0,
                }));
            let (out, cp) = read_varied_with_checkpoints(def_reader).await.unwrap();
            assert_eq!(out, payload);
            assert!(cp.is_some());

            // Immediate overflow detection when decoded output exceeds expected_size
            let mut over_reader = StreamDecoder::new(CompressionMethod::DEFLATE, crc, size - 10)
                .unwrap()
                .into_reader(Box::new(Cursor::new(compressed.clone())));
            let mut scratch = Vec::new();
            assert_eq!(
                over_reader
                    .read_to_end(&mut scratch)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );

            // Truncated stream rejected at EOF
            let mut trunc_reader = StreamDecoder::new(CompressionMethod::DEFLATE, crc, size)
                .unwrap()
                .into_reader(Box::new(Cursor::new(
                    compressed[..compressed.len() - 4].to_vec(),
                )));
            scratch.clear();
            assert_eq!(
                trunc_reader
                    .read_to_end(&mut scratch)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::UnexpectedEof
            );

            // CRC mismatch rejected at EOF
            let mut bad_crc_reader =
                StreamDecoder::new(CompressionMethod::DEFLATE, crc ^ 0xFFFF, size)
                    .unwrap()
                    .into_reader(Box::new(Cursor::new(compressed)));
            scratch.clear();
            assert_eq!(
                bad_crc_reader
                    .read_to_end(&mut scratch)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        });
    }
}
