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

//! Stateful ZIP entry [`ResumableAsyncRead`] supporting `Stored` and `Z_BLOCK`-checkpointed `Deflate`.

use crate::compat::MaybeSend;
use crate::stream::{Checkpoint, ResumableAsyncRead};
use binrw::binrw;
use core::ffi::c_int;
use futures::io::AsyncRead;
use rawzip::CompressionMethod;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

const DEFLATE_IN_BUF_SIZE: usize = 64 * 1024;
const MAX_DICT_SIZE: usize = 32_768;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZipCheckpointKind {
    #[brw(magic = 1u8)]
    Stored {
        offset: u64,
        #[br(assert(offset > 0 || crc32 == 0))]
        crc32: u32,
    },
    #[brw(magic = 2u8)]
    Deflate {
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
    },
}

/// Opaque, serializable mid-stream [`Checkpoint`] for [`ZipEntrySession`](crate::ZipEntrySession)
/// streams (`Stored` or `Deflate`).
///
/// Implements [`binrw::BinRead`] and [`binrw::BinWrite`] in a compact little-endian
/// format, and can be passed to [`ResumableStream::resume`](crate::ResumableStream::resume)
/// along with the trailing uncompressed dictionary bytes indicated by
/// [`ResumableStream::resume_dict_len`](crate::ResumableStream::resume_dict_len).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZipCheckpoint(ZipCheckpointKind);

impl Checkpoint for ZipCheckpoint {
    fn source_offset(&self) -> u64 {
        match self.0 {
            ZipCheckpointKind::Stored { offset, .. } => offset,
            ZipCheckpointKind::Deflate { comp_offset, .. } => comp_offset,
        }
    }

    fn output_offset(&self) -> u64 {
        match self.0 {
            ZipCheckpointKind::Stored { offset, .. } => offset,
            ZipCheckpointKind::Deflate { uncomp_offset, .. } => uncomp_offset,
        }
    }
}

impl ZipCheckpoint {
    pub(crate) fn resume_dict_len(
        &self,
        compression: CompressionMethod,
        comp_size: u64,
        uncomp_size: u64,
    ) -> Option<usize> {
        match (compression, self.0) {
            (CompressionMethod::STORE, ZipCheckpointKind::Stored { offset, .. })
                if offset <= comp_size && offset <= uncomp_size =>
            {
                Some(0)
            }
            (
                CompressionMethod::DEFLATE,
                ZipCheckpointKind::Deflate {
                    comp_offset,
                    uncomp_offset,
                    ..
                },
            ) if comp_offset <= comp_size && uncomp_offset <= uncomp_size => {
                Some(uncomp_offset.min(MAX_DICT_SIZE as u64) as usize)
            }
            _ => None,
        }
    }
}

enum InflateOutcome {
    Output(usize),
    NeedInput,
    StreamEnd,
}

struct DeflateState {
    expected_crc32: u32,
    expected_size: u64,
    comp_offset: u64,
    uncomp_offset: u64,
    crc32: u32,
    strm: libz_rs_sys::z_stream,
    in_buf: Vec<u8>,
    in_pos: usize,
    in_len: usize,
    last_in_byte: u8,
    last_checkpoint: Option<ZipCheckpoint>,
    has_pending_inflate: bool,
    in_final_block: bool,
    ended: bool,
}

// SAFETY: `z_stream` uses `zlib-rs`'s Rust global allocator (`rust-allocator`)
// and exclusively owns its heap-allocated inflate state. All other fields are
// `Send`, and `next_in`/`next_out` are cleared before returning from `inflate`.
unsafe impl Send for DeflateState {}

impl Drop for DeflateState {
    fn drop(&mut self) {
        // SAFETY: `self.strm` was successfully initialized by `inflateInit2_`.
        unsafe {
            libz_rs_sys::inflateEnd(&mut self.strm);
        }
    }
}

impl DeflateState {
    fn new(expected_crc32: u32, expected_size: u64) -> io::Result<Self> {
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
            expected_crc32,
            expected_size,
            comp_offset: 0,
            uncomp_offset: 0,
            crc32: 0,
            strm,
            in_buf: vec![0u8; DEFLATE_IN_BUF_SIZE],
            in_pos: 0,
            in_len: 0,
            last_in_byte: 0,
            last_checkpoint: None,
            has_pending_inflate: false,
            in_final_block: false,
            ended: false,
        })
    }

    fn inflate_into(&mut self, dst: &mut [u8]) -> io::Result<InflateOutcome> {
        debug_assert!(!dst.is_empty());
        debug_assert!(!self.ended);

        let mut filled = 0usize;
        let mut captured_this_call = false;

        while filled < dst.len() && (self.in_pos < self.in_len || self.has_pending_inflate) {
            let seeking_block = !captured_this_call && !self.in_final_block;
            let flush = if seeking_block {
                libz_rs_sys::Z_BLOCK
            } else {
                libz_rs_sys::Z_NO_FLUSH
            };

            let avail_in = self.in_len - self.in_pos;
            let avail_out = (dst.len() - filled).min(u32::MAX as usize);
            self.strm.next_in = if avail_in > 0 {
                self.in_buf[self.in_pos..].as_ptr()
            } else {
                core::ptr::null()
            };
            self.strm.avail_in = avail_in as libz_rs_sys::uInt;
            self.strm.next_out = dst[filled..].as_mut_ptr();
            self.strm.avail_out = avail_out as libz_rs_sys::uInt;

            // SAFETY: `self.strm` is initialized; `next_in`/`avail_in` point to
            // `self.in_buf[self.in_pos..self.in_len]` (or null when empty), and
            // `next_out`/`avail_out` point to `dst[filled..filled + avail_out]`.
            let rc = unsafe { libz_rs_sys::inflate(&mut self.strm, flush) };
            let remaining_in = self.strm.avail_in as usize;
            let remaining_out = self.strm.avail_out as usize;
            self.strm.next_in = core::ptr::null();
            self.strm.avail_in = 0;
            self.strm.next_out = core::ptr::null_mut();
            self.strm.avail_out = 0;

            let consumed = avail_in - remaining_in;
            let produced = avail_out - remaining_out;

            if consumed > 0 {
                self.last_in_byte = self.in_buf[self.in_pos + consumed - 1];
                self.in_pos += consumed;
                self.comp_offset += consumed as u64;
                if self.in_pos == self.in_len {
                    self.in_pos = 0;
                    self.in_len = 0;
                }
            }

            if produced > 0 {
                let new_uncomp =
                    check_output_add(self.uncomp_offset, self.expected_size, produced)?;
                let slice = &dst[filled..filled + produced];
                self.crc32 = zlib_rs::crc32::crc32(self.crc32, slice);
                self.uncomp_offset = new_uncomp;
                filled += produced;
            }

            match rc {
                libz_rs_sys::Z_STREAM_END => {
                    self.ended = true;
                    self.has_pending_inflate = false;
                    if self.in_pos < self.in_len {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "trailing data after Deflate stream end",
                        ));
                    }
                    return Ok(if filled > 0 {
                        InflateOutcome::Output(filled)
                    } else {
                        InflateOutcome::StreamEnd
                    });
                }
                libz_rs_sys::Z_OK | libz_rs_sys::Z_BUF_ERROR => {
                    if (self.strm.data_type & 0x40) != 0 {
                        self.in_final_block = true;
                    }
                    let at_block_end = seeking_block && (self.strm.data_type & 0x80) != 0;

                    if at_block_end
                        && !self.in_final_block
                        && self.uncomp_offset < self.expected_size
                    {
                        let prime_bits = (self.strm.data_type & 7) as u8;
                        let prime_value = if prime_bits > 0 {
                            self.last_in_byte >> (8 - prime_bits)
                        } else {
                            0
                        };
                        self.last_checkpoint = Some(ZipCheckpoint(ZipCheckpointKind::Deflate {
                            comp_offset: self.comp_offset,
                            uncomp_offset: self.uncomp_offset,
                            crc32: self.crc32,
                            prime_bits,
                            prime_value,
                        }));
                        captured_this_call = true;
                    }

                    if rc == libz_rs_sys::Z_BUF_ERROR && !at_block_end {
                        if self.in_pos < self.in_len || remaining_out == 0 {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("Deflate decompression error ({rc})"),
                            ));
                        }
                        self.has_pending_inflate = false;
                        break;
                    }

                    self.has_pending_inflate = remaining_out == 0 || at_block_end;
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Deflate decompression error ({rc})"),
                    ));
                }
            }
        }

        Ok(if filled > 0 {
            InflateOutcome::Output(filled)
        } else {
            InflateOutcome::NeedInput
        })
    }

    fn finish(mut self) -> io::Result<()> {
        if !self.ended {
            let mut scratch = [0u8; 1];
            self.strm.next_in = core::ptr::null();
            self.strm.avail_in = 0;
            self.strm.next_out = scratch.as_mut_ptr();
            self.strm.avail_out = scratch.len() as libz_rs_sys::uInt;
            // SAFETY: `self.strm` is initialized and `scratch` is valid writable memory.
            let rc = unsafe { libz_rs_sys::inflate(&mut self.strm, libz_rs_sys::Z_FINISH) };
            let produced = scratch.len() - self.strm.avail_out as usize;
            if rc != libz_rs_sys::Z_STREAM_END || produced != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated Deflate stream",
                ));
            }
            self.ended = true;
        }
        verify_zip_eof(
            self.uncomp_offset,
            self.expected_size,
            self.crc32,
            self.expected_crc32,
        )
    }
}

enum ZipDecoderMode {
    Stored {
        expected_crc32: u32,
        expected_size: u64,
        offset: u64,
        crc32: u32,
    },
    Deflate(Box<DeflateState>),
}

pub(crate) struct ZipDecoder {
    mode: ZipDecoderMode,
}

fn check_output_add(offset: u64, max_size: u64, len: usize) -> io::Result<u64> {
    offset
        .checked_add(len as u64)
        .filter(|&end| end <= max_size)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("decoded stream exceeded expected size ({max_size} bytes)"),
            )
        })
}

fn verify_zip_eof(
    uncomp_offset: u64,
    expected_size: u64,
    crc32: u32,
    expected_crc32: u32,
) -> io::Result<()> {
    if uncomp_offset != expected_size {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!(
                "uncompressed length mismatch: expected {expected_size} bytes, got {uncomp_offset}"
            ),
        ));
    }

    if crc32 != expected_crc32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("CRC-32 mismatch: expected {expected_crc32:#010x}, got {crc32:#010x}"),
        ));
    }

    Ok(())
}

impl ZipDecoder {
    pub(crate) fn new(
        compression: CompressionMethod,
        expected_crc32: u32,
        expected_size: u64,
    ) -> io::Result<Self> {
        let mode = match compression {
            CompressionMethod::STORE => ZipDecoderMode::Stored {
                expected_crc32,
                expected_size,
                offset: 0,
                crc32: 0,
            },
            CompressionMethod::DEFLATE => {
                ZipDecoderMode::Deflate(Box::new(DeflateState::new(expected_crc32, expected_size)?))
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("unsupported ZIP compression method: {other}"),
                ));
            }
        };
        Ok(Self { mode })
    }

    pub(crate) fn resume(
        compression: CompressionMethod,
        expected_crc32: u32,
        expected_comp_size: u64,
        expected_size: u64,
        checkpoint: ZipCheckpoint,
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

        let mode = match checkpoint.0 {
            ZipCheckpointKind::Stored { offset, crc32 } => ZipDecoderMode::Stored {
                expected_crc32,
                expected_size,
                offset,
                crc32,
            },
            ZipCheckpointKind::Deflate {
                comp_offset,
                uncomp_offset,
                crc32,
                prime_bits,
                prime_value,
            } => {
                let mut state = DeflateState::new(expected_crc32, expected_size)?;
                state.comp_offset = comp_offset;
                state.uncomp_offset = uncomp_offset;
                state.crc32 = crc32;
                if prime_bits > 0 {
                    state.last_in_byte = prime_value << (8 - prime_bits);
                    // SAFETY: `state.strm` is freshly initialized and `prime_bits` is in `1..=7`.
                    let rc = unsafe {
                        libz_rs_sys::inflatePrime(
                            &mut state.strm,
                            c_int::from(prime_bits),
                            c_int::from(prime_value),
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
                    // SAFETY: `state.strm` is raw inflate (`-15`) and `tail` is at most 32_768 bytes.
                    let rc = unsafe {
                        libz_rs_sys::inflateSetDictionary(
                            &mut state.strm,
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
                ZipDecoderMode::Deflate(Box::new(state))
            }
        };

        Ok(Self { mode })
    }

    pub(crate) fn into_reader<R>(self, reader: R) -> ZipEntryReader<R> {
        ZipEntryReader {
            reader,
            decoder: Some(self),
        }
    }

    fn finish(self) -> io::Result<()> {
        match self.mode {
            ZipDecoderMode::Stored {
                expected_crc32,
                expected_size,
                offset,
                crc32,
            } => verify_zip_eof(offset, expected_size, crc32, expected_crc32),
            ZipDecoderMode::Deflate(state) => state.finish(),
        }
    }
}

pub(crate) struct ZipEntryReader<R> {
    reader: R,
    decoder: Option<ZipDecoder>,
}

impl<R> ZipEntryReader<R> {
    fn fail(&mut self, err: io::Error) -> Poll<io::Result<usize>> {
        self.decoder = None;
        Poll::Ready(Err(err))
    }

    fn finish_eof(&mut self) -> Poll<io::Result<usize>> {
        if let Some(dec) = self.decoder.take()
            && let Err(e) = dec.finish()
        {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(0))
    }
}

impl<R: AsyncRead + MaybeSend + Unpin> ResumableAsyncRead for ZipEntryReader<R> {
    type Checkpoint = ZipCheckpoint;

    fn checkpoint(&self) -> Option<ZipCheckpoint> {
        match &self.decoder.as_ref()?.mode {
            ZipDecoderMode::Stored {
                expected_size,
                offset,
                crc32,
                ..
            } => (*offset > 0 && *offset < *expected_size).then_some(ZipCheckpoint(
                ZipCheckpointKind::Stored {
                    offset: *offset,
                    crc32: *crc32,
                },
            )),
            ZipDecoderMode::Deflate(state) => state.last_checkpoint,
        }
    }
}

impl<R: AsyncRead + MaybeSend + Unpin> AsyncRead for ZipEntryReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        loop {
            let this = &mut *self;
            let Some(dec) = this.decoder.as_mut() else {
                return Poll::Ready(Ok(0));
            };

            match &mut dec.mode {
                ZipDecoderMode::Stored {
                    expected_size,
                    offset,
                    crc32,
                    ..
                } => {
                    let n = match Pin::new(&mut this.reader).poll_read(cx, buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(0)) => return self.finish_eof(),
                        Poll::Ready(Ok(n)) => n,
                    };
                    let new_offset = match check_output_add(*offset, *expected_size, n) {
                        Ok(off) => off,
                        Err(e) => return self.fail(e),
                    };
                    *crc32 = zlib_rs::crc32::crc32(*crc32, &buf[..n]);
                    *offset = new_offset;
                    return Poll::Ready(Ok(n));
                }
                ZipDecoderMode::Deflate(state) => {
                    if !state.ended && (state.in_pos < state.in_len || state.has_pending_inflate) {
                        match state.inflate_into(buf) {
                            Ok(InflateOutcome::Output(n)) => return Poll::Ready(Ok(n)),
                            Ok(InflateOutcome::NeedInput | InflateOutcome::StreamEnd) => {}
                            Err(e) => return self.fail(e),
                        }
                    }

                    debug_assert_eq!(state.in_pos, state.in_len);
                    let n = match Pin::new(&mut this.reader).poll_read(cx, &mut state.in_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(0)) => return self.finish_eof(),
                        Poll::Ready(Ok(n)) => n,
                    };

                    if state.ended {
                        return self.fail(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "trailing data after Deflate stream end",
                        ));
                    }

                    state.in_pos = 0;
                    state.in_len = n;
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
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

        // First block: > 300 KiB of repetitive pattern to span multiple caller buffers
        // and exercise `consumed == 0` block boundaries.
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

    pub(crate) fn compress_multi_block(data: &[u8], chunk_sizes: &[usize]) -> Vec<u8> {
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
    fn test_zip_checkpoint_wire_round_trip_and_validation() {
        use binrw::{BinRead, BinWrite};

        let stored_cp = ZipCheckpoint(ZipCheckpointKind::Stored {
            offset: 1024,
            crc32: 0xABCD_1234,
        });
        let deflate_cp = ZipCheckpoint(ZipCheckpointKind::Deflate {
            comp_offset: 1024,
            uncomp_offset: 3072,
            crc32: 0x1234_5678,
            prime_bits: 5,
            prime_value: 0x1A,
        });

        for (cp, expected_len, exp_src, exp_out) in [
            (stored_cp, 13usize, 1024u64, 1024u64),
            (deflate_cp, 23, 1024, 3072),
        ] {
            let mut bytes = Vec::new();
            cp.write(&mut std::io::Cursor::new(&mut bytes)).unwrap();
            assert_eq!(bytes.len(), expected_len);
            let decoded = ZipCheckpoint::read(&mut std::io::Cursor::new(&bytes)).unwrap();
            assert_eq!(decoded, cp);
            assert_eq!(decoded.source_offset(), exp_src);
            assert_eq!(decoded.output_offset(), exp_out);
        }

        // Invalid Deflate prime_bits (> 7) and prime_value (>= 1 << prime_bits)
        let mut def_bytes = Vec::new();
        deflate_cp
            .write(&mut std::io::Cursor::new(&mut def_bytes))
            .unwrap();
        let mut bad_bits = def_bytes.clone();
        bad_bits[21] = 8;
        assert!(ZipCheckpoint::read(&mut std::io::Cursor::new(&bad_bits)).is_err());

        let mut bad_val = def_bytes;
        bad_val[22] = 0x20;
        assert!(ZipCheckpoint::read(&mut std::io::Cursor::new(&bad_val)).is_err());

        // Deflate comp_offset == 0 with non-zero uncomp_offset / crc32 / prime_bits
        let mut zero_comp_dirty = [0u8; 23];
        zero_comp_dirty[0] = 2; // Deflate tag
        zero_comp_dirty[9..17].copy_from_slice(&10u64.to_le_bytes());
        assert!(ZipCheckpoint::read(&mut std::io::Cursor::new(&zero_comp_dirty)).is_err());

        // Stored offset == 0 with non-zero crc32
        let mut zero_stored_dirty = [0u8; 13];
        zero_stored_dirty[0] = 1; // Stored tag
        zero_stored_dirty[9..13].copy_from_slice(&1u32.to_le_bytes());
        assert!(ZipCheckpoint::read(&mut std::io::Cursor::new(&zero_stored_dirty)).is_err());

        // Offset tag (0) and unknown tags must be rejected by ZipCheckpoint
        assert!(ZipCheckpoint::read(&mut std::io::Cursor::new(&[0u8; 23])).is_err());
        assert!(ZipCheckpoint::read(&mut std::io::Cursor::new(&[9u8; 23])).is_err());

        // Stored vs Deflate compatibility and bounds checks
        assert_eq!(
            stored_cp.resume_dict_len(CompressionMethod::STORE, 2048, 2048),
            Some(0)
        );
        assert_eq!(
            stored_cp.resume_dict_len(CompressionMethod::DEFLATE, 2048, 2048),
            None
        );
        assert_eq!(
            deflate_cp.resume_dict_len(CompressionMethod::DEFLATE, 2048, 4096),
            Some(3072)
        );
        assert_eq!(
            deflate_cp.resume_dict_len(CompressionMethod::STORE, 2048, 4096),
            None
        );
        assert_eq!(
            deflate_cp.resume_dict_len(CompressionMethod::DEFLATE, 1023, 4096),
            None
        );
        assert_eq!(
            deflate_cp.resume_dict_len(CompressionMethod::DEFLATE, 2048, 3071),
            None
        );
    }

    #[test]
    fn test_deflate_z_block_checkpoints_and_resume() {
        struct SteppedReader {
            data: Vec<u8>,
            pos: usize,
            steps: &'static [usize],
            step_idx: usize,
        }

        impl AsyncRead for SteppedReader {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut [u8],
            ) -> Poll<io::Result<usize>> {
                let step = self.steps[self.step_idx % self.steps.len()];
                self.step_idx += 1;
                let n = (self.data.len() - self.pos).min(step).min(buf.len());
                buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                self.pos += n;
                Poll::Ready(Ok(n))
            }
        }

        let payload = make_cross_32k_payload();
        let compressed = compress_multi_block(
            &payload,
            &[320 * 1024, 17_321, 29_113, 35_003, 19_997, 41_117],
        );
        let expected_crc = zlib_rs::crc32::crc32(0, &payload);
        let expected_size = payload.len() as u64;
        let expected_comp = compressed.len() as u64;

        let verify_resume = async |cp: ZipCheckpoint| {
            let dict_len = cp
                .resume_dict_len(CompressionMethod::DEFLATE, expected_comp, expected_size)
                .unwrap();
            let uncomp = cp.output_offset() as usize;
            let dict = &payload[uncomp - dict_len..uncomp];
            let mut resumed = ZipDecoder::resume(
                CompressionMethod::DEFLATE,
                expected_crc,
                expected_comp,
                expected_size,
                cp,
                dict,
            )
            .unwrap()
            .into_reader(SteppedReader {
                data: compressed[cp.source_offset() as usize..].to_vec(),
                pos: 0,
                steps: &[11_113],
                step_idx: 0,
            });
            let mut resumed_out = payload[..uncomp].to_vec();
            resumed.read_to_end(&mut resumed_out).await.unwrap();
            assert_eq!(resumed_out, payload);
        };

        block_on(async {
            let mut reader =
                ZipDecoder::new(CompressionMethod::DEFLATE, expected_crc, expected_size)
                    .unwrap()
                    .into_reader(SteppedReader {
                        data: compressed.clone(),
                        pos: 0,
                        steps: &[7, 131, 4093, 65535, 19, 8191],
                        step_idx: 0,
                    });

            let mut full_out = Vec::with_capacity(payload.len());
            let mut checkpoints = Vec::new();
            let out_sizes = [64 * 1024, 1, 7, 131, 4099, 256 * 1024];
            let mut out_idx = 0usize;
            assert_eq!(reader.checkpoint(), None);
            loop {
                let mut buf = vec![0u8; out_sizes[out_idx % out_sizes.len()]];
                out_idx += 1;
                let n = reader.read(&mut buf).await.unwrap();
                if n == 0 {
                    assert_eq!(reader.checkpoint(), None);
                    break;
                }
                full_out.extend_from_slice(&buf[..n]);
                if let Some(cp) = reader.checkpoint() {
                    assert!(
                        full_out.len() as u64 >= cp.output_offset(),
                        "checkpoint emitted ahead of delivered bytes"
                    );
                    if checkpoints.last() != Some(&cp) {
                        checkpoints.push(cp);
                    }
                }
            }
            // Post-EOF reads return 0 cleanly with no checkpoint
            assert_eq!(reader.read(&mut [0u8; 16]).await.unwrap(), 0);
            assert_eq!(reader.checkpoint(), None);
            assert_eq!(full_out, payload);

            assert!(
                checkpoints
                    .iter()
                    .any(|cp| matches!(cp.0, ZipCheckpointKind::Deflate { prime_bits: 0, .. }))
            );
            assert!(checkpoints.iter().any(|cp| matches!(
                cp.0,
                ZipCheckpointKind::Deflate {
                    prime_bits: 1..=7,
                    ..
                }
            )));

            // Short dictionary must be rejected explicitly rather than silently corrupting
            if let Some(&cp) = checkpoints.iter().find(|cp| cp.output_offset() > 0) {
                let dict_len = cp
                    .resume_dict_len(CompressionMethod::DEFLATE, expected_comp, expected_size)
                    .unwrap();
                assert_eq!(
                    ZipDecoder::resume(
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
                verify_resume(cp).await;
            }

            // Exercise consumed == 0 block boundaries with small caller buffers draining a
            // single pre-buffered compressed chunk spanning multiple Deflate blocks.
            let mut small_reader =
                ZipDecoder::new(CompressionMethod::DEFLATE, expected_crc, expected_size)
                    .unwrap()
                    .into_reader(Cursor::new(compressed.clone()));
            let mut small_out = Vec::with_capacity(payload.len());
            let mut small_cps = Vec::new();
            let mut buf = [0u8; 137];
            loop {
                let n = small_reader.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                small_out.extend_from_slice(&buf[..n]);
                if let Some(cp) = small_reader.checkpoint() {
                    assert!(small_out.len() as u64 >= cp.output_offset());
                    if small_cps.last() != Some(&cp) {
                        small_cps.push(cp);
                    }
                }
            }
            assert_eq!(small_out, payload);
            assert!(!small_cps.is_empty());
            verify_resume(small_cps[0]).await;
            verify_resume(small_cps[small_cps.len() / 2]).await;
        });
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

        async fn read_varied_with_checkpoints<R: ResumableAsyncRead>(
            mut reader: R,
        ) -> io::Result<(Vec<u8>, Option<R::Checkpoint>)> {
            let sizes = [1, 3, 7, 19, 131, 4099, 65537];
            let mut out = Vec::new();
            let mut first_cp = None;
            let mut idx = 0usize;
            loop {
                let mut buf = vec![0u8; sizes[idx % sizes.len()]];
                idx += 1;
                let n = reader.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
                if let Some(cp) = reader.checkpoint() {
                    assert!(
                        out.len() as u64 >= cp.output_offset(),
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
            // Stored & Deflate with tiny/varied read buffers exercising direct inflate
            // and the checkpoint delivery invariant.
            let stored_reader = ZipDecoder::new(CompressionMethod::STORE, crc, size)
                .unwrap()
                .into_reader(TrickleReader {
                    data: payload.clone(),
                    pos: 0,
                    reads: 0,
                });
            let (out, cp) = read_varied_with_checkpoints(stored_reader).await.unwrap();
            assert_eq!(out, payload);
            assert!(cp.is_some());

            let def_reader = ZipDecoder::new(CompressionMethod::DEFLATE, crc, size)
                .unwrap()
                .into_reader(TrickleReader {
                    data: compressed.clone(),
                    pos: 0,
                    reads: 0,
                });
            let (out, cp) = read_varied_with_checkpoints(def_reader).await.unwrap();
            assert_eq!(out, payload);
            assert!(cp.is_some());

            // Immediate overflow detection when decoded output exceeds expected_size
            let mut over_reader = ZipDecoder::new(CompressionMethod::DEFLATE, crc, size - 10)
                .unwrap()
                .into_reader(Cursor::new(compressed.clone()));
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
            let mut trunc_reader = ZipDecoder::new(CompressionMethod::DEFLATE, crc, size)
                .unwrap()
                .into_reader(Cursor::new(compressed[..compressed.len() - 4].to_vec()));
            scratch.clear();
            assert_eq!(
                trunc_reader
                    .read_to_end(&mut scratch)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::UnexpectedEof
            );

            // Highly compressible zero payload read in tiny chunks (tests direct inflate without
            // staging buffer growth and checkpoint resume across high-expansion blocks).
            let zeros = vec![0u8; 512 * 1024];
            let zeros_comp = compress_multi_block(&zeros, &[128 * 1024]);
            let zeros_crc = zlib_rs::crc32::crc32(0, &zeros);
            let zeros_reader =
                ZipDecoder::new(CompressionMethod::DEFLATE, zeros_crc, zeros.len() as u64)
                    .unwrap()
                    .into_reader(Cursor::new(zeros_comp.clone()));
            let (out, cp) = read_varied_with_checkpoints(zeros_reader).await.unwrap();
            assert_eq!(out, zeros);
            let cp = cp.expect("zero-filled multi-block stream emits checkpoint");
            let dict_len = cp
                .resume_dict_len(
                    CompressionMethod::DEFLATE,
                    zeros_comp.len() as u64,
                    zeros.len() as u64,
                )
                .unwrap();
            let uncomp = cp.output_offset() as usize;
            let mut resumed_zeros = zeros[..uncomp].to_vec();
            ZipDecoder::resume(
                CompressionMethod::DEFLATE,
                zeros_crc,
                zeros_comp.len() as u64,
                zeros.len() as u64,
                cp,
                &zeros[uncomp - dict_len..uncomp],
            )
            .unwrap()
            .into_reader(Cursor::new(
                zeros_comp[cp.source_offset() as usize..].to_vec(),
            ))
            .read_to_end(&mut resumed_zeros)
            .await
            .unwrap();
            assert_eq!(resumed_zeros, zeros);

            // Trailing bytes after Deflate stream end (both inline and on a follow-up read)
            let mut trailing = compressed.clone();
            trailing.extend_from_slice(b"junk");
            let mut inline_trailing = ZipDecoder::new(CompressionMethod::DEFLATE, crc, size)
                .unwrap()
                .into_reader(Cursor::new(trailing));
            scratch.clear();
            assert_eq!(
                inline_trailing
                    .read_to_end(&mut scratch)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );

            struct SplitTrailingReader {
                head: Vec<u8>,
                head_pos: usize,
                tail: Vec<u8>,
                tail_pos: usize,
            }
            impl AsyncRead for SplitTrailingReader {
                fn poll_read(
                    mut self: Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                    buf: &mut [u8],
                ) -> Poll<io::Result<usize>> {
                    if self.head_pos < self.head.len() {
                        let n = (self.head.len() - self.head_pos).min(buf.len());
                        buf[..n].copy_from_slice(&self.head[self.head_pos..self.head_pos + n]);
                        self.head_pos += n;
                        return Poll::Ready(Ok(n));
                    }
                    if self.tail_pos < self.tail.len() {
                        let n = (self.tail.len() - self.tail_pos).min(buf.len());
                        buf[..n].copy_from_slice(&self.tail[self.tail_pos..self.tail_pos + n]);
                        self.tail_pos += n;
                        return Poll::Ready(Ok(n));
                    }
                    Poll::Ready(Ok(0))
                }
            }
            let mut split_trailing = ZipDecoder::new(CompressionMethod::DEFLATE, crc, size)
                .unwrap()
                .into_reader(SplitTrailingReader {
                    head: compressed.clone(),
                    head_pos: 0,
                    tail: b"extra".to_vec(),
                    tail_pos: 0,
                });
            scratch.clear();
            assert_eq!(
                split_trailing
                    .read_to_end(&mut scratch)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );

            // CRC mismatch rejected at EOF
            let mut bad_crc_reader =
                ZipDecoder::new(CompressionMethod::DEFLATE, crc ^ 0xFFFF, size)
                    .unwrap()
                    .into_reader(Cursor::new(compressed));
            scratch.clear();
            assert_eq!(
                bad_crc_reader
                    .read_to_end(&mut scratch)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );

            // Stored reader suppresses checkpoint once all declared bytes have been read
            // (prior to EOF CRC verification) so an unverified 100% checkpoint is never persisted.
            let sample = b"hello stored world";
            let sample_crc = zlib_rs::crc32::crc32(0, sample);
            let mut exact_stored =
                ZipDecoder::new(CompressionMethod::STORE, sample_crc, sample.len() as u64)
                    .unwrap()
                    .into_reader(Cursor::new(sample.to_vec()));
            let mut half = [0u8; 6];
            assert_eq!(exact_stored.read(&mut half).await.unwrap(), 6);
            assert!(exact_stored.checkpoint().is_some());
            let mut rest = [0u8; 32];
            assert_eq!(
                exact_stored.read(&mut rest).await.unwrap(),
                sample.len() - 6
            );
            assert_eq!(exact_stored.checkpoint(), None);
            assert_eq!(exact_stored.read(&mut rest).await.unwrap(), 0);

            // 0-byte Stored and 0-byte Deflate streams verify cleanly with CRC=0
            let mut empty_stored = ZipDecoder::new(CompressionMethod::STORE, 0, 0)
                .unwrap()
                .into_reader(Cursor::new(Vec::<u8>::new()));
            assert_eq!(empty_stored.read(&mut [0u8; 8]).await.unwrap(), 0);

            let empty_deflate_bytes = vec![0x03, 0x00]; // valid empty final fixed block
            let mut empty_deflate = ZipDecoder::new(CompressionMethod::DEFLATE, 0, 0)
                .unwrap()
                .into_reader(Cursor::new(empty_deflate_bytes));
            assert_eq!(empty_deflate.read(&mut [0u8; 8]).await.unwrap(), 0);
        });
    }
}
