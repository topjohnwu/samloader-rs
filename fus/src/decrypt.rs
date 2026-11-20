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

//! Block-aligned AES-128-ECB streaming decryption and PKCS#7 unpadding.

use crate::data::resolve_range_bounds;
use aes::cipher::inout::InOutBuf;
use aes::cipher::{BlockModeDecrypt, KeyInit};
use futures::io::AsyncRead;
use std::io;
use std::ops::{Bound, RangeBounds};
use std::pin::Pin;
use std::task::{Context, Poll};

pub(crate) type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

pub(crate) fn decryptor(key: &[u8; 16]) -> Aes128EcbDec {
    Aes128EcbDec::new(key.into())
}

pub(crate) fn unpadded_block_len(block: &[u8; 16]) -> usize {
    let pad = block[15] as usize;
    if (1..=16).contains(&pad) && block[16 - pad..].iter().all(|&b| b == pad as u8) {
        16 - pad
    } else {
        16
    }
}

pub(crate) struct AlignedRange {
    pub(crate) http_start: Option<u64>,
    pub(crate) http_end: Option<u64>,
    pub(crate) skip_start: usize,
    pub(crate) dec_remaining: u64,
}

impl AlignedRange {
    pub(crate) fn new(range: impl RangeBounds<u64>, decrypted_size: u64, enc_size: u64) -> Self {
        let empty = Self {
            http_start: None,
            http_end: None,
            skip_start: 0,
            dec_remaining: 0,
        };
        let end_bounded = !matches!(
            range.end_bound(),
            Bound::Unbounded | Bound::Included(&u64::MAX)
        );
        let Some(clamped) = resolve_range_bounds(range, decrypted_size) else {
            return empty;
        };

        let max_enc_end = enc_size - 1;
        let req_start = clamped.start;
        let req_end = clamped.end - 1;
        let aligned_start = req_start & !15;
        let aligned_end = (req_end | 15).min(max_enc_end);

        Self {
            http_start: (aligned_start > 0).then_some(aligned_start),
            http_end: (end_bounded || aligned_end < max_enc_end).then_some(aligned_end),
            skip_start: (req_start - aligned_start) as usize,
            dec_remaining: clamped.end - req_start,
        }
    }
}

/// Async reader transparently decrypting an AES-128-ECB FUS byte range and trimming
/// unaligned boundaries.
pub(crate) struct DecryptReader<R>(Option<DecryptInner<R>>);

struct DecryptInner<R> {
    resp: R,
    dec: Aes128EcbDec,
    rem: [u8; 16],
    enc_len: usize,
    dec_pos: usize,
    dec_len: usize,
    skip_start: usize,
    dec_remaining: u64,
}

impl<R> DecryptReader<R> {
    pub(crate) const fn empty() -> Self {
        Self(None)
    }

    pub(crate) fn new(resp: R, dec: Aes128EcbDec, aligned: AlignedRange) -> Self {
        if aligned.dec_remaining == 0 {
            return Self(None);
        }
        Self(Some(DecryptInner {
            resp,
            dec,
            rem: [0; 16],
            enc_len: 0,
            dec_pos: 0,
            dec_len: 0,
            skip_start: aligned.skip_start,
            dec_remaining: aligned.dec_remaining,
        }))
    }
}

impl<R> DecryptInner<R> {
    fn drain_dec_rem(&mut self, buf: &mut [u8]) -> usize {
        let n = (self.dec_len - self.dec_pos).min(buf.len());
        buf[..n].copy_from_slice(&self.rem[self.dec_pos..self.dec_pos + n]);
        self.dec_pos += n;
        self.dec_remaining -= n as u64;
        n
    }
}

fn poll_read_at_least_16<R: AsyncRead + Unpin>(
    resp: &mut R,
    cx: &mut Context<'_>,
    dst: &mut [u8],
    total: &mut usize,
) -> Poll<io::Result<()>> {
    while *total < 16 {
        match Pin::new(&mut *resp).poll_read(cx, &mut dst[*total..]) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "premature EOF in encrypted stream",
                )));
            }
            Poll::Ready(Ok(n)) => *total += n,
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
}

impl<R: AsyncRead + Unpin> AsyncRead for DecryptReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let Some(inner) = self.0.as_mut() else {
            return Poll::Ready(Ok(0));
        };

        if inner.dec_pos < inner.dec_len {
            let n = inner.drain_dec_rem(buf);
            if inner.dec_remaining == 0 {
                self.0 = None;
            }
            return Poll::Ready(Ok(n));
        }

        let fast_cap = buf
            .len()
            .min(inner.dec_remaining.min(usize::MAX as u64) as usize);
        let max_aligned = fast_cap & !15;

        // Zero-copy fast path: aligned start and >= 16 bytes requested and available.
        if inner.skip_start == 0 && max_aligned >= 16 {
            let mut total = inner.enc_len;
            buf[..total].copy_from_slice(&inner.rem[..total]);
            inner.enc_len = 0;

            match poll_read_at_least_16(&mut inner.resp, cx, &mut buf[..max_aligned], &mut total) {
                Poll::Ready(Ok(())) => {}
                other => {
                    inner.rem[..total].copy_from_slice(&buf[..total]);
                    inner.enc_len = total;
                    return match other {
                        Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(Ok(())) => unreachable!(),
                    };
                }
            }

            let tail_len = total & 15;
            let aligned = total - tail_len;
            inner.rem[..tail_len].copy_from_slice(&buf[aligned..total]);
            inner.enc_len = tail_len;

            let (blocks, _) = InOutBuf::from(&mut buf[..aligned]).into_chunks();
            inner.dec.decrypt_blocks_inout(blocks);

            inner.dec_remaining -= aligned as u64;
            if inner.dec_remaining == 0 {
                self.0 = None;
            }
            return Poll::Ready(Ok(aligned));
        }

        // Staging path for unaligned prefix, small caller buffers (< 16),
        // or unaligned range end (< 16 remaining).
        let mut total = inner.enc_len;
        inner.enc_len = 0;

        match poll_read_at_least_16(&mut inner.resp, cx, &mut inner.rem, &mut total) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => {
                inner.enc_len = total;
                return Poll::Ready(Err(e));
            }
            Poll::Pending => {
                inner.enc_len = total;
                return Poll::Pending;
            }
        }

        let (blocks, _) = InOutBuf::from(&mut inner.rem[..]).into_chunks();
        inner.dec.decrypt_blocks_inout(blocks);

        let start_in_block = inner.skip_start;
        inner.skip_start = 0;
        let max_avail = inner.dec_remaining.min(16) as usize;
        let avail = (16 - start_in_block).min(max_avail);
        inner.dec_pos = start_in_block;
        inner.dec_len = start_in_block + avail;

        let n = inner.drain_dec_rem(buf);
        if inner.dec_remaining == 0 {
            self.0 = None;
        }
        Poll::Ready(Ok(n))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::test_util::TrickleReader;
    use aes::cipher::BlockModeEncrypt;
    use futures::executor::block_on;
    use futures::io::{AsyncReadExt, Cursor};

    pub(crate) const TEST_KEY: [u8; 16] = [0x13; 16];

    pub(crate) fn encrypt_test_data(plaintext: &[u8]) -> Vec<u8> {
        let mut buf = plaintext.to_vec();
        let mut enc = ecb::Encryptor::<aes::Aes128>::new_from_slice(&TEST_KEY).unwrap();
        let (blocks, tail) = InOutBuf::from(buf.as_mut_slice()).into_chunks();
        assert!(tail.is_empty());
        enc.encrypt_blocks_inout(blocks);
        buf
    }

    pub(crate) fn encrypt_pkcs7(plaintext: &[u8]) -> Vec<u8> {
        let pad = 16 - (plaintext.len() % 16);
        let mut padded = plaintext.to_vec();
        padded.extend(std::iter::repeat_n(pad as u8, pad));
        encrypt_test_data(&padded)
    }

    fn read_range(
        ciphertext: &[u8],
        decrypted_size: u64,
        range: impl RangeBounds<u64>,
        step: usize,
        buf_len: usize,
    ) -> ((Option<u64>, Option<u64>), Vec<u8>) {
        let aligned = AlignedRange::new(range, decrypted_size, ciphertext.len() as u64);
        let http_range = (aligned.http_start, aligned.http_end);

        let slice = if aligned.dec_remaining == 0 {
            Vec::new()
        } else {
            let s = aligned.http_start.unwrap_or(0) as usize;
            match aligned.http_end {
                Some(e) => ciphertext[s..=e as usize].to_vec(),
                None => ciphertext[s..].to_vec(),
            }
        };

        let mut reader = DecryptReader::new(
            TrickleReader::new(slice, step),
            decryptor(&TEST_KEY),
            aligned,
        );

        block_on(async {
            let mut out = Vec::new();
            let mut buf = vec![0u8; buf_len];
            loop {
                let n = reader.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
            (http_range, out)
        })
    }

    #[test]
    fn test_decrypt_reader_ranges() {
        fn check(
            ciphertext: &[u8],
            range: impl RangeBounds<u64> + std::fmt::Debug + Clone,
            exp_range: (Option<u64>, Option<u64>),
            step: usize,
            buf_len: usize,
            expected: &[u8],
        ) {
            let (http_range, out) = read_range(
                ciphertext,
                ciphertext.len() as u64,
                range.clone(),
                step,
                buf_len,
            );
            assert_eq!(http_range, exp_range, "range={range:?}");
            assert_eq!(out, expected, "range={range:?}");
        }

        let plaintext: Vec<u8> = (0..128_u8).collect();
        let ciphertext = encrypt_test_data(&plaintext);

        check(&ciphertext, .., (None, None), 5, 64, &plaintext);
        check(
            &ciphertext,
            ..=20,
            (None, Some(31)),
            64,
            64,
            &plaintext[..=20],
        );
        check(
            &ciphertext,
            5..=73,
            (None, Some(79)),
            3,
            7,
            &plaintext[5..=73],
        );
        check(&ciphertext, 5.., (None, None), 7, 32, &plaintext[5..]);
        check(
            &ciphertext,
            19..,
            (Some(16), None),
            11,
            256,
            &plaintext[19..],
        );
        #[allow(clippy::reversed_empty_ranges)]
        check(&ciphertext, 20..10, (None, None), 16, 64, &[]);
        check(&ciphertext, 128.., (None, None), 16, 64, &[]);
    }

    #[test]
    fn test_decrypt_reader_pkcs7_unpadding() {
        // Test 1-byte padding, partial-block (5-byte) padding, and full-block (16-byte) padding.
        for plain_len in [15_usize, 43, 48] {
            let plaintext: Vec<u8> = (0..plain_len).map(|i| (i as u8).wrapping_mul(3)).collect();
            let ciphertext = encrypt_pkcs7(&plaintext);
            let dec_size = plain_len as u64;

            for (step, buf_len) in [(5, 7), (64, 64)] {
                let (_, full) = read_range(&ciphertext, dec_size, .., step, buf_len);
                assert_eq!(full, plaintext, "plain_len={plain_len}");

                let (_, tail) = read_range(&ciphertext, dec_size, 10.., step, buf_len);
                assert_eq!(tail, &plaintext[10..], "plain_len={plain_len}");
            }
        }

        // Straddling plaintext/padding boundary (40..=46 -> only 40..43 are real plaintext)
        let plaintext: Vec<u8> = (0..43_u8).map(|i| i + 50).collect();
        let ciphertext = encrypt_pkcs7(&plaintext);
        let (_, straddle) = read_range(&ciphertext, 43, 40..=46, 7, 32);
        assert_eq!(straddle, &plaintext[40..43]);
    }

    #[test]
    fn test_decrypt_reader_truncated_block_errors() {
        let plaintext = vec![0xAA; 32];
        let ciphertext = encrypt_test_data(&plaintext);

        // Truncated mid-block (25 of 32 bytes) and on a block boundary (16 of 32 bytes)
        for trunc_len in [25_usize, 16] {
            let aligned = AlignedRange::new(.., 32, 32);
            let mut reader = DecryptReader::new(
                Cursor::new(ciphertext[..trunc_len].to_vec()),
                decryptor(&TEST_KEY),
                aligned,
            );
            block_on(async {
                let mut out = [0u8; 64];
                assert_eq!(reader.read(&mut out).await.unwrap(), 16);
                let err = reader.read(&mut out[16..]).await.unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
            });
        }
    }

    #[test]
    fn test_decrypt_reader_error_recovery_across_paths() {
        struct FlakyReader {
            data: Vec<u8>,
            pos: usize,
            reads: usize,
            fail_next: bool,
        }

        impl AsyncRead for FlakyReader {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut [u8],
            ) -> Poll<io::Result<usize>> {
                if self.fail_next {
                    self.fail_next = false;
                    self.reads += 1;
                    if self.reads.is_multiple_of(2) {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WouldBlock)));
                }
                let n = (self.data.len() - self.pos).min(7).min(buf.len());
                if n > 0 {
                    self.fail_next = true;
                }
                buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                self.pos += n;
                Poll::Ready(Ok(n))
            }
        }

        let plaintext: Vec<u8> = (0..37_u8).map(|i| i ^ 0x5A).collect();
        let ciphertext = encrypt_pkcs7(&plaintext);
        let aligned = AlignedRange::new(.., plaintext.len() as u64, ciphertext.len() as u64);
        let mut reader = DecryptReader::new(
            FlakyReader {
                data: ciphertext,
                pos: 0,
                reads: 0,
                fail_next: false,
            },
            decryptor(&TEST_KEY),
            aligned,
        );

        // Alternate between 64-byte (fast path) and 3-byte (staging path) buffers across WouldBlock and Poll::Pending
        block_on(async {
            let mut out = Vec::new();
            let mut use_large = true;
            loop {
                let mut buf = vec![0u8; if use_large { 64 } else { 3 }];
                match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        out.extend_from_slice(&buf[..n]);
                        use_large = !use_large;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        use_large = !use_large;
                    }
                    Err(e) => panic!("unexpected error: {e}"),
                }
            }
            assert_eq!(out, plaintext);
        });
    }
}
