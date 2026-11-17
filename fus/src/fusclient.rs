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

use crate::error::Result;
use crate::{auth, xml};
use aes::cipher::inout::InOutBuf;
use aes::cipher::{BlockModeDecrypt, KeyInit};
use reqwest::blocking::{Client, Response};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue, RANGE, USER_AGENT};
use std::io::{self, Read};
use std::sync::Mutex;
use std::time::Duration;
use xml::BinaryInform;

type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

/// Authentication token state. The download GET signs every request with
/// `encnonce`/`auth`; these expire, so they live behind a lock and are shared
/// by reference across all download threads (which only read them) and the
/// occasional reauthentication (which rewrites them). See [`FusClient`] and
/// [`DownloadSession`].
#[derive(Default)]
struct AuthState {
    auth: String,
    nonce: String,
    encnonce: String,
}

/// Client coordinating API communication and security authentication
/// with the Samsung Firmware Update Server (FUS).
pub struct FusClient {
    client: Client,
    auth_state: Mutex<AuthState>,
}

impl FusClient {
    /// Creates a new `FusClient` and initiates the standard FUS handshake to generate a session nonce.
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .cookie_store(true)
            // For the blocking client, `timeout` is applied per I/O operation with
            // a fresh deadline each call (see its `Read` impl) — so it flags a
            // stalled transfer (no data for 30s) without capping total download
            // time. This is the timeout that surfaces as `Decode/TimedOut`; the
            // download loop now resumes on it instead of aborting. 30s is also the
            // library default, made explicit here so it can be tuned.
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(15))
            .build()?;
        let fus = FusClient {
            client,
            auth_state: Mutex::new(AuthState::default()),
        };

        // Initialize nonce
        fus.generate_nonce()?;

        Ok(fus)
    }

    /// Queries the server for firmware binary metadata matching the requested model, region, and version.
    pub fn fetch_binary_info(
        &self,
        model: &str,
        region: &str,
        version: &str,
    ) -> Result<BinaryInform> {
        let mut parts: Vec<&str> = version.split('/').collect();
        if parts.len() == 3 {
            parts.push(parts[0]);
        }
        let fw = parts.join("/");
        let nonce = self.auth_state.lock().unwrap().nonce.clone();
        let req_xml = xml::binary_inform_req_xml(model, region, &fw, &nonce);

        let xml = self
            .make_req("NF_SmartDownloadBinaryInform.do", &req_xml)?
            .text()?;

        BinaryInform::parse(&xml)
    }

    fn make_headers(&self) -> HeaderMap {
        let (encnonce, auth) = {
            let state = self.auth_state.lock().unwrap();
            (state.encnonce.clone(), state.auth.clone())
        };
        let auth_val = format!(
            "FUS nonce=\"{}\", signature=\"{}\", nc=\"\", type=\"\", realm=\"\", newauth=\"1\"",
            encnonce, auth
        );

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_val).unwrap());
        headers.insert(USER_AGENT, HeaderValue::from_static("SMART 2.0"));
        headers
    }

    fn make_req(&self, path: &str, data: &str) -> reqwest::Result<Response> {
        let url = format!("https://neofussvr.sslcs.cdngc.net/{}", path);
        let resp = self
            .client
            .post(&url)
            .headers(self.make_headers())
            .body(data.to_string())
            .send()?
            .error_for_status()?;

        if let Some(nonce) = resp
            .headers()
            .get("NONCE")
            .or_else(|| resp.headers().get("nonce"))
            .and_then(|n| n.to_str().ok())
        {
            let nonce_str = nonce.to_string();
            if !nonce_str.is_empty() {
                let mut state = self.auth_state.lock().unwrap();
                if nonce_str != state.encnonce {
                    state.encnonce = nonce_str;
                    state.nonce = state.encnonce.clone();
                    state.auth = auth::decrypt_nonce(&state.encnonce);
                }
            }
        }

        Ok(resp)
    }

    fn generate_nonce(&self) -> reqwest::Result<()> {
        self.make_req("NF_SmartDownloadGenerateNonce.do", "")?;
        Ok(())
    }

    fn send_init_download(&self, info: &BinaryInform) -> Result<()> {
        let nonce = self.auth_state.lock().unwrap().nonce.clone();
        let init_xml = xml::binary_init_req_xml(
            &info.filename,
            &nonce,
            &info.version,
            &info.model_type,
            &info.region,
        );
        let xml = self
            .make_req("NF_SmartDownloadBinaryInitForMass.do", &init_xml)?
            .text()?;
        xml::check_xml_status(&xml)
    }

    /// Requests a download authorization ticket from FUS for `info` and consumes
    /// this client into an active [`DownloadSession`].
    pub fn init_download(self, info: BinaryInform) -> Result<DownloadSession> {
        self.send_init_download(&info)?;
        Ok(DownloadSession {
            client: self,
            info,
            reauth_gen: Mutex::new(0),
        })
    }
}

/// Active firmware download session holding an authenticated [`FusClient`]
/// and the resolved [`BinaryInform`] metadata.
pub struct DownloadSession {
    client: FusClient,
    info: BinaryInform,
    /// Reauthentication generation counter. It also serves as the lock that
    /// serializes reauth: a token expiry observed by many download threads at
    /// once triggers a single refresh, and the rest reuse its result.
    reauth_gen: Mutex<u64>,
}

impl DownloadSession {
    /// Returns the firmware binary metadata associated with this download session.
    pub fn info(&self) -> &BinaryInform {
        &self.info
    }

    /// Streams and transparently decrypts the entire firmware binary package,
    /// stripping trailing PKCS#7 padding and automatically handling re-authentication
    /// as needed.
    pub fn fetch(&self) -> Result<impl Read + use<>> {
        self.fetch_range(None, None)
    }

    /// Fetches a specific byte range or chunk of the firmware binary package, transparently
    /// decrypting it and automatically handling re-authentication as needed.
    ///
    /// Both `start` and the inclusive `end` are automatically expanded outward to the nearest
    /// 16-byte AES-128 block boundaries when fetching from the server, with any excess leading
    /// bytes, trailing bytes, or EOF PKCS#7 padding trimmed from the returned stream.
    pub fn fetch_range(&self, start: Option<u64>, end: Option<u64>) -> Result<impl Read + use<>> {
        let aligned = AlignedRange::new(start, end, self.info.size);
        if aligned.dec_remaining == 0 {
            return Ok(DecryptReader(None));
        }

        // Capture the token generation backing this request. If the request is
        // rejected as unauthorized, this lets the refresh tell whether another
        // thread has already rotated the token in the meantime.
        let gen_used = *self.reauth_gen.lock().unwrap();

        let resp = match self.fetch_range_once(aligned.http_start, aligned.http_end) {
            Err(e) if e.status() == Some(reqwest::StatusCode::UNAUTHORIZED) => {
                // The download token expired mid-transfer. Refresh it (at most
                // once per expiry across all threads) and retry the request once
                // with the new token. If it still fails, the caller's retry loop
                // takes over.
                self.reauthenticate(gen_used);
                self.fetch_range_once(aligned.http_start, aligned.http_end)?
            }
            other => other?,
        };

        Ok(DecryptReader::new(resp, self.get_decryptor(), aligned))
    }

    fn fetch_range_once(&self, start: Option<u64>, end: Option<u64>) -> reqwest::Result<Response> {
        let mut headers = self.client.make_headers();
        match (start, end) {
            (Some(s), Some(e)) => headers.insert(
                RANGE,
                HeaderValue::from_str(&format!("bytes={}-{}", s, e)).unwrap(),
            ),
            (None, Some(e)) => headers.insert(
                RANGE,
                HeaderValue::from_str(&format!("bytes=0-{}", e)).unwrap(),
            ),
            (Some(s), None) => headers.insert(
                RANGE,
                HeaderValue::from_str(&format!("bytes={}-", s)).unwrap(),
            ),
            _ => None,
        };

        let url = format!(
            "http://cloud-neofussvr.samsungmobile.com/NF_SmartDownloadBinaryForMass.do?file={}{}",
            self.info.path, self.info.filename
        );
        self.client
            .client
            .get(url)
            .headers(headers)
            .send()?
            .error_for_status()
    }

    /// Re-establish the session after the auth token expired (HTTP 401),
    /// rewriting the shared `nonce`/`encnonce`/`auth`.
    ///
    /// `gen_seen` is the generation the failed request was signed with. Holding
    /// `reauth_gen` serializes refreshes, and the generation check makes the
    /// refresh idempotent: the first thread to react to an expiry does the work
    /// and bumps the counter, so the others — which were waiting on the same
    /// lock with the same `gen_seen` — simply return and retry with the token
    /// that is now fresh. The new generation is published only on full success,
    /// so a failed refresh leaves the counter untouched and is retried.
    fn reauthenticate(&self, gen_seen: u64) {
        let mut generation = self.reauth_gen.lock().unwrap();
        if *generation != gen_seen {
            return;
        }
        if self.client.generate_nonce().is_ok()
            && self.client.send_init_download(&self.info).is_ok()
        {
            *generation += 1;
        }
    }

    fn get_decryptor(&self) -> Aes128EcbDec {
        Aes128EcbDec::new(&self.info.key.into())
    }
}

struct AlignedRange {
    http_start: Option<u64>,
    http_end: Option<u64>,
    skip_start: usize,
    dec_remaining: u64,
    enc_remaining: u64,
    unpad_tail: bool,
}

impl AlignedRange {
    fn new(start: Option<u64>, end: Option<u64>, file_size: u64) -> Self {
        let empty = Self {
            http_start: None,
            http_end: None,
            skip_start: 0,
            dec_remaining: 0,
            enc_remaining: 0,
            unpad_tail: false,
        };
        if file_size == 0 {
            return empty;
        }

        let req_start = start.unwrap_or(0);
        let max_end = file_size - 1;
        let req_end = end.map_or(max_end, |e| e.min(max_end));
        if req_end < req_start {
            return empty;
        }

        let aligned_start = req_start & !15;
        let aligned_end = (req_end | 15).min(max_end);
        let Some(dec_remaining) = (req_end - req_start).checked_add(1) else {
            return empty;
        };
        let Some(enc_remaining) = (aligned_end - aligned_start).checked_add(1) else {
            return empty;
        };

        Self {
            http_start: start.map(|_| aligned_start),
            http_end: end.map(|_| aligned_end),
            skip_start: (req_start - aligned_start) as usize,
            dec_remaining,
            enc_remaining,
            unpad_tail: file_size >= 16 && file_size.is_multiple_of(16) && aligned_end == max_end,
        }
    }
}

struct DecryptReader<R>(Option<DecryptInner<R>>);

struct DecryptInner<R> {
    resp: R,
    dec: Aes128EcbDec,
    rem: [u8; 16],
    enc_len: usize,
    dec_pos: usize,
    dec_len: usize,
    skip_start: usize,
    dec_remaining: u64,
    enc_remaining: u64,
    unpad_tail: bool,
}

impl<R> DecryptReader<R> {
    fn new(resp: R, dec: Aes128EcbDec, aligned: AlignedRange) -> Self {
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
            enc_remaining: aligned.enc_remaining,
            unpad_tail: aligned.unpad_tail,
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

fn unpadded_block_len(block: &[u8; 16]) -> usize {
    let pad = block[15] as usize;
    if (1..=16).contains(&pad) && block[16 - pad..].iter().all(|&b| b == pad as u8) {
        16 - pad
    } else {
        16
    }
}

fn read_at_least_16<R: Read>(resp: &mut R, dst: &mut [u8], total: &mut usize) -> io::Result<()> {
    while *total < 16 {
        match resp.read(&mut dst[*total..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "premature EOF in encrypted stream",
                ));
            }
            Ok(n) => *total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let Some(inner) = self.0.as_mut() else {
            return Ok(0);
        };

        if inner.dec_pos < inner.dec_len {
            let n = inner.drain_dec_rem(buf);
            if inner.dec_remaining == 0 {
                self.0 = None;
            }
            return Ok(n);
        }

        let enc_fast_limit = if inner.unpad_tail {
            inner.enc_remaining.saturating_sub(16)
        } else {
            inner.enc_remaining
        };
        let fast_cap = buf
            .len()
            .min(inner.dec_remaining.min(usize::MAX as u64) as usize)
            .min(enc_fast_limit.min(usize::MAX as u64) as usize);
        let max_aligned = fast_cap & !15;

        // Zero-copy fast path: aligned start and >= 16 non-final bytes requested and available.
        if inner.skip_start == 0 && max_aligned >= 16 {
            let mut total = inner.enc_len;
            buf[..total].copy_from_slice(&inner.rem[..total]);
            inner.enc_len = 0;

            if let Err(e) = read_at_least_16(&mut inner.resp, &mut buf[..max_aligned], &mut total) {
                inner.rem[..total].copy_from_slice(&buf[..total]);
                inner.enc_len = total;
                return Err(e);
            }

            let tail_len = total & 15;
            let aligned = total - tail_len;
            inner.rem[..tail_len].copy_from_slice(&buf[aligned..total]);
            inner.enc_len = tail_len;

            let (blocks, _) = InOutBuf::from(&mut buf[..aligned]).into_chunks();
            inner.dec.decrypt_blocks_inout(blocks);

            inner.enc_remaining -= aligned as u64;
            inner.dec_remaining -= aligned as u64;
            if inner.dec_remaining == 0 {
                self.0 = None;
            }
            return Ok(aligned);
        }

        // Staging path for unaligned prefix, small caller buffers (< 16),
        // unaligned range end (< 16 remaining), or the final PKCS#7-padded block.
        let mut total = inner.enc_len;
        inner.enc_len = 0;

        if let Err(e) = read_at_least_16(&mut inner.resp, &mut inner.rem, &mut total) {
            inner.enc_len = total;
            return Err(e);
        }
        inner.enc_remaining = inner.enc_remaining.saturating_sub(16);

        let (blocks, _) = InOutBuf::from(&mut inner.rem[..]).into_chunks();
        inner.dec.decrypt_blocks_inout(blocks);

        let block_plain_len = if inner.unpad_tail && inner.enc_remaining == 0 {
            unpadded_block_len(&inner.rem)
        } else {
            16
        };

        let start_in_block = inner.skip_start.min(block_plain_len);
        inner.skip_start = 0;
        let max_avail = inner.dec_remaining.min(16) as usize;
        let avail = (block_plain_len - start_in_block).min(max_avail);
        inner.dec_pos = start_in_block;
        inner.dec_len = start_in_block + avail;
        if inner.enc_remaining == 0 {
            inner.dec_remaining = avail as u64;
        }

        let n = inner.drain_dec_rem(buf);
        if inner.dec_remaining == 0 {
            self.0 = None;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockModeEncrypt;
    use std::io::Cursor;

    const TEST_KEY: [u8; 16] = [0x13; 16];

    fn encrypt_test_data(plaintext: &[u8]) -> Vec<u8> {
        let mut buf = plaintext.to_vec();
        let mut enc = ecb::Encryptor::<aes::Aes128>::new_from_slice(&TEST_KEY).unwrap();
        let (blocks, tail) = InOutBuf::from(buf.as_mut_slice()).into_chunks();
        assert!(tail.is_empty());
        enc.encrypt_blocks_inout(blocks);
        buf
    }

    fn encrypt_pkcs7(plaintext: &[u8]) -> Vec<u8> {
        let pad = 16 - (plaintext.len() % 16);
        let mut padded = plaintext.to_vec();
        padded.extend(std::iter::repeat_n(pad as u8, pad));
        encrypt_test_data(&padded)
    }

    struct TrickleReader {
        data: Vec<u8>,
        pos: usize,
        step: usize,
        reads: usize,
    }

    impl Read for TrickleReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            if self.reads.is_multiple_of(3) {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "eintr"));
            }
            let n = (self.data.len() - self.pos).min(self.step).min(buf.len());
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    fn read_range(
        ciphertext: &[u8],
        start: Option<u64>,
        end: Option<u64>,
        step: usize,
        buf_len: usize,
    ) -> ((Option<u64>, Option<u64>), Vec<u8>) {
        let file_size = ciphertext.len() as u64;
        let aligned = AlignedRange::new(start, end, file_size);
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
            TrickleReader {
                data: slice,
                pos: 0,
                step,
                reads: 0,
            },
            Aes128EcbDec::new_from_slice(&TEST_KEY).unwrap(),
            aligned,
        );

        let mut out = Vec::new();
        let mut buf = vec![0u8; buf_len];
        loop {
            let n = reader.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        (http_range, out)
    }

    #[test]
    fn test_decrypt_reader_ranges() {
        let plaintext: Vec<u8> = (0..128_u8).collect();
        let ciphertext = encrypt_test_data(&plaintext);

        type Case<'a> = (
            Option<u64>,
            Option<u64>,
            (Option<u64>, Option<u64>),
            usize,
            usize,
            &'a [u8],
        );
        let cases: &[Case<'_>] = &[
            (None, None, (None, None), 5, 64, &plaintext),
            (None, Some(20), (None, Some(31)), 64, 64, &plaintext[..=20]),
            (
                Some(5),
                Some(73),
                (Some(0), Some(79)),
                3,
                7,
                &plaintext[5..=73],
            ),
            (Some(19), None, (Some(16), None), 11, 256, &plaintext[19..]),
            (Some(20), Some(10), (None, None), 16, 64, &[]),
            (Some(128), None, (None, None), 16, 64, &[]),
        ];

        for &(start, end, exp_range, step, buf_len, expected) in cases {
            let (http_range, out) = read_range(&ciphertext, start, end, step, buf_len);
            assert_eq!(http_range, exp_range, "range=({start:?}, {end:?})");
            assert_eq!(out, expected, "range=({start:?}, {end:?})");
        }
    }

    #[test]
    fn test_decrypt_reader_pkcs7_unpadding() {
        // Test 1-byte padding, partial-block (5-byte) padding, and full-block (16-byte) padding.
        for plain_len in [15_usize, 43, 48] {
            let plaintext: Vec<u8> = (0..plain_len).map(|i| (i as u8).wrapping_mul(3)).collect();
            let ciphertext = encrypt_pkcs7(&plaintext);

            for (step, buf_len) in [(5, 7), (64, 64)] {
                let (_, full) = read_range(&ciphertext, None, None, step, buf_len);
                assert_eq!(full, plaintext, "plain_len={plain_len}");

                let (_, tail) = read_range(&ciphertext, Some(10), None, step, buf_len);
                assert_eq!(tail, &plaintext[10..], "plain_len={plain_len}");
            }
        }

        // Ranges overlapping and inside trailing PKCS#7 padding (43 plain + 5 pad = 48 encrypted).
        let plaintext: Vec<u8> = (0..43_u8).map(|i| i + 50).collect();
        let ciphertext = encrypt_pkcs7(&plaintext);
        assert_eq!(ciphertext.len(), 48);

        // Straddling plaintext/padding boundary (40..=46 -> only 40..43 are real plaintext)
        let (_, straddle) = read_range(&ciphertext, Some(40), Some(46), 7, 32);
        assert_eq!(straddle, &plaintext[40..43]);

        // Entirely inside the 5-byte padding region
        let (_, only_pad) = read_range(&ciphertext, Some(43), Some(47), 16, 32);
        assert!(only_pad.is_empty());

        // Starting at the full 16-byte PKCS#7 block (48 plain + 16 pad = 64 encrypted)
        let aligned_plain: Vec<u8> = (0..48_u8).map(|i| i + 20).collect();
        let aligned_cipher = encrypt_pkcs7(&aligned_plain);
        assert_eq!(aligned_cipher.len(), 64);
        let (_, pad_block) = read_range(&aligned_cipher, Some(48), None, 16, 64);
        assert!(pad_block.is_empty());
    }

    #[test]
    fn test_decrypt_reader_truncated_block_errors() {
        let plaintext = vec![0xAA; 32];
        let ciphertext = encrypt_test_data(&plaintext);

        // Truncated mid-block (25 of 32 bytes) and on a block boundary (16 of 32 bytes)
        for trunc_len in [25_usize, 16] {
            let aligned = AlignedRange::new(None, None, 32);
            let mut reader = DecryptReader::new(
                Cursor::new(ciphertext[..trunc_len].to_vec()),
                Aes128EcbDec::new(&TEST_KEY.into()),
                aligned,
            );
            let mut out = [0u8; 64];
            assert_eq!(reader.read(&mut out).unwrap(), 16);
            let err = reader.read(&mut out[16..]).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        }
    }

    #[test]
    fn test_decrypt_reader_error_recovery_across_paths() {
        struct FlakyReader {
            data: Vec<u8>,
            pos: usize,
            fail_next: bool,
        }

        impl Read for FlakyReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.fail_next {
                    self.fail_next = false;
                    return Err(io::Error::from(io::ErrorKind::WouldBlock));
                }
                let n = (self.data.len() - self.pos).min(7).min(buf.len());
                if n > 0 {
                    self.fail_next = true;
                }
                buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                self.pos += n;
                Ok(n)
            }
        }

        let plaintext: Vec<u8> = (0..37_u8).map(|i| i ^ 0x5A).collect();
        let ciphertext = encrypt_pkcs7(&plaintext);
        let aligned = AlignedRange::new(None, None, ciphertext.len() as u64);
        let mut reader = DecryptReader::new(
            FlakyReader {
                data: ciphertext,
                pos: 0,
                fail_next: false,
            },
            Aes128EcbDec::new(&TEST_KEY.into()),
            aligned,
        );

        // Alternate between 64-byte (fast path) and 3-byte (staging path) buffers across WouldBlock
        let mut out = Vec::new();
        let mut use_large = true;
        loop {
            let mut buf = vec![0u8; if use_large { 64 } else { 3 }];
            match reader.read(&mut buf) {
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
    }
}
