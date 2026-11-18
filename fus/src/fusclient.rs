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

use crate::compat::MaybeSend;
use crate::data::{DataSource, resolve_range_bounds};
use crate::error::{HttpError, Result};
use crate::http::{HttpClient, HttpMethod, HttpRequest, HttpResponse, PlatformClient};
use crate::{auth, xml};
use aes::cipher::inout::InOutBuf;
use aes::cipher::{BlockModeDecrypt, KeyInit};
use futures::io::AsyncRead;
use futures::lock::Mutex as AsyncMutex;
use std::io;
use std::ops::RangeBounds;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};
use xml::BinaryInform;

type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

/// Authentication token state. The download GET signs every request with
/// `encnonce`/`auth`; these expire, so they live behind a lock and are shared
/// by reference across all download tasks (which only read them) and the
/// occasional reauthentication (which rewrites them). See [`FusClient`] and
/// [`DownloadSession`].
#[derive(Default)]
struct AuthState {
    auth: String,
    nonce: String,
    encnonce: String,
}

impl AuthState {
    fn auth_header(&self) -> String {
        format!(
            "FUS nonce=\"{}\", signature=\"{}\", nc=\"\", type=\"\", realm=\"\", newauth=\"1\"",
            self.encnonce, self.auth
        )
    }
}

/// Client coordinating API communication and security authentication
/// with the Samsung Firmware Update Server (FUS).
pub struct FusClient {
    client: PlatformClient,
    auth_state: Mutex<AuthState>,
}

impl FusClient {
    /// Creates a new `FusClient` and initiates the standard FUS handshake to generate a session nonce.
    pub async fn new() -> Result<Self> {
        let fus = FusClient {
            client: PlatformClient::new()?,
            auth_state: Mutex::new(AuthState::default()),
        };

        // Initialize nonce
        fus.generate_nonce().await?;

        Ok(fus)
    }

    /// Queries the server for firmware binary metadata matching the requested model, region, and version.
    pub async fn fetch_binary_info(
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
            .make_req("NF_SmartDownloadBinaryInform.do", &req_xml)
            .await?
            .into_text()
            .await?;

        BinaryInform::parse(&xml)
    }

    async fn make_req(
        &self,
        path: &str,
        data: &str,
    ) -> std::result::Result<impl HttpResponse + use<>, HttpError> {
        let url = format!("https://neofussvr.sslcs.cdngc.net/{path}");
        let auth_val = self.auth_state.lock().unwrap().auth_header();
        let headers = [
            ("Authorization", auth_val.as_str()),
            ("User-Agent", "SMART 2.0"),
        ];

        let resp = self
            .client
            .send(HttpRequest {
                method: HttpMethod::Post,
                url: &url,
                headers: &headers,
                body: Some(data.as_bytes()),
            })
            .await?
            .ensure_success()?;

        if let Some(nonce) = resp.header("nonce").filter(|n| !n.is_empty()) {
            let mut state = self.auth_state.lock().unwrap();
            if nonce != state.encnonce {
                state.encnonce = nonce.to_string();
                state.nonce = state.encnonce.clone();
                state.auth = auth::decrypt_nonce(&state.encnonce);
            }
        }

        Ok(resp)
    }

    async fn generate_nonce(&self) -> std::result::Result<(), HttpError> {
        self.make_req("NF_SmartDownloadGenerateNonce.do", "")
            .await?;
        Ok(())
    }

    async fn send_init_download(&self, info: &BinaryInform) -> Result<()> {
        let nonce = self.auth_state.lock().unwrap().nonce.clone();
        let init_xml = xml::binary_init_req_xml(
            &info.filename,
            &nonce,
            &info.version,
            &info.model_type,
            &info.region,
        );
        let xml = self
            .make_req("NF_SmartDownloadBinaryInitForMass.do", &init_xml)
            .await?
            .into_text()
            .await?;
        xml::check_xml_status(&xml)
    }

    /// Requests a download authorization ticket from FUS for `info` and consumes
    /// this client into an active [`DownloadSession`].
    pub async fn init_download(self, info: BinaryInform) -> Result<DownloadSession> {
        self.send_init_download(&info).await?;
        Ok(DownloadSession {
            client: self,
            info,
            reauth_gen: AsyncMutex::new(0),
        })
    }
}

/// Active firmware download session holding an authenticated [`FusClient`]
/// and the resolved [`BinaryInform`] metadata.
pub struct DownloadSession {
    client: FusClient,
    info: BinaryInform,
    /// Reauthentication generation counter. It also serves as the lock that
    /// serializes reauth: a token expiry observed by many download tasks at
    /// once triggers a single refresh, and the rest reuse its result.
    reauth_gen: AsyncMutex<u64>,
}

impl DownloadSession {
    #[cfg(all(not(target_arch = "wasm32"), test))]
    pub(crate) fn from_mock(client: crate::http::MockClient, info: BinaryInform) -> Self {
        Self {
            client: FusClient {
                client,
                auth_state: Mutex::new(AuthState::default()),
            },
            info,
            reauth_gen: AsyncMutex::new(0),
        }
    }

    /// Returns the firmware binary metadata associated with this download session.
    pub fn info(&self) -> &BinaryInform {
        &self.info
    }

    async fn fetch_range_once(
        &self,
        start: Option<u64>,
        end: Option<u64>,
    ) -> std::result::Result<impl HttpResponse + use<>, HttpError> {
        let auth_val = self.client.auth_state.lock().unwrap().auth_header();
        let range_val = match (start, end) {
            (Some(s), Some(e)) => Some(format!("bytes={s}-{e}")),
            (None, Some(e)) => Some(format!("bytes=0-{e}")),
            (Some(s), None) => Some(format!("bytes={s}-")),
            (None, None) => None,
        };

        let mut headers = [
            ("Authorization", auth_val.as_str()),
            ("User-Agent", "SMART 2.0"),
            ("Range", ""),
        ];
        let headers = if let Some(range) = &range_val {
            headers[2].1 = range.as_str();
            &headers[..]
        } else {
            &headers[..2]
        };

        let url = format!(
            "http://cloud-neofussvr.samsungmobile.com/NF_SmartDownloadBinaryForMass.do?file={}{}",
            self.info.path, self.info.filename
        );
        self.client
            .client
            .send(HttpRequest {
                method: HttpMethod::Get,
                url: &url,
                headers,
                body: None,
            })
            .await?
            .ensure_success()
    }

    /// Re-establish the session after the auth token expired (HTTP 401),
    /// rewriting the shared `nonce`/`encnonce`/`auth`.
    ///
    /// `gen_seen` is the generation the failed request was signed with. Holding
    /// `reauth_gen` serializes refreshes, and the generation check makes the
    /// refresh idempotent: the first task to react to an expiry does the work
    /// and bumps the counter, so the others — which were waiting on the same
    /// lock with the same `gen_seen` — simply return and retry with the token
    /// that is now fresh. The new generation is published only on full success,
    /// so a failed refresh leaves the counter untouched and is retried.
    async fn reauthenticate(&self, gen_seen: u64) {
        let mut generation = self.reauth_gen.lock().await;
        if *generation != gen_seen {
            return;
        }
        if self.client.generate_nonce().await.is_ok()
            && self.client.send_init_download(&self.info).await.is_ok()
        {
            *generation += 1;
        }
    }

    fn get_decryptor(&self) -> Aes128EcbDec {
        Aes128EcbDec::new(&self.info.key.into())
    }
}

impl DataSource for DownloadSession {
    fn size_bounds(&self) -> (u64, u64) {
        if self.info.size == 0 {
            (0, 0)
        } else {
            (self.info.size.saturating_sub(16), self.info.size)
        }
    }

    async fn fetch_range(
        &self,
        range: impl RangeBounds<u64> + Send,
    ) -> io::Result<impl AsyncRead + MaybeSend + Unpin> {
        let aligned = AlignedRange::new(range, self.info.size);
        if aligned.dec_remaining == 0 {
            return Ok(DecryptReader(None));
        }

        // Capture the token generation backing this request. If the request is
        // rejected as unauthorized, this lets the refresh tell whether another
        // task has already rotated the token in the meantime.
        let gen_used = *self.reauth_gen.lock().await;

        let resp = match self
            .fetch_range_once(aligned.http_start, aligned.http_end)
            .await
        {
            Err(HttpError::Status(401)) => {
                // The download token expired mid-transfer. Refresh it (at most
                // once per expiry across all tasks) and retry the request once
                // with the new token. If it still fails, the caller's retry loop
                // takes over.
                self.reauthenticate(gen_used).await;
                self.fetch_range_once(aligned.http_start, aligned.http_end)
                    .await
                    .map_err(io::Error::other)?
            }
            other => other.map_err(io::Error::other)?,
        };

        Ok(DecryptReader::new(
            resp.into_reader(),
            self.get_decryptor(),
            aligned,
        ))
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
    fn new(range: impl RangeBounds<u64>, file_size: u64) -> Self {
        let empty = Self {
            http_start: None,
            http_end: None,
            skip_start: 0,
            dec_remaining: 0,
            enc_remaining: 0,
            unpad_tail: false,
        };
        let Some((req_start, end_opt)) = resolve_range_bounds(range) else {
            return empty;
        };
        if file_size == 0 || req_start >= file_size {
            return empty;
        }

        let max_end = file_size - 1;
        let end_excl = end_opt.map_or(file_size, |e| e.min(file_size));
        let req_end = end_excl - 1;
        let aligned_start = req_start & !15;
        let aligned_end = (req_end | 15).min(max_end);
        let dec_remaining = end_excl - req_start;
        let enc_remaining = aligned_end - aligned_start + 1;

        Self {
            http_start: (req_start > 0).then_some(aligned_start),
            http_end: end_opt.map(|_| aligned_end),
            skip_start: (req_start - aligned_start) as usize,
            dec_remaining,
            enc_remaining,
            unpad_tail: file_size >= 16 && file_size.is_multiple_of(16) && aligned_end == max_end,
        }
    }
}

/// Async reader transparently decrypting an AES-128-ECB FUS byte range and trimming
/// unaligned boundaries and trailing PKCS#7 padding.
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

            match poll_read_at_least_16(&mut inner.resp, cx, &mut buf[..max_aligned], &mut total) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => {
                    inner.rem[..total].copy_from_slice(&buf[..total]);
                    inner.enc_len = total;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    inner.rem[..total].copy_from_slice(&buf[..total]);
                    inner.enc_len = total;
                    return Poll::Pending;
                }
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
            return Poll::Ready(Ok(aligned));
        }

        // Staging path for unaligned prefix, small caller buffers (< 16),
        // unaligned range end (< 16 remaining), or the final PKCS#7-padded block.
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
        Poll::Ready(Ok(n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockModeEncrypt;
    use futures::executor::block_on;
    use futures::io::{AsyncReadExt, Cursor};

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
            let n = (self.data.len() - self.pos).min(self.step).min(buf.len());
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Poll::Ready(Ok(n))
        }
    }

    fn read_range(
        ciphertext: &[u8],
        range: impl RangeBounds<u64>,
        step: usize,
        buf_len: usize,
    ) -> ((Option<u64>, Option<u64>), Vec<u8>) {
        let file_size = ciphertext.len() as u64;
        let aligned = AlignedRange::new(range, file_size);
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
            Aes128EcbDec::new(&TEST_KEY.into()),
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
            let (http_range, out) = read_range(ciphertext, range.clone(), step, buf_len);
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
            (Some(0), Some(79)),
            3,
            7,
            &plaintext[5..=73],
        );
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

            for (step, buf_len) in [(5, 7), (64, 64)] {
                let (_, full) = read_range(&ciphertext, .., step, buf_len);
                assert_eq!(full, plaintext, "plain_len={plain_len}");

                let (_, tail) = read_range(&ciphertext, 10.., step, buf_len);
                assert_eq!(tail, &plaintext[10..], "plain_len={plain_len}");
            }
        }

        // Ranges overlapping and inside trailing PKCS#7 padding (43 plain + 5 pad = 48 encrypted).
        let plaintext: Vec<u8> = (0..43_u8).map(|i| i + 50).collect();
        let ciphertext = encrypt_pkcs7(&plaintext);
        assert_eq!(ciphertext.len(), 48);

        // Straddling plaintext/padding boundary (40..=46 -> only 40..43 are real plaintext)
        let (_, straddle) = read_range(&ciphertext, 40..=46, 7, 32);
        assert_eq!(straddle, &plaintext[40..43]);

        // Entirely inside the 5-byte padding region
        let (_, only_pad) = read_range(&ciphertext, 43..=47, 16, 32);
        assert!(only_pad.is_empty());

        // Starting at the full 16-byte PKCS#7 block (48 plain + 16 pad = 64 encrypted)
        let aligned_plain: Vec<u8> = (0..48_u8).map(|i| i + 20).collect();
        let aligned_cipher = encrypt_pkcs7(&aligned_plain);
        assert_eq!(aligned_cipher.len(), 64);
        let (_, pad_block) = read_range(&aligned_cipher, 48.., 16, 64);
        assert!(pad_block.is_empty());
    }

    #[test]
    fn test_decrypt_reader_truncated_block_errors() {
        let plaintext = vec![0xAA; 32];
        let ciphertext = encrypt_test_data(&plaintext);

        // Truncated mid-block (25 of 32 bytes) and on a block boundary (16 of 32 bytes)
        for trunc_len in [25_usize, 16] {
            let aligned = AlignedRange::new(.., 32);
            let mut reader = DecryptReader::new(
                Cursor::new(ciphertext[..trunc_len].to_vec()),
                Aes128EcbDec::new(&TEST_KEY.into()),
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
        let aligned = AlignedRange::new(.., ciphertext.len() as u64);
        let mut reader = DecryptReader::new(
            FlakyReader {
                data: ciphertext,
                pos: 0,
                reads: 0,
                fail_next: false,
            },
            Aes128EcbDec::new(&TEST_KEY.into()),
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

    #[test]
    fn test_download_session_data_source() {
        use crate::http::{MockClient, MockResponse};
        use std::sync::Arc;

        let plaintext: Vec<u8> = (0..75_u8).map(|i| i.wrapping_mul(5)).collect();
        let ciphertext = Arc::new(encrypt_pkcs7(&plaintext));
        assert_eq!(ciphertext.len(), 80);

        let info = BinaryInform {
            version: "T/T/T/T".into(),
            filename: "test.zip.enc4".into(),
            path: "/t/".into(),
            size: ciphertext.len() as u64,
            key: TEST_KEY,
            model_type: "SM-TEST".into(),
            region: "XAA".into(),
        };

        let requests = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
        let req_log = Arc::clone(&requests);
        let data_ref = Arc::clone(&ciphertext);
        let client = MockClient::from_handler(move |req| {
            let data = Arc::clone(&data_ref);
            let range_hdr = req
                .headers
                .iter()
                .find(|&&(k, _)| k.eq_ignore_ascii_case("Range"))
                .map(|&(_, v)| v.to_string());
            req_log.lock().unwrap().push(range_hdr.clone());
            let (s, e) = match range_hdr.as_deref() {
                None => (0, data.len()),
                Some(spec) => {
                    let spec = spec.strip_prefix("bytes=").unwrap();
                    let (s, e) = spec.split_once('-').unwrap();
                    let start = s.parse::<usize>().unwrap();
                    let end = if e.is_empty() {
                        data.len()
                    } else {
                        (e.parse::<usize>().unwrap() + 1).min(data.len())
                    };
                    (start, end)
                }
            };
            Box::pin(async move { Ok(MockResponse::ok_bytes(data[s..e].to_vec())) })
        });

        let session = DownloadSession::from_mock(client, info);
        assert_eq!(session.size_bounds(), (64, 80));

        let empty_info = BinaryInform {
            size: 0,
            ..session.info().clone()
        };
        let empty_session = DownloadSession::from_mock(
            MockClient::from_handler(|_| {
                Box::pin(async { unreachable!("must not issue HTTP request") })
            }),
            empty_info,
        );
        assert_eq!(empty_session.size_bounds(), (0, 0));

        block_on(async {
            // Empty/out-of-bounds ranges make zero HTTP requests
            let mut empty_out = Vec::new();
            session
                .fetch_range(0..0)
                .await
                .unwrap()
                .read_to_end(&mut empty_out)
                .await
                .unwrap();
            session
                .fetch_range(80..)
                .await
                .unwrap()
                .read_to_end(&mut empty_out)
                .await
                .unwrap();
            assert!(empty_out.is_empty());
            assert!(requests.lock().unwrap().is_empty());

            // Unaligned read_at issues aligned 16-byte range HTTP request
            let mut sub = [0u8; 30];
            assert_eq!(session.read_at(&mut sub, 19).await.unwrap(), 30);
            assert_eq!(&sub, &plaintext[19..49]);
            assert_eq!(
                requests.lock().unwrap().as_slice(),
                &[Some("bytes=16-63".to_string())]
            );

            // Straddling PKCS#7 tail via read_at
            let mut tail = [0u8; 32];
            assert_eq!(session.read_at(&mut tail, 64).await.unwrap(), 11);
            assert_eq!(&tail[..11], &plaintext[64..]);

            // Full fetch() omits Range header and strips PKCS#7 padding
            requests.lock().unwrap().clear();
            let mut full = Vec::new();
            session
                .fetch()
                .await
                .unwrap()
                .read_to_end(&mut full)
                .await
                .unwrap();
            assert_eq!(full, plaintext);
            assert_eq!(requests.lock().unwrap().as_slice(), &[None]);

            // Error mapping via io::Error::other
            let err_session = DownloadSession::from_mock(
                MockClient::from_handler(|_| Box::pin(async { Err(HttpError::Status(503)) })),
                session.info().clone(),
            );
            let err = err_session.fetch().await.err().unwrap();
            assert_eq!(err.kind(), io::ErrorKind::Other);
        });
    }
}
