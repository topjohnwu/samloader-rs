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

use crate::{auth, xml};
use aes::cipher::inout::InOutBuf;
use aes::cipher::{BlockModeDecrypt, KeyInit};
use reqwest::blocking::{Client, Response};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue, RANGE, USER_AGENT};
use std::io::{self, Read};
use std::sync::Mutex;
use std::time::Duration;
use xml::{BinaryInform, VersionInfo};

type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

/// Authentication token state. The download GET signs every request with
/// `encnonce`/`auth`; these expire, so they live behind a lock and are shared
/// by reference across all download threads (which only read them) and the
/// occasional reauthentication (which rewrites them). See [`FusClient`].
#[derive(Default)]
struct AuthState {
    auth: String,
    nonce: String,
    encnonce: String,
}

/// Client coordinating API communication, security authentication, and file downloading
/// with the Samsung Firmware Update Server (FUS).
pub struct FusClient {
    client: Client,
    auth_state: Mutex<AuthState>,
    /// Reauthentication generation counter. It also serves as the lock that
    /// serializes reauth: a token expiry observed by many download threads at
    /// once triggers a single refresh, and the rest reuse its result.
    reauth_gen: Mutex<u64>,
    /// The parsed and resolved binary download metadata for the active firmware session.
    pub info: BinaryInform,
}

impl FusClient {
    /// Creates a new `FusClient` and initiates the standard FUS handshake to generate a session nonce.
    pub fn new() -> reqwest::Result<Self> {
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
            reauth_gen: Mutex::new(0),
            info: Default::default(),
        };

        // Initialize nonce
        fus.make_req("NF_SmartDownloadGenerateNonce.do", fus.make_headers(), "")?;

        Ok(fus)
    }

    #[cfg(test)]
    pub(crate) fn new_mock(info: BinaryInform) -> Self {
        Self {
            client: Client::new(),
            auth_state: Mutex::new(AuthState::default()),
            reauth_gen: Mutex::new(0),
            info,
        }
    }

    /// Queries the server for firmware binary metadata matching the requested model, region, and version.
    pub fn fetch_binary_info(&mut self, model: &str, region: &str, version: &str) {
        let mut parts: Vec<&str> = version.split('/').collect();
        if parts.len() == 3 {
            parts.push(parts[0]);
        }
        let fw = parts.join("/");
        let nonce = self.auth_state.lock().unwrap().nonce.clone();
        let req_xml = xml::binary_inform_req_xml(model, region, &fw, &nonce);

        let xml = self
            .make_req(
                "NF_SmartDownloadBinaryInform.do",
                self.make_headers(),
                &req_xml,
            )
            .and_then(Response::text)
            .expect("Info request failed");

        self.info = BinaryInform::parse(&xml).expect("Info request invalid");
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

    fn make_history_headers(&self, model: &str) -> HeaderMap {
        let (client_nonce, signature) = auth::compute_history_headers(model);
        let auth_val = format!(
            "FUS nonce=\"{}\", signature=\"{}\", nc=\"00000001\", type=\"auth\", realm=\"interface\"",
            client_nonce, signature
        );

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_val).unwrap());
        headers.insert(USER_AGENT, HeaderValue::from_static("SMART 2.0"));
        headers
    }

    fn make_req(&self, path: &str, headers: HeaderMap, data: &str) -> reqwest::Result<Response> {
        let url = format!("https://neofussvr.sslcs.cdngc.net/{}", path);
        let resp = self
            .client
            .post(&url)
            .headers(headers)
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

    /// Fetches the historical list of released firmware versions for the target model and region.
    pub fn fetch_history(&self, model: &str, region: &str) -> reqwest::Result<VersionInfo> {
        let req_xml = xml::history_req_xml(model, region);
        let resp = self.make_req(
            "SmartHistory.do",
            self.make_history_headers(model),
            &req_xml,
        )?;
        let xml = resp.text()?;
        Ok(xml::parse_history_xml(&xml).expect("Failed to parse history.xml"))
    }

    /// Requests a download authorization ticket from FUS for the currently selected firmware file.
    pub fn init_download(&self) -> reqwest::Result<()> {
        let nonce = self.auth_state.lock().unwrap().nonce.clone();
        let init_xml = xml::binary_init_req_xml(
            &self.info.filename,
            &nonce,
            &self.info.version,
            &self.info.model_type,
            &self.info.region,
        );
        self.make_req(
            "NF_SmartDownloadBinaryInitForMass.do",
            self.make_headers(),
            &init_xml,
        )?;
        Ok(())
    }

    /// Fetches a specific byte range or chunk of the firmware binary package, transparently
    /// decrypting it and automatically handling re-authentication as needed.
    ///
    /// Both `start` and the inclusive `end` are automatically expanded outward to the nearest
    /// 16-byte AES-128 block boundaries when fetching from the server, with any excess leading
    /// or trailing bytes trimmed from the returned stream.
    pub fn download_file(
        &self,
        start: Option<u64>,
        end: Option<u64>,
    ) -> reqwest::Result<impl Read + use<>> {
        let aligned = AlignedRange::new(start, end);
        if aligned.remaining == Some(0) {
            return Ok(DecryptReader(None));
        }

        // Capture the token generation backing this request. If the request is
        // rejected as unauthorized, this lets the refresh tell whether another
        // thread has already rotated the token in the meantime.
        let gen_used = *self.reauth_gen.lock().unwrap();

        let resp = match self.download_file_once(aligned.start, aligned.end) {
            Err(e) if e.status() == Some(reqwest::StatusCode::UNAUTHORIZED) => {
                // The download token expired mid-transfer. Refresh it (at most
                // once per expiry across all threads) and retry the request once
                // with the new token. If it still fails, the caller's retry loop
                // takes over.
                self.reauthenticate(gen_used);
                self.download_file_once(aligned.start, aligned.end)?
            }
            other => other?,
        };

        Ok(DecryptReader::new(
            resp,
            self.get_decryptor(),
            aligned.skip_start,
            aligned.remaining,
        ))
    }

    fn download_file_once(
        &self,
        start: Option<u64>,
        end: Option<u64>,
    ) -> reqwest::Result<Response> {
        let mut headers = self.make_headers();
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
        if self
            .make_req("NF_SmartDownloadGenerateNonce.do", self.make_headers(), "")
            .is_ok()
            && self.init_download().is_ok()
        {
            *generation += 1;
        }
    }

    fn get_decryptor(&self) -> Aes128EcbDec {
        Aes128EcbDec::new_from_slice(self.info.key.as_slice()).unwrap()
    }
}

struct AlignedRange {
    start: Option<u64>,
    end: Option<u64>,
    skip_start: usize,
    remaining: Option<u64>,
}

impl AlignedRange {
    fn new(start: Option<u64>, end: Option<u64>) -> Self {
        let req_start = start.unwrap_or(0);
        if let Some(req_end) = end
            && req_end < req_start
        {
            return Self {
                start: None,
                end: None,
                skip_start: 0,
                remaining: Some(0),
            };
        }

        let aligned_start = req_start & !15;
        Self {
            start: start.map(|_| aligned_start),
            end: end.map(|e| e | 15),
            skip_start: (req_start - aligned_start) as usize,
            remaining: end.and_then(|e| (e - req_start).checked_add(1)),
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
    remaining: Option<u64>,
}

impl<R> DecryptReader<R> {
    fn new(resp: R, dec: Aes128EcbDec, skip_start: usize, remaining: Option<u64>) -> Self {
        Self(Some(DecryptInner {
            resp,
            dec,
            rem: [0; 16],
            enc_len: 0,
            dec_pos: 0,
            dec_len: 0,
            skip_start,
            remaining,
        }))
    }
}

impl<R> DecryptInner<R> {
    fn drain_dec_rem(&mut self, buf: &mut [u8]) -> usize {
        let n = (self.dec_len - self.dec_pos).min(buf.len());
        buf[..n].copy_from_slice(&self.rem[self.dec_pos..self.dec_pos + n]);
        self.dec_pos += n;
        if let Some(rem) = &mut self.remaining {
            *rem -= n as u64;
        }
        n
    }
}

fn read_at_least_16<R: Read>(resp: &mut R, dst: &mut [u8], total: &mut usize) -> io::Result<()> {
    while *total < 16 {
        match resp.read(&mut dst[*total..]) {
            Ok(0) if *total == 0 => return Ok(()),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated AES block at EOF",
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
            if inner.remaining == Some(0) {
                self.0 = None;
            }
            return Ok(n);
        }

        // Zero-copy fast path: aligned start, >= 16 bytes requested and remaining.
        if inner.skip_start == 0 && buf.len() >= 16 && inner.remaining.is_none_or(|rem| rem >= 16) {
            let cap = inner.remaining.map_or(buf.len(), |rem| {
                buf.len().min(rem.min(usize::MAX as u64) as usize)
            });
            let max_aligned = cap & !15;

            let mut total = inner.enc_len;
            buf[..total].copy_from_slice(&inner.rem[..total]);
            inner.enc_len = 0;

            if let Err(e) = read_at_least_16(&mut inner.resp, &mut buf[..max_aligned], &mut total) {
                inner.rem[..total].copy_from_slice(&buf[..total]);
                inner.enc_len = total;
                return Err(e);
            }
            if total == 0 {
                self.0 = None;
                return Ok(0);
            }

            let tail_len = total & 15;
            let aligned = total - tail_len;
            inner.rem[..tail_len].copy_from_slice(&buf[aligned..total]);
            inner.enc_len = tail_len;

            let (blocks, _) = InOutBuf::from(&mut buf[..aligned]).into_chunks();
            inner.dec.decrypt_blocks_inout(blocks);

            if let Some(rem) = &mut inner.remaining {
                *rem -= aligned as u64;
                if *rem == 0 {
                    self.0 = None;
                }
            }
            return Ok(aligned);
        }

        // Staging path for unaligned prefix, small caller buffers (< 16), or final tail (< 16).
        let mut total = inner.enc_len;
        inner.enc_len = 0;

        if let Err(e) = read_at_least_16(&mut inner.resp, &mut inner.rem, &mut total) {
            inner.enc_len = total;
            return Err(e);
        }
        if total == 0 {
            self.0 = None;
            return Ok(0);
        }

        let (blocks, _) = InOutBuf::from(&mut inner.rem[..]).into_chunks();
        inner.dec.decrypt_blocks_inout(blocks);

        inner.dec_pos = inner.skip_start;
        inner.skip_start = 0;
        let max_avail = inner.remaining.unwrap_or(u64::MAX).min(16) as usize;
        inner.dec_len = inner.dec_pos + (16 - inner.dec_pos).min(max_avail);

        let n = inner.drain_dec_rem(buf);
        if inner.remaining == Some(0) {
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

    struct TrickleReader {
        data: Vec<u8>,
        pos: usize,
        step: usize,
        interrupt_every: usize,
        reads: usize,
    }

    impl Read for TrickleReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            if self.interrupt_every > 0 && self.reads.is_multiple_of(self.interrupt_every) {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "eintr"));
            }
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            let n = (self.data.len() - self.pos).min(self.step).min(buf.len());
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    fn make_reader<R: Read>(inner: R, aligned: &AlignedRange) -> DecryptReader<R> {
        if aligned.remaining == Some(0) {
            return DecryptReader(None);
        }
        DecryptReader::new(
            inner,
            Aes128EcbDec::new_from_slice(&TEST_KEY).unwrap(),
            aligned.skip_start,
            aligned.remaining,
        )
    }

    #[test]
    fn test_decrypt_reader_ranges() {
        let plaintext: Vec<u8> = (0..128_u8).collect();
        let ciphertext = encrypt_test_data(&plaintext);

        // Full aligned stream with trickled reads and EINTR
        let aligned = AlignedRange::new(None, None);
        assert_eq!((aligned.start, aligned.end), (None, None));
        let mut reader = make_reader(
            TrickleReader {
                data: ciphertext.clone(),
                pos: 0,
                step: 5,
                interrupt_every: 3,
                reads: 0,
            },
            &aligned,
        );
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, plaintext);

        // Open start with unaligned end
        let aligned = AlignedRange::new(None, Some(20));
        assert_eq!((aligned.start, aligned.end), (None, Some(31)));
        let slice = ciphertext[..=aligned.end.unwrap() as usize].to_vec();
        let mut reader = make_reader(Cursor::new(slice), &aligned);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, plaintext[..=20]);

        // Single byte inside first block
        let aligned = AlignedRange::new(Some(5), Some(5));
        assert_eq!((aligned.start, aligned.end), (Some(0), Some(15)));
        let slice =
            ciphertext[aligned.start.unwrap() as usize..=aligned.end.unwrap() as usize].to_vec();
        let mut reader = make_reader(Cursor::new(slice), &aligned);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, plaintext[5..=5]);

        // Unaligned start & end spanning multiple blocks, read via small 7-byte caller buffer
        let aligned = AlignedRange::new(Some(5), Some(73));
        assert_eq!((aligned.start, aligned.end), (Some(0), Some(79)));
        let slice =
            ciphertext[aligned.start.unwrap() as usize..=aligned.end.unwrap() as usize].to_vec();
        let mut reader = make_reader(
            TrickleReader {
                data: slice,
                pos: 0,
                step: 3,
                interrupt_every: 4,
                reads: 0,
            },
            &aligned,
        );
        let mut out = Vec::new();
        let mut small_buf = [0u8; 7];
        loop {
            let n = reader.read(&mut small_buf).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&small_buf[..n]);
        }
        assert_eq!(out, plaintext[5..=73]);

        // Unaligned start, open-ended EOF, large buffer (transitions from staging to fast path)
        let aligned = AlignedRange::new(Some(19), None);
        assert_eq!((aligned.start, aligned.end), (Some(16), None));
        let slice = ciphertext[aligned.start.unwrap() as usize..].to_vec();
        let mut reader = make_reader(
            TrickleReader {
                data: slice,
                pos: 0,
                step: 11,
                interrupt_every: 2,
                reads: 0,
            },
            &aligned,
        );
        let mut out = vec![0u8; 256];
        let mut total = 0;
        loop {
            let n = reader.read(&mut out[total..]).unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }
        assert_eq!(&out[..total], &plaintext[19..]);

        // Empty range (start > end)
        let aligned = AlignedRange::new(Some(20), Some(10));
        let mut reader = make_reader(Cursor::new(Vec::<u8>::new()), &aligned);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn test_decrypt_reader_truncated_block_errors() {
        let plaintext = vec![0xAA; 32];
        let ciphertext = encrypt_test_data(&plaintext);
        let aligned = AlignedRange::new(None, None);
        let mut reader = make_reader(Cursor::new(ciphertext[..25].to_vec()), &aligned);
        let mut out = [0u8; 64];
        assert_eq!(reader.read(&mut out).unwrap(), 16);
        let err = reader.read(&mut out[16..]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
