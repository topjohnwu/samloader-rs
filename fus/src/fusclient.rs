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

//! FUS API client, version history queries, and authenticated [`DownloadSession`].

use crate::compat::MaybeSend;
use crate::data::DataSource;
use crate::decrypt::{AlignedRange, DecryptReader, decryptor, unpadded_block_len};
use crate::error::{Error, HttpError, Result};
use crate::http::{HttpClient, HttpMethod, HttpRequest, HttpResponse, PlatformClient};
use crate::{auth, xml};
use aes::cipher::BlockModeDecrypt;
use aes::cipher::inout::InOutBuf;
use futures::io::{AsyncRead, AsyncReadExt};
use futures::lock::Mutex as AsyncMutex;
use std::io;
use std::ops::RangeBounds;
use std::sync::Mutex;
use xml::{BinaryInform, VersionInfo};

const FUS_HOST: &str = "https://neofussvr.sslcs.cdngc.net";
const FUS_USER_AGENT: &str = "SMART 2.0";

/// Queries and fetches the standard firmware `version.xml` document for the specified
/// device model and region.
async fn fetch_version_xml(
    client: &impl HttpClient,
    model: &str,
    region: &str,
) -> Result<VersionInfo> {
    let version_url =
        format!("https://fota-cloud-dn.ospserver.net:443/firmware/{region}/{model}/version.xml");
    let headers = [("User-Agent", "Kies2.0_FUS")];
    let version_xml = client
        .send(HttpRequest {
            method: HttpMethod::Get,
            url: &version_url,
            headers: &headers,
            body: None,
        })
        .await?
        .ensure_success()?
        .into_text()
        .await?;

    xml::parse_version_xml(&version_xml)
}

/// Fetches the historical list of released firmware versions for the target model and region
/// through the `SmartHistory.do` endpoint.
async fn fetch_smart_history(
    client: &impl HttpClient,
    model: &str,
    region: &str,
) -> Result<VersionInfo> {
    let auth_val = auth::format_history_auth_header(model);
    let req_xml = xml::history_req_xml(model, region);
    let headers = [
        ("Authorization", auth_val.as_str()),
        ("User-Agent", FUS_USER_AGENT),
    ];

    let xml = client
        .send(HttpRequest {
            method: HttpMethod::Post,
            url: &format!("{FUS_HOST}/SmartHistory.do"),
            headers: &headers,
            body: Some(req_xml.as_bytes()),
        })
        .await?
        .ensure_success()?
        .into_text()
        .await?;

    xml::parse_history_xml(&xml)
}

async fn fetch_history_with(
    client: &impl HttpClient,
    model: &str,
    region: &str,
) -> Result<VersionInfo> {
    match fetch_smart_history(client, model, region).await {
        Ok(info) => Ok(info),
        Err(_) => fetch_version_xml(client, model, region).await,
    }
}

/// Fetches the historical list of released firmware versions for the target model and region.
pub async fn fetch_history(model: &str, region: &str) -> Result<VersionInfo> {
    let client = PlatformClient::new()?;
    fetch_history_with(&client, model, region).await
}

/// Authentication token state. The download GET signs every request with
/// `nonce`/`auth`; these expire, so they live behind a lock and are shared
/// by reference across all download tasks (which only read them) and the
/// occasional reauthentication (which rewrites them). See [`FusClient`] and
/// [`DownloadSession`].
#[derive(Default)]
struct AuthState {
    auth: String,
    nonce: String,
}

impl AuthState {
    fn auth_header(&self) -> String {
        auth::format_auth_header(&self.nonce, &self.auth)
    }
}

struct FusClientCore<C: HttpClient> {
    client: C,
    auth_state: Mutex<AuthState>,
}

impl<C: HttpClient> FusClientCore<C> {
    async fn new(client: C) -> Result<Self> {
        let fus = Self {
            client,
            auth_state: Mutex::new(AuthState::default()),
        };
        fus.generate_nonce().await?;
        Ok(fus)
    }

    async fn fetch_history(&self, model: &str, region: &str) -> Result<VersionInfo> {
        fetch_history_with(&self.client, model, region).await
    }

    async fn fetch_binary_info(
        &self,
        model: &str,
        region: &str,
        version: &str,
    ) -> Result<BinaryInform> {
        let fw = xml::normalize_version(version);
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
    ) -> std::result::Result<C::Response, HttpError> {
        let url = format!("{FUS_HOST}/{path}");
        let auth_val = self.auth_state.lock().unwrap().auth_header();
        let headers = [
            ("Authorization", auth_val.as_str()),
            ("User-Agent", FUS_USER_AGENT),
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
            if nonce != state.nonce {
                state.nonce = nonce.to_string();
                state.auth = auth::decrypt_nonce(&state.nonce);
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

    async fn init_download(self, info: BinaryInform) -> Result<DownloadSessionCore<C>> {
        self.send_init_download(&info).await?;
        let mut session = DownloadSessionCore {
            client: self,
            info,
            decrypted_size: 0,
            reauth_gen: AsyncMutex::new(0),
        };
        session.decrypted_size = session.probe_decrypted_size().await?;
        Ok(session)
    }
}

/// Client coordinating API communication and security authentication
/// with the Samsung Firmware Update Server (FUS).
pub struct FusClient(FusClientCore<PlatformClient>);

impl FusClient {
    /// Creates a new `FusClient` and initiates the standard FUS handshake to generate a session nonce.
    pub async fn new() -> Result<Self> {
        Ok(Self(FusClientCore::new(PlatformClient::new()?).await?))
    }

    /// Fetches the historical list of released firmware versions for the target model and region,
    /// reusing this client's underlying HTTP connection pool.
    pub async fn fetch_history(&self, model: &str, region: &str) -> Result<VersionInfo> {
        self.0.fetch_history(model, region).await
    }

    /// Queries the server for firmware binary metadata matching the requested model, region, and version.
    pub async fn fetch_binary_info(
        &self,
        model: &str,
        region: &str,
        version: &str,
    ) -> Result<BinaryInform> {
        self.0.fetch_binary_info(model, region, version).await
    }

    /// Requests a download authorization ticket from FUS for `info`, probes the
    /// final AES block to determine the exact unpadded payload length, and consumes
    /// this client into an active [`DownloadSession`].
    pub async fn init_download(self, info: BinaryInform) -> Result<DownloadSession> {
        Ok(DownloadSession(self.0.init_download(info).await?))
    }
}

struct DownloadSessionCore<C: HttpClient> {
    client: FusClientCore<C>,
    info: BinaryInform,
    decrypted_size: u64,
    /// Reauthentication generation counter. It also serves as the lock that
    /// serializes reauth: a token expiry observed by many download tasks at
    /// once triggers a single refresh, and the rest reuse its result.
    reauth_gen: AsyncMutex<u64>,
}

impl<C: HttpClient> DownloadSessionCore<C> {
    fn info(&self) -> &BinaryInform {
        &self.info
    }

    async fn probe_decrypted_size(&self) -> Result<u64> {
        let enc_size = self.info.size;
        if enc_size == 0 {
            return Ok(0);
        }
        if !enc_size.is_multiple_of(16) {
            return Err(Error::InvalidResponse(format!(
                "encrypted binary size ({enc_size}) is not a multiple of 16 bytes"
            )));
        }

        let resp = self
            .fetch_range_once(Some(enc_size - 16), Some(enc_size - 1))
            .await?;
        let mut block = [0u8; 16];
        resp.into_reader().read_exact(&mut block).await?;

        let mut dec = decryptor(&self.info.key);
        let (blocks, _) = InOutBuf::from(&mut block[..]).into_chunks();
        dec.decrypt_blocks_inout(blocks);

        let pad = 16 - unpadded_block_len(&block);
        Ok(enc_size - pad as u64)
    }

    async fn fetch_range_once(
        &self,
        start: Option<u64>,
        end: Option<u64>,
    ) -> std::result::Result<C::Response, HttpError> {
        let auth_val = self.client.auth_state.lock().unwrap().auth_header();
        let range_val = match (start, end) {
            (Some(s), Some(e)) => Some(format!("bytes={s}-{e}")),
            (None, Some(e)) => Some(format!("bytes=0-{e}")),
            (Some(s), None) => Some(format!("bytes={s}-")),
            (None, None) => None,
        };

        let mut headers = [
            ("Authorization", auth_val.as_str()),
            ("User-Agent", FUS_USER_AGENT),
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
        let resp = self
            .client
            .client
            .send(HttpRequest {
                method: HttpMethod::Get,
                url: &url,
                headers,
                body: None,
            })
            .await?;

        // A non-zero byte range MUST receive 206 Partial Content; accepting 200 OK
        // here would silently decrypt from byte 0 at the wrong offset.
        if start.is_some_and(|s| s > 0) && resp.status() != 206 {
            return Err(HttpError::Status(resp.status()));
        }

        resp.ensure_success()
    }

    /// Re-establish the session after the auth token expired (HTTP 401),
    /// rewriting the shared `nonce`/`auth`.
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
}

impl<C: HttpClient> DataSource for DownloadSessionCore<C> {
    fn size(&self) -> u64 {
        self.decrypted_size
    }

    async fn fetch_range(
        &self,
        range: impl RangeBounds<u64> + MaybeSend,
    ) -> io::Result<impl AsyncRead + MaybeSend + Unpin> {
        let aligned = AlignedRange::new(range, self.decrypted_size, self.info.size);
        if aligned.dec_remaining == 0 {
            return Ok(DecryptReader::empty());
        }

        let gen_used = *self.reauth_gen.lock().await;

        let resp = match self
            .fetch_range_once(aligned.http_start, aligned.http_end)
            .await
        {
            Err(HttpError::Status(401)) => {
                self.reauthenticate(gen_used).await;
                self.fetch_range_once(aligned.http_start, aligned.http_end)
                    .await
                    .map_err(io::Error::other)?
            }
            other => other.map_err(io::Error::other)?,
        };

        Ok(DecryptReader::new(
            resp.into_reader(),
            decryptor(&self.info.key),
            aligned,
        ))
    }
}

/// Active firmware download session holding an authenticated [`FusClient`]
/// and the resolved [`BinaryInform`] metadata.
pub struct DownloadSession(DownloadSessionCore<PlatformClient>);

impl DownloadSession {
    /// Returns the firmware binary metadata associated with this download session.
    pub fn info(&self) -> &BinaryInform {
        self.0.info()
    }
}

impl DataSource for DownloadSession {
    fn size(&self) -> u64 {
        self.0.size()
    }

    async fn fetch_range(
        &self,
        range: impl RangeBounds<u64> + MaybeSend,
    ) -> io::Result<impl AsyncRead + MaybeSend + Unpin> {
        self.0.fetch_range(range).await
    }
}

#[cfg(all(not(target_arch = "wasm32"), test))]
mod tests {
    use super::*;
    use crate::decrypt::tests::{TEST_KEY, encrypt_pkcs7};
    use crate::http::{MockClient, MockResponse};
    use crate::test_util::parse_http_range;
    use futures::executor::block_on;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    async fn session_from_mock(
        client: MockClient,
        info: BinaryInform,
    ) -> Result<DownloadSessionCore<MockClient>> {
        let mut session = DownloadSessionCore {
            client: FusClientCore {
                client,
                auth_state: Mutex::new(AuthState::default()),
            },
            info,
            decrypted_size: 0,
            reauth_gen: AsyncMutex::new(0),
        };
        session.decrypted_size = session.probe_decrypted_size().await?;
        Ok(session)
    }

    fn range_mock(
        ciphertext: Arc<Vec<u8>>,
        requests: Arc<Mutex<Vec<Option<String>>>>,
    ) -> MockClient {
        MockClient::from_handler(move |req| {
            let data = Arc::clone(&ciphertext);
            let range_hdr = req.header("Range").map(str::to_owned);
            requests.lock().unwrap().push(range_hdr.clone());
            let (s, e) = parse_http_range(range_hdr.as_deref(), data.len());
            let is_partial = range_hdr.is_some();
            Box::pin(async move {
                let slice = data[s..e].to_vec();
                Ok(if is_partial {
                    MockResponse::partial_bytes(slice)
                } else {
                    MockResponse::ok_bytes(slice)
                })
            })
        })
    }

    #[test]
    fn test_fus_client_handshake_inform_init_and_history_fallback() {
        let plaintext: Vec<u8> = (0..43_u8).map(|i| i.wrapping_mul(3)).collect();
        let ciphertext = Arc::new(encrypt_pkcs7(&plaintext));
        let enc_len = ciphertext.len();

        let inform_xml = format!(
            r#"<FUSMsg><FUSBody>
                <Results><Status>200</Status></Results>
                <Put>
                    <BINARY_NAME><Data>SM-S931U1_1_20240101000000_abcdefghij_fac.zip.enc4</Data></BINARY_NAME>
                    <BINARY_BYTE_SIZE><Data>{enc_len}</Data></BINARY_BYTE_SIZE>
                    <BINARY_LOCAL_CODE><Data>XAA</Data></BINARY_LOCAL_CODE>
                    <BINARY_SW_VERSION><Data>S931U1UEU1AWF1/S931U1OYM1AWF1/S931U1UEU1AWF1/S931U1UEU1AWF1</Data></BINARY_SW_VERSION>
                    <DEVICE_MODEL_TYPE><Data>9</Data></DEVICE_MODEL_TYPE>
                    <MODEL_PATH><Data>/neofus/9/</Data></MODEL_PATH>
                    <LOGIC_VALUE_FACTORY><Data>1234567890abcdef</Data></LOGIC_VALUE_FACTORY>
                </Put>
            </FUSBody></FUSMsg>"#
        );

        let seen_auth = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen_auth_clone = Arc::clone(&seen_auth);
        let data = Arc::clone(&ciphertext);

        let client = MockClient::from_handler(move |req| {
            let auth_hdr = req.header("Authorization").unwrap_or_default().to_owned();
            seen_auth_clone.lock().unwrap().push(auth_hdr);

            if req.url.contains("NF_SmartDownloadGenerateNonce.do") {
                return Box::pin(async {
                    Ok(MockResponse::ok_bytes(Vec::new()).with_header("nonce", "INITNONCE1234567"))
                });
            }
            if req.url.contains("NF_SmartDownloadBinaryInform.do") {
                let body = inform_xml.as_bytes().to_vec();
                return Box::pin(async move {
                    Ok(MockResponse::ok_bytes(body).with_header("nonce", "ROTATEDNONCE1234"))
                });
            }
            if req.url.contains("NF_SmartDownloadBinaryInitForMass.do") {
                let ok =
                    b"<FUSMsg><FUSBody><Results><Status>200</Status></Results></FUSBody></FUSMsg>"
                        .to_vec();
                return Box::pin(async move { Ok(MockResponse::ok_bytes(ok)) });
            }
            if req.url.contains("SmartHistory.do") {
                return Box::pin(async { Err(HttpError::Status(503)) });
            }
            if req.url.contains("version.xml") {
                let xml = b"<versioninfo><firmware><version><latest>A/B/C</latest></version></firmware></versioninfo>".to_vec();
                return Box::pin(async move { Ok(MockResponse::ok_bytes(xml)) });
            }
            let (s, e) = parse_http_range(req.header("Range"), data.len());
            let slice = data[s..e].to_vec();
            Box::pin(async move { Ok(MockResponse::partial_bytes(slice)) })
        });

        block_on(async {
            let fus = FusClientCore::new(client).await.unwrap();

            // SmartHistory.do fails with 503 -> falls back cleanly to version.xml
            let hist = fus.fetch_history("SM-S931U1", "XAA").await.unwrap();
            assert_eq!(hist.latest, "A/B/C/A");

            let info = fus
                .fetch_binary_info(
                    "SM-S931U1",
                    "XAA",
                    "S931U1UEU1AWF1/S931U1OYM1AWF1/S931U1UEU1AWF1",
                )
                .await
                .unwrap();
            assert_eq!(info.encrypted_size(), enc_len as u64);

            // Replace key with TEST_KEY so the probed ciphertext decrypts to valid PKCS#7 padding
            let mut info = info;
            info.key = TEST_KEY;
            let session = fus.init_download(info).await.unwrap();
            assert_eq!(session.size(), 43);

            // Verify nonce rotation occurred between GenerateNonce -> BinaryInform -> BinaryInitForMass
            let auths = seen_auth.lock().unwrap();
            assert!(auths.iter().any(|h| h.contains("INITNONCE1234567")));
            assert!(auths.iter().any(|h| h.contains("ROTATEDNONCE1234")));
        });
    }

    #[test]
    fn test_download_session_data_source() {
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
        let client = range_mock(Arc::clone(&ciphertext), Arc::clone(&requests));

        block_on(async {
            // Probing the last 16 bytes resolves exact unpadded length (75 of 80)
            let session = session_from_mock(client, info).await.unwrap();
            assert_eq!(session.size(), 75);
            assert_eq!(
                requests.lock().unwrap().as_slice(),
                &[Some("bytes=64-79".to_string())]
            );
            requests.lock().unwrap().clear();

            // Full 16-byte PKCS#7 padding block (48 plain + 16 pad = 64 encrypted)
            let aligned_plain: Vec<u8> = (0..48_u8).map(|i| i + 20).collect();
            let aligned_cipher = Arc::new(encrypt_pkcs7(&aligned_plain));
            let aligned_reqs = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
            let aligned_info = BinaryInform {
                size: aligned_cipher.len() as u64,
                ..session.info().clone()
            };
            let aligned_session = session_from_mock(
                range_mock(aligned_cipher, Arc::clone(&aligned_reqs)),
                aligned_info,
            )
            .await
            .unwrap();
            assert_eq!(aligned_session.size(), 48);
            aligned_reqs.lock().unwrap().clear();
            let mut aligned_out = Vec::new();
            aligned_session
                .fetch()
                .await
                .unwrap()
                .read_to_end(&mut aligned_out)
                .await
                .unwrap();
            assert_eq!(aligned_out, aligned_plain);
            assert_eq!(
                aligned_reqs.lock().unwrap().as_slice(),
                &[Some("bytes=0-47".to_string())]
            );

            // Empty session makes zero HTTP requests even during probe
            let empty_info = BinaryInform {
                size: 0,
                ..session.info().clone()
            };
            let empty_session = session_from_mock(
                MockClient::from_handler(|_| {
                    Box::pin(async { unreachable!("must not issue HTTP request") })
                }),
                empty_info,
            )
            .await
            .unwrap();
            assert_eq!(empty_session.size(), 0);

            // Empty/out-of-bounds ranges (including inside PKCS#7 padding) make zero HTTP requests
            let mut empty_out = Vec::new();
            session
                .fetch_range(0..0)
                .await
                .unwrap()
                .read_to_end(&mut empty_out)
                .await
                .unwrap();
            session
                .fetch_range(75..)
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

            // Straddling tail via read_at returns exact remaining plaintext
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

            // Server ignoring Range (returning 200 OK for non-zero offset) is rejected
            let bad_200_session = session_from_mock(
                MockClient::from_handler(|_| {
                    Box::pin(async { Ok(MockResponse::ok_bytes(vec![0; 80])) })
                }),
                session.info().clone(),
            )
            .await;
            assert!(matches!(
                bad_200_session,
                Err(Error::Http(HttpError::Status(200)))
            ));

            // Error mapping via io::Error::other (probe succeeds with 206, subsequent fetch returns 503)
            let probed = Arc::new(AtomicBool::new(false));
            let tail_block = ciphertext[64..80].to_vec();
            let err_session = session_from_mock(
                MockClient::from_handler(move |_| {
                    if !probed.swap(true, Ordering::Relaxed) {
                        let b = tail_block.clone();
                        Box::pin(async move { Ok(MockResponse::partial_bytes(b)) })
                    } else {
                        Box::pin(async { Err(HttpError::Status(503)) })
                    }
                }),
                session.info().clone(),
            )
            .await
            .unwrap();
            let err = err_session.fetch().await.err().unwrap();
            assert_eq!(err.kind(), io::ErrorKind::Other);
        });
    }

    #[test]
    fn test_download_session_401_reauth_and_invalid_size() {
        let plaintext: Vec<u8> = (0..43_u8).map(|i| i.wrapping_mul(7)).collect();
        let ciphertext = Arc::new(encrypt_pkcs7(&plaintext));
        let base_info = BinaryInform {
            version: "T/T/T/T".into(),
            filename: "SM-S931U1_1_20240101000000_abcdefghij_fac.zip.enc4".into(),
            path: "/t/".into(),
            size: ciphertext.len() as u64,
            key: TEST_KEY,
            model_type: "SM-TEST".into(),
            region: "XAA".into(),
        };

        block_on(async {
            // Non-multiple-of-16 encrypted size is rejected during probe
            let bad_info = BinaryInform {
                size: 17,
                ..base_info.clone()
            };
            let err = session_from_mock(
                MockClient::from_handler(|_| {
                    Box::pin(async { unreachable!("must reject invalid size before HTTP") })
                }),
                bad_info,
            )
            .await
            .err()
            .unwrap();
            assert!(matches!(err, Error::InvalidResponse(_)));

            // Mid-download HTTP 401 rotates nonce via GenerateNonce + BinaryInitForMass
            // once across concurrent tasks and retries with the refreshed Authorization header.
            let fresh_nonce = "NEWNONCE12345678";
            let expected_auth_hdr =
                auth::format_auth_header(fresh_nonce, &auth::decrypt_nonce(fresh_nonce));
            let nonce_calls = Arc::new(AtomicUsize::new(0));
            let init_calls = Arc::new(AtomicUsize::new(0));
            let probe_done = Arc::new(AtomicUsize::new(0));
            let data = Arc::clone(&ciphertext);
            let exp_auth = expected_auth_hdr.clone();
            let nc = Arc::clone(&nonce_calls);
            let ic = Arc::clone(&init_calls);
            let pd = Arc::clone(&probe_done);

            let client = MockClient::from_handler(move |req| {
                if req.url.contains("NF_SmartDownloadGenerateNonce.do") {
                    nc.fetch_add(1, Ordering::SeqCst);
                    return Box::pin(async move {
                        Ok(MockResponse::ok_bytes(Vec::new()).with_header("nonce", fresh_nonce))
                    });
                }
                if req.url.contains("NF_SmartDownloadBinaryInitForMass.do") {
                    ic.fetch_add(1, Ordering::SeqCst);
                    let ok_xml = b"<FUSMsg><FUSBody><Results><Status>200</Status></Results></FUSBody></FUSMsg>".to_vec();
                    return Box::pin(async move { Ok(MockResponse::ok_bytes(ok_xml)) });
                }

                let auth_hdr = req.header("Authorization").unwrap_or_default();
                let is_probe = pd.fetch_add(1, Ordering::SeqCst) == 0;
                if !is_probe && auth_hdr != exp_auth {
                    return Box::pin(async { Err(HttpError::Status(401)) });
                }

                let range_hdr = req.header("Range");
                let (s, e) = parse_http_range(range_hdr, data.len());
                let is_partial = range_hdr.is_some();
                let bytes = data[s..e].to_vec();
                Box::pin(async move {
                    Ok(if is_partial {
                        MockResponse::partial_bytes(bytes)
                    } else {
                        MockResponse::ok_bytes(bytes)
                    })
                })
            });

            let session = session_from_mock(client, base_info).await.unwrap();
            assert_eq!(session.size(), 43);

            let (r1, r2) = futures::join!(session.fetch_range(0..20), session.fetch_range(20..43));
            let mut out1 = Vec::new();
            let mut out2 = Vec::new();
            r1.unwrap().read_to_end(&mut out1).await.unwrap();
            r2.unwrap().read_to_end(&mut out2).await.unwrap();
            assert_eq!(out1, &plaintext[..20]);
            assert_eq!(out2, &plaintext[20..]);
            assert_eq!(nonce_calls.load(Ordering::SeqCst), 1);
            assert_eq!(init_calls.load(Ordering::SeqCst), 1);
        });
    }
}
