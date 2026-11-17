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

//! Crate for interacting with Samsung Firmware Update Server (FUS) to query
//! and download device firmware binaries.

#![deny(missing_docs)]

mod auth;
mod error;
mod fusclient;
mod http;
mod xml;

pub use error::{Error, HttpError, Result};
pub use fusclient::{DownloadSession, FusClient};
pub use xml::{BinaryInform, VersionInfo};

// Re-export public dependencies to avoid type mismatch and SemVer issues in public APIs.
pub use futures;

use http::{HttpClient, HttpMethod, HttpRequest, HttpResponse, PlatformClient};

/// Queries and fetches the standard firmware `version.xml` document for the specified
/// device model and region.
async fn fetch_version_xml(
    client: &impl HttpClient,
    model: &str,
    region: &str,
) -> Result<VersionInfo> {
    let version_url = format!(
        "https://fota-cloud-dn.ospserver.net:443/firmware/{}/{}/version.xml",
        region, model
    );
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
    let (nonce, signature) = auth::compute_history_headers(model);
    let auth_val = format!(
        "FUS nonce=\"{nonce}\", signature=\"{signature}\", \
         nc=\"00000001\", type=\"auth\", realm=\"interface\"",
    );
    let req_xml = xml::history_req_xml(model, region);
    let headers = [
        ("Authorization", auth_val.as_str()),
        ("User-Agent", "SMART 2.0"),
    ];

    let xml = client
        .send(HttpRequest {
            method: HttpMethod::Post,
            url: "https://neofussvr.sslcs.cdngc.net/SmartHistory.do",
            headers: &headers,
            body: Some(req_xml.as_bytes()),
        })
        .await?
        .ensure_success()?
        .into_text()
        .await?;

    xml::parse_history_xml(&xml)
}

/// Fetches the historical list of released firmware versions for the target model and region.
pub async fn fetch_history(model: &str, region: &str) -> Result<VersionInfo> {
    let client = PlatformClient::new()?;
    match fetch_smart_history(&client, model, region).await {
        Ok(info) => Ok(info),
        Err(_) => fetch_version_xml(&client, model, region).await,
    }
}

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
