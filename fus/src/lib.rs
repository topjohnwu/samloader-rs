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
mod xml;

pub use error::{Error, Result};
pub use fusclient::{DownloadSession, FusClient};
pub use xml::{BinaryInform, VersionInfo};

// Re-export public dependencies to avoid type mismatch and SemVer issues in public APIs.
pub use futures;
pub use reqwest;

use std::time::Duration;

/// Queries and fetches the standard firmware `version.xml` document for the specified
/// device model and region.
async fn fetch_version_xml(
    client: &reqwest::Client,
    model: &str,
    region: &str,
) -> Result<VersionInfo> {
    let version_url = format!(
        "https://fota-cloud-dn.ospserver.net:443/firmware/{}/{}/version.xml",
        region, model
    );
    let version_xml = client
        .get(&version_url)
        .header(reqwest::header::USER_AGENT, "Kies2.0_FUS")
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    xml::parse_version_xml(&version_xml)
}

/// Fetches the historical list of released firmware versions for the target model and region
/// through the `SmartHistory.do` endpoint.
async fn fetch_smart_history(
    client: &reqwest::Client,
    model: &str,
    region: &str,
) -> Result<VersionInfo> {
    let (nonce, signature) = auth::compute_history_headers(model);
    let auth_val = format!(
        "FUS nonce=\"{nonce}\", signature=\"{signature}\", \
         nc=\"00000001\", type=\"auth\", realm=\"interface\"",
    );

    let xml = client
        .post("https://neofussvr.sslcs.cdngc.net/SmartHistory.do")
        .header(reqwest::header::AUTHORIZATION, auth_val)
        .header(reqwest::header::USER_AGENT, "SMART 2.0")
        .body(xml::history_req_xml(model, region))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    xml::parse_history_xml(&xml)
}

/// Fetches the historical list of released firmware versions for the target model and region.
pub async fn fetch_history(model: &str, region: &str) -> Result<VersionInfo> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(15))
        .build()?;
    match fetch_smart_history(&client, model, region).await {
        Ok(info) => Ok(info),
        Err(_) => fetch_version_xml(&client, model, region).await,
    }
}

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
