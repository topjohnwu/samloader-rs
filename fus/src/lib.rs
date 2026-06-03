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

mod auth;
mod fusclient;
mod xml;

pub use fusclient::{Aes128EcbDec, FusClient};
pub use xml::{BinaryInform, VersionInfo};

// Re-export public dependencies to avoid type mismatch and SemVer issues in public APIs.
pub use aes;
pub use ecb;
pub use reqwest;

pub fn fetch_version_info(model: &str, region: &str) -> reqwest::Result<VersionInfo> {
    let version_url = format!(
        "https://fota-cloud-dn.ospserver.net:443/firmware/{}/{}/version.xml",
        region, model
    );
    let client = reqwest::blocking::Client::new();
    let version_xml = client
        .get(&version_url)
        .header(reqwest::header::USER_AGENT, "Kies2.0_FUS")
        .send()?
        .text()?;

    Ok(xml::parse_version_xml(&version_xml).expect("Failed to parse version.xml"))
}
