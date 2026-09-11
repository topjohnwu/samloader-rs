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

use crate::error::OdinError;
use std::collections::HashMap;
use std::fmt;

/// Diagnostic and identity information retrieved from a connected Samsung device in Download mode.
/// This corresponds to the pre-handshake `DVIF` ASCII query.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeviceInfo {
    /// The Samsung device model string (e.g., `"SM-F968B"` or `"SM-S931U1"`).
    pub model: Option<String>,
    /// Unique number / device serial number.
    pub serial_number: Option<String>,
    /// Storage capacity in gigabytes (e.g., `512` or `256`).
    pub storage_capacity_gb: Option<u32>,
    /// Storage chip vendor (e.g., `"SAMSUNG"`, `"MICRON"`).
    pub storage_vendor: Option<String>,
    /// Storage chip firmware revision.
    pub storage_firmware_version: Option<String>,
    /// Storage chip product / part number (e.g., `"KLUEG8UHDB"`).
    pub storage_product_name: Option<String>,
    /// Device provisioning status.
    pub provisioning_status: Option<String>,
    /// Active CSC / Sales Code (e.g., `"TUR"`, `"OXM"`, `"XAA"`).
    pub sales_code: Option<String>,
    /// Bootloader build version string (e.g., `"F968BXXS7BZH3"`).
    pub bootloader_version: Option<String>,
    /// Thermal Management Unit (TMU) temperature reading in degrees Celsius.
    pub temperature: Option<i32>,
    /// All raw key-value pairs returned by the device.
    pub raw_properties: HashMap<String, String>,
}

impl DeviceInfo {
    /// Parses a raw ASCII string response from the `DVIF` command.
    ///
    /// The response format returned by Samsung bootloader (`handle_dvif` in `abl_odin.efi`) is:
    /// `@#KEY1=VALUE1;KEY2=VALUE2;...;`
    pub fn parse(response: &str) -> Result<Self, OdinError> {
        let trimmed = response.trim();
        let payload = if let Some(idx) = trimmed.find("@#") {
            &trimmed[idx + 2..]
        } else {
            trimmed
        };

        let mut info = Self::default();
        let mut found_any = false;

        for token in payload.split(';') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }

            if let Some((key, val)) = token.split_once('=') {
                let key = key.trim();
                let val = val.trim();
                if key.is_empty() {
                    continue;
                }

                found_any = true;
                info.raw_properties.insert(key.to_string(), val.to_string());

                if val.is_empty() {
                    continue;
                }

                match key {
                    "MODEL" => info.model = Some(val.to_string()),
                    "UN" => info.serial_number = Some(val.to_string()),
                    "CAPA" => info.storage_capacity_gb = val.parse::<u32>().ok(),
                    "VENDOR" => info.storage_vendor = Some(val.to_string()),
                    "FWVER" => info.storage_firmware_version = Some(val.to_string()),
                    "PRODUCT" => info.storage_product_name = Some(val.to_string()),
                    "PROV" => info.provisioning_status = Some(val.to_string()),
                    "SALES" => info.sales_code = Some(val.to_string()),
                    "VER" => info.bootloader_version = Some(val.to_string()),
                    "TMU_TEMP" => info.temperature = val.parse::<i32>().ok(),
                    _ => {}
                }
            }
        }

        if !found_any {
            return Err(OdinError::DeviceInfoUnavailable);
        }

        Ok(info)
    }

    /// Formats the device information as a JSON string compatible with `odin4 -i`.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"modelName\":\"{}\",\"serialNumber\":\"{}\"}}",
            self.model.as_deref().unwrap_or(""),
            self.serial_number.as_deref().unwrap_or("")
        )
    }
}

impl fmt::Display for DeviceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(model) = &self.model {
            writeln!(f, "  Model:               {}", model)?;
        }
        if let Some(serial) = &self.serial_number {
            writeln!(f, "  Serial Number:       {}", serial)?;
        }
        if let Some(ver) = &self.bootloader_version {
            writeln!(f, "  Bootloader Version:  {}", ver)?;
        }
        if let Some(sales) = &self.sales_code {
            writeln!(f, "  Sales Code:          {}", sales)?;
        }
        if let Some(capa) = self.storage_capacity_gb {
            let mut storage_line = format!("{} GB", capa);
            if let Some(vendor) = &self.storage_vendor {
                storage_line.push_str(&format!(" {}", vendor));
            }
            if let Some(prod) = &self.storage_product_name {
                storage_line.push_str(&format!(" {}", prod));
            }
            if let Some(fw) = &self.storage_firmware_version {
                storage_line.push_str(&format!(" (FW: {})", fw));
            }
            writeln!(f, "  Storage:             {}", storage_line)?;
        } else if let Some(vendor) = &self.storage_vendor {
            writeln!(f, "  Storage Vendor:      {}", vendor)?;
        }
        if let Some(prov) = &self.provisioning_status {
            writeln!(f, "  Provisioning:        {}", prov)?;
        }
        if let Some(temp) = self.temperature {
            writeln!(f, "  Temperature:         {}°C", temp)?;
        }
        Ok(())
    }
}

/// Device information returned by the in-session binary protocol (Opcode `0x69`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionDeviceInfo {
    /// Tag 0: Device model string (e.g. `"SM-F968B"`).
    pub model: Option<String>,
    /// Tag 1: Unique Number / Storage CID (32-character hex string).
    pub unique_number: Option<String>,
    /// Tag 2: Sales code (e.g. `"TUR"`).
    pub sales_code: Option<String>,
    /// Tag 3: Carrier code (checked by `odin4` for blocked carriers).
    pub carrier: Option<String>,
    /// All raw entries indexed by tag ID.
    pub raw_entries: HashMap<u32, Vec<u8>>,
}

impl SessionDeviceInfo {
    /// Parses the in-session binary TLV buffer returned by Opcode `0x69`.
    ///
    /// The binary layout returned by `DownloadEngine::DeviceinfoAnalysis` in `odin4` and
    /// `abl_odin.efi` is:
    /// - `[0..4]`: Magic `0x12345678` (u32 LE)
    /// - `[4..8]`: Number of entries (u32 LE)
    /// - For each entry: Tag (u32), Offset (u32), Length (u32)
    ///   - Tag 0: Model string
    ///   - Tag 1: Unique Number / Storage CID
    ///   - Tag 2: Sales code
    ///   - Tag 3: Carrier code
    pub fn parse(data: &[u8]) -> Result<Self, OdinError> {
        if data.len() < 8 {
            return Err(OdinError::DeviceInfoUnavailable);
        }

        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if magic != 0x12345678 {
            return Err(OdinError::DeviceInfoParseFailed(format!(
                "Invalid session device info magic: 0x{:08X}",
                magic
            )));
        }

        let num_entries = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
        let mut info = Self::default();

        let mut offset = 8;
        for _ in 0..num_entries {
            if offset + 12 > data.len() {
                break;
            }
            let tag = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            let entry_offset =
                u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap()) as usize;
            let entry_len =
                u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap()) as usize;
            offset += 12;

            let abs_offset = 8 + entry_offset;
            if abs_offset < data.len() {
                let max_len = (data.len() - abs_offset).min(entry_len);
                let entry_data = data[abs_offset..abs_offset + max_len].to_vec();

                let end = entry_data
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(entry_data.len());
                let str_val = String::from_utf8_lossy(&entry_data[..end])
                    .trim()
                    .to_string();

                match tag {
                    0 => info.model = Some(str_val),
                    1 => info.unique_number = Some(str_val),
                    2 => info.sales_code = Some(str_val),
                    3 => info.carrier = Some(str_val),
                    _ => {}
                }

                info.raw_entries.insert(tag, entry_data);
            }
        }

        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dvif_complete() {
        let raw = "@#MODEL=SM-F968B;UN=C1A2B3C4;CAPA=512;VENDOR=SAMSUNG;FWVER=0800;PRODUCT=KLUEG8UHDB;PROV=2;SALES=TUR;VER=F968BXXS7BZH3;TMU_TEMP=32;";
        let info = DeviceInfo::parse(raw).expect("Failed to parse complete DVIF");

        assert_eq!(info.model.as_deref(), Some("SM-F968B"));
        assert_eq!(info.serial_number.as_deref(), Some("C1A2B3C4"));
        assert_eq!(info.storage_capacity_gb, Some(512));
        assert_eq!(info.storage_vendor.as_deref(), Some("SAMSUNG"));
        assert_eq!(info.storage_firmware_version.as_deref(), Some("0800"));
        assert_eq!(info.storage_product_name.as_deref(), Some("KLUEG8UHDB"));
        assert_eq!(info.provisioning_status.as_deref(), Some("2"));
        assert_eq!(info.sales_code.as_deref(), Some("TUR"));
        assert_eq!(info.bootloader_version.as_deref(), Some("F968BXXS7BZH3"));
        assert_eq!(info.temperature, Some(32));
        assert_eq!(
            info.to_json(),
            "{\"modelName\":\"SM-F968B\",\"serialNumber\":\"C1A2B3C4\"}"
        );
    }

    #[test]
    fn test_parse_dvif_partial() {
        let raw = "@#MODEL=SM-S931U1;UN=RF8M1234;CAPA=256;";
        let info = DeviceInfo::parse(raw).expect("Failed to parse partial DVIF");

        assert_eq!(info.model.as_deref(), Some("SM-S931U1"));
        assert_eq!(info.serial_number.as_deref(), Some("RF8M1234"));
        assert_eq!(info.storage_capacity_gb, Some(256));
        assert_eq!(info.storage_vendor, None);
        assert_eq!(info.temperature, None);
    }

    #[test]
    fn test_parse_dvif_empty() {
        assert!(DeviceInfo::parse("").is_err());
        assert!(DeviceInfo::parse("@#").is_err());
        assert!(DeviceInfo::parse(";;;").is_err());
    }

    #[test]
    fn test_parse_session_binary() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x12345678u32.to_le_bytes()); // magic
        data.extend_from_slice(&3u32.to_le_bytes()); // 3 entries

        // Entry 0: Tag 0 (Model), offset 36 (abs 44), len 32
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&36u32.to_le_bytes());
        data.extend_from_slice(&32u32.to_le_bytes());

        // Entry 1: Tag 1 (UN/CID), offset 68 (abs 76), len 36
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&68u32.to_le_bytes());
        data.extend_from_slice(&36u32.to_le_bytes());

        // Entry 2: Tag 2 (Sales Code), offset 104 (abs 112), len 4
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&104u32.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());

        // Offset 44: "SM-F968B\0" (padded to 32)
        let mut model_bytes = b"SM-F968B\0".to_vec();
        model_bytes.resize(32, 0);
        data.extend_from_slice(&model_bytes);

        // Offset 76: "1501004b333230340000000000000000\0" (32 hex + 1 null + 3 pad = 36)
        let mut cid_bytes = b"1501004b333230340000000000000000\0".to_vec();
        cid_bytes.resize(36, 0);
        data.extend_from_slice(&cid_bytes);

        // Offset 112: "TUR\0" (4 bytes)
        data.extend_from_slice(b"TUR\0");

        let info = SessionDeviceInfo::parse(&data).expect("Failed to parse binary");
        assert_eq!(info.model.as_deref(), Some("SM-F968B"));
        assert_eq!(
            info.unique_number.as_deref(),
            Some("1501004b333230340000000000000000")
        );
        assert_eq!(info.sales_code.as_deref(), Some("TUR"));
    }
}
