// Copyright 2026 John "topjohnwu" Wu
// Copyright 2010-2017 Benjamin Dobell, Glass Echidna
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

use crate::cli::DetectArgs;
use crate::progress;
use samloader_odin::{DeviceInfo, OdinConnection, UsbBackendOption, create_backend, detect_device};
use std::error::Error;
use std::fmt::Write;

fn push_json_escaped(out: &mut String, s: &str) {
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

/// Formats device information as a JSON string compatible with `odin4 -i`.
fn format_device_info_json(info: Option<&DeviceInfo>) -> String {
    let model = info.and_then(|i| i.model.as_deref()).unwrap_or("");
    let serial = info.and_then(|i| i.serial_number.as_deref()).unwrap_or("");
    let mut out = String::from("{\"modelName\":\"");
    push_json_escaped(&mut out, model);
    out.push_str("\",\"serialNumber\":\"");
    push_json_escaped(&mut out, serial);
    out.push_str("\"}");
    out
}

/// Reports whether a device in Download Mode is connected, and its details.
pub(crate) async fn run(
    args: DetectArgs,
    usb_backend: UsbBackendOption,
) -> Result<(), Box<dyn Error>> {
    let DetectArgs { wait, json } = args;
    if !json {
        progress::init(false);
    }
    if !detect_device(usb_backend, wait).await {
        return Err("Failed to detect compatible download-mode device.".into());
    }

    let info = if let Ok(transport) = create_backend(usb_backend, false).await {
        OdinConnection::open(transport)
            .query_device_info()
            .await
            .ok()
    } else {
        None
    };
    if json {
        println!("{}", format_device_info_json(info.as_ref()));
    } else {
        println!("Device detected (Download mode)");
        if let Some(info) = info {
            print!("{}", info);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_device_info_json() {
        let info = DeviceInfo::parse("@#MODEL=SM-F968B;UN=C1A2B3C4;").unwrap();
        assert_eq!(
            format_device_info_json(Some(&info)),
            "{\"modelName\":\"SM-F968B\",\"serialNumber\":\"C1A2B3C4\"}"
        );
        assert_eq!(
            format_device_info_json(None),
            "{\"modelName\":\"\",\"serialNumber\":\"\"}"
        );

        let escaped = DeviceInfo {
            model: Some("SM-\"X\"\\1\n".to_string()),
            serial_number: Some("A\t\x01".to_string()),
            ..Default::default()
        };
        assert_eq!(
            format_device_info_json(Some(&escaped)),
            "{\"modelName\":\"SM-\\\"X\\\"\\\\1\\n\",\"serialNumber\":\"A\\t\\u0001\"}"
        );
    }
}
