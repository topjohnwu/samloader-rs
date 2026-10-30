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

//! Operations that open a Samsung device by themselves: rebooting into
//! Download Mode and querying device info.

use crate::device_info::DeviceInfo;
use crate::error::OdinError;
use crate::session::OdinConnection;
#[cfg(target_arch = "wasm32")]
use crate::usb::VID_SAMSUNG;
use crate::usb::{DeviceMode, UsbBackendOption, create_backend};

/// Helper function to prompt user pairing for a Samsung device in normal mode
/// on WASM, which is required before calling [`reboot_download`].
///
/// Once the device reboots, it re-enumerates with a Download Mode product ID
/// and must be paired again with [`request_device`](crate::request_device).
#[cfg(target_arch = "wasm32")]
pub async fn request_reboot_device(usb_backend: UsbBackendOption) -> Result<(), OdinError> {
    match usb_backend {
        #[cfg(feature = "nusb")]
        UsbBackendOption::Nusb => {
            // WebUSB matches the class code against both the device class and
            // its interface classes, so this matches the modem interface.
            let selectors = [::nusb::DeviceSelector::all()
                .with_vid(VID_SAMSUNG)
                .with_class(crate::usb::USB_CLASS_CDC_DATA)];

            ::nusb::request_device(&selectors)
                .await
                .map_err(|e| OdinError::DeviceAccess(Box::new(e)))?
                .ok_or(OdinError::DeviceNotFound)?;
            Ok(())
        }
        #[cfg(mock_backend)]
        UsbBackendOption::Mock => Ok(()),
    }
}

/// Triggers a reboot of the connected Samsung device into Download Mode via the
/// specified backend protocol.
///
/// The AT command is sent to the first Samsung device not already in Download
/// Mode that exposes a usable interface; unrelated Samsung USB devices are
/// skipped. If no such device can be opened but one is already in Download
/// Mode, this is a no-op.
///
/// On WASM, the device must first be paired with `request_reboot_device`.
pub async fn reboot_download(usb_backend: UsbBackendOption) -> Result<(), OdinError> {
    let mut backend = match DeviceMode::Normal.open_with(usb_backend).await {
        Ok(backend) => backend,
        Err(e) => {
            // The error may come from an unrelated device of the same vendor,
            // so check for a device already in Download Mode before reporting it.
            if DeviceMode::Download.find_with(usb_backend).await.is_ok() {
                if !matches!(e, OdinError::NormalModeDeviceNotFound) {
                    crate::progress::println_verbose(&format!("Ignoring error: {e}"));
                }
                crate::progress::println("Device is already in Download Mode.");
                return Ok(());
            }
            return Err(e);
        }
    };

    let cmd: &[u8] = b"AT+SUDDLMOD=0,0\r";

    if !backend.send_data(cmd, 1000).await {
        return Err(OdinError::Transport(
            "Failed to send the reboot command".to_string(),
        ));
    }

    Ok(())
}

/// Connects to a device in download mode and queries diagnostic info via `DVIF`.
pub async fn query_device_info(
    usb_backend: UsbBackendOption,
    wait: bool,
) -> Result<DeviceInfo, OdinError> {
    let usb = create_backend(usb_backend, wait).await?;
    let mut conn = OdinConnection::new(usb);
    conn.query_device_info().await
}
