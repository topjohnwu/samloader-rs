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

//! Operations that open a Samsung device in Download Mode by themselves.

use crate::device_info::DeviceInfo;
use crate::error::OdinError;
use crate::session::OdinConnection;
use crate::usb::{UsbBackendOption, create_backend};

/// Connects to a device in download mode and queries diagnostic info via `DVIF`.
pub async fn query_device_info(
    usb_backend: UsbBackendOption,
    wait: bool,
) -> Result<DeviceInfo, OdinError> {
    let usb = create_backend(usb_backend, wait).await?;
    let mut conn = OdinConnection::new(usb);
    conn.query_device_info().await
}
