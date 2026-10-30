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

//! Transport abstractions implemented by every USB and serial backend.

use crate::compat::MaybeSend;
use crate::error::{OdinError, TransportError};
use std::time::Duration;

/// USB interface class code of CDC data interfaces, which carry the Odin
/// protocol in Download Mode and AT commands in normal mode.
#[cfg(any(feature = "nusb", feature = "rusb"))]
pub(crate) const USB_CLASS_CDC_DATA: u8 = 0x0A;

/// Trait representing a duplex data transport layer for USB or serial communication.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait UsbTransfer: MaybeSend {
    /// Resets the transport connection state and buffers.
    async fn reset(&mut self);
    /// Sends all of `data` across the transport, failing if it cannot be sent
    /// within `timeout`. An empty `data` sends a zero-length packet.
    async fn send(&mut self, data: &[u8], timeout: Duration) -> Result<(), TransportError>;
    /// Receives data from the transport into `data` within `timeout`,
    /// returning the number of bytes read. A zero-length packet reads 0 bytes.
    async fn receive(
        &mut self,
        data: &mut [u8],
        timeout: Duration,
    ) -> Result<usize, TransportError>;
    /// Returns the USB Product descriptor string if available.
    fn product_name(&self) -> Option<&str> {
        None
    }
}

/// Trait representing a backend factory and device locator for USB or serial transports.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait UsbBackend: Sized + UsbTransfer {
    /// The associated device type identifier.
    type UsbDevice: MaybeSend;

    /// Instantiates a new backend session wrapper for a given device.
    async fn new(device: Self::UsbDevice) -> Result<Self, OdinError>;
    /// Searches for a matching connected device based on a predicate.
    async fn find_device<'a, F>(predicate: F) -> Result<Self::UsbDevice, OdinError>
    where
        F: FnMut(u16, u16) -> bool + MaybeSend + 'a;
}
