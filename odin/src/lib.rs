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

//! Crate implementing the Samsung Odin/Loke flashing protocol and communication backends.

#![deny(missing_docs)]

mod error;
mod firmware;
mod odin;
mod packets;
mod usb;

pub use error::OdinError;
pub use firmware::{
    FirmwareFile, FirmwareInfo, FirmwareLz4File, Lz4FrameHeader, verify_md5_footer,
};
pub use odin::{OdinManager, reboot_download};
pub use usb::{UsbBackend, UsbBackendOption, UsbTransfer, create_backend, detect_device};

#[cfg(feature = "nusb")]
pub use usb::NusbBackend;

#[cfg(feature = "rusb")]
pub use usb::RusbBackend;

#[cfg(feature = "serialport")]
pub use usb::SerialBackend;

// Re-export public dependencies to avoid type mismatch and SemVer issues in public APIs.
#[cfg(feature = "rusb")]
pub use rusb;
pub use samloader_pit;
