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

#[cfg(all(target_arch = "wasm32", feature = "rusb"))]
compile_error!("Feature 'rusb' is not supported when building for WebAssembly!");

#[doc(hidden)]
pub mod compat;
mod device_info;
mod error;
mod firmware;
mod flash;
mod modem;
mod progress;
mod protocol;
mod session;
mod usb;

#[cfg(test)]
mod test_util;

pub use device_info::{DeviceInfo, SessionDeviceInfo};
pub use error::{FlashError, LokeError, OdinError, SendPartitionError, TransportError};
pub use firmware::verify_md5_footer;
pub use flash::{FlashRequest, PartitionTarget, PreparedFlash};
pub use modem::{DownloadModeReboot, reboot_download};
pub use progress::{FlashEvent, FlashProgress, clear_progress, set_progress};
pub use session::{OdinConnection, OdinSession, RebootMode, SalesCode};
pub use usb::{DeviceMode, UsbBackendOption, UsbTransfer, create_backend, detect_device};

#[cfg(target_arch = "wasm32")]
pub use modem::request_reboot_device;
#[cfg(target_arch = "wasm32")]
pub use usb::request_device;

// Re-export public dependencies to avoid type mismatch and SemVer issues in public APIs.
pub use binrw;
pub use futures;
pub use samloader_pit;

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
