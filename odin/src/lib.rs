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

pub mod error;
pub mod firmware;
pub mod odin_manager;
pub mod packets;
pub mod usb;

pub use error::OdinError;
pub use firmware::{
    FirmwareFile, FirmwareInfo, FirmwareLz4File, FirmwareSource, Lz4FrameHeader, TarEntryReader,
    verify_md5_footer,
};
pub use odin_manager::{OdinManager, reboot_download};
pub use rusb;
pub use usb::{UsbManager, find_download_mode_device};
