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

use thiserror::Error;

/// Represents all errors that can occur during communication with Samsung devices using the Odin protocol.
#[derive(Error, Debug)]
pub enum OdinError {
    /// Failed to detect a compatible download-mode device.
    #[error("Failed to detect compatible download-mode device.")]
    DeviceNotFound,

    /// Failed to access the USB device.
    #[cfg(target_os = "linux")]
    #[error(
        "Failed to access device. Error: {0}\n\n\
             On Linux, this is usually because your user lacks write permission to the USB device node.\n\
             To automatically fix this, please run the builtin fix command as root:\n\n\
             \tsudo samloader fix-usb"
    )]
    DeviceAccess(#[from] Box<dyn std::error::Error + Send + Sync>),

    /// Failed to access the USB device.
    #[cfg(not(target_os = "linux"))]
    #[error("Failed to access device. Error: {0}")]
    DeviceAccess(#[from] Box<dyn std::error::Error + Send + Sync>),

    /// Failed to retrieve the configuration descriptor from the USB device.
    #[error("Failed to retrieve config descriptor")]
    ConfigDescriptorRetrieval,

    /// Failed to find the correct interface configuration on the USB device.
    #[error("Failed to find correct interface configuration")]
    InterfaceConfigurationNotFound,

    /// Failed to claim the USB interface.
    #[error("Claiming interface failed!")]
    InterfaceClaimFailed,

    /// Failed to set up the USB interface.
    #[error("Setting up interface failed!")]
    InterfaceSetupFailed,

    /// Failed to send the handshake query.
    #[error("Failed to send handshake!")]
    HandshakeSendFailed,

    /// Failed to receive the handshake response.
    #[error("Unexpected handshake response!\nFailed to receive handshake response.")]
    HandshakeReceiveFailed,

    /// Handshake response did not match the expected greeting.
    #[error("Unexpected handshake response!\nExpected: \"{expected}\"\nReceived: \"{received}\"")]
    HandshakeMismatch {
        /// The expected response string.
        expected: String,
        /// The actually received response string.
        received: String,
    },

    /// Received an unexpected handshake format.
    #[error("Unexpected handshake response!")]
    UnexpectedHandshake,

    /// Failed to receive a protocol packet.
    #[error("Failed to receive packet!")]
    ReceivePacketFailed,

    /// Failed to send a protocol packet.
    #[error("Failed to send packet!")]
    SendPacketFailed,

    /// Packet response type was not what was expected.
    #[error("Response type mismatch! Expected: {expected}, Received: {received}")]
    ResponseTypeMismatch {
        /// The expected packet response type ID.
        expected: u32,
        /// The actually received packet response type ID.
        received: u32,
    },

    /// File part index received from device did not match what we expected to send.
    #[error("Expected file part index: {expected} Received: {received}")]
    FilePartIndexMismatch {
        /// The expected file part index.
        expected: usize,
        /// The actually received file part index.
        received: u32,
    },

    /// Failed to receive response for a sent file part block.
    #[error("Failed to receive file part response!")]
    FilePartResponseReceiveFailed,

    /// An error reported by the Samsung LOKE bootloader.
    #[error("{0}")]
    Loke(#[from] LokeError),

    /// An error occurred on the serial/VCOM communication port.
    #[error("Serial port error: {0}")]
    SerialError(String),

    /// An error occurred while parsing structures or headers.
    #[error("{0}")]
    ParseError(String),

    /// Device diagnostics (DVIF / 0x69) are not supported or unavailable on this device.
    #[error("Device information is not available on this device.")]
    DeviceInfoUnavailable,

    /// Failed to parse device diagnostics.
    #[error("Failed to parse device information: {0}")]
    DeviceInfoParseFailed(String),

    /// Invalid sales code provided (must be 3 ASCII alphanumeric characters).
    #[error("Invalid sales code \"{0}\": must be 3 alphanumeric ASCII characters (e.g. BTU, XAA)")]
    InvalidSalesCode(String),
}

/// Detailed error status reported by the Samsung LOKE bootloader.
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum LokeError {
    /// General failure / operation aborted / buffer overflow (-1 or 0).
    #[error("LOKE returned general failure (FAIL!) [code: {0}]")]
    General(i32),

    /// Storage partition is write-protected (-2).
    #[error("Storage partition is write-protected (FAIL! WP) [code: -2]")]
    WriteProtection,

    /// Flash block erase failure (-3).
    #[error("Flash block erase failure (FAIL! Erase) [code: -3]")]
    EraseFailure,

    /// Flash storage write failure (-4).
    #[error("Flash storage write failure (FAIL! Write) [code: -4]")]
    WriteFailure,

    /// Cryptographic signature, anti-rollback, or device lock verification failure (-5).
    #[error("Security or signature verification failure (FAIL! Auth) [code: -5]")]
    AuthFailure,

    /// Flashed image exceeds partition capacity or size limit (-6).
    #[error("Image exceeds partition size limit (FAIL! Size) [code: -6]")]
    SizeLimitExceeded,

    /// Sparse image format error or corrupt ext4 filesystem (-7).
    #[error("Corrupt filesystem or sparse image format error (FAIL! Ext4) [code: -7]")]
    Ext4Error,

    /// Binary rejected: partition name is blacklisted (code: 2).
    #[error("Binary rejected by device: invalid binary name (code: 2)")]
    InvalidBinary,

    /// Partition table mismatch between PIT and device GPT (code: 3).
    #[error("Partition table mismatch: PIT and GPT do not match (code: 3)")]
    PitGptMismatch,

    /// Flashed image exceeds partition boundary (code: 5).
    #[error("Image size exceeds partition boundary (code: 5)")]
    PartitionSizeExceeded,

    /// Partition not found in device partition table (code: 14).
    #[error("Partition not found in device partition table (code: 14)")]
    PartitionNotFound,

    /// Unsupported storage device type (code: 0x80000000).
    #[error("Unsupported storage device type (code: 0x80000000)")]
    UnsupportedDeviceType,

    /// Other failure code returned by LOKE.
    #[error("LOKE returned error status {0} (FAIL!)")]
    Other(i32),
}

impl LokeError {
    /// Maps a raw 32-bit status code from LOKE into a typed [`LokeError`].
    pub fn from_status(status_code: i32) -> Self {
        match status_code {
            -2 => Self::WriteProtection,
            -3 => Self::EraseFailure,
            -4 => Self::WriteFailure,
            -5 => Self::AuthFailure,
            -6 => Self::SizeLimitExceeded,
            -7 => Self::Ext4Error,
            2 => Self::InvalidBinary,
            3 => Self::PitGptMismatch,
            5 => Self::PartitionSizeExceeded,
            14 => Self::PartitionNotFound,
            i32::MIN => Self::UnsupportedDeviceType,
            0 | -1 => Self::General(status_code),
            other => Self::Other(other),
        }
    }
}

/// Represents errors that can occur during the high-level flashing process.
#[derive(Error, Debug)]
pub enum FlashError {
    /// An error originating from the low-level Odin protocol client.
    #[error("Odin error: {0}")]
    Odin(#[from] OdinError),

    /// Failed to open a file.
    #[error("Failed to open file \"{0}\": {1}")]
    FileOpenFailed(String, #[source] std::io::Error),

    /// Failed to read from a file.
    #[error("Failed to read file \"{0}\": {1}")]
    FileReadFailed(String, #[source] std::io::Error),

    /// Failed to seek within a file.
    #[error("Failed to seek file \"{0}\": {1}")]
    FileSeekFailed(String, #[source] std::io::Error),

    /// Failed to memory-map a file.
    #[error("Failed to memory map file \"{0}\": {1}")]
    MmapFailed(String, #[source] std::io::Error),

    /// Failed to parse an LZ4 frame header.
    #[error("Failed to parse LZ4 header for \"{0}\": {1}")]
    Lz4Header(String, #[source] std::io::Error),

    /// Failed to read entries from a TAR archive.
    #[error("Failed to read archive entries for \"{0}\": {1}")]
    ArchiveReadFailed(String, #[source] std::io::Error),

    /// The TAR archive contains a corrupted entry.
    #[error("Corrupted archive entry in \"{0}\": {1}")]
    ArchiveCorrupted(String, #[source] std::io::Error),

    /// MD5 verification failed for a TAR archive.
    #[error("MD5 verification failed for \"{0}\": {1}")]
    Md5VerificationFailed(String, #[source] std::io::Error),

    /// The files within the packages do not agree on the download allowlist manifest.
    #[error("Cross-archive consistency check failed! download-list.txt does not match.")]
    CrossArchiveInconsistency,

    /// Partition re-allocation requires an explicit PIT file.
    #[error("If you wish to repartition then a PIT file must be specified.")]
    RepartitionPitRequired,

    /// Failed to unpack the device-specific PIT file.
    #[error("Failed to unpack device's PIT file: {0}")]
    PitUnpackFailed(#[source] binrw::Error),

    /// The file does not map to any partition in the active PIT table.
    #[error("File \"{0}\" does not match any partition in the specified PIT.")]
    PartitionNotFound(String),

    /// The requested partition ID does not exist in the active PIT table.
    #[error("Partition identifier {0} does not exist in the specified PIT.")]
    PartitionIdNotFound(u32),

    /// The file payload is larger than the partition size defined in PIT.
    #[error("{0} partition is too small for given file. Use --skip-size-check to flash anyways.")]
    PartitionTooSmall(String),

    /// Dynamic partition pre-flight check failed due to insufficient space in Super partition or corrupt metadata.
    #[error(
        "Dynamic partition pre-flight check failed: insufficient free space in Super partition \
         or metadata corrupted. When flashing HOME_CSC without wipe, the Super partition must \
         have enough space for the target OS image. \
         (Try flashing the CSC binary to perform a clean flash)"
    )]
    SuperSizeCheckFailed(#[source] OdinError),
}
