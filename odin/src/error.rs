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
#[non_exhaustive]
pub enum OdinError {
    /// Failed to send the handshake query.
    #[error("Failed to send handshake: {0}")]
    HandshakeSendFailed(#[source] TransportError),

    /// Failed to receive the handshake response.
    #[error("Failed to receive handshake response: {0}")]
    HandshakeReceiveFailed(#[source] TransportError),

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
    #[error("Failed to receive packet: {0}")]
    ReceivePacketFailed(#[source] TransportError),

    /// Failed to send a protocol command.
    #[error("Failed to send command: {0}")]
    SendCommandFailed(#[source] TransportError),

    /// Packet response type was not what was expected.
    #[error("Response type mismatch! Expected: {expected}, Received: {received}")]
    ResponseTypeMismatch {
        /// The expected packet response type ID.
        expected: u32,
        /// The actually received packet response type ID.
        received: u32,
    },

    /// Chunk index received from device did not match what we expected to send.
    #[error("Expected chunk index: {expected} Received: {received}")]
    ChunkIndexMismatch {
        /// The expected chunk index.
        expected: usize,
        /// The actually received chunk index.
        received: u32,
    },

    /// Failed to receive response for a sent chunk.
    #[error("Failed to receive chunk response: {0}")]
    ChunkResponseReceiveFailed(#[source] Box<OdinError>),

    /// An error reported by the Samsung LOKE bootloader.
    #[error("{0}")]
    Loke(#[from] LokeError),

    /// The USB or serial transport could not open the device or failed to transfer data.
    #[error("{0}")]
    Transport(#[from] TransportError),

    /// A slice is larger than the bootloader can stage in memory.
    #[error("Slice of {size} bytes exceeds the maximum of {max} bytes")]
    SliceTooLarge {
        /// The (decompressed) size of the slice in bytes.
        size: usize,
        /// The maximum slice size in bytes.
        max: usize,
    },

    /// A response packet from the device is malformed.
    #[error("{0}")]
    InvalidResponse(String),

    /// Device diagnostics (DVIF / 0x69) are not supported or unavailable on this device.
    #[error("Device information is not available on this device.")]
    DeviceInfoUnavailable,

    /// Failed to parse device diagnostics.
    #[error("Failed to parse device information: {0}")]
    DeviceInfoParseFailed(String),

    /// Invalid sales code provided (must be 3 ASCII alphanumeric characters).
    #[error("Invalid sales code \"{0}\": must be 3 alphanumeric ASCII characters (e.g. BTU, XAA)")]
    InvalidSalesCode(String),

    /// An I/O error occurred while reading or decompressing firmware data.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// An error from a USB or serial transport.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum TransportError {
    /// Failed to detect a compatible download-mode device.
    #[error("Failed to detect compatible download-mode device.")]
    DeviceNotFound,

    /// Failed to detect a Samsung device in normal (non-download) mode.
    #[error("Failed to detect Samsung device in normal mode.")]
    NormalModeDeviceNotFound,

    /// Failed to access the USB device.
    #[cfg(target_os = "linux")]
    #[error(
        "Failed to access device. Error: {0}\n\n\
             On Linux, this is usually because your user lacks write permission to the USB device node.\n\
             To automatically fix this, please run the builtin fix command as root:\n\n\
             \tsudo samloader fix-usb"
    )]
    DeviceAccess(Box<dyn std::error::Error + Send + Sync>),

    /// Failed to access the USB device.
    #[cfg(not(target_os = "linux"))]
    #[error("Failed to access device. Error: {0}")]
    DeviceAccess(Box<dyn std::error::Error + Send + Sync>),

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

    /// The name does not match any USB backend enabled in this build.
    #[error("Unknown USB backend: {0}")]
    UnknownBackend(String),

    /// The transfer did not complete before its timeout.
    #[error("Transfer timed out")]
    Timeout,

    /// The transport accepted fewer bytes than were sent.
    #[error("Short write: sent {sent} of {expected} bytes")]
    ShortWrite {
        /// The number of bytes the transport accepted.
        sent: usize,
        /// The number of bytes that were to be sent.
        expected: usize,
    },

    /// The transport could not be set up.
    #[error("{0}: {1}")]
    Setup(String, #[source] Box<dyn std::error::Error + Send + Sync>),

    /// The backend library reported an error.
    #[error(transparent)]
    Backend(Box<dyn std::error::Error + Send + Sync>),
}

impl TransportError {
    /// Wraps an error from the backend library.
    pub(crate) fn backend(e: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Backend(Box::new(e))
    }
}

/// Detailed error status reported by the Samsung LOKE bootloader.
#[derive(Error, Debug, PartialEq, Eq)]
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
            -2 | -20 => Self::WriteProtection,
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
#[non_exhaustive]
pub enum FlashError {
    /// An error originating from the low-level Odin protocol client.
    #[error("Odin error: {0}")]
    Odin(#[from] OdinError),

    /// Failed to read from a file.
    #[error("Failed to read file \"{0}\": {1}")]
    FileReadFailed(String, #[source] std::io::Error),

    /// Failed to parse an LZ4 frame header.
    #[error("Failed to parse LZ4 header for \"{0}\": {1}")]
    Lz4Header(String, #[source] std::io::Error),

    /// The TAR archive contains a corrupted entry.
    #[error("Corrupted archive entry in \"{0}\": {1}")]
    ArchiveCorrupted(String, #[source] std::io::Error),

    /// MD5 verification failed for a TAR archive.
    #[error("MD5 verification failed for \"{0}\": {1}")]
    Md5VerificationFailed(String, #[source] std::io::Error),

    /// The files within the packages do not agree on the download allowlist manifest.
    #[error("Cross-archive consistency check failed! download-list.txt does not match.")]
    CrossArchiveInconsistency,

    /// Failed to unpack the device-specific PIT file.
    #[error("Failed to unpack device's PIT file: {0}")]
    PitUnpackFailed(#[source] binrw::Error),

    /// The file does not map to any partition in the active PIT table.
    #[error("File \"{0}\" does not match any partition in the specified PIT.")]
    PartitionNotFound(String),

    /// The requested partition ID does not exist in the active PIT table.
    #[error("Partition ID {0} does not exist in the specified PIT.")]
    PartitionIdNotFound(u32),

    /// The skip target does not match any file or partition in the active PIT table.
    #[error("Skip target \"{0}\" does not match any file or partition in the specified PIT.")]
    SkipTargetNotFound(String),

    /// Failed to set the requested AVB flags in a vbmeta image.
    #[error("Failed to rewrite vbmeta of {0}: {1}")]
    VbmetaRewriteFailed(String, #[source] std::io::Error),

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loke_error_from_status() {
        assert_eq!(LokeError::from_status(-2), LokeError::WriteProtection);
        assert_eq!(LokeError::from_status(-20), LokeError::WriteProtection);
        assert_eq!(LokeError::from_status(-3), LokeError::EraseFailure);
        assert_eq!(LokeError::from_status(-4), LokeError::WriteFailure);
        assert_eq!(LokeError::from_status(-5), LokeError::AuthFailure);
        assert_eq!(LokeError::from_status(-6), LokeError::SizeLimitExceeded);
        assert_eq!(LokeError::from_status(-7), LokeError::Ext4Error);
        assert_eq!(LokeError::from_status(2), LokeError::InvalidBinary);
        assert_eq!(LokeError::from_status(3), LokeError::PitGptMismatch);
        assert_eq!(LokeError::from_status(5), LokeError::PartitionSizeExceeded);
        assert_eq!(LokeError::from_status(14), LokeError::PartitionNotFound);
        assert_eq!(
            LokeError::from_status(i32::MIN),
            LokeError::UnsupportedDeviceType
        );
        assert_eq!(LokeError::from_status(0), LokeError::General(0));
        assert_eq!(LokeError::from_status(-1), LokeError::General(-1));
        assert_eq!(LokeError::from_status(999), LokeError::Other(999));
    }
}
