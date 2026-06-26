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

    /// Failed to access the USB device via libusb.
    #[cfg(all(target_os = "linux", feature = "rusb"))]
    #[error(
        "Failed to access device. libusb error: {0}\n\n\
             On Linux, this is usually because your user lacks write permission to the USB device node.\n\
             To automatically fix this, please run the builtin fix command as root:\n\n\
             \tsudo samloader fix-usb"
    )]
    DeviceAccess(#[from] rusb::Error),

    /// Failed to access the USB device via libusb.
    #[cfg(all(not(target_os = "linux"), feature = "rusb"))]
    #[error("Failed to access device. libusb error: {0}")]
    DeviceAccess(#[from] rusb::Error),

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

    /// Failed to receive PIT file size.
    #[error("Failed to receive PIT file size!")]
    PitFileSizeReceiveFailed,

    /// Failed to request a specific part of the PIT file.
    #[error("Failed to request PIT file part #{0}!")]
    PitFilePartRequestFailed(u32),

    /// Failed to receive a specific part of the PIT file.
    #[error("Failed to receive PIT file part #{0}!")]
    PitFilePartReceiveFailed(u32),

    /// Failed to request ending the PIT file transfer sequence.
    #[error("Failed to send request to end PIT file transfer!")]
    PitFileEndSendFailed,

    /// General failure during device PIT file download.
    #[error("Failed to download PIT file!")]
    PitDownloadFailed,

    /// Failed to start the sequence for uploading/downloading a firmware file.
    #[error("Failed to begin file transfer sequence!")]
    FileTransferSequenceBeginFailed,

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

    /// Failed to end the sequence for uploading/downloading a firmware file.
    #[error("Failed to end file transfer sequence!")]
    FileTransferSequenceEndFailed,

    /// Failed to start the Odin flashing session.
    #[error("Failed to begin session!")]
    BeginSessionFailed,

    /// Failed to negotiate the packet transfer chunk size.
    #[error("Failed to send file part size packet!")]
    FilePartSizeSendFailed,

    /// Negotiating packet transfer chunk size returned an error status code.
    #[error("Unexpected file part size response!\nExpected: 0\nReceived: {0}")]
    UnexpectedFilePartSizeResponse(u32),

    /// Failed to end the Odin flashing session.
    #[error("Failed to send end session packet!")]
    EndSessionSendFailed,

    /// Failed to initialize PIT flashing transfer.
    #[error("Failed to initialize PIT file transfer!")]
    PitFileTransferInitFailed,

    /// Failed to send PIT partition metadata info.
    #[error("Failed to send PIT file part information!")]
    PitFilePartInfoSendFailed,

    /// Failed to complete PIT partition flashing sequence.
    #[error("Failed to send end PIT file transfer packet!")]
    PitFileTransferEndSendFailed,

    /// Failed to prepare file transfer operations.
    #[error("Failed to initialize file transfer!")]
    FileTransferInitFailed,

    /// Failed to advertise the total flashing session payload size in bytes.
    #[error("Failed to send total bytes packet!")]
    TotalBytesSendFailed,

    /// Initiating session total bytes returned an error status code.
    #[error("Unexpected session total bytes response!\nExpected: 0\nReceived: {0}")]
    UnexpectedTotalBytesResponse(u32),

    /// An error occurred on the serial/VCOM communication port.
    #[error("Serial port error: {0}")]
    SerialError(String),

    /// An error occurred while parsing structures or headers.
    #[error("{0}")]
    ParseError(String),
}
