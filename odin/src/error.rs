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

#[derive(Error, Debug)]
pub enum OdinError {
    #[error("Failed to detect compatible download-mode device.")]
    DeviceNotFound,

    #[error("Failed to access device. Serial port error: {0}")]
    DeviceAccess(#[from] serialport::Error),

    #[error("Failed to retrieve config descriptor")]
    ConfigDescriptorRetrieval,

    #[error("Failed to find correct interface configuration")]
    InterfaceConfigurationNotFound,

    #[error("Claiming interface failed!")]
    InterfaceClaimFailed,

    #[error("Setting up interface failed!")]
    InterfaceSetupFailed,

    #[error("Failed to send handshake!")]
    HandshakeSendFailed,

    #[error("Unexpected handshake response!\nFailed to receive handshake response.")]
    HandshakeReceiveFailed,

    #[error("Unexpected handshake response!\nExpected: \"{expected}\"\nReceived: \"{received}\"")]
    HandshakeMismatch { expected: String, received: String },

    #[error("Unexpected handshake response!")]
    UnexpectedHandshake,

    #[error("Failed to receive packet!")]
    ReceivePacketFailed,

    #[error("Failed to send packet!")]
    SendPacketFailed,

    #[error("Response type mismatch! Expected: {expected}, Received: {received}")]
    ResponseTypeMismatch { expected: u32, received: u32 },

    #[error("Failed to receive PIT file size!")]
    PitFileSizeReceiveFailed,

    #[error("Failed to request PIT file part #{0}!")]
    PitFilePartRequestFailed(u32),

    #[error("Failed to receive PIT file part #{0}!")]
    PitFilePartReceiveFailed(u32),

    #[error("Failed to send request to end PIT file transfer!")]
    PitFileEndSendFailed,

    #[error("Failed to download PIT file!")]
    PitDownloadFailed,

    #[error("Failed to begin file transfer sequence!")]
    FileTransferSequenceBeginFailed,

    #[error("Expected file part index: {expected} Received: {received}")]
    FilePartIndexMismatch { expected: usize, received: u32 },

    #[error("Failed to receive file part response!")]
    FilePartResponseReceiveFailed,

    #[error("Failed to end file transfer sequence!")]
    FileTransferSequenceEndFailed,

    #[error("Failed to begin session!")]
    BeginSessionFailed,

    #[error("Failed to send file part size packet!")]
    FilePartSizeSendFailed,

    #[error("Unexpected file part size response!\nExpected: 0\nReceived: {0}")]
    UnexpectedFilePartSizeResponse(u32),

    #[error("Failed to send end session packet!")]
    EndSessionSendFailed,

    #[error("Failed to send reboot device packet!")]
    RebootDeviceSendFailed,

    #[error("Failed to initialize PIT file transfer!")]
    PitFileTransferInitFailed,

    #[error("Failed to send PIT file part information!")]
    PitFilePartInfoSendFailed,

    #[error("Failed to send end PIT file transfer packet!")]
    PitFileTransferEndSendFailed,

    #[error("Failed to initialize file transfer!")]
    FileTransferInitFailed,

    #[error("Failed to send total bytes packet!")]
    TotalBytesSendFailed,

    #[error("Unexpected session total bytes response!\nExpected: 0\nReceived: {0}")]
    UnexpectedTotalBytesResponse(u32),

    #[error("Serial port error: {0}")]
    SerialError(String),

    #[error("{0}")]
    ParseError(String),
}
