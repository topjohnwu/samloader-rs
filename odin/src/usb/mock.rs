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

//! Mock transport mimicking the Samsung Odin/Loke download mode protocol
//! emulating a Samsung SM-F968B device.

use crate::packets::{
    RESPONSE_TYPE_END_SESSION, RESPONSE_TYPE_FILE_TRANSFER, RESPONSE_TYPE_PIT_FILE,
    RESPONSE_TYPE_SEND_FILE_PART, RESPONSE_TYPE_SESSION_SETUP, RequestPacket,
};
use crate::usb::UsbTransfer;
use binrw::BinRead;
use std::collections::VecDeque;
use std::io::Cursor;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Uninitialized,
    HandshakeComplete,
    SessionBegun,
    FileTransferFlash,
    FileTransferPart,
}

/// A mock USB/serial transport backend that implements the Loke-Odin protocol,
/// emulating a Samsung SM-F968B device.
pub struct MockBackend {
    verbose: bool,
    state: State,
    incoming_buffer: Vec<u8>,
    outgoing_queue: VecDeque<u8>,
    current_part_index: u32,
    packet_size: usize,
    pit_data: &'static [u8],
}

impl MockBackend {
    /// Instantiates a new `MockBackend`.
    pub fn new(verbose: bool) -> Self {
        Self {
            verbose,
            state: State::Uninitialized,
            incoming_buffer: Vec::new(),
            outgoing_queue: VecDeque::new(),
            current_part_index: 0,
            packet_size: 0x20000, // default Loke part size
            pit_data: include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/test-data/Q7MQ_EUR_OPENX.pit"
            )),
        }
    }

    fn push_response(&mut self, response_type: u32, value: u32) {
        if self.verbose {
            eprintln!(
                "MockBackend: queueing response: response_type = {:#04X?}, value = {}",
                response_type, value
            );
        }
        self.outgoing_queue.extend(&response_type.to_le_bytes());
        self.outgoing_queue.extend(&value.to_le_bytes());
    }
}

impl UsbTransfer for MockBackend {
    fn reset(&mut self) {
        if self.verbose {
            eprintln!("MockBackend: connection reset");
        }
        self.state = State::Uninitialized;
        self.incoming_buffer.clear();
        self.outgoing_queue.clear();
        self.current_part_index = 0;
        self.packet_size = 0x20000;
    }

    fn send_data(&mut self, data: &[u8], _timeout: i32, _retry: bool) -> bool {
        if data.is_empty() {
            return true;
        }

        self.incoming_buffer.extend_from_slice(data);

        match self.state {
            State::Uninitialized => {
                if self.incoming_buffer == b"ODIN" {
                    if self.verbose {
                        eprintln!("MockBackend: Handshake matching ODIN -> LOKE");
                    }
                    self.state = State::HandshakeComplete;
                    self.outgoing_queue.extend(b"LOKE");
                    self.incoming_buffer.clear();
                }
            }
            State::HandshakeComplete
            | State::SessionBegun
            | State::FileTransferFlash
            | State::FileTransferPart => {
                // If we are transmitting partition file chunks, consume raw
                // bytes of `packet_size` size.
                if self.state == State::FileTransferPart
                    && self.incoming_buffer.len() >= self.packet_size
                {
                    if self.verbose {
                        eprintln!(
                            "MockBackend: Received chunk of {} bytes (idx: {})",
                            self.packet_size, self.current_part_index
                        );
                    }
                    self.push_response(RESPONSE_TYPE_SEND_FILE_PART, self.current_part_index);
                    self.current_part_index += 1;
                    self.incoming_buffer.drain(..self.packet_size);
                    return true;
                }

                // Otherwise, parse standard 1024-byte control packets
                if self.incoming_buffer.len() >= 1024 {
                    let mut cursor = Cursor::new(&self.incoming_buffer[..1024]);
                    if let Ok(packet) = RequestPacket::read_le(&mut cursor) {
                        if self.verbose {
                            eprintln!("MockBackend: Received request packet: {:?}", packet);
                        }
                        match packet {
                            RequestPacket::Session(session_req) => match session_req {
                                crate::packets::SessionRequest::Begin { .. } => {
                                    self.state = State::SessionBegun;
                                    // Report version 2 + LZ4 compression support
                                    self.push_response(RESPONSE_TYPE_SESSION_SETUP, 0x00028000);
                                }
                                crate::packets::SessionRequest::FilePartSize { size } => {
                                    self.packet_size = size as usize;
                                    self.push_response(RESPONSE_TYPE_SESSION_SETUP, 0);
                                }
                                _ => {
                                    self.push_response(RESPONSE_TYPE_SESSION_SETUP, 0);
                                }
                            },
                            RequestPacket::PitFile(pit_req) => match pit_req {
                                crate::packets::PitFileRequest::Flash => {
                                    self.push_response(RESPONSE_TYPE_PIT_FILE, 0);
                                }
                                crate::packets::PitFileRequest::Dump => {
                                    self.push_response(
                                        RESPONSE_TYPE_PIT_FILE,
                                        self.pit_data.len() as u32,
                                    );
                                }
                                crate::packets::PitFileRequest::Part(pit_part) => {
                                    let part = match pit_part {
                                        crate::packets::PitFilePart::Flash { size } => size,
                                        crate::packets::PitFilePart::Dump { part } => part,
                                    };
                                    let offset = part as usize * 500;
                                    let end = (offset + 500).min(self.pit_data.len());
                                    if offset < self.pit_data.len() {
                                        self.outgoing_queue.extend(&self.pit_data[offset..end]);
                                    }
                                }
                                _ => {
                                    self.push_response(RESPONSE_TYPE_PIT_FILE, 0);
                                }
                            },
                            RequestPacket::FileTransfer(transfer_req) => match transfer_req {
                                crate::packets::FileTransferRequest::Flash
                                | crate::packets::FileTransferRequest::Lz4Flash => {
                                    self.state = State::FileTransferFlash;
                                    self.push_response(RESPONSE_TYPE_FILE_TRANSFER, 0);
                                }
                                crate::packets::FileTransferRequest::Part { .. }
                                | crate::packets::FileTransferRequest::Lz4Part { .. } => {
                                    self.state = State::FileTransferPart;
                                    self.current_part_index = 0;
                                    self.push_response(RESPONSE_TYPE_FILE_TRANSFER, 0);
                                }
                                crate::packets::FileTransferRequest::End(_)
                                | crate::packets::FileTransferRequest::Lz4End(_) => {
                                    self.state = State::SessionBegun;
                                    self.push_response(RESPONSE_TYPE_FILE_TRANSFER, 0);
                                }
                            },
                            RequestPacket::EndSession(end_req) => match end_req {
                                crate::packets::EndSessionRequest::EndSession => {
                                    self.state = State::HandshakeComplete;
                                    self.push_response(RESPONSE_TYPE_END_SESSION, 0);
                                }
                                crate::packets::EndSessionRequest::RebootDevice => {
                                    self.state = State::Uninitialized;
                                }
                            },
                        }
                    }
                    self.incoming_buffer.drain(..1024);
                }
            }
        }
        true
    }

    fn receive_data(&mut self, data: &mut [u8], _timeout: i32, _retry: bool) -> i32 {
        if self.outgoing_queue.is_empty() {
            return 0;
        }
        let size = std::cmp::min(data.len(), self.outgoing_queue.len());
        for item in data.iter_mut().take(size) {
            *item = self.outgoing_queue.pop_front().unwrap();
        }
        size as i32
    }
}
