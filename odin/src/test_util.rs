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

//! Helpers shared by the crate's tests.

use crate::firmware::Lz4FrameHeader;
use crate::session::{OdinConnection, OdinSession};
use crate::usb::MockBackend;
use futures::io::Cursor;
use lz4_flex::frame::BlockSize;
use samloader_pit::{PitData, PitEntry};

/// PIT of an A/B device (SM-F968B).
pub(crate) const Q7MQ_PIT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/test-data/Q7MQ_EUR_OPENX.pit"
));

/// PIT of a legacy non-A/B device (GT-I9305).
pub(crate) const M3_PIT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/test-data/M3_EUR_OPEN_4G.pit"
));

/// PIT of a MediaTek device with lowercase partition names (SM-A145R).
pub(crate) const A14M_PIT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/test-data/A14M_MEA_OPEN.pit"
));

/// Parses [`Q7MQ_PIT`].
pub(crate) fn ab_pit_data() -> PitData {
    PitData::new(Q7MQ_PIT).unwrap()
}

/// Finds a PIT entry that is known to exist.
pub(crate) fn find_entry<'p>(pit_data: &'p PitData, name: &str) -> &'p PitEntry {
    pit_data.find_entry_by_name(name).unwrap()
}

/// Begins a session on a mock device.
pub(crate) async fn mock_session(backend: MockBackend) -> OdinSession {
    let mut connection = OdinConnection::new(Box::new(backend));
    connection.init().await.unwrap();
    connection.begin_session().await.unwrap()
}

/// Builds a TAR archive containing `files` as `(path, content)`.
pub(crate) fn build_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for &(path, content) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, content).unwrap();
    }
    builder.finish().unwrap();
    builder.into_inner().unwrap()
}

/// Compresses `data` into an LZ4 frame with 1 MiB independent blocks, like Samsung
/// firmware, returning the frame and its parsed header.
pub(crate) fn lz4_compress(data: &[u8]) -> (Vec<u8>, Lz4FrameHeader) {
    lz4_compress_with(data, BlockSize::Max1MB)
}

/// Compresses `data` into an LZ4 frame with independent blocks of `block_size`,
/// returning the frame and its parsed header.
pub(crate) fn lz4_compress_with(data: &[u8], block_size: BlockSize) -> (Vec<u8>, Lz4FrameHeader) {
    use lz4_flex::frame::{BlockMode, FrameEncoder, FrameInfo};
    use std::io::Write;

    let info = FrameInfo::new()
        .content_size(Some(data.len() as u64))
        .block_size(block_size)
        .block_mode(BlockMode::Independent);
    let mut encoder = FrameEncoder::with_frame_info(info, Vec::new());
    encoder.write_all(data).unwrap();
    let compressed = encoder.finish().unwrap();
    let header =
        futures::executor::block_on(Lz4FrameHeader::parse(Cursor::new(&compressed[..]))).unwrap();
    (compressed, header)
}
