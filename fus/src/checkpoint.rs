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

//! Versioned (`SAMLOADR` v5) resumable download checkpoint metadata serialization.

use crate::decoder::ZipCheckpoint;
use crate::stream::OffsetCheckpoint;
use binrw::{BinRead, BinWrite, binrw};
use std::io::Cursor;

const META_VERSION: u32 = 5;

/// Polymorphic mid-stream checkpoint payload supporting raw offset streams and
/// ZIP archive entry streams.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointState {
    /// Raw byte-offset checkpoint for [`DataStream`](crate::DataStream) transfers.
    #[brw(magic = 1u8)]
    Offset(OffsetCheckpoint),
    /// ZIP entry checkpoint for [`ZipEntryStream`](crate::ZipEntryStream) transfers.
    #[brw(magic = 2u8)]
    Zip(ZipCheckpoint),
}

impl From<OffsetCheckpoint> for CheckpointState {
    fn from(cp: OffsetCheckpoint) -> Self {
        Self::Offset(cp)
    }
}

impl TryFrom<CheckpointState> for OffsetCheckpoint {
    type Error = ();

    fn try_from(state: CheckpointState) -> Result<Self, ()> {
        match state {
            CheckpointState::Offset(cp) => Ok(cp),
            _ => Err(()),
        }
    }
}

impl From<ZipCheckpoint> for CheckpointState {
    fn from(cp: ZipCheckpoint) -> Self {
        Self::Zip(cp)
    }
}

impl TryFrom<CheckpointState> for ZipCheckpoint {
    type Error = ();

    fn try_from(state: CheckpointState) -> Result<Self, ()> {
        match state {
            CheckpointState::Zip(cp) => Ok(cp),
            _ => Err(()),
        }
    }
}

/// Versioned (`SAMLOADR` v5) sidecar metadata record binding a [`CheckpointState`]
/// to a specific build checksum and expected output size.
#[binrw]
#[brw(little, magic = b"SAMLOADR")]
#[br(import(expected_checksum: [u8; 16], expected_size: u64))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointMeta {
    #[br(temp, assert(version == META_VERSION))]
    #[bw(calc = META_VERSION)]
    version: u32,

    /// Build fingerprint checksum identifying the source firmware binary.
    #[br(assert(checksum == expected_checksum))]
    pub checksum: [u8; 16],

    /// Expected byte length of the completed output file.
    #[br(assert(target_size == expected_size))]
    pub target_size: u64,

    /// Serialized mid-stream checkpoint state.
    pub state: CheckpointState,
}

impl CheckpointMeta {
    /// Serializes this metadata record into its `SAMLOADR` v5 binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::with_capacity(64));
        self.write(&mut cursor)
            .expect("in-memory checkpoint serialization cannot fail");
        cursor.into_inner()
    }

    /// Parses and validates a `SAMLOADR` v5 metadata record against `expected_checksum`
    /// and `expected_size`, rejecting truncated, overlong, or mismatched payloads.
    pub fn from_bytes(
        bytes: &[u8],
        expected_checksum: [u8; 16],
        expected_size: u64,
    ) -> Option<Self> {
        let mut cursor = Cursor::new(bytes);
        let meta = Self::read_args(&mut cursor, (expected_checksum, expected_size)).ok()?;
        (cursor.position() as usize == bytes.len()).then_some(meta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_meta_round_trip_and_rejection() {
        let checksum = [0x42; 16];
        let other_checksum = [0x99; 16];
        let target_size = 4096_u64;

        let offset_cp = OffsetCheckpoint::new(2048);

        let mut stored_bytes = [0u8; 13];
        stored_bytes[0] = 0; // Stored
        stored_bytes[1..9].copy_from_slice(&1536u64.to_le_bytes());
        stored_bytes[9..13].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let stored_cp = ZipCheckpoint::read(&mut Cursor::new(&stored_bytes)).unwrap();

        let mut deflate_bytes = [0u8; 23];
        deflate_bytes[0] = 1; // Deflate
        deflate_bytes[1..9].copy_from_slice(&1024u64.to_le_bytes());
        deflate_bytes[9..17].copy_from_slice(&3072u64.to_le_bytes());
        deflate_bytes[17..21].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        deflate_bytes[21] = 5;
        deflate_bytes[22] = 0x1A;
        let deflate_cp = ZipCheckpoint::read(&mut Cursor::new(&deflate_bytes)).unwrap();

        let mut last_bytes = Vec::new();
        for state in [
            CheckpointState::Offset(offset_cp),
            CheckpointState::Zip(stored_cp),
            CheckpointState::Zip(deflate_cp),
        ] {
            let meta = CheckpointMeta {
                checksum,
                target_size,
                state,
            };
            last_bytes = meta.to_bytes();

            let parsed = CheckpointMeta::from_bytes(&last_bytes, checksum, target_size).unwrap();
            assert_eq!(parsed.state, state);
        }

        // Cross-type checkpoint extraction must reject mismatches
        assert_eq!(
            OffsetCheckpoint::try_from(CheckpointState::Offset(offset_cp)),
            Ok(offset_cp)
        );
        assert_eq!(
            ZipCheckpoint::try_from(CheckpointState::Offset(offset_cp)),
            Err(())
        );
        assert_eq!(
            ZipCheckpoint::try_from(CheckpointState::Zip(deflate_cp)),
            Ok(deflate_cp)
        );
        assert_eq!(
            OffsetCheckpoint::try_from(CheckpointState::Zip(deflate_cp)),
            Err(())
        );

        // Truncated / trailing-garbage sidecar files must be rejected
        assert!(
            CheckpointMeta::from_bytes(&last_bytes[..last_bytes.len() - 1], checksum, target_size)
                .is_none()
        );
        let mut overlong = last_bytes.clone();
        overlong.push(0);
        assert!(CheckpointMeta::from_bytes(&overlong, checksum, target_size).is_none());

        // Corrupt magic (0), version (8), checksum (12), target_size (28), state tag (36), checkpoint kind (37)
        for &(off, val) in &[
            (0, 0xFF),
            (8, 0x04),
            (12, 0xFF),
            (28, 0xFF),
            (36, 0x09),
            (37, 0x09),
        ] {
            let mut tampered = last_bytes.clone();
            tampered[off] = val;
            assert!(
                CheckpointMeta::from_bytes(&tampered, checksum, target_size).is_none(),
                "offset={off}"
            );
        }

        // Checksum and target_size mismatches
        assert!(CheckpointMeta::from_bytes(&last_bytes, other_checksum, target_size).is_none());
        assert!(CheckpointMeta::from_bytes(&last_bytes, checksum, target_size + 1).is_none());
    }
}
