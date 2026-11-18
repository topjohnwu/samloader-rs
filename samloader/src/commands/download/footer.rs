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

use binrw::{BinRead, BinWrite, binrw};
use fast_md5::Md5;
use samloader_fus::BinaryInform;
use std::fs::{File, OpenOptions};
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const FOOTER_VERSION: u32 = 4;
pub(crate) const FOOTER_SIZE: usize = 36;

#[binrw]
#[brw(little, magic = b"SAMLOADR")]
#[br(import(expected_checksum: [u8; 16], target_size: u64))]
pub(crate) struct Footer {
    #[br(temp, assert(version == FOOTER_VERSION))]
    #[bw(calc = FOOTER_VERSION)]
    version: u32,

    #[br(assert(checksum == expected_checksum))]
    pub checksum: [u8; 16],

    #[br(assert(offset <= target_size))]
    pub offset: u64,
}

impl Footer {
    pub(crate) fn new(checksum: [u8; 16]) -> Self {
        Self {
            checksum,
            offset: 0,
        }
    }

    pub(crate) fn write_to_slice(&self, dst: &mut [u8; FOOTER_SIZE]) {
        let mut cursor = Cursor::new(&mut dst[..]);
        self.write(&mut cursor)
            .expect("in-memory footer serialization cannot fail");
        debug_assert_eq!(cursor.position() as usize, FOOTER_SIZE);
    }

    pub(crate) fn read_from_part<R: Read + Seek>(
        reader: &mut R,
        expected_checksum: [u8; 16],
        target_size: u64,
    ) -> Option<Self> {
        let file_len = reader.seek(SeekFrom::End(0)).ok()?;
        let expected_len = target_size.checked_add(FOOTER_SIZE as u64)?;
        if file_len != expected_len {
            return None;
        }
        reader.seek(SeekFrom::Start(target_size)).ok()?;
        Self::read_args(reader, (expected_checksum, target_size)).ok()
    }
}

fn update_len_prefixed(hasher: &mut Md5, data: &[u8]) {
    hasher.update(&(data.len() as u64).to_le_bytes());
    hasher.update(data);
}

pub(crate) fn raw_checksum(info: &BinaryInform) -> [u8; 16] {
    let mut hasher = Md5::new();
    update_len_prefixed(&mut hasher, info.version.as_bytes());
    update_len_prefixed(&mut hasher, info.filename.as_bytes());
    update_len_prefixed(&mut hasher, info.path.as_bytes());
    hasher.update(&info.size.to_le_bytes());
    hasher.update(&info.key);
    update_len_prefixed(&mut hasher, info.model_type.as_bytes());
    update_len_prefixed(&mut hasher, info.region.as_bytes());
    hasher.finalize()
}

fn write_at(file: &File, buf: &[u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::write_at(file, buf, offset)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::FileExt::seek_write(file, buf, offset)
    }
}

pub(crate) fn write_all_at(file: &File, mut buf: &[u8], mut offset: u64) -> io::Result<()> {
    while !buf.is_empty() {
        match write_at(file, buf, offset) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write whole buffer",
                ));
            }
            Ok(n) => {
                buf = &buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(windows)]
fn set_sparse(file: &File, sparse: bool) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::{FILE_SET_SPARSE_BUFFER, FSCTL_SET_SPARSE};

    let buf = FILE_SET_SPARSE_BUFFER { SetSparse: sparse };
    let mut returned = 0_u32;
    // Best-effort: avoids NTFS synchronously zero-filling up to `target_size` on
    // initial footer creation; ignored on filesystems without sparse support.
    //
    // SAFETY: `file` owns a valid open `HANDLE` for the duration of the call,
    // and `buf` / `returned` outlive the synchronous `DeviceIoControl` call.
    unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_SET_SPARSE,
            (&raw const buf).cast(),
            size_of::<FILE_SET_SPARSE_BUFFER>() as u32,
            std::ptr::null_mut(),
            0,
            &raw mut returned,
            std::ptr::null_mut(),
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PartState {
    Fresh,
    Resumed,
    Restarted,
}

pub(crate) fn prepare_part_file(
    final_path: &Path,
    expected_checksum: [u8; 16],
    target_size: u64,
    force: bool,
) -> io::Result<(File, PathBuf, Footer, PartState)> {
    let part_path = {
        let mut s = final_path.as_os_str().to_owned();
        s.push(".part");
        PathBuf::from(s)
    };

    if let Some(parent) = final_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }

    if force {
        let _ = std::fs::remove_file(final_path);
        let _ = std::fs::remove_file(&part_path);
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(force)
        .open(&part_path)?;

    let existing_len = file.seek(SeekFrom::End(0))?;
    if !force
        && existing_len > 0
        && let Some(footer) = Footer::read_from_part(&mut file, expected_checksum, target_size)
    {
        #[cfg(windows)]
        set_sparse(&file, true);

        let state = if footer.offset > 0 {
            PartState::Resumed
        } else {
            PartState::Fresh
        };
        return Ok((file, part_path, footer, state));
    }

    let state = if !force && existing_len > 0 {
        file.set_len(0)?;
        PartState::Restarted
    } else {
        PartState::Fresh
    };

    #[cfg(windows)]
    set_sparse(&file, true);

    let footer = Footer::new(expected_checksum);
    let mut footer_buf = [0u8; FOOTER_SIZE];
    footer.write_to_slice(&mut footer_buf);
    write_all_at(&file, &footer_buf, target_size)?;
    file.sync_data()?;

    Ok((file, part_path, footer, state))
}

pub(crate) fn finalize_part_file(
    file: File,
    part_path: &Path,
    final_path: &Path,
    final_size: u64,
) -> io::Result<()> {
    file.set_len(final_size)?;
    #[cfg(windows)]
    set_sparse(&file, false);
    file.sync_data()?;
    drop(file);

    if final_path.exists() {
        let _ = std::fs::remove_file(final_path);
    }
    std::fs::rename(part_path, final_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_info() -> BinaryInform {
        BinaryInform {
            version: "S931U1UES1AXB2/S931U1OYM1AXB2/S931U1UES1AXB2/S931U1UES1AXB2".to_string(),
            filename: "SM-S931U1_1_20240215120000_abcdefghij_fac.zip.enc4".to_string(),
            path: "T1/SM-S931U1/XAA/".to_string(),
            size: 10_000_000,
            key: [0x42; 16],
            model_type: "SM-S931U1".to_string(),
            region: "XAA".to_string(),
        }
    }

    fn read_part(target_size: u64, footer_bytes: &[u8], checksum: [u8; 16]) -> Option<Footer> {
        let mut part = vec![0u8; target_size as usize];
        part.extend_from_slice(footer_bytes);
        Footer::read_from_part(&mut Cursor::new(part), checksum, target_size)
    }

    #[test]
    fn test_footer_v4_round_trip_and_rejection() {
        let info = mock_info();
        let checksum = raw_checksum(&info);
        let target_size = 4096_u64;

        let mut footer = Footer::new(checksum);
        footer.offset = 3072;

        let mut buf = [0u8; FOOTER_SIZE];
        footer.write_to_slice(&mut buf);
        assert_eq!(buf.len(), 36);

        let parsed = read_part(target_size, &buf, checksum).unwrap();
        assert_eq!(parsed.offset, 3072);

        // Truncated / overlong part files must be rejected
        assert!(read_part(target_size, &buf[..FOOTER_SIZE - 1], checksum).is_none());
        let mut overlong = buf.to_vec();
        overlong.push(0);
        assert!(read_part(target_size, &overlong, checksum).is_none());

        // Corrupt magic (0), version (8), and checksum (12)
        for &(off, val) in &[(0, 0xFF), (8, 0x03), (12, 0xFF)] {
            let mut tampered = buf;
            tampered[off] = val;
            assert!(
                read_part(target_size, &tampered, checksum).is_none(),
                "offset={off}"
            );
        }

        // Checksum mismatch
        let mut other = mock_info();
        other.version.push('X');
        assert!(read_part(target_size, &buf, raw_checksum(&other)).is_none());

        // Bounds failure: offset > target_size
        let mut bad_offset = Footer::new(checksum);
        bad_offset.offset = target_size + 1;
        bad_offset.write_to_slice(&mut buf);
        assert!(read_part(target_size, &buf, checksum).is_none());
    }
}
