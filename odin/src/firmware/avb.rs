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

//! Rewriting of AVB vbmeta flags, mirroring fastboot's `--disable-verity` and
//! `--disable-verification`.
//!
//! See external/avb/libavb/avb_vbmeta_image.h and avb_footer.h for the layouts.

use std::io;

/// Bit 0 of the vbmeta flags, set by `--disable-verity`.
pub(crate) const AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED: u32 = 1 << 0;
/// Bit 1 of the vbmeta flags, set by `--disable-verification`.
pub(crate) const AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED: u32 = 1 << 1;

const AVB_MAGIC: &[u8] = b"AVB0";
const AVB_FOOTER_MAGIC: &[u8] = b"AVBf";
const AVB_FOOTER_SIZE: usize = 64;
const AVB_FOOTER_VBMETA_OFFSET: usize = 20;
const AVB_VBMETA_IMAGE_HEADER_SIZE: usize = 256;
// The 32-bit big endian |flags| field of the vbmeta header
const AVB_VBMETA_FLAGS_OFFSET: usize = 120;

fn invalid_data(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Sets `flags` in the vbmeta struct of `data`, returning the offset of the struct.
///
/// With `in_footer`, the struct is located through the AVB footer at the end of the
/// image (e.g. boot.img on devices without a vbmeta partition). Otherwise it must be
/// at the start of the image. Like fastboot, images smaller than a vbmeta header are
/// left unmodified and `None` is returned.
pub(crate) fn rewrite_vbmeta(
    data: &mut [u8],
    flags: u32,
    in_footer: bool,
) -> io::Result<Option<u64>> {
    if data.len() < AVB_VBMETA_IMAGE_HEADER_SIZE {
        return Ok(None);
    }

    let vbmeta_offset = if in_footer {
        let footer = &data[data.len() - AVB_FOOTER_SIZE..];
        if !footer.starts_with(AVB_FOOTER_MAGIC) {
            return Err(invalid_data(format!(
                "Failed to find AVB_FOOTER at offset: {}, is BOARD_AVB_ENABLE true?",
                data.len() - AVB_FOOTER_SIZE
            )));
        }
        let offset = &footer[AVB_FOOTER_VBMETA_OFFSET..AVB_FOOTER_VBMETA_OFFSET + 8];
        u64::from_be_bytes(offset.try_into().unwrap())
    } else {
        0
    };

    let header = usize::try_from(vbmeta_offset)
        .ok()
        .and_then(|start| data.get_mut(start..start.checked_add(AVB_VBMETA_IMAGE_HEADER_SIZE)?))
        .filter(|header| header.starts_with(AVB_MAGIC))
        .ok_or_else(|| {
            invalid_data(format!(
                "Failed to find AVB_MAGIC at offset: {}",
                vbmeta_offset
            ))
        })?;

    let field = &mut header[AVB_VBMETA_FLAGS_OFFSET..AVB_VBMETA_FLAGS_OFFSET + 4];
    let value = u32::from_be_bytes((&*field).try_into().unwrap()) | flags;
    field.copy_from_slice(&value.to_be_bytes());

    Ok(Some(vbmeta_offset))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn vbmeta_image(flags: u32) -> Vec<u8> {
        let mut data = vec![0u8; 4096];
        data[..4].copy_from_slice(AVB_MAGIC);
        data[AVB_VBMETA_FLAGS_OFFSET..AVB_VBMETA_FLAGS_OFFSET + 4]
            .copy_from_slice(&flags.to_be_bytes());
        data
    }

    pub(crate) fn vbmeta_flags(data: &[u8], vbmeta_offset: usize) -> u32 {
        let start = vbmeta_offset + AVB_VBMETA_FLAGS_OFFSET;
        u32::from_be_bytes(data[start..start + 4].try_into().unwrap())
    }

    /// Builds a boot image with its vbmeta at `vbmeta_offset`, located by an AVB footer.
    pub(crate) fn boot_image(vbmeta_offset: u64) -> Vec<u8> {
        let mut data = vec![0u8; 64 * 1024];
        let start = vbmeta_offset as usize;
        data[start..start + 4].copy_from_slice(AVB_MAGIC);
        let footer = data.len() - AVB_FOOTER_SIZE;
        data[footer..footer + 4].copy_from_slice(AVB_FOOTER_MAGIC);
        data[footer + AVB_FOOTER_VBMETA_OFFSET..footer + AVB_FOOTER_VBMETA_OFFSET + 8]
            .copy_from_slice(&vbmeta_offset.to_be_bytes());
        data
    }

    #[test]
    fn test_rewrite_vbmeta_sets_flags() {
        let mut data = vbmeta_image(0);
        let flags = AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED;
        assert_eq!(rewrite_vbmeta(&mut data, flags, false).unwrap(), Some(0));
        assert_eq!(vbmeta_flags(&data, 0), flags);

        let flags = AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED;
        assert_eq!(rewrite_vbmeta(&mut data, flags, false).unwrap(), Some(0));
        assert_eq!(vbmeta_flags(&data, 0), 0x3);

        // Only the flags field changes
        let mut expected = vbmeta_image(0x3);
        assert_eq!(data, expected);

        // Existing bits are preserved
        expected = vbmeta_image(0x8000_0000);
        rewrite_vbmeta(
            &mut expected,
            AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED,
            false,
        )
        .unwrap();
        assert_eq!(vbmeta_flags(&expected, 0), 0x8000_0001);
    }

    #[test]
    fn test_rewrite_vbmeta_in_footer() {
        let mut data = boot_image(0x2000);
        let flags =
            AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED | AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED;
        assert_eq!(
            rewrite_vbmeta(&mut data, flags, true).unwrap(),
            Some(0x2000)
        );
        assert_eq!(vbmeta_flags(&data, 0x2000), 0x3);
        assert_eq!(vbmeta_flags(&data, 0), 0);
    }

    #[test]
    fn test_rewrite_vbmeta_rejects_invalid_images() {
        // Missing AVB_MAGIC
        let mut data = vec![0u8; 4096];
        assert!(rewrite_vbmeta(&mut data, 1, false).is_err());

        // Missing AVB footer
        let mut data = vbmeta_image(0);
        assert!(rewrite_vbmeta(&mut data, 1, true).is_err());

        // Footer pointing past the end of the image
        let mut data = boot_image(0);
        let len = data.len() as u64;
        let footer = data.len() - AVB_FOOTER_SIZE;
        data[footer + AVB_FOOTER_VBMETA_OFFSET..footer + AVB_FOOTER_VBMETA_OFFSET + 8]
            .copy_from_slice(&(len - 16).to_be_bytes());
        assert!(rewrite_vbmeta(&mut data, 1, true).is_err());
        data[footer + AVB_FOOTER_VBMETA_OFFSET..footer + AVB_FOOTER_VBMETA_OFFSET + 8]
            .copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(rewrite_vbmeta(&mut data, 1, true).is_err());
    }

    #[test]
    fn test_rewrite_vbmeta_ignores_small_images() {
        let mut data = vec![0u8; AVB_VBMETA_IMAGE_HEADER_SIZE - 1];
        assert_eq!(rewrite_vbmeta(&mut data, 1, false).unwrap(), None);
        assert!(data.iter().all(|&b| b == 0));
    }
}
