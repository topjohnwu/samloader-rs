// Copyright 2026 John "topjohnwu" Wu
// Copyright 2021-2024 Henrik Grimler
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

use super::*;
use crate::OdinError;
use crate::test_util::{
    A14M_PIT, M3_PIT, Q7MQ_PIT, ab_pit_data, build_tar, find_entry, lz4_compress,
    lz4_compress_with, mock_session,
};
use crate::usb::{MockBackend, MockEvent};

impl<P: AsyncRead + AsyncSeek + Unpin, I: AsyncRead + AsyncSeek + Unpin> FlashRequest<P, I> {
    /// Prepares and executes the flash.
    async fn run(self, session: &mut OdinSession) -> Result<(), FlashError> {
        self.prepare().await?.execute(session).await
    }
}

#[test]
fn test_flash_partitions_super_size_preflight() {
    let run = |protocol_version: u32, fail_check: bool| {
        futures::executor::block_on(async {
            let mut backend = MockBackend::new().with_protocol_version(protocol_version);
            if fail_check {
                backend = backend.with_fail_check_super_size(-1);
            }
            let mut session = mock_session(backend).await;

            let mut prepared = FlashRequest::new().prepare().await.unwrap();
            prepared.has_download_list = true;
            prepared
                .flash(&mut session, FlashPlan::default(), Some(27276104))
                .await
        })
    };

    assert!(run(3, false).is_ok());
    assert!(matches!(
        run(3, true),
        Err(FlashError::SuperSizeCheckFailed(_))
    ));
    // Legacy protocol version 2 must skip opcode 0x6a, so a failing check is never sent
    assert!(run(2, true).is_ok());
}

fn skipped_names(targets: &[&str]) -> Result<Vec<String>, FlashError> {
    let pit_data = ab_pit_data();
    let request = FlashRequest::new().skip(targets);
    let skipped_ids = request.options.skipped_partition_ids(&pit_data)?;
    let mut names: Vec<String> = pit_data
        .entries
        .iter()
        .filter(|e| skipped_ids.contains(&e.partition_id))
        .map(|e| e.partition_name.to_string_lossy().into_owned())
        .collect();
    names.sort();
    Ok(names)
}

#[test]
fn test_skip_partition_name_covers_ab_slots() {
    assert_eq!(skipped_names(&["BOOT"]).unwrap(), ["BOOT_A", "BOOT_B"]);
    assert_eq!(
        skipped_names(&["vbmeta"]).unwrap(),
        ["VBMETA_A", "VBMETA_B"]
    );
    assert_eq!(skipped_names(&["boot_b"]).unwrap(), ["BOOT_B"]);
    assert_eq!(skipped_names(&["SUPER"]).unwrap(), ["SUPER"]);
}

#[test]
fn test_skip_file_name_covers_all_matching_partitions() {
    assert_eq!(skipped_names(&["boot.img"]).unwrap(), ["BOOT_A", "BOOT_B"]);
    assert_eq!(
        skipped_names(&["AP/vbmeta.img.lz4"]).unwrap(),
        ["VBMETA_A", "VBMETA_B"]
    );
    assert_eq!(
        skipped_names(&["init_boot.img", "DTBO", " "]).unwrap(),
        ["DTBO_A", "DTBO_B", "INIT_BOOT_A", "INIT_BOOT_B"]
    );
}

#[test]
fn test_skip_unknown_target_fails() {
    assert!(matches!(
        skipped_names(&["BOOT", "nonexistent.img"]),
        Err(FlashError::SkipTargetNotFound(t)) if t == "nonexistent.img"
    ));
}

#[test]
fn test_resolve_drops_skipped_partitions() {
    let partitions = vec![
        (None, "boot.img", Cursor::new(&b"DUMMY IMAGE DATA"[..])),
        (None, "vbmeta.img", Cursor::new(&b"DUMMY IMAGE DATA"[..])),
        (None, "dtbo.img", Cursor::new(&b"DUMMY IMAGE DATA"[..])),
        (
            Some("VBMETA_B".to_string()),
            "vbmeta.img",
            Cursor::new(&b"DUMMY IMAGE DATA"[..]),
        ),
    ];

    futures::executor::block_on(async {
        let pit_data = ab_pit_data();
        let mut prepared = FlashRequest::new()
            .partitions(partitions)
            .skip(&["boot.img", "VBMETA"])
            .prepare()
            .await
            .unwrap();
        let plan = prepared.resolve(&pit_data, true).await.unwrap();

        let names: Vec<String> = plan
            .payloads
            .iter()
            .map(|p| p.pit_entry.partition_name.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["DTBO_A"]);
    });
}

#[test]
fn test_execute_skipping_super_skips_super_size_check() {
    let tar_bytes = build_tar(&[
        ("meta-data/super_used_size.txt", b"27276104\n"),
        ("meta-data/download-list.txt", b"boot.img\nsuper.img\n"),
        ("boot.img", b"DUMMY BOOT IMAGE DATA"),
        ("super.img", b"DUMMY SUPER IMAGE DATA"),
    ]);

    let run = |skip: &[&str]| {
        futures::executor::block_on(async {
            let mut session = mock_session(
                MockBackend::with_profile(crate::usb::DeviceProfile::sm_f968b())
                    .with_protocol_version(3)
                    .with_fail_check_super_size(-1),
            )
            .await;
            FlashRequest::new()
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                .skip(skip)
                .run(&mut session)
                .await
        })
    };

    assert!(matches!(run(&[]), Err(FlashError::SuperSizeCheckFailed(_))));
    assert!(run(&["super.img"]).is_ok());
}

#[test]
fn test_execute_super_size_check_with_ddp_and_non_ddp_super_images() {
    let non_ddp_super = crate::firmware::lp::tests::build_test_raw_image(0);
    let ddp_super = crate::firmware::lp::tests::build_test_raw_image(26_779_384);

    // The device rejects the super size check, so a flash only succeeds without it
    let run = |packages: &[(&str, &[u8])], partitions: &[(&str, &[u8])]| {
        let tar_bytes = build_tar(packages);
        futures::executor::block_on(async {
            let mut session = mock_session(
                MockBackend::new()
                    .with_protocol_version(3)
                    .with_fail_check_super_size(-1),
            )
            .await;
            let packages = (!packages.is_empty()).then(|| ("AP.tar", Cursor::new(&tar_bytes[..])));
            FlashRequest::new()
                .packages(packages)
                .partitions(
                    partitions.iter().map(|&(name, data)| {
                        (Some(name.to_string()), "super.img", Cursor::new(data))
                    }),
                )
                .run(&mut session)
                .await
        })
    };

    // Package without super_used_size.txt never inspects its super.img, even if the
    // image itself has a DDP header
    assert!(run(&[("super.img", &non_ddp_super)], &[]).is_ok());
    assert!(run(&[("super.img", &ddp_super)], &[]).is_ok());

    // Standalone non-DDP super.img (offset 0x400 == 0, e.g. SM-P610) sends no 0x6a check
    assert!(run(&[], &[("SUPER", &non_ddp_super)]).is_ok());

    // Package with super_used_size.txt or standalone DDP super.img (offset 0x400 > 0) sends 0x6a
    let res = run(
        &[
            ("meta-data/super_used_size.txt", b"26779384\n"),
            ("super.img", &non_ddp_super),
        ],
        &[],
    );
    assert!(matches!(res, Err(FlashError::SuperSizeCheckFailed(_))));

    let res = run(&[], &[("SUPER", &ddp_super)]);
    assert!(matches!(res, Err(FlashError::SuperSizeCheckFailed(_))));
}

fn rewrite_vbmeta(
    pit_data: &PitData,
    partitions: Vec<Cursor<Vec<u8>>>,
    planned: &mut [FirmwarePartitionPayload<'_>],
    verity: bool,
    verification: bool,
) -> Result<(), FlashError> {
    futures::executor::block_on(async {
        let mut prepared = FlashRequest::new()
            .partitions(partitions.into_iter().map(|r| (None, "part", r)))
            .disable_verity(verity)
            .disable_verification(verification)
            .prepare()
            .await
            .unwrap();
        prepared
            .rewrite_vbmeta_payloads(pit_data, planned, true)
            .await
    })
}

fn planned_bytes(
    planned: &FirmwarePartitionPayload<'_>,
    partitions: &[Cursor<Vec<u8>>],
) -> Vec<u8> {
    assert!(planned.image.lz4_header.is_none());
    match &planned.image.source {
        ImageSource::Memory(data) => data.clone(),
        ImageSource::Image { index, .. } => partitions[*index].get_ref().clone(),
        ImageSource::Package { .. } => unreachable!(),
    }
}

#[test]
fn test_rewrite_vbmeta_payloads_patches_all_vbmeta() {
    use crate::firmware::avb::tests::{vbmeta_flags, vbmeta_image};

    let pit_data = ab_pit_data();
    let image = vbmeta_image(0);
    let size = image.len() as u64;
    let (lz4_bytes, header) = lz4_compress(&image);
    let lz4_size = lz4_bytes.len() as u64;
    let backing = || {
        vec![
            Cursor::new(image.clone()),
            Cursor::new(lz4_bytes.clone()),
            Cursor::new(image.clone()),
            Cursor::new(image.clone()),
        ]
    };
    let mut planned = vec![
        FirmwarePartitionPayload {
            pit_entry: find_entry(&pit_data, "VBMETA_A"),
            image: FirmwareImage {
                source: ImageSource::Image { index: 0, size },
                lz4_header: None,
            },
        },
        FirmwarePartitionPayload {
            pit_entry: find_entry(&pit_data, "VBMETA_B"),
            image: FirmwareImage {
                source: ImageSource::Image {
                    index: 1,
                    size: lz4_size,
                },
                lz4_header: Some(header),
            },
        },
        FirmwarePartitionPayload {
            pit_entry: find_entry(&pit_data, "VBMETA_SYSTEM_A"),
            image: FirmwareImage {
                source: ImageSource::Image { index: 2, size },
                lz4_header: None,
            },
        },
        FirmwarePartitionPayload {
            pit_entry: find_entry(&pit_data, "BOOT_A"),
            image: FirmwareImage {
                source: ImageSource::Image { index: 3, size },
                lz4_header: None,
            },
        },
    ];

    rewrite_vbmeta(&pit_data, backing(), &mut planned, true, false).unwrap();
    assert_eq!(
        vbmeta_flags(&planned_bytes(&planned[0], &backing()), 0),
        0x1
    );
    assert_eq!(
        vbmeta_flags(&planned_bytes(&planned[1], &backing()), 0),
        0x1
    );

    // Rewriting again accumulates flags, and LZ4 passthrough stays disabled
    rewrite_vbmeta(&pit_data, backing(), &mut planned, false, true).unwrap();
    for p in &planned[..2] {
        let data = planned_bytes(p, &backing());
        assert_eq!(data.len(), image.len());
        assert_eq!(vbmeta_flags(&data, 0), 0x3);
    }

    // Like fastboot, only top-level vbmeta partitions are rewritten
    assert_eq!(planned_bytes(&planned[2], &backing()), image);
    assert_eq!(planned_bytes(&planned[3], &backing()), image);
}

#[test]
fn test_rewrite_vbmeta_payloads_boot_without_vbmeta_partition() {
    use crate::firmware::avb::tests::{boot_image, vbmeta_flags};

    // M3_EUR_OPEN_4G.pit has no vbmeta partition, so the vbmeta in boot's footer
    // is rewritten. A boot image without an AVB footer is rejected.
    let pit_data = PitData::new(M3_PIT).unwrap();

    let boot = boot_image(0x1000);

    let mut planned = vec![FirmwarePartitionPayload {
        pit_entry: find_entry(&pit_data, "BOOT"),
        image: FirmwareImage {
            source: ImageSource::Image {
                index: 0,
                size: boot.len() as u64,
            },
            lz4_header: None,
        },
    }];
    rewrite_vbmeta(&pit_data, vec![Cursor::new(boot)], &mut planned, true, true).unwrap();
    assert_eq!(vbmeta_flags(&planned_bytes(&planned[0], &[]), 0x1000), 0x3);

    let mut planned = vec![FirmwarePartitionPayload {
        pit_entry: find_entry(&pit_data, "BOOT"),
        image: FirmwareImage {
            source: ImageSource::Image {
                index: 0,
                size: 4096,
            },
            lz4_header: None,
        },
    }];
    assert!(matches!(
        rewrite_vbmeta(
            &pit_data,
            vec![Cursor::new(vec![0u8; 4096])],
            &mut planned,
            true,
            false,
        ),
        Err(FlashError::VbmetaRewriteFailed(_, _))
    ));
}

#[test]
fn test_execute_truncated_package_fails_before_device() {
    let tar_bytes = build_tar(&[("boot.img", &[0xABu8; 1024])]);
    let truncated = &tar_bytes[..600];

    futures::executor::block_on(async {
        let backend = MockBackend::new();
        let events = backend.event_log();
        let mut session = mock_session(backend).await;

        let res = FlashRequest::new()
            .erase(true)
            .packages([("AP.tar", Cursor::new(truncated))])
            .run(&mut session)
            .await;

        assert!(matches!(res, Err(FlashError::ArchiveCorrupted(pkg, _)) if pkg == "AP.tar"));
        let logged = events.lock().unwrap();
        assert!(
            !logged.contains(&MockEvent::NandErase)
                && !logged.contains(&MockEvent::PitFlash)
                && !logged.iter().any(|e| matches!(e, MockEvent::Slice { .. })),
            "no destructive operations should have occurred, got: {:?}",
            *logged
        );
    });
}

#[test]
fn test_execute_invalid_vbmeta_does_not_flash_pit() {
    let tar_bytes = build_tar(&[("vbmeta.img", &[0xFFu8; 512])]);

    futures::executor::block_on(async {
        let backend = MockBackend::new();
        let events = backend.event_log();
        let mut session = mock_session(backend).await;

        let res = FlashRequest::new()
            .pit(Q7MQ_PIT)
            .erase(true)
            .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
            .disable_verity(true)
            .run(&mut session)
            .await;

        assert!(matches!(res, Err(FlashError::VbmetaRewriteFailed(name, _)) if name == "VBMETA_A"));
        let logged = events.lock().unwrap();
        assert!(
            !logged.contains(&MockEvent::PitFlash) && !logged.contains(&MockEvent::NandErase),
            "PitFlash/NandErase should not have occurred, got: {:?}",
            *logged
        );
    });
}

#[test]
fn test_execute_matches_partition_names_ignoring_case() {
    // The Galaxy A14 4G (MediaTek) uses lowercase partition names
    let pit_data = PitData::new(A14M_PIT).unwrap();
    let init_boot_id = find_entry(&pit_data, "init_boot").partition_id;

    for name in ["init_boot", "INIT_BOOT"] {
        futures::executor::block_on(async {
            let backend = MockBackend::new();
            let events = backend.event_log();
            let mut session = mock_session(backend).await;

            let image = b"INIT BOOT IMAGE DATA";
            FlashRequest::new()
                .pit(A14M_PIT)
                .partitions([(
                    Some(name.to_string()),
                    "init_boot.img",
                    Cursor::new(&image[..]),
                )])
                .run(&mut session)
                .await
                .unwrap();

            let logged = events.lock().unwrap();
            let flashed: Vec<_> = logged
                .iter()
                .filter_map(|e| match e {
                    MockEvent::Slice {
                        partition_id, data, ..
                    } => Some((*partition_id, data.as_slice())),
                    _ => None,
                })
                .collect();
            assert_eq!(flashed, [(init_boot_id, &image[..])], "{name}");
        });
    }
}

#[test]
fn test_execute_vbmeta_payload_flags() {
    let raw_vbmeta = crate::firmware::avb::tests::vbmeta_image(0);
    let (vbmeta_lz4, _) = lz4_compress(&raw_vbmeta);

    // Flashes `vbmeta` and returns whether its slice was sent as LZ4, and its data
    let flash = |name: &str, vbmeta: &[u8], disable: bool| {
        let tar_bytes = build_tar(&[(name, vbmeta)]);
        futures::executor::block_on(async {
            let backend = MockBackend::with_profile(crate::usb::DeviceProfile::sm_f968b());
            let events = backend.event_log();
            let mut session = mock_session(backend).await;

            FlashRequest::new()
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                .disable_verity(disable)
                .disable_verification(disable)
                .run(&mut session)
                .await
                .unwrap();

            let logged = events.lock().unwrap();
            logged
                .iter()
                .find_map(|e| match e {
                    MockEvent::Slice { lz4, data, .. } => Some((*lz4, data.clone())),
                    _ => None,
                })
                .expect("vbmeta slice")
        })
    };

    // 1. With --disable-verity and --disable-verification: sent raw, byte 123 is 0x03
    let (lz4, data) = flash("vbmeta.img.lz4", &vbmeta_lz4, true);
    assert!(!lz4, "rewritten vbmeta must be sent raw (uncompressed)");
    // Only the flags field (big endian u32 at offset 120) changes
    let mut expected = raw_vbmeta.clone();
    expected[123] = 0x03;
    assert_eq!(data, expected);

    // 2. Without flags on raw input: payload matches input exactly
    assert_eq!(flash("vbmeta.img", &raw_vbmeta, false), (false, raw_vbmeta));

    // 3. Without flags on LZ4 input: lz4 passthrough is preserved
    let (lz4, data) = flash("vbmeta.img.lz4", &vbmeta_lz4, false);
    assert!(lz4, "unmodified vbmeta must preserve LZ4 passthrough");
    // Passthrough sends the LZ4 blocks between the 15 byte frame header and the EndMark
    assert_eq!(data, &vbmeta_lz4[15..vbmeta_lz4.len() - 4]);

    // 4. Without flags, the vbmeta is never parsed, so an invalid one is flashed as is
    let (invalid_lz4, _) = lz4_compress(&[0u8; 4096]);
    let (lz4, _) = flash("vbmeta.img.lz4", &invalid_lz4, false);
    assert!(lz4);
}

#[test]
fn test_execute_decompresses_lz4_the_device_cannot_take() {
    use crate::usb::DeviceProfile;
    use lz4_flex::frame::BlockSize;

    // Spans several 64 KiB blocks
    let image: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let (lz4_1mb, _) = lz4_compress(&image);
    let (lz4_64kb, _) = lz4_compress_with(&image, BlockSize::Max64KB);

    let flash = |profile: DeviceProfile, lz4_image: &[u8]| {
        let tar_bytes = build_tar(&[("boot.img.lz4", lz4_image)]);
        futures::executor::block_on(async {
            let backend = MockBackend::with_profile(profile);
            let events = backend.event_log();
            let mut session = mock_session(backend).await;

            FlashRequest::new()
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                .run(&mut session)
                .await
                .unwrap();

            let logged = events.lock().unwrap().clone();
            let slices: Vec<_> = logged
                .into_iter()
                .filter_map(|e| match e {
                    MockEvent::Slice { lz4, data, .. } => Some((lz4, data)),
                    _ => None,
                })
                .collect();
            assert!(!slices.is_empty());
            assert!(slices.iter().all(|(lz4, _)| !lz4), "slices must be raw");
            slices
                .into_iter()
                .flat_map(|(_, data)| data)
                .collect::<Vec<u8>>()
        })
    };

    // A device without LZ4 support
    assert_eq!(flash(DeviceProfile::gt_i9305(), &lz4_1mb), image);
    // An LZ4 capable device given blocks other than 1 MiB
    assert_eq!(flash(DeviceProfile::sm_f968b(), &lz4_64kb), image);
}

#[test]
fn test_execute_reports_read_errors_while_sending() {
    use crate::usb::DeviceProfile;

    // The frame header is intact, so prepare succeeds, but the blocks are cut
    // short, so decompressing fails while the partition is being sent
    let image: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let (lz4_image, _) = lz4_compress(&image);
    let tar_bytes = build_tar(&[("boot.img.lz4", &lz4_image[..lz4_image.len() / 2])]);

    let res = futures::executor::block_on(async {
        let mut session = mock_session(MockBackend::with_profile(DeviceProfile::gt_i9305())).await;
        FlashRequest::new()
            .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
            .run(&mut session)
            .await
    });
    assert!(matches!(res, Err(FlashError::FileReadFailed(name, _)) if name == "boot.img.lz4"));
}

#[test]
fn test_execute_with_local_pit_reports_once() {
    #[derive(Clone, Default)]
    struct Collector(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    impl crate::FlashProgress for Collector {
        fn println(&self, msg: &str) {
            self.0.lock().unwrap().push(msg.to_string());
        }
    }

    let _guard = crate::progress::TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let tar_bytes = build_tar(&[
        ("boot.img", b"DUMMY BOOT IMAGE DATA"),
        ("dtbo.img", b"DUMMY DTBO IMAGE DATA"),
    ]);

    let collector = Collector::default();
    crate::progress::set_progress(collector.clone());
    let res = futures::executor::block_on(async {
        let mut session = mock_session(MockBackend::new()).await;

        // The plan is checked against the local PIT and then rebuilt against the
        // flashed PIT, but informational messages must only be printed once
        FlashRequest::new()
            .pit(Q7MQ_PIT)
            .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
            .skip(&["DTBO"])
            .run(&mut session)
            .await
    });
    crate::progress::clear_progress();
    res.unwrap();

    let messages = collector.0.lock().unwrap();
    let count = messages
        .iter()
        .filter(|m| m.as_str() == "Skipping DTBO_A (excluded with --skip)")
        .count();
    assert_eq!(count, 1, "messages: {:?}", *messages);
}

/// Summarizes the images of a prepared flash for comparisons.
fn image_summary<P, I>(
    prepared: &PreparedFlash<P, I>,
) -> Vec<(String, u64, Option<u64>, Option<u32>)> {
    prepared
        .images
        .iter()
        .map(|planned| {
            (
                format!("{:?}", planned.target),
                planned.image.size(),
                planned.image.lz4_header.as_ref().map(|h| h.content_size),
                planned.super_used_size,
            )
        })
        .collect()
}

#[test]
fn test_prepare_is_deterministic_without_device() {
    let (vendor_lz4, _) = lz4_compress(&[0xAB; 4096]);
    let tar_bytes = build_tar(&[("boot.img", b"BOOT"), ("vendor.img.lz4", &vendor_lz4)]);

    let prepare = || {
        futures::executor::block_on(
            FlashRequest::new()
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                .partitions([
                    (Some("12".to_string()), "a.img", Cursor::new(&b"A"[..])),
                    (Some("BOOT".to_string()), "b.img", Cursor::new(&b"BB"[..])),
                ])
                // Skip targets are only resolved against a PIT during execution
                .skip(&["nonexistent"])
                .prepare(),
        )
        .unwrap()
    };

    let summary = image_summary(&prepare());
    assert_eq!(summary, image_summary(&prepare()));
    assert_eq!(
        summary,
        [
            ("File(\"boot.img\")".to_string(), 4, None, None),
            (
                "File(\"vendor.img\")".to_string(),
                vendor_lz4.len() as u64,
                Some(4096),
                None
            ),
            ("PartitionId(12)".to_string(), 1, None, None),
            ("Partition(\"BOOT\")".to_string(), 2, None, None),
        ]
    );
}

#[test]
fn test_prepare_rejects_corrupt_lz4_regardless_of_skip() {
    let tar_bytes = build_tar(&[("boot.img.lz4", &[0xFF; 64]), ("orphan.img.lz4", b"")]);
    let skips: [&[&str]; 3] = [&[], &["boot.img", "orphan.img"], &["BOOT"]];
    for skip in skips {
        let res = futures::executor::block_on(
            FlashRequest::new()
                .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
                .skip(skip)
                .prepare(),
        );
        assert!(matches!(res, Err(FlashError::Lz4Header(name, _)) if name == "boot.img.lz4"));
    }

    // A corrupt image is rejected even if it would be overridden by a later one
    let res = futures::executor::block_on(
        FlashRequest::new()
            .partitions([
                (None, "boot.img.lz4", Cursor::new(&[0xFFu8; 64][..])),
                (
                    Some("BOOT".to_string()),
                    "boot.img",
                    Cursor::new(&b"BOOT"[..]),
                ),
            ])
            .prepare(),
    );
    assert!(matches!(res, Err(FlashError::Lz4Header(name, _)) if name == "boot.img.lz4"));
}

#[test]
fn test_prepare_rejects_invalid_inputs() {
    let tar_bytes = build_tar(&[("boot.img", b"BOOT")]);
    let prepare = |request: FlashRequest<Cursor<&[u8]>>| {
        futures::executor::block_on(request.prepare()).map(|_| ())
    };

    let res = prepare(FlashRequest::new().sales_code(Some("TOOLONG")));
    assert!(
        matches!(res, Err(FlashError::Odin(OdinError::InvalidSalesCode(code))) if code == "TOOLONG")
    );

    let res = prepare(
        FlashRequest::new()
            .pit(&b"invalid"[..])
            .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))]),
    );
    assert!(matches!(res, Err(FlashError::PitUnpackFailed(_))));

    let pit_tar = build_tar(&[("boot.img", b"BOOT"), ("device.pit", b"invalid")]);
    let res = prepare(FlashRequest::new().packages([("CSC.tar", Cursor::new(pit_tar.as_slice()))]));
    assert!(matches!(res, Err(FlashError::PitUnpackFailed(_))));

    let _guard = crate::progress::TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut md5_tar = tar_bytes.clone();
    md5_tar.extend_from_slice(b"0123456789abcdef0123456789abcdef  AP.tar\n");
    let res =
        prepare(FlashRequest::new().packages([("AP.tar.md5", Cursor::new(md5_tar.as_slice()))]));
    assert!(matches!(res, Err(FlashError::Md5VerificationFailed(name, _)) if name == "AP.tar.md5"));
}

#[test]
fn test_prepare_inspects_super_images() {
    let super_img = crate::firmware::lp::tests::build_test_raw_image(6144);
    let expected = crate::firmware::lp::inspect_super_bytes(&super_img);
    assert_eq!(expected, Some(6144));

    let tar_bytes = build_tar(&[("super.img", &super_img)]);
    let prepared = futures::executor::block_on(
        FlashRequest::new()
            .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
            .partitions([
                (
                    Some("SUPER".to_string()),
                    "a.img",
                    Cursor::new(&super_img[..]),
                ),
                (Some("7".to_string()), "b.img", Cursor::new(&super_img[..])),
            ])
            .prepare(),
    )
    .unwrap();
    let sizes: Vec<_> = prepared.images.iter().map(|i| i.super_used_size).collect();
    // Package super.img is never inspected; partition IDs cannot be identified as super without a PIT
    assert_eq!(sizes, [None, expected, None]);

    // super_used_size.txt takes precedence over inspecting package images,
    // while standalone super images are still inspected to allow overrides
    let override_img = crate::firmware::lp::tests::build_test_raw_image(9999);
    let tar_bytes = build_tar(&[
        ("meta-data/super_used_size.txt", b"123\n"),
        ("super.img", &super_img),
    ]);
    let mut prepared = futures::executor::block_on(
        FlashRequest::new()
            .packages([("AP.tar", Cursor::new(tar_bytes.as_slice()))])
            .partitions([(
                Some("SUPER".to_string()),
                "override.img",
                Cursor::new(&override_img[..]),
            )])
            .prepare(),
    )
    .unwrap();
    assert_eq!(prepared.super_used_size, Some(123));
    assert_eq!(prepared.images[0].super_used_size, None);
    assert_eq!(prepared.images[1].super_used_size, Some(9999));

    let pit_data = ab_pit_data();
    let plan = futures::executor::block_on(prepared.resolve(&pit_data, true)).unwrap();
    assert_eq!(
        futures::executor::block_on(prepared.super_used_size(&plan)),
        Some(9999)
    );
}

#[test]
fn test_super_used_size_inspects_partition_id_targets() {
    let super_img = crate::firmware::lp::tests::build_test_raw_image(6144);
    let pit_data = ab_pit_data();
    let super_id = find_entry(&pit_data, "SUPER").partition_id;

    futures::executor::block_on(async {
        let mut prepared = FlashRequest::new()
            .partitions([(
                Some(super_id.to_string()),
                "super.img",
                Cursor::new(&super_img[..]),
            )])
            .prepare()
            .await
            .unwrap();
        assert_eq!(prepared.images[0].super_used_size, None);

        let plan = prepared.resolve(&pit_data, true).await.unwrap();
        assert_eq!(
            prepared.super_used_size(&plan).await,
            crate::firmware::lp::inspect_super_bytes(&super_img)
        );
    });
}

#[test]
fn test_prepared_flash_flashes_userdata() {
    let tar_bytes = build_tar(&[("boot.img", b"BOOT"), ("AP/userdata.img", b"DATA")]);
    let listed_tar = build_tar(&[
        ("meta-data/download-list.txt", b"boot.img\n"),
        ("boot.img", b"BOOT"),
        ("userdata.img", b"DATA"),
    ]);
    let boot_tar = build_tar(&[("boot.img", b"BOOT")]);
    let (userdata_lz4, _) = lz4_compress(b"DATA");
    let lz4_tar = build_tar(&[("AP/userdata.img.lz4", &userdata_lz4)]);

    type Partitions<'a> = Vec<(Option<String>, &'a str, Cursor<&'a [u8]>)>;
    let flashes_userdata = |tar: &[u8], partitions: Partitions, skip: &[&str]| {
        futures::executor::block_on(
            FlashRequest::new()
                .packages([("AP.tar", Cursor::new(tar))])
                .partitions(partitions)
                .skip(skip)
                .prepare(),
        )
        .unwrap()
        .flashes_userdata()
    };
    let data = || Cursor::new(&b"DATA"[..]);

    assert!(flashes_userdata(&tar_bytes, vec![], &[]));
    assert!(!flashes_userdata(&tar_bytes, vec![], &["userdata"]));
    assert!(!flashes_userdata(&tar_bytes, vec![], &[" USERDATA "]));
    assert!(!flashes_userdata(
        &tar_bytes,
        vec![],
        &["out/userdata.img.lz4"]
    ));
    assert!(flashes_userdata(&tar_bytes, vec![], &["boot", "super.img"]));
    assert!(flashes_userdata(&lz4_tar, vec![], &[]));
    assert!(!flashes_userdata(&lz4_tar, vec![], &["userdata.img"]));
    assert!(!flashes_userdata(&listed_tar, vec![], &[]));
    assert!(!flashes_userdata(&boot_tar, vec![], &[]));
    assert!(flashes_userdata(
        &boot_tar,
        vec![(None, "userdata.img", data())],
        &[]
    ));
    assert!(flashes_userdata(
        &boot_tar,
        vec![(Some("USERDATA".to_string()), "data.img", data())],
        &[]
    ));
    assert!(!flashes_userdata(
        &boot_tar,
        vec![(Some("USERDATA".to_string()), "data.img", data())],
        &["userdata"]
    ));
    // Partition IDs cannot be resolved without a PIT
    assert!(!flashes_userdata(
        &boot_tar,
        vec![(Some("42".to_string()), "userdata.img", data())],
        &[]
    ));
}

#[test]
fn test_resolve_last_writer_wins() {
    let bl_tar = build_tar(&[("boot.img", b"FIRST")]);
    let ap_tar = build_tar(&[("boot.img", b"SECOND")]);
    let pit_data = ab_pit_data();
    let boot_name = pit_data
        .find_entry_by_flash_filename("boot.img")
        .unwrap()
        .partition_name
        .to_string_lossy()
        .into_owned();

    futures::executor::block_on(async {
        let packages = || {
            [
                ("BL.tar", Cursor::new(bl_tar.as_slice())),
                ("AP.tar", Cursor::new(ap_tar.as_slice())),
            ]
        };

        let mut prepared = FlashRequest::new()
            .packages(packages())
            .prepare()
            .await
            .unwrap();
        let plan = prepared.resolve(&pit_data, true).await.unwrap();
        assert_eq!(plan.payloads.len(), 1);
        assert!(matches!(
            plan.payloads[0].image.source,
            ImageSource::Package { index: 1, .. }
        ));

        // Explicit partitions come after packages, so they win
        let mut prepared = FlashRequest::new()
            .packages(packages())
            .partitions([(
                Some(boot_name.clone()),
                "my_boot.img",
                Cursor::new(&b"MINE"[..]),
            )])
            .prepare()
            .await
            .unwrap();
        let plan = prepared.resolve(&pit_data, true).await.unwrap();
        assert_eq!(plan.payloads.len(), 1);
        assert!(matches!(
            plan.payloads[0].image.source,
            ImageSource::Image { index: 0, .. }
        ));
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn test_phase_futures_are_send() {
    fn assert_send<T: Send>(_: &T) {}

    let prepare = FlashRequest::new()
        .packages([("AP.tar", Cursor::new(&b""[..]))])
        .prepare();
    assert_send(&prepare);
    let _ = |prepared: PreparedFlash, session: &mut OdinSession| {
        assert_send(&prepared.execute(session));
    };
}

#[test]
fn test_execute_operation_order() {
    let tar_bytes = build_tar(&[("boot.img", b"DUMMY BOOT IMAGE DATA")]);
    let csc = || MockEvent::SalesCode("XAA".to_string());

    let run = |pit: Option<&[u8]>, packages: bool, skip: &[&str]| {
        futures::executor::block_on(async {
            let backend = MockBackend::new();
            let events = backend.event_log();
            let mut session = mock_session(backend).await;

            let mut request = FlashRequest::new()
                .sales_code(Some("XAA"))
                .erase(true)
                .skip(skip);
            if let Some(pit) = pit {
                request = request.pit(pit);
            }
            let packages = packages.then(|| ("AP.tar", Cursor::new(tar_bytes.as_slice())));
            let res = request.packages(packages).run(&mut session).await;
            let logged = events.lock().unwrap().clone();
            (res, logged)
        })
    };

    // Without a local PIT: the sales code is set after the device PIT is read and resolved
    let (res, logged) = run(None, true, &[]);
    assert!(res.is_ok());
    assert_eq!(
        logged[..3],
        [MockEvent::PitDump, csc(), MockEvent::NandErase]
    );
    assert!(matches!(logged[3], MockEvent::Slice { .. }));

    // With a local PIT: the sales code is set after the dry run, before anything is written
    let (res, logged) = run(Some(Q7MQ_PIT), true, &[]);
    assert!(res.is_ok());
    assert_eq!(
        logged[..4],
        [
            csc(),
            MockEvent::NandErase,
            MockEvent::PitFlash,
            MockEvent::PitDump
        ]
    );
    assert!(matches!(logged[4], MockEvent::Slice { .. }));

    // Nothing to flash: the sales code is set first
    let (res, logged) = run(None, false, &[]);
    assert!(res.is_ok());
    assert_eq!(logged, [csc(), MockEvent::NandErase, MockEvent::EndSession]);

    // Resolving fails: neither the sales code is set nor the device erased
    let (res, logged) = run(None, true, &["nonexistent"]);
    assert!(matches!(res, Err(FlashError::SkipTargetNotFound(t)) if t == "nonexistent"));
    assert_eq!(logged, [MockEvent::PitDump]);
}

#[test]
fn test_execute_ends_session_before_rebooting() {
    let tar_bytes = build_tar(&[("boot.img", b"DUMMY BOOT IMAGE DATA")]);

    let run = |packages: bool, reboot_mode: RebootMode| {
        futures::executor::block_on(async {
            let backend = MockBackend::new();
            let events = backend.event_log();
            let mut session = mock_session(backend).await;

            let packages = packages.then(|| ("AP.tar", Cursor::new(tar_bytes.as_slice())));
            let res = FlashRequest::new()
                .sales_code(Some("XAA"))
                .reboot_mode(reboot_mode)
                .packages(packages)
                .run(&mut session)
                .await;
            assert!(res.is_ok());
            let logged = events.lock().unwrap().clone();
            logged[logged.len().saturating_sub(2)..].to_vec()
        })
    };

    // Both the settings-only path and a full flash end the session first
    for packages in [false, true] {
        assert_eq!(
            run(packages, RebootMode::Normal),
            [MockEvent::EndSession, MockEvent::Reboot]
        );
        assert_eq!(
            run(packages, RebootMode::Download),
            [MockEvent::EndSession, MockEvent::RebootToDownload]
        );
        assert_eq!(
            run(packages, RebootMode::None).last(),
            Some(&MockEvent::EndSession)
        );
    }
}
