# Repartitioning safety notes

An explicit PIT flash is destructive. It can move or resize partitions, invalidate the existing
filesystem layout, and require a factory reset. A file copy is not necessarily a complete backup
of application-private data, message databases, authenticator secrets, or passkeys.

## Validate the firmware layout offline

Run `flash --check-only --pit ...` with the exact packages intended for the live operation. The
preflight deliberately does not open a USB device. It verifies:

- package MD5 footers;
- Samsung download-list selection and archive precedence;
- byte equality between an explicit PIT and a PIT embedded in the selected packages;
- filename-to-partition mapping; and
- logical image size against partition capacity.

Android sparse images declare their logical size in the sparse header. The correct capacity check
is `block_size * total_blocks`; neither the LZ4 content length nor the sparse stream's file length
is a safe substitute. A truncated sparse header is an error, not a raw image.

The live explicit-PIT path performs this same expensive validation before opening USB. This order
matters: leaving a bootloader idle while the host verifies MD5s or decompresses multi-gigabyte
images can cause the next Odin command to fail after the PIT was already written.

## Field case that motivated these checks

A Galaxy Note10+ (`SM-N975U1`) recovery exposed a layout migration that was invisible when only
`HOME_CSC` was used. The device's old PIT provided a 300 MiB PRODUCT partition, while the firmware
image expanded to 2,000 MiB. The full CSC contained the corresponding 2,000 MiB PRODUCT PIT. Of 74
compared entries, 68 were unchanged; PRODUCT grew, later partitions shifted, and USERDATA moved by
about 1.66 GiB.

The bootloader rejected PRODUCT almost immediately because it could not fit. A subsequent AVB
footer error was a consequence of the incomplete partition, not proof that sparse `DONT_CARE`
chunks needed to be zero-filled. Repacking filtered archives and using `HOME_CSC` could not solve
the geometry mismatch.

Recovery used the original AP and CP packages, the full CSC, and its byte-identical explicit PIT.
Offline preflight confirmed all expanded images fit. The real operation completed with exit status
zero, ended the Odin session, issued the reboot command, and the device entered its boot sequence.
The already-matching bootloader package was omitted in that particular recovery to reduce risk;
that is a case-specific decision, not general flashing guidance.

## Compressed-transfer compatibility

The session reply advertises the Odin protocol version in its high 16 bits; bit 15 of that field
indicates direct LZ4-transfer support. `--no-lz4` overrides the advertisement and decompresses on
the host. It is useful as a conservative compatibility fallback, although it increases host work
and USB transfer volume.

Do not use `--skip-size-check`, `--skip-md5`, or NAND erase to work around a failed preflight.
Resolve the package/PIT mismatch first.
