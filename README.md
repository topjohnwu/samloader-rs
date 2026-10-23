# samloader

An all-in-one Samsung firmware download and flash tool.

```
Usage: samloader [OPTIONS] <COMMAND>

Commands:
  download         Download firmware
  check-update     Check available versions
  detect           Indicates whether or not a download mode device can be detected
  dump-pit         Dumps the connected device's PIT file to the specified output file
  print-pit        Prints the contents of a PIT file in a human readable format
  flash            Flashes one or more firmware files to your phone
  verify-md5       Verifies the MD5 checksum of one or more .tar.md5 files
  reboot-download  Boot a connected Samsung device into download mode
  fix-usb          Add udev rules to fix USB device access permissions on Linux
  help             Print this message or the help of the given subcommand(s)

Options:
      --verbose                    Enable verbose output
      --usb-backend <usb_backend>  The USB backend to use [default: nusb] [possible values: nusb, vcom]
  -h, --help                       Print help
  -V, --version                    Print version
```

## Features

- Combines both firmware downloading and flashing into a single utility.
- Downloads firmware using multiple parallel connections (default: 8) to bypass server-side connection speed throttling and maximize bandwidth usage.
- Decrypts firmware files on-the-fly, eliminating separate download and decryption steps.
- Supports flashing raw images and official package files across Linux, macOS, and Windows.
- Processes and extracts official TAR firmware packages in-memory, avoiding slow disk write operations.
- Transmits raw LZ4-compressed data directly to supported devices to reduce USB transfer size and time.
- Provides an offline, PIT-aware preflight for repartitioning and firmware size checks.

## Safer repartition flashing

Changing a device's PIT rewrites its partition layout and can destroy user data. Validate the
complete firmware set against the firmware's PIT before connecting a phone:

```bash
samloader flash --check-only --pit layout.pit \
  --AP AP.tar.md5 --CP CP.tar.md5 --CSC CSC.tar.md5
```

The offline check verifies package MD5 footers, requires an explicit PIT to match any PIT embedded
in the selected packages, applies package precedence, and compares each image's logical size with
its target partition. For Android sparse images this means `block_size * total_blocks`, not the
compressed or sparse-stream file length. No USB backend is opened by `--check-only`.

After a successful check, a live flash with the same explicit PIT performs the full validation
before opening the Odin USB session and reuses the validated sizes while the bootloader waits:

```bash
samloader flash --pit layout.pit \
  --AP AP.tar.md5 --CP CP.tar.md5 --CSC CSC.tar.md5
```

Use the full CSC package when the firmware requires a new partition layout; a `HOME_CSC` package
may omit the PIT and the images needed for moved partitions. `--no-lz4` is available as a
compatibility fallback for devices that reject direct compressed transfer; it decompresses LZ4
images on the host. See [the repartitioning safety notes](docs/repartitioning.md) before using
either command.

## Install

If you have a working Rust toolchain installed, you can install with:

```bash
cargo install samloader
```

Prebuilt executables for Linux, macOS, and Windows are also available in the [latest GitHub release](https://github.com/topjohnwu/samloader-rs/releases/latest).

## License & Acknowledgements

This project is licensed under the **Apache License, Version 2.0**.

`samloader` is built on top of and inspired by several incredible open-source projects:

- **Heimdall (Firmware Flashing):**
  The core flashing functionality is a derivative work of [~grimler/Heimdall](https://git.sr.ht/~grimler/Heimdall). This implementation began as a precise 1-to-1 conversion of the original C++ project into safe and idiomatic Rust. The original code is licensed under the **MIT License** (preserved in this repository), and copyright headers are preserved in the relevant source files.

- **Firmware Downloading / FUS:**
  The firmware downloading and decryption implementation was inspired from multiple places, including [samloader](https://github.com/samloader/samloader), [samfirm.js](https://github.com/jesec/samfirm.js/), [Bifrost](https://github.com/zacharee/Bifrost), and [asgard](https://github.com/ducthoe/asgard).
