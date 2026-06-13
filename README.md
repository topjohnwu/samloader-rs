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
  help             Print this message or the help of the given subcommand(s)

Options:
      --verbose                    Enable verbose output
      --usb-backend <usb_backend>  The USB backend to use [default: libusb] [possible values: libusb, vcom]
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

- **Firmware Downloading:**
  The firmware downloading and decryption implementation was inspired from multiple places, including [samloader](https://github.com/samloader/samloader), [samfirm.js](https://github.com/jesec/samfirm.js/), and [Bifrost](https://github.com/zacharee/Bifrost).
