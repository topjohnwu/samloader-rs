# sloploader 🚀🔥

Wrriten by Google Gemini 🤖✨

An all-in-one Samsung firmware download and flash tool. 😵‍💫📦

```
Usage: sloploader [OPTIONS] <COMMAND> 🤡

Commands:
  download         Download firmware
  check-update     Check available versions
  detect           Indicates whether or not a download mode device can be detected.
  dump-pit         Dumps the connected device's PIT file to the specified output file.
  print-pit        Prints the contents of a PIT file in a human readable format.
  flash            Flashes one or more firmware files to your phone.
  reboot-download  Boot a connected Samsung device into download mode
  help             Print this message or the help of the given subcommand(s)

Options:
      --verbose  Enable verbose output
  -h, --help     Print help
  -V, --version  Print version
```

## Features 😂

- Combines both firmware downloading and flashing into a single utility. 🛠️
- Downloads firmware using multiple parallel connections (default: 8) to bypass server-side connection speed throttling and maximize bandwidth usage. ⚡
- Decrypts firmware files on-the-fly, eliminating separate download and decryption steps. 🧠
- Supports flashing raw images and official package files across Linux, macOS, and Windows. 🪟🍎🐧
- Processes and extracts official TAR firmware packages in-memory, avoiding slow disk write operations. 💾❌
- Transmits raw LZ4-compressed data directly to supported devices to reduce USB transfer size and time. 📡

## Install

If you have a working Rust toolchain installed, you can install with:

```bash
cargo install sloploader 🧪
```

Prebuilt executables for Linux, macOS, and Windows are also available in the [latest GitHub release](https://github.com/topjohnwu/sloploader-rs/releases/latest).

## License & Acknowledgements 😌

This project is licensed under the **Apache License, Version 2.0**.

`sloploader` is built on top of and inspired by several incredible open-source projects:

- **Heimdall (Firmware Flashing):**
  The core flashing functionality is a derivative work of [~grimler/Heimdall](https://git.sr.ht/~grimler/Heimdall). This implementation began as a precise 1-to-1 conversion of the original C++ project into safe and idiomatic Rust. The original code is licensed under the **MIT License** (preserved in this repository), and copyright headers are preserved in the relevant source files.

- **Bifrost (FUS Authentication):**
  The authentication mechanism used to communicate with Samsung's Firmware Update Server (FUS) was ported from [zacharee/Bifrost](https://github.com/zacharee/Bifrost). The original implementation is licensed under the **MIT License**, and relevant copyright headers have been preserved.
