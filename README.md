# samloader-rs

Download firmware for Samsung devices from official Samsung servers.

```
Usage: samloader <COMMAND>

Commands:
  download      Download the latest firmware
  check-update  Check the latest version
  help          Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

```
Usage: samloader download [OPTIONS] --model <model> --region <region>

Options:
  -m, --model <model>        The model name (e.g. SM-S931U1)
  -r, --region <region>      Region CSC code (e.g. XAA)
  -j, --threads <threads>    Number of parallel connections [default: 8]
  -d, --out-dir <out_dir>    Output directory
  -o, --out-file <out_file>  Output file path
  -h, --help                 Print help
```

```
Usage: samloader check-update --model <model> --region <region>

Options:
  -m, --model <model>    The model name (e.g. SM-S931U1)
  -r, --region <region>  Region CSC code (e.g. XAA)
  -h, --help             Print help
```

## Features

- Samsung server throttles the download speed per connection. This tool downloads the firmware with multiple connections (default: 8) to fully utilize your network bandwidth.
- Decryption happens on-the-fly. There are no separate download and decryption steps.

## Install

If you have a working Rust toolchain installed, you can simply install with the following command:

```bash
cargo install samloader
```

You can also download the prebuilt executables for Linux, macOS, and Windows in the [latest GitHub release](https://github.com/topjohnwu/samloader-rs/releases/latest).

## Notes

This project was originally based on the work of [ananjaser1211/samloader](https://github.com/ananjaser1211/samloader).
