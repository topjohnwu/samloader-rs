# samloader-rs

A Rust tool to download Samsung firmware via the FUS (Firmware Update Server) protocol.

Fork of [topjohnwu/samloader-rs](https://github.com/topjohnwu/samloader-rs) with support for **downloading a specific firmware version** (not just the latest).

## Features

- Download the **latest** Samsung firmware for any model/region
- Download a **specific firmware version** using `--version` / `-v` flag
- List **all available firmware versions** with `check-update --all` / `-a`
- Multi-threaded download with configurable parallelism (`-j`)
- Automatic decryption of encrypted firmware (`*.enc4` → `*.zip`)
- No IMEI / serial number required
- Built on top of the official Samsung FUS protocol

## Installation

```bash
cargo install --path .
```

Or build from source:

```bash
cargo build --release
./target/release/samloader --help
```

## Usage

### Download the latest firmware

```bash
samloader download -m "SM-S721B" -r "EUX" -d ./firmware
```

### Download a specific firmware version

```bash
samloader download -m "SM-S721B" -r "EUX" -v "S721BXXS7BYH1/S721BOXM7BYH1/S721BXXS7BYH1" -d ./firmware
```

The version string can be in 3-part (PDA/CSC/MODEM) or 4-part (PDA/CSC/MODEM/PDA) format.

### List all available firmware versions

```bash
samloader check-update -m "SM-S721B" -r "EUX" --all
```

### Check the latest version only

```bash
samloader check-update -m "SM-S721B" -r "EUX"
```

## Options

| Flag | Description |
|------|-------------|
| `-m`, `--model` | Device model (e.g. `SM-S721B`) |
| `-r`, `--region` | CSC region code (e.g. `EUX`) |
| `-v`, `--version` | Specific firmware version to download (PDA/CSC/MODEM) |
| `-j`, `--threads` | Number of parallel connections (default: 8) |
| `-d`, `--out-dir` | Output directory |
| `-o`, `--out-file` | Output file path |
| `-a`, `--all` | List all available versions (check-update only) |

## Patch

This fork adds the following changes on top of upstream v1.2.0:

- `download --version` / `-v`: Download a specific firmware version instead of the latest
- `check-update --all` / `-a`: List all firmware versions available for a device
- `fetch_binary_info_for_version()`: New FUS client method for version-specific binary info
- `fetch_all_versions()`: New FUS client method to enumerate all versions from version.xml
- `parse_version_xml_all()`: XML parser for all upgrade entries
- Auto-converts 3-part version strings to 4-part (FUS requirement)

The patch is maintained at `patches/samloader-rs/0001-version-select.patch` in the [ExtremeROM_a14](https://github.com/clangsdorff/ExtremeROM_a14) repo.

## Credits

- [topjohnwu/samloader-rs](https://github.com/topjohnwu/samloader-rs) - Original Rust samloader implementation
- [nlscc/samloader](https://github.com/nlscc/samloader) - Original Python samloader
- Samsung FUS protocol

## License

Apache 2.0
