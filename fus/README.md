# samloader-fus

A pure-Rust client library for interacting with the Samsung Firmware Update Server (FUS) to query and download official Samsung device firmware packages.

## Features

- Negotiates secure FUS handshakes and automatically rotates nonces.
- Fetches stable, previous, and beta firmware versions for any model and CSC.
- Resolves binary sizes, file paths, MD5 checksums, and decryption keys.
- Downloads firmware using a multi-threaded engine with connection pooling.
- Performs zero-copy, in-memory AES-128-ECB decryption of `.enc4` payloads.

## Usage

### Basic Version Checking & Downloading

```rust
use samloader_fus::{DownloadOptions, FusClient, download_firmware, fetch_history};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Fetch version info
    let version_info = fetch_history("SM-S931U1", "XAA")?;
    println!("Latest firmware version: {}", version_info.latest);

    // 2. Initialize the FUS Client
    let mut client = FusClient::new()?;
    client.fetch_binary_info("SM-S931U1", "XAA", &version_info.latest);
    println!("File name: {}, size: {}", client.info.filename, client.info.size);

    // 3. Download the firmware in parallel (resumable)
    // Implement `DownloadProgress` or pass `&()` for a silent download.
    let options = DownloadOptions {
        threads: 8,
        force: false,
    };
    download_firmware(&client, "firmware.zip", options, &())?;
    println!("Download complete!");

    Ok(())
}
```

## License

This project is licensed under the Apache License, Version 2.0.
