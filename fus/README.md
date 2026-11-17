# samloader-fus

A pure-Rust client library for interacting with the Samsung Firmware Update Server (FUS) to query and stream official Samsung device firmware packages.

## Features

- Negotiates secure FUS handshakes, rotates nonces, and automatically refreshes expired download tokens.
- Fetches stable, previous, and beta firmware versions for any model and CSC.
- Resolves binary sizes, file paths, and decryption keys.
- Streams arbitrary byte ranges with transparent, zero-copy AES-128-ECB decryption and PKCS#7 unpadding of `.enc2`/`.enc4` payloads.

## Usage

### Basic Version Checking & Streaming Download

```rust,no_run
use samloader_fus::{FusClient, fetch_history};
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Fetch version info
    let version_info = fetch_history("SM-S931U1", "XAA")?;
    println!("Latest firmware version: {}", version_info.latest);

    // 2. Initialize the FUS Client and download session
    let client = FusClient::new()?;
    let info = client.fetch_binary_info("SM-S931U1", "XAA", &version_info.latest)?;
    println!("File name: {}, size: {}", info.filename, info.size);
    let session = client.init_download(info)?;

    // 3. Stream and decrypt the firmware package (or use `fetch_range` for parallel ranges)
    let mut reader = session.fetch()?;
    let mut file = File::create("firmware.zip")?;
    std::io::copy(&mut reader, &mut file)?;
    println!("Download complete!");

    Ok(())
}
```

## License

This project is licensed under the Apache License, Version 2.0.
