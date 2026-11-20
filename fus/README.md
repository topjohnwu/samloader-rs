# samloader-fus

A pure-Rust client library for interacting with the Samsung Firmware Update Server (FUS) to query and stream official Samsung device firmware packages.

## Features

- Negotiates secure FUS handshakes, rotates nonces, and automatically refreshes expired download tokens.
- Fetches stable, previous, and beta firmware versions for any model and CSC.
- Resolves binary sizes, file paths, and decryption keys.
- Streams arbitrary byte ranges via `DataSource` with transparent, zero-copy AES-128-ECB decryption and exact PKCS#7 unpadding of `.enc2`/`.enc4` payloads.
- Accelerates downloads with `ParallelDataSource` (sliding-window multi-connection range fetching, retries, work-stealing, and head-of-line hedging).
- Parses ZIP / ZIP64 Central Directories directly over any `DataSource` via `ZipArchive` and streams individual entries with CRC-32 verification and mid-stream `ResumableStream` checkpoints (`DataStream`/`OffsetCheckpoint` and `ZipEntryStream`/`ZipCheckpoint`).

## Usage

Callers must run on an active Tokio runtime (required by `reqwest` for async I/O and timeouts).

### Basic Version Checking & Streaming Download

```rust,no_run
use samloader_fus::{
    DataSource, FusClient, fetch_history,
    futures::io::{AllowStdIo, copy},
};
use std::fs::File;

async fn download_firmware() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Fetch version info
    let version_info = fetch_history("SM-S931U1", "XAA").await?;
    println!("Latest firmware version: {}", version_info.latest);

    // 2. Initialize the FUS Client and download session
    let client = FusClient::new().await?;
    let info = client
        .fetch_binary_info("SM-S931U1", "XAA", &version_info.latest)
        .await?;
    println!(
        "File name: {}, encrypted size: {}",
        info.filename(),
        info.encrypted_size()
    );
    let session = client.init_download(info).await?;

    // 3. Stream and decrypt the firmware package (or wrap in `ParallelDataSource`)
    let mut reader = session.fetch().await?;
    let mut file = AllowStdIo::new(File::create("firmware.zip")?);
    copy(&mut reader, &mut file).await?;
    println!("Download complete!");

    Ok(())
}
```

## License

This project is licensed under the Apache License, Version 2.0.
