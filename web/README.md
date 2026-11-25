# samloader-web

Browser-based Samsung firmware downloader and Odin flasher powered by [`samloader-fus`](../fus) and [`samloader-odin`](../odin) compiled to WebAssembly, using [WebUSB](https://wicg.github.io/webusb/) (`nusb`) and [Web Serial](https://wicg.github.io/serial/) (`vcom`).

**Live Web App:** [https://topjohnwu.github.io/samloader-rs/](https://topjohnwu.github.io/samloader-rs/)

## Features

- **Samsung Server Firmware Lookup & Inspection**: Query FUS firmware history (`Latest`, `Previous Stable`, `Beta`) or enter a custom version string, auto-fill Model & Region from a connected Download Mode device (DVIF), highlight the installed bootloader version, and inspect the encrypted ZIP Central Directory before downloading.
- **Selective Component Extraction & Smart CSC Selection**: Download either the full decrypted `.zip` archive or selected `.tar.md5` components (`BL`, `AP`, `CP`, `CSC` / `HOME_CSC`, `USERDATA`, or extra archive files) with range-resumable parallel connections and ZIP CRC-32 validation.
- **Download & Flash**: Stream selected firmware components into OPFS staging and flash them directly to a Download Mode device with shared Odin options (PIT, CSC/Sales Code, NAND Erase, vbmeta flags, reboot target).
- **Local Files Flasher**: Load local `.tar` / `.tar.md5` packages, `.pit` files, and individual partition images with Web Worker MD5 verification.

## FUS Bridge Userscript

Samsung FUS servers block cross-origin browser `fetch()` requests (CORS) and serve encrypted firmware binaries over plain HTTP (which browsers block as mixed content on HTTPS pages). To talk to Samsung FUS directly from your browser without any backend proxy, the **Samsung Server** mode uses a lightweight local userscript bridge: [`web/site/samloader-fus-bridge.user.js`](site/samloader-fus-bridge.user.js).

### Setup

1. Install **Tampermonkey** (on Chrome MV3, ensure **Allow User Scripts** / Developer Mode is enabled for the extension).
2. Click **Install Userscript** (or **Copy Script** / **Download `.user.js`** for manual installation) in the web UI banner.
3. Click **Reload Page** so Tampermonkey injects the bridge into the tab. The badge switches to `FUS Bridge v1.0.0`.

The userscript activates only on pages containing `<meta name="samloader-fus-bridge" content="1">`, enforces a strict `https`/`http` allowlist restricted to Samsung's three FUS endpoints (`neofussvr.sslcs.cdngc.net`, `cloud-neofussvr.samsungmobile.com`, and `fota-cloud-dn.ospserver.net`), and exposes a thin `GM.xmlHttpRequest` wrapper to `web/site/app/fus_bridge.js` so streaming and worker relay updates deploy with the web app without reinstalling the script.

## Browser Compatibility & Storage

| Feature | Desktop Chromium (Chrome / Edge / Brave / Opera) | Other Browsers (Firefox / Safari / iOS) |
| --- | --- | --- |
| Firmware Lookup, Inspect & Download Only | Direct resumable disk writes via File System Access API (`showDirectoryPicker`) | Not supported (requires Chromium Tampermonkey) |
| **Load into Local Flash** (after directory download) | Loads `FileSystemFileHandle`s directly into **Local Files** slots without re-reading MD5 | — |
| Device Flashing (Odin / AT / **Download & Flash**) | Supported via WebUSB / Web Serial in a Secure Context (`http://localhost`, `127.0.0.1`, or `https://`) | WebUSB / Web Serial unavailable (Debug `Mock Device` only if built with `--features mock`) |

### OPFS Cache & Resume Checkpoints

- **Download & Flash** stages decrypted files in the browser's Origin Private File System (`samloader-staging/`) with `.part` resume checkpoints and CRC-32 verification.
- Cancelling or hitting an error keeps the partial OPFS checkpoint so re-running skips already-completed ranges/files.
- A successful **Download & Flash** automatically clears the OPFS cache afterwards, whereas a failed/aborted flash retains it so retrying skips re-downloading (or click **Clear Cache** to remove staged files manually).

## Prerequisites

Add the `wasm32-unknown-unknown` target to your Rust toolchain:

```bash
rustup target add wasm32-unknown-unknown
```

## Building

From the repository root, compile `samloader-web` for WebAssembly and generate the JS/WASM bindings into `web/site/pkg`:

```bash
cargo xtask build-web
# or
cargo build-web
```

To build with debug/dev profile instead:

```bash
cargo xtask build-web --dev
```

The mock backend is omitted by default in all builds; to explicitly include it (e.g. for UI development without physical hardware):

```bash
cargo xtask build-web -- --features mock
```

## Running Locally

Serve the `web/site/` directory with any static HTTP server. For example, using Python:

```bash
python3 -m http.server -d web/site 8000
```

Then open `http://localhost:8000` in a Chromium-based browser (Chrome, Edge, Brave, Opera).

> **Note:** WebUSB and Web Serial are only exposed in [Secure Contexts](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts) (`http://localhost`, `http://127.0.0.1`, or `https://`), and require a Chromium-based browser. When built with `--features mock`, you can also select the **Mock Device (Debug)** backend in the UI to test flashing workflows in any browser without physical hardware.

## Static File Structure

```text
web/
├── Cargo.toml                   # Rust crate manifest for samloader-web
├── src/                         # Rust/WASM implementation
├── tests/                       # Node unit tests, benchmarks & local FUS relay
└── site/                        # Served website document root
    ├── index.html                   # App shell (Samsung Server & Local Files panels)
    ├── styles.css                   # Material Design 3 styling (light/dark tokens)
    ├── manifest.webmanifest         # PWA manifest for standalone installation
    ├── sw.js                        # Network-first Service Worker with offline fallback
    ├── samloader-fus-bridge.user.js # Tampermonkey userscript for FUS CORS bypass
    ├── app/
    │   ├── app.js                   # Entry point, WASM init, device hotplug & UI wiring
    │   ├── bridge.js                # JS facade over wasm-bindgen exports in pkg/
    │   ├── capabilities.js          # Browser capability detection (flashing & downloading)
    │   ├── device.js                # Paired device state, DVIF queries, PIT dumps & reboots
    │   ├── download.js              # OPFS staging, worker download & Download & Flash flows
    │   ├── exclusive.js             # Exclusive operation guard, wake lock & beforeunload
    │   ├── flash.js                 # Flash job orchestration & EMA speed/ETA tracking
    │   ├── format.js                # Byte-size and duration formatting helpers
    │   ├── fus_bridge.js            # Main-thread & Worker MessagePort transport over userscript
    │   ├── logger.js                # App logging and error-reporting facade over WASM buffer
    │   ├── server.js                # FUS bridge probing, history lookup, inspect & selection state
    │   ├── slots.js                 # Odin slot/partition state & sequential MD5 worker queue
    │   └── state.js                 # Shared application state and Odin slot metadata
    ├── workers/
    │   ├── download.js              # Module Web Worker running concurrent FUS downloads & DEFLATE
    │   └── md5.js                   # Module Web Worker running streaming .tar.md5 checks
    ├── ui/
    │   ├── controls.js              # View visibility, button enablement & header/advanced controls
    │   ├── device.js                # Device list, DVIF telemetry grid & PIT save UI
    │   ├── download.js              # OPFS cache banner, picker/wipe prompts & progress UI
    │   ├── flash.js                 # Flashing progress bar, outcome banner & action bar UI
    │   ├── log.js                   # Virtualized Rust-backed activity log panel
    │   ├── server.js                # Samsung Server panel rendering, preferences & events
    │   ├── slots.js                 # Package slot dropzones, MD5 badges & sortable partitions UI
    │   ├── theme.js                 # Light / Dark / System theme switcher
    │   └── util.js                  # DOM progress/accessibility helpers and file download trigger
    ├── fonts/                       # Self-hosted DM Sans, Roboto, and Roboto Mono fonts
    ├── icons/                       # Raster PNG app icons for PWA installation
    └── pkg/                         # Generated wasm-bindgen JS/WASM bundle (built by xtask)
```

## Deploying

Automated GitHub Pages deployment is configured in [`.github/workflows/pages.yml`](../.github/workflows/pages.yml), publishing on GitHub Releases and manual `workflow_dispatch` runs to `https://topjohnwu.github.io/samloader-rs/`.

The web app is a purely static site with no backend server requirements. Fonts are self-hosted from `web/site/fonts/`, so the page makes no third-party requests other than optional Samsung FUS requests via the user's installed bridge userscript.

1. Build the release WASM bundle and stage the static site (web assets, userscript, fonts, and generated `pkg/` bindings) into `dist/`:

   ```bash
   cargo xtask build-web --dist dist
   ```

2. Deploy the contents of `dist/` to any static hosting provider (GitHub Pages, Cloudflare Pages, Netlify, Vercel, S3, nginx, etc.):
   - **HTTPS required:** Production deployments must be served over `https://` so the browser enables `navigator.usb` (WebUSB), `navigator.serial` (Web Serial), and OPFS SyncAccessHandle in workers.
   - **MIME types:** Ensure `.wasm` files are served with `Content-Type: application/wasm` and `.js` / `.user.js` files with `Content-Type: text/javascript` (standard on all modern static hosts).

## License

This project is licensed under the Apache License, Version 2.0.

The bundled fonts in `web/site/fonts/` (DM Sans, Roboto, and Roboto Mono) are licensed under the SIL Open Font License, Version 1.1. See the `OFL-*.txt` files next to them.
