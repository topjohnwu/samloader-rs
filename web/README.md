# samloader-web

Browser-based Samsung Odin firmware flasher powered by [`samloader-odin`](../odin) compiled to WebAssembly, using [WebUSB](https://wicg.github.io/webusb/) (`nusb`) and [Web Serial](https://wicg.github.io/serial/) (`vcom`).

## Prerequisites

Add the `wasm32-unknown-unknown` target to your Rust toolchain:

```bash
rustup target add wasm32-unknown-unknown
```

## Building

From the repository root, compile `samloader-web` for WebAssembly and generate the JS/WASM bindings into `web/pkg`:

```bash
cargo xtask build-web
# or
cargo build-web
```

To build with debug/dev profile instead:

```bash
cargo xtask build-web --dev
```

## Running Locally

Serve the `web/` directory with any static HTTP server. For example, using Python:

```bash
python3 -m http.server -d web 8000
```

Then open `http://localhost:8000` in a Chromium-based browser (Chrome, Edge, Brave, Opera).

> **Note:** WebUSB and Web Serial are only exposed in [Secure Contexts](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts) (`http://localhost`, `http://127.0.0.1`, or `https://`), and require a Chromium-based browser. You can also select the **Mock Device (Debug)** backend in the UI to test flashing workflows in any browser without physical hardware.

## Deploying

The web app is a purely static site with no backend server requirements. Fonts are self-hosted from `web/fonts/`, so the page makes no third-party requests.

1. Build the release WASM bundle and stage the static site (web assets, fonts, and the generated `pkg/` bindings) into `dist/`:

   ```bash
   cargo xtask build-web --dist dist
   ```

2. Deploy the contents of `dist/` to any static hosting provider (GitHub Pages, Cloudflare Pages, Netlify, Vercel, S3, nginx, etc.):
   - **HTTPS required:** Production deployments must be served over `https://` so the browser enables `navigator.usb` (WebUSB) and `navigator.serial` (Web Serial).
   - **MIME types:** Ensure `.wasm` files are served with `Content-Type: application/wasm` and `.js` files with `Content-Type: text/javascript` (standard on all modern static hosts).

## License

This project is licensed under the Apache License, Version 2.0.

The bundled fonts in `web/fonts/` (DM Sans, Roboto, and Roboto Mono) are licensed under the SIL Open Font License, Version 1.1. See the `OFL-*.txt` files next to them.
