# Web App Instructions (`web/`)

## Building & Linting

- Rebuild WASM bindings into `web/pkg/` after editing `web/src/` or any workspace crate `samloader-web` depends on (`fus/`, `odin/`, `pit/`):
  ```bash
  cargo xtask build-web
  # Include the Mock Device backend when testing flashing without physical hardware:
  cargo xtask build-web -- --features mock
  ```
- Lint WASM code with:
  ```bash
  cargo clippy -p samloader-web --target wasm32-unknown-unknown -- -D warnings
  ```
- Keep `web/samloader-fus-bridge.user.js` targeting **Tampermonkey** (`@sandbox JavaScript`, `GM.xmlHttpRequest`, `unsafeWindow`).

## JavaScript Syntax, Unit Tests & Benchmarks

`web/` uses Node.js built-ins (`node --check`, `node:test`) with no npm dependencies. Test files live in `web/tests/` (excluded from `dist/` staging by `xtask`).

- **Syntax check** all JS files:
  ```bash
  for f in web/*.js web/app/*.js web/ui/*.js web/workers/*.js web/tests/*.mjs; do node --check "$f" || exit 1; done
  ```
- **Run unit tests** (userscript allowlist, direct main-thread transport, worker `MessagePort` credit-based backpressure, coalescing, abort/401 handling, and buffer helpers):
  ```bash
  node --test web/tests/*.test.mjs
  ```
- **Run bridge throughput benchmark** (64 MiB streaming across `openBridgePort()` + `createFusHttpTransport()` at 32 / 64 / 512 KiB upstream chunks):
  ```bash
  node web/tests/bench_bridge.mjs
  ```

## Local CORS Relay Proxy (Browser Testing Without Tampermonkey)

When testing live Samsung FUS lookup, inspection, or downloads in a browser environment where Tampermonkey cannot be installed (e.g., automated or sandboxed browsers), start the local relay server:

```bash
python3 web/tests/dev_fus_relay.py 8088
```

Then open **`http://127.0.0.1:8088/`** (use `127.0.0.1` or `localhost` so the browser treats the tab as a Secure Context for OPFS `SyncAccessHandle`, WebUSB, and Web Serial).

What `dev_fus_relay.py` does:
- Serves `web/` statically with `Cache-Control: no-store` and proper `.wasm`/`.js` MIME types.
- Injects a `window.GM = { xmlHttpRequest }` shim and `<script src="/samloader-fus-bridge.user.js"></script>` into `index.html` in memory so the real userscript, `app/fus_bridge.js`, workers, and WASM run unmodified.
- Relays `POST /__fus_relay` to Samsung's 3 allowlisted FUS hosts with a per-host cookie jar and `64 KiB` streaming responses.
