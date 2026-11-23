#!/usr/bin/env python3
"""
Local dev server + live Samsung FUS CORS relay for testing samloader-web
in a browser when Tampermonkey cannot be installed (e.g. headless/sandboxed browsers).

Serves web/site/ on http://127.0.0.1:<port>/ and injects a GM.xmlHttpRequest shim
alongside the real web/site/samloader-fus-bridge.user.js so the production JS/WASM/Worker/OPFS
stack runs unmodified against Samsung's live FUS endpoints.

Usage:
    python3 web/tests/dev_fus_relay.py [port]
"""

import http.client
import http.cookies
import http.server
import json
import os
import socketserver
import ssl
import sys
import threading
import time
import urllib.parse

SITE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "site"))
PORT = int(sys.argv[1] if len(sys.argv) > 1 else "8088")

ALLOWED_TARGETS = {
    ("https", "neofussvr.sslcs.cdngc.net", 443),
    ("http", "cloud-neofussvr.samsungmobile.com", 80),
    ("https", "fota-cloud-dn.ospserver.net", 443),
}

# Thread-safe per-host cookie jar mimicking browser / reqwest cookie_store(true)
COOKIE_LOCK = threading.Lock()
COOKIE_JAR = {}  # host -> { name: value }

GM_SHIM_HTML = r"""
<script>
(() => {
  const gmXhr = function xmlHttpRequest(details) {
    const controller = new AbortController();
    const {
      method = "GET",
      url,
      headers = {},
      data = null,
      responseType = "text",
      onloadstart,
      onreadystatechange,
      onload,
      onerror,
      onabort,
    } = details || {};

    let aborted = false;
    const reqHandle = {
      abort() {
        aborted = true;
        controller.abort();
      },
    };

    const headerPairs = Object.entries(headers || {}).map(([k, v]) => [String(k), String(v)]);
    const meta = JSON.stringify({ method: String(method).toUpperCase(), url, headers: headerPairs });

    let bodyToSend = undefined;
    if (data !== null && data !== undefined && data !== "") {
      bodyToSend = data;
    }

    fetch("/__fus_relay", {
      method: "POST",
      headers: {
        "X-Fus-Meta": meta,
        "Content-Type": "application/octet-stream",
      },
      body: bodyToSend,
      signal: controller.signal,
    })
      .then(async (resp) => {
        if (!resp.ok) {
          const text = await resp.text().catch(() => resp.statusText);
          throw new Error(text || `Relay HTTP ${resp.status}`);
        }
        const upstreamStatus = Number(resp.headers.get("X-Fus-Status") || "0");
        const upstreamHeadersJson = resp.headers.get("X-Fus-Headers") || "[]";
        let pairs = [];
        try {
          pairs = JSON.parse(upstreamHeadersJson);
        } catch {}
        const rawHeaders = pairs.map(([k, v]) => `${k}: ${v}`).join("\r\n");

        if (responseType === "stream" && resp.body) {
          if (typeof onloadstart === "function") {
            onloadstart({
              status: upstreamStatus,
              statusText: "",
              responseHeaders: rawHeaders,
              response: resp.body,
              readyState: 2,
            });
          }
          return;
        }

        if (typeof onreadystatechange === "function") {
          onreadystatechange({
            status: upstreamStatus,
            statusText: "",
            responseHeaders: rawHeaders,
            readyState: 2,
          });
        }

        const payload =
          responseType === "arraybuffer" ? await resp.arrayBuffer() : await resp.text();
        if (typeof onload === "function") {
          onload({
            status: upstreamStatus,
            statusText: "",
            responseHeaders: rawHeaders,
            response: payload,
            responseText: typeof payload === "string" ? payload : "",
            readyState: 4,
          });
        }
      })
      .catch((err) => {
        if (aborted || err?.name === "AbortError") {
          if (typeof onabort === "function") onabort({ error: "Aborted" });
        } else {
          if (typeof onerror === "function") onerror({ error: err?.message || String(err) });
        }
      });

    return reqHandle;
  };
  gmXhr.RESPONSE_TYPE_STREAM = "stream";
  window.GM = { xmlHttpRequest: gmXhr };
  window.unsafeWindow = window;
})();
</script>
<script src="/samloader-fus-bridge.user.js"></script>
"""


def validate_url(raw_url: str):
    parsed = urllib.parse.urlsplit(raw_url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port or (443 if scheme == "https" else 80 if scheme == "http" else None)
    if (scheme, host, port) not in ALLOWED_TARGETS:
        raise ValueError(f"Host not allowed: {raw_url}")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return scheme, host, port, path


class FusRelayHandler(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    extensions_map = {
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        ".wasm": "application/wasm",
        ".js": "text/javascript; charset=utf-8",
        ".mjs": "text/javascript; charset=utf-8",
        ".svg": "image/svg+xml",
        ".woff2": "font/woff2",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=SITE_DIR, **kwargs)

    def log_message(self, format, *args):
        sys.stderr.write(f"[relay] {self.address_string()} - {format % args}\n")

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self):
        clean_path = urllib.parse.urlsplit(self.path).path
        if clean_path in ("/", "/index.html"):
            index_path = os.path.join(SITE_DIR, "index.html")
            with open(index_path, "rb") as f:
                html = f.read().decode("utf-8")
            marker = "</body>"
            idx = html.rfind(marker)
            if idx != -1:
                html = html[:idx] + GM_SHIM_HTML + "\n" + html[idx:]
            else:
                html = html + GM_SHIM_HTML
            data = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        super().do_GET()

    def do_POST(self):
        if urllib.parse.urlsplit(self.path).path != "/__fus_relay":
            self.send_error(404, "Not Found")
            return

        meta_raw = self.headers.get("X-Fus-Meta")
        if not meta_raw:
            self.send_error(400, "Missing X-Fus-Meta")
            return

        try:
            meta = json.loads(meta_raw)
            method = str(meta.get("method", "GET")).upper()
            url = str(meta.get("url", ""))
            req_headers = meta.get("headers", [])
            scheme, host, port, path = validate_url(url)
        except Exception as e:
            body = f"Invalid relay request: {e}".encode("utf-8")
            self.send_response(400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        req_body = self.rfile.read(content_length) if content_length > 0 else b""

        send_headers = {}
        has_cookie = False
        has_content_length = False
        for k, v in req_headers:
            kl = str(k).lower()
            if kl == "host":
                continue
            if kl == "cookie":
                has_cookie = True
            if kl == "content-length":
                has_content_length = True
            send_headers[str(k)] = str(v)

        if method == "POST" and not has_content_length:
            send_headers["Content-Length"] = str(len(req_body))

        if not has_cookie:
            with COOKIE_LOCK:
                host_cookies = COOKIE_JAR.get(host)
                if host_cookies:
                    send_headers["Cookie"] = "; ".join(
                        f"{k}={v}" for k, v in host_cookies.items()
                    )

        conn = None
        t0 = time.monotonic()
        try:
            if scheme == "https":
                ctx = ssl.create_default_context()
                conn = http.client.HTTPSConnection(host, port, timeout=30, context=ctx)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=30)

            conn.request(
                method,
                path,
                body=req_body if method == "POST" else None,
                headers=send_headers,
            )
            resp = conn.getresponse()
            hdr_dt = time.monotonic() - t0
            if (
                resp.status not in (200, 206)
                or hdr_dt >= 2.0
                or resp.headers.get_all("Set-Cookie")
                or "GenerateNonce" in path
                or "BinaryInitForMass" in path
            ):
                sys.stderr.write(
                    f"[upstream] {method} {host}{path[:60]} range={send_headers.get('Range')} "
                    f"status={resp.status} hdr_dt={hdr_dt:.2f}s "
                    f"set_cookie={resp.headers.get_all('Set-Cookie')}\n"
                )

            set_cookies = resp.headers.get_all("Set-Cookie") or []
            if set_cookies:
                with COOKIE_LOCK:
                    jar = COOKIE_JAR.setdefault(host, {})
                    for sc in set_cookies:
                        c = http.cookies.SimpleCookie()
                        c.load(sc)
                        for name, morsel in c.items():
                            jar[name] = morsel.value

            resp_header_pairs = [[k, v] for k, v in resp.getheaders()]
            upstream_len = resp.getheader("Content-Length")

            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("X-Fus-Status", str(resp.status))
            self.send_header("X-Fus-Headers", json.dumps(resp_header_pairs))
            if upstream_len is not None:
                self.send_header("Content-Length", upstream_len)
                self.end_headers()
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
            else:
                payload = resp.read()
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            try:
                body = f"Upstream error: {e}".encode("utf-8")
                self.send_response(502)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception:
                pass
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), FusRelayHandler)
    print(f"Serving {SITE_DIR} with live FUS relay on http://127.0.0.1:{PORT}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
