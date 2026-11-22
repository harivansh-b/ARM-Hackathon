"""Stdlib HTTP server: static UI + JSON API. No third-party dependencies."""
from __future__ import annotations

import cgi, json, tempfile, threading, traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from . import core

STATIC = Path(__file__).parent / "static"
TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml"}
MAX_UPLOAD = 25 * 1024 * 1024


class Handler(BaseHTTPRequestHandler):
    server_version = "Guardian"

    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n > 1_000_000:
            raise ValueError("request too large")
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        path = urlparse(self.path).path
        try:
            if path == "/api/system":
                return self._json(core.system_info())
            if path == "/api/system/hashes":
                return self._json(core.model_files(hashes=True))
            if path == "/api/system/benchmarks":
                return self._json(core.stored_benchmarks())
            if path == "/api/sensor/scenarios":
                return self._json(core.list_scenarios())
            if path == "/api/sustained":
                return self._json(core.SUSTAINED.status())
            if path == "/api/status":
                return self._json({"ok": True, "llama_ready": core.llama_ready()})
        except Exception as e:
            return self._json({"error": str(e)}, 500)
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        f = (STATIC / rel).resolve()
        if STATIC.resolve() not in f.parents or not f.is_file():
            f = STATIC / "index.html"  # single-page app fallback
        data = f.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", TYPES.get(f.suffix, "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            if path == "/api/check":
                b = self._body()
                return self._json(core.check_message(b.get("text", ""), b.get("sender"), with_llm=bool(b.get("llm"))))
            if path == "/api/import":
                return self._json(self._import())
            if path == "/api/check-batch":
                b = self._body()
                items = [m if isinstance(m, dict) else {"text": m} for m in b.get("messages", [])]
                items = [{"id": str(i + 1), "text": str(m.get("text", "")).strip(), "sender": b.get("sender") or None, "label": m.get("label")} for i, m in enumerate(items) if str(m.get("text", "")).strip()][:500]
                if not items:
                    raise ValueError("no messages")
                r = core.analyze_batch(items)
                return self._json(r)
            if path == "/api/import-sample":
                r = core.import_messages(core.SAMPLE_CSV); r["filename"] = "sample sms.csv"
                return self._json(r)
            if path == "/api/sensor/explain":
                ev = self._body().get("evidence")
                if not isinstance(ev, dict) or "event_type" not in ev:
                    raise ValueError("evidence required")
                return self._json(core.net_explain(ev, True))
            if path == "/api/sensor/replay":
                b = self._body()
                return self._json(core.replay(b.get("scenario"), with_llm=bool(b.get("llm"))))
            if path == "/api/sensor/upload":
                return self._json(self._upload_pcap())
            if path == "/api/sustained/start":
                core.SUSTAINED.start(bool(self._body().get("llama")))
                return self._json(core.SUSTAINED.status())
            if path == "/api/sustained/stop":
                core.SUSTAINED.stop()
                return self._json(core.SUSTAINED.status())
            if path == "/api/system/benchmark":
                return self._json(core.live_benchmark())
            if path == "/api/system/llama-benchmark":
                return self._json(core.llama_benchmark())
            self._json({"error": "not found"}, 404)
        except ValueError as e:
            self._json({"error": str(e)}, 400)
        except Exception as e:
            traceback.print_exc()
            self._json({"error": f"{type(e).__name__}: {e}"}, 500)

    def _file(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_UPLOAD:
            raise ValueError("file too large (25 MB max)")
        form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={"REQUEST_METHOD": "POST", "CONTENT_TYPE": self.headers["Content-Type"]})
        item = form["file"] if "file" in form else None
        if item is None or not item.filename:
            raise ValueError("no file uploaded")
        return item

    def _import(self):
        item = self._file()
        suffix = Path(item.filename).suffix.lower()
        if suffix not in (".csv", ".xml", ".json", ".jsonl", ".txt"):
            raise ValueError("supported formats: CSV, XML, JSON, JSONL, TXT")
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as t:
            t.write(item.file.read())
        try:
            res = core.import_messages(Path(t.name))
        finally:
            Path(t.name).unlink(missing_ok=True)
        res["filename"] = item.filename
        return res

    def _upload_pcap(self):
        item = self._file()
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as t:
            t.write(item.file.read())
        try:
            res = core.replay(pcap=Path(t.name))
        finally:
            Path(t.name).unlink(missing_ok=True)
        res["title"] = item.filename; res["source"] = item.filename + " (uploaded)"
        return res


def serve(host: str = "0.0.0.0", port: int = 8080) -> None:
    core.SERVER_PORT = port
    core.sms_runtime()  # fail fast / one-time train
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"Guardian running → http://{host}:{port}  (Llama: {'ready' if core.llama_ready() else 'not found, template fallback'})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
