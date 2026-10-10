"""model-inference: L2 detection models on CPU (tickets 09-10): NER PII and prompt-injection classifier, ONNX int8."""

import json
import logging
import os
import signal
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import mtls

SERVICE = "model-inference"
FORBIDDEN_FILE = os.environ.get("FORBIDDEN_FIELDS_FILE") or (
    Path(__file__).resolve().parents[2] / "internal/privacy/forbidden_fields.txt"
)
FORBIDDEN = {
    line.strip().lower()
    for line in Path(FORBIDDEN_FILE).read_text().splitlines()
    if line.strip() and not line.startswith("#")
}
# Attributes every LogRecord has; anything else came from `extra=`.
_STD = set(vars(logging.makeLogRecord({}))) | {"message", "asctime"}


class JSONFormatter(logging.Formatter):
    """JSON lines; drops forbidden fields from `extra` (spec §10.2, §12.3)."""

    def format(self, record):
        out = {
            "level": record.levelname,
            "msg": record.getMessage(),
            "service": SERVICE,
        }
        for k, v in vars(record).items():
            if k not in _STD and k.lower() not in FORBIDDEN:
                out[k] = v
        return json.dumps(out, default=str)


log = logging.getLogger(SERVICE)


MAX_CONTENT = 256 << 10  # spec §8.1
MAX_VIEWS = 8
MODEL = None  # l2.Model, loaded in main() from MODEL_DIR


def analyze(body):
    """POST /v1/analyze: {"text", "views"?: [decoded texts], "trust"?: trusted|untrusted} -> l2.Model.analyze."""
    try:
        req = json.loads(body)
        text, views, trust = (
            req["text"],
            req.get("views") or [],
            req.get("trust") or "trusted",
        )
        ok = (
            isinstance(text, str)
            and isinstance(views, list)
            and len(views) <= MAX_VIEWS
            and all(
                isinstance(v, str) and len(v.encode()) <= MAX_CONTENT for v in views
            )
            and trust in ("trusted", "untrusted")
            and len(text.encode()) <= MAX_CONTENT
        )
    except (ValueError, KeyError, TypeError, AttributeError):
        ok = False
    if not ok:
        return 400, {"error": "want {text, views?, trust?}, each at most 256 KB"}
    return 200, MODEL.analyze(text, views, trust)


class Handler(BaseHTTPRequestHandler):
    def reply(self, code, body):
        raw = json.dumps(body).encode() if not isinstance(body, bytes) else body
        self.send_response(code)
        self.send_header(
            "Content-Type",
            "application/json" if not isinstance(body, bytes) else "text/plain",
        )
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/healthz":
            self.reply(200, b"ok")
        elif self.path == "/readyz":  # ready only with a model loaded
            self.reply(
                200 if MODEL else 503, {"model": MODEL.version if MODEL else None}
            )
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path != "/v1/analyze":
            self.send_error(404)
            return
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_CONTENT * (MAX_VIEWS + 1) + 4096:
            self.reply(413, {"error": "too large"})
            return
        if MODEL is None:
            self.reply(503, {"error": "no model loaded"})
            return
        try:
            self.reply(*analyze(self.rfile.read(n)))
        except Exception as e:  # never echo content; the type is enough to debug
            log.error("analyze failed", extra={"error_type": type(e).__name__})
            self.reply(500, {"error": "internal error"})

    def log_message(self, *args):  # stdlib access log would bypass the JSON formatter
        pass


class Probe(Handler):
    """The plain probe port: /healthz and /readyz (model loaded), never the model itself."""

    def do_POST(self):
        self.send_error(404)


def main():
    h = logging.StreamHandler()
    h.setFormatter(JSONFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[h])
    global MODEL
    if os.environ.get("MODEL_DIR"):
        import l2  # onnxruntime is only needed when a model is served

        MODEL = l2.Model(os.environ["MODEL_DIR"])
        log.info("model loaded", extra={"model": MODEL.version, "tasks": MODEL.tasks})
    # Probe port + mTLS model port (ticket 40, mtls.py).
    srvs = mtls.servers(Handler, probe=Probe)
    # shutdown() blocks until serve_forever() returns, so it must not run on the serving thread.
    signal.signal(
        signal.SIGTERM,
        lambda *_: [threading.Thread(target=s.shutdown).start() for s in srvs],
    )
    for s in srvs[1:]:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    for s in srvs:
        log.info("listening", extra={"addr": s.server_address})
    srvs[0].serve_forever()


if __name__ == "__main__":
    main()
