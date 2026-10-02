"""model-inference: hello-world skeleton. NER / injection classifier come in tickets 09-10."""

import json
import logging
import os
import signal
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

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


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/healthz":
            self.send_error(404)
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):  # stdlib access log would bypass the JSON formatter
        pass


def main():
    h = logging.StreamHandler()
    h.setFormatter(JSONFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[h])
    srv = ThreadingHTTPServer(("", int(os.environ.get("PORT", "8080"))), Handler)
    # shutdown() blocks until serve_forever() returns, so it must not run on the serving thread.
    signal.signal(
        signal.SIGTERM, lambda *_: threading.Thread(target=srv.shutdown).start()
    )
    log.info("listening", extra={"addr": srv.server_address})
    srv.serve_forever()


if __name__ == "__main__":
    main()
