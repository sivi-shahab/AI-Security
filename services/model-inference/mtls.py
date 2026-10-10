"""Workload mTLS for model-inference (ticket 40, threat model G1), the Python side of internal/server/mtls.go.

MTLS_DIR holds the pod's SPIFFE SVID from csi-driver-spiffe (tls.crt, tls.key, ca.crt, rewritten in place before
expiry). The model port only completes a TLS 1.3 handshake with a client certificate from that CA whose SPIFFE ID is
in MTLS_ALLOW; anything else is dropped before a request is read. $PORT serves /healthz only, for probes.
"""

import logging
import os
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = logging.getLogger("model-inference")


def spiffe_id(cert):
    for typ, val in (cert or {}).get("subjectAltName", ()):
        if typ == "URI" and val.startswith("spiffe://"):
            return val
    return ""


class SVID:
    """The certificate directory as an SSLContext, rebuilt when tls.crt or ca.crt changes."""

    def __init__(self, directory):
        self.dir = directory
        self._lock = threading.Lock()
        self._mod = None
        self._ctx = None
        self.context()  # fail at startup, not at the first call

    def _path(self, name):
        return os.path.join(self.dir, name)

    def context(self):
        mod = max(os.stat(self._path(f)).st_mtime_ns for f in ("tls.crt", "ca.crt"))
        with self._lock:
            if mod != self._mod:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.load_cert_chain(self._path("tls.crt"), self._path("tls.key"))
                ctx.load_verify_locations(self._path("ca.crt"))
                self._ctx, self._mod = ctx, mod
            return self._ctx


class MTLSServer(ThreadingHTTPServer):
    """Handshake and identity check on the request's own thread, so a slow client cannot stall accept()."""

    def __init__(self, addr, handler, svid, allow):
        super().__init__(addr, handler)
        self.svid, self.allow = svid, set(allow)

    def finish_request(self, request, client_address):
        request.settimeout(10)
        try:
            conn = self.svid.context().wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError) as e:
            log.warning("tls handshake refused", extra={"reason": type(e).__name__})
            return
        try:
            peer = spiffe_id(conn.getpeercert())
            if peer not in self.allow:
                log.warning("workload not allowed", extra={"peer": peer})
                return
            super().finish_request(conn, client_address)
        finally:
            conn.close()

    def handle_error(self, request, client_address):
        # socketserver prints a raw traceback to stderr, past the JSON formatter and its forbidden-field filter.
        log.warning(
            "request failed", extra={"reason": type(sys.exc_info()[1]).__name__}
        )


class Health(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/healthz":
            self.send_error(404)
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


def servers(handler):
    """[probe server, model server] with MTLS_DIR; [one plain server] with MTLS_INSECURE=true (development)."""
    port = int(os.environ.get("PORT", "8080"))
    directory = os.environ.get("MTLS_DIR")
    if directory:
        allow = [
            a.strip() for a in os.environ.get("MTLS_ALLOW", "").split(",") if a.strip()
        ]
        if not allow:
            raise SystemExit("MTLS_ALLOW is empty: no workload could call")
        mport = int(os.environ.get("MTLS_PORT", "8443"))
        return [
            ThreadingHTTPServer(("", port), Health),
            MTLSServer(("", mport), handler, SVID(directory), allow),
        ]
    if os.environ.get("MTLS_INSECURE") == "true":
        log.warning("MTLS_INSECURE: model routes served without client authentication")
        return [ThreadingHTTPServer(("", port), handler)]
    raise SystemExit(
        "MTLS_DIR not set: the model would be open to any pod (MTLS_INSECURE=true only for local development)"
    )
