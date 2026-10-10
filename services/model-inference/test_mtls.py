"""Ticket 40 AC: model-inference answers only detection-svc (MTLS_ALLOW); other pods are refused at the handshake."""

import http.client
import os
import ssl
import threading
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import mtls

# Test-only CA, never trusted by a deployment (allowlisted in .gitleaks.toml).
PKI = Path(__file__).resolve().parent / "testdata" / "pki"
DETECTION = "spiffe://aisec.bank/ns/aisec/sa/detection-svc"


class Model(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"scored")

    def log_message(self, *args):
        pass


def client_ctx(identity):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False  # identity is the SPIFFE ID, checked below
    ctx.load_verify_locations(PKI / "model-inference" / "ca.crt")
    if identity:
        ctx.load_cert_chain(PKI / identity / "tls.crt", PKI / identity / "tls.key")
    return ctx


class MTLSTest(unittest.TestCase):
    def setUp(self):
        self.srv = mtls.MTLSServer(
            ("127.0.0.1", 0), Model, mtls.SVID(PKI / "model-inference"), [DETECTION]
        )
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    def call(self, identity):
        c = http.client.HTTPSConnection(
            "127.0.0.1",
            self.srv.server_address[1],
            context=client_ctx(identity),
            timeout=5,
        )
        try:
            c.request("POST", "/v1/score", body=b"{}")
            r = c.getresponse()
            return r.status, r.read()
        finally:
            c.close()

    def test_only_detection_svc(self):
        self.assertEqual(self.call("detection-svc"), (200, b"scored"))
        # The server sees the client's SPIFFE ID; check the client sees the server's too.
        s = ssl.create_connection(("127.0.0.1", self.srv.server_address[1]))
        with client_ctx("detection-svc").wrap_socket(s) as tls:
            self.assertEqual(
                mtls.spiffe_id(tls.getpeercert()),
                "spiffe://aisec.bank/ns/aisec/sa/model-inference",
            )
        for identity in ["siem-export", None, "foreign-detection-svc"]:
            with (
                self.subTest(identity=identity),
                self.assertRaises((ssl.SSLError, OSError, http.client.HTTPException)),
            ):
                self.call(identity)

    def test_servers_refuse_to_run_open(self):
        env = {
            k: os.environ.pop(k)
            for k in ("MTLS_DIR", "MTLS_INSECURE", "MTLS_ALLOW")
            if k in os.environ
        }
        self.addCleanup(os.environ.update, env)
        with self.assertRaises(SystemExit):
            mtls.servers(Model)
        os.environ["MTLS_DIR"] = str(PKI / "model-inference")
        self.addCleanup(os.environ.pop, "MTLS_DIR", None)
        with self.assertRaises(SystemExit):  # no MTLS_ALLOW
            mtls.servers(Model)


if __name__ == "__main__":
    unittest.main()
