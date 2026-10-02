import io
import logging
import unittest

import app

SECRET = "NIK 3171234567890001"


class PrivacyTest(unittest.TestCase):
    def test_forbidden_fields_never_logged(self):
        buf = io.StringIO()
        h = logging.StreamHandler(buf)
        h.setFormatter(app.JSONFormatter())
        log = logging.getLogger("privacy-test")
        log.addHandler(h)
        log.propagate = False

        for key in app.FORBIDDEN:
            log.warning("x", extra={key: SECRET})
            log.warning("x", extra={key.upper(): SECRET})
        log.warning("ok", extra={"decision_id": "d-1"})

        out = buf.getvalue()
        self.assertNotIn(SECRET, out)
        self.assertIn('"decision_id": "d-1"', out)
        self.assertGreaterEqual(len(app.FORBIDDEN), 5)


if __name__ == "__main__":
    unittest.main()
