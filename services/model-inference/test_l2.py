import json
import os
import unittest

import app
import numpy as np
import l2

NAMES = ["O", "B-PII.NAME", "I-PII.NAME", "B-PII_ID.NIK", "I-PII_ID.NIK"]


class DecodeTest(unittest.TestCase):
    def test_byte_offsets(self):
        self.assertEqual(l2.byte_offsets("aé€b"), [0, 1, 3, 6, 7])

    def test_spans(self):
        # [CLS] Budi San ##toso NIK 3201 ##0115 [SEP]
        labels = [0, 1, 2, 2, 0, 3, 4, 0]
        probs = [1, 0.9, 0.8, 0.7, 1, 0.95, 0.85, 1]
        offs = [(0, 0), (0, 4), (5, 8), (8, 12), (13, 16), (17, 21), (21, 25), (0, 0)]
        self.assertEqual(
            [
                (t, a, b, round(c, 3))
                for t, a, b, c in l2.spans(labels, probs, offs, NAMES)
            ],
            [("PII.NAME", 0, 12, 0.8), ("PII_ID.NIK", 17, 25, 0.9)],
        )
        # An I- of another type starts a new span instead of extending.
        self.assertEqual(len(l2.spans([1, 4], [1, 1], [(0, 2), (3, 5)], NAMES)), 2)

    def test_merge_windows(self):
        found = [
            ("PII.NAME", 10, 20, 0.7),
            ("PII.NAME", 10, 22, 0.9),
            ("PII_ID.NIK", 30, 46, 0.8),
        ]
        self.assertEqual(
            l2.merge(found), [("PII.NAME", 10, 22, 0.9), ("PII_ID.NIK", 30, 46, 0.8)]
        )


class InjectionTest(unittest.TestCase):
    """The worst view counts; untrusted content also counts an instruction aimed at the AI (indirect type)."""

    def model(self, logits):
        m = l2.Model.__new__(l2.Model)
        m.version, m.tasks = "t", ["injection"]
        m.meta = {
            "injection": {
                "types": ["direct", "indirect"],
                "feature_mean": [0.0, 0.0],
                "feature_std": [1.0, 1.0],
                "weights": [1.0, 0.0],
                "bias": 0.0,
            }
        }
        m.lm = l2.TrigramLM({"tri": {}, "ctx": {}, "v": 300})
        m._run = lambda text: (None, None, np.array([logits[text]]))
        return m

    def test_views_and_trust(self):
        m = self.model({"plain": [-4.0, -9.0, 2.0], "decoded": [3.0, 0.0, -9.0]})
        self.assertLess(m.analyze("plain")["injection"]["score"], 0.05)
        r = m.analyze("plain", ["decoded"])["injection"]
        self.assertGreater(r["score"], 0.9)
        self.assertEqual(r["types"], ["direct"])
        self.assertGreater(
            m.analyze("plain", trust="untrusted")["injection"]["score"], 0.85
        )


class Stub:
    version = "stub"

    def analyze(self, text, views, trust):
        return {
            "model": self.version,
            "n": len(text),
            "views": len(views),
            "trust": trust,
        }


class APITest(unittest.TestCase):
    def setUp(self):
        app.MODEL = Stub()

    def tearDown(self):
        app.MODEL = None

    def test_validation(self):
        ok = app.analyze(
            json.dumps({"text": "halo", "views": ["x"], "trust": "untrusted"})
        )
        self.assertEqual(
            ok, (200, {"model": "stub", "n": 4, "views": 1, "trust": "untrusted"})
        )
        for bad in [
            "{",
            '{"views": []}',
            '{"text": 1}',
            '{"text": "a", "trust": "maybe"}',
            json.dumps({"text": "a", "views": ["v"] * 9}),
        ]:
            self.assertEqual(app.analyze(bad)[0], 400, bad)
        self.assertEqual(
            app.analyze(json.dumps({"text": "a" * (app.MAX_CONTENT + 1)}))[0], 400
        )


@unittest.skipUnless(
    os.environ.get("MODEL_DIR"), "MODEL_DIR not set (trained model not available)"
)
class ModelTest(unittest.TestCase):
    """With a trained model: a name and an identity number are found at the right byte offsets."""

    def test_entities(self):
        m = l2.Model(os.environ["MODEL_DIR"])
        text = "Mohon cek data nasabah Bambang Purnomo, NIK 3201011505900001, alamat Jl. Kartini No. 5, Malang."
        found = {
            (e["type"], text.encode()[e["start"] : e["end"]].decode())
            for e in m.analyze(text)["entities"]
        }
        self.assertIn(("PII_ID.NIK", "3201011505900001"), found)
        self.assertTrue(
            any(t == "PII.NAME" and "Bambang" in v for t, v in found), found
        )


if __name__ == "__main__":
    unittest.main()
