"""L2 detection model (tickets 09-10): one ONNX int8 encoder, NER PII head and prompt-injection head.

Offsets in and out are UTF-8 byte offsets, like the Go detectors. Content is never logged.
"""

import json
import math
import os
from pathlib import Path

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer

STRIDE = 32
MAX_WINDOWS = 16  # ponytail: ~4k tokens analysed per text; the rest is L1 only. Raise with batching on GPU.
PPL_TAIL = 8192  # GCG-style suffixes sit at the end; the perplexity feature reads the last 8 KB
MIN_ENTITY = 0.5  # calibrated confidence an entity needs to be reported


def _softmax(z):
    z = z - z.max(-1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(-1, keepdims=True)


def _sigmoid(x):
    return 1 / (1 + math.exp(-x))


def byte_offsets(text):
    """out[i] = UTF-8 byte offset of character i (and of the end, at len(text))."""
    out, b = [0] * (len(text) + 1), 0
    for i, ch in enumerate(text):
        out[i] = b
        b += len(ch.encode())
    out[len(text)] = b
    return out


def spans(labels, probs, offsets, names):
    """BIO token labels -> [(type, char start, char end, confidence)]. probs: max class probability per token."""
    out, cur = [], None
    for lab, p, (a, b) in zip(labels, probs, offsets):
        if a == b:  # special or padding token
            continue
        name = names[lab]
        if name == "O":
            cur = None
            continue
        tag, typ = name[:1], name[2:]
        if tag == "I" and cur and cur[0] == typ:
            cur[2], cur[3] = b, cur[3] + [p]
            continue
        cur = [typ, a, b, [p]]
        out.append(cur)
    return [(t, a, b, sum(ps) / len(ps)) for t, a, b, ps in out]


def merge(found):
    """Overlapping windows report a span twice: keep one per overlapping same-type run, widest and most confident."""
    out = []
    for t, a, b, c in sorted(found, key=lambda x: (x[1], -x[2])):
        if out and out[-1][0] == t and a < out[-1][2]:
            pt, pa, pb, pc = out[-1]
            out[-1] = (t, pa, max(pb, b), max(pc, c))
        else:
            out.append((t, a, b, c))
    return out


class TrigramLM:
    """Character trigram LM over benign text: the perplexity feature for adversarial suffixes (FR-PSEC-4)."""

    def __init__(self, d):
        self.tri, self.ctx, self.v = d["tri"], d["ctx"], d["v"]

    def perplexity(self, text, window=48):
        s = "\x02\x02" + text[-PPL_TAIL:].lower()
        nll = []
        for i in range(2, len(s)):
            c, n = self.ctx.get(s[i - 2 : i], 0), self.tri.get(s[i - 2 : i + 1], 0)
            nll.append(-math.log((n + 0.1) / (c + 0.1 * self.v)))
        if not nll:
            return 0.0
        if len(nll) <= window:
            return sum(nll) / len(nll)
        acc = best = sum(nll[:window])
        for i in range(window, len(nll)):
            acc += nll[i] - nll[i - window]
            best = max(best, acc)
        return best / window


class Model:
    def __init__(self, path):
        path = Path(path)
        self.meta = json.loads((path / "model.json").read_text())
        self.version = f"{self.meta['version']}+{self.meta['sha256'][:12]}"
        self.tasks = self.meta["tasks"]
        self.labels = self.meta["labels"]
        self.tok = Tokenizer.from_file(str(path / "tokenizer.json"))
        self.tok.enable_truncation(self.meta["max_len"], stride=STRIDE)
        self.tok.no_padding()
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = int(os.environ.get("ORT_THREADS", "2"))
        opts.inter_op_num_threads = 1
        self.sess = ort.InferenceSession(
            str(path / "model.onnx"), opts, providers=["CPUExecutionProvider"]
        )
        self.lm = (
            TrigramLM(json.loads((path / "trigram.json").read_text()))
            if "injection" in self.tasks
            else None
        )

    def _run(self, text):
        e = self.tok.encode(text)
        wins = ([e] + list(e.overflowing))[:MAX_WINDOWS]
        n = max(len(w.ids) for w in wins)
        ids = np.zeros((len(wins), n), dtype=np.int64)
        mask = np.zeros((len(wins), n), dtype=np.int64)
        for i, w in enumerate(wins):
            ids[i, : len(w.ids)], mask[i, : len(w.ids)] = w.ids, 1
        tl, sl = self.sess.run(None, {"input_ids": ids, "attention_mask": mask})
        return wins, tl, sl

    def entity_confidence(self, c):
        """Mean token probability -> P(entity correct): Platt scaling fitted on entities of held-out templates."""
        cal = self.meta.get("entity_calibration")
        if not cal:
            return c
        c = min(max(c, 1e-6), 1 - 1e-6)
        return _sigmoid(cal[0] * math.log(c / (1 - c)) + cal[1])

    def entities(self, text, wins, tl, min_conf=MIN_ENTITY):
        probs = _softmax(tl / self.meta["ner_temperature"])
        found = []
        for i, w in enumerate(wins):
            k = len(w.ids)
            found += spans(
                probs[i, :k].argmax(-1), probs[i, :k].max(-1), w.offsets, self.labels
            )
        bo = byte_offsets(text)
        out = []
        for t, a, b, c in merge(found):
            c = self.entity_confidence(float(c))
            if c >= min_conf:
                out.append(
                    {"type": t, "start": bo[a], "end": bo[b], "confidence": round(c, 4)}
                )
        return out

    def injection(self, text, sl):
        inj = self.meta["injection"]
        i = int(sl[:, 0].argmax())
        ppl = self.lm.perplexity(text)
        x = (np.array([sl[i, 0], ppl]) - inj["feature_mean"]) / inj["feature_std"]
        score = _sigmoid(float(x @ np.array(inj["weights"]) + inj["bias"]))
        temps = inj.get("type_temperature") or [1.0] * len(inj["types"])
        types = {
            t: _sigmoid(float(sl[i, 1 + j]) / temps[j])
            for j, t in enumerate(inj["types"])
        }
        return score, types, ppl

    def analyze(self, text, views=(), trust="trusted"):
        """NER on the text as given (offsets refer to it); injection on the text and every decoded view, the worst
        one counting. Untrusted content (RAG, tool results, e-mail, web) also counts an instruction aimed at the AI
        inside data (the `indirect` type) as injection (FR-PSEC-2)."""
        out = {"model": self.version}
        wins, tl, sl = self._run(text)
        if "ner" in self.tasks:
            out["entities"] = self.entities(text, wins, tl)
        if "injection" in self.tasks:
            best = self.injection(text, sl) + (text,)
            for v in views:
                if v:
                    _, _, vsl = self._run(v)
                    r = self.injection(v, vsl) + (v,)
                    best = max(best, r, key=lambda r: r[0])
            score, types, ppl, _ = best
            if trust == "untrusted":
                score = max(score, types.get("indirect", 0.0))
            out["injection"] = {
                "score": round(score, 4),
                "types": sorted(t for t, p in types.items() if p >= 0.5),
                "type_scores": {t: round(p, 4) for t, p in types.items()},
                "perplexity": round(ppl, 3),
            }
        return out
