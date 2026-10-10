"""Train the L2 model (tickets 09-10) on CPU and export it to ONNX int8.

One multilingual encoder (distilbert-base-multilingual-cased, Apache-2.0) with two heads: token labels for NER PII
(ticket 09) and a sequence head for prompt injection (binary + attack types, ticket 10). One forward pass serves
both, which is what keeps L2 inside its 50 ms p95 budget on CPU. --tasks ner trains the NER head only.

    python train.py --tasks ner,injection --out ../models/l2

Inputs (never the holdout): out/train.jsonl (evalcorpus train: train-only templates), out/public.jsonl
(fetch_public.py). Texts that also occur in data/eval/v1 are dropped. Output: model.onnx (int8), tokenizer.json,
model.json (labels, calibration, version), trigram.json (character LM for the perplexity feature).
"""

import argparse
import os
import collections
import hashlib
import json
import math
import random
from pathlib import Path

import numpy as np
import torch
from onnxruntime.quantization import QuantType, quantize_dynamic
from transformers import AutoModel, AutoTokenizer

BASE = "distilbert/distilbert-base-multilingual-cased"
BASE_REV = "45c032ab32cc946ad88a166f7cb282f58c753c2e"
ENTITIES = [
    "PII.NAME",
    "PII.ADDRESS",
    "PHI.DIAGNOSIS",
    "PII_ID.NIK",
    "PII_ID.KK",
    "PII_ID.NPWP",
    "PII_ID.PHONE",
    "PCI.PAN",
    "FIN.ACCOUNT",
]
LABELS = ["O"] + [p + e for e in ENTITIES for p in ("B-", "I-")]
TYPES = ["direct", "indirect", "role_confusion", "exfil_markdown", "suffix"]
TECHNIQUE_TYPE = {
    "direct": "direct",
    "roleplay": "direct",
    "multilingual": "direct",
    "indirect": "indirect",
    "role_confusion": "role_confusion",
    "exfil_markdown": "exfil_markdown",
    "suffix": "suffix",
}
MAX_LEN = 128
HERE = Path(__file__).parent
REPO = HERE.parents[2]


class L2(torch.nn.Module):
    def __init__(self, encoder):
        super().__init__()
        self.encoder = encoder
        h = encoder.config.hidden_size
        self.drop = torch.nn.Dropout(0.1)
        self.tokens = torch.nn.Linear(h, len(LABELS))
        self.seq = torch.nn.Linear(h, 1 + len(TYPES))

    def forward(self, input_ids, attention_mask):
        x = self.drop(
            self.encoder(
                input_ids=input_ids, attention_mask=attention_mask
            ).last_hidden_state
        )
        return self.tokens(x), self.seq(x[:, 0])


def jsonl(path):
    # split on "\n" only: str.splitlines() also breaks on U+2028 and friends inside JSON strings
    return [json.loads(line) for line in Path(path).read_text().split("\n") if line]


def holdout_texts():
    return {
        s["text"] for f in (REPO / "data/eval/v1").glob("*.jsonl") for s in jsonl(f)
    }


def byte_to_char(text, spans):
    pos, b = {}, 0
    for i, ch in enumerate(text):
        pos[b] = i
        b += len(ch.encode())
    pos[b] = len(text)
    return [(pos[s], pos[e], t) for s, e, t in spans]


def load(tasks):
    banned = holdout_texts()
    rows = []
    for s in jsonl(HERE / "out/train.jsonl"):
        if s["text"] in banned:
            continue
        ner = s["kind"] in (
            "pii",
            "benign",
        )  # injection texts carry unlabelled numbers and e-mails: no NER loss
        spans = byte_to_char(
            s["text"],
            [(e["start"], e["end"], e["type"]) for e in s.get("entities") or []],
        )
        typ = TECHNIQUE_TYPE.get(s.get("technique", ""), None) if s["attack"] else None
        rows.append(
            {
                "text": s["text"],
                "ner": ner,
                "spans": spans,
                "attack": s["attack"],
                "type": typ,
                "src": "synthetic",
                "group": s.get("template"),
            }
        )
    if "injection" in tasks:
        for s in jsonl(HERE / "out/public.jsonl"):
            if s["text"] not in banned:
                rows.append(
                    {
                        "text": s["text"],
                        "ner": False,
                        "spans": [],
                        "attack": s["attack"],
                        "type": None,
                        "src": s["source"],
                    }
                )
    else:
        rows = [r for r in rows if r["ner"]]
    random.Random(5).shuffle(rows)
    return rows


def encode(tok, rows):
    enc = tok(
        [r["text"] for r in rows],
        truncation=True,
        max_length=MAX_LEN,
        return_offsets_mapping=True,
    )
    out = []
    for i, r in enumerate(rows):
        offs = enc["offset_mapping"][i]
        labels = [-100] * len(offs)
        if r["ner"]:
            begun = set()
            for j, (a, b) in enumerate(offs):
                if a == b:
                    continue
                lab = "O"
                for k, (s, e, t) in enumerate(r["spans"]):
                    if a < e and b > s:
                        lab = ("I-" if k in begun else "B-") + t
                        begun.add(k)
                        break
                labels[j] = LABELS.index(lab)
        types = [-1.0] * len(TYPES)
        if r["type"]:
            types = [1.0 if t == r["type"] else 0.0 for t in TYPES]
        elif not r["attack"] and r["src"] == "synthetic":
            types = [0.0] * len(TYPES)
        out.append((enc["input_ids"][i], labels, float(r["attack"]), types))
    return out


def batches(data, size, shuffle):
    idx = list(range(len(data)))
    if shuffle:
        random.shuffle(idx)
    for k in range(0, len(idx), size):
        chunk = [data[i] for i in idx[k : k + size]]
        n = max(len(c[0]) for c in chunk)
        ids = torch.tensor([c[0] + [0] * (n - len(c[0])) for c in chunk])
        mask = torch.tensor([[1] * len(c[0]) + [0] * (n - len(c[0])) for c in chunk])
        labels = torch.tensor([c[1] + [-100] * (n - len(c[1])) for c in chunk])
        yield (
            ids,
            mask,
            labels,
            torch.tensor([c[2] for c in chunk]),
            torch.tensor([c[3] for c in chunk]),
        )


def losses(model, b, tasks, pos_weight):
    ids, mask, labels, attack, types = b
    tl, sl = model(ids, mask)
    loss = torch.tensor(0.0)
    if "ner" in tasks and (labels != -100).any():
        loss = loss + torch.nn.functional.cross_entropy(
            tl.reshape(-1, len(LABELS)), labels.reshape(-1), ignore_index=-100
        )
    if "injection" in tasks:
        loss = loss + torch.nn.functional.binary_cross_entropy_with_logits(
            sl[:, 0], attack, pos_weight=pos_weight
        )
        m = types >= 0
        if m.any():
            loss = loss + 0.5 * torch.nn.functional.binary_cross_entropy_with_logits(
                sl[:, 1:][m], types[m]
            )
    return loss


def ship(out):
    """fp32 ONNX + meta.partial.json -> int8 model.onnx + model.json, refused when int8 disagrees with fp32.

    Per-channel, reduced range, the two output heads kept in fp32: plain per-tensor int8 on AVX2 (no VNNI) saturates
    and scrambled the logits (50% token agreement), and quantized heads flip close calls. The fp32 file stays next to
    it (never shipped) so a release can be re-quantized without retraining (--requantize).
    """
    import onnx
    from tokenizers import Tokenizer

    meta = json.loads((out / "meta.partial.json").read_text())
    graph = onnx.load(str(out / "model.fp32.onnx")).graph
    heads = [
        n.name
        for n in graph.node
        if n.op_type == "MatMul" and ("tokens" in n.name or "seq" in n.name)
    ]
    quantize_dynamic(
        str(out / "model.fp32.onnx"),
        str(out / "model.onnx"),
        weight_type=QuantType.QInt8,
        op_types_to_quantize=["MatMul"],
        per_channel=True,
        reduce_range=True,
        nodes_to_exclude=heads,
    )
    tok = Tokenizer.from_file(str(out / "tokenizer.json"))
    tok.enable_truncation(MAX_LEN)
    texts = [s["text"] for s in jsonl(HERE / "out/train.jsonl")][::25][:300]
    agree = quantization_agreement(out, tok, texts)
    meta["int8_agreement"] = agree
    print(f"int8 vs fp32 agreement {agree}", flush=True)
    if agree["token_argmax"] < 0.99 or (
        "injection" in meta["tasks"] and agree["attack_decision"] < 0.99
    ):
        raise SystemExit("int8 model disagrees with fp32: not shipping it")
    digest = hashlib.sha256()
    for f in ("model.onnx", "tokenizer.json", "trigram.json"):
        digest.update((out / f).read_bytes())
    meta["sha256"] = digest.hexdigest()
    (out / "model.json").write_text(json.dumps(meta, indent=1))
    print("wrote", out, meta["sha256"])


def quantization_agreement(out, tok, texts):
    """Token argmax and attack decision (logit > 0) agreement of the int8 model with fp32 (training texts)."""
    import onnxruntime as ort

    f32 = ort.InferenceSession(str(out / "model.fp32.onnx"))
    q8 = ort.InferenceSession(str(out / "model.onnx"))
    tok_ok = tok_n = att_ok = 0
    for t in texts:
        ids = np.array([tok.encode(t).ids], dtype=np.int64)
        feed = {"input_ids": ids, "attention_mask": np.ones_like(ids)}
        (a, sa), (b, sb) = f32.run(None, feed), q8.run(None, feed)
        tok_ok += int((a.argmax(-1) == b.argmax(-1)).sum())
        tok_n += a.shape[1]
        att_ok += int((sa[0, 0] > 0) == (sb[0, 0] > 0))
    return {
        "token_argmax": round(tok_ok / tok_n, 4),
        "attack_decision": round(att_ok / len(texts), 4),
    }


def fit_temperature(logits, labels):
    """Temperature for the token softmax (Guo et al. 2017), by grid on dev NLL."""
    best = (1e9, 1.0)
    for t in np.arange(0.05, 5.01, 0.05):
        z = logits / t
        z = z - z.max(1, keepdims=True)
        nll = -(z[np.arange(len(labels)), labels] - np.log(np.exp(z).sum(1))).mean()
        best = min(best, (nll, float(t)))
    return best[1]


def platt(x, y, iters=3000, lr=0.1):
    """Logistic regression on features x (n, d) -> calibrated probability; returns weights + bias."""
    w, b = np.zeros(x.shape[1]), 0.0
    for _ in range(iters):
        p = 1 / (1 + np.exp(-(x @ w + b)))
        g = p - y
        w -= lr * (x.T @ g / len(y) + 1e-4 * w)
        b -= lr * g.mean()
    return w.tolist(), float(b)


# --- character trigram LM: the perplexity feature for GCG-style suffixes (FR-PSEC-4) --------------------------


def trigram_lm(texts):
    counts, ctx = collections.Counter(), collections.Counter()
    for t in texts:
        s = "\x02\x02" + t.lower()
        for i in range(2, len(s)):
            counts[s[i - 2 : i + 1]] += 1
            ctx[s[i - 2 : i]] += 1
    keep = {k: v for k, v in counts.items() if v >= 2}
    return {"tri": keep, "ctx": {k: v for k, v in ctx.items() if v >= 2}, "v": 300}


def perplexity(lm, text, window=48):
    """Highest per-character negative log-likelihood over windows: high where text stops being language."""
    s = "\x02\x02" + text.lower()
    nll = []
    for i in range(2, len(s)):
        c = lm["ctx"].get(s[i - 2 : i], 0)
        n = lm["tri"].get(s[i - 2 : i + 1], 0)
        nll.append(-math.log((n + 0.1) / (c + 0.1 * lm["v"])))
    if not nll:
        return 0.0
    if len(nll) <= window:
        return sum(nll) / len(nll)
    acc = sum(nll[:window])
    best = acc
    for i in range(window, len(nll)):
        acc += nll[i] - nll[i - window]
        best = max(best, acc)
    return best / window


def split_dev(rows):
    """Training rows first, dev after (returned cut). Dev gets whole templates the model never trains on, plus 10% of
    the rest: calibrating on templates seen in training would make every confidence look earned."""
    groups = sorted({r.get("group") for r in rows if r.get("group")})
    held = set(groups[::6])
    is_dev = [
        r.get("group") in held or (not r.get("group") and i % 10 == 0)
        for i, r in enumerate(rows)
    ]
    print(f"dev templates {sorted(held)}")
    return [r for r, d in zip(rows, is_dev) if not d] + [
        r for r, d in zip(rows, is_dev) if d
    ], len(rows) - sum(is_dev)


def calibrate(out):
    """Entity-level Platt scaling on the dev split's NER rows, decoded by the shipped int8 model as served (l2.py):
    the token temperature alone left the holdout entity ECE at 0.13 (pii-ner-1, first evaluation)."""
    import sys

    sys.path.insert(0, str(HERE.parent))
    import l2

    meta = json.loads((out / "model.json").read_text())
    meta.pop("entity_calibration", None)
    (out / "model.json").write_text(json.dumps(meta, indent=1))
    m = l2.Model(out)
    rows, cut = split_dev(load(meta["tasks"]))
    conf, ok = [], []
    for r in rows[cut:]:
        if not r["ner"]:
            continue
        bo = l2.byte_offsets(r["text"])
        gold = [(t, bo[s], bo[e]) for s, e, t in r["spans"]]
        wins, tl, _ = m._run(r["text"])
        for e in m.entities(r["text"], wins, tl, min_conf=0.0):
            conf.append(min(max(e["confidence"], 1e-6), 1 - 1e-6))
            ok.append(
                any(
                    t == e["type"] and e["start"] < b and a < e["end"]
                    for t, a, b in gold
                )
            )
    x = np.log(np.array(conf) / (1 - np.array(conf)))[:, None]
    w, b = platt(x, np.array(ok, dtype=float))
    after = 1 / (1 + np.exp(-(x[:, 0] * w[0] + b)))
    meta["entity_calibration"] = [w[0], b]
    meta["entity_calibration_dev"] = {
        "entities": len(ok),
        "precision": round(float(np.mean(ok)), 4),
        "ece_before": round(ece(np.array(conf), np.array(ok)), 4),
        "ece_after": round(ece(after, np.array(ok)), 4),
    }
    print(
        "entity calibration", meta["entity_calibration"], meta["entity_calibration_dev"]
    )
    (out / "model.json").write_text(json.dumps(meta, indent=1))


def ece(conf, ok, bins=10):
    k = np.minimum((conf * bins).astype(int), bins - 1)
    return float(
        sum(
            abs(ok[k == i].mean() - conf[k == i].mean()) * (k == i).sum()
            for i in range(bins)
            if (k == i).any()
        )
        / len(conf)
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tasks", default="ner,injection")
    ap.add_argument("--out", default=str(REPO / "services/model-inference/models/l2"))
    ap.add_argument("--epochs", type=float, default=2)
    ap.add_argument("--version", default="l2-1")
    ap.add_argument("--layers", type=int, default=3)
    ap.add_argument(
        "--requantize",
        action="store_true",
        help="only re-run quantization + gate on --out",
    )
    ap.add_argument(
        "--calibrate",
        action="store_true",
        help="only re-fit entity calibration on --out",
    )
    a = ap.parse_args()
    if a.calibrate:
        calibrate(Path(a.out))
        return
    if a.requantize:
        ship(Path(a.out))
        return
    tasks = a.tasks.split(",")
    torch.manual_seed(5)
    random.seed(5)
    torch.set_num_threads(int(os.environ.get("THREADS", "8")))

    tok = AutoTokenizer.from_pretrained(BASE, revision=BASE_REV)
    encoder = AutoModel.from_pretrained(BASE, revision=BASE_REV)
    # CPU budget (training here and the 50 ms p95 at serving): the first --layers transformer layers, word embeddings
    # frozen (92M of the 134M parameters; pretrained multilingual vocabulary kept as is).
    encoder.transformer.layer = encoder.transformer.layer[: a.layers]
    encoder.config.n_layers = a.layers
    encoder.embeddings.word_embeddings.weight.requires_grad_(False)
    model = L2(encoder)
    rows, cut = split_dev(load(tasks))
    train, dev = encode(tok, rows[:cut]), encode(tok, rows[cut:])
    pos = sum(r[2] for r in train)
    pos_weight = torch.tensor((len(train) - pos) / max(pos, 1))
    print(f"train {len(train)} dev {len(dev)} attacks {pos:.0f}", flush=True)

    opt = torch.optim.AdamW(
        [p for p in model.parameters() if p.requires_grad], lr=6e-5, weight_decay=0.01
    )
    steps = int(math.ceil(len(train) / 16) * a.epochs)
    sched = torch.optim.lr_scheduler.LambdaLR(
        opt, lambda s: min(1.0, (s + 1) / 100) * max(0.0, 1 - s / steps)
    )
    model.train()
    step = 0
    while step < steps:
        for b in batches(train, 16, True):
            loss = losses(model, b, tasks, pos_weight)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            opt.zero_grad()
            step += 1
            if step % 10 == 0:
                print(f"step {step}/{steps} loss {loss.item():.4f}", flush=True)
            if step >= steps:
                break

    # Calibration on dev (never the holdout): token temperature, and Platt over [logit, perplexity] for injection.
    model.eval()
    tok_logits, tok_labels, seq_z, seq_y, ppl, type_z, type_y = (
        [],
        [],
        [],
        [],
        [],
        [],
        [],
    )
    dev_rows = rows[cut:]
    lm = trigram_lm([r["text"] for r in rows[:cut] if not r["attack"]])
    with torch.no_grad():
        k = 0
        for b in batches(dev, 32, False):
            tl, sl = model(b[0], b[1])
            m = b[2] != -100
            tok_logits.append(tl[m].numpy())
            tok_labels.append(b[2][m].numpy())
            seq_z += sl[:, 0].tolist()
            seq_y += b[3].tolist()
            for i in range(len(b[0])):
                ppl.append(perplexity(lm, dev_rows[k + i]["text"]))
                if (b[4][i] >= 0).all() and b[3][i] > 0:
                    type_z.append(sl[i, 1:].numpy())
                    type_y.append(b[4][i].numpy())
            k += len(b[0])
    meta = {
        "version": a.version,
        "base": BASE,
        "base_revision": BASE_REV,
        "layers": a.layers,
        "max_len": MAX_LEN,
        "labels": LABELS,
        "tasks": tasks,
    }
    if "ner" in tasks:
        tl, ty = np.concatenate(tok_logits), np.concatenate(tok_labels)
        meta["ner_temperature"] = fit_temperature(tl, ty)
        acc = (tl.argmax(1) == ty).mean()
        print(f"dev token accuracy {acc:.4f} T={meta['ner_temperature']:.2f}")
    if "injection" in tasks:
        x = np.stack([np.array(seq_z), np.array(ppl)], 1)
        mu, sd = x.mean(0), x.std(0) + 1e-6
        w, bias = platt((x - mu) / sd, np.array(seq_y))
        meta["injection"] = {
            "types": TYPES,
            "feature_mean": mu.tolist(),
            "feature_std": sd.tolist(),
            "weights": w,
            "bias": bias,
        }
        if type_z:
            tz, tyy = np.stack(type_z), np.stack(type_y)
            meta["injection"]["type_temperature"] = [
                fit_temperature(
                    np.stack([-tz[:, j], tz[:, j]], 1) / 2, tyy[:, j].astype(int)
                )
                for j in range(len(TYPES))
            ]
        print(f"dev platt w={w} b={bias:.3f}")

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    tok.backend_tokenizer.save(str(out / "tokenizer.json"))
    (out / "trigram.json").write_text(json.dumps(lm))
    ids = torch.tensor([tok("Halo, nama saya Budi.")["input_ids"]])
    torch.onnx.export(
        model,
        (ids, torch.ones_like(ids)),
        str(out / "model.fp32.onnx"),
        input_names=["input_ids", "attention_mask"],
        output_names=["token_logits", "seq_logits"],
        dynamic_axes={
            "input_ids": {0: "b", 1: "t"},
            "attention_mask": {0: "b", 1: "t"},
            "token_logits": {0: "b", 1: "t"},
            "seq_logits": {0: "b"},
        },
        opset_version=17,
    )
    (out / "meta.partial.json").write_text(json.dumps(meta, indent=1))
    ship(out)
    if "ner" in tasks:
        calibrate(out)


if __name__ == "__main__":
    main()
