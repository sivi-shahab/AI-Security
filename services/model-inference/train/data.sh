#!/bin/sh
# Generates the L2 training data and the derived holdout NER gold into train/out (run from the repo root, with Go).
set -eu
out=services/model-inference/train/out
mkdir -p "$out"
go run ./cmd/evalcorpus train -seed 7 -n 3000 > "$out/train.jsonl"
go run ./cmd/evalcorpus nergold -dir data/eval/v1 > "$out/holdout-ner.jsonl"
wc -l "$out"/*.jsonl
