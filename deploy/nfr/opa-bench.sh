#!/bin/sh
# Ticket 21: OPA decision cost as spec §13.1 asks (opa bench), on 1 vCPU like the sidecar, plus a profile of the
# most expensive expressions. Needs the signed bundle from run.sh up. Output: results/opa-bench.txt.
set -eu
cd "$(dirname "$0")"
opa() { docker run --rm --cpus=1 -v "$PWD/.bundle":/b:ro -v "$PWD/config":/c:ro openpolicyagent/opa:1.21.1-static "$@"; }
{
  opa bench --bundle /b/aisec.tar.gz --input /c/opa-input.json --count 1 'data.aisec.decision.result' |
    grep -E 'samples|ns/op|query_eval_ns_(median|90%|95%|99%|max)'
  echo "--- profile (top expressions by time)"
  opa eval --bundle /b/aisec.tar.gz --input /c/opa-input.json --profile --profile-limit 10 --format pretty \
    'data.aisec.decision.result' | grep -E '^[|│] *[0-9.]+[µm]?s ' | head -10 | cut -c1-160
} | tee results/opa-bench.txt
