#!/bin/sh
# Ticket 21 soak against a running harness (run.sh up): RATE RPS (default 100 = 5x the ASM-2 peak) for DURATION
# (default 24h, the gate), per-minute p95/errors from the load generator and memory/CPU of every container each
# minute. Usage: DURATION=24h deploy/nfr/soak.sh   Results: deploy/nfr/results/soak-<duration>*.
set -eu
cd "$(dirname "$0")"
mkdir -p results
d=${DURATION:-24h}
rate=${RATE:-100}
stats=results/soak-$d-stats.tsv
printf 'time\tcontainer\tmem\tcpu\n' > "$stats"
( while true; do
    docker stats --no-stream --format "$(date -u +%H:%M:%S)\t{{.Name}}\t{{.MemUsage}}\t{{.CPUPerc}}" | grep t21- >> "$stats"
    sleep 60
  done ) &
sampler=$!
trap 'kill $sampler 2>/dev/null || true' EXIT
./.bin/nfr load -url http://localhost:18080/openai/v1/chat/completions -rps "$rate" -d "$d" -tokens 1000 -minutes \
  -label "soak-$d" > "results/soak-$d.json"
