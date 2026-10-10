#!/bin/sh
# Ticket 21 §13.1 measurements against a running harness (run.sh up). Results: deploy/nfr/results/*.json.
# Overhead = the same load through the gateway minus straight to the mock provider.
set -eu
cd "$(dirname "$0")"
mkdir -p results
gw=http://localhost:18080/openai/v1/chat/completions
direct=http://localhost:19000/v1/chat/completions
nfr=./.bin/nfr
run() { name=$1; shift; echo "== $name" >&2; $nfr load -label "$name" "$@" | tee "results/$name.json"; }

# Warm up (JIT-free Go, but connection pools, Kafka producer metadata, OPA caches).
$nfr load -url $gw -rps 20 -d 15s >/dev/null

# Ramp: the highest open-loop rate one pod sustains without errors (30 s each, 1K tokens). RAMP_ONLY=1 stops here.
for r in 20 40 60 80 100; do
  run "ramp-${r}rps" -url $gw -rps $r -d 30s -tokens 1000
  sleep 10
done
[ "${RAMP_ONLY:-}" = 1 ] && exit 0
# ASM-2 peak (20 RPS), the realistic overhead.
run "direct-1000tok-20rps" -url $direct -rps 20 -d 60s -tokens 1000
run "gateway-1000tok-20rps" -url $gw -rps 20 -d 60s -tokens 1000
run "gateway-8000tok-20rps" -url $gw -rps 20 -d 60s -tokens 8000

# Latency at 100 RPS (5x the ASM-2 peak), prompts of ~1K and ~8K tokens.
for t in 1000 8000; do
  run "direct-${t}tok-100rps" -url $direct -rps 100 -d 60s -tokens $t
  run "gateway-${t}tok-100rps" -url $gw -rps 100 -d 60s -tokens $t
done
# Throughput of one pod (gateway 3 vCPU + OPA 1 vCPU): closed loop, 1K tokens.
run "gateway-1000tok-closed-c64" -url $gw -c 64 -d 60s -tokens 1000
run "gateway-1000tok-closed-c128" -url $gw -c 128 -d 60s -tokens 1000
# Streaming: 20 chunks 5 ms apart; per-window overhead = (gateway - direct) / windows.
run "direct-stream-20x5ms" -url $direct -rps 20 -d 60s -tokens 200 -stream
run "gateway-stream-20x5ms" -url $gw -rps 20 -d 60s -tokens 200 -stream
# Event -> OpenSearch (searchable).
echo "== events" >&2
$nfr events -url $gw -opensearch http://localhost:19200 -n 200 -gap 100ms | tee results/event-to-opensearch.json
