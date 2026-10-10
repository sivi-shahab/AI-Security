#!/bin/sh
# Ticket 21 chaos against a running harness (run.sh up): each dependency is stopped while two apps send traffic,
# one fail_closed (nfr-app-key) and one fail_open (nfr-open-key), 30 RPS each, then restarted and checked again.
# Expected (spec §13.3): PDP down -> fail_closed refuses (503), fail_open forwards and counts fail_open_total; OPA
# restarted while the Policy Service is down -> last verified bundle from disk; Kafka/Redis down -> traffic keeps
# flowing. Results: deploy/nfr/results/chaos-*.json and chaos-summary.txt.
set -eu
cd "$(dirname "$0")"
mkdir -p results
gw=http://localhost:18080/openai/v1/chat/completions
nfr=./.bin/nfr
both() { # phase label: both apps for $2
  $nfr load -url $gw -key nfr-app-key -rps 30 -d "$2" -tokens 500 -label "$1-closed" > "results/chaos-$1-closed.json" &
  $nfr load -url $gw -key nfr-open-key -rps 30 -d "$2" -tokens 500 -label "$1-open" > "results/chaos-$1-open.json"
  wait
}
metric() { curl -s localhost:18080/metrics | awk -v m="$1" '$1 ~ "^"m {s += $2} END {print s + 0}'; }
summary=results/chaos-summary.txt
: > $summary
note() { echo "$*" | tee -a $summary; }
codes() { sed -n 's/.*"codes":\({[^}]*}\).*"achieved_rps":\([0-9.]*\).*"P95":\([0-9.]*\).*"P99":\([0-9.]*\).*/codes=\1 rps=\2 p95_ms=\3 p99_ms=\4/p' "results/chaos-$1.json"; }
errs() { docker logs --since "$1" t21-ai-gateway 2>&1 | grep -c "$2" || true; }

both baseline 20s
note "baseline closed: $(codes baseline-closed)"
note "baseline open:   $(codes baseline-open)"

# --- PDP (OPA sidecar) down -----------------------------------------------------------------------------------
fo0=$(metric aigw_fail_open_total)
docker stop t21-opa >/dev/null
both opa-down 30s
docker start t21-opa >/dev/null
note "opa down closed: $(codes opa-down-closed)"
note "opa down open:   $(codes opa-down-open)  fail_open_total +$(( $(metric aigw_fail_open_total) - fo0 ))"
sleep 5
both opa-back 15s
note "opa back closed: $(codes opa-back-closed)"

# --- OPA restarted while the Policy Service (bundle server) is down: persisted bundle -------------------------
docker stop t21-bundles >/dev/null
docker restart t21-opa >/dev/null
t0=$(date +%s)
until [ "$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer nfr-app-key' -H 'Content-Type: application/json' \
  -d '{"model":"m","messages":[{"role":"user","content":"halo"}]}' $gw)" = 200 ] || [ $(( $(date +%s) - t0 )) -gt 60 ]; do sleep 1; done
note "opa restarted without policy service: serving after $(( $(date +%s) - t0 )) s; $(docker logs t21-opa 2>&1 | grep -c 'Bundle loaded from disk\|loaded from disk' || true) disk-load log line(s)"
both opa-cached 15s
note "opa cached closed: $(codes opa-cached-closed)"
docker start t21-bundles >/dev/null

# --- Kafka down -----------------------------------------------------------------------------------------------
since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
docker stop t21-kafka >/dev/null
both kafka-down 30s
note "kafka down closed: $(codes kafka-down-closed)  event errors logged: $(errs "$since" 'decision event')"
note "kafka down open:   $(codes kafka-down-open)"
docker start t21-kafka >/dev/null
sleep 20
both kafka-back 15s
note "kafka back closed: $(codes kafka-back-closed)"

# --- Redis down -----------------------------------------------------------------------------------------------
since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
docker stop t21-redis >/dev/null
both redis-down 30s
note "redis down closed: $(codes redis-down-closed)  counter errors logged: $(errs "$since" 'counter unavailable\|quota')"
docker start t21-redis >/dev/null
sleep 5
both redis-back 15s
note "redis back closed: $(codes redis-back-closed)"

# --- detection-svc down: not on the gateway's path (L1 runs in-process) ---------------------------------------
docker stop t21-detection-svc >/dev/null
both detection-down 30s
note "detection-svc down closed: $(codes detection-down-closed)"
docker start t21-detection-svc >/dev/null
