#!/bin/sh
# Ticket 21 NFR harness driver. From the repo root: deploy/nfr/run.sh up|down|nfr <args>
# Needs docker (compose v2); Go runs in the golang:1.25 image, nothing is installed on the host.
set -eu
cd "$(dirname "$0")"
root=$(cd ../.. && pwd)
gorun() { docker run --rm -v "$root":/src -w /src -e CGO_ENABLED=0 golang:1.25 "$@"; }
case "${1:-}" in
up)
  gorun go build -o deploy/nfr/.bin/nfr ./deploy/nfr/nfr
  rm -rf .bundle && mkdir .bundle
  gorun /src/deploy/nfr/.bin/nfr bundle -out /src/deploy/nfr/.bundle
  for s in ai-gateway detection-svc event-ingest; do
    docker build -q -t "t21-$s" --build-arg SERVICE="$s" -f "$root/build/go.Dockerfile" "$root" >/dev/null
  done
  docker compose up -d
  # The decision topic is created by the platform team in production (3 partitions, as internal/ingest's test);
  # without it every Emit waits its 2 s timeout in the request path.
  until docker exec t21-kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --create --if-not-exists \
    --topic aisec.decision_event.v1 --partitions 3 --replication-factor 1 >/dev/null 2>&1; do sleep 2; done
  until curl -fsS localhost:18080/healthz >/dev/null 2>&1; do sleep 2; done
  ;;
down) docker compose down -v ;;
nfr) shift; ./.bin/nfr "$@" ;;
*) echo "usage: $0 up|down|nfr <args>" >&2; exit 2 ;;
esac
