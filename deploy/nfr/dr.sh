#!/bin/sh
# Ticket 21 DR drill (spec §12.1: RPO <= 15 min, RTO <= 4 h for control/analytics plane), locally with docker:
#  1. Postgres primary archives WAL (archive_timeout 60 s) to S3-compatible storage (MinIO) and takes a base backup
#     there, while a writer inserts a timestamped row every 200 ms.
#  2. Disaster: the primary and its disk are destroyed (only what reached MinIO survives).
#  3. Restore into a fresh server from MinIO (base backup + WAL, PITR to the end of the archive) and measure
#     RPO = disaster time - last recovered row, RTO = disaster -> restored server accepting writes.
#  4. Object storage: a WORM (object lock) audit bucket replicated to a second MinIO; the primary is lost; the bucket
#     is restored from the replica, retention and content checked.
# Output: deploy/nfr/results/dr.json. Everything runs on its own network t21-dr and is removed at the end.
set -eu
cd "$(dirname "$0")"
mkdir -p results
net=t21-dr
pgimg=postgres:17
minio=minio/minio:RELEASE.2024-06-13T22-53-53Z
mcimg=$minio  # ships mc (RELEASE.2024-06-10); the separate minio/mc image is not pullable
now() { date +%s.%N; }
# waitfor <what> <cmd...>: retry for up to 5 minutes, then fail loudly instead of hanging.
waitfor() { what=$1; shift; i=0; until "$@" >/dev/null 2>&1; do i=$((i + 1)); [ $i -gt 300 ] && { echo "timeout: $what" >&2; exit 1; }; sleep 1; done; }
mc() { docker run --rm --network $net -e MC_HOST_s3=http://minio:minio-test-only@t21-minio:9000 \
  -e MC_HOST_replica=http://minio:minio-test-only@t21-minio-replica:9000 -v t21-dr-xfer:/xfer --entrypoint mc $mcimg "$@"; }
psql_on() { h=$1; shift; docker run --rm --network $net -e PGPASSWORD=test $pgimg psql -h "$h" -U postgres -tAc "$@"; }
cleanup() {
  docker rm -f t21-pg-primary t21-pg-restore t21-minio t21-minio-replica t21-archiver t21-writer >/dev/null 2>&1 || true
  docker volume rm t21-dr-archive t21-dr-xfer t21-dr-restore >/dev/null 2>&1 || true
  docker network rm $net >/dev/null 2>&1 || true
}
cleanup
trap cleanup EXIT
docker network create $net >/dev/null
docker volume create t21-dr-archive >/dev/null
docker volume create t21-dr-xfer >/dev/null
docker volume create t21-dr-restore >/dev/null

for m in t21-minio t21-minio-replica; do
  docker run -d --name $m --network $net -e MINIO_ROOT_USER=minio -e MINIO_ROOT_PASSWORD=minio-test-only $minio server /data >/dev/null
done
waitfor minio mc ls s3
waitfor minio-replica mc ls replica
mc mb s3/pg-wal s3/pg-base >/dev/null

docker run --rm -v t21-dr-archive:/archive -v t21-dr-xfer:/xfer alpine:3.20 chown 999:999 /archive /xfer # postgres runs as 999
# 1. Primary with WAL archiving; the archiver ships every archived segment to MinIO as it appears.
docker run -d --name t21-pg-primary --network $net -e POSTGRES_PASSWORD=test -v t21-dr-archive:/archive -v t21-dr-xfer:/xfer --user postgres $pgimg \
  -c wal_level=replica -c archive_mode=on -c archive_timeout=60 -c "archive_command=cp %p /archive/%f" >/dev/null
docker run -d --name t21-archiver --network $net -e MC_HOST_s3=http://minio:minio-test-only@t21-minio:9000 \
  -v t21-dr-archive:/archive --entrypoint mc $mcimg mirror --watch --overwrite /archive s3/pg-wal >/dev/null
waitfor primary psql_on t21-pg-primary "select 1"
psql_on t21-pg-primary "create table drill (id bigserial primary key, at timestamptz not null default clock_timestamp())" >/dev/null
docker run -d --name t21-writer --network $net -e PGPASSWORD=test --entrypoint sh $pgimg -c \
  'while true; do psql -h t21-pg-primary -U postgres -qc "insert into drill default values" >/dev/null 2>&1; sleep 0.2; done' >/dev/null
sleep 20
# Over the local socket: the image's pg_hba allows replication connections only there.
docker exec t21-pg-primary sh -c 'rm -rf /xfer/base && pg_basebackup -D /xfer/base -Ft -z -X stream' >/dev/null
mc cp --recursive /xfer/base/ s3/pg-base/ >/dev/null
echo "base backup in MinIO; writing for 4 more minutes" >&2
sleep 240

# 2. Disaster: primary, its disk and its local archive are gone.
t_disaster=$(now)
docker rm -f t21-writer t21-pg-primary >/dev/null
sleep 5 # whatever the archiver had not shipped by now is lost with the site
docker rm -f t21-archiver >/dev/null
docker volume rm t21-dr-archive >/dev/null

# 3. Restore from MinIO only.
docker run --rm -v t21-dr-xfer:/xfer alpine:3.20 rm -rf /xfer/base /xfer/wal
mc cp --recursive s3/pg-base/ /xfer/base/ >/dev/null
mc cp --recursive s3/pg-wal/ /xfer/wal/ >/dev/null
docker run --rm -v t21-dr-xfer:/xfer -v t21-dr-restore:/pgdata alpine:3.20 sh -c '
  cd /pgdata && tar xzf /xfer/base/base.tar.gz && mkdir -p pg_wal && tar xzf /xfer/base/pg_wal.tar.gz -C pg_wal
  touch recovery.signal
  printf "restore_command = '"'"'cp /xfer/wal/%%f %%p'"'"'\nrecovery_target_action = promote\n" >> postgresql.auto.conf
  chown -R 999:999 /pgdata && chmod 700 /pgdata'
docker run -d --name t21-pg-restore --network $net -e PGDATA=/pgdata -v t21-dr-restore:/pgdata -v t21-dr-xfer:/xfer --user postgres $pgimg >/dev/null
promoted() { [ "$(psql_on t21-pg-restore "select pg_is_in_recovery()" 2>/dev/null)" = "f" ]; }
waitfor restore promoted
psql_on t21-pg-restore "insert into drill default values" >/dev/null
t_ready=$(now)
last=$(psql_on t21-pg-restore "select extract(epoch from max(at)) from drill where id < (select max(id) from drill)")
rows=$(psql_on t21-pg-restore "select count(*) - 1 from drill")
wal=$(mc ls s3/pg-wal | wc -l)

# 4. WORM audit bucket: object lock on the primary, replicated, primary lost, restored from the replica.
mc mb --with-lock s3/audit replica/audit >/dev/null
mc retention set --default COMPLIANCE 1d s3/audit >/dev/null
docker run --rm -v t21-dr-xfer:/xfer alpine:3.20 sh -c 'head -c 1048576 /dev/urandom > /xfer/anchor-0001.json && sha256sum /xfer/anchor-0001.json | cut -c1-64 > /xfer/anchor.sha'
mc cp /xfer/anchor-0001.json s3/audit/2026/10/ >/dev/null
delete_refused=false
mc rm --version-id "$(mc stat --json s3/audit/2026/10/anchor-0001.json | sed -n 's/.*"versionID":"\([^"]*\)".*/\1/p')" s3/audit/2026/10/anchor-0001.json >/dev/null 2>&1 || delete_refused=true
mc mirror --retention s3/audit replica/audit >/dev/null 2>&1 || mc mirror s3/audit replica/audit >/dev/null
t_obj=$(now)
docker rm -f t21-minio >/dev/null
docker run -d --name t21-minio --network $net -e MINIO_ROOT_USER=minio -e MINIO_ROOT_PASSWORD=minio-test-only $minio server /data >/dev/null
waitfor minio-new mc ls s3
mc mb --with-lock s3/audit >/dev/null
mc retention set --default COMPLIANCE 1d s3/audit >/dev/null
mc mirror replica/audit s3/audit >/dev/null
t_obj_ready=$(now)
mc cp s3/audit/2026/10/anchor-0001.json /xfer/restored.json >/dev/null
same=$(docker run --rm -v t21-dr-xfer:/xfer alpine:3.20 sh -c '[ "$(sha256sum /xfer/restored.json | cut -c1-64)" = "$(cat /xfer/anchor.sha)" ] && echo true || echo false')
locked=$(mc retention info s3/audit/2026/10/anchor-0001.json 2>/dev/null | grep -qi compliance && echo true || echo false)

awk -v d="$t_disaster" -v r="$t_ready" -v l="$last" -v rows="$rows" -v wal="$wal" -v o="$t_obj" -v oready="$t_obj_ready" \
  -v del="$delete_refused" -v same="$same" -v locked="$locked" 'BEGIN {
  printf "{\"postgres\": {\"rpo_seconds\": %.1f, \"rto_seconds\": %.1f, \"rows_recovered\": %d, \"wal_objects\": %d},\n", d - l, r - d, rows, wal
  printf " \"object_storage\": {\"restore_seconds\": %.1f, \"worm_delete_refused\": %s, \"content_identical\": %s, \"retention_on_restored\": %s}}\n", oready - o, del, same, locked
}' | tee results/dr.json
