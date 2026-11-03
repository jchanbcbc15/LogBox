#!/usr/bin/env bash
# Show what is in the dead letter queue (DLQ) of one Logstash instance. Read only: it works on a COPY of the
# DLQ files, so the running instance is not touched and nothing is removed or replayed.
#
#   demo/dlq-inspect.sh <source-name>          e.g. demo/dlq-inspect.sh firewall
#   demo/dlq-inspect.sh <source-name> --size   only print the bytes of refused events (0 = empty)
#
# The DLQ lives in the Docker volume logbox-ls-<source-name>-data, in dead_letter_queue/main/.
set -euo pipefail
name="${1:?usage: $0 <source-name> [--size]}"
vol="logbox-ls-${name}-data"
img="${LOGSTASH_IMAGE:-docker.elastic.co/logstash/logstash:8.19.22}"

docker volume inspect "$vol" >/dev/null 2>&1 || { echo "No volume $vol (is the source '$name' deployed?)" >&2; exit 1; }

if [ "${2:-}" = "--size" ]; then
  # each segment file has a 1-byte header; anything beyond that is refused events
  docker run --rm -v "$vol":/d:ro --entrypoint sh "$img" -c \
    "find /d/dead_letter_queue -type f -name '*.log*' -exec wc -c {} + 2>/dev/null | grep -v ' total\$' | awk '{s+=(\$1>1?\$1-1:0)} END{print s+0}'"
  exit 0
fi

work="$(mktemp -d)"; copy="dlq-inspect-$$"
trap 'docker volume rm -f "$copy" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
docker volume create "$copy" >/dev/null
# copy the files (as the logstash user, uid 1000) into a throwaway volume
docker run --rm -u 0 -v "$vol":/from:ro -v "$copy":/to --entrypoint sh "$img" -c \
  'mkdir -p /to/dead_letter_queue && cp -a /from/dead_letter_queue/. /to/dead_letter_queue/ && chown -R 1000:1000 /to'

cat > "$work/read.conf" <<'EOF'
input  { dead_letter_queue { path => "/usr/share/logstash/data/dead_letter_queue" pipeline_id => "main" commit_offsets => false } }
output { stdout { codec => rubydebug { metadata => true } } }
EOF
echo "== entries in the DLQ of $name (each block is one refused event; the reason is in [@metadata][dead_letter_queue][reason]) =="
# The DLQ input keeps waiting for new entries and never ends by itself, so start the reader in the background,
# wait until its pipeline is running, give it a few seconds to print what is there, then stop it.
cname="dlq-reader-$$"
trap 'docker rm -f "$cname" >/dev/null 2>&1 || true; docker volume rm -f "$copy" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
docker run -d --name "$cname" -v "$work":/usr/share/logstash/pipeline:ro -v "$copy":/usr/share/logstash/data \
  -e XPACK_MONITORING_ENABLED=false "$img" >/dev/null
for _ in $(seq 1 60); do
  docker logs "$cname" 2>&1 | grep -q "Pipelines running" && break
  sleep 2
done
sleep 5
docker logs "$cname" 2>&1 | sed -n '/^{/,/^}/p'
echo "== end (no blocks above means the DLQ is empty) =="
