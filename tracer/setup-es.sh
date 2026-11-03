#!/usr/bin/env bash
# Install the index templates before any data is written. The templates name the metadata namespace as
# {{ metadata_namespace }} (Ansible renders it); here it is replaced with METADATA_NS, default org.
set -euo pipefail
cd "$(dirname "$0")"
source .env
for t in logs-logbox logs-rejects; do
  printf "template %s: " "$t"
  curl -s -u "elastic:$ES_PASSWORD" -H 'Content-Type: application/json' \
    -X PUT "http://127.0.0.1:9200/_index_template/$t" \
    --data-binary "$(sed "s/{{ metadata_namespace }}/${METADATA_NS:-org}/g" "../elasticsearch/templates/$t.json")"
  echo
done
