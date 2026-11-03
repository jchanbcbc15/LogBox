#!/usr/bin/env bash
# Copy shared + source config into ONE flat pipeline directory. Logstash loads files in
# filename order, so shared and source files must sit in the same directory to interleave.
set -euo pipefail
cd "$(dirname "$0")"
SRC=${1:-syslog}
rm -rf "run/$SRC/pipeline" && mkdir -p "run/$SRC/pipeline"
cp ../logstash/shared/*.conf "run/$SRC/pipeline/"
cp ../logstash/sources/"$SRC"/*.conf "run/$SRC/pipeline/"
ls "run/$SRC/pipeline"
