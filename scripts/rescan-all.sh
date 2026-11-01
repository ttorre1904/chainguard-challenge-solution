#!/usr/bin/env bash
# Re-scan every existing hello:<id>-<label> image today, with today's vulnerability databases.
set -euo pipefail
cd "$(dirname "$0")/.."
grype db update >/dev/null 2>&1 || true
for tag in $(docker images --format '{{.Tag}}' hello | grep -E '^[a-z][a-z]*-' | sort -V); do
  id=$(echo "$tag" | sed -E 's/^([a-z][a-z]*)-.*/\1/'); label=$(echo "$tag" | sed -E 's/^[a-z][a-z]*-//')
  ID="$(echo "${id:0:1}" | tr '[:lower:]' '[:upper:]')${id:1}"
  scripts/step.sh "$ID" "$label" -
done
scripts/summarize.sh