#!/usr/bin/env bash
# Usage: scripts/step.sh <ID> <label> <dockerfile|-> [docker build args...]
#   scripts/step.sh A baseline Dockerfile.single --build-arg GO_VERSION=1.18
#   scripts/step.sh Eapko melange -      # "-" = skip the build; scan an image that already exists
set -euo pipefail
trap 'echo "!! step.sh stopped at line $LINENO while running: $BASH_COMMAND" >&2' ERR

ID="${1:?id, e.g. A}"; LABEL="${2:?label}"; DF="${3:?dockerfile or -}"; shift 3
cd "$(dirname "$0")/.."
for t in docker jq syft grype trivy go govulncheck; do
  command -v "$t" >/dev/null || { echo "!! missing tool: $t (install it first; see Phase 4)" >&2; exit 1; }
done
LID=$(echo "$ID" | tr '[:upper:]' '[:lower:]')
IMG="hello:${LID}-${LABEL}"; E="evidence/${ID}"; mkdir -p evidence/bin

if [ "$DF" != "-" ]; then
  echo "==> [$ID] cold build (no cache): $IMG"
  t0=$(date +%s); docker build --provenance=false --no-cache -f "docker/$DF" -t "$IMG" "$@" go/; t1=$(date +%s)
  echo "==> [$ID] warm build (everything cached)"
  docker build --provenance=false -f "docker/$DF" -t "$IMG" "$@" go/ >/dev/null; t2=$(date +%s)
  { echo "cold_build_s=$((t1-t0))"; echo "warm_build_s=$((t2-t1))"
    echo "cmd: docker build --provenance=false -f docker/$DF -t $IMG $* go/"; } > "$E.build.txt"
fi

echo "==> [$ID] image properties"
syft "$IMG" -o json > "$E.syft.json" 2> "$E.syft.log"
{ echo "image: $IMG"
  echo "image_id: $(docker image inspect -f '{{.Id}}' "$IMG")   # local image ID; the registry digest exists only after a push"
  echo "size_bytes: $(docker image inspect -f '{{.Size}}' "$IMG")"
  echo "layers: $(docker image inspect -f '{{len .RootFS.Layers}}' "$IMG")"
  echo "user: '$(docker image inspect -f '{{.Config.User}}' "$IMG")'  (empty = root)"
  echo "entrypoint: $(docker image inspect -f '{{json .Config.Entrypoint}}' "$IMG")  cmd: $(docker image inspect -f '{{json .Config.Cmd}}' "$IMG")"
  if docker run --rm --entrypoint sh "$IMG" -c true >/dev/null 2>&1; then echo "shell_present: yes"; else echo "shell_present: no"; fi
  echo "syft_total_packages: $(jq '.artifacts|length' "$E.syft.json")"
  echo "syft_os_packages: $(jq '[.artifacts[]|select(.type=="deb" or .type=="apk" or .type=="rpm")]|length' "$E.syft.json")"
  echo "libc_packages: $(jq -r '[.artifacts[]|select(.name|test("^(libc6|musl|glibc)$"))|.name]|unique|join(",")' "$E.syft.json")"
} > "$E.props.txt"
echo "   $(grep -E '^(size_bytes|layers|user|shell_present|syft_total_packages|syft_os_packages):' "$E.props.txt" | tr '\n' ' ')"

echo "==> [$ID] vulnerability databases"
grype db update > "$E.db-update.log" 2>&1 || echo "   (grype db update reported a problem; see $E.db-update.log)"

echo "==> [$ID] scans"
# Informational commands must never abort the run: '|| true' on the producer, 'sed -n' instead of 'head'.
{ echo "date_utc: $(date -u +%FT%TZ)"; echo "image: $IMG"
  echo "--- grype version";   { grype version 2>&1 || true; }   | sed -n '1,4p'
  echo "--- grype db status"; { grype db status 2>&1 || true; } | sed -n '1,8p'
  echo "--- trivy version";   { trivy --version 2>&1 || true; } | sed -n '1,4p'
  echo "cmd: grype $IMG -o json > $E.grype.json"
  echo "cmd: trivy image --quiet --format json --output $E.trivy.json $IMG"
} > "$E.scan-meta.txt"

if ! grype "$IMG" -o json > "$E.grype.json" 2> "$E.grype.log"; then
  echo "!! grype failed. Last lines of $E.grype.log:" >&2; tail -n 20 "$E.grype.log" >&2; exit 1
fi
[ -s "$E.grype.json" ] || { echo "!! grype wrote an empty file; see $E.grype.log" >&2; exit 1; }
if ! trivy image --quiet --format json --output "$E.trivy.json" "$IMG" 2> "$E.trivy.log"; then
  echo "!! trivy failed. Last lines of $E.trivy.log:" >&2; tail -n 20 "$E.trivy.log" >&2; exit 1
fi
[ -s "$E.trivy.json" ] || { echo "!! trivy wrote an empty file; see $E.trivy.log" >&2; exit 1; }
echo "   findings: grype=$(jq '(.matches // []) | length' "$E.grype.json")  trivy=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$E.trivy.json")"

echo "==> [$ID] Go build info and reachability (binary mode)"
BIN="evidence/bin/${ID}-hello-server"; rm -f "$BIN"
cid=$(docker create "$IMG")
for p in /hello-server /app/hello-server /usr/bin/hello-server; do
  if docker cp "$cid:$p" "$BIN" >/dev/null 2>&1; then break; fi
done
docker rm "$cid" >/dev/null
if [ -f "$BIN" ]; then
  go version -m "$BIN" > "$E.buildinfo.txt" || true
  govulncheck -mode=binary "$BIN" > "$E.govulncheck-binary.txt" 2>&1 || true
  echo "   $(sed -n '1p' "$E.buildinfo.txt")"
else
  echo "   (no hello-server binary found in the image at the usual paths; skipping govulncheck binary mode)"
fi
echo "==> [$ID] done. Evidence written:"; ls -1 "$E".* | sed 's/^/   /'
echo "    Next: scripts/summarize.sh"
