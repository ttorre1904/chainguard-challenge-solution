#!/usr/bin/env bash
# Usage: scripts/runtime-profile.sh <ID> <image> [extra docker run flags...]
set -euo pipefail
LABEL="${1:?ID e.g. F}"; IMG="${2:?image}"; shift 2
cd "$(dirname "$0")/.."; mkdir -p evidence
NAME="rp-$LABEL"; OUT="evidence/$LABEL.runtime.txt"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p 8080:8080 "$@" "$IMG" >/dev/null
sleep 2
PID=$(docker inspect -f '{{.State.Pid}}' "$NAME")
{
  echo "label: $LABEL   image: $IMG   date: $(date -u +%FT%TZ)"
  echo "extra docker run flags: $*"
  echo "--- endpoint";  curl -s -o /dev/null -w 'HTTP %{http_code}\n' http://localhost:8080/; curl -s http://localhost:8080/; echo
  echo "--- configured user: '$(docker inspect -f '{{.Config.User}}' "$NAME")' (empty = image default)"
  echo "--- docker host config"
  docker inspect -f 'ReadonlyRootfs={{.HostConfig.ReadonlyRootfs}} CapDrop={{.HostConfig.CapDrop}} SecurityOpt={{.HostConfig.SecurityOpt}} Memory={{.HostConfig.Memory}} PidsLimit={{.HostConfig.PidsLimit}} NanoCpus={{.HostConfig.NanoCpus}}' "$NAME"
  echo "--- what the Linux kernel says about the app process (host PID $PID)"
  sudo grep -E '^(Uid|Gid|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs|Seccomp):' "/proc/$PID/status"
  echo "--- shell exec attempt"
  docker exec "$NAME" sh -c 'echo shell works' 2>&1 | head -n 2 || true
  echo "--- time to stop (graceful SIGTERM handling)"
  ( time docker stop "$NAME" >/dev/null ) 2>&1 | grep real
} | tee "$OUT"
docker rm -f "$NAME" >/dev/null 2>&1 || true