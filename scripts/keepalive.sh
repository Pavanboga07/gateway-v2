#!/usr/bin/env bash
# Keep the Render free-tier Gateway warm.
#
# Render suspends free web services after ~15 minutes without inbound
# traffic, and nothing running ON the service can prevent that (a
# suspended process runs no code). So this script pings the public
# /healthz endpoint from the OUTSIDE on a schedule (see
# .github/workflows/keepalive.yml, every 10 minutes). Any integer
# cadence under 15 minutes works; 10 leaves margin for one missed run.
#
# Usage:
#   scripts/keepalive.sh [https://your-gateway.onrender.com]
#
# Exit 0 when the Gateway answers {"status": ...}; non-zero otherwise
# (the scheduled workflow fails loudly so a real outage pages you
# instead of hiding behind a nap).
set -euo pipefail

BASE="${1:-${RENDER_GATEWAY_URL:-https://gateway-v2-ub7w.onrender.com}}"
URL="${BASE%/}/healthz"

for attempt in 1 2 3; do
  if body=$(curl -fsS --max-time 60 "$URL" 2>/dev/null); then
    echo "gateway warm: $body"
    exit 0
  fi
  echo "attempt $attempt: no answer from $URL; retrying..." >&2
  sleep 20
done

echo "gateway did not answer $URL after 3 attempts" >&2
exit 1
