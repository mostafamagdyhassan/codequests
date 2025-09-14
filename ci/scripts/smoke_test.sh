#!/usr/bin/env bash
set -euo pipefail

ENDPOINT="${1:-http://localhost:8000}"

# simple healthcheck
status=$(curl -s -o /dev/null -w "%{http_code}" ${ENDPOINT}/listTasks || true)
if [ "${status}" != "200" ]; then
  echo "smoke test failed: ${status}"
  exit 1
else
  echo "smoke test OK"
fi
