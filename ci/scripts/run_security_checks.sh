#!/usr/bin/env bash
set -euo pipefail

# Check image signature
IMAGE="${1:-}"
if [ -n "${IMAGE}" ]; then
  cosign verify "${IMAGE}" || { echo "cosign verify failed"; exit 2; }
fi

# Check RBAC via kubectl (if kubeconfig present)
if kubectl version --short >/dev/null 2>&1; then
  kubectl auth can-i get pods --as=system:serviceaccount:app:backend-sa -n app || echo "RBAC check failed"
fi
