#!/usr/bin/env bash
set -euo pipefail

ENV="${1:-dev}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TF_DIR="$ROOT/terraform/envs/$ENV"

if [ ! -d "$TF_DIR" ]; then
  echo "Env $ENV not found in terraform/envs"
  exit 1
fi

pushd "$TF_DIR"
export TF_VAR_aws_profile="${ENV}"
# Optional: Set TF_VAR_aws_region by reading tfvars or env
terraform init
terraform apply -auto-approve
# Wait for outputs
CLUSTER_NAME=$(terraform output -raw cluster_name)
REGION=$(terraform output -raw region 2>/dev/null || echo "${AWS_REGION:-us-west-2}")
popd

# generate kubeconfig
"$ROOT/scripts/gen-kubeconfig.sh" "$ENV"

# Install helm add-ons
echo "Installing helm add-ons..."
kubectl config use-context "$CLUSTER_NAME" || true
# you can call helm installs here, or separate script
"$ROOT/scripts/install-addons.sh" "$ENV" || true
