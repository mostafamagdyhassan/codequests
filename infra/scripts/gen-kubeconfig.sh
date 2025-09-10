#!/usr/bin/env bash
set -euo pipefail

ENV="${1:-dev}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TF_DIR="$ROOT/terraform/envs/$ENV"

pushd "$TF_DIR"
# Assumes terraform applied and module outputs cluster name & region
CLUSTER_NAME=$(terraform output -raw cluster_name)
REGION=$(terraform output -raw aws_region 2>/dev/null || echo "${AWS_REGION:-us-west-2}")
popd

echo "Updating kubeconfig for $CLUSTER_NAME in $REGION"
aws eks update-kubeconfig --name "$CLUSTER_NAME" --region "$REGION" --profile "$ENV"
# optional: set context name to <env>-<cluster>
kubectl config rename-context "arn:aws:eks:$REGION:$(aws sts get-caller-identity --query Account --output text --profile $ENV):cluster/$CLUSTER_NAME" "$ENV-$CLUSTER_NAME" || true
kubectl config use-context "$ENV-$CLUSTER_NAME"
