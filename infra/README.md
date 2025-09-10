# Infra: EKS + VPC Terraform (dev & prod) + Local alternatives

## What this repo contains
- Terraform modules to create:
  - VPC (public & private subnets, NAT GW, route tables)
  - EKS cluster (managed nodegroups or managed EC2/managed node groups)
- Environment folders for `dev` and `prod` (separate accounts/regions via AWS profiles)
- Scripts to deploy/destroy and to fetch kubeconfig
- Helm-based installation steps (via scripts) for core add-ons:
  - AWS VPC CNI (comes with EKS AMI / addon)
  - AWS EBS CSI driver
  - Metrics Server
  - AWS Load Balancer Controller

> NOTE: This repo **does not** run Terraform for you. You must have AWS credentials & permissions.

---

## Design decisions & assumptions
- Multi-account separation: use separate Terraform runs (one per environment) using different AWS profiles and tfvars. This avoids trying to manage multiple accounts inside one state.
- Regions: `dev` and `prod` can be set to different AWS regions in `terraform.tfvars`.
- Add-ons: uses a mix of `aws_eks_addon` (where available) and `helm_release` via the Helm provider to install controllers not offered as addons.
- NodeGroups: uses managed node groups (EKS managed) for simplicity and cost predictability.
- Remote state: optional S3 backend can be enabled in `global/backend.tf`.

---

## Prerequisites
- Terraform >= 1.2
- AWS CLI (configured profiles for dev/prod)
- kubectl
- helm
- jq (used in scripts)
- AWS account(s) with permissions to create networking, EKS, IAM, EC2, etc.
- Optional: `eksctl` (not required)

---

## Quick start (high-level)
1. Set AWS CLI profiles:
   ```bash
   aws configure --profile dev
   aws configure --profile prod
