# codequests
3tier-app/
│── backend/
│   ├── app.py
│   ├── requirements.txt
│   └── Dockerfile
│
│── frontend/
│   ├── index.html
│   └── nginx.conf
│
│── k8s/
│   ├── backend-deployment.yaml
│   ├── backend-service.yaml
│   ├── frontend-deployment.yaml
│   ├── frontend-service.yaml
│   └── postgres-values.yaml  

helm repo add bitnami https://charts.bitnami.com/bitnami
helm install postgres bitnami/postgresql -f k8s/postgres-values.yaml


docker build -t your-dockerhub-username/backend ./backend
docker build -t your-dockerhub-username/frontend ./frontend
docker push your-dockerhub-username/backend
docker push your-dockerhub-username/frontend

helm install postgres bitnami/postgresql -f k8s/postgres-values.yaml


kubectl apply -f k8s/

minikube service frontend


docker compose up --build


Access:

Frontend → http://localhost:8080

Backend API → http://localhost:8000/docs
 (FastAPI auto-docs)

Postgres → localhost:5432 (user: admin, pass: admin, db: tasksdb)





Scaling Criteria

Target metric: CPU utilization

Threshold: Scale when average CPU usage across pods exceeds 50% of the requested CPU

Min pods: 1 (to save resources when idle)

Max pods: 5 (to limit runaway scaling)

Reasoning:

API workloads are bursty. CPU usage correlates well with request load.

FastAPI is async, but still CPU-bound when handling multiple requests.

Setting 50% threshold ensures we add pods before saturation.







kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml


PSA Restricted Key Points

Run as non-root (runAsNonRoot: true).

Disallow privilege escalation (allowPrivilegeEscalation: false).

Drop all capabilities (add only if needed).

Read-only root filesystem (recommended, not mandatory for this FastAPI app).

Non-root user ID (e.g., 1000).
How This Meets PSA “Restricted”

✅ Runs as non-root user (runAsNonRoot, USER appuser).

✅ No privilege escalation (allowPrivilegeEscalation: false).

✅ No Linux capabilities (drop: ALL).

✅ Read-only root filesystem (app only writes to mounted volumes if needed).










helm-chart/
│── Chart.yaml
│── values.yaml
│── templates/
│   ├── namespace.yaml
│   ├── backend-deployment.yaml
│   ├── backend-service.yaml
│   ├── backend-hpa.yaml
│   ├── frontend-deployment.yaml
│   ├── frontend-service.yaml
│   └── _helpers.tpl
│── charts/ (for dependencies like postgres)





helm dependency update ./helm-chart
helm install three-tier-app ./helm-chart







Edit terraform/envs/dev/terraform.tfvars and terraform/envs/prod/terraform.tfvars for region, cidr block, names.

Run the deploy script for dev:

./scripts/deploy.sh dev


Generate kubeconfig:

./scripts/gen-kubeconfig.sh dev
kubectl get nodes


Install add-ons (scripts will apply them).



erraform structure
terraform/global/providers.tf

sets AWS provider, region determined by env-level tfvars or AWS_PROFILE.

configures Helm provider but uses dynamic kubeconfig after cluster creation.

terraform/modules/vpc

creates:

VPC

public & private subnets (3 AZs recommended)

Internet Gateway + public route table

NAT Gateways (one per AZ or single NGW - configurable)

Security groups: eks-control-plane-sg, eks-node-sg with minimal rules

terraform/modules/eks

creates EKS cluster and managed nodegroup(s)

outputs the cluster name, endpoint, and cluster-iam-role ARN, nodegroup names

attaches IAM roles needed for add-ons (ALB controller, EBS CSI) via policies

Networking (high-level)

VPC CIDR and AZs configurable per env.

Private subnets are used for worker nodes (recommended).

Security Groups:

eks-control-plane-sg for control-plane to manage comms

eks-node-sg for nodes — allows inbound from control-plane and intra-node

postgres-sg (example if you deploy DB in VPC) — restrict access to backend instance/subnet.

Add-ons deployed

AWS VPC CNI: recommended to use aws_eks_addon or default EKS CNI (keeps networking stable)

EBS CSI driver: helm chart or aws_eks_addon depending on EKS version

Metrics Server: helm chart

AWS Load Balancer Controller: helm chart (requires IAM OIDC and IAM role for serviceAccount)

Scripts handle necessary IAM role creation for the ALB controller (IRSA).

IAM and OIDC (IRSA)

The Helm-installed controllers (ALB controller, EBS CSI) use IRSA. Terraform module creates OIDC provider for the cluster and IAM roles with proper policies (attached via AWS managed policies or policy documents provided).

How to deploy (automated)

Use scripts/deploy.sh <env>:

deploy.sh does:

terraform init and terraform apply in terraform/envs/<env>

waits for cluster creation outputs

runs scripts/gen-kubeconfig.sh <env>

installs Helm charts for add-ons (EBS CSI, metrics-server, aws-load-balancer-controller)

destroy.sh reverses the deploy.

Local Kubernetes alternatives (you said you lack credits)

If you don't want to incur AWS costs or don't have sufficient credits, you can test locally using:

k3s (lightweight, CNCF, production-capable), pros: very lightweight, CRI support, works well in VMs; cons: no cloud provider integrations by default.

microk8s (snap) pros: simple single-node, supports enable addons (ingress, storage, registry); cons: Ubuntu-friendly.

minikube pros: easy to get started with local Docker driver; cons: single-node, limited to host resources, no LB by default (minikube addons include a tunnel).

kind (Kubernetes in Docker) pros: great for CI, ephemeral clusters, fast; cons: single-node control-plane by default, limited storage class (hostPath), no LB out of box.

Trade-offs vs EKS

Load Balancer: EKS integrates with AWS ELB/ALB/NLB. Local clusters don't have cloud LBs; you must use NodePort, MetalLB (for LBs in local environment), or port-forwarding.

Persistent Storage: EKS + EBS provide dynamic storage via CSI. Local clusters may rely on hostPath or local PVs or need to install local-storage provisioner (e.g., microk8s has storage addon, k3s supports local-storage, kind supports hostPath provisioner).

IAM & IRSA: EKS uses IAM + OIDC IRSA. Impossible locally (no AWS IAM); controllers that expect cloud IAM will need mock/service-account RBAC or to run with full node permissions.

Autoscaling: HPA works locally; Cluster Autoscaler and NodeGroup autoscaling require cloud provider APIs — not available locally.

CNI: EKS uses AWS VPC CNI; local clusters typically use simpler CNIs (calico, flannel) — network behavior differs under load.

Cost & access: Local is free and great for dev/test; EKS offers production-grade HA, cloud native integrations.

Recommendation: For local testing of your Helm manifests and app, use k3d (k3s in docker) or microk8s + MetalLB (for testing LoadBalancer behavior) and a local storage class (or hostPath) for PVs. Documented steps below.

Scripts

./scripts/deploy.sh <env> - deploys terraform for the environment and runs post-install helm steps.

./scripts/destroy.sh <env> - destroys terraform infra for that environment.

./scripts/gen-kubeconfig.sh <env> - obtains cluster name & region from terraform outputs and runs aws eks update-kubeconfig.

./scripts/bootstrap.sh - installs CLI prerequisites (terraform, awscli, kubectl, helm) - optional helper.

Scripts assume AWS_PROFILE=<env> or --profile is used.

Next steps & customization

Add S3 remote state (in global/backend.tf) to protect states across users.

Replace managed nodegroups with Fargate or self-managed groups if desired.

Add CI (GitHub Actions / GitLab CI) to run terraform fmt, validate, and apply in a controlled pipeline.

Optionally add module tests (terratest).

Contact & support

If you want I can:

Drop the full terraform files (modules + envs) in this chat as ready-to-copy files.

Generate the scripts/ content tailored to your environment (e.g., set AWS_PROFILE mapping).



---

# Example Terraform files (essential excerpts)

Below are **concrete** files to copy into the structure above. They are minimal but complete enough to run after you set variables.

> NOTE: You should copy these into `infra/terraform/...` as shown in the layout.

---

## `terraform/global/versions.tf`
```hcl
terraform {
  required_version = ">= 1.2.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.0"
    }
  }
}



Helm Add-ons (post terraform)

After cluster exists and kubeconfig is configured (script handles this), scripts will:

Create IAM roles (IRSA) for the ALB controller and EBS CSI if not created by module.

Install AWS Load Balancer Controller via Helm:

helm repo add eks https://aws.github.io/eks-charts
helm repo update
helm upgrade --install aws-load-balancer-controller eks/aws-load-balancer-controller \
  --namespace kube-system \
  --set clusterName=$CLUSTER_NAME \
  --set serviceAccount.create=false \
  --set serviceAccount.name=aws-load-balancer-controller \
  --set region=$REGION


Install EBS CSI driver (if needed):

helm repo add aws-ebs-csi-driver https://kubernetes-sigs.github.io/aws-ebs-csi-driver
helm upgrade --install aws-ebs-csi-driver aws-ebs-csi-driver/aws-ebs-csi-driver --namespace kube-system


Install Metrics Server:

helm repo add bitnami https://charts.bitnami.com/bitnami
helm upgrade --install metrics-server bitnami/metrics-server --namespace kube-system


The exact Helm values may vary with chart versions. The scripts will pass cluster name




















