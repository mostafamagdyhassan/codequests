# codequests
This project demonstrates a complete DevSecOps pipeline for a simple 3-tier application consisting of:
1.	Frontend → A lightweight Nginx-based static web UI.
2.	Backend → A Python Flask/FastAPI REST API exposing endpoints:
o	POST /addTask
o	DELETE /deleteTask
o	GET /listTasks
3.	Database → PostgreSQL with hardened access (pg_hba.conf, secrets management).
The project integrates infrastructure as code, CI/CD, monitoring, observability, and security controls to simulate a real-world production-grade deployment.
________________________________________
Architecture
•	Local Development: Docker Compose integrates backend, frontend, Postgres, and monitoring (Prometheus, Grafana, Loki, Promtail, Alertmanager, Jaeger).
•	Kubernetes (Deployment):
o	Backend, frontend, Postgres deployed in app namespace.
o	Monitoring stack deployed in monitoring namespace.
o	NetworkPolicies restrict DB access to backend only.
o	HPA (Horizontal Pod Autoscaler) scales backend pods based on CPU/memory utilization.
o	Pod Security Admission ensures containers run as non-root.
o	Ingress routes traffic to frontend/backend.
•	Observability:
o	Prometheus scrapes app/DB metrics.
o	Grafana dashboards visualize CPU, memory, latency, and DB stats.
o	Loki + Promtail handle structured logs.
o	OpenTelemetry Collector + Jaeger provide distributed tracing across services.
________________________________________
Infrastructure (Terraform)
•	Dev environment:
o	Uses Minikube or MicroK8s for local clusters.
o	Lightweight and cost-free, but limited LoadBalancer support and storage options.
•	Prod environment:
o	Uses AWS EKS with Terraform modules for:
	VPC + Subnets (public & private).
	Security Groups, IAM roles, and RBAC.
	EKS cluster with node groups.
o	Terraform state stored in S3 with DynamoDB locking.
•	Modular Design:
o	modules/vpc for networking.
o	modules/eks for Kubernetes cluster provisioning.
________________________________________
Security (DevSecOps)
1.	Image Security
o	Docker images built via GitHub Actions.
o	Scanned with Trivy, Grype, and/or Snyk.
o	Signed with cosign to ensure provenance.
2.	Secrets Management
o	Secrets injected into Kubernetes via Secrets manifests (or AWS Secrets Manager in prod).
o	DB passwords, SMTP creds, and signing keys never stored in plain text.
3.	RBAC
o	Service accounts per namespace.
o	RoleBindings restrict backend to only required Kubernetes resources.
4.	Network Policies
o	Only backend pods can access Postgres.
o	No public network access to DB.
5.	Pod Security Admission
o	Backend, frontend, DB run as non-root users.
o	Capabilities dropped by default.
6.	Data Security
o	Encryption at rest → EKS-managed storage (EBS/RDS) encrypted with KMS.
o	Encryption in transit → TLS termination at Ingress + mTLS inside cluster (if enabled).
7.	DDoS/WAF
o	AWS WAF + Shield for prod (CloudFront/ALB integration).
o	Rate limiting + fail2ban at ingress level for local/dev.
________________________________________
 Monitoring & Alerts
•	Prometheus
o	Scrapes backend (Flask metrics), Postgres (pg_exporter), and node metrics.
o	Alert rules:
	High CPU (>80% for 5 mins).
	Pod restarts/crash loops.
	Postgres unavailable.
•	Alertmanager
o	Routes alerts via email (SMTP config).
o	Optionally extendable to Slack or webhooks.
•	Grafana
o	Dashboards for app latency, throughput, Postgres queries, and resource usage.
o	Logs + traces correlated with metrics.
•	Loki + Promtail
o	Collect logs from app containers and nodes.
o	Query logs via Grafana.
•	Jaeger + OpenTelemetry
o	Trace requests across frontend → backend → Postgres.
o	Helps detect slow queries, bottlenecks.
________________________________________
CI/CD Pipelines (GitHub Actions)
1. App Deployment Pipeline
•	Triggers on pull requests, commits to develop, and merges to main.
•	Steps:
1.	Checkout code.
2.	Run security scans (Trivy, Snyk).
3.	Run unit + smoke tests.
4.	Build Docker image, tag with Git SHA.
5.	Sign image with cosign.
6.	Push to GitHub Container Registry / AWS ECR.
7.	Deploy to Kubernetes (using Helm manifests).
2. Infrastructure Pipeline
•	Triggers on infra changes (terraform/).
•	Steps:
1.	Run terraform fmt, validate.
2.	Run tfsec and checkov (IaC scanning).
3.	Run terraform plan.
4.	Require manual approval for production changes.
5.	Run terraform apply.
________________________________________
FinOps & Governance
•	Cost Tracking
o	AWS Cost Explorer, Kubecost (in prod) for cluster cost visibility.
o	Namespace-level cost attribution.
•	FinOps Practices
o	Right-sizing workloads with HPA.
o	Spot instances for dev/test environments.
o	Automatic cleanup jobs for unused resources.
•	Compliance
o	GDPR/Regional compliance → data stored in region-specific RDS/EBS.
o	IAM policies and RBAC enforce least privilege.
o	Audit logs enabled in Kubernetes and AWS CloudTrail.
•	Anomaly Detection
o	Prometheus rules detect unusual spikes in traffic, latency, or DB errors.
o	Security scans run on each commit to catch vulnerabilities early.


Commands :
helm repo add bitnami https://charts.bitnami.com/bitnami
helm install postgres bitnami/postgresql -f k8s/postgres-values.yaml
docker build -t your-dockerhub-username/backend ./backend
docker build -t your-dockerhub-username/frontend ./frontend
docker push your-dockerhub-username/backend
docker push your-dockerhub-username/frontend
helm install postgres bitnami/postgresql -f k8s/postgres-values.yaml
kubectl apply -f kubrenetes/
minikube service frontend
docker compose up –build

Access:
Frontend → http://localhost:8080
Backend API → http://localhost:8000/docs
 (FastAPI auto-docs)
Postgres → localhost:5432 (user: admin, pass: admin, db: tasksdb)

Scaling Criteria:
Target metric: CPU utilization
Threshold: Scale when average CPU usage across pods exceeds 50% of the requested CPU
Min pods: 1 (to save resources when idle)
Max pods: 5 (to limit runaway scaling)
Reasoning:
API workloads are bursty. CPU usage correlates well with request load.
FastAPI is async, but still CPU-bound when handling multiple requests.
Setting 50% threshold ensures we add pods before saturation.
Commands:
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
PSA Restricted Key Points
Run as non-root (runAsNonRoot: true).
Disallow privilege escalation (allowPrivilegeEscalation: false).
Drop all capabilities (add only if needed).
Read-only root filesystem (recommended, not mandatory for this FastAPI app).
Non-root user ID (e.g., 1000).
How This Meets PSA “Restricted”
Runs as non-root user (runAsNonRoot, USER appuser).
No privilege escalation (allowPrivilegeEscalation: false).
No Linux capabilities (drop: ALL).
 Read-only root filesystem (app only writes to mounted volumes if needed).
Helm:
helm dependency update ./helm-chart
helm install three-tier-app ./helm-chart
terraform;
sets AWS provider, region determined by env-level tfvars or AWS_PROFILE.
configures Helm provider but uses dynamic kubeconfig after cluster creation.
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
Networking 
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
1) Access control (network + service → resource scoping)
Enforced by
Kubernetes NetworkPolicy to restrict Pod→Pod / Pod→DB communications.
AWS Security Groups limiting inbound to app subnets / ALB only.
Namespaces for multi-tenant separation (app namespace).
Least-privileged SG rules and private subnets for DB.
2) DDoS protection & WAF
Enforced by
AWS WAF attached to the ALB (application load balancer).
AWS Shield (Standard is automatic; Shield Advanced optional).
Rate limiting / IP blocking rules in WAF (managed rule groups + custom rules).
ALB idle/timeouts tuned to mitigate slow-Loris style attacks.
3) Data encryption — at rest & in transit
Enforced by
At rest
EBS volumes (worker node storage and dynamic PVs) encrypted with customer-managed KMS key (CMK).
EKS Secrets encryption at rest (encryptionConfig using KMS) for etcd (EKS supports encryptionConfig via API or eksctl/module).
S3 buckets and RDS/managed databases encrypted with KMS.
In transit
TLS termination at ALB (cert from ACM). Internal pod→pod traffic uses mTLS optionally (not enabled by default); at minimum we use TLS for client→ALB and ALB→ingress/backend (HTTPS).
Enforce readOnlyRootFilesystem and avoid plaintext secrets in env.
4) Secrets management
Enforced by
Use AWS Secrets Manager or AWS SSM Parameter Store for database credentials and sensitive config. Application uses IRSA + kubernetes-external-secrets (or external-secrets Helm chart) to fetch secrets into Kubernetes securely.
Kubernetes Secrets are still used but stored encrypted at rest (see previous section).
Avoid environment variables with plaintext secrets in Helm values — use references.

5) Role-Based Access Control (RBAC)
Enforced by
Kubernetes Roles / RoleBindings scoped to namespaces.
Use least-privilege Roles for CI/CD service accounts and controllers.
Use IRSA for AWS permissions (map Kubernetes service accounts to IAM roles).
6) Automated security checks & tests (one script to run the checks)
Place the following script as scripts/security-checks.sh and make executable. It calls the smaller checks above and exits non-zero on failures so CI can pick it up.
7) Notes & trade-offs / limitations
WAF/Shield: WAF rules and Shield Advanced cost money. We provide Terraform snippets, but enabling Shield Advanced is optional (and should be a controlled decision).
Secrets: Kubernetes Secrets are base64-encoded — not encrypted by default unless kube-apiserver encryptionConfig is enabled. Use KMS-backed encryption for etcd or use ExternalSecrets to keep secrets in AWS Secrets Manager.
Encryption verification: Some checks (e.g., etcd server-side encryption) require checking cluster configuration / AWS console or Terraform outputs — not just in-cluster commands.
NetworkPolicy enforcement: NetworkPolicy only works if your CNI supports it (most do: Calico, Cilium). AWS VPC CNI historically requires an additional controller or using security groups for Pod networking — verify on your cluster.
RBAC tests: kubectl auth can-i --as is a practical, safe way to validate permissions. Impersonation requires cluster admin privileges to test.
No DDoS testing included: We do not issue DDoS or high-volume traffic to external endpoints. Use load tests responsibly and in isolated environments.
 Example quick checklist for operators: 
kubectl get ns → app present.
kubectl get netpol -A → Postgres NetPol exists.
kubectl auth can-i ... --as=system:serviceaccount:app:backend-sa → expected responses.
aws wafv2 get-web-acl --name <web-acl> → rules present.
openssl s_client -connect <ALB>:443 → TLS negotiates.
aws ec2 describe-volumes --filters 'Name=tag:Name,Values=*eks*' → Encrypted true.
kubectl get secret db-credentials -n app → exists (synced from AWS Secrets Manager).
Run scripts/security-checks.sh → all green.
 Grafana Dashboards:
Import ready-made dashboards:
Docker + cAdvisor (ID: 193 on Grafana.com).
Node Exporter Full (ID: 1860).
Postgres Exporter (ID: 9628).
Flask/HTTP latency from backend metrics.
Grafana’s community has a ready-made Postgres Exporter dashboard (ID: 9628).
1. Detect anomalies & vulnerabilities
a) Anomaly Detection
Metrics-based anomalies:
Use Prometheus + Alertmanager for thresholds (e.g., CPU > 80%, memory leaks, DB down).
Add Grafana Anomaly Detection plugin or ML-based tools (e.g., Prometheus Adaptive Alerts, Datadog anomaly detection).
Log anomalies:
Loki + Promtail + Grafana dashboards.
Define queries for unusual error rates (e.g., HTTP 5xx spike).
Tracing anomalies:
OpenTelemetry + Jaeger → detect abnormal latency in service-to-service calls.
b) Vulnerability Detection
Container Scanning:
Use Trivy or Grype in CI/CD pipeline (scan images before pushing).
Dependency Scanning:
Python → pip-audit or Snyk for libraries.
Runtime Security:
Falco (CNCF) to monitor unexpected syscalls (e.g., shell in container).
Cluster Security:
kube-bench (CIS Kubernetes benchmarks).
kube-hunter for pen-testing.
 This ensures you catch both performance anomalies and security vulnerabilities early.
2. Ensure compliance with regional data regulations
Depending on region (e.g., GDPR in EU, HIPAA in US healthcare, PCI DSS for finance):
Data at Rest
Encrypt Postgres volumes using KMS (AWS EBS encryption / LUKS in local cluster).
Apply role-based access → Postgres users restricted (least privilege).
Data in Transit
TLS termination at ingress (NGINX/Traefik).
Enforce HTTPS-only communication (no plain HTTP).
Data Governance
Data locality:
For cloud → ensure DB is in region where data must stay (e.g., eu-west-1 for EU).
Audit logging:
Loki + Promtail for access logs.
Store audit logs securely (e.g., S3 with retention policies).
Kubernetes Compliance
Pod Security Admission (PSA) policies → enforce non-root.
NetworkPolicies → restrict DB access to app namespace only (done already).
Secrets → managed via Kubernetes Secrets + Sealed Secrets or HashiCorp Vault.
This aligns with GDPR, HIPAA, PCI DSS principles (encryption, access control, audit, data residency).
3. Track costs & apply FinOps principles
CoSt Tracking
Kubecost (open-source, deploy in cluster).
Breaks down costs per namespace, pod, and service.
For AWS EKS (if you move from local):
Use AWS Cost Explorer with tagging (e.g., env=dev, env=prod).
Enable AWS Budgets & Alarms.
Optimization (FinOps Principles)
Right-sizing:
Use HPA (already configured) to autoscale pods only when needed.
Idle resource detection:
Kubecost highlights underutilized nodes/pods.
Storage optimization:
Clean unused PVCs, limit Postgres volume growth.
Environment separation:
Dev uses cheaper resources (local cluster, spot instances).
Prod uses HA setup in cloud with proper SLAs.
Forecasting:
Regular cost reports to predict growth (alerts when spend > budget).
 This brings visibility, accountability, and efficiency — the 3 pillars of FinOps.


                ┌───────────────────────────┐
                │         Frontend          │
                │ (NGINX serving static app)│
                └───────────┬───────────────┘
                            │
                            ▼
                ┌───────────────────────────┐
                │         Backend           │
                │   Flask API + OTEL +      │
                │   Prometheus metrics      │
                └───────────┬───────────────┘
                            │
                            ▼
                ┌───────────────────────────┐
                │        Postgres DB        │
                │  + postgres_exporter      │
                └───────────────────────────┘


   ┌─────────────────────────────────────────────────────────┐
   │                  Observability Stack                    │
   │  Prometheus <──scrapes── backend, exporter               │
   │  Alertmanager → email alerts                             │
   │  Grafana ← dashboards ← Prometheus + Loki + Jaeger       │
   │  Loki+Promtail ← logs (app, db, infra)                   │
   │  Jaeger ← traces from OTEL Collector                     │
   └─────────────────────────────────────────────────────────┘


   ┌─────────────────────────────────────────────────────────┐
   │                   Security Controls                     │
   │  - PSA (non-root)  - RBAC  - NetworkPolicies             │
   │  - TLS ingress     - Secrets mgmt (Vault/K8s)            │
   │  - Trivy / pip-audit / Falco                             │
   └─────────────────────────────────────────────────────────┘


   ┌─────────────────────────────────────────────────────────┐
   │                 Infrastructure Layer                    │
   │  - Terraform → VPC, EKS, SGs, IAM, storage              │
   │  - Dev = local (Minikube/MicroK8s)                      │
   │  - Prod = AWS EKS (HA, multi-AZ)                        │
   └─────────────────────────────────────────────────────────┘


   ┌─────────────────────────────────────────────────────────┐
   │                  FinOps (Cost Mgmt)                     │
   │  - Kubecost → per-namespace cost                        │
   │  - AWS Budgets → prod cost alerts                       │
   │  - Right-sizing with HPA, cleaning idle resources        │




How to apply everything (recommended order)
Create namespaces:
kubectl apply -f kubernetes/namespaces/00-ns-app.yaml
kubectl apply -f kubernetes/namespaces/00-ns-monitoring.yaml
Create secrets:
kubectl apply -f kubernetes/secrets/secret-db.yaml
kubectl apply -f kubernetes/secrets/secret-alerts.yaml
Deploy Postgres (so DB exists before backend):
kubectl apply -f kubernetes/deployments/postgres-deployment.yaml
kubectl apply -f kubernetes/services/postgres-svc.yaml
NetworkPolicy default-deny then specific allow:
kubectl apply -f kubernetes/networkpolicies/default-deny-app.yaml
kubectl apply -f kubernetes/networkpolicies/postgres-netpol.yaml
Deploy backend & frontend + services:
kubectl apply -f kubernetes/deployments/backend-deployment.yaml
kubectl apply -f kubernetes/services/backend-svc.yaml
kubectl apply -f kubernetes/deployments/frontend-deployment.yaml
kubectl apply -f kubernetes/services/frontend-svc.yaml
Deploy monitoring & tracing (monitoring namespace):
kubectl apply -f kubernetes/deployments/prometheus-deployment.yaml
kubectl apply -f kubernetes/deployments/grafana-deployment.yaml
kubectl apply -f kubernetes/deployments/loki-deployment.yaml
kubectl apply -f kubernetes/deployments/promtail-daemonset.yaml
kubectl apply -f kubernetes/deployments/otel-collector-deployment.yaml
kubectl apply -f kubernetes/deployments/jaeger-deployment.yaml
Apply HPA:
kubectl apply -f kubernetes/hpa/backend-hpa.yaml
kubectl apply -f kubernetes/ingress/ingress.yaml
Notes (app pipeline):
Scanners: Trivy (Aqua) + Grype provide overlapping coverage (OS packages + language deps). Trivy is quick, Grype offers a different database mapping — running both increases detection probability.
Image signing: cosign keyless signing uses GitHub OIDC so no private cosign keys in repo. The id-token: write permission is required in workflow. COSIGN_EXPERIMENTAL=1 may be required for some OIDC features.
Image registry: GHCR (GitHub Container Registry) used here — it integrates with GitHub and works
with GITHUB_TOKEN for auth.
Kubernetes deployment: supports Helm or plain kubectl set image. The workflow verifies the cosign signature before applying the image.
Secrets: AWS role is obtained via OIDC (see infra pipeline); you must set secrets.AWS_ROLE_TO_ASSUME and secrets.AWS_REGION if deploying to EKS. For non-AWS, provide KUBE_CONFIG_DATA (base64 kubeconfig) as a secret and use it.
Uses GitHub OIDC + aws-actions/configure-aws-credentials to assume an AWS role. This avoids long-lived AWS keys in GitHub Secrets — recommended.
Runs tfsec and Checkov for infrastructure-as-code security scanning.
Requires manual approval step before applying to production (controlled via job conditions or environment protection rules). You can also add the environment with required reviewers in GitHub repo settings to enforce manual approvals.
Terraform remote state should be set in terraform/prod/backend.tf (S3 + DynamoDB) — configure TF_VAR_* via repo secrets.
Security & DevSecOps features implemented
No long-lived cloud credentials in repo — use GitHub OIDC to assume AWS roles.
Image vulnerability scanning — Trivy + Grype in pipeline (failing build on high/critical).
Terraform IaC scanning — tfsec + Checkov.
Image signing & provenance — cosign keyless signing with OIDC; verify signature before deploy.
Secrets management — keep secrets in GitHub Secrets for CI; runtime secrets stored in cloud provider or Vault (recommended). Optionally use external-secrets in cluster to retrieve from AWS Secrets Manager.
RBAC — deployments use ServiceAccounts and namespace isolation; pipeline can run RBAC checks (via kubectl auth can-i).
Artifact registry — GHCR, with images signed and provenance recorded in workflow metadata.
Policy enforcement — require tfsec/checkov to pass before plan; enforce manual approval for prod apply; require metadata in artifacts; require cosign verification before deploy.
Supply-chain provenance — cosign signatures + attestation can be extended (e.g., rekor, in-toto).
Tool choices & short justification (comparison)
Container vulnerability scanning
Trivy (chosen) — fast, simple, good coverage for OS packages & language deps, built-in CI action.
Grype (also used) — different DB/matching; complementary.
Snyk — strong prioritization + fix advice but is commercial; good for enterprise.
Image signing
cosign (chosen) — easy keyless signing using OIDC (no keys stored in repo), integrates with Sigstore/Rekor for transparency.
Alternatives: Notary (v2), GPG — more setup & key handling.
Terraform scanning (IaC)
tfsec (chosen) — fast, targeted to TF, active ruleset.
checkov (also used) — broad coverage across IaC types and policies.
Secrets management
GitHub Secrets for CI-life secrets; AWS Secrets Manager or HashiCorp Vault for runtime secrets.
Use Kubernetes External Secrets (external-secrets) to sync secrets with least privilege (IRSA).
Kubernetes deployment method
Helm preferred for templating & upgrades; kubectl for simple patches.
Use Helm charts (in repo or public) and add helm test for post-install checks.
Cloud auth
GitHub OIDC (chosen) to assume AWS IAM roles — no AWS keys in repo.
Alternative: IAM user creds in GitHub secrets (less secure).

