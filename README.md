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













