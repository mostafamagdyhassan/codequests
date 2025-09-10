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






