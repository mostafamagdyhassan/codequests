🔧 Running Locust
Locally
export API_HOST="http://localhost:8000"
export WAIT_MIN=1
export WAIT_MAX=2

locust -f locustfile.py --headless -u 50 -r 5 -t 5m


-u 50: simulate 50 concurrent users.

-r 5: spawn 5 new users per second.

-t 5m: run test for 5 minutes.

With Docker
docker build -t locust-test .
docker run --rm -e API_HOST="http://backend.default.svc.cluster.local:8000" \
    locust-test -f locustfile.py --headless -u 100 -r 10 -t 10m

🔍 HPA Integration

Since your HPA scales based on CPU, you should:

Deploy this Locust job as a Kubernetes Job or run it externally.

Observe pod scaling with:

kubectl get hpa -n app -w
kubectl get pods -n app -o wide


If CPU usage exceeds the threshold (averageUtilization: 50 from your HPA), Kubernetes will add more backend pods.
