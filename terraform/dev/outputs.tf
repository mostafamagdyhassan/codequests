output "namespace" {
  description = "Namespace used for app deployment"
  value       = kubernetes_namespace.app.metadata[0].name
}

output "prometheus_url" {
  description = "Prometheus URL (Minikube service URL)"
  value       = "Run 'minikube service prometheus-kube-prometheus-prometheus -n app' to access Prometheus"
}
