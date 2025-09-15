terraform {
  required_version = ">= 1.5.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.27"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
  }
}

provider "kubernetes" {
  config_path = var.kubeconfig
  config_context = var.kube_context
}

provider "helm" {
  kubernetes {
    config_path = var.kubeconfig
    config_context = var.kube_context
  }
}

# Example namespace for your app
resource "kubernetes_namespace" "app" {
  metadata {
    name = "app"
  }
}

# Example Helm chart (Prometheus for local monitoring)
resource "helm_release" "prometheus" {
  name       = "prometheus"
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "kube-prometheus-stack"
  namespace  = kubernetes_namespace.app.metadata[0].name

  values = [
    file("${path.module}/values/prometheus-values.yaml")
  ]
}
