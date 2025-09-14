terraform {
  required_version = ">= 1.3.0"
}

provider "kubernetes" {
  config_path = "~/.kube/config"
  config_context = "minikube" # or microk8s
}

resource "kubernetes_namespace" "app" {
  metadata {
    name = "app"
  }
}

resource "kubernetes_namespace" "monitoring" {
  metadata {
    name = "monitoring"
  }
}
