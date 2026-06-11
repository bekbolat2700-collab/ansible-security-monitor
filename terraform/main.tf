terraform {
  required_version = ">= 1.0.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
  }
}

provider "kubernetes" {
  config_path = "~/.kube/config"
}

resource "kubernetes_namespace" "security_monitor" {
  metadata {
    name = var.namespace
    labels = {
      app         = "security-monitor"
      environment = var.environment
      managed_by  = "terraform"
    }
  }
}

resource "kubernetes_network_policy" "security_monitor" {
  metadata {
    name      = "security-monitor-policy"
    namespace = kubernetes_namespace.security_monitor.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        app = "security-monitor"
      }
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        namespace_selector {
          match_labels = {
            app = "security-monitor"
          }
        }
      }
    }
  }
}
