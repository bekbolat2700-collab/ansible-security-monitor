output "namespace" {
  description = "Kubernetes namespace name"
  value       = kubernetes_namespace.security_monitor.metadata[0].name
}

output "environment" {
  description = "Environment"
  value       = var.environment
}
