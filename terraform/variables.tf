variable "namespace" {
  description = "Kubernetes namespace"
  type        = string
  default     = "security-monitor"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "replicas" {
  description = "Number of replicas"
  type        = number
  default     = 1
}
