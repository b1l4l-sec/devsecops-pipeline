variable "app_name" {
  description = "Application name"
  type        = string
  default     = "devsecops-app"
}

variable "app_version" {
  description = "Docker image version to deploy"
  type        = string
  default     = "1.0.0"
}

variable "app_port" {
  description = "Port the app listens on"
  type        = number
  default     = 5000
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
}
