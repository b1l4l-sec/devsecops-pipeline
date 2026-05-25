output "container_name" {
  description = "Running container name"
  value       = docker_container.app.name
}

output "container_id" {
  description = "Container ID"
  value       = docker_container.app.id
}

output "app_url" {
  description = "Application URL"
  value       = "http://localhost:${var.app_port}"
}

output "network_name" {
  description = "Docker network name"
  value       = docker_network.app_network.name
}
