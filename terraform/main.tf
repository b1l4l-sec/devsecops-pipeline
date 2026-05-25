terraform {
  required_version = ">= 1.0.0"

  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

provider "docker" {}

# Pull / reference the local image
resource "docker_image" "app" {
  name         = "${var.app_name}:${var.app_version}"
  keep_locally = true
}

# Create a dedicated network
resource "docker_network" "app_network" {
  name = "${var.app_name}-network"
}

# Deploy the container
resource "docker_container" "app" {
  name  = "${var.app_name}-${var.environment}"
  image = docker_image.app.image_id

  restart = "unless-stopped"

  ports {
    internal = var.app_port
    external = var.app_port
  }

  networks_advanced {
    name = docker_network.app_network.name
  }

  env = [
    "APP_VERSION=${var.app_version}",
    "ENVIRONMENT=${var.environment}"
  ]

  healthcheck {
    test         = ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"]
    interval     = "30s"
    timeout      = "5s"
    retries      = 3
    start_period = "10s"
  }

  labels {
    label = "app"
    value = var.app_name
  }

  labels {
    label = "version"
    value = var.app_version
  }

  labels {
    label = "environment"
    value = var.environment
  }
}
