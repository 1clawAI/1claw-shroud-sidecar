# Drop the Shroud sidecar alongside any Docker-based workspace.
# Point your LLM client at http://localhost:8080 (or container name).

resource "docker_image" "shroud_sidecar" {
  name = "ghcr.io/1clawai/1claw-shroud-sidecar:latest"
}

resource "docker_container" "shroud_sidecar" {
  name  = "shroud-sidecar"
  image = docker_image.shroud_sidecar.image_id

  ports {
    internal = 8080
    external = 8080
  }

  env = [
    "ONECLAW_AGENT_ID=${var.oneclaw_agent_id}",
    "ONECLAW_AGENT_API_KEY=${var.oneclaw_agent_api_key}",
    "ONECLAW_DEFAULT_PROVIDER=${var.default_provider}",
  ]

  restart = "unless-stopped"
}

variable "oneclaw_agent_id" {
  type        = string
  description = "1Claw agent UUID"
}

variable "oneclaw_agent_api_key" {
  type        = string
  sensitive   = true
  description = "1Claw agent API key (ocv_...)"
}

variable "default_provider" {
  type    = string
  default = "openai"
}
