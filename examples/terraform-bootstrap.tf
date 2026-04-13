# Deploy the Shroud sidecar in bootstrap mode — the sidecar auto-provisions
# a vault, agent, and policy on first start using the human API key.
# No pre-existing agent credentials needed.

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
    "ONECLAW_MASTER_API_KEY=${var.oneclaw_master_api_key}",
    "ONECLAW_VAULT_NAME=${var.vault_name}",
    "ONECLAW_AGENT_NAME=${var.agent_name}",
    "ONECLAW_DEFAULT_PROVIDER=${var.default_provider}",
  ]

  volumes {
    host_path      = var.state_dir
    container_path = "/home/nonroot/.1claw"
  }

  restart = "unless-stopped"

  provisioner "local-exec" {
    when    = destroy
    command = <<-EOT
      docker run --rm \
        -e ONECLAW_MASTER_API_KEY="${var.oneclaw_master_api_key}" \
        -v "${var.state_dir}:/home/nonroot/.1claw" \
        ${docker_image.shroud_sidecar.name} teardown
    EOT
  }
}

variable "oneclaw_master_api_key" {
  type        = string
  sensitive   = true
  description = "Human 1ck_ API key for auto-provisioning"
}

variable "vault_name" {
  type    = string
  default = "shroud-sidecar"
}

variable "agent_name" {
  type    = string
  default = "shroud-sidecar-agent"
}

variable "default_provider" {
  type    = string
  default = "openai"
}

variable "state_dir" {
  type        = string
  default     = "/tmp/1claw-state"
  description = "Host directory for persisting bootstrap state across container restarts"
}
