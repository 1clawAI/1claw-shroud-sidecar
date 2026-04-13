# Coder template snippet: run Shroud sidecar alongside the workspace container.
# The workspace agent gets OPENAI_API_BASE=http://localhost:8080 so all LLM
# calls route through Shroud transparently.

resource "docker_container" "shroud_sidecar" {
  count = data.coder_workspace.me.start_count
  name  = "shroud-sidecar-${lower(data.coder_workspace.me.name)}"
  image = docker_image.shroud_sidecar.image_id

  env = [
    "ONECLAW_AGENT_ID=${var.oneclaw_agent_id}",
    "ONECLAW_AGENT_API_KEY=${var.oneclaw_agent_api_key}",
    "ONECLAW_DEFAULT_PROVIDER=openai",
    "CODER_WORKSPACE_ID=${data.coder_workspace.me.id}",
  ]

  # Share the network namespace with the workspace container so
  # the sidecar is reachable at localhost:8080 from inside the workspace.
  network_mode = "container:${docker_container.workspace[0].id}"
}

resource "docker_image" "shroud_sidecar" {
  name = "ghcr.io/1clawai/1claw-shroud-sidecar:latest"
}

# Set OPENAI_API_BASE so the OpenAI SDK (and compatible tools) routes
# through the sidecar instead of directly to api.openai.com.
resource "coder_env" "openai_base_url" {
  agent_id = coder_agent.main.id
  name     = "OPENAI_API_BASE"
  value    = "http://localhost:8080/v1"
}
