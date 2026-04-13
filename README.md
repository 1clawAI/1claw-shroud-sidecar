# 1Claw Shroud Sidecar

A lightweight HTTP proxy that routes LLM traffic through [1Claw Shroud](https://1claw.xyz) — the TEE-backed proxy that inspects prompts, redacts secrets, blocks prompt injection, and enforces per-agent policies. Drop it into any environment as a sidecar container or standalone binary.

## What it does

```
┌──────────────┐     ┌──────────────────┐     ┌─────────────────┐     ┌──────────────┐
│  Your app /  │────▶│  Shroud Sidecar   │────▶│  shroud.1claw   │────▶│  OpenAI /    │
│  AI agent    │◀────│  (localhost:8080) │◀────│  (TEE proxy)    │◀────│  Anthropic   │
└──────────────┘     └──────────────────┘     └─────────────────┘     └──────────────┘
                      Injects headers            PII redaction          Upstream LLM
                      Emits audit JSON           Injection detection
                                                 Policy enforcement
```

1. **Intercepts** LLM HTTP requests on `localhost:8080`
2. **Injects** `X-Shroud-Agent-Key`, `X-Shroud-Provider`, and optional `X-Shroud-Model` headers
3. **Forwards** to `https://shroud.1claw.xyz` where Shroud applies secret redaction, PII scrubbing, prompt injection defense, and per-agent policies inside a TEE
4. **Emits** a JSON audit line per request to stdout (timestamp, agent, provider, model, tokens, latency, status)

## Why use a sidecar?

- **Transparent.** Set `OPENAI_API_BASE=http://localhost:8080/v1` and your existing OpenAI SDK calls route through Shroud with zero code changes.
- **No credentials in app code.** The sidecar holds the `X-Shroud-Agent-Key`; your app just sends normal LLM requests to localhost.
- **BYOK pass-through.** If the caller sends `Authorization: Bearer sk-...`, the sidecar forwards it as `X-Shroud-Api-Key` so Shroud uses the caller's provider key. Otherwise Shroud resolves the key from the vault.
- **Structured audit.** Every request gets a JSON log line — pipe to any log aggregator for visibility into LLM usage.
- **Infra-agnostic.** Works in Docker, Kubernetes, Coder, Compose, systemd, or as a bare binary.

## Two operating modes

### Mode 1: Manual (pre-existing credentials)

You already have a 1Claw agent with an API key. Pass them directly:

```bash
export ONECLAW_AGENT_ID=your-agent-uuid
export ONECLAW_AGENT_API_KEY=ocv_your_key
./shroud-sidecar
```

### Mode 2: Bootstrap (zero-config provisioning)

Pass a human `1ck_` API key and the sidecar provisions everything on first start — vault, agent (with Shroud enabled), and access policy. Credentials are cached to a state file so subsequent starts reuse them.

```bash
export ONECLAW_MASTER_API_KEY=1ck_your_human_key
./shroud-sidecar
```

On first run you'll see:

```
[bootstrap] Authenticating with master API key...
[bootstrap] Authenticated
[bootstrap] Resolving vault 'shroud-sidecar'...
[bootstrap] Vault: 9a1b2c3d-...
[bootstrap] Creating agent 'shroud-sidecar-agent' (shroud_enabled: true)...
[bootstrap] Agent: e4f5a6b7-... (key: ocv_abcdef12...)
[bootstrap] Creating access policy (path: **)...
[bootstrap] Policy created
[bootstrap] State saved to ~/.1claw/shroud-sidecar-state.json
1claw-shroud-sidecar listening on :8080 → https://shroud.1claw.xyz (agent e4f5a6b7...)
```

Subsequent starts load from the state file — no API calls.

#### Teardown

Clean up the provisioned agent (and optionally the vault) with:

```bash
export ONECLAW_MASTER_API_KEY=1ck_your_human_key
./shroud-sidecar teardown
```

To also delete the vault, add `ONECLAW_AUTO_DESTROY_VAULT=true`.

#### Bootstrap configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ONECLAW_MASTER_API_KEY` | — | Human `1ck_` API key (triggers bootstrap mode) |
| `ONECLAW_BASE_URL` | `https://api.1claw.xyz` | 1Claw API base URL |
| `ONECLAW_VAULT_NAME` | `shroud-sidecar` | Name for the auto-created vault |
| `ONECLAW_AGENT_NAME` | `shroud-sidecar-agent` | Name for the auto-created agent |
| `ONECLAW_POLICY_PATH` | `**` | Secret path pattern for the access policy |
| `ONECLAW_STATE_FILE` | `~/.1claw/shroud-sidecar-state.json` | Where to cache provisioned credentials |
| `ONECLAW_AUTO_DESTROY_VAULT` | `false` | Delete vault on teardown (default: agent only) |

## Quick start

### Install a release (no compile)

Prebuilt binaries are published for **linux/amd64** and **darwin/arm64** on each [GitHub Release](https://github.com/1clawAI/1claw-shroud-sidecar/releases). Container images are pushed to **GHCR** on the same tag.

**One-liner** (installs to `~/.local/bin` by default; set `PREFIX` to change):

```bash
curl -fsSL https://raw.githubusercontent.com/1clawAI/1claw-shroud-sidecar/main/install.sh | sh
```

Pin a version (recommended once a release exists):

```bash
SHROUD_SIDECAR_VERSION=v1.0.0 curl -fsSL https://raw.githubusercontent.com/1clawAI/1claw-shroud-sidecar/v1.0.0/install.sh | sh
```

**Docker (GHCR)** — replace `v1.0.0` with the tag you want (also tagged `latest` on the newest release):

```bash
docker pull ghcr.io/1clawai/1claw-shroud-sidecar:v1.0.0
```

Until you publish a release, use **build from source** or **Dockerfile** below.

### Binary (from source)

```bash
# Build
go build -o shroud-sidecar .

# Manual mode
export ONECLAW_AGENT_ID=your-agent-uuid
export ONECLAW_AGENT_API_KEY=ocv_your_key
export ONECLAW_DEFAULT_PROVIDER=openai
./shroud-sidecar

# Bootstrap mode (provisions everything automatically)
export ONECLAW_MASTER_API_KEY=1ck_your_human_key
./shroud-sidecar
```

### Docker

```bash
docker build -t shroud-sidecar .

# Manual mode
docker run -p 8080:8080 \
  -e ONECLAW_AGENT_ID=your-agent-uuid \
  -e ONECLAW_AGENT_API_KEY=ocv_your_key \
  -e ONECLAW_DEFAULT_PROVIDER=openai \
  shroud-sidecar

# Bootstrap mode
docker run -p 8080:8080 \
  -v ~/.1claw:/home/nonroot/.1claw \
  -e ONECLAW_MASTER_API_KEY=1ck_your_human_key \
  shroud-sidecar
```

> **Note:** In bootstrap mode with Docker, mount `~/.1claw` so the state file persists across container restarts.

### Docker Compose

```bash
cp .env.example .env   # fill in credentials
cd examples && docker compose up
```

### Test it

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```

The sidecar forwards to Shroud, which inspects and forwards to OpenAI. You'll see an audit line on stdout:

```json
{"timestamp":"2026-04-12T...","agent_id":"...","provider":"openai","model":"gpt-4o-mini","method":"POST","path":"/v1/chat/completions","status_code":200,"latency_ms":1234,"request_bytes":89,"response_bytes":512,"prompt_token_count":12,"completion_token_count":28}
```

## Testing

Run these **in order** for a full matrix: fast local checks first, then live API scripts.

| Step | Command | Network | What it covers |
|------|---------|---------|----------------|
| 1 | `go test ./...` | No | Proxy handler, config parsing, audit JSON shape, teardown parsing (see `main_test.go`) |
| 2 | `bash tests/test_integration.sh` | Yes (`api.1claw.xyz`, `shroud.1claw.xyz`) | Bootstrap, `/healthz`, state reuse, proxy to Shroud, BYOK header path, teardown no-op + full teardown, manual mode |
| 3 | `bash tests/test_security.sh` | Yes | Injection 403, benign vs injection, audit must not leak BYOK bearer; optional OpenAI completion + vault redaction when `OPENAI_API_KEY` is set |

Build the binary before the shell scripts (they invoke `./shroud-sidecar` in the package directory):

```bash
go build -o shroud-sidecar .
go test ./...
bash tests/test_integration.sh
bash tests/test_security.sh
```

### Credentials for live scripts

Integration and security tests need a human **`1ck_` API key**, either:

- `export ONECLAW_MASTER_API_KEY=1ck_...`, or  
- When this package is checked out under the 1claw monorepo (`packages/1claw-shroud-sidecar/`), a **repository-root** `.env` with `ADMIN_EMAIL` and `ADMIN_PASSWORD` (the scripts mint a temporary `1ck_` key and revoke it on exit). **Standalone clones** of the sidecar repo should use `ONECLAW_MASTER_API_KEY` or adjust the path — the helper looks two levels above the package directory for `.env`.

Optional environment variables:

| Variable | Used by | Purpose |
|----------|---------|---------|
| `TEST_PORT` | `test_integration.sh` | Listen port (default **18080**). Set if the default conflicts with another process. |
| `TEST_SECURITY_PORT` | `test_security.sh` | Listen port (default **18082**). |
| `OPENAI_API_KEY` or `OPENAI_API_KEY_E2E` | `test_security.sh` | Enables optional real completion + vault secret redaction checks. |
| `REDACTION_MANIFEST_WAIT_SECS` | `test_security.sh` | Seconds to wait after `PUT` secret before the redaction chat (default **90**). Shroud reloads vault manifests on an interval (~60s). |
| `REDACTION_RETRY_WAIT_SECS` | `test_security.sh` | Extra wait before a **second** completion attempt if the first still shows the raw secret (default **45**). |
| `REDACTION_E2E_CHAT` | `test_security.sh` | Set to **0** for **PUT-only** Test 6 (checks Vault accepts the secret; skips the OpenAI echo probe). Useful to confirm the flow without waiting on manifest timing. |

**Test 6 troubleshooting**

- **`PUT .../secrets/...` returns HTTP 500** with a generic RFC 7807 body: the Vault API persists `secret_type` with a DB `CHECK` constraint. Allowed values include `note`, `api_key`, `password`, etc. — **not** `generic`. The script uses `type: note` for the probe secret.
- **Chat probe still sees the raw secret** after waits: the manifest may not have refreshed yet — raise `REDACTION_MANIFEST_WAIT_SECS` / `REDACTION_RETRY_WAIT_SECS`, or use `REDACTION_E2E_CHAT=0` to validate only the Vault write.

### Integration test scenarios (step 2)

1. **Bootstrap — fresh** — Creates vault, agent, policy; state file `600`; keys present.  
2. **Health** — `GET /healthz` returns OK (local only).  
3. **State reuse** — Second start keeps the same agent id.  
4. **Proxy** — `POST /v1/chat/completions` reaches Shroud (expects **401** without a provider key in vault; proves path works).  
5. **BYOK** — `Authorization: Bearer sk-...` forwarded; audit line does not need to show 200.  
6. **Teardown no state** — `teardown` with no state file is a graceful no-op.  
7. **Teardown full** — Deletes agent + vault, removes state (`ONECLAW_AUTO_DESTROY_VAULT=true`).  
8. **Manual mode** — Boots with `ONECLAW_AGENT_ID` + `ONECLAW_AGENT_API_KEY` after a one-off bootstrap for credentials.

### LLM security features (what the tests prove)

The sidecar only **routes traffic and sets headers**; **PII redaction, injection scoring, threat detectors, output policy, and per-agent `shroud_config` are enforced in Shroud**, not in this binary. The security script exercises the same path your apps use:

| Check | What it validates |
|--------|-------------------|
| **Injection block** | A crafted prompt that exceeds Shroud’s hard injection threshold returns **403** with `error.type: shroud_error` (forwarded unchanged through the sidecar). |
| **Benign traffic** | A normal prompt is **not** rejected as injection (typically **401** without a provider key in vault, or **200** with `Authorization: Bearer sk-...`). |
| **Audit hygiene** | Structured audit lines on stdout **never** contain the BYOK bearer token. |
| **Local health** | `GET /healthz` is answered by the sidecar only (does not call Shroud). |
| **Optional real LLM** | With `OPENAI_API_KEY` or `OPENAI_API_KEY_E2E` set, runs one successful completion through Shroud to the provider. |
| **Vault secret redaction** | Stores a `note` secret in the bootstrap vault (agent JWT `PUT`), waits for Shroud’s manifest refresh, then sends a BYOK completion that embeds the value. The assistant output **must not** contain the raw secret if Shroud redacted the request body. Tunables: `REDACTION_MANIFEST_WAIT_SECS` (default **90**), `REDACTION_RETRY_WAIT_SECS` (default **45**), or `REDACTION_E2E_CHAT=0` to skip the chat and only verify the Vault write. |

```bash
bash tests/test_security.sh
# Full Test 6 (Vault PUT + OpenAI redaction probe) with OpenAI BYOK:
OPENAI_API_KEY=sk-... bash tests/test_security.sh
# PUT-only Test 6 (no manifest timing / echo probe):
REDACTION_E2E_CHAT=0 OPENAI_API_KEY=sk-... bash tests/test_security.sh
# Longer manifest wait if the echo probe flakes:
REDACTION_MANIFEST_WAIT_SECS=120 REDACTION_RETRY_WAIT_SECS=60 OPENAI_API_KEY=sk-... bash tests/test_security.sh
```

Tune blocking thresholds, PII mode, and detectors in the 1Claw dashboard or API (`shroud_config` on the agent), then re-run the script to confirm behavior.

**Note:** Secret redaction in Shroud is **manifest-driven** (values from your vaults). Response-side redaction uses the same manifest. The sidecar does not perform redaction; it only proxies.

## Environment variables

### Manual mode

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ONECLAW_AGENT_ID` | **Yes** | — | 1Claw agent UUID |
| `ONECLAW_AGENT_API_KEY` | **Yes** | — | Agent API key (`ocv_...`) |

### Common (both modes)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ONECLAW_SHROUD_URL` | No | `https://shroud.1claw.xyz` | Shroud endpoint |
| `ONECLAW_DEFAULT_PROVIDER` | No | auto-detect from path | Default LLM provider (`openai`, `anthropic`, `google`, etc.) |
| `ONECLAW_DEFAULT_MODEL` | No | — | Default model name |
| `ONECLAW_VAULT_ID` | No | — | Vault ID (for audit context; auto-set in bootstrap mode) |
| `CODER_WORKSPACE_ID` | No | — | Workspace/environment ID (for audit context) |
| `LISTEN_ADDR` | No | `:8080` | Listen address |

## Provider detection

The sidecar resolves the LLM provider in this order:

1. `X-Shroud-Provider` header from the caller (highest priority)
2. `ONECLAW_DEFAULT_PROVIDER` env var
3. Auto-detect from the request path:
   - `/chat/completions` → `openai`
   - `/messages` → `anthropic`
   - `/generateContent` → `google`

## BYOK (Bring Your Own Key)

If the caller sends `Authorization: Bearer sk-...`, the sidecar strips it and passes the key as `X-Shroud-Api-Key`. Shroud uses it directly instead of resolving from the vault. This lets apps that already have a provider key benefit from Shroud's inspection without storing the key in 1Claw.

## Audit log format

One JSON line per request, written to stdout:

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string | RFC 3339 with nanoseconds |
| `workspace_id` | string | From `CODER_WORKSPACE_ID` (omitted if unset) |
| `agent_id` | string | 1Claw agent UUID |
| `provider` | string | LLM provider name |
| `model` | string | Model name (from header, body, or default) |
| `method` | string | HTTP method |
| `path` | string | Request path |
| `status_code` | int | Upstream response status |
| `latency_ms` | int | Round-trip time in milliseconds |
| `request_bytes` | int | Request body size |
| `response_bytes` | int | Response body size |
| `prompt_token_count` | int | Prompt tokens (from upstream `usage`, if present) |
| `completion_token_count` | int | Completion tokens (from upstream `usage`, if present) |
| `error` | string | Error message (omitted on success) |

## Deployment examples

See the `examples/` directory:

- **`docker-compose.yml`** — Standalone with Compose
- **`terraform-docker.tf`** — Terraform `docker_container` resource
- **`terraform-bootstrap.tf`** — Terraform with bootstrap mode (auto-provision)
- **`kubernetes.yaml`** — K8s Deployment + Service with Secret refs
- **`coder-template.tf`** — Coder workspace sidecar with `network_mode: container`

## Architecture

The sidecar is a single static Go binary (no runtime dependencies, ~6 MB compressed). It uses only the Go standard library — no frameworks, no CGO.

At runtime it operates in one of two modes:

### Manual mode
1. Read `ONECLAW_AGENT_ID` + `ONECLAW_AGENT_API_KEY` from env
2. Start the HTTP proxy

### Bootstrap mode
1. Read `ONECLAW_MASTER_API_KEY` from env
2. Check for cached state file (`~/.1claw/shroud-sidecar-state.json`)
3. If no state file exists, call the 1Claw API:
   - Authenticate with the human API key
   - Create (or reuse) a vault
   - Create an agent with `shroud_enabled: true`
   - Create an access policy
   - Save credentials to the state file
4. Start the HTTP proxy with the provisioned credentials

### Proxy flow (both modes)
1. Accept HTTP request on `LISTEN_ADDR`
2. Read the body, detect provider + model
3. Build upstream request to `ONECLAW_SHROUD_URL` + original path
4. Set `X-Shroud-Agent-Key` (agent_id:api_key), `X-Shroud-Provider`, `X-Shroud-Model`
5. If caller sent `Authorization: Bearer ...`, forward as `X-Shroud-Api-Key`
6. Forward response back to caller
7. Parse `usage` from response JSON (if OpenAI-shaped)
8. Emit JSON audit line to stdout

## How Shroud handles the request

Once the sidecar forwards to `shroud.1claw.xyz`:

1. Shroud authenticates via `X-Shroud-Agent-Key` (exchanges for a short-lived JWT internally)
2. Runs the **inspection pipeline** — secret redaction, PII detection, prompt injection scoring
3. Runs the **PolicyEngine** using the agent's `shroud_config` from the JWT (thresholds, provider/model allowlists, rate limits)
4. Resolves the provider API key from the vault (or uses `X-Shroud-Api-Key` if provided)
5. Forwards to the upstream LLM provider
6. Inspects the response (output policy, harmful content)
7. Returns the response to the sidecar

Configure Shroud behavior per-agent in the 1Claw dashboard, CLI (`1claw agent update --shroud`), or SDK.

## License

Apache-2.0
