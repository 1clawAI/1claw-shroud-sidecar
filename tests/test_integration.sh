#!/bin/bash
# Integration tests for 1claw-shroud-sidecar
# Requires: ONECLAW_MASTER_API_KEY (1ck_ human key) in env or ../../.env
# Tests: bootstrap, health, proxy, state reuse, teardown, manual mode
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SIDECAR_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$SIDECAR_DIR/../.." && pwd)"

PASS=0
FAIL=0
TESTS_RUN=0
SIDECAR_PID=""
TEST_PORT=18080
STATE_DIR=""
CLEANUP_JWT=""
CLEANUP_KEY_ID=""

# ---------- helpers ----------

log_test() {
  TESTS_RUN=$((TESTS_RUN + 1))
  echo ""
  echo "=== TEST $TESTS_RUN: $1 ==="
}

pass() {
  PASS=$((PASS + 1))
  echo "  PASS: $1"
}

fail() {
  FAIL=$((FAIL + 1))
  echo "  FAIL: $1" >&2
}

cleanup() {
  if [ -n "${SIDECAR_PID:-}" ]; then
    kill "$SIDECAR_PID" 2>/dev/null || true
    wait "$SIDECAR_PID" 2>/dev/null || true
    SIDECAR_PID=""
  fi
  lsof -ti:"$TEST_PORT" 2>/dev/null | xargs kill -9 2>/dev/null || true
  if [ -n "${STATE_DIR:-}" ] && [ -d "$STATE_DIR" ]; then
    rm -rf "$STATE_DIR"
    STATE_DIR=""
  fi
  if [ -n "${CLEANUP_KEY_ID:-}" ] && [ -n "${CLEANUP_JWT:-}" ]; then
    echo ""
    echo "[cleanup] Revoking test API key $CLEANUP_KEY_ID..."
    curl -sf -X DELETE \
      -H "Authorization: Bearer $CLEANUP_JWT" \
      "https://api.1claw.xyz/v1/auth/api-keys/$CLEANUP_KEY_ID" >/dev/null 2>&1 \
      && echo "[cleanup] API key revoked" \
      || echo "[cleanup] WARNING: Could not revoke API key"
  fi
}
trap cleanup EXIT

load_master_key() {
  if [ -n "${ONECLAW_MASTER_API_KEY:-}" ]; then
    return 0
  fi

  local env_file="$ROOT_DIR/.env"
  if [ ! -f "$env_file" ]; then
    echo "ERROR: ONECLAW_MASTER_API_KEY not set and no .env found at $env_file"
    exit 1
  fi

  local admin_email admin_password jwt key_resp
  admin_email=$(grep '^ADMIN_EMAIL=' "$env_file" | cut -d= -f2-)
  admin_password=$(grep '^ADMIN_PASSWORD=' "$env_file" | cut -d= -f2-)

  if [ -z "$admin_email" ] || [ -z "$admin_password" ]; then
    echo "ERROR: ONECLAW_MASTER_API_KEY not set and .env lacks ADMIN_EMAIL/ADMIN_PASSWORD"
    exit 1
  fi

  echo "[setup] Authenticating as $admin_email to create test API key..."
  jwt=$(curl -sf -X POST https://api.1claw.xyz/v1/auth/token \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"$admin_email\", \"password\": \"$admin_password\"}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

  key_resp=$(curl -sf -X POST https://api.1claw.xyz/v1/auth/api-keys \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $jwt" \
    -d '{"name": "shroud-sidecar-integration-test"}')

  ONECLAW_MASTER_API_KEY=$(echo "$key_resp" | python3 -c "import json,sys; print(json.load(sys.stdin)['api_key'])")
  CLEANUP_KEY_ID=$(echo "$key_resp" | python3 -c "import json,sys; print(json.load(sys.stdin)['key']['id'])")
  CLEANUP_JWT="$jwt"
  export ONECLAW_MASTER_API_KEY

  echo "[setup] Created test API key: ${ONECLAW_MASTER_API_KEY:0:12}... (id: $CLEANUP_KEY_ID)"
}

stop_sidecar() {
  if [ -n "${SIDECAR_PID:-}" ]; then
    kill "$SIDECAR_PID" 2>/dev/null || true
    wait "$SIDECAR_PID" 2>/dev/null || true
    SIDECAR_PID=""
  fi
  lsof -ti:"$TEST_PORT" 2>/dev/null | xargs kill -9 2>/dev/null || true
}

wait_for_health() {
  local attempts=0
  while ! curl -sf "http://localhost:$TEST_PORT/healthz" >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    if [ $attempts -gt 30 ]; then
      return 1
    fi
    sleep 0.5
  done
  return 0
}

start_sidecar_with_state() {
  local use_state_dir="${1:-$STATE_DIR}"
  stop_sidecar
  sleep 1

  export LISTEN_ADDR=":$TEST_PORT"
  export ONECLAW_STATE_FILE="$use_state_dir/state.json"
  export ONECLAW_DEFAULT_PROVIDER=openai

  cd "$SIDECAR_DIR"
  ./shroud-sidecar &
  SIDECAR_PID=$!

  if ! wait_for_health; then
    echo "  Sidecar failed to start (PID $SIDECAR_PID)"
    return 1
  fi
  echo "  Sidecar running on :$TEST_PORT (PID $SIDECAR_PID)"
}

# ---------- build ----------

echo "Building shroud-sidecar..."
cd "$SIDECAR_DIR"
GOROOT="${GOROOT:-/opt/homebrew/Cellar/go/1.24.3/libexec}" go build -o shroud-sidecar . 2>&1
echo "Build OK"

# ---------- load credentials ----------

load_master_key

# ---------- shared state dir ----------

STATE_DIR=$(mktemp -d)
export ONECLAW_VAULT_NAME="sidecar-int-test-$$"
export ONECLAW_AGENT_NAME="sidecar-int-agent-$$"

# ---------- test cases ----------

test_bootstrap_fresh() {
  log_test "Bootstrap — fresh provisioning"

  start_sidecar_with_state || { fail "sidecar did not start"; return; }

  local state_file="$STATE_DIR/state.json"
  if [ -f "$state_file" ]; then
    pass "state file created"
  else
    fail "state file not created"; return
  fi

  local vault_id agent_id agent_key
  vault_id=$(python3 -c "import json; print(json.load(open('$state_file'))['vault_id'])")
  agent_id=$(python3 -c "import json; print(json.load(open('$state_file'))['agent_id'])")
  agent_key=$(python3 -c "import json; print(json.load(open('$state_file'))['agent_api_key'])")

  [ -n "$vault_id" ] && [ "$vault_id" != "None" ] \
    && pass "vault_id present: ${vault_id:0:8}..." \
    || fail "vault_id missing"

  [ -n "$agent_id" ] && [ "$agent_id" != "None" ] \
    && pass "agent_id present: ${agent_id:0:8}..." \
    || fail "agent_id missing"

  echo "$agent_key" | grep -q "^ocv_" \
    && pass "agent_api_key has ocv_ prefix" \
    || fail "agent_api_key wrong prefix: $agent_key"

  local perms
  perms=$(stat -f '%Lp' "$state_file" 2>/dev/null || stat -c '%a' "$state_file" 2>/dev/null)
  [ "$perms" = "600" ] \
    && pass "state file has mode 600" \
    || fail "state file mode $perms, expected 600"

  stop_sidecar
}

test_health_check() {
  log_test "Health check endpoint"

  start_sidecar_with_state || { fail "sidecar did not start"; return; }

  local status
  status=$(curl -sf "http://localhost:$TEST_PORT/healthz" \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)

  [ "$status" = "ok" ] \
    && pass "/healthz returns {status: ok}" \
    || fail "/healthz status: $status"

  stop_sidecar
}

test_state_reuse() {
  log_test "State reuse — no re-provisioning on restart"

  start_sidecar_with_state || { fail "sidecar did not start"; return; }

  local original_agent_id
  original_agent_id=$(python3 -c "import json; print(json.load(open('$STATE_DIR/state.json'))['agent_id'])")

  stop_sidecar
  sleep 1

  cd "$SIDECAR_DIR"
  ./shroud-sidecar &
  SIDECAR_PID=$!

  if ! wait_for_health; then
    fail "sidecar failed to restart"; return
  fi

  local restarted_agent_id
  restarted_agent_id=$(python3 -c "import json; print(json.load(open('$STATE_DIR/state.json'))['agent_id'])")

  [ "$original_agent_id" = "$restarted_agent_id" ] \
    && pass "agent_id unchanged after restart ($original_agent_id)" \
    || fail "agent_id changed: $original_agent_id → $restarted_agent_id"

  stop_sidecar
}

test_proxy_shroud() {
  log_test "Proxy — request reaches Shroud and returns"

  start_sidecar_with_state || { fail "sidecar did not start"; return; }

  local resp http_code body
  resp=$(curl -s -w "\n%{http_code}" "http://localhost:$TEST_PORT/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hi"}]}')

  http_code=$(echo "$resp" | tail -1)
  body=$(echo "$resp" | sed '$d')

  # 200 = provider key in vault, 401 = no key (expected for fresh bootstrap)
  if [ "$http_code" = "200" ] || [ "$http_code" = "401" ]; then
    pass "Shroud responded with HTTP $http_code (proxy works)"
  else
    fail "unexpected HTTP $http_code: $body"
  fi

  echo "$body" | python3 -m json.tool >/dev/null 2>&1 \
    && pass "response is valid JSON" \
    || fail "response is not valid JSON: $body"

  stop_sidecar
}

test_proxy_byok() {
  log_test "Proxy — BYOK pass-through header"

  start_sidecar_with_state || { fail "sidecar did not start"; return; }

  local resp http_code
  resp=$(curl -s -w "\n%{http_code}" "http://localhost:$TEST_PORT/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer sk-fake-key-for-test" \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"test"}]}')

  http_code=$(echo "$resp" | tail -1)

  if [ "$http_code" != "000" ] && [ "$http_code" != "502" ]; then
    pass "BYOK request reached Shroud (HTTP $http_code)"
  else
    fail "BYOK request failed: HTTP $http_code"
  fi

  stop_sidecar
}

test_teardown_no_state() {
  log_test "Teardown — no state file (graceful no-op)"

  local empty_dir
  empty_dir=$(mktemp -d)
  local saved_state="$ONECLAW_STATE_FILE"
  export ONECLAW_STATE_FILE="$empty_dir/nonexistent.json"

  cd "$SIDECAR_DIR"
  local output
  output=$(./shroud-sidecar teardown 2>&1)

  echo "$output" | grep -q "nothing to clean up" \
    && pass "graceful no-op when no state file" \
    || fail "unexpected: $output"

  export ONECLAW_STATE_FILE="$saved_state"
  rm -rf "$empty_dir"
}

test_teardown() {
  log_test "Teardown — deletes agent and removes state"

  # Ensure a fresh bootstrap exists
  start_sidecar_with_state || { fail "sidecar did not start"; return; }
  stop_sidecar
  sleep 1

  export ONECLAW_AUTO_DESTROY_VAULT=true
  cd "$SIDECAR_DIR"
  local output
  output=$(./shroud-sidecar teardown 2>&1)
  unset ONECLAW_AUTO_DESTROY_VAULT

  echo "$output" | grep -q "Agent deleted" \
    && pass "agent deleted" \
    || fail "agent delete not confirmed: $output"

  echo "$output" | grep -q "Vault deleted" \
    && pass "vault deleted" \
    || fail "vault delete not confirmed: $output"

  [ ! -f "$STATE_DIR/state.json" ] \
    && pass "state file removed" \
    || fail "state file still exists"

  echo "$output" | grep -q "Cleanup complete" \
    && pass "teardown completed" \
    || fail "teardown incomplete: $output"
}

test_manual_mode() {
  log_test "Manual mode — direct agent credentials"

  # Bootstrap to get real creds
  local saved_vault_name="$ONECLAW_VAULT_NAME"
  local saved_agent_name="$ONECLAW_AGENT_NAME"
  export ONECLAW_VAULT_NAME="sidecar-manual-test-$$"
  export ONECLAW_AGENT_NAME="sidecar-manual-agent-$$"
  local manual_state_dir
  manual_state_dir=$(mktemp -d)

  start_sidecar_with_state "$manual_state_dir" || { fail "could not bootstrap"; return; }

  local agent_id agent_key
  agent_id=$(python3 -c "import json; print(json.load(open('$manual_state_dir/state.json'))['agent_id'])")
  agent_key=$(python3 -c "import json; print(json.load(open('$manual_state_dir/state.json'))['agent_api_key'])")
  stop_sidecar
  sleep 1

  # Switch to manual mode
  local saved_master="$ONECLAW_MASTER_API_KEY"
  unset ONECLAW_MASTER_API_KEY
  export ONECLAW_AGENT_ID="$agent_id"
  export ONECLAW_AGENT_API_KEY="$agent_key"

  cd "$SIDECAR_DIR"
  ./shroud-sidecar &
  SIDECAR_PID=$!

  if wait_for_health; then
    pass "sidecar started in manual mode"

    curl -sf "http://localhost:$TEST_PORT/healthz" | grep -q '"ok"' \
      && pass "health check OK in manual mode" \
      || fail "health check failed in manual mode"
  else
    fail "manual mode sidecar did not start"
  fi

  stop_sidecar

  # Restore and clean up
  export ONECLAW_MASTER_API_KEY="$saved_master"
  unset ONECLAW_AGENT_ID ONECLAW_AGENT_API_KEY
  export ONECLAW_STATE_FILE="$manual_state_dir/state.json"
  export ONECLAW_AUTO_DESTROY_VAULT=true
  cd "$SIDECAR_DIR"
  ./shroud-sidecar teardown 2>&1 | grep -E "\[teardown\]" || true
  unset ONECLAW_AUTO_DESTROY_VAULT

  rm -rf "$manual_state_dir"

  # Restore original names and state dir
  export ONECLAW_VAULT_NAME="$saved_vault_name"
  export ONECLAW_AGENT_NAME="$saved_agent_name"
  export ONECLAW_STATE_FILE="$STATE_DIR/state.json"
}

# ---------- runner ----------

echo ""
echo "Running 1Claw Shroud Sidecar integration tests..."
echo "Sidecar dir: $SIDECAR_DIR"
echo "Test port: $TEST_PORT"
echo ""

test_bootstrap_fresh
test_health_check
test_state_reuse
test_proxy_shroud
test_proxy_byok
test_teardown_no_state
test_teardown
test_manual_mode

echo ""
echo "==============================="
echo "Results: $PASS passed, $FAIL failed (out of $TESTS_RUN tests)"
echo "==============================="

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
