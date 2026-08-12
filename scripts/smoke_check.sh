#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${OPSCOUNCIL_BASE_URL:-http://127.0.0.1:8000}"
REQUIRE_SAFE_RUNTIME="${OPSCOUNCIL_REQUIRE_SAFE_RUNTIME:-true}"
REQUIRE_MODEL="${OPSCOUNCIL_REQUIRE_MODEL:-false}"
REQUIRE_DEPLOYMENT_READY="${OPSCOUNCIL_REQUIRE_DEPLOYMENT_READY:-false}"
REQUIRE_WORKER="${OPSCOUNCIL_REQUIRE_WORKER:-false}"
REQUIRE_FEISHU="${OPSCOUNCIL_REQUIRE_FEISHU:-auto}"
REQUIRE_LAB_FIXTURES="${OPSCOUNCIL_REQUIRE_LAB_FIXTURES:-false}"
WORKER_SERVICE_NAME="${OPSCOUNCIL_WORKER_SERVICE_NAME:-opscouncil-worker}"
FEISHU_SERVICE_NAME="${OPSCOUNCIL_FEISHU_SERVICE_NAME:-opscouncil-feishu}"
FEISHU_ENV_FILE="${OPSCOUNCIL_FEISHU_ENV_FILE:-/etc/opscouncil/feishu.env}"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing command: $1" >&2
    exit 1
  fi
}

secure_file_security() {
  local path="$1"
  if [ "$(id -u)" = "0" ]; then
    stat -c '%u:%a' "$path"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -n stat -c '%u:%a' "$path"
  else
    return 1
  fi
}

json_field() {
  python3 -c '
import json
import sys

field = sys.argv[1]
value = json.load(sys.stdin)
for part in field.split("."):
    value = value[part]
print(value)
' "$1"
}

need_cmd curl
need_cmd python3

curl -fsS "$BASE_URL/healthz" >/dev/null
curl -fsS "$BASE_URL/" >/dev/null
tools_json="$(curl -fsS "$BASE_URL/api/tools")"
runtime_json="$(curl -fsS "$BASE_URL/api/runtime/safety")"
worker_runtime_json="$(curl -fsS "$BASE_URL/api/runtime/worker")"
deployment_json="$(curl -fsS "$BASE_URL/api/deployment/readiness")"
ai_json="$(curl -fsS "$BASE_URL/api/ai/status")"
feishu_json="$(curl -fsS "$BASE_URL/api/channels/feishu/status")"
lab_scenarios_json="$(curl -fsS "$BASE_URL/api/lab/scenarios")"
mcp_init_json="$(curl -fsS "$BASE_URL/mcp" \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"opscouncil-smoke-check","version":"1.0.0"}}}')"
mcp_tools_json="$(curl -fsS "$BASE_URL/mcp" \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Content-Type: application/json' \
  -H 'MCP-Protocol-Version: 2025-11-25' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')"

tool_count="$(printf '%s' "$tools_json" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"
mcp_protocol="$(printf '%s' "$mcp_init_json" | json_field result.protocolVersion)"
mcp_tool_count="$(printf '%s' "$mcp_tools_json" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["result"]["tools"]))')"
runtime_status="$(printf '%s' "$runtime_json" | json_field overall_status)"
runtime_summary="$(printf '%s' "$runtime_json" | json_field summary)"
runtime_user="$(printf '%s' "$runtime_json" | json_field executor.runtime_user)"
runtime_uid="$(printf '%s' "$runtime_json" | json_field executor.runtime_uid)"
worker_runtime_status="$(printf '%s' "$worker_runtime_json" | json_field overall_status)"
worker_runtime_summary="$(printf '%s' "$worker_runtime_json" | json_field summary)"
online_worker_count="$(printf '%s' "$worker_runtime_json" | json_field online_worker_count)"
deployment_status="$(printf '%s' "$deployment_json" | json_field overall_status)"
deployment_summary="$(printf '%s' "$deployment_json" | json_field summary)"
deployment_machine="$(printf '%s' "$deployment_json" | json_field platform.machine)"
deployment_os="$(printf '%s' "$deployment_json" | json_field platform.os)"
ai_configured="$(printf '%s' "$ai_json" | json_field configured)"
chat_model="$(printf '%s' "$ai_json" | json_field chat_model)"
feishu_enabled="$(printf '%s' "$feishu_json" | json_field enabled)"
feishu_connected="$(printf '%s' "$feishu_json" | json_field connected)"
feishu_instance_status="$(printf '%s' "$feishu_json" | json_field instance_status)"
lab_failed_service_status="$(printf '%s' "$lab_scenarios_json" | python3 -c '
import json
import sys

scenarios = json.load(sys.stdin)
match = next((item for item in scenarios if item.get("id") == "failed-service"), None)
print(match.get("status", "missing") if match else "missing")
')"

if [ "$tool_count" -lt 4 ]; then
  echo "tool registry check failed: expected at least 4 tools, got $tool_count" >&2
  exit 1
fi

if [ "$mcp_protocol" != "2025-11-25" ] || [ "$mcp_tool_count" -lt 4 ]; then
  echo "MCP protocol check failed: protocol=$mcp_protocol tools=$mcp_tool_count" >&2
  exit 1
fi

if [ "$REQUIRE_SAFE_RUNTIME" = "true" ] && [ "$runtime_status" != "ok" ]; then
  echo "runtime safety check failed: $runtime_status - $runtime_summary" >&2
  echo "run the service as a restricted account, not with sudo/root." >&2
  exit 2
fi

if [ "$REQUIRE_MODEL" = "true" ] && [ "$ai_configured" != "True" ] && [ "$ai_configured" != "true" ]; then
  echo "model service check failed: BAILIAN_API_KEY is not configured" >&2
  exit 3
fi

if [ "$REQUIRE_DEPLOYMENT_READY" = "true" ] && [ "$deployment_status" != "ok" ]; then
  echo "deployment readiness check failed: $deployment_status - $deployment_summary" >&2
  echo "target platform observed: ${deployment_os}/${deployment_machine}" >&2
  exit 4
fi

worker_status="$worker_runtime_status"
if [ "$REQUIRE_WORKER" = "true" ]; then
  need_cmd systemctl
  if ! systemctl is-active --quiet "$WORKER_SERVICE_NAME"; then
    echo "worker service check failed: $WORKER_SERVICE_NAME is not active" >&2
    exit 5
  fi
  if [ "$worker_runtime_status" = "blocked" ] || [ "$online_worker_count" -lt 1 ]; then
    echo "worker heartbeat check failed: $worker_runtime_summary" >&2
    exit 5
  fi
  worker_status="active/$worker_runtime_status"
fi

feishu_required="false"
if [ "$REQUIRE_FEISHU" = "true" ]; then
  feishu_required="true"
elif [ "$REQUIRE_FEISHU" = "auto" ] && { [ "$feishu_enabled" = "True" ] || [ "$feishu_enabled" = "true" ]; }; then
  feishu_required="true"
fi

feishu_status="not-required"
if [ "$feishu_required" = "true" ]; then
  need_cmd systemctl
  need_cmd stat
  if ! systemctl is-active --quiet "$FEISHU_SERVICE_NAME"; then
    echo "Feishu channel check failed: $FEISHU_SERVICE_NAME is not active" >&2
    exit 6
  fi
  if [ "$feishu_connected" != "True" ] && [ "$feishu_connected" != "true" ]; then
    echo "Feishu channel check failed: long connection is not ready ($feishu_instance_status)" >&2
    exit 6
  fi
  feishu_env_security="$(secure_file_security "$FEISHU_ENV_FILE" 2>/dev/null || true)"
  if [ "$feishu_env_security" != "0:600" ]; then
    echo "Feishu channel check failed: $FEISHU_ENV_FILE must exist with mode 0600" >&2
    echo "run sudo -v before the smoke check so root-owned credential metadata can be verified" >&2
    exit 6
  fi
  feishu_status="connected"
fi

if [ "$REQUIRE_LAB_FIXTURES" = "true" ] && [ "$lab_failed_service_status" != "ready" ]; then
  echo "lab fixture check failed: failed-service status is $lab_failed_service_status" >&2
  echo "install with OPSCOUNCIL_INSTALL_LAB_FIXTURES=true and rerun the smoke check" >&2
  exit 7
fi

echo "OpsCouncil smoke check passed: $BASE_URL"
echo "- tools: $tool_count"
echo "- mcp: $mcp_protocol tools=$mcp_tool_count"
echo "- runtime: $runtime_status ($runtime_user/uid $runtime_uid)"
echo "- deployment: $deployment_status (${deployment_os}/${deployment_machine})"
echo "- model: $chat_model configured=$ai_configured"
echo "- worker: $worker_status"
echo "- Feishu: $feishu_status enabled=$feishu_enabled state=$feishu_instance_status"
echo "- lab fixture: $lab_failed_service_status required=$REQUIRE_LAB_FIXTURES"
