#!/usr/bin/env bash
set -euo pipefail

# 60-Second End-to-End Piton Agent Control Loop Demo
# Runs the exact CLI commands a real developer/platform engineer runs.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'kill ${UPSTREAM_PID:-} 2>/dev/null || true; rm -rf "${WORK_DIR}"' EXIT

cp "${SCRIPT_DIR}/.env.example" "${WORK_DIR}/"
cp "${SCRIPT_DIR}/mcp.json" "${WORK_DIR}/"
cp "${SCRIPT_DIR}/observed_manifest.json" "${WORK_DIR}/"
cp "${SCRIPT_DIR}/billing_agent.py" "${WORK_DIR}/"

# Pick piton CLI from active venv or PATH
if [[ -x "${REPO_ROOT}/.venv/bin/piton" ]]; then
  PROM="${REPO_ROOT}/.venv/bin/piton"
  PY="${REPO_ROOT}/.venv/bin/python"
else
  PROM="piton"
  PY="python3"
fi

# Host holds the real secret; the child agent will NEVER see it.
export STRIPE_API_KEY="sk_live_REAL_HOST_SECRET_DEMO_999"
export PITON_LEDGER_SIGNING_KEY="demo-hmac-signing-key"
export PITON_TOKENIZER_KEY="demo-pii-tokenizer-key"

echo "======================================================================"
echo " 1) Booting local mock Stripe + MCP upstreams (port 19001)"
echo "======================================================================"
"${PY}" "${SCRIPT_DIR}/mock_upstreams.py" 19001 &
UPSTREAM_PID=$!
sleep 0.5

echo ""
echo "======================================================================"
echo " 2) piton init — Discover MCPs, Quarantine Day-1 Poisoned Tools"
echo "======================================================================"
# Exit code 2 is expected because observed_manifest.json includes 1 Day-1 poisoned tool
"${PROM}" init \
  --repo "${WORK_DIR}" \
  --agent-id billing-support-agent \
  --manifest "${WORK_DIR}/observed_manifest.json" || true

# Point the demo's local_dev stripe slot to our local mock upstream & tighten initial refund max to $50
"${PY}" - <<PY
from pathlib import Path
from piton.iac.schema import AgentIaCConfig, ParameterBound, ToolPolicy, ToolTier, BoundExceededAction

cfg_path = Path("${WORK_DIR}/piton.yaml")
cfg = AgentIaCConfig.load_file(cfg_path)
cfg.local_dev_credentials["stripe_api"].upstream_base_url = "http://127.0.0.1:19001"
cfg.local_dev_credentials["stripe_api"].allowed_hosts = ["127.0.0.1"]
cfg.local_dev_credentials["stripe_api"].allowed_path_prefixes = ["/v1/"]
cfg.mcp_servers["billing-internal"].tools["refund_invoice"] = ToolPolicy(
    tier=ToolTier.BOUNDED_WRITE,
    idempotency_key="required",
    parameter_bounds={
        "amount": ParameterBound(min=0.01, max=50.0),
        "customer_email": ParameterBound(allow_domains=["acme.com"]),
    },
    on_bound_exceeded=BoundExceededAction.MRTR_ESCALATE,
)
cfg.save_file(cfg_path)
PY

echo ""
echo "======================================================================"
echo " 3) piton run — Boot Go Sidecar, Strip Real Secrets, Run Agent"
echo "======================================================================"
"${PROM}" run \
  --config "${WORK_DIR}/piton.yaml" \
  --lockfile "${WORK_DIR}/piton.lock" \
  --ghost-env "${WORK_DIR}/.env.agent" \
  --traces "${WORK_DIR}/.piton/traces.jsonl" \
  --compiled-policy "${WORK_DIR}/.piton/runtime_policy.json" \
  --addr 127.0.0.1:18080 \
  -- "${PY}" "${WORK_DIR}/billing_agent.py"

echo ""
echo "======================================================================"
echo " 4) piton top — Flight Recorder (PII-Tokenized Live Ledger)"
echo "======================================================================"
"${PROM}" top --traces "${WORK_DIR}/.piton/traces.jsonl"

echo ""
echo "======================================================================"
echo " 5) piton ledger-verify — Cross-Language Go->Python HMAC Check"
echo "======================================================================"
"${PROM}" ledger-verify --traces "${WORK_DIR}/.piton/traces.jsonl"

echo ""
echo "======================================================================"
echo " 6) piton replay — Calibrate Shadow -> Enforce Before Flipping"
echo "======================================================================"
"${PROM}" replay \
  --config "${WORK_DIR}/piton.yaml" \
  --traces "${WORK_DIR}/.piton/traces.jsonl" \
  --simulate-enforce

echo ""
echo "Demo complete! Every layer of the Agent Control Loop verified."
