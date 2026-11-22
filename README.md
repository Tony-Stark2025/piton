# Prometheus — The Agent Control Loop

**Diff-Governed MCP Manifest Pinning (`prometheus.lock`), Shadow-to-Enforce Policy Calibration (`prometheus replay`), Signed Decision Ledgers & Envoy v3 gRPC `ext_proc` Sidecar.**

Prometheus gives platform engineering and security teams the missing operational control loop above existing agent gateways (`Envoy`, `agentgateway`, `Stacklok ToolHive`, `AWS AgentCore`, `Docker`):

1. **Zero-Friction Day-1 Onboarding (`prometheus init`)** — Statically scans your repo's MCP configs (`.cursor/mcp.json`, `mcp.json`, `claude_desktop_config.json`), `.env.example`, and `docker-compose.yml` to generate clean human-intent `prometheus.yaml` (`mode: shadow`), machine-managed `prometheus.lock`, and safe `.env.agent` ghost handles—while running a deterministic **Day-1 MCP Description-Poisoning Linter** that quarantines covert prompt injections, credential exfil directives, and invisible Unicode before pinning.
2. **Split-Hash MCP Manifest Pinning (`prometheus.lock`)** — Separates `structural_sha256` (`name` + canonical `inputSchema`, hard-blocked on drift everywhere) from `description_sha256` (hard-blocked on `third_party` MCPs to stop rug pulls, `warn` on `internal` MCPs so docstring edits never cause outages), plus cross-server tool-shadowing detection and a drop-in GitHub Action PR diff gate ([prometheus-lock-gate.yml](.github/workflows/prometheus-lock-gate.yml)).
3. **Shadow-to-Enforce Policy Calibration (`prometheus replay` & `prometheus top`)** — Records PII-preserving deterministic tokenized traces (`alice@acme.com` → `tok_8f1a2b3c@acme.com`, keeping domains and numeric ceilings replayable without storing raw PII) into an **HMAC-chained, version-pinned Signed Decision Ledger**, then replays shadow traffic offline to compute exact false-block rates and concrete `parameter_bounds` calibration suggestions before flipping `shadow` → `enforce`.
4. **Static Go Bidirectional Sidecar (`sidecar/`)** — Sub-millisecond production enforcement speaking:
   - **Official Envoy v3 Bidirectional gRPC `ext_proc`** (`envoy.service.ext_proc.v3.ExternalProcessor` on HTTP/2 port `50051`) for Envoy Proxy, Envoy AI Gateway / Agent Router, and Istio.
   - **Cryptographic OIDC JWKS `RS256` / `ES256` Verification** (auto-discovery + TTL cache + key-rotation refresh + RFC 8693 OBO `sub`/`act.sub` extraction, fail-closed).
   - **Zero-Secret Reverse Proxy (`/gw/{slot}/...`) + Bidirectional MCP Proxy (`/mcp/{server}`)**: format-preserving ghost tokens (`sk_test_promghost_*`), `3xx` redirect refusal, `Accept-Encoding` stripping, and a **sliding-window multi-encoding response secret scrubber** (catching secrets split across streaming/SSE chunk boundaries + base64/URL/JSON-escaped leaks).

---

## Architecture

```text
  [ Repo + MCP Configs ] ──► prometheus init (+ Day-1 Poisoning Lint)
                                    │
                   ┌────────────────┴────────────────┐
                   ▼                                 ▼
            prometheus.yaml                   prometheus.lock
       (Human Intent & Bounds)         (Split structural / description pins)
                   │                                 │
                   └────────────────┬────────────────┘
                                    ▼
  [ Envoy / agentgateway / Agent ] ◄──► [ Go Sidecar (ext_proc gRPC + /mcp + /gw) ]
                                           • RS256/ES256 OIDC JWKS + RFC 8693 OBO
                                           • Parameter Bounds + MCP MRTR (-32002)
                                           • Live tools/list Rug-Pull Pin (-32001)
                                           • Sliding-Window Secret Redaction
                                                    │
                                                    ▼
                                     [ Signed Decision Ledger (JSONL) ]
                                       (HMAC-chained, PII-tokenized)
                                                    │
                              ┌─────────────────────┴─────────────────────┐
                              ▼                                           ▼
                       prometheus top                             prometheus replay
                   (Live Flight Recorder)                  (0% False-Block Calibration)
```

---

## 60-Second Quickstart Demo

Requires **Python 3.10+** and **Go 1.24+**.

```bash
# 1. Install Prometheus CLI (editable)
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 2. Run the self-contained 60-second Agent Control Loop demo
bash examples/quickstart-billing-agent/run_demo.sh
```

The demo runs the exact user workflow end-to-end:
1. `prometheus init` discovers MCP servers + `.env.example`, **quarantines a Day-1 poisoned tool**, and writes `prometheus.yaml`, `prometheus.lock`, and `.env.agent`.
2. `prometheus run -- python billing_agent.py` compiles policy, boots the Go sidecar with the real host `STRIPE_API_KEY`, **strips the real key from the agent process**, verifies the `/gw/stripe_api` egress swap + response leak scrubbing, and executes autonomous MCP calls.
3. `prometheus top` displays the PII-tokenized flight recorder.
4. `prometheus ledger-verify` cryptographically verifies the Go-written HMAC chain in Python.
5. `prometheus replay --simulate-enforce` calculates exact block rates and outputs concrete `parameter_bounds` calibrations before promoting to `enforce`.

---

## CLI Reference

```bash
# Generate prometheus.yaml (shadow), prometheus.lock, and .env.agent
prometheus init --repo . [--manifest observed_tools.json]

# Run any local agent with zero live secrets in its process environment
prometheus run --config prometheus.yaml -- python my_agent.py

# Live / recent flight recorder view
prometheus top --traces .prometheus/traces.jsonl [--follow]

# Verify HMAC chain integrity of the version-pinned compliance ledger
prometheus ledger-verify --traces .prometheus/traces.jsonl

# Simulate `enforce` mode over recorded shadow traffic to calibrate bounds
prometheus replay --config prometheus.yaml --traces .prometheus/traces.jsonl --simulate-enforce

# CI Pull Request gate: diff observed MCP tools/list against prometheus.lock
prometheus lock --config prometheus.yaml --lockfile prometheus.lock --manifest observed_tools.json --diff

# Refresh approved internal MCP hashes after review
prometheus lock --config prometheus.yaml --lockfile prometheus.lock --manifest observed_tools.json --update

# Compile prometheus.yaml to .prometheus/runtime_policy.json for the Go sidecar
prometheus compile --config prometheus.yaml --out .prometheus/runtime_policy.json
```

---

## Production Envoy / Kubernetes Deployment

Build the standalone static Go sidecar binary:

```bash
cd sidecar
CGO_ENABLED=0 go build -o bin/prometheus-sidecar ./cmd/prometheus-sidecar
./bin/prometheus-sidecar \
  --policy .prometheus/runtime_policy.json \
  --lock prometheus.lock \
  --traces /var/log/prometheus/traces.jsonl \
  --addr 127.0.0.1:8080 \
  --grpc-addr 127.0.0.1:50051
```

Wire Envoy's `envoy.filters.http.ext_proc` filter to `127.0.0.1:50051` using the included reference config [sidecar/deploy/envoy-ext-proc.yaml](sidecar/deploy/envoy-ext-proc.yaml).

---

## Running All Tests

```bash
# Go sidecar unit + race + Envoy v3 gRPC ext_proc + OIDC RS256/ES256 JWKS tests
(cd sidecar && go test -race -v ./...)

# Python control loop + cross-language Go<->Python integration + security test suites
pytest tests/test_sidecar_integration.py \
       tests/test_agent_control_loop_v3.py \
       tests/test_ifc_and_patch_risk_gate.py \
       tests/test_security_hardening_fixes.py \
       tests/test_commercial_saas_and_agentic_owasp.py \
       tests/test_prometheus_v25_architecture.py -v
```
