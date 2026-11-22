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
# Add --probe to introspect live HTTP/SSE and STDIO MCP servers directly
prometheus init --repo . [--probe] [--manifest observed_tools.json]

# Wrap any local STDIO MCP server (Cursor / Claude Desktop) with live lockfile pinning & bounds
prometheus wrap --config prometheus.yaml --lockfile prometheus.lock --server billing -- npx -y @modelcontextprotocol/server-billing

# Run central Enterprise Control Plane (MRTR Slack/Web Approval Bridge, Fleet Readiness UI & Signed SOC2 Export)
prometheus control-plane --host 127.0.0.1 --port 8090 --db .prometheus/control_plane.db

# Run any local agent with zero live secrets in its process environment (optionally streaming to Control Plane)
prometheus run --config prometheus.yaml [--collector-url http://127.0.0.1:8090] -- python my_agent.py

# Live / recent flight recorder view
prometheus top --traces .prometheus/traces.jsonl [--follow]

# Verify HMAC chain integrity of the version-pinned compliance ledger
prometheus ledger-verify --traces .prometheus/traces.jsonl

# Simulate `enforce` mode over recorded shadow traffic OR OpenTelemetry (OTel) JSONL spans,
# and optionally export calibrated policies for agentgateway (CEL) or ToolHive / AWS AgentCore (Cedar)
prometheus replay --config prometheus.yaml --traces .prometheus/traces.jsonl --simulate-enforce [--export cel|cedar]

# CI Pull Request gate: diff observed (or live --probe) MCP tools/list against prometheus.lock
prometheus lock --config prometheus.yaml --lockfile prometheus.lock [--probe | --manifest observed_tools.json] --diff

# Refresh approved internal MCP hashes after review
prometheus lock --config prometheus.yaml --lockfile prometheus.lock [--probe | --manifest observed_tools.json] --update

# Compile prometheus.yaml to .prometheus/runtime_policy.json for the Go sidecar
prometheus compile --config prometheus.yaml --out .prometheus/runtime_policy.json
```

---

## Reusable GitHub Action (`prometheus.lock` PR Gate)

Drop MCP manifest rug-pull & Day-1 poisoning gating into any repository in 6 lines of YAML (powered by [action.yml](action.yml)):

```yaml
- name: Prometheus MCP Lockfile Gate
  uses: Tony-Stark2025/prometheus-enterprise@v0.3.0
  with:
    config: prometheus.yaml
    lockfile: prometheus.lock
    probe: "true" # or set `manifest: observed_tools.json`
```

---

## Production Envoy / Kubernetes Deployment

Deploy into EKS / GKE / AKS with the included **Helm Chart + Envoy Gateway `EnvoyExtensionPolicy` CRD** ([deploy/helm/prometheus-sidecar/](deploy/helm/prometheus-sidecar/)):

```bash
helm install prometheus-sidecar ./deploy/helm/prometheus-sidecar \
  --set image.repository=ghcr.io/tony-stark2025/prometheus-sidecar \
  --set secrets.existingSecret=prometheus-sidecar-keys \
  --set redis.enabled=true \
  --set redis.addr=redis-master.default.svc.cluster.local:6379 \
  --set envoyGateway.enabled=true \
  --set envoyGateway.targetRef.name=mcp-agents-route
```

Or run the standalone static Go sidecar binary / distroless non-root image (`sidecar/Dockerfile`):

```bash
cd sidecar
CGO_ENABLED=0 go build -trimpath -o bin/prometheus-sidecar ./cmd/prometheus-sidecar
PROMETHEUS_LEDGER_SIGNING_KEY="$(openssl rand -hex 32)" ./bin/prometheus-sidecar \
  --policy .prometheus/runtime_policy.json \
  --lock prometheus.lock \
  --traces /var/log/prometheus/traces.jsonl \
  --addr 127.0.0.1:8080 \
  --grpc-addr 127.0.0.1:50051 \
  [--redis-addr 127.0.0.1:6379]
```

**Real Envoy Proxy v1.33 Wire E2E Harness** ([deploy/envoy-e2e/](deploy/envoy-e2e/)):

```bash
cd deploy/envoy-e2e
docker compose up -d --build
python3 verify_envoy_e2e.py
docker compose down -v
```

Production SRE features built into the Go sidecar:
- **Official Envoy v3 `ext_proc` + `grpc.health.v1`** on port `50051` (verified against live Envoy v1.33 in CI on every push).
- **Optional Redis/Valkey distributed state** (`--redis-addr` / `PROMETHEUS_REDIS_ADDR`) sharing idempotency keys, per-trace counters, and rolling 1-hour per-principal budgets across Kubernetes replicas.
- **Prometheus `/metrics`** exposition & Prometheus Operator `ServiceMonitor`.
- **MCP `2026-07-28` Multi-Request Tool Resolution (MRTR)** returning structured `resultType: "input_required"` + HMAC-signed `requestState` approval tokens for human-in-the-loop escalations.
- **Bounded memory & graceful shutdown**: 10 MiB payload caps, HTTP timeouts, non-root distroless image, and `SIGTERM`/`SIGINT` graceful drain.

---

## Running All Tests

```bash
# Go sidecar unit + race + Envoy v3 gRPC ext_proc + OIDC RS256/ES256 JWKS + Redis store tests
(cd sidecar && go test -race -v ./...)

# Python control loop + live MCP probe/wrap (Streamable HTTP + Node.js STDIO) + CEL/Cedar export suites
pytest tests/test_sprint_abc_hardening_and_probe.py \
       tests/test_sidecar_integration.py \
       tests/test_agent_control_loop_v3.py \
       tests/test_ifc_and_patch_risk_gate.py \
       tests/test_security_hardening_fixes.py \
       tests/test_commercial_saas_and_agentic_owasp.py \
       tests/test_prometheus_v25_architecture.py -v
```
