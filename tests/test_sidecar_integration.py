"""
Cross-Language Go <-> Python End-to-End Integration Test for the Prometheus Agent Control Loop:
1. `prometheus init` generates `prometheus.yaml` (shadow), `prometheus.lock`, and `.env.agent`
2. `prometheus run -- <agent>` compiles policy, boots the static Go sidecar, strips real host
   secrets from the child agent process, injects format-preserving ghost tokens, proxies real
   HTTP (/gw) and MCP (/mcp) requests, and writes HMAC-chained PII-tokenized ledger records
3. Python `SignedDecisionLedger.verify_chain()` verifies the Go-written cryptographic chain!
4. Python `replay_traces()` calibrates the Go-recorded shadow traffic for safe promotion to `enforce`!
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import socket
import sys
import threading

from prometheus.cli import main as cli_main
from prometheus.iac.replay import SignedDecisionLedger, replay_traces
from prometheus.iac.schema import (
    AgentIaCConfig,
    BoundExceededAction,
    EnforcementMode,
    ParameterBound,
    ToolPolicy,
    ToolTier,
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_prometheus_run_go_sidecar_and_cross_language_ledger_replay(tmp_path: Path, monkeypatch):
    real_stripe_secret = "sk_live_HOST_ONLY_SECRET_987654321"
    monkeypatch.setenv("STRIPE_API_KEY", real_stripe_secret)
    monkeypatch.setenv("PROMETHEUS_LEDGER_SIGNING_KEY", "cross-lang-hmac-secret")
    monkeypatch.setenv("PROMETHEUS_TOKENIZER_KEY", "cross-lang-tok-secret")

    # 1. Start a real local mock upstream (serving both /v1/invoices REST and /mcp JSON-RPC)
    received_auth_headers = []

    class UpstreamHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            received_auth_headers.append(self.headers.get("Authorization"))
            body = json.dumps({"ok": True, "echo_leak": real_stripe_secret}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(length).decode("utf-8"))
            if req.get("method") == "tools/list":
                resp = {
                    "jsonrpc": "2.0",
                    "id": req.get("id"),
                    "result": {
                        "tools": [
                            {
                                "name": "refund_invoice",
                                "description": "Issues a refund for an invoice.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "amount": {"type": "number"},
                                        "customer_email": {"type": "string"},
                                    },
                                },
                            }
                        ]
                    },
                }
            else:
                resp = {"jsonrpc": "2.0", "id": req.get("id"), "result": {"status": "refunded"}}
            raw = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(raw)

    upstream_port = _free_port()
    upstream_server = HTTPServer(("127.0.0.1", upstream_port), UpstreamHandler)
    t = threading.Thread(target=upstream_server.serve_forever, daemon=True)
    t.start()

    try:
        # 2. Seed mock repo and run `prometheus init`
        (tmp_path / ".env.example").write_text("STRIPE_API_KEY=\n", encoding="utf-8")
        (tmp_path / "mcp.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "billing-internal": {"url": f"http://127.0.0.1:{upstream_port}/mcp"}
                    }
                }
            ),
            encoding="utf-8",
        )
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "billing-internal": [
                        {
                            "name": "refund_invoice",
                            "description": "Issues a refund for an invoice.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "amount": {"type": "number"},
                                    "customer_email": {"type": "string"},
                                },
                            },
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        assert cli_main(["init", "--repo", str(tmp_path), "--manifest", str(manifest_path)]) == 0

        # Point local_dev_credentials stripe_api upstream to our local test server & tighten refund max=50
        cfg_path = tmp_path / "prometheus.yaml"
        cfg = AgentIaCConfig.load_file(cfg_path)
        cfg.local_dev_credentials["stripe_api"].upstream_base_url = f"http://127.0.0.1:{upstream_port}"
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

        # 3. Write an autonomous child agent script that proves:
        #    (a) It NEVER sees the real host secret in os.environ
        #    (b) Calling /gw/stripe_api swaps the real secret at the boundary & scrubs response leaks
        #    (c) Calling /mcp/billing-internal records shadow traces to the Go-written ledger
        agent_script = tmp_path / "agent.py"
        agent_script.write_text(
            f"""
import json, os, urllib.request

# (a) Zero-secret guarantee: real host secret must NOT exist in agent process env!
agent_key = os.environ["STRIPE_API_KEY"]
assert agent_key.startswith("sk_test_promghost_"), f"Expected ghost token, got {{agent_key}}"
assert "{real_stripe_secret}" not in str(dict(os.environ)), "Real secret leaked into agent env!"

gw_url = os.environ["PROMETHEUS_GATEWAY_URL"]

# (b) Call zero-secret /gw reverse proxy with ghost token -> response echo must be scrubbed!
req = urllib.request.Request(
    gw_url + "/gw/stripe_api/v1/invoices",
    headers={{"Authorization": "Bearer " + agent_key}},
)
with urllib.request.urlopen(req, timeout=5) as resp:
    body = resp.read().decode("utf-8")
    assert resp.status == 200
    assert "{real_stripe_secret}" not in body, f"Secret leaked in body: {{body}}"
    assert "[REDACTED_BY_PROMETHEUS]" in body

# (c) Call bidirectional MCP proxy in shadow mode (1 within $50 bound, 1 above $50 bound)
for idx, amt in enumerate([25.5, 135.5], start=1):
    payload = json.dumps({{
        "jsonrpc": "2.0",
        "id": idx,
        "method": "tools/call",
        "params": {{
            "name": "refund_invoice",
            "arguments": {{"amount": amt, "customer_email": f"user{{idx}}@acme.com"}},
        }},
    }}).encode("utf-8")
    mreq = urllib.request.Request(
        gw_url + "/mcp/billing-internal",
        data=payload,
        headers={{
            "Content-Type": "application/json",
            "X-OBO-Principal": "user:rep@acme.com|agent:billing",
            "Idempotency-Key": f"idem-{{idx}}",
            "traceparent": f"00-trace-live-{{idx}}-01",
        }},
    )
    with urllib.request.urlopen(mreq, timeout=5) as mresp:
        assert mresp.status == 200
        data = json.loads(mresp.read().decode("utf-8"))
        assert "result" in data
""",
            encoding="utf-8",
        )

        sidecar_port = _free_port()
        traces_path = tmp_path / ".prometheus" / "traces.jsonl"
        compiled_path = tmp_path / ".prometheus" / "runtime_policy.json"

        rc = cli_main(
            [
                "run",
                "--config", str(cfg_path),
                "--lockfile", str(tmp_path / "prometheus.lock"),
                "--ghost-env", str(tmp_path / ".env.agent"),
                "--traces", str(traces_path),
                "--compiled-policy", str(compiled_path),
                "--addr", f"127.0.0.1:{sidecar_port}",
                "--",
                sys.executable,
                str(agent_script),
            ]
        )
        assert rc == 0

        # Confirm upstream genuinely received the real host secret swapped in by the Go sidecar
        assert received_auth_headers == [f"Bearer {real_stripe_secret}"]

        # 4. Cross-language cryptographic verification: Python verifies Go-written HMAC ledger!
        ledger = SignedDecisionLedger(traces_path, signing_key=b"cross-lang-hmac-secret")
        records = ledger.load_records()
        assert len(records) == 2
        # Verify raw PII never landed in Go-written ledger
        raw_ledger = traces_path.read_text(encoding="utf-8")
        assert "user1@acme.com" not in raw_ledger
        assert "@acme.com" in raw_ledger

        ok, err = ledger.verify_chain()
        assert ok is True, f"Cross-language Go->Python HMAC ledger verification failed: {err}"

        # 5. Python `replay_traces()` replays Go-written shadow traffic and recommends exact calibration!
        report = replay_traces(cfg, records, simulate_enforce=True)
        assert report.total_replayed == 2
        assert report.allowed_count == 1
        assert report.blocked_or_escalated_count == 1
        assert report.violations_by_rule["PARAM_MAX_EXCEEDED"] == 1
        assert any("136" in s.suggestion for s in report.suggestions)

    finally:
        upstream_server.shutdown()
