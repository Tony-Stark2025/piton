"""
End-to-End Cross-Language Integration Test for the Prometheus Enterprise Control Plane:
- Real compiled Go `prometheus-sidecar` <-> Python Control Plane Server (SQLite)
- Uber-style Declarative Response Projection (dot-paths + `/metrics` byte savings)
- Live MCP 2026-07-28 MRTR Escalation -> Slack Block Kit Webhook -> Signed Slack Interaction
  Callback -> Python-minted `X-Prometheus-MRTR-Approval` -> Go Sidecar Verification & Retry
- Multi-Pod Signed Decision Ledger Ingestion (cross-language Go->Python HMAC verification)
- Fleet `shadow -> enforce` Readiness Scorecards, Embedded Governance UI & Signed SOC2 Export
"""

import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

from prometheus.control_plane.server import create_control_plane_server
from prometheus.iac.schema import (
    AgentIaCConfig,
    AgentMeta,
    BoundExceededAction,
    EnforcementMode,
    IdentityConfig,
    IdentityMode,
    MCPServerPolicy,
    ParameterBound,
    ToolPolicy,
    ToolTier,
    TrustTier,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SIDECAR_BIN = REPO_ROOT / "sidecar" / "bin" / "prometheus-sidecar"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _post_json(url: str, payload: dict, headers: dict | None = None) -> tuple[int, dict]:
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), method="POST", headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw}


def _get_json(url: str, headers: dict | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(url, method="GET", headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw}


def test_enterprise_control_plane_mrtr_slack_projection_and_audit_e2e(tmp_path: Path):
    from prometheus.cli import _resolve_sidecar_binary

    sidecar_bin = _resolve_sidecar_binary(None)
    if sidecar_bin is None or not sidecar_bin.is_file():
        pytest.skip("prometheus-sidecar binary unavailable")

    signing_key = b"enterprise-control-plane-signing-key-32b"
    control_api_key = "cp-live-api-key-99"
    slack_signing_secret = "slack-secret-xyz-123"

    # 1. Start mock Slack Incoming Webhook receiver
    slack_received: list[dict] = []

    class MockSlackHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            slack_received.append(json.loads(self.rfile.read(n).decode("utf-8")))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

    slack_srv = HTTPServer(("127.0.0.1", 0), MockSlackHandler)
    slack_port = slack_srv.server_address[1]
    threading.Thread(target=slack_srv.serve_forever, daemon=True).start()

    # 2. Start real Control Plane server (SQLite)
    cp_port = _free_port()
    cp_httpd, cp_store = create_control_plane_server(
        host="127.0.0.1",
        port=cp_port,
        db_path=tmp_path / "control_plane.db",
        signing_key=signing_key,
        api_key=control_api_key,
        slack_webhook_url=f"http://127.0.0.1:{slack_port}/services/T00/B00/XXX",
        slack_signing_secret=slack_signing_secret,
    )
    threading.Thread(target=cp_httpd.serve_forever, daemon=True).start()
    cp_url = f"http://127.0.0.1:{cp_port}"

    # 3. Start live MCP upstream returning unprojected PII/bloat on get_customer_invoice
    class UpstreamMCPHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(n).decode("utf-8"))
            params = req.get("params") or {}
            tool = params.get("name")
            if tool == "get_customer_invoice":
                inner = {
                    "invoice_id": "inv_777",
                    "status": "paid",
                    "raw_ssn": "999-88-7777",
                    "internal_audit_blob": "B" * 600,
                    "customer": {"tier": "enterprise", "credit_card": "4111-2222-3333-4444"},
                }
            else:
                inner = {"status": "refunded", "amount": (params.get("arguments") or {}).get("amount")}
            body = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": req.get("id"),
                    "result": {"content": [{"type": "text", "text": json.dumps(inner)}]},
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    up_srv = HTTPServer(("127.0.0.1", 0), UpstreamMCPHandler)
    up_port = up_srv.server_address[1]
    threading.Thread(target=up_srv.serve_forever, daemon=True).start()

    # 4. Compile runtime_policy.json with response_projection + MRTR bounds
    cfg = AgentIaCConfig(
        agent=AgentMeta(id="billing-enterprise-agent", owner="secops@acme.com", mode=EnforcementMode.ENFORCE),
        identity=IdentityConfig(mode=IdentityMode.OIDC_OBO, require_delegated_sub=True, allow_trusted_headers=True),
        mcp_servers={
            "billing-mcp": MCPServerPolicy(
                url=f"http://127.0.0.1:{up_port}/mcp",
                trust_tier=TrustTier.INTERNAL,
                tools={
                    "get_customer_invoice": ToolPolicy(
                        tier=ToolTier.READ,
                        response_projection=["invoice_id", "status", "customer.tier"],
                    ),
                    "refund_invoice": ToolPolicy(
                        tier=ToolTier.BOUNDED_WRITE,
                        idempotency_key="required",
                        parameter_bounds={"amount": ParameterBound(min=0.01, max=100.0)},
                        on_bound_exceeded=BoundExceededAction.MRTR_ESCALATE,
                    ),
                },
            )
        },
    )
    policy_path = tmp_path / "runtime_policy.json"
    policy_path.write_text(json.dumps(cfg.model_dump(mode="json", exclude_none=True), indent=2), encoding="utf-8")
    traces_path = tmp_path / "traces.jsonl"

    sidecar_port = _free_port()
    env = os.environ.copy()
    env["PROMETHEUS_LEDGER_SIGNING_KEY"] = signing_key.decode("utf-8")
    env["PROMETHEUS_CONTROL_API_KEY"] = control_api_key
    sidecar_proc = subprocess.Popen(
        [
            str(sidecar_bin),
            "--policy", str(policy_path),
            "--lock", "",
            "--traces", str(traces_path),
            "--addr", f"127.0.0.1:{sidecar_port}",
            "--collector-url", cp_url,
        ],
        env=env,
    )

    try:
        # Wait for Go sidecar /healthz
        for _ in range(50):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{sidecar_port}/healthz", timeout=0.2) as r:
                    if r.status == 200:
                        break
            except Exception:
                time.sleep(0.1)

        base_hdrs = {
            "X-Forwarded-User": "alice@acme.com",
            "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        }
        cp_hdrs = {"X-Prometheus-Control-Key": control_api_key}

        # Step A: Uber-style Response Projection strips raw_ssn, credit_card, and 600-byte blob
        code, body = _post_json(
            f"http://127.0.0.1:{sidecar_port}/mcp/billing-mcp",
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "get_customer_invoice", "arguments": {}}},
            base_hdrs,
        )
        assert code == 200
        inner_resp = json.loads(body["result"]["content"][0]["text"])
        assert inner_resp == {"invoice_id": "inv_777", "status": "paid", "customer": {"tier": "enterprise"}}
        with urllib.request.urlopen(f"http://127.0.0.1:{sidecar_port}/metrics", timeout=2) as r:
            metrics_txt = r.read().decode("utf-8")
            assert "prometheus_sidecar_bytes_projected_total " in metrics_txt
            assert "prometheus_sidecar_bytes_projected_total 0\n" not in metrics_txt

        # Step B: Over-bounds refund ($250 > $100) triggers MRTR input_required + async Control Plane + Slack webhook
        refund_payload = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "refund_invoice", "arguments": {"amount": 250.0}},
        }
        code, body = _post_json(
            f"http://127.0.0.1:{sidecar_port}/mcp/billing-mcp",
            refund_payload,
            {**base_hdrs, "Idempotency-Key": "cp-e2e-refund-1"},
        )
        assert code == 200
        assert body["result"]["resultType"] == "input_required"

        # Poll Control Plane until async escalation + Slack Block Kit prompt arrive
        approvals = []
        for _ in range(40):
            _, data = _get_json(f"{cp_url}/api/v1/mrtr/approvals?status=pending", cp_hdrs)
            approvals = data.get("approvals") or []
            if approvals and slack_received:
                break
            time.sleep(0.1)
        assert len(approvals) == 1
        esc_id = approvals[0]["id"]
        assert len(slack_received) == 1
        assert slack_received[0]["blocks"][0]["text"]["text"].startswith("Prometheus MRTR")

        # Step C: Unsigned Slack callback MUST be rejected 401; signed Slack callback approves & mints token!
        interaction_form = urllib.parse.urlencode(
            {
                "payload": json.dumps(
                    {
                        "user": {"username": "secops-lead"},
                        "actions": [{"action_id": "prometheus_mrtr_approve", "value": esc_id}],
                    }
                )
            }
        ).encode("utf-8")
        bad_req = urllib.request.Request(
            f"{cp_url}/api/v1/slack/interactions",
            data=interaction_form,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded", "X-Slack-Request-Timestamp": str(int(time.time())), "X-Slack-Signature": "v0=bad"},
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(bad_req, timeout=3)
        assert exc_info.value.code == 401

        ts_str = str(int(time.time()))
        slack_sig = "v0=" + hmac.new(
            slack_signing_secret.encode("utf-8"),
            f"v0:{ts_str}:".encode("utf-8") + interaction_form,
            hashlib.sha256,
        ).hexdigest()
        good_req = urllib.request.Request(
            f"{cp_url}/api/v1/slack/interactions",
            data=interaction_form,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Slack-Request-Timestamp": ts_str,
                "X-Slack-Signature": slack_sig,
            },
        )
        with urllib.request.urlopen(good_req, timeout=3) as resp:
            assert resp.status == 200

        # Step D: Agent fetches approved token from Control Plane and retries through Go sidecar -> ADMITTED!
        code, esc_after = _get_json(f"{cp_url}/api/v1/mrtr/approvals/{esc_id}", cp_hdrs)
        assert code == 200
        assert esc_after["status"] == "approved"
        assert esc_after["decided_by"] == "slack:secops-lead"
        approval_token = esc_after["approval_token"]
        assert approval_token

        code, retry_body = _post_json(
            f"http://127.0.0.1:{sidecar_port}/mcp/billing-mcp",
            refund_payload,
            {
                **base_hdrs,
                "Idempotency-Key": "cp-e2e-refund-1",
                "X-Prometheus-MRTR-Approval": approval_token,
            },
        )
        assert code == 200
        retry_inner = json.loads(retry_body["result"]["content"][0]["text"])
        assert retry_inner["status"] == "refunded"
        assert retry_inner["amount"] == 250.0

        # Step E: Verify Fleet Ledger HMAC parity, Readiness Scorecard, Governance UI, and Signed SOC2 Bundle
        readiness = {}
        for _ in range(40):
            _, readiness = _get_json(f"{cp_url}/api/v1/fleet/readiness", cp_hdrs)
            if readiness.get("agents") and readiness["agents"][0]["total_calls"] >= 3:
                break
            time.sleep(0.1)

        agent_row = readiness["agents"][0]
        assert agent_row["agent_id"] == "billing-enterprise-agent"
        assert agent_row["total_calls"] == 3
        assert agent_row["allowed_calls"] == 2
        assert agent_row["mrtr_escalated_calls"] == 1
        assert agent_row["verified_hmac_records"] == 3  # 100% Go->Python HMAC verification!

        # Embedded Governance Web UI renders cleanly
        with urllib.request.urlopen(f"{cp_url}/", timeout=3) as ui_resp:
            html = ui_resp.read().decode("utf-8")
            assert ui_resp.status == 200
            assert "PROMETHEUS" in html and "MRTR Human Approvals" in html

        # Signed SOC2 / EU AI Act Audit Bundle verifies cleanly
        code, bundle = _get_json(f"{cp_url}/api/v1/audit/export", cp_hdrs)
        assert code == 200
        assert bundle["schema"] == "prometheus.compliance.audit_bundle.v1"
        assert len(bundle["decision_ledger"]) == 3
        assert len(bundle["mrtr_approvals"]) == 1
        body_no_sig = {k: v for k, v in bundle.items() if k != "integrity"}
        canon = json.dumps(body_no_sig, sort_keys=True, separators=(",", ":")).encode("utf-8")
        assert bundle["integrity"]["bundle_sha256"] == hashlib.sha256(canon).hexdigest()
        assert bundle["integrity"]["bundle_hmac"] == hmac.new(signing_key, canon, hashlib.sha256).hexdigest()
    finally:
        sidecar_proc.terminate()
        try:
            sidecar_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            sidecar_proc.kill()
        cp_httpd.shutdown()
        cp_httpd.server_close()
        cp_store.close()
        up_srv.shutdown()
        up_srv.server_close()
        slack_srv.shutdown()
        slack_srv.server_close()
