"""
Live Envoy Proxy v1.33 <-> Prometheus Go Sidecar (`ext_proc` gRPC) Wire Verification.

Sends real HTTP/1.1 requests through Envoy (:10000), which invokes prometheus-sidecar
over HTTP/2 gRPC `envoy.service.ext_proc.v3.ExternalProcessor` (:50051) before and after
proxying to upstream-mcp (:9001).

Verifies:
1. Envoy cluster health (grpc.health.v1) + sidecar /metrics endpoint.
2. In-bounds `tools/call` succeeds through Envoy ext_proc.
3. Out-of-bounds `tools/call` triggers real MCP 2026-07-28 MRTR `input_required` with
   HMAC-signed `requestState`, and succeeds on retry with a signed approval token.
4. Pinned `tools/list` succeeds through Envoy ResponseBody inspection.
5. Upstream `tools/list` rug-pull is rewritten/blocked in-flight via Envoy `BodyMutation` (-32001).
"""

import base64
import hashlib
import hmac
import json
import sys
import time
import urllib.error
import urllib.request

ENVOY_URL = "http://127.0.0.1:10000/mcp/billing-third-party"
UPSTREAM_ADMIN = "http://127.0.0.1:19001/__toggle_rugpull"
SIDECAR_METRICS = "http://127.0.0.1:18080/metrics"
SIGNING_KEY = b"envoy-e2e-signing-key-32-bytes-minimum"


def post_json(url: str, payload: dict, headers: dict | None = None) -> tuple[int, dict]:
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


def wait_for_ready():
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(SIDECAR_METRICS, timeout=2) as r:
                if r.status == 200:
                    code, _ = post_json(
                        ENVOY_URL,
                        {"jsonrpc": "2.0", "id": 0, "method": "tools/list", "params": {}},
                        {"X-Forwarded-User": "alice@acme.com"},
                    )
                    if code == 200:
                        return
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError("Envoy + prometheus-sidecar did not become ready within 30s")


def sign_mrtr_approval(request_state: str) -> str:
    payload_b64, _ = request_state.split(".", 1)
    pad = "=" * ((4 - len(payload_b64) % 4) % 4)
    st = json.loads(base64.urlsafe_b64decode(payload_b64 + pad).decode("utf-8"))
    st["approved"] = True
    raw = json.dumps(st, sort_keys=True, separators=(",", ":")).encode("utf-8")
    mac = hmac.new(SIGNING_KEY, raw, hashlib.sha256).hexdigest()[:32]
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") + "." + mac


def main():
    wait_for_ready()
    base_headers = {
        "X-Forwarded-User": "alice@acme.com",
        "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    }

    # 1. Pinned tools/list passes through Envoy ext_proc
    post_json(UPSTREAM_ADMIN, {"enabled": False})
    code, body = post_json(ENVOY_URL, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, base_headers)
    assert code == 200 and len(body.get("result", {}).get("tools", [])) == 1, f"Pinned tools/list failed: {code} {body}"
    print("[PASS] 1. Real Envoy ext_proc allowed pinned tools/list")

    # 2. In-bounds tools/call passes through Envoy ext_proc
    code, body = post_json(
        ENVOY_URL,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "refund_invoice",
                "arguments": {
                    "invoice_id": "inv-1",
                    "amount": 40,
                    "currency": "USD",
                    "customer_email": "alice@acme.com",
                },
            },
        },
        {**base_headers, "Idempotency-Key": "envoy-e2e-ok-1"},
    )
    assert code == 200 and "result" in body and "error" not in body, f"Allowed tools/call failed: {code} {body}"
    print("[PASS] 2. Real Envoy ext_proc allowed in-bounds tools/call")

    # 3. Over-bounds tools/call returns MCP 2026-07-28 MRTR input_required via Envoy ImmediateResponse
    over_payload = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "refund_invoice",
            "arguments": {
                "invoice_id": "inv-2",
                "amount": 250,
                "currency": "USD",
                "customer_email": "alice@acme.com",
            },
        },
    }
    code, body = post_json(ENVOY_URL, over_payload, {**base_headers, "Idempotency-Key": "envoy-e2e-mrtr-1"})
    res = body.get("result", {})
    assert code == 200 and res.get("resultType") == "input_required" and res.get("requestState"), (
        f"Expected MCP input_required MRTR, got {code} {body}"
    )
    print("[PASS] 3. Real Envoy ext_proc returned MCP 2026-07-28 MRTR input_required")

    # 4. Retry with HMAC-signed MRTR approval token succeeds through Envoy ext_proc
    approval_token = sign_mrtr_approval(res["requestState"])
    code, body = post_json(
        ENVOY_URL,
        over_payload,
        {
            **base_headers,
            "Idempotency-Key": "envoy-e2e-mrtr-1",
            "X-Prometheus-Approval-Token": approval_token,
        },
    )
    assert code == 200 and "content" in body.get("result", {}), f"Approved MRTR retry failed: {code} {body}"
    print("[PASS] 4. Real Envoy ext_proc honored signed MRTR approval token on retry")

    # 5. Live upstream tools/list rug-pull is blocked in-flight via Envoy BodyMutation!
    post_json(UPSTREAM_ADMIN, {"enabled": True})
    code, body = post_json(ENVOY_URL, {"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {}}, base_headers)
    assert body.get("error", {}).get("code") == -32001, f"Expected rug-pull -32001 via BodyMutation, got {code} {body}"
    print("[PASS] 5. Real Envoy ext_proc blocked live upstream tools/list rug-pull via BodyMutation (-32001)")

    # 6. Check sidecar /metrics exposition
    with urllib.request.urlopen(SIDECAR_METRICS, timeout=3) as r:
        metrics_text = r.read().decode("utf-8")
        assert "prometheus_sidecar_rugpulls_blocked_total 1" in metrics_text, f"Missing rugpull metric:\n{metrics_text}"
        assert "prometheus_sidecar_mrtr_escalated_total 1" in metrics_text, f"Missing MRTR metric:\n{metrics_text}"
    print("[PASS] 6. Sidecar /metrics accurately recorded rug-pull block and MRTR escalation")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[FAIL] Envoy E2E verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
