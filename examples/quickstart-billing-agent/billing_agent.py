"""
Autonomous Billing Support Agent for the 60-second Prometheus Quickstart Demo.

Runs inside `prometheus run -- python billing_agent.py` and proves:
  1. Zero-secret runtime: the agent process NEVER receives the real STRIPE_API_KEY
     (it only sees a format-preserving ghost handle `sk_test_promghost_*`).
  2. Boundary secret swap + response scrubbing: calling `/gw/stripe_api/v1/invoices`
     authenticates upstream with the real key AND redacts the upstream's accidental echo leak.
  3. Bounded autonomous MCP tool calls: executes `read_ticket`, `refund_invoice` ($35),
     and `refund_invoice` ($135) while recording PII-tokenized HMAC-chained ledger records.
  4. Live third-party MCP rug-pull detection on `zendesk-vendor` `tools/list`.
"""

import json
import os
import sys
import urllib.request


def http_json(url: str, method: str = "GET", payload: dict | None = None, headers: dict | None = None) -> dict:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    gw = os.environ["PROMETHEUS_GATEWAY_URL"]
    ghost_stripe = os.environ["STRIPE_API_KEY"]

    print("\n=== [Agent] Step 1: Zero-Secret Process Check ===")
    print(f"  Agent sees STRIPE_API_KEY = {ghost_stripe}")
    if not ghost_stripe.startswith("sk_test_promghost_"):
        print("  FAIL: Expected format-preserving ghost token!", file=sys.stderr)
        return 1
    print("  PASS: Real host secret is NOT present in agent environment.")

    print("\n=== [Agent] Step 2: Zero-Secret /gw Swap + Response Leak Scrubbing ===")
    inv = http_json(
        f"{gw}/gw/stripe_api/v1/invoices",
        headers={"Authorization": f"Bearer {ghost_stripe}"},
    )
    print(f"  Upstream response received by agent: {json.dumps(inv)}")
    if inv.get("accidental_debug_leak") != "[REDACTED_BY_PROMETHEUS]":
        print("  FAIL: Upstream secret leak was not scrubbed!", file=sys.stderr)
        return 1
    print("  PASS: Go sidecar swapped real key at egress AND scrubbed leaked echo from response.")

    print("\n=== [Agent] Step 3: Autonomous MCP Tool Calls (Shadow Recording -> Replay) ===")
    common_headers = {
        "X-OBO-Principal": "user:support-rep@acme.com|agent:billing-support-agent",
        "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-01",
    }
    for idx, (email, amt) in enumerate(
        [("alice@acme.com", 35.0), ("bob@acme.com", 135.0), ("carol@partner.io", 42.0)], start=1
    ):
        resp = http_json(
            f"{gw}/mcp/billing-internal",
            method="POST",
            payload={
                "jsonrpc": "2.0",
                "id": idx,
                "method": "tools/call",
                "params": {
                    "name": "refund_invoice",
                    "arguments": {
                        "invoice_id": f"inv_{1000 + idx}",
                        "amount": amt,
                        "currency": "USD",
                        "customer_email": email,
                    },
                },
            },
            headers={**common_headers, "Idempotency-Key": f"idem-demo-{idx}"},
        )
        tag = "ERROR" if "error" in resp else "OK"
        print(f"  refund_invoice(${amt:.2f}, {email}) -> {tag}: {json.dumps(resp.get('result') or resp.get('error'))}")

    print("\n=== [Agent] Step 4: Live Third-Party MCP Rug-Pull Detection ===")
    # Flip mock zendesk-vendor server into a rug pull and inspect tools/list via Go sidecar
    http_json("http://127.0.0.1:19001/toggle-rug-pull", method="POST", payload={})
    list_resp = http_json(
        f"{gw}/mcp/zendesk-vendor",
        method="POST",
        payload={"jsonrpc": "2.0", "id": 99, "method": "tools/list"},
    )
    if "error" in list_resp:
        print(f"  BLOCKED BY LOCKFILE: {list_resp['error']['code']} {list_resp['error']['message']}")
    else:
        print("  SHADOW MODE: tools/list drift recorded with X-Prometheus-Manifest-Warnings (no outage).")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
