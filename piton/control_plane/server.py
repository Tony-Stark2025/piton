"""
Piton Control Plane HTTP Server & Embedded Governance UI.

Pure Python stdlib (`http.server` + `sqlite3`) — zero heavy runtime dependencies:
- Live MRTR Approval Bridge (REST + Slack Block Kit webhook + verified Slack interactions)
- Multi-Pod Signed Decision Ledger Collector (`POST /api/v1/ledger/ingest`)
- Live MCP Lockfile Drift Collector (`POST /api/v1/drift/ingest`)
- Fleet `shadow -> enforce` Readiness Scorecards (`GET /api/v1/fleet/readiness`)
- Tamper-Evident Signed SOC2 / EU AI Act Audit Bundle Export (`GET /api/v1/audit/export`)
- Embedded Live Web UI (`GET /`) for 1-click MRTR approvals and fleet readiness
"""

import hmac
import json
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional

from piton.control_plane.store import (
    ControlPlaneStore,
    build_slack_mrtr_blocks,
    verify_slack_signature,
)

MAX_REQUEST_BYTES = 2 * 1024 * 1024  # 2 MiB

DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Piton Control Plane — Fleet Governance &amp; MRTR Approvals</title>
  <style>
    :root {
      --bg: #0b0f17; --card: #121826; --border: #232d42;
      --text: #e6edf7; --muted: #8b9bb4; --accent: #f97316;
      --ok: #22c55e; --warn: #eab308; --bad: #ef4444;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); }
    header { display: flex; justify-content: space-between; align-items: center; padding: 16px 24px; border-bottom: 1px solid var(--border); background: #0e1421; }
    h1 { font-size: 18px; margin: 0; letter-spacing: 0.2px; }
    h1 span { color: var(--accent); }
    .actions { display: flex; gap: 10px; align-items: center; }
    input, button { font: inherit; border-radius: 6px; border: 1px solid var(--border); padding: 7px 12px; }
    input { background: #0b0f17; color: var(--text); width: 220px; }
    button { background: var(--accent); color: #0b0f17; font-weight: 600; cursor: pointer; border: none; }
    button.secondary { background: #1e293b; color: var(--text); border: 1px solid var(--border); }
    button.approve { background: var(--ok); color: #062812; }
    button.deny { background: var(--bad); color: #fff; }
    main { max-width: 1280px; margin: 20px auto; padding: 0 20px; display: grid; gap: 20px; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 16px 20px; }
    .card h2 { margin: 0 0 12px; font-size: 15px; color: #cbd5e1; display: flex; justify-content: space-between; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
    th { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.4px; }
    .pill { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
    .pill.ok { background: rgba(34,197,94,0.18); color: var(--ok); }
    .pill.warn { background: rgba(234,179,8,0.18); color: var(--warn); }
    .pill.bad { background: rgba(239,68,68,0.18); color: var(--bad); }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: #93c5fd; word-break: break-all; }
    .muted { color: var(--muted); }
    .btn-row { display: flex; gap: 6px; }
  </style>
</head>
<body>
  <header>
    <h1><span>PITON</span> Enterprise Control Plane</h1>
    <div class="actions">
      <input id="apiKey" type="password" placeholder="X-Piton-Control-Key" autocomplete="off" />
      <input id="approver" value="secops@acme.com" placeholder="Approver email" />
      <button class="secondary" onclick="refreshAll()">Refresh</button>
      <button onclick="exportAudit()">Export Signed SOC2 Audit</button>
    </div>
  </header>
  <main>
    <section id="authBanner" class="card" style="display:none;border-color:var(--bad);">
      <strong style="color:var(--bad);">Authentication required (401):</strong>
      <span class="muted">Enter your <code>PITON_CONTROL_API_KEY</code> in the top bar and click Refresh.</span>
    </section>
    <section class="card">
      <h2>Pending &amp; Recent MRTR Human Approvals <span id="pendingCount" class="pill warn">0 pending</span></h2>
      <table>
        <thead><tr><th>ID</th><th>Agent / Tool</th><th>OBO Principal</th><th>Tokenized Args &amp; Violation</th><th>Status</th><th>Action / Token</th></tr></thead>
        <tbody id="mrtrBody"><tr><td colspan="6" class="muted">Loading...</td></tr></tbody>
      </table>
    </section>

    <section class="card">
      <h2>Fleet Shadow &rarr; Enforce Readiness Scorecards</h2>
      <table>
        <thead><tr><th>Agent</th><th>Total Calls</th><th>Allowed</th><th>Shadow Denies</th><th>MRTR</th><th>Drift Alerts</th><th>HMAC Verified</th><th>Avg Latency</th><th>Ready?</th></tr></thead>
        <tbody id="fleetBody"><tr><td colspan="9" class="muted">Loading...</td></tr></tbody>
      </table>
    </section>

    <section class="card">
      <h2>MCP Lockfile Drift &amp; Poisoning Alerts</h2>
      <table>
        <thead><tr><th>Agent</th><th>Server.Tool</th><th>Kind</th><th>Action</th><th>Message</th></tr></thead>
        <tbody id="driftBody"><tr><td colspan="5" class="muted">Loading...</td></tr></tbody>
      </table>
    </section>

    <section class="card">
      <h2>Recent Signed Decision Ledger</h2>
      <table>
        <thead><tr><th>Agent</th><th>Server.Tool</th><th>OBO Principal</th><th>Verdict</th><th>HMAC</th><th>Latency</th></tr></thead>
        <tbody id="ledgerBody"><tr><td colspan="6" class="muted">Loading...</td></tr></tbody>
      </table>
    </section>
  </main>
  <script>
    function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
    const apiKeyInput = document.getElementById('apiKey');
    apiKeyInput.value = sessionStorage.getItem('piton_control_api_key') || '';
    apiKeyInput.addEventListener('change', () => {
      sessionStorage.setItem('piton_control_api_key', apiKeyInput.value.trim());
    });
    function authHeaders(extra) {
      const h = Object.assign({}, extra || {});
      const key = (apiKeyInput.value || '').trim();
      if (key) h['X-Piton-Control-Key'] = key;
      return h;
    }
    async function apiFetchJson(url, opts) {
      const res = await fetch(url, Object.assign({}, opts || {}, { headers: authHeaders((opts && opts.headers) || {}) }));
      if (res.status === 401) {
        document.getElementById('authBanner').style.display = 'block';
        throw new Error('unauthorized');
      }
      document.getElementById('authBanner').style.display = 'none';
      return res.json();
    }
    async function decide(id, action) {
      const approver = document.getElementById('approver').value || 'secops@acme.com';
      await apiFetchJson(`/api/v1/mrtr/approvals/${encodeURIComponent(id)}/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Approver-Email': approver },
        body: JSON.stringify({ approver })
      });
      await refreshAll();
    }
    async function exportAudit() {
      const data = await apiFetchJson('/api/v1/audit/export');
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `piton-signed-audit-${Date.now()}.json`;
      a.click();
    }
    async function refreshAll() {
      let mrtr, fleet, drifts, ledger;
      try {
        [mrtr, fleet, drifts, ledger] = await Promise.all([
          apiFetchJson('/api/v1/mrtr/approvals'),
          apiFetchJson('/api/v1/fleet/readiness'),
          apiFetchJson('/api/v1/drift/events'),
          apiFetchJson('/api/v1/ledger/recent'),
        ]);
      } catch (_) {
        return;
      }
      const pending = (mrtr.approvals || []).filter(a => a.status === 'pending').length;
      document.getElementById('pendingCount').textContent = `${pending} pending`;
      document.getElementById('mrtrBody').innerHTML = (mrtr.approvals || []).length ? mrtr.approvals.map(a => `
        <tr>
          <td><code>${esc(a.id)}</code></td>
          <td><b>${esc(a.agent_id)}</b><br/><code>${esc(a.server_name)}.${esc(a.tool_name)}</code></td>
          <td><code>${esc(a.principal)}</code></td>
          <td><code>${esc(JSON.stringify(a.tokenized_arguments))}</code><br/><span class="muted">${esc((a.violations||[]).map(v=>v.message||v.rule_id).join('; '))}</span></td>
          <td><span class="pill ${a.status==='approved'?'ok':a.status==='denied'?'bad':'warn'}">${esc(a.status)}</span>${a.decided_by?`<br/><span class="muted">${esc(a.decided_by)}</span>`:''}</td>
          <td>${a.status==='pending'
            ? `<div class="btn-row"><button class="approve" onclick="decide('${esc(a.id)}','approve')">Approve</button><button class="deny" onclick="decide('${esc(a.id)}','deny')">Deny</button></div>`
            : (a.approval_token ? `<code>${esc(a.approval_token.slice(0, 36))}...</code>` : '<span class="muted">&mdash;</span>')}</td>
        </tr>`).join('') : '<tr><td colspan="6" class="muted">No MRTR escalations recorded yet.</td></tr>';

      document.getElementById('fleetBody').innerHTML = (fleet.agents || []).length ? fleet.agents.map(ag => `
        <tr>
          <td><b>${esc(ag.agent_id)}</b></td>
          <td>${ag.total_calls}</td>
          <td>${ag.allowed_calls}</td>
          <td>${ag.shadow_denied_calls} (${ag.shadow_block_rate_pct}%)</td>
          <td>${ag.mrtr_escalated_calls}</td>
          <td>${ag.drift_alerts}</td>
          <td>${ag.verified_hmac_records}/${ag.total_calls}</td>
          <td>${ag.avg_latency_ms}ms</td>
          <td><span class="pill ${ag.ready_to_enforce?'ok':'warn'}">${ag.ready_to_enforce?'READY':'CALIBRATE'}</span></td>
        </tr>`).join('') : '<tr><td colspan="9" class="muted">No agent telemetry ingested yet.</td></tr>';

      document.getElementById('driftBody').innerHTML = (drifts.events || []).length ? drifts.events.map(d => `
        <tr>
          <td><b>${esc(d.agent_id)}</b></td>
          <td><code>${esc(d.server_name)}.${esc(d.tool_name)}</code></td>
          <td><code>${esc(d.kind)}</code></td>
          <td><span class="pill ${d.action==='block'?'bad':'warn'}">${esc(d.action)}</span></td>
          <td>${esc(d.message)}</td>
        </tr>`).join('') : '<tr><td colspan="5" class="muted">No lockfile drift alerts.</td></tr>';

      document.getElementById('ledgerBody').innerHTML = (ledger.records || []).length ? ledger.records.map(r => `
        <tr>
          <td><b>${esc(r.agent_id)}</b></td>
          <td><code>${esc(r.server_name)}.${esc(r.tool_name)}</code></td>
          <td><code>${esc(r.obo_principal || '-')}</code></td>
          <td><span class="pill ${r.verdict==='allow'?'ok':r.verdict==='deny'?'bad':'warn'}">${esc(r.verdict)}</span></td>
          <td><span class="pill ${r.hmac_verified?'ok':'bad'}">${r.hmac_verified?'VERIFIED':'INVALID'}</span></td>
          <td>${Number(r.latency_ms||0).toFixed(1)}ms</td>
        </tr>`).join('') : '<tr><td colspan="6" class="muted">No ledger records ingested yet.</td></tr>';
    }
    refreshAll();
    setInterval(refreshAll, 5000);
  </script>
</body>
</html>
"""


def _post_slack_webhook_async(webhook_url: str, payload: Dict[str, Any]) -> None:
    def _send() -> None:
        try:
            req = urllib.request.Request(
                webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=4) as resp:
                resp.read(4096)
        except Exception:
            pass

    threading.Thread(target=_send, daemon=True).start()


def create_control_plane_server(
    host: str,
    port: int,
    db_path: str | Path,
    signing_key: bytes,
    api_key: str = "",
    slack_webhook_url: str = "",
    slack_signing_secret: str = "",
) -> tuple[ThreadingHTTPServer, ControlPlaneStore]:
    """Creates a threaded Control Plane HTTP server backed by SQLite."""
    store = ControlPlaneStore(db_path=db_path, signing_key=signing_key)
    api_key_clean = api_key.strip()
    slack_url_clean = slack_webhook_url.strip()
    slack_secret_clean = slack_signing_secret.strip()

    class ControlPlaneHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def _send_json(self, code: int, obj: Any) -> None:
            body = json.dumps(obj, sort_keys=True).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, code: int, html: str) -> None:
            body = html.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_body(self) -> Optional[bytes]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return None
            if length < 0 or length > MAX_REQUEST_BYTES:
                return None
            return self.rfile.read(length) if length > 0 else b""

        def _check_api_key(self) -> bool:
            if not api_key_clean:
                return True
            provided = (self.headers.get("X-Piton-Control-Key") or "").strip()
            return hmac.compare_digest(provided, api_key_clean)

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            qs = urllib.parse.parse_qs(parsed.query)

            if path == "/":
                self._send_html(200, DASHBOARD_HTML)
                return
            if path == "/healthz":
                self._send_json(200, {"status": "ok", "service": "piton-control-plane"})
                return
            if not self._check_api_key():
                self._send_json(401, {"error": "unauthorized"})
                return

            if path == "/api/v1/mrtr/approvals":
                status = (qs.get("status") or [None])[0]
                self._send_json(200, {"approvals": store.list_escalations(status=status)})
                return
            if path.startswith("/api/v1/mrtr/approvals/"):
                esc_id = path[len("/api/v1/mrtr/approvals/") :]
                esc = store.get_escalation(esc_id)
                if not esc:
                    self._send_json(404, {"error": "not_found"})
                    return
                self._send_json(200, esc)
                return
            if path == "/api/v1/fleet/readiness":
                self._send_json(200, store.get_fleet_readiness())
                return
            if path == "/api/v1/ledger/recent":
                agent_id = (qs.get("agent_id") or [None])[0]
                self._send_json(200, {"records": store.list_recent_ledger(agent_id=agent_id)})
                return
            if path == "/api/v1/drift/events":
                self._send_json(200, {"events": store.list_drift_events()})
                return
            if path == "/api/v1/audit/export":
                agent_id = (qs.get("agent_id") or [None])[0]
                self._send_json(200, store.build_signed_audit_bundle(agent_id=agent_id))
                return

            self._send_json(404, {"error": "not_found"})

        def do_POST(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            raw = self._read_body()
            if raw is None:
                self._send_json(413, {"error": "payload_too_large"})
                return

            # Slack interactive callback uses Slack HMAC signature verification
            if path == "/api/v1/slack/interactions":
                ts = self.headers.get("X-Slack-Request-Timestamp", "")
                sig = self.headers.get("X-Slack-Signature", "")
                if not verify_slack_signature(slack_secret_clean, ts, raw, sig):
                    self._send_json(401, {"error": "invalid_slack_signature"})
                    return
                form = urllib.parse.parse_qs(raw.decode("utf-8", errors="replace"))
                payload_raw = (form.get("payload") or ["{}"])[0]
                try:
                    interaction = json.loads(payload_raw)
                except Exception:
                    self._send_json(400, {"error": "invalid_slack_payload"})
                    return
                actions = interaction.get("actions") or []
                if not actions:
                    self._send_json(400, {"error": "missing_actions"})
                    return
                action = actions[0]
                esc_id = str(action.get("value") or "")
                approve = action.get("action_id") == "piton_mrtr_approve"
                user = interaction.get("user") or {}
                approver = str(user.get("username") or user.get("name") or user.get("id") or "slack-user")
                esc, err = store.decide_escalation(esc_id, approve=approve, approver=f"slack:{approver}")
                if err:
                    self._send_json(400, {"error": err})
                    return
                self._send_json(
                    200,
                    {
                        "text": f"Escalation `{esc_id}` *{esc['status'].upper()}* by `{esc['decided_by']}`.",
                        "escalation": esc,
                    },
                )
                return

            if not self._check_api_key():
                self._send_json(401, {"error": "unauthorized"})
                return

            ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
            if ctype != "application/json":
                self._send_json(415, {"error": "unsupported_media_type_require_application_json"})
                return

            try:
                body = json.loads(raw.decode("utf-8") or "{}")
            except Exception:
                self._send_json(400, {"error": "invalid_json"})
                return
            if not isinstance(body, dict):
                self._send_json(400, {"error": "expected_json_object"})
                return

            if path == "/api/v1/mrtr/escalations":
                esc, err = store.create_escalation(body)
                if err or not esc:
                    self._send_json(400, {"error": err or "invalid_escalation"})
                    return
                if slack_url_clean:
                    _post_slack_webhook_async(slack_url_clean, build_slack_mrtr_blocks(esc))
                self._send_json(201, esc)
                return

            if path.startswith("/api/v1/mrtr/approvals/") and (
                path.endswith("/approve") or path.endswith("/deny")
            ):
                approve = path.endswith("/approve")
                suffix_len = len("/approve") if approve else len("/deny")
                esc_id = path[len("/api/v1/mrtr/approvals/") : -suffix_len]
                approver = str(
                    self.headers.get("X-Approver-Email")
                    or body.get("approver")
                    or ""
                ).strip()
                esc, err = store.decide_escalation(esc_id, approve=approve, approver=approver)
                if err or not esc:
                    code = 404 if err == "Escalation not found." else 400
                    self._send_json(code, {"error": err or "decision_failed"})
                    return
                self._send_json(200, esc)
                return

            if path == "/api/v1/ledger/ingest":
                stored, verified = store.ingest_ledger_record(body)
                self._send_json(201, {"stored": stored, "hmac_verified": verified})
                return

            if path == "/api/v1/drift/ingest":
                count = store.ingest_drift_events(body)
                self._send_json(201, {"ingested": count})
                return

            self._send_json(404, {"error": "not_found"})

    httpd = ThreadingHTTPServer((host, port), ControlPlaneHandler)
    return httpd, store
