"""
Persistent SQLite Control Plane Store for:
- MCP 2026-07-28 MRTR Human-in-the-Loop Escalations & Cryptographic Approval Signing
- Multi-Pod Signed Decision Ledger Ingestion (with Go<->Python HMAC verification)
- Live MCP Lockfile Drift Alerting
- Per-Agent `shadow -> enforce` Readiness Scorecards & Signed Compliance Bundles
"""

import base64
import hashlib
import hmac
import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from prometheus.iac.schema import normalize_json_numbers


def _hmac_hex(key: bytes, payload: bytes, length: int = 0) -> str:
    digest = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return digest[:length] if length > 0 else digest


def verify_and_decode_mrtr_state(request_state: str, signing_key: bytes) -> Optional[Dict[str, Any]]:
    """
    Verifies a Go-minted MCP MRTR `requestState` (`base64url_nopad(json).hmac32`)
    using constant-time HMAC-SHA256 verification and returns the decoded payload dict.
    """
    parts = request_state.strip().split(".")
    if len(parts) != 2:
        return None
    b64_payload, sig = parts
    pad = "=" * ((4 - len(b64_payload) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(b64_payload + pad)
    except Exception:
        return None
    expected = _hmac_hex(signing_key, raw, 32)
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    return data


def mint_approved_mrtr_token(request_state: str, signing_key: bytes) -> Tuple[Optional[str], Optional[str]]:
    """
    Cryptographically verifies an incoming MRTR `requestState`, ensures it has not
    expired, flips `approved: true`, and returns a freshly signed `X-Prometheus-MRTR-Approval`
    token accepted by the Go Envoy `ext_proc` and HTTP `/mcp/` sidecars.
    """
    payload = verify_and_decode_mrtr_state(request_state, signing_key)
    if payload is None:
        return None, "Invalid or tampered MRTR requestState signature."
    expires_at = int(payload.get("expires_at") or 0)
    if expires_at > 0 and time.time() > expires_at:
        return None, "MRTR requestState has expired."

    payload["approved"] = True
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    mac = _hmac_hex(signing_key, raw, 32)
    token = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") + "." + mac
    return token, None


def verify_decision_record_hmac(record: Dict[str, Any], signing_key: bytes) -> bool:
    """Verifies a Go/Python DecisionLedgerRecord HMAC-SHA256 signature."""
    provided = str(record.get("record_hmac") or "")
    if not provided:
        return False
    body = {k: v for k, v in record.items() if k != "record_hmac"}
    normalized = normalize_json_numbers(body)
    canonical = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected = _hmac_hex(signing_key, canonical)
    return hmac.compare_digest(provided, expected)


def verify_slack_signature(
    signing_secret: str,
    timestamp: str,
    raw_body: bytes,
    provided_signature: str,
    max_skew_seconds: int = 300,
) -> bool:
    """Verifies Slack webhook interactive callback `X-Slack-Signature` (v0=HMAC-SHA256)."""
    if not signing_secret or not timestamp or not provided_signature:
        return False
    try:
        ts_int = int(timestamp)
    except ValueError:
        return False
    if abs(time.time() - ts_int) > max_skew_seconds:
        return False
    base = f"v0:{timestamp}:".encode("utf-8") + raw_body
    expected = "v0=" + hmac.new(signing_secret.encode("utf-8"), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(provided_signature.strip(), expected)


def build_slack_mrtr_blocks(escalation: Dict[str, Any]) -> Dict[str, Any]:
    """Constructs a Slack Block Kit interactive approval prompt for an MRTR escalation."""
    esc_id = escalation["id"]
    agent_id = escalation["agent_id"]
    server = escalation["server_name"]
    tool = escalation["tool_name"]
    principal = escalation.get("principal") or "unknown"
    args_preview = json.dumps(escalation.get("tokenized_arguments") or {}, sort_keys=True)
    violations = escalation.get("violations") or []
    reason = "; ".join(str(v.get("message") or v.get("rule_id") or "") for v in violations) or "Exceeds autonomous bounds"

    return {
        "text": f"[Prometheus MRTR] Approval required for {agent_id}: {server}.{tool}",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "Prometheus MRTR — Human Approval Required"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Agent:*\n`{agent_id}`"},
                    {"type": "mrkdwn", "text": f"*Tool:*\n`{server}.{tool}`"},
                    {"type": "mrkdwn", "text": f"*OBO Principal:*\n`{principal}`"},
                    {"type": "mrkdwn", "text": f"*Escalation ID:*\n`{esc_id}`"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Reason:* {reason}\n*Tokenized Args:* `{args_preview}`"},
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Approve & Sign Token"},
                        "style": "primary",
                        "action_id": "prometheus_mrtr_approve",
                        "value": esc_id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Deny"},
                        "style": "danger",
                        "action_id": "prometheus_mrtr_deny",
                        "value": esc_id,
                    },
                ],
            },
        ],
    }


class ControlPlaneStore:
    """Thread-safe SQLite backing store for fleet ledgers, drift alerts, and MRTR approvals."""

    def __init__(self, db_path: str | Path, signing_key: bytes):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.signing_key = signing_key
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS mrtr_approvals (
                    id TEXT PRIMARY KEY,
                    created_at REAL NOT NULL,
                    agent_id TEXT NOT NULL,
                    server_name TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    principal TEXT NOT NULL,
                    request_state TEXT NOT NULL,
                    tokenized_arguments_json TEXT NOT NULL,
                    violations_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    decided_by TEXT,
                    decided_at REAL,
                    approval_token TEXT
                );

                CREATE TABLE IF NOT EXISTS fleet_ledger (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    agent_id TEXT NOT NULL,
                    traceparent TEXT NOT NULL,
                    obo_principal TEXT,
                    server_name TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    latency_ms REAL NOT NULL,
                    policy_sha256 TEXT NOT NULL,
                    lockfile_sha256 TEXT NOT NULL,
                    record_hmac TEXT NOT NULL,
                    hmac_verified INTEGER NOT NULL,
                    raw_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS drift_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    agent_id TEXT NOT NULL,
                    server_name TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    action TEXT NOT NULL,
                    message TEXT NOT NULL
                );
                """
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------
    # MRTR Escalations & Human Approvals
    # ------------------------------------------------------------------

    def create_escalation(self, payload: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        request_state = str(payload.get("request_state") or "").strip()
        if not request_state:
            return None, "Missing request_state."
        if verify_and_decode_mrtr_state(request_state, self.signing_key) is None:
            return None, "Rejected escalation: invalid MRTR request_state HMAC signature."

        esc_id = f"mrtr_{uuid.uuid4().hex[:12]}"
        created_at = float(payload.get("timestamp") or time.time())
        agent_id = str(payload.get("agent_id") or "unknown-agent")
        server_name = str(payload.get("server_name") or "")
        tool_name = str(payload.get("tool_name") or "")
        principal = str(payload.get("principal") or "")
        tok_args = payload.get("tokenized_arguments") or {}
        violations = payload.get("violations") or []

        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO mrtr_approvals (
                    id, created_at, agent_id, server_name, tool_name, principal,
                    request_state, tokenized_arguments_json, violations_json, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
                """,
                (
                    esc_id,
                    created_at,
                    agent_id,
                    server_name,
                    tool_name,
                    principal,
                    request_state,
                    json.dumps(tok_args, sort_keys=True),
                    json.dumps(violations),
                ),
            )
        return self.get_escalation(esc_id), None

    def _row_to_escalation(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "created_at": row["created_at"],
            "agent_id": row["agent_id"],
            "server_name": row["server_name"],
            "tool_name": row["tool_name"],
            "principal": row["principal"],
            "request_state": row["request_state"],
            "tokenized_arguments": json.loads(row["tokenized_arguments_json"]),
            "violations": json.loads(row["violations_json"]),
            "status": row["status"],
            "decided_by": row["decided_by"],
            "decided_at": row["decided_at"],
            "approval_token": row["approval_token"],
        }

    def get_escalation(self, esc_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM mrtr_approvals WHERE id = ?", (esc_id,)).fetchone()
            return self._row_to_escalation(row) if row else None

    def list_escalations(self, status: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            if status:
                rows = self._conn.execute(
                    "SELECT * FROM mrtr_approvals WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM mrtr_approvals ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [self._row_to_escalation(r) for r in rows]

    def decide_escalation(
        self, esc_id: str, approve: bool, approver: str
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        if not approver.strip():
            return None, "Approver identity is required."
        esc = self.get_escalation(esc_id)
        if not esc:
            return None, "Escalation not found."
        if esc["status"] != "pending":
            return esc, f"Escalation already decided ({esc['status']})."

        now = time.time()
        approval_token: Optional[str] = None
        new_status = "denied"
        if approve:
            tok, err = mint_approved_mrtr_token(esc["request_state"], self.signing_key)
            if err or not tok:
                return None, err or "Failed to mint MRTR approval token."
            approval_token = tok
            new_status = "approved"

        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE mrtr_approvals
                SET status = ?, decided_by = ?, decided_at = ?, approval_token = ?
                WHERE id = ?
                """,
                (new_status, approver.strip(), now, approval_token, esc_id),
            )
        return self.get_escalation(esc_id), None

    # ------------------------------------------------------------------
    # Central Fleet Signed Decision Ledger & Drift Alerts
    # ------------------------------------------------------------------

    def ingest_ledger_record(self, record: Dict[str, Any]) -> Tuple[bool, bool]:
        """Stores a DecisionLedgerRecord and returns `(stored, hmac_verified)`."""
        verified = verify_decision_record_hmac(record, self.signing_key)
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO fleet_ledger (
                    timestamp, agent_id, traceparent, obo_principal, server_name, tool_name,
                    verdict, latency_ms, policy_sha256, lockfile_sha256, record_hmac, hmac_verified, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    float(record.get("timestamp") or time.time()),
                    str(record.get("agent_id") or "unknown"),
                    str(record.get("traceparent") or ""),
                    record.get("obo_principal"),
                    str(record.get("server_name") or ""),
                    str(record.get("tool_name") or ""),
                    str(record.get("verdict") or ""),
                    float(record.get("latency_ms") or 0.0),
                    str(record.get("policy_sha256") or ""),
                    str(record.get("lockfile_sha256") or ""),
                    str(record.get("record_hmac") or ""),
                    1 if verified else 0,
                    json.dumps(record, sort_keys=True),
                ),
            )
        return True, verified

    def ingest_drift_events(self, payload: Dict[str, Any]) -> int:
        ts = float(payload.get("timestamp") or time.time())
        agent_id = str(payload.get("agent_id") or "unknown")
        server_name = str(payload.get("server_name") or "")
        drifts = payload.get("drifts") or []
        inserted = 0
        with self._lock, self._conn:
            for d in drifts:
                if not isinstance(d, dict):
                    continue
                self._conn.execute(
                    """
                    INSERT INTO drift_events (timestamp, agent_id, server_name, tool_name, kind, action, message)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ts,
                        agent_id,
                        str(d.get("server_name") or server_name),
                        str(d.get("tool_name") or ""),
                        str(d.get("kind") or "drift"),
                        str(d.get("action") or "warn"),
                        str(d.get("message") or ""),
                    ),
                )
                inserted += 1
        return inserted

    def list_recent_ledger(self, limit: int = 50, agent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            if agent_id:
                rows = self._conn.execute(
                    "SELECT hmac_verified, raw_json FROM fleet_ledger WHERE agent_id = ? ORDER BY id DESC LIMIT ?",
                    (agent_id, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT hmac_verified, raw_json FROM fleet_ledger ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            out = []
            for r in rows:
                item = json.loads(r["raw_json"])
                item["hmac_verified"] = bool(r["hmac_verified"])
                out.append(item)
            return out

    def list_drift_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM drift_events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def get_fleet_readiness(self) -> Dict[str, Any]:
        """Computes per-agent `shadow -> enforce` readiness scorecards across the fleet."""
        with self._lock:
            ledger_rows = self._conn.execute(
                """
                SELECT
                    agent_id,
                    COUNT(*) AS total_calls,
                    SUM(CASE WHEN verdict = 'allow' THEN 1 ELSE 0 END) AS allowed_calls,
                    SUM(CASE WHEN verdict = 'shadow_deny' THEN 1 ELSE 0 END) AS shadow_denied_calls,
                    SUM(CASE WHEN verdict = 'deny' THEN 1 ELSE 0 END) AS denied_calls,
                    SUM(CASE WHEN verdict = 'mrtr_escalate' THEN 1 ELSE 0 END) AS mrtr_escalated_calls,
                    SUM(hmac_verified) AS verified_hmac_records,
                    AVG(latency_ms) AS avg_latency_ms
                FROM fleet_ledger
                GROUP BY agent_id
                ORDER BY total_calls DESC
                """
            ).fetchall()
            drift_rows = self._conn.execute(
                "SELECT agent_id, COUNT(*) AS drift_count FROM drift_events GROUP BY agent_id"
            ).fetchall()
            pending_mrtr = self._conn.execute(
                "SELECT COUNT(*) AS cnt FROM mrtr_approvals WHERE status = 'pending'"
            ).fetchone()["cnt"]

        drift_by_agent = {r["agent_id"]: int(r["drift_count"]) for r in drift_rows}
        agents = []
        for r in ledger_rows:
            aid = r["agent_id"]
            total = int(r["total_calls"])
            shadow_denies = int(r["shadow_denied_calls"] or 0)
            drifts = drift_by_agent.get(aid, 0)
            shadow_block_rate = round((shadow_denies / total) * 100.0, 2) if total > 0 else 0.0
            agents.append(
                {
                    "agent_id": aid,
                    "total_calls": total,
                    "allowed_calls": int(r["allowed_calls"] or 0),
                    "shadow_denied_calls": shadow_denies,
                    "denied_calls": int(r["denied_calls"] or 0),
                    "mrtr_escalated_calls": int(r["mrtr_escalated_calls"] or 0),
                    "verified_hmac_records": int(r["verified_hmac_records"] or 0),
                    "avg_latency_ms": round(float(r["avg_latency_ms"] or 0.0), 2),
                    "drift_alerts": drifts,
                    "shadow_block_rate_pct": shadow_block_rate,
                    "ready_to_enforce": total > 0 and shadow_denies == 0 and drifts == 0,
                }
            )
        return {
            "generated_at": time.time(),
            "pending_mrtr_approvals": int(pending_mrtr),
            "agents": agents,
        }

    def build_signed_audit_bundle(self, agent_id: Optional[str] = None) -> Dict[str, Any]:
        """Generates a tamper-evident SOC2 / EU AI Act signed compliance export bundle."""
        bundle_body = {
            "schema": "prometheus.compliance.audit_bundle.v1",
            "exported_at": time.time(),
            "agent_filter": agent_id or "*",
            "fleet_readiness": self.get_fleet_readiness(),
            "mrtr_approvals": self.list_escalations(limit=500),
            "drift_events": self.list_drift_events(limit=500),
            "decision_ledger": self.list_recent_ledger(limit=1000, agent_id=agent_id),
        }
        canonical = json.dumps(bundle_body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        bundle_sha256 = hashlib.sha256(canonical).hexdigest()
        bundle_hmac = _hmac_hex(self.signing_key, canonical)
        return {
            **bundle_body,
            "integrity": {
                "algorithm": "HMAC-SHA256",
                "bundle_sha256": bundle_sha256,
                "bundle_hmac": bundle_hmac,
            },
        }
