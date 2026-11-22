"""
Prometheus Enterprise Control Plane:
- Live MCP 2026-07-28 MRTR Human-in-the-Loop Approval Bridge (REST + Slack Block Kit + Web UI)
- Central Fleet Signed Decision Ledger Collector (Go<->Python HMAC verification)
- Fleet-wide `shadow -> enforce` Readiness Scorecards & Drift Alerts
- Tamper-Evident SOC2 / EU AI Act Signed Audit Bundle Exporter
"""

from prometheus.control_plane.store import ControlPlaneStore, verify_slack_signature

__all__ = ["ControlPlaneStore", "verify_slack_signature"]
