"""
Split-Hash MCP Manifest Pinning Engine (`prometheus.lock`) & CI Diff Gate.

Fills the operational gap left when the MCP signed-manifests proposal closed (Sep 2026)
and `snyk-agent-scan` dropped hash-based pinning (Aug 2026):
- `structural_sha256`: Canonical SHA-256 of `{name, inputSchema}` (hard-blocks on drift for all servers).
- `description_sha256`: Canonical SHA-256 of `description` (hard-blocks on `third_party` servers,
  warns on `internal` servers so benign docstring edits don't break production).
- Cross-server tool shadowing detection: Flags duplicate tool names exposed by distinct MCP servers.
- Day-1 poisoning gate: Refuses to pin tools that fail `lint_tool_definition()` unless explicitly forced.
"""

from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from prometheus.iac.poisoning_lint import LintSeverity, PoisoningFinding, lint_tool_definition
from prometheus.iac.schema import (
    ManifestLockfile,
    PinnedServerManifest,
    PinnedToolEntry,
    TrustTier,
)


class DriftKind(str, Enum):
    STRUCTURAL_DRIFT = "structural_drift"
    DESCRIPTION_DRIFT = "description_drift"
    UNPINNED_TOOL = "unpinned_tool"
    REMOVED_TOOL = "removed_tool"
    CROSS_SERVER_SHADOWING = "cross_server_shadowing"
    DAY1_POISONING = "day1_poisoning"


class DriftAction(str, Enum):
    BLOCK = "block"
    WARN = "warn"


class ManifestDriftItem(BaseModel):
    server_name: str
    tool_name: str
    kind: DriftKind
    action: DriftAction
    message: str
    expected_sha256: Optional[str] = None
    observed_sha256: Optional[str] = None
    previous_preview: Optional[str] = None
    observed_preview: Optional[str] = None


class LockVerificationResult(BaseModel):
    passed: bool
    blocked_count: int = 0
    warning_count: int = 0
    drifts: List[ManifestDriftItem] = Field(default_factory=list)


def _strip_schema_descriptions(obj: Any) -> Any:
    """
    Removes prose `description`/`title` fields from `inputSchema` so `structural_sha256`
    hashes strictly the machine contract (types, required fields, property names, enums, bounds)
    while prose changes are captured in `description_sha256`.
    """
    if isinstance(obj, dict):
        return {
            k: _strip_schema_descriptions(v)
            for k, v in obj.items()
            if k not in ("description", "title")
        }
    if isinstance(obj, list):
        return [_strip_schema_descriptions(i) for i in obj]
    return obj


def _collect_prose_surface(tool: Dict[str, Any]) -> Dict[str, Any]:
    """Extracts all human/LLM prose surfaces (tool description + schema property descriptions)."""
    def _extract_prose(obj: Any) -> Any:
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if k in ("description", "title") and isinstance(v, str):
                    out[k] = v.strip()
                elif isinstance(v, (dict, list)):
                    sub = _extract_prose(v)
                    if sub:
                        out[k] = sub
            return out
        if isinstance(obj, list):
            items = [_extract_prose(i) for i in obj]
            return [i for i in items if i]
        return None

    return {
        "description": str(tool.get("description") or "").strip(),
        "schema_prose": _extract_prose(tool.get("inputSchema") or {}),
    }


def compute_structural_sha256(tool: Dict[str, Any]) -> str:
    """Canonical SHA-256 of the tool's machine contract (`name` + structural `inputSchema`)."""
    contract = {
        "name": str(tool.get("name") or ""),
        "inputSchema": _strip_schema_descriptions(tool.get("inputSchema") or {}),
    }
    canonical = json.dumps(contract, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def compute_description_sha256(tool: Dict[str, Any]) -> str:
    """Canonical SHA-256 of the tool's prose descriptions (tool description + parameter descriptions)."""
    prose = _collect_prose_surface(tool)
    canonical = json.dumps(prose, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def build_lockfile_from_servers(
    servers_tools: Dict[str, Tuple[TrustTier, Optional[str], List[Dict[str, Any]]]],
    allow_poisoned: bool = False,
) -> Tuple[ManifestLockfile, List[PoisoningFinding]]:
    """
    Builds a split-hash `ManifestLockfile` from discovered/live server `tools/list` payloads.
    Runs Day-1 poisoning lint on every tool; unless `allow_poisoned=True`, tools with
    CRITICAL/HIGH poisoning findings are quarantined (excluded from pinned lockfile).
    """
    lock = ManifestLockfile()
    all_findings: List[PoisoningFinding] = []

    for server_name, (trust_tier, url, tools) in sorted(servers_tools.items()):
        pinned_tools: Dict[str, PinnedToolEntry] = {}
        for tool in tools:
            if not isinstance(tool, dict) or not tool.get("name"):
                continue
            tool_name = str(tool["name"])
            findings = lint_tool_definition(server_name, tool)
            all_findings.extend(findings)
            has_blocking_poison = any(
                f.severity in (LintSeverity.CRITICAL, LintSeverity.HIGH) for f in findings
            )
            if has_blocking_poison and not allow_poisoned:
                continue

            desc_text = str(tool.get("description") or "").strip()
            pinned_tools[tool_name] = PinnedToolEntry(
                structural_sha256=compute_structural_sha256(tool),
                description_sha256=compute_description_sha256(tool),
                description_preview=desc_text[:160],
                poisoning_lint_passed=not has_blocking_poison,
                poisoning_warnings=[f"{f.rule_id}: {f.message}" for f in findings],
            )

        lock.servers[server_name] = PinnedServerManifest(
            trust_tier=trust_tier,
            url=url,
            tools=pinned_tools,
        )

    return lock, all_findings


def detect_cross_server_shadowing(
    observed_servers: Dict[str, List[Dict[str, Any]]],
) -> List[ManifestDriftItem]:
    """Detects duplicate tool names exposed across multiple MCP servers in the same agent config."""
    tool_owners: Dict[str, List[str]] = {}
    for server_name, tools in sorted(observed_servers.items()):
        for tool in tools:
            if isinstance(tool, dict) and tool.get("name"):
                tname = str(tool["name"])
                tool_owners.setdefault(tname, []).append(server_name)

    drifts: List[ManifestDriftItem] = []
    for tool_name, owners in sorted(tool_owners.items()):
        unique_owners = sorted(set(owners))
        if len(unique_owners) > 1:
            drifts.append(
                ManifestDriftItem(
                    server_name=", ".join(unique_owners),
                    tool_name=tool_name,
                    kind=DriftKind.CROSS_SERVER_SHADOWING,
                    action=DriftAction.BLOCK,
                    message=(
                        f"Cross-server tool shadowing detected: tool '{tool_name}' is exposed by "
                        f"multiple servers ({', '.join(unique_owners)}). Namespace or remove duplicate."
                    ),
                )
            )
    return drifts


def verify_tools_list(
    lockfile: ManifestLockfile,
    server_name: str,
    observed_tools: List[Dict[str, Any]],
    trust_tier_override: Optional[TrustTier] = None,
) -> LockVerificationResult:
    """
    Verifies a live or CI-inspected `tools/list` payload against `prometheus.lock`.
    - Structural schema drift -> BLOCK on ALL servers (internal & third-party).
    - Description drift -> BLOCK on `third_party`, WARN on `internal`.
    - Poisoning lint critical/high on drifted or new tools -> BLOCK on ALL servers.
    - Unpinned tool -> BLOCK on `third_party`, WARN on `internal`.
    """
    pinned_server = lockfile.servers.get(server_name)
    trust_tier = trust_tier_override or (
        pinned_server.trust_tier if pinned_server else TrustTier.THIRD_PARTY
    )
    pinned_tools = pinned_server.tools if pinned_server else {}

    drifts: List[ManifestDriftItem] = []
    seen_names = set()

    for tool in observed_tools:
        if not isinstance(tool, dict) or not tool.get("name"):
            continue
        tname = str(tool["name"])
        seen_names.add(tname)

        obs_struct = compute_structural_sha256(tool)
        obs_desc = compute_description_sha256(tool)
        obs_preview = str(tool.get("description") or "").strip()[:160]

        # Always run poisoning lint on observed tools so rug-pull injections are caught immediately
        poison_findings = lint_tool_definition(server_name, tool)
        blocking_poison = [
            f for f in poison_findings if f.severity in (LintSeverity.CRITICAL, LintSeverity.HIGH)
        ]
        if blocking_poison:
            drifts.append(
                ManifestDriftItem(
                    server_name=server_name,
                    tool_name=tname,
                    kind=DriftKind.DAY1_POISONING,
                    action=DriftAction.BLOCK,
                    message=f"Tool poisoning detected ({blocking_poison[0].rule_id}): {blocking_poison[0].message}",
                    observed_sha256=obs_desc,
                    observed_preview=obs_preview,
                )
            )

        pinned = pinned_tools.get(tname)
        if pinned is None:
            drifts.append(
                ManifestDriftItem(
                    server_name=server_name,
                    tool_name=tname,
                    kind=DriftKind.UNPINNED_TOOL,
                    action=DriftAction.BLOCK if trust_tier == TrustTier.THIRD_PARTY else DriftAction.WARN,
                    message=f"Tool '{tname}' on server '{server_name}' is not pinned in prometheus.lock.",
                    observed_sha256=obs_struct,
                    observed_preview=obs_preview,
                )
            )
            continue

        if obs_struct != pinned.structural_sha256:
            drifts.append(
                ManifestDriftItem(
                    server_name=server_name,
                    tool_name=tname,
                    kind=DriftKind.STRUCTURAL_DRIFT,
                    action=DriftAction.BLOCK,
                    message=(
                        f"Structural schema drift on '{server_name}.{tname}': inputSchema contract "
                        "changed since prometheus.lock was approved."
                    ),
                    expected_sha256=pinned.structural_sha256,
                    observed_sha256=obs_struct,
                )
            )

        if obs_desc != pinned.description_sha256:
            action = DriftAction.BLOCK if trust_tier == TrustTier.THIRD_PARTY else DriftAction.WARN
            drifts.append(
                ManifestDriftItem(
                    server_name=server_name,
                    tool_name=tname,
                    kind=DriftKind.DESCRIPTION_DRIFT,
                    action=action,
                    message=(
                        f"Description drift on {trust_tier.value} server '{server_name}.{tname}': "
                        + (
                            "blocked as potential rug pull."
                            if action == DriftAction.BLOCK
                            else "warning only (internal server); run `prometheus lock --update` after review."
                        )
                    ),
                    expected_sha256=pinned.description_sha256,
                    observed_sha256=obs_desc,
                    previous_preview=pinned.description_preview,
                    observed_preview=obs_preview,
                )
            )

    for pinned_name in sorted(pinned_tools.keys()):
        if pinned_name not in seen_names:
            drifts.append(
                ManifestDriftItem(
                    server_name=server_name,
                    tool_name=pinned_name,
                    kind=DriftKind.REMOVED_TOOL,
                    action=DriftAction.WARN,
                    message=f"Pinned tool '{pinned_name}' is no longer advertised by '{server_name}'.",
                )
            )

    blocked_count = sum(1 for d in drifts if d.action == DriftAction.BLOCK)
    warning_count = sum(1 for d in drifts if d.action == DriftAction.WARN)
    return LockVerificationResult(
        passed=blocked_count == 0,
        blocked_count=blocked_count,
        warning_count=warning_count,
        drifts=drifts,
    )


def diff_lockfiles(old: ManifestLockfile, new: ManifestLockfile) -> LockVerificationResult:
    """Computes a structured diff between an approved `prometheus.lock` and a newly scanned lockfile."""
    drifts: List[ManifestDriftItem] = []
    all_servers = sorted(set(old.servers.keys()) | set(new.servers.keys()))

    for srv in all_servers:
        old_srv = old.servers.get(srv)
        new_srv = new.servers.get(srv)
        trust = new_srv.trust_tier if new_srv else (old_srv.trust_tier if old_srv else TrustTier.THIRD_PARTY)
        old_tools = old_srv.tools if old_srv else {}
        new_tools = new_srv.tools if new_srv else {}

        for tname in sorted(set(old_tools.keys()) | set(new_tools.keys())):
            o = old_tools.get(tname)
            n = new_tools.get(tname)
            if o is None and n is not None:
                drifts.append(
                    ManifestDriftItem(
                        server_name=srv,
                        tool_name=tname,
                        kind=DriftKind.UNPINNED_TOOL,
                        action=DriftAction.BLOCK if trust == TrustTier.THIRD_PARTY else DriftAction.WARN,
                        message=f"New tool added: '{srv}.{tname}'.",
                        observed_sha256=n.structural_sha256,
                        observed_preview=n.description_preview,
                    )
                )
            elif o is not None and n is None:
                drifts.append(
                    ManifestDriftItem(
                        server_name=srv,
                        tool_name=tname,
                        kind=DriftKind.REMOVED_TOOL,
                        action=DriftAction.WARN,
                        message=f"Tool removed: '{srv}.{tname}'.",
                        expected_sha256=o.structural_sha256,
                    )
                )
            elif o is not None and n is not None:
                if o.structural_sha256 != n.structural_sha256:
                    drifts.append(
                        ManifestDriftItem(
                            server_name=srv,
                            tool_name=tname,
                            kind=DriftKind.STRUCTURAL_DRIFT,
                            action=DriftAction.BLOCK,
                            message=f"Structural inputSchema changed on '{srv}.{tname}'.",
                            expected_sha256=o.structural_sha256,
                            observed_sha256=n.structural_sha256,
                        )
                    )
                if o.description_sha256 != n.description_sha256:
                    drifts.append(
                        ManifestDriftItem(
                            server_name=srv,
                            tool_name=tname,
                            kind=DriftKind.DESCRIPTION_DRIFT,
                            action=DriftAction.BLOCK if trust == TrustTier.THIRD_PARTY else DriftAction.WARN,
                            message=f"Description prose changed on '{srv}.{tname}'.",
                            expected_sha256=o.description_sha256,
                            observed_sha256=n.description_sha256,
                            previous_preview=o.description_preview,
                            observed_preview=n.description_preview,
                        )
                    )

    blocked = sum(1 for d in drifts if d.action == DriftAction.BLOCK)
    warned = sum(1 for d in drifts if d.action == DriftAction.WARN)
    return LockVerificationResult(
        passed=blocked == 0,
        blocked_count=blocked,
        warning_count=warned,
        drifts=drifts,
    )


def render_diff_markdown(result: LockVerificationResult) -> str:
    """Renders a GitHub PR-ready markdown table for CI diff-review gates."""
    if not result.drifts:
        return "### Prometheus Lockfile Check: Passed\nNo MCP tool schema or description drift detected."

    status = "BLOCKED" if not result.passed else "WARNING"
    lines = [
        f"### Prometheus Lockfile Check: {status} ({result.blocked_count} blocking, {result.warning_count} warnings)",
        "",
        "| Action | Server | Tool | Drift Type | Details |",
        "| --- | --- | --- | --- | --- |",
    ]
    for d in result.drifts:
        lines.append(
            f"| **{d.action.value.upper()}** | `{d.server_name}` | `{d.tool_name}` | `{d.kind.value}` | {d.message} |"
        )
    return "\n".join(lines)
