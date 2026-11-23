"""
Day-1 MCP Tool-Description & Schema Poisoning Linter (Audit-Hardened).

Prevents `piton init` and `piton lock` from blindly hashing and pinning
an already-poisoned third-party MCP server on Day 1.
Hardened against:
- NFKC Unicode homoglyph evasion
- Invisible zero-width, bidi-override, and Unicode tag characters
- ReDoS (bounded quantifiers only; no `.*` + DOTALL catastrophic backtracking)
- Poisoned `tool["name"]`, `annotations`, `examples`, `outputSchema`, and oversized `inputSchema`
"""

from enum import Enum
import json
import re
from typing import Any, Dict, List, Tuple
import unicodedata
from pydantic import BaseModel, Field


class LintSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


class PoisoningFinding(BaseModel):
    server_name: str
    tool_name: str
    rule_id: str
    severity: LintSeverity
    field_path: str
    message: str
    matched_snippet: str = ""


class PoisoningLintReport(BaseModel):
    passed: bool
    findings: List[PoisoningFinding] = Field(default_factory=list)

    @property
    def critical_or_high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity in (LintSeverity.CRITICAL, LintSeverity.HIGH))


# Deterministic, ReDoS-safe rule catalog (bounded gaps `{0,120}` instead of unbounded `.*`)
POISONING_RULES: Tuple[Tuple[str, LintSeverity, str, str], ...] = (
    (
        "MCP_POISON_INSTRUCTION_OVERRIDE",
        LintSeverity.CRITICAL,
        r"(ignore\s+(all\s+)?(previous|prior|above)\s+instructions?|disregard\s+(all\s+)?(previous|prior)|new\s+system\s+prompt|override\s+system\s+instructions?)",
        "Tool metadata contains prompt-override directives attempting to hijack agent instructions.",
    ),
    (
        "MCP_POISON_COVERT_CONCEALMENT",
        LintSeverity.CRITICAL,
        r"(do\s+not\s+(tell|inform|mention|show|notify)\s+the\s+user|never\s+mention\s+this|hide\s+this\s+from\s+the\s+user|silently\s+(send|forward|copy|bcc|exfiltrate|execute)|<\s*IMPORTANT\s*>|<\s*SYSTEM\s*>)",
        "Tool metadata contains covert concealment or pseudo-system tags used in MCP tool-poisoning attacks.",
    ),
    (
        "MCP_POISON_CREDENTIAL_EXFIL",
        LintSeverity.CRITICAL,
        r"(~/\.ssh|id_rsa|id_ed25519|/etc/passwd|\.aws/credentials|\.env\b|\bexfiltrat\w*\b|webhook\.site|ngrok\.io|blind\s+carbon\s+copy|\bbcc\b\s+[^\s]{1,80}@|pass\s+(all|the)\s+(api\s+keys?|secrets?|tokens?|credentials?))",
        "Tool metadata references sensitive credential paths or covert outbound exfiltration.",
    ),
    (
        "MCP_POISON_CROSS_TOOL_SHADOWING",
        LintSeverity.HIGH,
        r"((before|after|whenever|instead\s+of)\s+(calling|invoking|using)\s+[`'\"]?[a-zA-Z0-9_.-]{1,64}[`'\"]?[^.\n]{0,120}(also\s+call|must\s+first|redirect|override|replace|send\s+the\s+output)|redefine\s+the\s+behavior\s+of)",
        "Tool metadata attempts cross-server tool shadowing by steering calls to adjacent tools.",
    ),
    (
        "MCP_POISON_SHELL_RCE_DIRECTIVE",
        LintSeverity.HIGH,
        r"(\bcurl\s+[^|\n]{1,120}\|\s*(ba)?sh\b|\bwget\s+[^|\n]{1,120}\|\s*(ba)?sh\b|bash\s+-c\s+['\"]|powershell\s+-enc)",
        "Tool metadata contains embedded shell-execution / pipe-to-shell commands.",
    ),
)

INVISIBLE_UNICODE_RE = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\U000e0000-\U000e007f]"
)

MAX_SAFE_DESCRIPTION_CHARS = 2_000
MAX_SAFE_SCHEMA_BYTES = 16_384


def _collect_all_strings(obj: Any, prefix: str) -> List[Tuple[str, str]]:
    """Recursively extracts string leaves from schemas, annotations, and examples."""
    found: List[Tuple[str, str]] = []
    if isinstance(obj, str):
        found.append((prefix, obj))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            found.extend(_collect_all_strings(v, f"{prefix}.{k}"))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            found.extend(_collect_all_strings(item, f"{prefix}[{idx}]"))
    return found


def lint_tool_definition(
    server_name: str,
    tool: Dict[str, Any],
) -> List[PoisoningFinding]:
    """Lints a single MCP `tools/list` tool object across name, description, schemas, and annotations."""
    findings: List[PoisoningFinding] = []
    tool_name = str(tool.get("name") or "unknown_tool")
    description = str(tool.get("description") or "")

    text_surfaces: List[Tuple[str, str]] = [
        ("name", tool_name),
        ("description", description),
    ]
    for surface_key in ("inputSchema", "outputSchema", "annotations", "examples"):
        if surface_key in tool and tool[surface_key] is not None:
            text_surfaces.extend(_collect_all_strings(tool[surface_key], surface_key))

    if len(description) > MAX_SAFE_DESCRIPTION_CHARS:
        findings.append(
            PoisoningFinding(
                server_name=server_name,
                tool_name=tool_name,
                rule_id="MCP_POISON_DESCRIPTION_BLOAT",
                severity=LintSeverity.MEDIUM,
                field_path="description",
                message=(
                    f"Tool description length ({len(description)} chars) exceeds {MAX_SAFE_DESCRIPTION_CHARS} "
                    "chars; oversized descriptions frequently conceal injected instructions."
                ),
                matched_snippet=description[:120],
            )
        )

    if isinstance(tool.get("inputSchema"), dict):
        schema_bytes = len(json.dumps(tool["inputSchema"]).encode("utf-8"))
        if schema_bytes > MAX_SAFE_SCHEMA_BYTES:
            findings.append(
                PoisoningFinding(
                    server_name=server_name,
                    tool_name=tool_name,
                    rule_id="MCP_POISON_SCHEMA_BLOAT",
                    severity=LintSeverity.MEDIUM,
                    field_path="inputSchema",
                    message=f"Tool inputSchema size ({schema_bytes} bytes) exceeds {MAX_SAFE_SCHEMA_BYTES} bytes.",
                )
            )

    for field_path, text in text_surfaces:
        if not text:
            continue

        if INVISIBLE_UNICODE_RE.search(text):
            findings.append(
                PoisoningFinding(
                    server_name=server_name,
                    tool_name=tool_name,
                    rule_id="MCP_POISON_INVISIBLE_UNICODE",
                    severity=LintSeverity.CRITICAL,
                    field_path=field_path,
                    message="Detected invisible zero-width, bidi-override, or Unicode tag characters used to hide prompt injections.",
                    matched_snippet=repr(text[:120]),
                )
            )

        # NFKC normalize before lexical matching to defeat Unicode homoglyph/fullwidth obfuscation
        normalized = unicodedata.normalize("NFKC", INVISIBLE_UNICODE_RE.sub("", text))

        for rule_id, severity, pattern, msg in POISONING_RULES:
            m = re.search(pattern, normalized, re.IGNORECASE)
            if m:
                findings.append(
                    PoisoningFinding(
                        server_name=server_name,
                        tool_name=tool_name,
                        rule_id=rule_id,
                        severity=severity,
                        field_path=field_path,
                        message=msg,
                        matched_snippet=m.group(0)[:140],
                    )
                )

    return findings


def lint_tools_list(
    server_name: str,
    tools: List[Dict[str, Any]],
) -> PoisoningLintReport:
    """Runs Day-1 poisoning lint across an entire MCP server's `tools/list` output."""
    all_findings: List[PoisoningFinding] = []
    for tool in tools:
        if isinstance(tool, dict):
            all_findings.extend(lint_tool_definition(server_name, tool))
    has_blocking = any(f.severity in (LintSeverity.CRITICAL, LintSeverity.HIGH) for f in all_findings)
    return PoisoningLintReport(passed=not has_blocking, findings=all_findings)
