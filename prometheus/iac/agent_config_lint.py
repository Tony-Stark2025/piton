"""
Deterministic AI Coding-Agent Supply-Chain Linter (Piton / Prometheus).

Catches real-world 2025-2026 coding-agent RCE & poisoning attacks in repository configs:
1. `.claude/settings.json` & `.claude/settings.local.json`:
   - Malicious `hooks` (`PreToolUse`, `PostToolUse`, `SessionStart`, `UserPromptSubmit`, `Stop`)
     running download-and-exec (`curl|sh`, `wget|bash`), reverse shells, base64/inline payloads,
     or harvesting `~/.aws`, `~/.ssh`, `.env`, `GITHUB_TOKEN`, `NPM_TOKEN`, etc.
   - Dangerous overly-broad `permissions.allow` wildcards (`Bash(*)`, `Bash(curl*)`, `Bash(rm*)`).
2. `.vscode/tasks.json`:
   - Auto-executing `runOptions.runOn == "folderOpen"` tasks (classic repo-open RCE).
3. `.cursor/rules/*`, `.cursorrules`, `CLAUDE.md`, `AGENTS.md`, `.github/copilot-instructions.md`,
   `.claude/skills/**/*.md`, `.agents/skills/**/*.md`, `.claude/commands/**/*.md`:
   - Invisible/bidi Unicode smuggling (zero-width chars, Trojan Source bidi overrides, Unicode Tags)
   - Covert prompt-injection instruction overrides & credential exfiltration directives.
"""

import json
from pathlib import Path
import re
from typing import Any, Dict, List
import unicodedata
from pydantic import BaseModel

from prometheus.iac.poisoning_lint import (
    LintSeverity,
    PoisoningFinding,
    lint_tool_definition,
)

# High-signal shell RCE & credential-harvesting patterns inside hook commands
_HOOK_DOWNLOAD_EXEC_RE = re.compile(
    r"(?i)\b(?:curl|wget|fetch)\b[^\n]{0,200}\|\s*(?:sh|bash|zsh|dash|python3?|node|perl|ruby)\b"
)
_HOOK_REVERSE_SHELL_RE = re.compile(
    r"(?i)(?:/dev/tcp/|nc\s+-[a-z]*e|ncat\s+-[a-z]*e|bash\s+-i\s+>&|mkfifo\s+/tmp/|socat\s+exec:|python3?\s+-c\s+['\"][^'\"]{0,200}socket)"
)
_HOOK_OBFUSCATED_EXEC_RE = re.compile(
    r"(?i)(?:base64\s+(?:-d|--decode)[^\n]{0,120}\|\s*(?:sh|bash|zsh|python3?|node)|eval\s+\$\(|powershell[^\n]{0,80}-enc(?:odedcommand)?)"
)
_HOOK_CRED_EXFIL_RE = re.compile(
    r"(?i)(?:~/\.ssh|~/\.aws|~/\.kube|~/\.npmrc|~/\.netrc|/etc/shadow|id_rsa|aws_secret_access_key|github_token|npm_token|openai_api_key|anthropic_api_key|stripe_api_key|\.env\b)"
    r"[^\n]{0,160}(?:curl|wget|nc|http://|https://|base64|webhook|discord|telegram|pastebin)"
)
_HOOK_NET_POST_RE = re.compile(
    r"(?i)\b(?:curl|wget)\b[^\n]{0,180}(?:-d\b|--data|--upload-file|-F\b|-X\s*POST)[^\n]{0,180}(?:\$[A-Z_]{3,}|/etc/|~/\.|\.env)"
)
_DANGEROUS_PERMISSION_RE = re.compile(
    r"(?i)^Bash\(\s*(?:\*|rm\b|curl\b|wget\b|sh\b|bash\b|sudo\b|chmod\b|chown\b)"
)


class AgentConfigScanResult(BaseModel):
    scanned_files: List[str]
    findings: List[PoisoningFinding]

    @property
    def critical_or_high_count(self) -> int:
        return sum(
            1
            for f in self.findings
            if f.severity in (LintSeverity.CRITICAL, LintSeverity.HIGH)
        )


def _extract_hook_commands(obj: Any, path_prefix: str = "") -> List[tuple[str, str]]:
    """Recursively extracts `(hook_path, command_string)` from `.claude/settings.json` hooks."""
    out: List[tuple[str, str]] = []
    if isinstance(obj, dict):
        cmd = obj.get("command")
        if isinstance(cmd, str) and cmd.strip():
            out.append((path_prefix or "hooks", cmd.strip()))
        for k, v in obj.items():
            if k == "command":
                continue
            sub = f"{path_prefix}.{k}" if path_prefix else str(k)
            out.extend(_extract_hook_commands(v, sub))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            out.extend(_extract_hook_commands(item, f"{path_prefix}[{idx}]"))
    return out


def lint_claude_settings(rel_path: str, data: Dict[str, Any]) -> List[PoisoningFinding]:
    findings: List[PoisoningFinding] = []

    hooks = data.get("hooks")
    if hooks is not None:
        for hook_loc, raw_cmd in _extract_hook_commands(hooks, "hooks"):
            cmd = unicodedata.normalize("NFKC", raw_cmd)
            if _HOOK_DOWNLOAD_EXEC_RE.search(cmd):
                findings.append(
                    PoisoningFinding(
                        server_name="agent-config",
                        tool_name=rel_path,
                        rule_id="AGENT_HOOK_DOWNLOAD_EXEC",
                        severity=LintSeverity.CRITICAL,
                        field_path=hook_loc,
                        message="Claude Code hook downloads and pipes remote code directly into a shell/interpreter.",
                        matched_snippet=cmd[:160],
                    )
                )
            if _HOOK_REVERSE_SHELL_RE.search(cmd):
                findings.append(
                    PoisoningFinding(
                        server_name="agent-config",
                        tool_name=rel_path,
                        rule_id="AGENT_HOOK_REVERSE_SHELL",
                        severity=LintSeverity.CRITICAL,
                        field_path=hook_loc,
                        message="Claude Code hook contains an interactive/reverse shell command.",
                        matched_snippet=cmd[:160],
                    )
                )
            if _HOOK_OBFUSCATED_EXEC_RE.search(cmd):
                findings.append(
                    PoisoningFinding(
                        server_name="agent-config",
                        tool_name=rel_path,
                        rule_id="AGENT_HOOK_OBFUSCATED_EXEC",
                        severity=LintSeverity.CRITICAL,
                        field_path=hook_loc,
                        message="Claude Code hook decodes or dynamically evaluates obfuscated shell payloads.",
                        matched_snippet=cmd[:160],
                    )
                )
            if _HOOK_CRED_EXFIL_RE.search(cmd) or _HOOK_NET_POST_RE.search(cmd):
                findings.append(
                    PoisoningFinding(
                        server_name="agent-config",
                        tool_name=rel_path,
                        rule_id="AGENT_HOOK_CREDENTIAL_EXFIL",
                        severity=LintSeverity.CRITICAL,
                        field_path=hook_loc,
                        message="Claude Code hook accesses credentials/secrets and transmits data over the network.",
                        matched_snippet=cmd[:160],
                    )
                )

    perms = data.get("permissions")
    if isinstance(perms, dict):
        allow_list = perms.get("allow")
        if isinstance(allow_list, list):
            for entry in allow_list:
                if isinstance(entry, str) and _DANGEROUS_PERMISSION_RE.search(entry.strip()):
                    findings.append(
                        PoisoningFinding(
                            server_name="agent-config",
                            tool_name=rel_path,
                            rule_id="AGENT_UNSAFE_PERMISSION_WILDCARD",
                            severity=LintSeverity.HIGH,
                            field_path="permissions.allow",
                            message=f"Overly permissive auto-approve rule '{entry.strip()}' bypasses human confirmation for dangerous shell commands.",
                            matched_snippet=entry.strip()[:120],
                        )
                    )
    return findings


def lint_vscode_tasks(rel_path: str, data: Dict[str, Any]) -> List[PoisoningFinding]:
    findings: List[PoisoningFinding] = []
    tasks = data.get("tasks")
    if not isinstance(tasks, list):
        return findings
    for idx, task in enumerate(tasks):
        if not isinstance(task, dict):
            continue
        run_opts = task.get("runOptions")
        if isinstance(run_opts, dict) and str(run_opts.get("runOn") or "").lower() == "folderopen":
            label = str(task.get("label") or f"task[{idx}]")
            cmd = str(task.get("command") or "")
            findings.append(
                PoisoningFinding(
                    server_name="agent-config",
                    tool_name=rel_path,
                    rule_id="VSCODE_FOLDER_OPEN_AUTORUN",
                    severity=LintSeverity.CRITICAL,
                    field_path=f"tasks[{idx}].runOptions.runOn",
                    message="VS Code / Cursor task executes automatically on folderOpen (untrusted repo RCE vector).",
                    matched_snippet=cmd[:160] or label,
                )
            )
    return findings


def lint_agent_instruction_file(rel_path: str, content: str) -> List[PoisoningFinding]:
    """
    Applies the deterministic MCP/prompt poisoning linter (NFKC + bidi/invisible Unicode,
    covert tags, credential exfil directives, instruction hijacks) to coding-agent rules
    and skill markdown files.
    """
    fake_tool = {"name": rel_path, "description": content[:32768]}
    findings = lint_tool_definition("agent-rules", fake_tool)
    return findings


def scan_agent_supply_chain(repo_path: Path) -> AgentConfigScanResult:
    """
    Scans a repository for coding-agent RCE hooks, auto-run tasks, and poisoned
    instruction/skill files across Claude Code, Cursor, VS Code, and Copilot.
    """
    repo_root = repo_path.resolve()
    scanned: List[str] = []
    findings: List[PoisoningFinding] = []

    # 1. Claude Code settings & hooks
    for rel in (".claude/settings.json", ".claude/settings.local.json"):
        p = repo_root / rel
        if p.is_file():
            scanned.append(rel)
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    findings.extend(lint_claude_settings(rel, data))
            except Exception:
                pass

    # 2. VS Code / Cursor tasks.json folderOpen RCE
    tasks_path = repo_root / ".vscode" / "tasks.json"
    if tasks_path.is_file():
        scanned.append(".vscode/tasks.json")
        try:
            raw = tasks_path.read_text(encoding="utf-8")
            # Strip simple // comments common in JSONC tasks.json
            cleaned = re.sub(r"(?m)^\s*//.*$", "", raw)
            data = json.loads(cleaned)
            if isinstance(data, dict):
                findings.extend(lint_vscode_tasks(".vscode/tasks.json", data))
        except Exception:
            pass

    # 3. Coding-agent rules, instructions & skill markdown files
    rule_candidates: List[Path] = []
    for single in (
        ".cursorrules",
        "CLAUDE.md",
        "AGENTS.md",
        ".github/copilot-instructions.md",
    ):
        p = repo_root / single
        if p.is_file():
            rule_candidates.append(p)

    for glob_dir, patterns in (
        (repo_root / ".cursor" / "rules", ("*.mdc", "*.md", "*.txt")),
        (repo_root / ".claude" / "skills", ("*.md",)),
        (repo_root / ".claude" / "commands", ("*.md",)),
        (repo_root / ".agents" / "skills", ("*.md",)),
    ):
        if glob_dir.is_dir():
            for pat in patterns:
                rule_candidates.extend(sorted(glob_dir.rglob(pat)))

    seen_paths = set()
    for p in rule_candidates:
        if p in seen_paths or not p.is_file():
            continue
        seen_paths.add(p)
        rel = str(p.relative_to(repo_root))
        scanned.append(rel)
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
            findings.extend(lint_agent_instruction_file(rel, content))
        except Exception:
            pass

    return AgentConfigScanResult(scanned_files=scanned, findings=findings)
