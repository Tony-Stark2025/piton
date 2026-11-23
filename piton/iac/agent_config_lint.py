"""
Deterministic AI Coding-Agent Supply-Chain Linter (Piton).

Catches real-world coding-agent RCE & poisoning attacks in repository configs:
1. `.claude/settings.json` & `.claude/settings.local.json`:
   - Malicious `hooks` (`PreToolUse`, `PostToolUse`, `SessionStart`, `UserPromptSubmit`, `Stop`)
     running download-and-exec (`curl|sh`, `wget|bash`), reverse shells, base64/inline payloads,
     or harvesting `~/.aws`, `~/.ssh`, `.env`, `GITHUB_TOKEN`, `NPM_TOKEN`, etc.
   - Dangerous overly-broad `permissions.allow` rules (`Bash`, `Bash(*)`, `Bash(curl*)`, `Bash(rm*)`).
2. `.vscode/tasks.json` (full JSONC support: `//` inline comments, `/* */` block comments, trailing commas):
   - Auto-executing `runOptions.runOn == "folderOpen"` tasks (classic repo-open RCE).
3. `.mcp.json`, `mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`:
   - Malicious STDIO server `command`/`args` executing download-and-exec, reverse shells, or credential exfil.
4. `.cursor/rules/*`, `.cursorrules`, `CLAUDE.md`, `AGENTS.md`, `.github/copilot-instructions.md`,
   `.claude/skills/**/*.md`, `.claude/commands/**/*.md`:
   - Invisible/bidi Unicode smuggling (zero-width chars, Trojan Source bidi overrides, Unicode Tags; UTF-8 BOM ignored)
   - Covert prompt-injection instruction overrides, shell RCE, & credential exfiltration directives
     (calibrated so benign docs like "Never commit .env" do NOT false-positive).
"""

import json
from pathlib import Path
import re
from typing import Any, Dict, List, Tuple
import unicodedata
from pydantic import BaseModel

from piton.iac.poisoning_lint import (
    INVISIBLE_UNICODE_RE,
    LintSeverity,
    PoisoningFinding,
)

# High-signal shell RCE & credential-harvesting patterns inside hook / MCP STDIO commands
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
    r"(?i)(?:(?:~/|\$HOME/)\.ssh|(?:~/|\$HOME/)\.aws|(?:~/|\$HOME/)\.kube|(?:~/|\$HOME/)\.npmrc|(?:~/|\$HOME/)\.netrc|/etc/shadow|id_rsa|aws_secret_access_key|github_token|npm_token|openai_api_key|anthropic_api_key|stripe_api_key|\.env\b)"
    r"[^\n]{0,160}(?:curl|wget|nc|http://|https://|base64|webhook|discord|telegram|pastebin)"
)
_HOOK_NET_POST_RE = re.compile(
    r"(?i)\b(?:curl|wget)\b[^\n]{0,180}(?:-d\b|--data|--upload-file|-F\b|-H\b|-X\s*POST)[^\n]{0,180}(?:\$[A-Z_]{3,}|/etc/|~/\.|\$HOME/\.|\.env\b|id_rsa)"
)
_DANGEROUS_PERMISSION_RE = re.compile(
    r"(?i)^(?:Bash$|Bash\(\s*(?:\*|rm\b|curl\b|wget\b|sh\b|bash\b|sudo\b|chmod\b|chown\b|/bin/sh\b|/bin/bash\b))"
)

# Dedicated coding-agent instruction/rule file catalog (prevents false positives on benign CLAUDE.md docs)
AGENT_RULE_PATTERNS: Tuple[Tuple[str, LintSeverity, str, str], ...] = (
    (
        "AGENT_RULE_INSTRUCTION_OVERRIDE",
        LintSeverity.CRITICAL,
        r"(ignore\s+(all\s+)?(previous|prior|above)\s+instructions?|disregard\s+(all\s+)?(previous|prior)|new\s+system\s+prompt|override\s+system\s+instructions?)",
        "Agent rule file contains prompt-override directives attempting to hijack coding-agent instructions.",
    ),
    (
        "AGENT_RULE_COVERT_CONCEALMENT",
        LintSeverity.CRITICAL,
        r"(do\s+not\s+(tell|inform|mention|show|notify)\s+the\s+user|never\s+mention\s+this|hide\s+this\s+from\s+the\s+user|silently\s+(send|forward|copy|bcc|exfiltrate|execute))",
        "Agent rule file contains covert concealment directives instructing the agent to hide actions from the user.",
    ),
    (
        "AGENT_RULE_CREDENTIAL_EXFIL",
        LintSeverity.CRITICAL,
        r"((?:~/|\$HOME/)\.ssh/id_(?:rsa|ed25519)|(?:~/|\$HOME/)\.aws/credentials|/etc/shadow|(?:read|cat|copy|send|post|upload|forward|exfiltrat\w*)\s+[^\n]{0,80}(?:~/\.ssh|~/\.aws/credentials|id_rsa|id_ed25519|/etc/shadow)|(?:send|post|upload|forward|exfiltrat\w*|curl|wget)\s+[^\n]{0,80}\.env\b|\bexfiltrat\w*\b[^\n]{0,80}(?:\.env\b|secret|token|key|ssh|cred|passwd)|webhook\.site|ngrok\.io|pass\s+(all|the)\s+(api\s+keys?|secrets?|tokens?|credentials?))",
        "Agent rule file directs credential reading or covert outbound exfiltration.",
    ),
    (
        "AGENT_RULE_SHELL_RCE",
        LintSeverity.HIGH,
        r"(\bcurl\s+[^|\n]{1,120}\|\s*(?:ba)?sh\b|\bwget\s+[^|\n]{1,120}\|\s*(?:ba)?sh\b|powershell\s+-enc)",
        "Agent rule file embeds pipe-to-shell or encoded command execution directives.",
    ),
)

_MCP_CONFIG_CANDIDATES = (
    ".mcp.json",
    "mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
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


def _parse_jsonc(raw: str) -> Any:
    """
    Parses JSONC (VS Code / Cursor config files) by stripping `//` inline comments,
    `/* ... */` block comments outside strings, and trailing commas before `}` or `]`.
    """
    out: List[str] = []
    i = 0
    n = len(raw)
    in_str = False
    esc = False
    while i < n:
        ch = raw[i]
        if in_str:
            out.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and raw[i + 1] == "/":
            i += 2
            while i < n and raw[i] not in ("\n", "\r"):
                i += 1
            continue
        if ch == "/" and i + 1 < n and raw[i + 1] == "*":
            i += 2
            while i + 1 < n and not (raw[i] == "*" and raw[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1

    stripped = "".join(out)
    # Remove trailing commas before closing object/array braces
    stripped = re.sub(r",(\s*[}\]])", r"\1", stripped)
    return json.loads(stripped)


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


def _lint_shell_command(
    server_label: str,
    rel_path: str,
    loc: str,
    raw_cmd: str,
    subject: str,
) -> List[PoisoningFinding]:
    findings: List[PoisoningFinding] = []
    cmd = unicodedata.normalize("NFKC", raw_cmd)
    if _HOOK_DOWNLOAD_EXEC_RE.search(cmd):
        findings.append(
            PoisoningFinding(
                server_name=server_label,
                tool_name=rel_path,
                rule_id="AGENT_HOOK_DOWNLOAD_EXEC",
                severity=LintSeverity.CRITICAL,
                field_path=loc,
                message=f"{subject} downloads and pipes remote code directly into a shell/interpreter.",
                matched_snippet=cmd[:160],
            )
        )
    if _HOOK_REVERSE_SHELL_RE.search(cmd):
        findings.append(
            PoisoningFinding(
                server_name=server_label,
                tool_name=rel_path,
                rule_id="AGENT_HOOK_REVERSE_SHELL",
                severity=LintSeverity.CRITICAL,
                field_path=loc,
                message=f"{subject} contains an interactive/reverse shell command.",
                matched_snippet=cmd[:160],
            )
        )
    if _HOOK_OBFUSCATED_EXEC_RE.search(cmd):
        findings.append(
            PoisoningFinding(
                server_name=server_label,
                tool_name=rel_path,
                rule_id="AGENT_HOOK_OBFUSCATED_EXEC",
                severity=LintSeverity.CRITICAL,
                field_path=loc,
                message=f"{subject} decodes or dynamically evaluates obfuscated shell payloads.",
                matched_snippet=cmd[:160],
            )
        )
    if _HOOK_CRED_EXFIL_RE.search(cmd) or _HOOK_NET_POST_RE.search(cmd):
        findings.append(
            PoisoningFinding(
                server_name=server_label,
                tool_name=rel_path,
                rule_id="AGENT_HOOK_CREDENTIAL_EXFIL",
                severity=LintSeverity.CRITICAL,
                field_path=loc,
                message=f"{subject} accesses credentials/secrets and transmits data over the network.",
                matched_snippet=cmd[:160],
            )
        )
    return findings


def lint_claude_settings(rel_path: str, data: Dict[str, Any]) -> List[PoisoningFinding]:
    findings: List[PoisoningFinding] = []

    hooks = data.get("hooks")
    if hooks is not None:
        for hook_loc, raw_cmd in _extract_hook_commands(hooks, "hooks"):
            findings.extend(
                _lint_shell_command("agent-config", rel_path, hook_loc, raw_cmd, "Claude Code hook")
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


def lint_mcp_stdio_configs(rel_path: str, data: Dict[str, Any]) -> List[PoisoningFinding]:
    findings: List[PoisoningFinding] = []
    servers = data.get("mcpServers") or data.get("servers")
    if not isinstance(servers, dict):
        return findings
    for srv_name, srv_cfg in servers.items():
        if not isinstance(srv_cfg, dict):
            continue
        cmd = srv_cfg.get("command")
        args = srv_cfg.get("args") or []
        if isinstance(cmd, str) and cmd.strip():
            full_cmd = " ".join([cmd.strip()] + [str(a) for a in args if a is not None])
            findings.extend(
                _lint_shell_command(
                    "mcp-config",
                    rel_path,
                    f"mcpServers.{srv_name}",
                    full_cmd,
                    f"MCP STDIO server '{srv_name}' command",
                )
            )
    return findings


def lint_agent_instruction_file(rel_path: str, content: str) -> List[PoisoningFinding]:
    """
    Scans the full coding-agent instruction/rule/skill markdown file for invisible/bidi
    Unicode smuggling, prompt-override directives, covert concealment, shell RCE, and
    credential exfiltration instructions — without flagging benign docs like "Never commit .env".
    """
    findings: List[PoisoningFinding] = []
    # Strip standard leading UTF-8 BOM so legitimate editors don't trigger invisible-Unicode
    text = content[1:] if content.startswith("\ufeff") else content
    if not text:
        return findings

    m_inv = INVISIBLE_UNICODE_RE.search(text)
    if m_inv:
        start = max(0, m_inv.start() - 30)
        end = min(len(text), m_inv.end() + 70)
        findings.append(
            PoisoningFinding(
                server_name="agent-rules",
                tool_name=rel_path,
                rule_id="AGENT_RULE_INVISIBLE_UNICODE",
                severity=LintSeverity.CRITICAL,
                field_path="content",
                message="Agent rule file contains invisible zero-width, bidi-override, or Unicode tag characters.",
                matched_snippet=repr(text[start:end]),
            )
        )

    normalized = unicodedata.normalize("NFKC", INVISIBLE_UNICODE_RE.sub("", text))
    for rule_id, severity, pattern, msg in AGENT_RULE_PATTERNS:
        m = re.search(pattern, normalized, re.IGNORECASE)
        if m:
            findings.append(
                PoisoningFinding(
                    server_name="agent-rules",
                    tool_name=rel_path,
                    rule_id=rule_id,
                    severity=severity,
                    field_path="content",
                    message=msg,
                    matched_snippet=m.group(0)[:140],
                )
            )

    return findings


def scan_agent_supply_chain(repo_path: Path) -> AgentConfigScanResult:
    """
    Scans a repository for coding-agent RCE hooks, auto-run tasks, malicious STDIO MCP
    commands, and poisoned instruction/skill files across Claude Code, Cursor, VS Code, and Copilot.
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
                data = _parse_jsonc(p.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    findings.extend(lint_claude_settings(rel, data))
            except Exception:
                pass

    # 2. VS Code / Cursor tasks.json folderOpen RCE (full JSONC support)
    tasks_path = repo_root / ".vscode" / "tasks.json"
    if tasks_path.is_file():
        scanned.append(".vscode/tasks.json")
        try:
            data = _parse_jsonc(tasks_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                findings.extend(lint_vscode_tasks(".vscode/tasks.json", data))
        except Exception:
            pass

    # 3. MCP JSON configs (STDIO command/args RCE scan before `piton init --probe`)
    for rel in _MCP_CONFIG_CANDIDATES:
        p = repo_root / rel
        if p.is_file():
            scanned.append(rel)
            try:
                data = _parse_jsonc(p.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    findings.extend(lint_mcp_stdio_configs(rel, data))
            except Exception:
                pass

    # 4. Coding-agent rules, instructions & skill markdown files
    rule_candidates: List[Path] = []
    for single in (
        ".cursorrules",
        "CLAUDE.md",
        ".claude/CLAUDE.md",
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
