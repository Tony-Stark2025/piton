"""
`prometheus init` — Static Repository & MCP Config Scanner (Uber Argus Pattern).

Generates a Day-1 `prometheus.yaml` (defaulting to `mode: shadow`), `prometheus.lock`
(split structural/description hashes after Day-1 poisoning lint), and `.env.agent`
(format-preserving ghost tokens for zero-secret local prototyping) in <1 second.
"""

import base64
import json
from pathlib import Path
import re
import secrets
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import yaml
from pydantic import BaseModel, Field

from prometheus.iac.lockfile import build_lockfile_from_servers
from prometheus.iac.poisoning_lint import PoisoningFinding
from prometheus.iac.schema import (
    AgentIaCConfig,
    AgentMeta,
    EnforcementMode,
    IdentityConfig,
    IdentityMode,
    LocalDevCredentialSlot,
    ManifestLockfile,
    MCPServerPolicy,
    ParameterBound,
    RateLimitPolicy,
    ToolPolicy,
    ToolTier,
    TrustTier,
)


MCP_CONFIG_CANDIDATES = (
    ".cursor/mcp.json",
    ".mcp.json",
    "mcp.json",
    "claude_desktop_config.json",
    "mcp_servers.json",
)

ENV_TEMPLATE_CANDIDATES = (
    ".env.example",
    ".env.sample",
    ".env.template",
)

# Env var name patterns -> (slot_key, ghost_format, default_upstream_url)
KNOWN_PROVIDER_MAP: Tuple[Tuple[str, str, str, str], ...] = (
    ("STRIPE", "stripe_api", "stripe_test", "https://api.stripe.com"),
    ("GITHUB", "github_api", "github", "https://api.github.com"),
    ("SLACK", "slack_api", "slack", "https://slack.com/api"),
    ("OPENAI", "openai_api", "openai", "https://api.openai.com"),
    ("ANTHROPIC", "anthropic_api", "anthropic", "https://api.anthropic.com"),
    ("ZENDESK", "zendesk_api", "generic", "https://example.zendesk.com"),
    ("LINEAR", "linear_api", "generic", "https://api.linear.app"),
)

SECRET_ENV_SUFFIXES = ("_API_KEY", "_SECRET_KEY", "_SECRET", "_TOKEN", "_ACCESS_KEY")

BOUNDED_WRITE_KEYWORDS = (
    "delete", "remove", "refund", "transfer", "wire", "payout", "charge",
    "send_", "post_", "publish", "approve", "grant", "revoke", "drop",
)


def generate_format_preserving_ghost_token(ghost_format: str, slot_name: str = "slot") -> str:
    """
    Generates a harmless placeholder token that satisfies real client SDK prefix &
    structural validators (e.g. Stripe `sk_test_`, GitHub `ghp_`, Slack `xoxb-`, JWT 3-part).
    """
    rand_hex = secrets.token_hex(12)
    fmt = ghost_format.lower()
    if fmt == "stripe_test":
        return f"sk_test_promghost_{rand_hex}"
    if fmt == "stripe_live":
        return f"sk_live_promghost_{rand_hex}"
    if fmt == "github":
        return f"ghp_promghost{rand_hex[:24]}"
    if fmt == "slack":
        return f"xoxb-000000000000-000000000000-promghost{rand_hex[:14]}"
    if fmt == "openai":
        return f"sk-proj-promghost-{rand_hex}"
    if fmt == "anthropic":
        return f"sk-ant-api03-promghost-{rand_hex}"
    if fmt == "jwt":
        hdr = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": f"prom_ghost_{slot_name}", "exp": 4102444800}).encode()
        ).decode().rstrip("=")
        sig = base64.urlsafe_b64encode(f"promghost_{rand_hex}".encode()).decode().rstrip("=")
        return f"{hdr}.{payload}.{sig}"
    return f"prom_ghost_{slot_name}_{rand_hex}"


def _infer_trust_tier(server_name: str, url: Optional[str]) -> TrustTier:
    if url:
        host = (urlparse(url).hostname or "").lower()
        if host in ("localhost", "127.0.0.1", "::1") or host.endswith((".internal", ".local", ".corp", ".lan")):
            return TrustTier.INTERNAL
    lower_name = server_name.lower()
    if any(tok in lower_name for tok in ("internal", "local", "billing", "core")):
        return TrustTier.INTERNAL
    return TrustTier.THIRD_PARTY


def _classify_tool_policy(tool: Dict[str, Any]) -> ToolPolicy:
    name = str(tool.get("name") or "").lower()
    is_bounded = any(kw in name for kw in BOUNDED_WRITE_KEYWORDS)
    if not is_bounded:
        if any(name.startswith(p) for p in ("update_", "edit_", "create_", "draft_", "set_")):
            return ToolPolicy(tier=ToolTier.REVERSIBLE_WRITE)
        return ToolPolicy(tier=ToolTier.READ)

    bounds: Dict[str, ParameterBound] = {}
    props = (tool.get("inputSchema") or {}).get("properties") or {}
    if isinstance(props, dict):
        for pname, pdef in props.items():
            if not isinstance(pdef, dict):
                continue
            plower = pname.lower()
            if plower in ("amount", "total", "price", "refund_amount") and pdef.get("type") in ("number", "integer"):
                bounds[pname] = ParameterBound(min=0.01, max=100.0)
            elif "email" in plower or "domain" in plower or "recipient" in plower:
                bounds[pname] = ParameterBound(allow_domains=["example.com"])

    return ToolPolicy(
        tier=ToolTier.BOUNDED_WRITE,
        idempotency_key="required",
        parameter_bounds=bounds,
        rate_limit=RateLimitPolicy(max_calls_per_trace=5),
    )


class InitScanResult(BaseModel):
    config: AgentIaCConfig
    lockfile: ManifestLockfile
    ghost_env: Dict[str, str] = Field(default_factory=dict)
    poisoning_findings: List[PoisoningFinding] = Field(default_factory=list)
    discovered_files: List[str] = Field(default_factory=list)


def scan_repository(
    repo_root: Path,
    agent_id: Optional[str] = None,
    owner: str = "platform-team@example.com",
    live_server_tools: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    allow_poisoned: bool = False,
) -> InitScanResult:
    """
    Statically scans a repository for MCP server configs and env secret templates,
    runs Day-1 poisoning lint on any discovered/live tool manifests, and produces
    `prometheus.yaml` (shadow mode), `prometheus.lock`, and `.env.agent`.
    """
    repo_root = Path(repo_root).resolve()
    resolved_agent_id = agent_id or re.sub(r"[^a-zA-Z0-9_-]+", "-", repo_root.name).strip("-").lower() or "agent"

    discovered_files: List[str] = []
    mcp_servers: Dict[str, MCPServerPolicy] = {}
    servers_for_lock: Dict[str, Tuple[TrustTier, Optional[str], List[Dict[str, Any]]]] = {}
    local_creds: Dict[str, LocalDevCredentialSlot] = {}
    ghost_env: Dict[str, str] = {}

    # 1. Discover MCP configurations
    for rel in MCP_CONFIG_CANDIDATES:
        candidate = repo_root / rel
        if not candidate.is_file():
            continue
        try:
            raw = json.loads(candidate.read_text(encoding="utf-8"))
        except Exception:
            continue
        discovered_files.append(rel)
        servers_dict = raw.get("mcpServers") or raw.get("servers") or {}
        if not isinstance(servers_dict, dict):
            continue
        for srv_name, srv_cfg in servers_dict.items():
            if not isinstance(srv_cfg, dict):
                continue
            url = srv_cfg.get("url")
            cmd = srv_cfg.get("command")
            args = [str(a) for a in (srv_cfg.get("args") or [])]
            trust = _infer_trust_tier(srv_name, url)

            tools_list: List[Dict[str, Any]] = []
            if live_server_tools and srv_name in live_server_tools:
                tools_list = live_server_tools[srv_name]
            elif isinstance(srv_cfg.get("tools"), list):
                tools_list = srv_cfg["tools"]

            tool_policies = {
                str(t["name"]): _classify_tool_policy(t)
                for t in tools_list
                if isinstance(t, dict) and t.get("name")
            }

            mcp_servers[srv_name] = MCPServerPolicy(
                url=url,
                command=cmd,
                args=args,
                trust_tier=trust,
                tools=tool_policies,
            )
            servers_for_lock[srv_name] = (trust, url, tools_list)

    # Also include any live_server_tools passed directly that weren't in a static JSON file
    if live_server_tools:
        for srv_name, tools_list in live_server_tools.items():
            if srv_name not in mcp_servers:
                trust = _infer_trust_tier(srv_name, None)
                mcp_servers[srv_name] = MCPServerPolicy(
                    trust_tier=trust,
                    tools={
                        str(t["name"]): _classify_tool_policy(t)
                        for t in tools_list
                        if isinstance(t, dict) and t.get("name")
                    },
                )
                servers_for_lock[srv_name] = (trust, None, tools_list)

    # 2. Discover credential slots from .env.example / docker-compose templates (never commit raw prod .env)
    env_var_names: List[str] = []
    for rel in ENV_TEMPLATE_CANDIDATES:
        candidate = repo_root / rel
        if not candidate.is_file():
            continue
        discovered_files.append(rel)
        for line in candidate.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            var = stripped.split("=", 1)[0].strip()
            if var and any(var.upper().endswith(sfx) for sfx in SECRET_ENV_SUFFIXES):
                env_var_names.append(var)

    for dc_name in ("docker-compose.yml", "docker-compose.yaml"):
        dc_path = repo_root / dc_name
        if not dc_path.is_file():
            continue
        try:
            dc_data = yaml.safe_load(dc_path.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        discovered_files.append(dc_name)
        for svc in (dc_data.get("services") or {}).values():
            if not isinstance(svc, dict):
                continue
            env_section = svc.get("environment")
            if isinstance(env_section, dict):
                for k in env_section.keys():
                    if any(str(k).upper().endswith(sfx) for sfx in SECRET_ENV_SUFFIXES):
                        env_var_names.append(str(k))
            elif isinstance(env_section, list):
                for item in env_section:
                    k = str(item).split("=", 1)[0].strip()
                    if any(k.upper().endswith(sfx) for sfx in SECRET_ENV_SUFFIXES):
                        env_var_names.append(k)

    for var in sorted(set(env_var_names)):
        var_up = var.upper()
        slot_key = var.lower()
        ghost_fmt = "generic"
        upstream = "https://api.example.com"
        for prefix, mapped_slot, mapped_fmt, mapped_url in KNOWN_PROVIDER_MAP:
            if prefix in var_up:
                slot_key = mapped_slot
                ghost_fmt = mapped_fmt
                upstream = mapped_url
                break
        if "JWT" in var_up:
            ghost_fmt = "jwt"

        host = urlparse(upstream).hostname or "api.example.com"
        local_creds[slot_key] = LocalDevCredentialSlot(
            ghost_format=ghost_fmt,
            source=f"env://{var}",
            upstream_base_url=upstream,
            allowed_hosts=[host],
            allowed_methods=["GET", "POST"],
            allowed_path_prefixes=["/"],
            follow_redirects=False,
            redact_in_responses=True,
        )
        ghost_env[var] = generate_format_preserving_ghost_token(ghost_fmt, slot_key)
        ghost_env[f"{var}_BASE_URL"] = f"http://localhost:8080/gw/{slot_key}"

    lockfile, poisoning_findings = build_lockfile_from_servers(
        servers_for_lock, allow_poisoned=allow_poisoned
    )

    config = AgentIaCConfig(
        version="1",
        agent=AgentMeta(id=resolved_agent_id, owner=owner, mode=EnforcementMode.SHADOW),
        identity=IdentityConfig(mode=IdentityMode.OIDC_OBO, require_delegated_sub=True),
        local_dev_credentials=local_creds,
        mcp_servers=mcp_servers,
    )

    return InitScanResult(
        config=config,
        lockfile=lockfile,
        ghost_env=ghost_env,
        poisoning_findings=poisoning_findings,
        discovered_files=discovered_files,
    )


def write_init_artifacts(repo_root: Path, result: InitScanResult) -> Dict[str, Path]:
    """Writes `prometheus.yaml`, `prometheus.lock`, and `.env.agent` to the repository root."""
    repo_root = Path(repo_root).resolve()
    yaml_path = repo_root / "prometheus.yaml"
    lock_path = repo_root / "prometheus.lock"
    env_path = repo_root / ".env.agent"

    result.config.save_file(yaml_path)
    result.lockfile.save_file(lock_path)

    env_lines = [
        "# Auto-generated by `prometheus init` — safe format-preserving ghost handles (ZERO real secrets)",
        "# Real secrets stay in the host/gateway environment and are swapped at the boundary.",
    ]
    for k, v in sorted(result.ghost_env.items()):
        env_lines.append(f"{k}={v}")
    env_path.write_text("\n".join(env_lines) + "\n", encoding="utf-8")

    return {
        "prometheus.yaml": yaml_path,
        "prometheus.lock": lock_path,
        ".env.agent": env_path,
    }
