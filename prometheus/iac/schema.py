"""
Declarative Agent IaC (`prometheus.yaml`) and Split-Hash MCP Manifest Lockfile (`prometheus.lock`) Schemas.

Design guarantees:
- Human intent & parameter-bounded policies live in `prometheus.yaml` (committed to git).
- Machine-managed SHA-256 hashes live in `prometheus.lock` (eliminating YAML merge conflicts).
- Production identity defaults to OIDC/OBO delegation (`oidc_obo`) with stateless W3C `traceparent`
  correlation (MCP 2026-07-28 compatible); static env keys are strictly isolated to `local_dev_credentials`.
"""

from enum import Enum
import hashlib
import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional
import yaml
from pydantic import BaseModel, Field


class EnforcementMode(str, Enum):
    SHADOW = "shadow"
    ENFORCE = "enforce"


class IdentityMode(str, Enum):
    OIDC_OBO = "oidc_obo"
    LOCAL_DEV = "local_dev"


class TrustTier(str, Enum):
    INTERNAL = "internal"
    THIRD_PARTY = "third_party"


class ToolTier(str, Enum):
    READ = "read"
    REVERSIBLE_WRITE = "reversible_write"
    BOUNDED_WRITE = "bounded_write"


class BoundExceededAction(str, Enum):
    MRTR_ESCALATE = "mrtr_escalate"  # MCP 2026-07-28 out-of-band elicitation
    BLOCK = "block"
    WARN = "warn"


class AgentMeta(BaseModel):
    id: str = Field(..., description="Unique agent identifier")
    owner: str = Field(default="platform-team@example.com", description="Owning engineering team or email")
    mode: EnforcementMode = Field(default=EnforcementMode.SHADOW, description="shadow (observe) or enforce")


class IdentityConfig(BaseModel):
    mode: IdentityMode = Field(default=IdentityMode.OIDC_OBO)
    issuer: Optional[str] = Field(default=None, description="OIDC issuer URL (Okta / Entra / Auth0)")
    jwks_url: Optional[str] = Field(default=None, description="Explicit JWKS URL (auto-discovered from issuer if omitted)")
    audience: Optional[str] = Field(default=None, description="Expected JWT aud claim")
    verify_jwt_signature: bool = Field(
        default=False,
        description="When true (or when jwks_url/issuer is set with enforce), cryptographically verify RS256/ES256 JWTs via JWKS",
    )
    require_delegated_sub: bool = Field(
        default=True,
        description="Require OBO user+agent principal claims in production enforce mode",
    )
    correlate_header: str = Field(
        default="traceparent",
        description="Stateless MCP 2026-07-28 correlation header (W3C traceparent)",
    )


class LocalDevCredentialSlot(BaseModel):
    """Local-dev-only zero-secret credential slot using format-preserving ghost tokens."""
    ghost_format: str = Field(
        default="generic",
        description="Format template: stripe_test, stripe_live, github, slack, openai, jwt, generic",
    )
    source: str = Field(..., description="env://VAR_NAME or file:///path/to/secret")
    upstream_base_url: str = Field(..., description="Target HTTPS base URL")
    allowed_hosts: List[str] = Field(default_factory=list)
    allowed_methods: List[str] = Field(default_factory=lambda: ["GET", "POST"])
    allowed_path_prefixes: List[str] = Field(default_factory=lambda: ["/"])
    follow_redirects: bool = Field(default=False, description="Never leak credentials across 3xx redirects")
    redact_in_responses: bool = Field(default=True)


class ParameterBound(BaseModel):
    """Deterministic argument-level constraint (Progent/Cedar-style bounded autonomy)."""
    min: Optional[float] = None
    max: Optional[float] = None
    enum: Optional[List[Any]] = None
    allow_domains: Optional[List[str]] = None
    deny_domains: Optional[List[str]] = None
    regex: Optional[str] = None
    max_length: Optional[int] = None


class RateLimitPolicy(BaseModel):
    max_calls_per_trace: Optional[int] = Field(default=None, ge=1)


class ToolPolicy(BaseModel):
    tier: ToolTier = Field(default=ToolTier.READ)
    idempotency_key: Optional[str] = Field(
        default=None,
        description="Set to 'required' to enforce single-use idempotency on bounded writes",
    )
    parameter_bounds: Dict[str, ParameterBound] = Field(default_factory=dict)
    rate_limit: Optional[RateLimitPolicy] = None
    on_bound_exceeded: BoundExceededAction = Field(default=BoundExceededAction.MRTR_ESCALATE)


class MCPServerPolicy(BaseModel):
    url: Optional[str] = None
    command: Optional[str] = Field(default=None, description="STDIO command if discovered locally")
    args: List[str] = Field(default_factory=list)
    trust_tier: TrustTier = Field(default=TrustTier.THIRD_PARTY)
    tools: Dict[str, ToolPolicy] = Field(default_factory=dict)


class AgentIaCConfig(BaseModel):
    """Top-level `prometheus.yaml` schema."""
    version: str = Field(default="1")
    agent: AgentMeta
    identity: IdentityConfig = Field(default_factory=IdentityConfig)
    local_dev_credentials: Dict[str, LocalDevCredentialSlot] = Field(default_factory=dict)
    mcp_servers: Dict[str, MCPServerPolicy] = Field(default_factory=dict)

    def canonical_sha256(self) -> str:
        payload = self.model_dump(mode="json")
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def to_yaml(self) -> str:
        return yaml.safe_dump(
            self.model_dump(mode="json", exclude_none=True),
            sort_keys=False,
            default_flow_style=False,
        )

    @classmethod
    def from_yaml(cls, raw_yaml: str) -> "AgentIaCConfig":
        data = yaml.safe_load(raw_yaml) or {}
        return cls.model_validate(data)

    @classmethod
    def load_file(cls, path: Path) -> "AgentIaCConfig":
        return cls.from_yaml(path.read_text(encoding="utf-8"))

    def save_file(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_yaml(), encoding="utf-8")


# =============================================================================
# Split-Hash MCP Manifest Lockfile (`prometheus.lock`)
# =============================================================================

class PinnedToolEntry(BaseModel):
    """
    Separates structural schema pin (`name` + canonical `inputSchema`) from prose
    description pin (`description`) so benign internal docstring edits warn instead
    of causing outages, while schema mutations or third-party rug pulls hard-block.
    """
    structural_sha256: str
    description_sha256: str
    description_preview: str = ""
    poisoning_lint_passed: bool = True
    poisoning_warnings: List[str] = Field(default_factory=list)


class PinnedServerManifest(BaseModel):
    trust_tier: TrustTier = TrustTier.THIRD_PARTY
    url: Optional[str] = None
    tools: Dict[str, PinnedToolEntry] = Field(default_factory=dict)


class ManifestLockfile(BaseModel):
    """Top-level `prometheus.lock` schema."""
    version: str = Field(default="1")
    generated_at: float = Field(default_factory=time.time)
    servers: Dict[str, PinnedServerManifest] = Field(default_factory=dict)

    def canonical_sha256(self) -> str:
        # Exclude timestamp so identical pin sets yield identical compliance ledger hashes
        payload = {
            "version": self.version,
            "servers": {
                srv_name: srv.model_dump(mode="json")
                for srv_name, srv in sorted(self.servers.items())
            },
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def to_json(self) -> str:
        return json.dumps(self.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_json(cls, raw_json: str) -> "ManifestLockfile":
        return cls.model_validate(json.loads(raw_json))

    @classmethod
    def load_file(cls, path: Path) -> "ManifestLockfile":
        return cls.from_json(path.read_text(encoding="utf-8"))

    def save_file(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(), encoding="utf-8")
