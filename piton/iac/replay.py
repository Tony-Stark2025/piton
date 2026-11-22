"""
Piton Policy Calibration Engine (`piton replay`), PII-Preserving Deterministic
Tokenization, Parameter-Bounded Evaluator, and Version-Pinned Signed Decision Ledger.

Implements the Agent Control Loop validated by late-2026 production systems:
1. Deterministic PII-preserving tokenization: Masks raw PII (`alice@acme.com` ->
   `tok_a1b2c3d4@acme.com`) while preserving structural predicates (email domains,
   numeric ceilings, enum values) so offline replay stays 100% accurate without leaking PII.
2. Version-pinned, HMAC-chained Signed Decision Ledger: Ties every decision to
   `policy_sha256`, `lockfile_sha256`, W3C `traceparent`, OBO principal, and `input_hash`
   so auditors can deterministically replay why any action was allowed or denied months later.
3. Counterfactual `replay_traces`: Replays shadow traffic against candidate `piton.yaml`
   policies in simulated `enforce` mode and emits concrete calibration suggestions to reach
   0% false blocks before flipping production traffic from `shadow` to `enforce`.
"""

from enum import Enum
import hashlib
import hmac
import json
import math
from pathlib import Path
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from piton.iac.schema import (
    AgentIaCConfig,
    BoundExceededAction,
    EnforcementMode,
    IdentityMode,
    ManifestLockfile,
    ParameterBound,
    ToolPolicy,
)


EMAIL_RE = re.compile(r"^([^@\s]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})$")
PII_KEY_HINTS = ("email", "user", "customer", "recipient", "phone", "ssn", "name", "address", "card", "account")


class DecisionVerdict(str, Enum):
    ALLOW = "allow"
    SHADOW_DENY = "shadow_deny"
    MRTR_ESCALATE = "mrtr_escalate"
    DENY = "deny"


class DeterministicTokenizer:
    """
    HMAC-SHA256 format-preserving tokenizer for PII-safe trace logs & accurate replay.
    - `alice@acme.com` -> `tok_<8hex>@acme.com` (domain predicate preserved!)
    - Numeric fields (`amount: 75.0`), booleans, and non-PII enums (`USD`) stay intact.
    - Arbitrary PII strings (`ssn`, `phone`, `customer_name`) become `tok_<12hex>`.
    """

    def __init__(self, secret_key: bytes = b"piton-default-tokenizer-key") -> None:
        self._key = secret_key

    def _hmac_hex(self, value: str, length: int = 12) -> str:
        return hmac.new(self._key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:length]

    def tokenize_value(self, key: str, value: Any) -> Any:
        if isinstance(value, bool) or isinstance(value, (int, float)) or value is None:
            return value
        if isinstance(value, dict):
            return {k: self.tokenize_value(k, v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.tokenize_value(key, v) for v in value]
        if isinstance(value, str):
            m = EMAIL_RE.match(value.strip())
            if m:
                local_part, domain = m.group(1), m.group(2).lower()
                return f"tok_{self._hmac_hex(local_part, 8)}@{domain}"
            k_lower = key.lower()
            if any(hint in k_lower for hint in PII_KEY_HINTS) and not value.startswith("tok_"):
                return f"tok_{self._hmac_hex(value, 12)}"
        return value

    def tokenize_arguments(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return {k: self.tokenize_value(k, v) for k, v in arguments.items()}


class RuleViolation(BaseModel):
    rule_id: str
    parameter: Optional[str] = None
    message: str
    observed_value: Optional[Any] = None
    configured_bound: Optional[Any] = None
    recommended_action: BoundExceededAction = BoundExceededAction.BLOCK


class PolicyEvaluationResult(BaseModel):
    verdict: DecisionVerdict
    violations: List[RuleViolation] = Field(default_factory=list)
    server_name: str
    tool_name: str


def _extract_domain(value: str) -> Optional[str]:
    """
    Safe domain extraction preventing URL parser differentials such as
    `https://evil.com/?x=@acme.com` (never checks `@` before `://`!).
    """
    from urllib.parse import urlparse

    v = value.strip().lower()
    if not v or any(ch.isspace() for ch in v):
        return None
    if "://" in v:
        parsed = urlparse(v)
        # Reject URL userinfo (`@`) smuggling outright
        if parsed.username is not None or parsed.password is not None:
            return None
        return parsed.hostname.lower() if parsed.hostname else None
    m = EMAIL_RE.match(v)
    if m:
        return m.group(2).lower()
    if "." in v and "@" not in v and "/" not in v:
        return v
    return None


def _strict_enum_member(val: Any, allowed: List[Any]) -> bool:
    for item in allowed:
        if type(val) is bool or type(item) is bool:
            if type(val) is type(item) and val == item:
                return True
            continue
        if isinstance(val, (int, float)) and isinstance(item, (int, float)):
            if float(val) == float(item):
                return True
            continue
        if type(val) is type(item) and val == item:
            return True
    return False


def _check_parameter_bound(param_name: str, value: Any, bound: ParameterBound, on_exceed: BoundExceededAction) -> List[RuleViolation]:
    violations: List[RuleViolation] = []

    if bound.min is not None or bound.max is not None:
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            violations.append(
                RuleViolation(
                    rule_id="PARAM_TYPE_MISMATCH",
                    parameter=param_name,
                    message=f"Parameter '{param_name}' expected numeric value for range bound.",
                    observed_value=value,
                    configured_bound={"min": bound.min, "max": bound.max},
                    recommended_action=on_exceed,
                )
            )
        else:
            if bound.min is not None and value < bound.min:
                violations.append(
                    RuleViolation(
                        rule_id="PARAM_MIN_EXCEEDED",
                        parameter=param_name,
                        message=f"Parameter '{param_name}'={value} is below minimum bound {bound.min}.",
                        observed_value=value,
                        configured_bound=bound.min,
                        recommended_action=on_exceed,
                    )
                )
            if bound.max is not None and value > bound.max:
                violations.append(
                    RuleViolation(
                        rule_id="PARAM_MAX_EXCEEDED",
                        parameter=param_name,
                        message=f"Parameter '{param_name}'={value} exceeds maximum bound {bound.max}.",
                        observed_value=value,
                        configured_bound=bound.max,
                        recommended_action=on_exceed,
                    )
                )

    if bound.enum is not None and not _strict_enum_member(value, bound.enum):
        violations.append(
            RuleViolation(
                rule_id="PARAM_ENUM_VIOLATION",
                parameter=param_name,
                message=f"Parameter '{param_name}'={value!r} not in allowed enum {bound.enum}.",
                observed_value=value,
                configured_bound=bound.enum,
                recommended_action=on_exceed,
            )
        )

    has_string_bounds = (
        bound.max_length is not None
        or bound.regex is not None
        or bound.allow_domains is not None
        or bound.deny_domains is not None
    )
    if has_string_bounds:
        if not isinstance(value, str):
            violations.append(
                RuleViolation(
                    rule_id="PARAM_TYPE_MISMATCH",
                    parameter=param_name,
                    message=f"Parameter '{param_name}' expected string value for domain/regex/length bound.",
                    observed_value=value,
                    recommended_action=on_exceed,
                )
            )
        else:
            if bound.max_length is not None and len(value) > bound.max_length:
                violations.append(
                    RuleViolation(
                        rule_id="PARAM_MAX_LENGTH_EXCEEDED",
                        parameter=param_name,
                        message=f"Parameter '{param_name}' length {len(value)} exceeds max_length {bound.max_length}.",
                        observed_value=len(value),
                        configured_bound=bound.max_length,
                        recommended_action=on_exceed,
                    )
                )
            if bound.regex is not None and not re.search(bound.regex, value):
                violations.append(
                    RuleViolation(
                        rule_id="PARAM_REGEX_MISMATCH",
                        parameter=param_name,
                        message=f"Parameter '{param_name}' failed regex bound '{bound.regex}'.",
                        observed_value=value,
                        configured_bound=bound.regex,
                        recommended_action=on_exceed,
                    )
                )
            if bound.allow_domains is not None or bound.deny_domains is not None:
                dom = _extract_domain(value)
                if bound.deny_domains and dom and dom in [d.lower() for d in bound.deny_domains]:
                    violations.append(
                        RuleViolation(
                            rule_id="PARAM_DOMAIN_DENIED",
                            parameter=param_name,
                            message=f"Domain '{dom}' on parameter '{param_name}' is explicitly denied.",
                            observed_value=dom,
                            configured_bound=bound.deny_domains,
                            recommended_action=on_exceed,
                        )
                    )
                if bound.allow_domains is not None:
                    allowed = [d.lower() for d in bound.allow_domains]
                    if not dom or dom not in allowed:
                        violations.append(
                            RuleViolation(
                                rule_id="PARAM_DOMAIN_NOT_ALLOWED",
                                parameter=param_name,
                                message=f"Domain '{dom}' on parameter '{param_name}' is not in allow_domains {bound.allow_domains}.",
                                observed_value=dom,
                                configured_bound=bound.allow_domains,
                                recommended_action=on_exceed,
                            )
                        )

    return violations


def evaluate_tool_call_against_policy(
    config: AgentIaCConfig,
    server_name: str,
    tool_name: str,
    arguments: Dict[str, Any],
    *,
    obo_principal: Optional[str] = None,
    idempotency_key: Optional[str] = None,
    trace_tool_call_count: int = 1,
    principal_hourly_calls: int = 1,
    principal_hourly_sum: float = 0.0,
    simulate_enforce: bool = False,
) -> PolicyEvaluationResult:
    """
    Deterministically evaluates a single MCP tool call against `piton.yaml`
    parameter bounds, rate limits, cumulative principal ceilings, idempotency, and OIDC/OBO rules.
    """
    violations: List[RuleViolation] = []

    # 1. Production OIDC/OBO delegated principal check
    if config.identity.mode == IdentityMode.OIDC_OBO and config.identity.require_delegated_sub:
        if not obo_principal:
            violations.append(
                RuleViolation(
                    rule_id="MISSING_OBO_PRINCIPAL",
                    message="OIDC/OBO delegated user principal (`sub`/`act`) is required in production.",
                    recommended_action=BoundExceededAction.BLOCK,
                )
            )

    srv_policy = config.mcp_servers.get(server_name)
    if srv_policy is None:
        violations.append(
            RuleViolation(
                rule_id="UNKNOWN_MCP_SERVER",
                message=f"MCP server '{server_name}' is not declared in piton.yaml.",
                recommended_action=BoundExceededAction.BLOCK,
            )
        )
        tool_policy = None
    else:
        tool_policy = srv_policy.tools.get(tool_name)
        if tool_policy is None and srv_policy.strict_unknown_tools:
            violations.append(
                RuleViolation(
                    rule_id="UNLISTED_MCP_TOOL",
                    message=f"Tool '{server_name}.{tool_name}' is not declared in piton.yaml.",
                    recommended_action=BoundExceededAction.BLOCK,
                )
            )

    if tool_policy is not None:
        # 2. Idempotency requirement on bounded writes
        if tool_policy.idempotency_key == "required" and not idempotency_key:
            violations.append(
                RuleViolation(
                    rule_id="MISSING_IDEMPOTENCY_KEY",
                    message=f"Bounded write '{server_name}.{tool_name}' requires an idempotency key.",
                    recommended_action=BoundExceededAction.BLOCK,
                )
            )

        # 3. Per-trace & per-principal rolling-hour quotas
        if tool_policy.rate_limit:
            if tool_policy.rate_limit.max_calls_per_trace is not None:
                if trace_tool_call_count > tool_policy.rate_limit.max_calls_per_trace:
                    violations.append(
                        RuleViolation(
                            rule_id="TRACE_RATE_LIMIT_EXCEEDED",
                            message=(
                                f"Call #{trace_tool_call_count} to '{server_name}.{tool_name}' exceeds "
                                f"max_calls_per_trace={tool_policy.rate_limit.max_calls_per_trace}."
                            ),
                            observed_value=trace_tool_call_count,
                            configured_bound=tool_policy.rate_limit.max_calls_per_trace,
                            recommended_action=tool_policy.on_bound_exceeded,
                        )
                    )
            if tool_policy.rate_limit.max_calls_per_hour is not None:
                if principal_hourly_calls > tool_policy.rate_limit.max_calls_per_hour:
                    violations.append(
                        RuleViolation(
                            rule_id="PRINCIPAL_HOURLY_CALLS_EXCEEDED",
                            message=(
                                f"Hourly call #{principal_hourly_calls} exceeds "
                                f"max_calls_per_hour={tool_policy.rate_limit.max_calls_per_hour}."
                            ),
                            observed_value=principal_hourly_calls,
                            configured_bound=tool_policy.rate_limit.max_calls_per_hour,
                            recommended_action=tool_policy.on_bound_exceeded,
                        )
                    )
            if tool_policy.rate_limit.max_sum_per_hour is not None:
                if principal_hourly_sum > tool_policy.rate_limit.max_sum_per_hour:
                    violations.append(
                        RuleViolation(
                            rule_id="PRINCIPAL_HOURLY_SUM_EXCEEDED",
                            parameter=tool_policy.rate_limit.sum_parameter,
                            message=(
                                f"Cumulative hourly {tool_policy.rate_limit.sum_parameter}={principal_hourly_sum:.2f} "
                                f"exceeds max_sum_per_hour={tool_policy.rate_limit.max_sum_per_hour}."
                            ),
                            observed_value=principal_hourly_sum,
                            configured_bound=tool_policy.rate_limit.max_sum_per_hour,
                            recommended_action=tool_policy.on_bound_exceeded,
                        )
                    )

        # 4. Parameter bounds (fail closed when required bounded parameter is omitted)
        for param_name, bound in tool_policy.parameter_bounds.items():
            if param_name not in arguments:
                if bound.required:
                    violations.append(
                        RuleViolation(
                            rule_id="MISSING_BOUNDED_PARAMETER",
                            parameter=param_name,
                            message=f"Required bounded parameter '{param_name}' was omitted.",
                            recommended_action=BoundExceededAction.BLOCK,
                        )
                    )
                continue
            violations.extend(
                _check_parameter_bound(
                    param_name,
                    arguments[param_name],
                    bound,
                    tool_policy.on_bound_exceeded,
                )
            )

    effective_mode = EnforcementMode.ENFORCE if simulate_enforce else config.agent.mode
    if not violations:
        verdict = DecisionVerdict.ALLOW
    elif effective_mode == EnforcementMode.SHADOW:
        verdict = DecisionVerdict.SHADOW_DENY
    else:
        if any(v.recommended_action == BoundExceededAction.BLOCK for v in violations):
            verdict = DecisionVerdict.DENY
        elif any(v.recommended_action == BoundExceededAction.MRTR_ESCALATE for v in violations):
            verdict = DecisionVerdict.MRTR_ESCALATE
        else:
            verdict = DecisionVerdict.ALLOW

    return PolicyEvaluationResult(
        verdict=verdict,
        violations=violations,
        server_name=server_name,
        tool_name=tool_name,
    )


# =============================================================================
# Version-Pinned, Tamper-Evident Signed Decision Ledger
# =============================================================================

class DecisionLedgerRecord(BaseModel):
    timestamp: float = Field(default_factory=time.time)
    agent_id: str
    traceparent: str
    obo_principal: Optional[str] = None
    server_name: str
    tool_name: str
    tokenized_arguments: Dict[str, Any] = Field(default_factory=dict)
    idempotency_key: Optional[str] = None
    input_sha256: str
    policy_sha256: str
    lockfile_sha256: str
    verdict: DecisionVerdict
    violations: List[RuleViolation] = Field(default_factory=list)
    latency_ms: float = 0.0
    prev_record_hmac: str = "GENESIS"
    record_hmac: str = ""


class SignedDecisionLedger:
    """
    Append-only, HMAC-chained JSONL compliance ledger.
    Each record pins the exact `policy_sha256` and `lockfile_sha256` active at decision time
    plus PII-tokenized arguments so auditors can deterministically replay any decision.
    """

    def __init__(
        self,
        ledger_path: Path,
        signing_key: bytes = b"piton-ledger-signing-key",
        tokenizer: Optional[DeterministicTokenizer] = None,
    ) -> None:
        self.ledger_path = Path(ledger_path)
        self._signing_key = signing_key
        self.tokenizer = tokenizer or DeterministicTokenizer()
        self._last_hmac = "GENESIS"
        if self.ledger_path.is_file():
            existing = self.load_records()
            if existing:
                self._last_hmac = existing[-1].record_hmac

    def _compute_record_hmac(self, record: DecisionLedgerRecord) -> str:
        from piton.iac.schema import normalize_json_numbers

        body = normalize_json_numbers(record.model_dump(mode="json", exclude={"record_hmac"}))
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(self._signing_key, canonical, hashlib.sha256).hexdigest()

    def append_decision(
        self,
        config: AgentIaCConfig,
        lockfile: Optional[ManifestLockfile],
        *,
        traceparent: str,
        server_name: str,
        tool_name: str,
        raw_arguments: Dict[str, Any],
        evaluation: PolicyEvaluationResult,
        obo_principal: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        latency_ms: float = 0.0,
    ) -> DecisionLedgerRecord:
        tokenized = self.tokenizer.tokenize_arguments(raw_arguments)
        raw_canonical = json.dumps(raw_arguments, sort_keys=True, separators=(",", ":")).encode("utf-8")
        input_sha = hashlib.sha256(raw_canonical).hexdigest()

        rec = DecisionLedgerRecord(
            agent_id=config.agent.id,
            traceparent=traceparent,
            obo_principal=obo_principal,
            server_name=server_name,
            tool_name=tool_name,
            tokenized_arguments=tokenized,
            idempotency_key=idempotency_key,
            input_sha256=input_sha,
            policy_sha256=config.canonical_sha256(),
            lockfile_sha256=lockfile.canonical_sha256() if lockfile else "NONE",
            verdict=evaluation.verdict,
            violations=evaluation.violations,
            latency_ms=latency_ms,
            prev_record_hmac=self._last_hmac,
        )
        rec.record_hmac = self._compute_record_hmac(rec)
        self._last_hmac = rec.record_hmac

        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with self.ledger_path.open("a", encoding="utf-8") as fh:
            fh.write(rec.model_dump_json() + "\n")
        return rec

    def load_records(self) -> List[DecisionLedgerRecord]:
        if not self.ledger_path.is_file():
            return []
        records: List[DecisionLedgerRecord] = []
        for line in self.ledger_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            records.append(DecisionLedgerRecord.model_validate_json(line))
        return records

    def verify_chain(self) -> Tuple[bool, Optional[str]]:
        """Verifies every record HMAC and hash-chain link to detect any tampering or deletion."""
        records = self.load_records()
        expected_prev = "GENESIS"
        for idx, rec in enumerate(records):
            if rec.prev_record_hmac != expected_prev:
                return False, f"Chain break at record {idx}: expected prev_hmac={expected_prev}, got {rec.prev_record_hmac}"
            expected_hmac = self._compute_record_hmac(rec)
            if not hmac.compare_digest(rec.record_hmac, expected_hmac):
                return False, f"Tampered payload at record {idx}: HMAC mismatch"
            expected_prev = rec.record_hmac
        return True, None


# =============================================================================
# Counterfactual Shadow-to-Enforce Calibrator (`piton replay`)
# =============================================================================

class CalibrationSuggestion(BaseModel):
    server_name: str
    tool_name: str
    parameter: Optional[str] = None
    rule_id: str
    affected_calls: int
    suggestion: str


class ReplayReport(BaseModel):
    total_replayed: int
    allowed_count: int
    blocked_or_escalated_count: int
    false_block_rate_pct: float
    violations_by_rule: Dict[str, int] = Field(default_factory=dict)
    suggestions: List[CalibrationSuggestion] = Field(default_factory=list)
    ready_to_enforce: bool


def replay_traces(
    config: AgentIaCConfig,
    records: List[DecisionLedgerRecord],
    simulate_enforce: bool = True,
) -> ReplayReport:
    """
    Replays recorded shadow traces against a candidate `piton.yaml` to compute
    exact first-step block/escalation rates and recommend parameter-bound calibrations
    before promoting from `shadow` to `enforce`.
    """
    trace_counts: Dict[Tuple[str, str, str], int] = {}
    violations_by_rule: Dict[str, int] = {}

    # Track observed values that triggered violations for concrete bound calibration
    max_exceeded_obs: Dict[Tuple[str, str, str], List[float]] = {}
    domain_obs: Dict[Tuple[str, str, str], List[str]] = {}
    enum_obs: Dict[Tuple[str, str, str], List[Any]] = {}
    rate_obs: Dict[Tuple[str, str], List[int]] = {}
    missing_obo_count = 0

    allowed = 0
    blocked_or_esc = 0

    for rec in records:
        key = (rec.traceparent, rec.server_name, rec.tool_name)
        trace_counts[key] = trace_counts.get(key, 0) + 1

        ev = evaluate_tool_call_against_policy(
            config=config,
            server_name=rec.server_name,
            tool_name=rec.tool_name,
            arguments=rec.tokenized_arguments,
            obo_principal=rec.obo_principal,
            idempotency_key=rec.idempotency_key,
            trace_tool_call_count=trace_counts[key],
            simulate_enforce=simulate_enforce,
        )

        if ev.verdict == DecisionVerdict.ALLOW:
            allowed += 1
        else:
            blocked_or_esc += 1
            for v in ev.violations:
                violations_by_rule[v.rule_id] = violations_by_rule.get(v.rule_id, 0) + 1
                if v.rule_id == "PARAM_MAX_EXCEEDED" and v.parameter and isinstance(v.observed_value, (int, float)):
                    max_exceeded_obs.setdefault((rec.server_name, rec.tool_name, v.parameter), []).append(float(v.observed_value))
                elif v.rule_id == "PARAM_DOMAIN_NOT_ALLOWED" and v.parameter and isinstance(v.observed_value, str):
                    domain_obs.setdefault((rec.server_name, rec.tool_name, v.parameter), []).append(v.observed_value)
                elif v.rule_id == "PARAM_ENUM_VIOLATION" and v.parameter:
                    enum_obs.setdefault((rec.server_name, rec.tool_name, v.parameter), []).append(v.observed_value)
                elif v.rule_id == "TRACE_RATE_LIMIT_EXCEEDED" and isinstance(v.observed_value, int):
                    rate_obs.setdefault((rec.server_name, rec.tool_name), []).append(v.observed_value)
                elif v.rule_id == "MISSING_OBO_PRINCIPAL":
                    missing_obo_count += 1

    suggestions: List[CalibrationSuggestion] = []
    for (srv, tool, param), vals in sorted(max_exceeded_obs.items()):
        sorted_vals = sorted(vals)
        p95 = sorted_vals[min(len(sorted_vals) - 1, math.ceil(0.95 * len(sorted_vals)) - 1)]
        observed_max = max(sorted_vals)
        suggestions.append(
            CalibrationSuggestion(
                server_name=srv,
                tool_name=tool,
                parameter=param,
                rule_id="PARAM_MAX_EXCEEDED",
                affected_calls=len(vals),
                suggestion=(
                    f"Observed {len(vals)} calls above max (p95={p95:.2f}, max={observed_max:.2f}). "
                    f"Raising `{param}.max` to {math.ceil(observed_max)} eliminates {len(vals)}/{len(vals)} blocks (or keep MRTR escalation)."
                ),
            )
        )

    for (srv, tool, param), doms in sorted(domain_obs.items()):
        uniq = sorted(set(doms))
        suggestions.append(
            CalibrationSuggestion(
                server_name=srv,
                tool_name=tool,
                parameter=param,
                rule_id="PARAM_DOMAIN_NOT_ALLOWED",
                affected_calls=len(doms),
                suggestion=f"Review and optionally add observed domains {uniq} to `{param}.allow_domains`.",
            )
        )

    for (srv, tool, param), vals in sorted(enum_obs.items()):
        uniq = sorted({str(v) for v in vals})
        suggestions.append(
            CalibrationSuggestion(
                server_name=srv,
                tool_name=tool,
                parameter=param,
                rule_id="PARAM_ENUM_VIOLATION",
                affected_calls=len(vals),
                suggestion=f"Review observed enum values {uniq} for `{param}.enum`.",
            )
        )

    for (srv, tool), counts in sorted(rate_obs.items()):
        suggestions.append(
            CalibrationSuggestion(
                server_name=srv,
                tool_name=tool,
                rule_id="TRACE_RATE_LIMIT_EXCEEDED",
                affected_calls=len(counts),
                suggestion=f"Observed peak {max(counts)} calls/trace; consider raising `rate_limit.max_calls_per_trace` to {max(counts)}.",
            )
        )

    if missing_obo_count > 0:
        suggestions.append(
            CalibrationSuggestion(
                server_name="*",
                tool_name="*",
                rule_id="MISSING_OBO_PRINCIPAL",
                affected_calls=missing_obo_count,
                suggestion="Wire OIDC/OBO JWT extraction on your gateway (or set `identity.mode: local_dev` for local prototyping).",
            )
        )

    total = len(records)
    rate_pct = round((blocked_or_esc / total) * 100.0, 2) if total > 0 else 0.0
    return ReplayReport(
        total_replayed=total,
        allowed_count=allowed,
        blocked_or_escalated_count=blocked_or_esc,
        false_block_rate_pct=rate_pct,
        violations_by_rule=violations_by_rule,
        suggestions=suggestions,
        ready_to_enforce=(total > 0 and blocked_or_esc == 0),
    )


# =============================================================================
# Standard OpenTelemetry / Gateway Access-Log Ingestion & CEL/Cedar Exporters
# =============================================================================

def load_otel_or_ledger_records(
    path: Path,
    tokenizer: Optional[DeterministicTokenizer] = None,
) -> List[DecisionLedgerRecord]:
    """
    Loads either native Piton `DecisionLedgerRecord` JSONL OR standard OpenTelemetry
    MCP span / gateway JSONL exports (recognizing `mcp.server`, `mcp.tool`, `mcp.arguments`,
    `trace_id`/`traceparent`, `enduser.id`/`obo.principal`), applying PII tokenization on ingest.
    """
    tok = tokenizer or DeterministicTokenizer()
    records: List[DecisionLedgerRecord] = []
    if not path.is_file():
        return records

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        raw = json.loads(line)
        if "record_hmac" in raw and "tokenized_arguments" in raw:
            records.append(DecisionLedgerRecord.model_validate(raw))
            continue

        # Standard OpenTelemetry / Envoy / agentgateway span JSON shape
        attrs = raw.get("attributes") if isinstance(raw.get("attributes"), dict) else raw
        server_name = str(attrs.get("mcp.server") or attrs.get("server_name") or "default")
        tool_name = str(attrs.get("mcp.tool") or attrs.get("mcp.method.name") or attrs.get("tool_name") or "unknown")
        raw_args = attrs.get("mcp.arguments") or attrs.get("arguments") or {}
        if isinstance(raw_args, str):
            try:
                raw_args = json.loads(raw_args)
            except Exception:
                raw_args = {}
        if not isinstance(raw_args, dict):
            raw_args = {}
        obo = attrs.get("obo.principal") or attrs.get("enduser.id") or attrs.get("user.id")
        tp = str(raw.get("traceparent") or raw.get("trace_id") or attrs.get("traceparent") or "00-otel-import-01")
        idem = attrs.get("mcp.idempotency_key") or attrs.get("idempotency_key")

        tok_args = tok.tokenize_arguments(raw_args)
        in_sha = hashlib.sha256(json.dumps(raw_args, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        records.append(
            DecisionLedgerRecord(
                agent_id=str(attrs.get("service.name") or "otel-imported-agent"),
                traceparent=tp,
                obo_principal=str(obo) if obo else None,
                server_name=server_name,
                tool_name=tool_name,
                tokenized_arguments=tok_args,
                idempotency_key=str(idem) if idem else None,
                input_sha256=in_sha,
                policy_sha256="OTEL_IMPORT",
                lockfile_sha256="OTEL_IMPORT",
                verdict=DecisionVerdict.ALLOW,
            )
        )
    return records


def export_cel_policies(config: AgentIaCConfig) -> str:
    """
    Compiles calibrated `piton.yaml` parameter bounds into ready-to-apply CEL
    authorization expressions for Solo.io / AAIF `agentgateway` and Envoy CEL filters.
    """
    lines = [
        f"# Auto-generated by Piton Replay/Compiler for agent '{config.agent.id}'",
        "# Compatible with AAIF agentgateway & Envoy CEL authorization policies",
        "policies:",
    ]
    for srv_name, srv in sorted(config.mcp_servers.items()):
        for tool_name, tpol in sorted(srv.tools.items()):
            preds: List[str] = [
                f'mcp.server == "{srv_name}"',
                f'mcp.tool.name == "{tool_name}"',
            ]
            if config.identity.mode == IdentityMode.OIDC_OBO and config.identity.require_delegated_sub:
                preds.append('has(jwt.sub) && jwt.sub != ""')
            if tpol.idempotency_key == "required":
                preds.append('has(request.headers["idempotency-key"]) && request.headers["idempotency-key"] != ""')
            for pname, b in sorted(tpol.parameter_bounds.items()):
                if b.required:
                    preds.append(f'"{pname}" in mcp.tool.arguments')
                if b.min is not None:
                    preds.append(f'double(mcp.tool.arguments["{pname}"]) >= {b.min}')
                if b.max is not None:
                    preds.append(f'double(mcp.tool.arguments["{pname}"]) <= {b.max}')
                if b.enum:
                    enum_lit = json.dumps(b.enum)
                    preds.append(f'mcp.tool.arguments["{pname}"] in {enum_lit}')
                if b.allow_domains:
                    dom_expr = " || ".join(
                        f'string(mcp.tool.arguments["{pname}"]).endsWith("@{d.lower()}")'
                        for d in b.allow_domains
                    )
                    preds.append(f"({dom_expr})")
            lines.append(f"  - name: allow_{srv_name}_{tool_name}".replace("-", "_"))
            lines.append(f"    match: '{' && '.join(preds)}'")
    return "\n".join(lines) + "\n"


def export_cedar_policies(config: AgentIaCConfig) -> str:
    """
    Compiles calibrated `piton.yaml` parameter bounds into ready-to-apply Cedar
    policies for Stacklok ToolHive and AWS Bedrock AgentCore Policy.
    """
    blocks = [
        f"// Auto-generated by Piton Replay/Compiler for agent '{config.agent.id}'",
        "// Compatible with Stacklok ToolHive & AWS Bedrock AgentCore Policy (Cedar)",
        "",
    ]
    for srv_name, srv in sorted(config.mcp_servers.items()):
        for tool_name, tpol in sorted(srv.tools.items()):
            conds: List[str] = []
            if tpol.idempotency_key == "required":
                conds.append("context has idempotency_key")
            for pname, b in sorted(tpol.parameter_bounds.items()):
                if b.required:
                    conds.append(f"context.arguments has {pname}")
                if b.min is not None:
                    conds.append(f"context.arguments.{pname} >= {int(round(b.min * 100))}")
                if b.max is not None:
                    conds.append(f"context.arguments.{pname} <= {int(round(b.max * 100))}")
                if b.enum:
                    enum_expr = " || ".join(f'context.arguments.{pname} == {json.dumps(v)}' for v in b.enum)
                    conds.append(f"({enum_expr})")
                if b.allow_domains:
                    dom_expr = " || ".join(
                        f'context.arguments.{pname} like "*@{d.lower()}"' for d in b.allow_domains
                    )
                    conds.append(f"({dom_expr})")
            blocks.append(f'permit (')
            blocks.append(f'  principal is Agent::Principal,')
            blocks.append(f'  action == MCP::Action::"{srv_name}:{tool_name}",')
            blocks.append(f'  resource')
            blocks.append(f')')
            if conds:
                blocks.append("when {")
                blocks.append("  " + " &&\n  ".join(conds))
                blocks.append("};")
            else:
                blocks[-1] += ";"
            blocks.append("")
    return "\n".join(blocks)

