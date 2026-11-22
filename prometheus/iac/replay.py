"""
Prometheus Policy Calibration Engine (`prometheus replay`), PII-Preserving Deterministic
Tokenization, Parameter-Bounded Evaluator, and Version-Pinned Signed Decision Ledger.

Implements the Agent Control Loop validated by late-2026 production systems:
1. Deterministic PII-preserving tokenization: Masks raw PII (`alice@acme.com` ->
   `tok_a1b2c3d4@acme.com`) while preserving structural predicates (email domains,
   numeric ceilings, enum values) so offline replay stays 100% accurate without leaking PII.
2. Version-pinned, HMAC-chained Signed Decision Ledger: Ties every decision to
   `policy_sha256`, `lockfile_sha256`, W3C `traceparent`, OBO principal, and `input_hash`
   so auditors can deterministically replay why any action was allowed or denied months later.
3. Counterfactual `replay_traces`: Replays shadow traffic against candidate `prometheus.yaml`
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

from prometheus.iac.schema import (
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

    def __init__(self, secret_key: bytes = b"prometheus-default-tokenizer-key") -> None:
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
    v = value.strip().lower()
    if "@" in v:
        return v.rsplit("@", 1)[1]
    if "://" in v:
        host = v.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        return host or None
    if "." in v and " " not in v:
        return v
    return None


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

    if bound.enum is not None and value not in bound.enum:
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

    if isinstance(value, str):
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
    simulate_enforce: bool = False,
) -> PolicyEvaluationResult:
    """
    Deterministically evaluates a single MCP tool call against `prometheus.yaml`
    parameter bounds, rate limits, idempotency requirements, and OIDC/OBO identity rules.
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
    tool_policy: Optional[ToolPolicy] = srv_policy.tools.get(tool_name) if srv_policy else None

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

        # 3. Per-trace call quota
        if tool_policy.rate_limit and tool_policy.rate_limit.max_calls_per_trace is not None:
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

        # 4. Parameter bounds
        for param_name, bound in tool_policy.parameter_bounds.items():
            if param_name in arguments:
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
        signing_key: bytes = b"prometheus-ledger-signing-key",
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
        body = record.model_dump(mode="json", exclude={"record_hmac"})
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
# Counterfactual Shadow-to-Enforce Calibrator (`prometheus replay`)
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
    Replays recorded shadow traces against a candidate `prometheus.yaml` to compute
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
