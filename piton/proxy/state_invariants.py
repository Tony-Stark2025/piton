"""
State Invariant & Lineage Gate.
Verifies tool invocation sequences against causal dependency graphs,
enforces read-before-write invariants, and verifies pre-state witness hashes H(S).
"""

import re
import threading
import time
from typing import Any, Dict, List, Optional, Set
import structlog

from piton.pentest.route_graph import OpenAPIRouteGraph
from piton.proxy.models import (
    ActionPermit,
    CapabilityToken,
    DenialCode,
    PreStateWitness,
    SemanticDenialEnvelope,
)
from piton.proxy.denial_envelope import DenialEnvelopeFactory
from piton.proxy.token_authority import TokenAuthority

logger = structlog.get_logger(__name__)


class StateWitnessRegistry:
    """
    Thread-safe, tenant-isolated registry of canonical live states and pre-state witness hashes.
    """

    MAX_ENTRIES = 10_000

    def __init__(self, token_authority: Optional[TokenAuthority] = None):
        self._lock = threading.RLock()
        self._states: Dict[str, Any] = {}
        self._witnesses: Dict[str, PreStateWitness] = {}
        self._consumed_permits: Set[str] = set()
        self._token_authority = token_authority or TokenAuthority()

    @staticmethod
    def _scope_key(resource_id: str, tenant_id: Optional[str] = None) -> str:
        if tenant_id:
            return f"{tenant_id}::{resource_id}"
        return resource_id

    def _evict_if_needed(self) -> None:
        if len(self._states) >= self.MAX_ENTRIES:
            oldest = next(iter(self._states))
            self._states.pop(oldest, None)
            self._witnesses.pop(oldest, None)
        if len(self._consumed_permits) >= self.MAX_ENTRIES * 2:
            # Prune half of oldest set entries to keep memory bounded
            to_drop = list(self._consumed_permits)[: self.MAX_ENTRIES]
            for pid in to_drop:
                self._consumed_permits.discard(pid)

    def try_consume_permit(self, permit_id: str) -> bool:
        """
        Atomically checks and consumes a single-use ActionPermit BEFORE downstream dispatch.
        Returns True if this caller won the atomic reservation, False if already consumed (replay).
        """
        with self._lock:
            if permit_id in self._consumed_permits:
                return False
            self._evict_if_needed()
            self._consumed_permits.add(permit_id)
            return True

    def mark_permit_consumed(self, permit_id: str) -> None:
        with self._lock:
            self._evict_if_needed()
            self._consumed_permits.add(permit_id)

    def is_permit_consumed(self, permit_id: str) -> bool:
        with self._lock:
            return permit_id in self._consumed_permits

    def register_state(
        self,
        resource_id: str,
        state_data: Any,
        source_op: str = "seed",
        tenant_id: Optional[str] = None,
    ) -> PreStateWitness:
        key = self._scope_key(resource_id, tenant_id)
        with self._lock:
            self._evict_if_needed()
            self._states[key] = state_data
            witness = self._token_authority.create_pre_state_witness(
                resource_id=resource_id,
                state_data=state_data,
                source_op=source_op,
            )
            self._witnesses[key] = witness
            return witness

    def get_state(self, resource_id: str, tenant_id: Optional[str] = None) -> Optional[Any]:
        key = self._scope_key(resource_id, tenant_id)
        with self._lock:
            return self._states.get(key)

    def get_state_hash(self, resource_id: str, tenant_id: Optional[str] = None) -> Optional[str]:
        key = self._scope_key(resource_id, tenant_id)
        with self._lock:
            if key not in self._states:
                return None
            return self._token_authority.compute_state_hash(self._states[key])

    def get_witness(self, resource_id: str, tenant_id: Optional[str] = None) -> Optional[PreStateWitness]:
        key = self._scope_key(resource_id, tenant_id)
        with self._lock:
            return self._witnesses.get(key)

    def update_state(
        self,
        resource_id: str,
        new_state_data: Any,
        source_op: str = "update",
        tenant_id: Optional[str] = None,
    ) -> PreStateWitness:
        key = self._scope_key(resource_id, tenant_id)
        with self._lock:
            self._evict_if_needed()
            self._states[key] = new_state_data
            witness = self._token_authority.create_pre_state_witness(
                resource_id=resource_id,
                state_data=new_state_data,
                source_op=source_op,
            )
            self._witnesses[key] = witness
            return witness

    def delete_state(self, resource_id: str, tenant_id: Optional[str] = None) -> None:
        key = self._scope_key(resource_id, tenant_id)
        with self._lock:
            self._states.pop(key, None)
            self._witnesses.pop(key, None)

    def has_resource(self, resource_id: str, tenant_id: Optional[str] = None) -> bool:
        key = self._scope_key(resource_id, tenant_id)
        with self._lock:
            return key in self._states

    def list_known_resources(self, tenant_id: Optional[str] = None) -> List[str]:
        with self._lock:
            if tenant_id:
                prefix = f"{tenant_id}::"
                return [k[len(prefix):] for k in self._states.keys() if k.startswith(prefix)]
            return [k for k in self._states.keys() if "::" not in k]


class CausalLineageTracker:
    """
    Tracks causal lineages of read operations witnessed during an execution session.
    """

    def __init__(self):
        self._lock = threading.RLock()
        # session_id -> {scoped_resource_key -> PreStateWitness}
        self._session_witnesses: Dict[str, Dict[str, PreStateWitness]] = {}
        # session_id -> list of executed op signatures e.g. ["GET /api/v1/items/1"]
        self._session_history: Dict[str, List[str]] = {}

    def record_read(
        self,
        session_id: str,
        resource_id: str,
        witness: PreStateWitness,
        op_name: str,
        tenant_id: Optional[str] = None,
    ) -> None:
        key = StateWitnessRegistry._scope_key(resource_id, tenant_id)
        with self._lock:
            if session_id not in self._session_witnesses:
                self._session_witnesses[session_id] = {}
                self._session_history[session_id] = []
            self._session_witnesses[session_id][key] = witness
            self._session_history[session_id].append(op_name)

    def has_read_witness(
        self,
        session_id: str,
        resource_id: str,
        tenant_id: Optional[str] = None,
    ) -> bool:
        key = StateWitnessRegistry._scope_key(resource_id, tenant_id)
        with self._lock:
            return (
                session_id in self._session_witnesses
                and key in self._session_witnesses[session_id]
            )

    def get_witness(
        self,
        session_id: str,
        resource_id: str,
        tenant_id: Optional[str] = None,
    ) -> Optional[PreStateWitness]:
        key = StateWitnessRegistry._scope_key(resource_id, tenant_id)
        with self._lock:
            return self._session_witnesses.get(session_id, {}).get(key)

    def get_history(self, session_id: str) -> List[str]:
        with self._lock:
            return list(self._session_history.get(session_id, []))


class StateInvariantGate:
    """
    Gatekeeper that enforces causal invariants and pre-state witness alignment.
    Rejects unverified or out-of-order mutations before they reach backend tools.
    """

    MUTATING_HTTP_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
    MUTATING_MCP_TOOLS = {
        "approve_action", "reject_action", "dispatch_action", "delete_draft",
        "transfer", "send", "revoke", "grant", "write", "set", "drop", "insert", "mutate",
        "wipe_db", "purge_users", "run_sql", "eval_python", "post_webhook",
    }
    MUTATING_TOOL_PREFIXES = (
        "create_", "update_", "delete_", "approve_", "reject_",
        "modify_", "apply_", "execute_", "remove_", "cancel_", "dispatch_", "patch_",
        "transfer_", "send_", "revoke_", "grant_", "write_", "set_", "drop_", "insert_", "mutate_",
        "wipe_", "purge_", "run_", "post_",
    )

    @staticmethod
    def extract_resource_id_from_body_or_query(
        target: str, payload: Optional[Any] = None
    ) -> Optional[str]:
        """Extracts resource ID candidate from target query parameters or request body."""
        if "?" in target:
            from urllib.parse import parse_qs
            query_str = target.split("?", 1)[1]
            params = parse_qs(query_str)
            for k in ("resource_id", "id", "draft_id", "item_id", "target_id", "invoice_id", "workspace_id", "user_id"):
                if k in params and params[k]:
                    return str(params[k][0])
            for k, v in params.items():
                if k.endswith("_id") and v:
                    return str(v[0])
        if isinstance(payload, dict):
            candidate_dicts = [payload]
            for sub_key in ("args", "params", "body", "data", "input"):
                if isinstance(payload.get(sub_key), dict):
                    candidate_dicts.append(payload[sub_key])
            for d in candidate_dicts:
                for k in ("resource_id", "id", "draft_id", "item_id", "target_id", "invoice_id", "workspace_id", "user_id"):
                    if k in d and d[k] is not None:
                        return str(d[k])
                for k, v in d.items():
                    if k.endswith("_id") and isinstance(v, (str, int)):
                        return str(v)
        return None

    def __init__(
        self,
        token_authority: TokenAuthority,
        registry: Optional[StateWitnessRegistry] = None,
        route_graph: Optional[OpenAPIRouteGraph] = None,
    ):
        self.token_authority = token_authority
        self.registry = registry or StateWitnessRegistry(token_authority)
        self.lineage_tracker = CausalLineageTracker()
        self.route_graph = route_graph

    def is_mutation(self, method: str, target: str) -> bool:
        """Determines if the operation is a stateful mutation."""
        method_up = method.upper()
        if method_up in self.MUTATING_HTTP_METHODS:
            return True
        target_low = target.lower()
        if target_low in self.MUTATING_MCP_TOOLS or any(
            target_low.startswith(prefix) for prefix in self.MUTATING_TOOL_PREFIXES
        ):
            return True
        method_low = method.lower()
        if method_low in self.MUTATING_MCP_TOOLS or any(
            method_low.startswith(prefix) for prefix in self.MUTATING_TOOL_PREFIXES
        ):
            return True
        return False

    def try_consume_permit(self, permit_id: str) -> bool:
        return self.registry.try_consume_permit(permit_id)

    def mark_permit_consumed(self, permit_id: str) -> None:
        self.registry.mark_permit_consumed(permit_id)

    def is_permit_consumed(self, permit_id: str) -> bool:
        return self.registry.is_permit_consumed(permit_id)

    def _check_route_graph_prerequisites(
        self,
        session_id: str,
        method: str,
        target: str,
    ) -> Optional[SemanticDenialEnvelope]:
        if not self.route_graph:
            return None

        clean_target = target.split("?")[0]
        matching_op = None
        for op_id, op in self.route_graph.operations.items():
            if op.method.value.upper() != method.upper():
                continue
            pattern = "^" + re.sub(r"\{[a-zA-Z0-9_-]+\}", r"([^/]+)", op.path) + "$"
            if re.match(pattern, clean_target):
                matching_op = op
                break

        if not matching_op:
            return None

        prereq_op_ids: Set[str] = set()
        for src_id, dependents in self.route_graph.adj_list.items():
            if matching_op.op_id in dependents:
                prereq_op_ids.add(src_id)

        if not prereq_op_ids:
            return None

        history = self.lineage_tracker.get_history(session_id)
        missing_prereqs = []
        for prereq_id in prereq_op_ids:
            prereq_op = self.route_graph.operations.get(prereq_id)
            if not prereq_op:
                continue
            satisfied = any(
                prereq_op.path in h or f"{prereq_op.method.value} {prereq_op.path}" in h
                for h in history
            )
            if not satisfied:
                missing_prereqs.append(f"{prereq_op.method.value} {prereq_op.path}")

        if missing_prereqs:
            logger.warn(
                "hypervisor_route_graph_prerequisite_missing",
                session_id=session_id,
                target=target,
                missing=missing_prereqs,
            )
            return DenialEnvelopeFactory.causal_lineage_violation(
                resource_id=matching_op.op_id,
                target_op=f"{method} {target}",
                prerequisite_reads=missing_prereqs,
            )

        return None

    def verify_execution_gate(
        self,
        session_id: str,
        method: str,
        target: str,
        resource_id: Optional[str],
        permit: Optional[ActionPermit],
        token: CapabilityToken,
        payload: Optional[Any] = None,
        tenant_id: Optional[str] = None,
    ) -> Optional[SemanticDenialEnvelope]:
        """
        Evaluates causal dependency, hallucination checks, and pre-state drift.
        Returns None if permitted, or a structured SemanticDenialEnvelope if denied.
        """
        effective_tenant = tenant_id or token.scope.tenant_id

        clean_target = target.split("?")[0].rstrip("/").lower()
        is_create = (
            method.upper() == "POST"
            and not any(act in clean_target for act in (
                "approve", "reject", "cancel", "submit", "publish", "archive",
                "lock", "mutate", "transfer", "revoke", "grant", "execute", "apply", "delete", "update", "modify"
            ))
        )

        # Resolve resource ID from query or payload if not passed explicitly
        if resource_id is None:
            if not is_create:
                resource_id = self.extract_resource_id_from_body_or_query(target, payload)
            elif "?" in target:
                resource_id = self.extract_resource_id_from_body_or_query(target, None)

        # Safe read operations do not require prior lineage or permits
        if not self.is_mutation(method, target):
            return None

        # Replay prevention: One-time permits cannot be reused
        if permit is not None and self.is_permit_consumed(permit.permit_id):
            logger.warn("hypervisor_permit_replay_detected", permit_id=permit.permit_id)
            return SemanticDenialEnvelope(
                denied=True,
                denial_code=DenialCode.PERMIT_TAMPERED,
                violated_invariant="PermitAlreadyConsumed: ActionPermit is single-use and has already been redeemed.",
                details=f"Permit '{permit.permit_id}' cannot be replayed for subsequent mutations.",
                permitted_alternate_paths=[f"inspect_{resource_id or permit.resource_id}"],
                suggested_recovery_step=f"Re-inspect resource '{resource_id or permit.resource_id}' to produce a fresh pre-state witness and request a new ActionPermit.",
                timestamp=time.time(),
            )

        # Route graph causal prerequisite verification
        route_denial = self._check_route_graph_prerequisites(session_id, method, target)
        if route_denial is not None:
            return route_denial

        # Fail closed on non-create mutations with unresolved resource_id
        if resource_id is None and not is_create:
            logger.warn("hypervisor_unresolved_mutating_resource", method=method, target=target)
            return DenialEnvelopeFactory.missing_action_permit(
                action_method=method,
                resource_id=target,
            )

        # If operation targets a specific resource
        if resource_id is not None:
            # 1. Hallucination Gate: Check if resource actually exists in backend (tenant-scoped)
            # Never leak resource IDs from other tenants in valid_candidates!
            if not self.registry.has_resource(resource_id, tenant_id=effective_tenant):
                logger.warn("hypervisor_hallucinated_resource", resource_id=resource_id, tenant_id=effective_tenant)
                return DenialEnvelopeFactory.hallucinated_resource_id(
                    resource_id=resource_id,
                    valid_candidates=[],
                )

            # 2. Causal Lineage Gate: Verify prior read / inspection occurred in this session
            if not self.lineage_tracker.has_read_witness(session_id, resource_id, tenant_id=effective_tenant):
                logger.warn("hypervisor_lineage_violation", session_id=session_id, resource_id=resource_id, target=target)
                prereq_paths = [
                    f"GET {target.rsplit('/', 1)[0]}/{resource_id}" if "/" in target else f"inspect_{resource_id}",
                    "list_pending_actions" if "action" in target else "list_resources",
                ]
                return DenialEnvelopeFactory.causal_lineage_violation(
                    resource_id=resource_id,
                    target_op=f"{method} {target}",
                    prerequisite_reads=prereq_paths,
                )

            # 3. Action Permit Gate: Destructive mutations must bundle a valid permit
            if permit is None:
                logger.warn("hypervisor_missing_permit", resource_id=resource_id, method=method, target=target)
                return DenialEnvelopeFactory.missing_action_permit(
                    action_method=method,
                    resource_id=resource_id,
                )

            # 4. Pre-State Drift Verification: Ensure permit pre-state witness matches current state
            current_state_hash = self.registry.get_state_hash(resource_id, tenant_id=effective_tenant)
            permit_denial = self.token_authority.verify_action_permit(
                permit=permit,
                token=token,
                current_state_hash=current_state_hash,
                expected_method=method,
                expected_resource_id=resource_id,
            )
            if permit_denial is not None:
                logger.warn("hypervisor_permit_verification_failed", denial=permit_denial.denial_code, resource_id=resource_id)
                return permit_denial

        return None
