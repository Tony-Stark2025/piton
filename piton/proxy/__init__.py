"""
Piton Capability Hypervisor & Stateful Execution Firewall.
Provides inline capability attenuation, state invariant verification,
pre-state witness gates H(S), and semantic denial envelopes.
"""

from piton.proxy.models import (
    ActionPermit,
    CapabilityToken,
    DenialCode,
    PreStateWitness,
    ProxyToolRequest,
    ProxyToolResponse,
    ScopeBoundary,
    SemanticDenialEnvelope,
    ToolCallType,
)
from piton.proxy.token_authority import (
    AttenuationViolationError,
    TokenAuthority,
)
from piton.proxy.state_invariants import (
    CausalLineageTracker,
    StateInvariantGate,
    StateWitnessRegistry,
)
from piton.proxy.denial_envelope import DenialEnvelopeFactory
from piton.proxy.hypervisor import ToolExecutionHypervisor

__all__ = [
    "ActionPermit",
    "AttenuationViolationError",
    "CapabilityToken",
    "CausalLineageTracker",
    "DenialCode",
    "DenialEnvelopeFactory",
    "PreStateWitness",
    "ProxyToolRequest",
    "ProxyToolResponse",
    "ScopeBoundary",
    "SemanticDenialEnvelope",
    "StateInvariantGate",
    "StateWitnessRegistry",
    "TokenAuthority",
    "ToolCallType",
    "ToolExecutionHypervisor",
]
