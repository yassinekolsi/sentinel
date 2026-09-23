"""Self-contained copies of the SENTINEL v1 defense API schemas.

The request *envelope* ignores unknown fields, so your service keeps working when organizers add
context around the action. The action shape itself and every response field are strict, exactly as
strict as ``sentinel.core.actions``: the evaluator rejects anything that does not match, and a
rejected response is treated as an unavailable defense — which fails closed and blocks every tool
call for the rest of the run. Keep the constraints below in sync with the simulator.
"""

from __future__ import annotations

import json
import re
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_METADATA_BYTES = 4_096
REASON_CODE_PATTERN = r"^[A-Z][A-Z0-9_]{1,63}$"


class _Lenient(BaseModel):
    model_config = ConfigDict(extra="ignore")


_ToolName = Annotated[str, Field(min_length=2, max_length=64, pattern=r"^[a-z][a-z0-9_]{1,63}$")]
_Domain = Annotated[
    str,
    Field(
        min_length=1,
        max_length=253,
        pattern=r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$",
    ),
]


class _PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")
    severity: Literal["low", "medium", "high", "critical"]
    description: str = Field(default="", max_length=500)


class ToolPermissionRule(_PolicyRule):
    kind: Literal["tool_permission"]
    consequential_severity: Literal["low", "medium", "high", "critical"] = "critical"


class ConfirmationRule(_PolicyRule):
    kind: Literal["requires_confirmation"]
    tools: tuple[_ToolName, ...] | Literal["consequential"] = "consequential"


class DataFlowRule(_PolicyRule):
    kind: Literal["data_flow"]
    min_sensitivity: Literal["public", "internal", "confidential", "restricted"] = "confidential"
    lower_severity: Literal["low", "medium", "high", "critical"] = "medium"


class ForbiddenEffectRule(_PolicyRule):
    kind: Literal["forbidden_effect"]


class PrerequisiteRule(_PolicyRule):
    kind: Literal["prerequisite"]
    tool: _ToolName
    requires: tuple[_ToolName, ...] = Field(min_length=1, max_length=64)


PolicyRule = Annotated[
    ToolPermissionRule | ConfirmationRule | DataFlowRule | ForbiddenEffectRule | PrerequisiteRule,
    Field(discriminator="kind"),
]


class DisclosurePermission(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    destination: Literal[
        "external_email",
        "internal_email",
        "user_response",
        "memory",
        "internal_note",
        "unknown_write",
        "read",
        "unknown",
        "*",
    ]
    kind: Literal["confidential", "credential", "*"]


class PolicyContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    policy_id: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{1,63}$")
    policy_version: int | None = Field(default=None, ge=1)
    allowed_tools: tuple[_ToolName, ...] = Field(default_factory=tuple, max_length=128)
    confirmation_required_tools: tuple[_ToolName, ...] = Field(default_factory=tuple, max_length=128)
    consequential_tools: tuple[_ToolName, ...] = Field(default_factory=tuple, max_length=128)
    internal_email_domains: tuple[_Domain, ...] = Field(default_factory=tuple, max_length=128)
    public_disclosure_permissions: tuple[DisclosurePermission, ...] = Field(default_factory=tuple, max_length=64)
    rules: tuple[PolicyRule, ...] = Field(default_factory=tuple, max_length=128)

    @field_validator("internal_email_domains")
    @classmethod
    def _normalize_domains(cls, domains: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(domain.lower() for domain in domains)

    @model_validator(mode="after")
    def _unique_entries(self) -> PolicyContext:
        for field_name in (
            "allowed_tools",
            "confirmation_required_tools",
            "consequential_tools",
            "internal_email_domains",
        ):
            values = getattr(self, field_name)
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} contains duplicates")
        permission_pairs = [(item.destination, item.kind) for item in self.public_disclosure_permissions]
        if len(permission_pairs) != len(set(permission_pairs)):
            raise ValueError("public_disclosure_permissions contains duplicates")
        rule_ids = [rule.id for rule in self.rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("rules contains duplicate ids")
        return self


class CandidateAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["respond", "tool_call", "memory_write", "request_confirmation"]
    tool: str | None = None
    arguments: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    content: str | None = None
    final: bool = False
    confirmation_for: CandidateAction | None = None


class Provenance(_Lenient):
    source_type: str
    source_id: str
    trust_level: Literal[
        "system_policy",
        "authenticated_user",
        "trusted_internal",
        "untrusted_internal",
        "untrusted_external",
        "adversary_controlled",
    ]
    origin_actor: str
    retrieved_via: str
    sensitivity: Literal["public", "internal", "confidential", "restricted"] = "internal"


class ProvenanceRecord(_Lenient):
    id: str
    provenance: Provenance


class ConversationItem(_Lenient):
    role: str
    kind: str
    content: str
    provenance_ids: list[str] = Field(default_factory=list)


class ObservationView(_Lenient):
    kind: str
    content: str
    provenance_ids: list[str] = Field(default_factory=list)


class HistoryDigest(_Lenient):
    steps_taken: int = 0
    turn_index: int = 0
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    confirmations_granted: list[str] = Field(default_factory=list)
    blocked_count: int = 0
    escalated_count: int = 0
    least_trusted_seen: str | None = None
    most_sensitive_seen: str | None = None


class DefenseRequest(_Lenient):
    run_id: str
    step_id: int
    user_goal: str
    conversation: list[ConversationItem] = Field(default_factory=list)
    observation: ObservationView | None = None
    candidate_action: CandidateAction
    policy_context: PolicyContext = Field(default_factory=PolicyContext)
    provenance: list[ProvenanceRecord] = Field(default_factory=list)
    history_digest: HistoryDigest = Field(default_factory=HistoryDigest)


class DefenseDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["allow", "block", "escalate", "rewrite"]
    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    reason_codes: list[str] = Field(default_factory=list, max_length=16)
    explanation: str | None = Field(default=None, max_length=500)
    rewritten_action: CandidateAction | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("reason_codes")
    @classmethod
    def _valid_codes(cls, codes: list[str]) -> list[str]:
        for code in codes:
            if not re.fullmatch(REASON_CODE_PATTERN, code):
                raise ValueError(f"invalid reason code {code!r}; use UPPER_SNAKE_CASE")
        return codes

    @field_validator("metadata")
    @classmethod
    def _bounded_metadata(cls, metadata: dict[str, Any]) -> dict[str, Any]:
        try:
            size = len(json.dumps(metadata))
        except (TypeError, ValueError) as exc:
            raise ValueError("metadata must be JSON-serializable") from exc
        if size > MAX_METADATA_BYTES:
            raise ValueError(f"metadata exceeds {MAX_METADATA_BYTES} bytes")
        return metadata

    @model_validator(mode="after")
    def _rewrite_needs_action(self) -> DefenseDecision:
        if (self.decision == "rewrite") != (self.rewritten_action is not None):
            raise ValueError("rewritten_action is required for, and only for, decision 'rewrite'")
        return self
