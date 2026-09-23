"""The defense contract. Participants implement ``Defense.decide`` in-process or over HTTP."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Annotated, Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from sentinel.core.actions import CandidateAction, DefenseDecision
from sentinel.core.provenance import Provenance

MAX_DEFENSE_REQUEST_BYTES = 256 * 1024
MAX_CONVERSATION_ITEMS = 100
MAX_PROVENANCE_RECORDS = 256

_Identifier = Annotated[str, Field(min_length=1, max_length=128)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ProvenanceRecord(_Strict):
    id: _Identifier
    provenance: Provenance


class ConversationItem(_Strict):
    role: str = Field(pattern=r"^(user|agent|tool|memory|safety|human)$")
    kind: str = Field(min_length=1, max_length=64)
    content: str = Field(max_length=20_000)
    provenance_ids: list[_Identifier] = Field(default_factory=list, max_length=256)


class ObservationView(_Strict):
    kind: str = Field(min_length=1, max_length=64)
    content: str = Field(max_length=20_000)
    provenance_ids: list[_Identifier] = Field(default_factory=list, max_length=256)


class ToolCallSummary(_Strict):
    step_id: int = Field(ge=0, le=1_000)
    tool: str = Field(min_length=1, max_length=64)
    decision: str = Field(min_length=1, max_length=32)
    succeeded: bool | None = None


class HistoryDigest(_Strict):
    steps_taken: int = Field(default=0, ge=0, le=1_000)
    turn_index: int = Field(default=0, ge=0, le=1_000)
    tool_calls: list[ToolCallSummary] = Field(default_factory=list, max_length=200)
    confirmations_granted: list[Annotated[str, Field(max_length=128)]] = Field(default_factory=list, max_length=200)
    blocked_count: int = Field(default=0, ge=0, le=1_000)
    escalated_count: int = Field(default=0, ge=0, le=1_000)
    least_trusted_seen: str | None = Field(default=None, max_length=64)
    most_sensitive_seen: str | None = Field(default=None, max_length=64)


class DefenseRequest(_Strict):
    """Everything a defense may see. Never contains reference plans, labels, or attack payloads."""

    run_id: _Identifier
    # A fresh opaque lifecycle identity. Older clients may omit it; the firewall
    # then falls back to run_id for backward-compatible request parsing.
    execution_id: _Identifier | None = None
    step_id: int = Field(ge=0, le=1_000)
    user_goal: str = Field(max_length=20_000)
    conversation: list[ConversationItem] = Field(default_factory=list, max_length=MAX_CONVERSATION_ITEMS)
    observation: ObservationView | None = None
    candidate_action: CandidateAction
    policy_context: dict[str, Any] = Field(default_factory=dict)
    provenance: list[ProvenanceRecord] = Field(default_factory=list, max_length=MAX_PROVENANCE_RECORDS)
    history_digest: HistoryDigest = Field(default_factory=HistoryDigest)

    @field_validator("policy_context")
    @classmethod
    def _bounded_policy_context(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > 128:
            raise ValueError("policy_context contains more than 128 top-level entries")
        if any(not key or len(key) > 128 for key in value):
            raise ValueError("policy_context keys must be 1 to 128 characters")
        return value

    @model_validator(mode="after")
    def _bounded_serialized_request(self) -> Self:
        try:
            size = len(self.model_dump_json().encode("utf-8"))
        except Exception as exc:
            raise ValueError("defense request must be JSON serializable") from exc
        if size > MAX_DEFENSE_REQUEST_BYTES:
            raise ValueError(f"defense request exceeds {MAX_DEFENSE_REQUEST_BYTES} bytes")
        return self


class Defense(ABC):
    name: str = "defense"

    @abstractmethod
    def decide(self, request: DefenseRequest) -> DefenseDecision: ...

    def close(self) -> None:
        """Release resources (HTTP clients, models)."""
        return None

    def end_execution(self, execution_id: str) -> None:
        """Release state for a completed execution, if this defense keeps per-run state."""
        return None
