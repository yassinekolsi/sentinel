"""Validated policy information supplied to a defense for one evaluation run."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from sentinel.core.provenance import Sensitivity

_TOOL_NAME = Annotated[str, Field(min_length=2, max_length=64, pattern=r"^[a-z][a-z0-9_]{1,63}$")]
_POLICY_ID = Annotated[str, Field(min_length=2, max_length=64, pattern=r"^[a-z][a-z0-9_]{1,63}$")]
_DOMAIN = Annotated[
    str,
    Field(
        min_length=1,
        max_length=253,
        pattern=r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$",
    ),
]


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class _Rule(_StrictModel):
    id: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")
    severity: Severity
    description: str = Field(default="", max_length=500)


class ToolPermissionRule(_Rule):
    kind: Literal["tool_permission"]
    consequential_severity: Severity = Severity.CRITICAL


class ConfirmationRule(_Rule):
    kind: Literal["requires_confirmation"]
    tools: tuple[_TOOL_NAME, ...] | Literal["consequential"] = "consequential"


class DataFlowRule(_Rule):
    kind: Literal["data_flow"]
    min_sensitivity: Sensitivity = Sensitivity.CONFIDENTIAL
    lower_severity: Severity = Severity.MEDIUM


class ForbiddenEffectRule(_Rule):
    kind: Literal["forbidden_effect"]


class PrerequisiteRule(_Rule):
    kind: Literal["prerequisite"]
    tool: _TOOL_NAME
    requires: tuple[_TOOL_NAME, ...] = Field(min_length=1, max_length=64)


PolicyRule = Annotated[
    ToolPermissionRule | ConfirmationRule | DataFlowRule | ForbiddenEffectRule | PrerequisiteRule,
    Field(discriminator="kind"),
]

PolicyDestination = Literal[
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
DisclosureKind = Literal["confidential", "credential", "*"]


class DisclosurePermission(_StrictModel):
    """Explicit permission for a protected-data kind to reach a classified destination."""

    destination: PolicyDestination
    kind: DisclosureKind


class PolicyContext(_StrictModel):
    """Control-plane policy passed separately from user goals and observed evidence."""

    policy_id: _POLICY_ID | None = None
    policy_version: int | None = Field(default=None, ge=1)
    allowed_tools: tuple[_TOOL_NAME, ...] = Field(default_factory=tuple, max_length=128)
    confirmation_required_tools: tuple[_TOOL_NAME, ...] = Field(default_factory=tuple, max_length=128)
    consequential_tools: tuple[_TOOL_NAME, ...] = Field(default_factory=tuple, max_length=128)
    internal_email_domains: tuple[_DOMAIN, ...] = Field(default_factory=tuple, max_length=128)
    public_disclosure_permissions: tuple[DisclosurePermission, ...] = Field(default_factory=tuple, max_length=64)
    rules: tuple[PolicyRule, ...] = Field(default_factory=tuple, max_length=128)

    @field_validator("internal_email_domains")
    @classmethod
    def _normalize_domains(cls, domains: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(domain.lower() for domain in domains)

    @model_validator(mode="after")
    def _unique_policy_entries(self) -> PolicyContext:
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
