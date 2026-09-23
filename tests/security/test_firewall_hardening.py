"""Regression coverage for the frozen model-independent hardening suite."""

from __future__ import annotations

import base64

import pytest

from sentinel.core.actions import ActionType, CandidateAction, Decision
from sentinel.firewall.engine import Firewall
from sentinel.firewall.state import SecurityState, SensitiveValue
from tests.security.firewall_hardening_cases import (
    FROZEN_SUITE_IDENTITY_SHA256,
    cases,
    suite_identity,
)
from tests.security.firewall_hardening_harness import build_request, decide, safe_attack_outcome

pytestmark = pytest.mark.security


@pytest.mark.parametrize("case", cases(), ids=lambda case: case.case_id)
def test_frozen_firewall_boundary_cases(case) -> None:  # type: ignore[no-untyped-def]
    result = decide(case)
    assert result.decision.value == case.expected
    if case.outcome == "attack":
        assert safe_attack_outcome(case, result)
    else:
        assert result.decision is Decision.ALLOW


def test_case_suite_identity_is_frozen() -> None:
    assert suite_identity() == FROZEN_SUITE_IDENTITY_SHA256


def test_decoder_budget_exhaustion_blocks_a_sensitive_external_action() -> None:
    case = next(item for item in cases() if item.case_id == "cred-exact")
    request = build_request(case)
    payload = " ".join(base64.b64encode(f"safe-record-{index:03d}".encode()).decode() for index in range(129))
    action = CandidateAction(
        type=ActionType.TOOL_CALL,
        tool="email_draft",
        arguments={"to": "ops@vendor.example", "subject": "Update", "body": payload},
    )
    decision = Firewall().decide(request.model_copy(update={"candidate_action": action}))
    assert decision.decision is Decision.BLOCK
    assert decision.reason_codes == ["ANALYSIS_CAPACITY_EXCEEDED"]


def test_compact_credential_matching_keeps_case_sensitive_near_match_allowed() -> None:
    state = SecurityState(sensitive={"credential": SensitiveValue("SecretValue-9123", credential=True)})
    assert state.leaks("secretvalue-9123", external=True) == []
