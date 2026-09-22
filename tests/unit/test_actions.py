import pytest
from pydantic import ValidationError

from sentinel.core.actions import ActionType, CandidateAction, Decision, DefenseDecision
from tests.conftest import tool_call


def test_tool_call_requires_tool() -> None:
    with pytest.raises(ValidationError, match="require 'tool'"):
        CandidateAction(type=ActionType.TOOL_CALL)


def test_respond_requires_content_and_no_arguments() -> None:
    with pytest.raises(ValidationError):
        CandidateAction(type=ActionType.RESPOND)
    with pytest.raises(ValidationError):
        CandidateAction(type=ActionType.RESPOND, content="x", arguments={"a": 1})


def test_request_confirmation_needs_tool_call_target() -> None:
    with pytest.raises(ValidationError):
        CandidateAction(type=ActionType.REQUEST_CONFIRMATION, content="?")
    ok = CandidateAction(type=ActionType.REQUEST_CONFIRMATION, confirmation_for=tool_call("email_send", to="a"))
    assert ok.confirmation_for is not None


def test_only_respond_can_be_final() -> None:
    with pytest.raises(ValidationError, match="final"):
        CandidateAction(type=ActionType.MEMORY_WRITE, content="x", final=True)


def test_argument_bounds() -> None:
    with pytest.raises(ValidationError):
        tool_call("email_read", **{f"a{i}": i for i in range(40)})
    with pytest.raises(ValidationError):
        tool_call("email_read", body="x" * 9_000)
    with pytest.raises(ValidationError):
        CandidateAction(type=ActionType.TOOL_CALL, tool="Bad-Name")


def test_digest_is_canonical() -> None:
    a = tool_call("payment_prepare", amount=1250, reference="CASE  7001")
    b = tool_call("payment_prepare", reference="CASE 7001", amount=1250.0)
    c = tool_call("payment_prepare", reference="CASE 7001", amount=1251)
    assert a.digest() == b.digest()
    assert a.digest() != c.digest()


def test_approval_digest_binds_exact_typed_payload() -> None:
    base = tool_call(
        "payment_prepare",
        account_id="ACC-1",
        beneficiary_id="BEN-1",
        amount=42,
        reference="line one\nline two",
    )
    reordered = tool_call(
        "payment_prepare",
        reference="line one\nline two",
        amount=42,
        beneficiary_id="BEN-1",
        account_id="ACC-1",
    )
    assert base.approval_digest() == reordered.approval_digest()
    assert base.approval_digest().startswith("approval-v1:")
    assert base.approval_digest() != base.digest()
    mutations = [
        {**base.arguments, "reference": "line one line two"},
        {**base.arguments, "account_id": "ACC-2"},
        {**base.arguments, "beneficiary_id": "BEN-2"},
        {**base.arguments, "amount": 42.0},
        {**base.arguments, "reference": "líne one\nline two"},
    ]
    assert all(
        base.approval_digest() != base.model_copy(update={"arguments": arguments}).approval_digest()
        for arguments in mutations
    )


def test_decision_validation() -> None:
    DefenseDecision(decision=Decision.ALLOW, risk_score=0.2, confidence=0.9, reason_codes=["OK_CODE"])
    with pytest.raises(ValidationError):
        DefenseDecision(decision=Decision.ALLOW, risk_score=1.5, confidence=0.5)
    with pytest.raises(ValidationError, match="UPPER_SNAKE_CASE"):
        DefenseDecision(decision=Decision.BLOCK, risk_score=0.5, confidence=0.5, reason_codes=["lower"])
    with pytest.raises(ValidationError, match="rewritten_action"):
        DefenseDecision(decision=Decision.REWRITE, risk_score=0.5, confidence=0.5)
    with pytest.raises(ValidationError):
        DefenseDecision(decision=Decision.ALLOW, risk_score=0.5, confidence=0.5, rewritten_action=tool_call("x_y"))
    with pytest.raises(ValidationError, match="metadata"):
        DefenseDecision(decision=Decision.ALLOW, risk_score=0.5, confidence=0.5, metadata={"blob": "x" * 5000})
    with pytest.raises(ValidationError):
        DefenseDecision.model_validate({"decision": "allow", "risk_score": 0, "confidence": 0, "extra": 1})
