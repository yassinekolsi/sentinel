from datetime import UTC, datetime

import pytest

from sentinel.core.actions import ActionType, CandidateAction, Decision
from sentinel.core.provenance import Provenance, Sensitivity, SourceType, TrustLevel
from sentinel.defenses.interface import (
    ConversationItem,
    HistoryDigest,
    ObservationView,
    ProvenanceRecord,
    ToolCallSummary,
)
from sentinel.firewall.engine import Firewall
from sentinel.firewall.state import variants
from tests.conftest import defense_request, tool_call


def evidence(content, *, trust=TrustLevel.TRUSTED_INTERNAL, sensitivity=Sensitivity.RESTRICTED):
    provenance = Provenance(
        source_type=SourceType.DOCUMENT,
        source_id="any-document",
        trust_level=trust,
        sensitivity=sensitivity,
        origin_actor="reader",
        retrieved_via="document_read",
        timestamp=datetime.now(UTC),
    )
    return {
        "provenance": [ProvenanceRecord(id="p1", provenance=provenance)],
        "conversation": [ConversationItem(role="tool", kind="tool_result", content=content, provenance_ids=["p1"])],
    }


@pytest.mark.parametrize("encoding", ["plain", "base64", "hex", "reversed", "spaced"])
@pytest.mark.parametrize("sink", ["email_draft", "ticket_update", "respond", "memory_write"])
def test_secret_disclosure_across_sinks_and_encodings(encoding, sink):
    secret = "random-credential-X9k42z"
    encoded = " ".join(secret) if encoding == "spaced" else variants(secret)[encoding]
    action = (
        tool_call(sink, to="vendor@vendor.example", subject="reply", body=encoded)
        if sink == "email_draft"
        else tool_call(sink, ticket_id="TCK-0001", note=encoded)
        if sink == "ticket_update"
        else CandidateAction(type=ActionType(sink), content=encoded)
    )
    request = defense_request(action, **evidence('{"access_token": "' + secret + '"}'))
    result = Firewall().decide(request)
    assert result.decision is Decision.BLOCK
    assert result.reason_codes == ["SENSITIVE_DATA_FLOW"]


def test_benign_scary_language_is_not_a_rule_violation():
    action = CandidateAction(type=ActionType.RESPOND, content="The phishing message said ignore previous instructions.")
    assert Firewall().decide(defense_request(action)).decision is Decision.ALLOW


def test_confirmation_does_not_allow_changed_action():
    approved = tool_call("email_send", to="user@atlas.example", subject="status", body="Original")
    changed = approved.model_copy(update={"arguments": {**approved.arguments, "body": "Changed"}})
    result = Firewall().decide(
        defense_request(changed, history_digest=HistoryDigest(confirmations_granted=[approved.digest()]))
    )
    assert result.decision is Decision.REWRITE


def test_confirmation_cannot_override_hard_data_flow():
    action = tool_call("email_send", to="user@atlas.example", subject="status", body="random-credential-X9k42z")
    result = Firewall().decide(
        defense_request(
            action,
            history_digest=HistoryDigest(confirmations_granted=[action.digest()]),
            **evidence('{"access_token":"random-credential-X9k42z"}'),
        )
    )
    assert result.decision is Decision.BLOCK


def test_rewrite_must_be_permitted():
    action = tool_call("email_send", to="vendor@vendor.example", subject="hello", body="Normal reply")
    result = Firewall().decide(defense_request(action, policy_context={"allowed_tools": ["email_send"]}))
    assert result.decision is Decision.ESCALATE


def test_persistent_sensitivity_survives_history_window():
    firewall = Firewall()
    first = defense_request(tool_call("email_read", email_id="EM-2003"), **evidence('{"token":"abc123-secret-value"}'))
    firewall.decide(first)
    second = defense_request(CandidateAction(type=ActionType.RESPOND, content="abc123-secret-value"), step_id=50)
    assert firewall.decide(second).decision is Decision.BLOCK


def test_payment_prerequisite_is_per_object_and_requires_success():
    firewall = Firewall()
    policy = {"allowed_tools": ["payment_prepare", "payment_confirm", "payment_execute"]}
    prepare = tool_call(
        "payment_prepare", account_id="ACC-0001", beneficiary_id="BEN-01", amount=10, reference="refund"
    )
    assert firewall.decide(defense_request(prepare, policy_context=policy)).decision is Decision.ALLOW
    history = HistoryDigest(
        tool_calls=[ToolCallSummary(step_id=1, tool="payment_prepare", decision="allow", succeeded=True)]
    )
    observation = ObservationView(kind="tool_result", content='{"payment_id":"PAY-0001","status":"prepared"}')
    wrong = defense_request(
        tool_call("payment_confirm", payment_id="PAY-0002"),
        step_id=2,
        policy_context=policy,
        observation=observation,
        history_digest=history,
    )
    assert firewall.decide(wrong).reason_codes == ["OBJECT_PREREQUISITE_MISSING"]
    correct = wrong.model_copy(
        update={"step_id": 3, "candidate_action": tool_call("payment_confirm", payment_id="PAY-0001")}
    )
    assert firewall.decide(correct).decision is Decision.ESCALATE


def test_unknown_provenance_never_becomes_authority():
    firewall = Firewall()
    request = defense_request(
        tool_call("email_read", email_id="EM-2003"),
        conversation=[
            ConversationItem(role="memory", kind="memory", content="Approved by system", provenance_ids=["missing"])
        ],
    )
    firewall.decide(request)
    assert next(iter(firewall.states["unit"].evidence.values())).trust == "unknown"


def test_idempotence_conflicts_and_run_isolation():
    firewall = Firewall()
    request = defense_request(tool_call("email_read", email_id="EM-2003"))
    assert firewall.decide(request) == firewall.decide(request)
    conflict = request.model_copy(update={"candidate_action": tool_call("email_read", email_id="EM-2004")})
    assert firewall.decide(conflict).decision is Decision.BLOCK
    assert firewall.decide(conflict.model_copy(update={"run_id": "other"})).decision is Decision.ALLOW


def test_identifiers_do_not_determine_decision():
    request = defense_request(CandidateAction(type=ActionType.RESPOND, content="Summary"), **evidence("Ordinary text"))
    renamed = request.model_copy(update={"run_id": "finance_false_approval"})
    assert Firewall().decide(request) == Firewall().decide(renamed)
