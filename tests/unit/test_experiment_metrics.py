import json

import httpx
import pytest

from sentinel.core.actions import ActionType, CandidateAction
from sentinel.firewall.experiment import failure_breakdown, gate
from sentinel.firewall.semantic import LocalMonitor, MonitorError, MonitorFailureCategory
from sentinel.firewall.state import SecurityState
from tests.conftest import defense_request


def judgment(**overrides):
    return {
        "authorized": "yes",
        "authority_substitution": "no",
        "sensitive_disclosure": "no",
        "goal_relevant": "yes",
        "confidence": 0.8,
        "evidence_ids": ["policy"],
        **overrides,
    }


def assess_with(handler):
    monitor = LocalMonitor(transport=httpx.MockTransport(handler))
    try:
        return monitor.assess(
            defense_request(CandidateAction(type=ActionType.RESPOND, content="Summary")),
            SecurityState(),
            thinking=False,
        )
    finally:
        monitor.close()


@pytest.mark.parametrize(
    ("body", "category"),
    [
        (
            {"done": True, "message": {"content": "not json"}},
            MonitorFailureCategory.PARSE_VALIDATION,
        ),
        (
            {"done": True, "message": {"content": json.dumps(judgment(authorized="maybe"))}},
            MonitorFailureCategory.PARSE_VALIDATION,
        ),
        (
            {"done": False, "message": {"content": json.dumps(judgment())}},
            MonitorFailureCategory.TRUNCATION_INCOMPLETE,
        ),
        (
            {"done": True, "done_reason": "length", "message": {"content": json.dumps(judgment())}},
            MonitorFailureCategory.TRUNCATION_INCOMPLETE,
        ),
        (
            {"done": True, "message": {"content": json.dumps(judgment(evidence_ids=["invented"]))}},
            MonitorFailureCategory.INVALID_EVIDENCE,
        ),
    ],
)
def test_monitor_errors_have_stable_output_categories(body, category):
    with pytest.raises(MonitorError) as caught:
        assess_with(lambda _request: httpx.Response(200, json=body))
    assert caught.value.category is category


@pytest.mark.parametrize(
    ("handler", "category"),
    [
        (
            lambda request: (_ for _ in ()).throw(httpx.ReadTimeout("slow", request=request)),
            MonitorFailureCategory.TIMEOUT,
        ),
        (
            lambda _request: httpx.Response(503, json={"error": "unavailable"}),
            MonitorFailureCategory.TRANSPORT_HTTP,
        ),
    ],
)
def test_monitor_distinguishes_timeout_from_transport_and_http(handler, category):
    with pytest.raises(MonitorError) as caught:
        assess_with(handler)
    assert caught.value.category is category


def test_failure_breakdown_is_split_by_thinking_mode_without_changing_gate():
    rows = []
    for index in range(10):
        for thinking in [False, True]:
            error_category = None
            if index == 0:
                error_category = (
                    MonitorFailureCategory.TIMEOUT.value if thinking else MonitorFailureCategory.PARSE_VALIDATION.value
                )
            elif index == 1 and thinking:
                error_category = MonitorFailureCategory.INVALID_EVIDENCE.value
            rows.append(
                {
                    "case_id": str(index),
                    "thinking": thinking,
                    "correct": thinking or index >= 2,
                    "predicted_unsafe": True,
                    "expected_unsafe": True,
                    "latency_s": 1,
                    "error": "failed" if error_category else None,
                    "error_category": error_category,
                }
            )

    breakdown = failure_breakdown(rows)
    assert breakdown["overall"]["failures"] == 3
    assert breakdown["overall"]["by_category"] == {
        "parse_validation": 1,
        "timeout": 1,
        "truncation_incomplete": 0,
        "transport_http": 0,
        "invalid_evidence": 1,
        "other": 0,
    }
    assert breakdown["thinking_off"]["parse_validation_rate"] == 0.1
    assert breakdown["thinking_on"]["by_category"]["timeout"] == 1
    assert not gate(rows)["enable_cascade"]


def test_unknown_failure_category_is_counted_as_other():
    breakdown = failure_breakdown([{"thinking": False, "error": "unexpected", "error_category": "future_category"}])
    assert breakdown["overall"]["by_category"]["other"] == 1
