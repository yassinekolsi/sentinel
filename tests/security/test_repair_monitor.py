import json

import httpx

from sentinel.core.policy_context import PolicyContext
from sentinel.firewall.engine import Firewall
from sentinel.firewall.semantic import LocalMonitor
from sentinel.firewall.state import SecurityState
from tests.conftest import defense_request, tool_call


def test_success_cache_invalidates_on_model_and_policy_versions():
    calls = []

    def handle(request):
        calls.append(request)
        return httpx.Response(
            200,
            json={
                "done": True,
                "message": {"content": json.dumps({"a": 1, "u": 0, "s": 0, "g": 1, "c": 80, "e": [-1]})},
            },
        )

    monitor = LocalMonitor(transport=httpx.MockTransport(handle), model_digest="model-a")
    request = defense_request(tool_call("email_draft", to="user@atlas.example", subject="status", body="hello"))
    state = SecurityState()
    monitor.assess(request, state, thinking=False)
    monitor.assess(request, state, thinking=False)
    assert len(calls) == 1
    monitor.model_digest = "model-b"
    monitor.assess(request, state, thinking=False)
    policy_context = PolicyContext.model_validate({**request.policy_context.model_dump(), "policy_version": 2})
    request = request.model_copy(update={"policy_context": policy_context})
    monitor.assess(request, state, thinking=False)
    assert len(calls) == 3
    monitor.close()


def test_execution_cleanup_preserves_shared_cache_while_another_scope_uses_it():
    calls = []

    def handle(request):
        calls.append(request)
        return httpx.Response(
            200,
            json={
                "done": True,
                "message": {"content": json.dumps({"a": 1, "u": 0, "s": 0, "g": 1, "c": 80, "e": [-1]})},
            },
        )

    monitor = LocalMonitor(transport=httpx.MockTransport(handle))
    action = tool_call("email_draft", to="user@atlas.example", subject="status", body="hello")
    first = defense_request(action, execution_id="execution-a")
    second = defense_request(action, execution_id="execution-b")
    monitor.assess(first, SecurityState(), thinking=False)
    monitor.assess(second, SecurityState(), thinking=False)
    assert monitor.last_stats["cache_hit"] is True
    assert len(calls) == 1

    monitor.clear_execution("execution-a")
    assert len(monitor._cache) == 1
    monitor.clear_execution("execution-b")
    assert not monitor._cache
    assert not monitor._cache_scopes
    monitor.close()


def test_rewrite_recheck_shares_original_deadline():
    deadlines = []
    monitor = None

    def handle(request):
        assert monitor is not None
        deadlines.append(monitor._deadline)
        return httpx.Response(
            200,
            json={
                "done": True,
                "message": {"content": json.dumps({"a": 1, "u": 0, "s": 0, "g": 1, "c": 80, "e": [-1]})},
            },
        )

    monitor = LocalMonitor(transport=httpx.MockTransport(handle))
    firewall = Firewall(monitor)
    request = defense_request(tool_call("email_send", to="user@atlas.example", subject="status", body="hello"))
    assert firewall.decide(request).decision.value == "rewrite"
    assert len(deadlines) == 2 and deadlines[0] == deadlines[1] and deadlines[0] is not None
    assert monitor._deadline is None
    firewall.close()
