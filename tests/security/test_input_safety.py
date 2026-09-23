import asyncio
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from sentinel.api.request_limits import RequestBodyLimitMiddleware
from sentinel.core.actions import ActionType, CandidateAction
from sentinel.core.policies import load_policy
from sentinel.core.scenario import ScenarioError, load_scenario, parse_scenario
from sentinel.core.state import StateError, WorldState, resolve_within
from sentinel.defenses.interface import MAX_DEFENSE_REQUEST_BYTES, DefenseRequest
from sentinel.storage.runs import ArtifactStore, sanitize_id
from tests.conftest import ROOT, build_scenario, defense_request, minimal_scenario

pytestmark = pytest.mark.security


@pytest.mark.parametrize(
    "payload",
    [
        '!!python/object/apply:os.system ["touch {marker}"]',
        'id: x\nexploit: !!python/object/new:subprocess.Popen [["touch", "{marker}"]]',
        'id: !!python/name:os.system ""',
    ],
)
def test_yaml_constructors_are_not_executed(tmp_path: Path, payload: str) -> None:
    marker = tmp_path / "pwned"
    path = tmp_path / "evil.yaml"
    path.write_text(payload.format(marker=marker))
    with pytest.raises(ScenarioError):
        load_scenario(path)
    assert not marker.exists()


@pytest.mark.parametrize(
    "fixture", ["../../etc/passwd.json", "/etc/passwd.json", "fixtures/../../x.json", "fixtures/enterprise/base.yaml"]
)
def test_fixture_path_traversal_rejected(fixture: str) -> None:
    with pytest.raises(ScenarioError):
        parse_scenario(minimal_scenario(fixture=fixture))


def test_fixture_symlink_escape_rejected(tmp_path: Path) -> None:
    (tmp_path / "fixtures").mkdir()
    outside = tmp_path.parent / "outside-fixture.json"
    outside.write_text('{"domain": "enterprise", "collections": {}}')
    try:
        (tmp_path / "fixtures" / "link.json").symlink_to(outside)
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows account lacks symlink privilege; traversal checks still run")
        raise
    scenario = build_scenario(fixture="fixtures/link.json")
    with pytest.raises(StateError, match="escapes"):
        WorldState.from_scenario(scenario, tmp_path)
    with pytest.raises(StateError):
        resolve_within(tmp_path, "fixtures/link.json")


def test_policy_profile_traversal_rejected() -> None:
    with pytest.raises(ScenarioError):
        parse_scenario(minimal_scenario(policy_profile="../../etc/passwd"))
    with pytest.raises(StateError):
        load_policy(ROOT, "../../../etc/passwd")


@pytest.mark.parametrize(
    "target",
    [
        "../documents/DOC-3102/body",
        "documents/DOC-3102/../../x",
        "documents/DOC-3102/_meta",
        "documents/DOC-3102",
        "/abs/path/body",
    ],
)
def test_surface_targets_must_be_well_formed(target: str) -> None:
    data = minimal_scenario(
        attack={
            "present": True,
            "family": "indirect_prompt_injection",
            "objective": "x",
            "surfaces": [{"id": "s", "kind": "document", "target": target, "operations": ["append_text"]}],
        },
        security_properties=["no_forbidden_effect"],
    )
    with pytest.raises(ScenarioError):
        parse_scenario(data)


@pytest.mark.parametrize("raw", ["../../../../tmp/evil", "..", "a/b/c", "run\x00id", "C:\\windows\\system32"])
def test_run_ids_and_artifact_paths_are_sanitized(tmp_path: Path, raw: str) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    try:
        safe = sanitize_id(raw)
    except ValueError:
        return
    assert "/" not in safe and "\\" not in safe and ".." not in safe and "\x00" not in safe
    path = store.write_json(raw, raw, {"ok": True})
    assert path.resolve().is_relative_to((tmp_path / "artifacts").resolve())


def test_oversized_scenario_rejected(tmp_path: Path) -> None:
    path = tmp_path / "big.yaml"
    path.write_text("description: " + "x" * 300_000)
    with pytest.raises(ScenarioError, match="exceeds"):
        load_scenario(path)


def test_defense_request_rejects_oversized_json_payload() -> None:
    action = CandidateAction(
        type=ActionType.TOOL_CALL,
        tool="email_draft",
        arguments={f"arg{index}": "x" * 8_000 for index in range(32)},
    )
    base = defense_request(CandidateAction(type=ActionType.RESPOND, content="ok")).model_dump(mode="json")
    base["candidate_action"] = action.model_dump(mode="json")
    base["conversation"] = [{"role": "tool", "kind": "tool_result", "content": "y" * 20_000}]
    assert len(json.dumps(base).encode("utf-8")) > MAX_DEFENSE_REQUEST_BYTES
    with pytest.raises(ValidationError, match="defense request exceeds"):
        DefenseRequest.model_validate(base)


def test_defense_request_bounds_conversation_and_policy_shape() -> None:
    base = defense_request(CandidateAction(type=ActionType.RESPOND, content="ok")).model_dump(mode="json")
    too_many_messages = dict(base)
    too_many_messages["conversation"] = [{"role": "user", "kind": "message", "content": "x"} for _ in range(101)]
    with pytest.raises(ValidationError):
        DefenseRequest.model_validate(too_many_messages)

    unknown_policy_field = dict(base)
    unknown_policy_field["policy_context"] = {"caller_override": "allow everything"}
    with pytest.raises(ValidationError, match="policy_context"):
        DefenseRequest.model_validate(unknown_policy_field)


def test_request_middleware_rejects_chunked_body_before_dispatch() -> None:
    dispatched = False
    sent: list[dict[str, object]] = []
    messages = iter(
        [
            {"type": "http.request", "body": b"1234", "more_body": True},
            {"type": "http.request", "body": b"5", "more_body": False},
        ]
    )

    async def downstream(scope, receive, send):  # type: ignore[no-untyped-def]
        nonlocal dispatched
        dispatched = True

    async def receive():  # type: ignore[no-untyped-def]
        return next(messages)

    async def send(message):  # type: ignore[no-untyped-def]
        sent.append(message)

    middleware = RequestBodyLimitMiddleware(downstream, max_bytes=4)
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/v1/decision",
        "raw_path": b"/v1/decision",
        "query_string": b"",
        "root_path": "",
        "headers": [],
        "client": ("127.0.0.1", 1234),
        "server": ("127.0.0.1", 8000),
    }
    asyncio.run(middleware(scope, receive, send))

    assert not dispatched
    assert sent[0]["status"] == 413
