import json

import pytest

from sentinel.core.events import Actor, EventLog, EventType, LogicalClock
from sentinel.firewall.experiment import gate
from sentinel.firewall.viewer import read_live, redact


def test_live_trace_is_written_when_event_occurs():
    seen = []
    log = EventLog("test", LogicalClock(0), sink=seen.append)
    event = log.append(EventType.USER_MESSAGE, Actor.USER, 1, {"text": "hi"})
    assert seen == [event]


def test_live_reader_tolerates_only_unfinished_last_line(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text('{"step_id":1}\n{"step', encoding="utf-8")
    assert read_live(path) == [{"step_id": 1}]
    path.write_text("{oops}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Corrupt trace"):
        read_live(path)
    path.write_text("42\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not an object"):
        read_live(path)


def test_presentation_redacts_plain_encoded_and_spaced_secrets():
    from sentinel.firewall.state import variants

    secret = "credential-test-9123AB"
    events = [
        {"payload": {"token": secret}},
        {"payload": {"body": " ".join(secret)}},
        *[{"payload": {"body": v}} for v in variants(secret).values()],
    ]
    rendered = json.dumps(redact(events))
    assert secret not in rendered and " ".join(secret) not in rendered
    assert all(v not in rendered for v in variants(secret).values())
    assert events[0]["payload"]["token"] == secret


def test_presentation_redacts_secrets_used_as_object_keys():
    secret = "credential-object-key-9123AB"
    events = [{"payload": {"token": secret, "nested": {secret: "value"}}}]
    assert secret not in json.dumps(redact(events))


def test_cascade_gate_needs_complete_pairs_and_no_new_unsafe_allow():
    assert not gate([])["enable_cascade"]
    rows = []
    for i in range(10):
        for thinking in [False, True]:
            rows.append(
                {
                    "case_id": str(i),
                    "thinking": thinking,
                    "correct": thinking or i >= 2,
                    "predicted_unsafe": True,
                    "expected_unsafe": True,
                    "latency_s": 1,
                    "error": None,
                }
            )
    assert gate(rows)["enable_cascade"]
    rows[-1]["predicted_unsafe"] = False
    assert not gate(rows)["enable_cascade"]
