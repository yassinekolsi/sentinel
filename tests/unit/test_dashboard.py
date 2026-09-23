import json

import pytest
from fastapi.testclient import TestClient

from sentinel.firewall.dashboard import create_dashboard, export_dashboard, snapshot
from sentinel.firewall.viewer import redact


def event(kind, payload, run="run-a"):
    return {"run_id": run, "step_id": 1, "type": kind, "payload": payload}


def write_trace(tmp_path, events):
    path = tmp_path / "events.live.jsonl"
    path.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    return path


def test_export_escapes_attacker_markup_and_redacts_without_changing_trace(tmp_path):
    attack = '</script><img src=x onerror="alert(1)">'
    secret = "correct horse battery staple"
    path = write_trace(tmp_path, [event("retrieval_result", {"password": secret, "text": attack})])
    original = path.read_bytes()
    output = tmp_path / "replay.html"
    export_dashboard(path, output)
    html = output.read_text(encoding="utf-8")
    assert attack not in html and secret not in html
    assert "\\u003c/script\\u003e" in html
    assert "RECORDED REPLAY" in html
    assert "textContent=text" in html
    assert path.read_bytes() == original


def test_snapshot_scopes_results_and_joins_timing_without_mutating_artifact(tmp_path):
    path = write_trace(tmp_path, [event("defense_decision", {"decision": "allow"})])
    (tmp_path / "results.json").write_text(
        json.dumps(
            {
                "model": "mock",
                "attack_mode": "adaptive",
                "outcomes": [
                    {"run_id": "run-a", "decisions": [{"step_id": 1, "latency_ms": 1.25}]},
                    {"run_id": "run-b", "decisions": []},
                ],
            }
        )
    )
    data = snapshot(path)
    assert data["metadata"]["model"] == "mock"
    assert data["metadata"]["attack_mode"] == "adaptive"
    assert len(data["metadata"]["outcomes"]) == 1
    assert data["events"][0]["payload"]["latency_ms"] == 1.25
    assert "latency_ms" not in path.read_text()


def test_live_reader_is_read_only_fixed_path_and_reports_corrupt_trace(tmp_path):
    path = write_trace(tmp_path, [event("user_message", {"text": "hello"})])
    client = TestClient(create_dashboard(path), base_url="http://127.0.0.1")
    assert client.get("/").status_code == 200
    assert client.get("/api/trace?path=C:/private").json()["events"][0]["payload"]["text"] == "hello"
    assert client.post("/api/trace").status_code == 405
    assert client.get("/api/trace", headers={"Host": "attacker.example"}).status_code == 400
    assert "access-control-allow-origin" not in client.get("/api/trace").headers
    path.write_text('{"unfinished":', encoding="utf-8")
    assert client.get("/api/trace").json()["events"] == []
    path.write_text("broken\n", encoding="utf-8")
    assert client.get("/api/trace").status_code == 503


def test_live_metadata_handles_missing_and_in_progress_files(tmp_path):
    path = tmp_path / "future.jsonl"
    (tmp_path / "results.json").write_text('{"unfinished":')
    (tmp_path / "manifest.json").write_text(json.dumps({"effective_config": {"model": "ollama:qwen3:8b"}}))
    data = snapshot(path)
    assert data["events"] == []
    assert data["metadata"]["model"] == "ollama:qwen3:8b"
    with pytest.raises(FileNotFoundError):
        export_dashboard(path, tmp_path / "bad.html")


@pytest.mark.parametrize("secret", ["abc", "correct horse battery staple"])
def test_redaction_covers_explicit_short_and_multiword_credentials(secret):
    rendered = json.dumps(redact([event("retrieval_result", {"password": secret, "echo": secret})]))
    assert secret not in rendered
