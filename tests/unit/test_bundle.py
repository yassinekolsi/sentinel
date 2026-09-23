import json
import zipfile

import pytest

from sentinel.firewall.bundle import build_bundle, verify_bundle
from sentinel.firewall.manifest import sha256, source_identity


def test_package_source_snapshot_and_tamper_detection(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    source = root / "README.md"
    source.write_text("source snapshot")
    marker = {"commit": "archived-commit", "file_sha256": {"README.md": sha256(source)}}
    (root / ".sentiel-source.json").write_text(json.dumps(marker))
    run = tmp_path / "run"
    run.mkdir()
    (run / "events.live.jsonl").write_text(
        json.dumps({"run_id": "r", "type": "task_success", "step_id": 1, "payload": {"summary": "done"}}) + "\n"
    )
    (run / "results.json").write_text(
        json.dumps({"model": "mock", "mode": "rules", "outcomes": [{"run_id": "r", "decisions": []}]})
    )
    output = tmp_path / "bundle"
    archive = build_bundle(root, [run], output)
    assert archive.is_file() and verify_bundle(output)["ok"]
    with zipfile.ZipFile(output / "source.zip") as packaged:
        assert packaged.read("README.md") == source.read_bytes()
        assert ".sentiel-source.json" in packaged.namelist()
    assert not list(output.rglob("*technical-report*"))
    (output / "index.html").write_text("tampered")
    (output / "unexpected.txt").write_text("extra")
    result = verify_bundle(output)
    assert not result["ok"]
    assert result["failures"] == ["index.html"]
    assert result["unexpected"] == ["unexpected.txt"]
    with pytest.raises(ValueError, match="versioned"):
        build_bundle(root, [run], output)


def test_archive_source_identity_is_recomputed_after_edit(tmp_path):
    source = tmp_path / "main.py"
    source.write_text("initial")
    (tmp_path / ".sentiel-source.json").write_text(
        json.dumps({"commit": "original", "file_sha256": {"main.py": sha256(source)}})
    )
    before = source_identity(tmp_path)
    source.write_text("changed")
    after = source_identity(tmp_path)
    assert after["origin"] == "source archive"
    assert after["commit"] == "original"
    assert after["dirty"] is None
    assert before["tree_sha256"] != after["tree_sha256"]


def test_checksum_paths_cannot_escape_bundle(tmp_path):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("private")
    (bundle / "checksums.json").write_text(json.dumps({"../outside": sha256(outside)}))
    assert verify_bundle(bundle)["failures"] == ["../outside"]


def test_partial_run_is_not_packaged_as_complete(tmp_path):
    with pytest.raises(ValueError, match="completed results"):
        build_bundle(tmp_path, [tmp_path], tmp_path / "output")
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("failure", ["unfinished", "checksum"])
def test_bundle_rejects_unfinished_or_tampered_evidence(tmp_path, failure):
    events = [{"run_id": "done", "type": "task_success", "payload": {}}]
    if failure == "unfinished":
        events.append({"run_id": "pending", "type": "user_message", "payload": {}})
    (tmp_path / "events.live.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events))
    (tmp_path / "results.json").write_text(json.dumps({"outcomes": [{"run_id": "done"}]}))
    if failure == "checksum":
        (tmp_path / "manifest.json").write_text(json.dumps({"artifact_sha256": {"results.json": "wrong"}}))
    with pytest.raises(ValueError, match=failure):
        build_bundle(tmp_path, [tmp_path], tmp_path / "bundle")
