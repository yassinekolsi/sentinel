"""Portable source and redacted evidence packaging, independent of report/video deliverables."""

from __future__ import annotations

import html
import json
import zipfile
from pathlib import Path
from typing import Any

from sentinel.firewall.dashboard import page, snapshot
from sentinel.firewall.manifest import sha256, source_identity


def verify_bundle(directory: Path) -> dict[str, Any]:
    root = directory.resolve()
    expected = json.loads((root / "checksums.json").read_text(encoding="utf-8"))
    if not isinstance(expected, dict):
        raise ValueError("invalid checksum manifest")
    failures = []
    for name, digest in expected.items():
        target = (root / name).resolve()
        if (
            not target.is_relative_to(root)
            or (root / name).is_symlink()
            or not target.is_file()
            or sha256(target) != digest
        ):
            failures.append(name)
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() and p != root / "checksums.json"}
    unexpected = sorted(actual - expected.keys())
    return {
        "ok": not failures and not unexpected,
        "checked": len(expected),
        "failures": failures,
        "unexpected": unexpected,
    }


def build_bundle(root: Path, runs: list[Path], output: Path) -> Path:
    """Never overwrite an earlier bundle or imply report/video completion."""
    root, output = root.resolve(), output.resolve()
    if output.exists() or output.with_suffix(".zip").exists():
        raise ValueError("output must be new; choose a versioned directory")
    if not runs:
        raise ValueError("at least one completed run directory is required")
    prepared = []
    for directory in runs:
        directory = directory.resolve()
        trace, results = directory / "events.live.jsonl", directory / "results.json"
        if not trace.is_file() or not results.is_file():
            raise ValueError(f"completed results and live trace required: {directory}")
        data = snapshot(trace)
        if not data["metadata"].get("outcomes"):
            raise ValueError(f"no completed outcomes match this trace: {directory}")
        recorded = {event.get("run_id") for event in data["events"]}
        completed = {outcome["run_id"] for outcome in data["metadata"]["outcomes"]}
        if recorded - completed:
            raise ValueError(f"trace contains unfinished runs: {directory}")
        original_manifest = directory / "manifest.json"
        if original_manifest.is_file():
            declared = json.loads(original_manifest.read_text(encoding="utf-8")).get("artifact_sha256", {})
            for name, digest in declared.items():
                artifact = (directory / name).resolve()
                if not artifact.is_relative_to(directory) or not artifact.is_file() or sha256(artifact) != digest:
                    raise ValueError(f"original artifact checksum mismatch: {name}")
        prepared.append((directory, trace, results, data))
    source = source_identity(root)
    source_files = source["file_sha256"]
    if any((root / name).resolve().is_relative_to(output) for name in source_files):
        raise ValueError("output overlaps the source tree")
    output.mkdir(parents=True)
    with zipfile.ZipFile(output / "source.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(".sentiel-source.json", json.dumps(source, indent=2))
        for name, expected in source_files.items():
            path = root / name
            if not path.resolve().is_relative_to(root) or sha256(path) != expected:
                raise ValueError("source changed while packaging; retry into a new directory")
            archive.write(path, name)
    (output / "source-identity.json").write_text(json.dumps(source, indent=2), encoding="utf-8")
    links = []
    inputs = []
    for index, (directory, trace, results, data) in enumerate(prepared, 1):
        name = f"evidence/{index:02d}"
        destination = output / name
        destination.mkdir(parents=True)
        (destination / "replay.html").write_text(page(data), encoding="utf-8")
        (destination / "presentation.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
        manifest = directory / "manifest.json"
        if manifest.exists():
            # Original manifest describes original raw files, not the redacted presentation copy.
            (destination / "original-manifest.json").write_bytes(manifest.read_bytes())
        metadata = data["metadata"]
        schedule = "scheduled adaptive" if metadata["attack_mode"] == "adaptive" else metadata["attack_mode"]
        scope = (
            ", ".join(str(item.get("scenario_id", item["run_id"])) for item in metadata["outcomes"])
            if len(metadata["outcomes"]) <= 3
            else f"{len(metadata['outcomes'])} cases"
        )
        label = f"{metadata['mode']} / {metadata['model']} / {schedule} / {scope} ({directory.parent.name})"
        links.append(f'<li><a href="{name}/replay.html">{html.escape(label)}</a></li>')
        inputs.append(
            {
                "presentation": name,
                "original_directory": str(directory),
                "original_trace_sha256": sha256(trace),
                "original_results_sha256": sha256(results),
                "source_match": (
                    json.loads(manifest.read_text(encoding="utf-8")).get("source", {}).get("tree_sha256")
                    == source["tree_sha256"]
                    if manifest.exists()
                    else False
                ),
            }
        )
    (output / "evidence-index.json").write_text(json.dumps(inputs, indent=2), encoding="utf-8")
    (output / "index.html").write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>sentiel evidence bundle</title>'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<style>body{max-width:900px;margin:60px auto;padding:24px;font:17px/1.7 system-ui;"
        "background:#0b1016;color:#edf3f8}a{color:#83edc5}li{margin:12px 0}</style>"
        "<h1>sentiel / evidence bundle</h1><p>Offline interactive replays. Synthetic data; simulated human approvals. "
        "Each replay labels its model and measured outcomes, including failures. "
        "Mock trajectories follow reference plans; "
        "they do not establish real-model robustness.</p><ul>" + "".join(links) + "</ul>"
        '<p><a href="source.zip">Source snapshot</a> · <a href="source-identity.json">Source identity</a> · '
        '<a href="checksums.json">Checksums</a> · <a href="evidence-index.json">Evidence provenance</a></p>'
        "<p>Technical report and video are excluded. Raw traces remain at the recorded original locations; "
        "presentation copies use best-effort redaction. Original manifests refer to raw artifacts, "
        "not redacted copies. Evidence from earlier source trees stays labeled with its original provenance. "
        "No upload is claimed.</p></html>",
        encoding="utf-8",
    )
    (output / "REPRODUCE.txt").write_text(
        "Extract source.zip. From its root, with Python 3.12 and uv installed:\n"
        "py -3.12 -m uv sync --frozen\n"
        "py -3.12 -m uv run --frozen pytest\n"
        "py -3.12 -m uv run --frozen sentiel evaluate --artifacts artifacts/reproduction\n"
        "py -3.12 -m uv run --frozen sentiel verify-bundle <extracted-bundle-directory>\n"
        "For real-agent runs, install local Ollama and qwen3:8b as described in README.md.\n"
        "Model weights are not included. Setup needs dependency downloads; replays need no network.\n"
        "Checksums detect changes, not authorship. Keep the ZIP checksum separately.\n",
        encoding="utf-8",
    )
    checksums = {p.relative_to(output).as_posix(): sha256(p) for p in sorted(output.rglob("*")) if p.is_file()}
    (output / "checksums.json").write_text(json.dumps(checksums, indent=2), encoding="utf-8")
    if not verify_bundle(output)["ok"]:
        raise ValueError("bundle verification failed")
    archive_path = output.with_suffix(".zip")
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(output.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(output).as_posix())
    return archive_path
