"""Evaluator-side reproducibility metadata, never supplied to the defense."""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from sentinel.firewall.semantic import PROMPT_VERSION, WIRE_SCHEMA_VERSION


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_identity(root: Path) -> dict[str, Any]:
    def git(*args: str) -> str:
        # Fixed read-only commands; args are code constants, never request content.
        return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()  # noqa: S603, S607

    return {"commit": git("rev-parse", "HEAD"), "dirty": bool(git("status", "--porcelain"))}


def runtime_snapshot() -> dict[str, Any]:
    result: dict[str, Any] = {"platform": platform.platform(), "python": platform.python_version()}
    with httpx.Client(base_url="http://127.0.0.1:11434", trust_env=False, timeout=5) as client:
        for endpoint in ("version", "tags", "ps"):
            try:
                response = client.get(f"/api/{endpoint}")
                response.raise_for_status()
                result[endpoint] = response.json()
            except (httpx.HTTPError, ValueError) as exc:
                result[endpoint] = {"unavailable": type(exc).__name__}
    # Backend cannot be inferred from total VRAM or a model name.
    result["backend"] = "see runtime server log; API does not identify compute backend"
    return result


def new_manifest(root: Path, config: dict[str, Any], *, runtime: bool) -> dict[str, Any]:
    return {
        "created_utc": datetime.now(UTC).isoformat(),
        "source": source_identity(root),
        "runtime": runtime_snapshot() if runtime else {"model": "mock"},
        "prompt_version": PROMPT_VERSION,
        "wire_schema_version": WIRE_SCHEMA_VERSION,
        "effective_config": config,
        "warmup": "not performed by CLI; cold load included unless external warmup documented",
        "harness": "exact approval-v1; unique execution ID; two blocked-final recovery retries",
        "runs": [],
    }


def save_manifest(directory: Path, manifest: dict[str, Any]) -> None:
    manifest["artifact_sha256"] = {
        path.relative_to(directory).as_posix(): sha256(path)
        for path in sorted(directory.rglob("*"))
        if path.is_file() and path.name != "manifest.json"
    }
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
