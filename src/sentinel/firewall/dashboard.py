"""Read-only, offline browser observability. Evaluation metadata never enters the defense."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from sentinel.firewall.viewer import read_live, redact


def snapshot(path: Path) -> dict[str, Any]:
    """Read only the selected trace and its sibling run metadata; redact before delivery."""
    events = read_live(path)
    metadata: dict[str, Any] = {
        "model": "unknown",
        "mode": "unknown",
        "attack_mode": "unknown",
        "outcomes": [],
        "exposure": {},
    }
    for name in ("manifest.json", "results.json"):
        sibling = path.parent / name
        if not sibling.exists():
            continue
        try:
            data = json.loads(sibling.read_text(encoding="utf-8"))
        except ValueError:
            # A live writer may be replacing the summary; never invent a verdict.
            continue
        if not isinstance(data, dict):
            continue
        if name == "manifest.json":
            config = data.get("effective_config", {})
            if isinstance(config, dict):
                metadata.update({key: config[key] for key in ("model", "mode") if key in config})
                if "adaptive" in config:
                    metadata["attack_mode"] = "adaptive" if config["adaptive"] else "static"
            source = data.get("source", {})
            if isinstance(source, dict):
                metadata["source"] = {
                    key: source[key] for key in ("commit", "dirty", "origin", "tree_sha256") if key in source
                }
        else:
            metadata.update(
                {key: data[key] for key in ("model", "mode", "attack_mode", "outcomes", "exposure") if key in data}
            )
    run_ids = {event.get("run_id") for event in events}
    metadata["outcomes"] = [o for o in metadata["outcomes"] if isinstance(o, dict) and o.get("run_id") in run_ids]
    # Timing is a measurement, kept outside deterministic simulator events.
    timings = {
        (outcome["run_id"], decision["step_id"]): decision["latency_ms"]
        for outcome in metadata["outcomes"]
        for decision in outcome.get("decisions", [])
        if "step_id" in decision and "latency_ms" in decision
    }
    for event in events:
        key = (event.get("run_id"), event.get("step_id"))
        if event.get("type") == "defense_decision" and key in timings:
            event["payload"] = {**event.get("payload", {}), "latency_ms": timings[key]}
    # Include metadata in the same redaction pass: a later retrieval can identify an earlier secret.
    cleaned = redact([*events, {"payload": metadata}])
    return {"events": cleaned[:-1], "metadata": cleaned[-1]["payload"]}


def page(data: dict[str, Any], *, live: bool = False) -> str:
    template = Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")
    # JSON is embedded in an inert script element. Escape HTML delimiters, including closing scripts.
    encoded = json.dumps({**data, "live": live}, ensure_ascii=True).replace("<", "\\u003c")
    encoded = encoded.replace(">", "\\u003e").replace("&", "\\u0026")
    return template.replace("__TRACE_DATA__", encoded)


def export_dashboard(path: Path, output: Path) -> None:
    if not path.is_file():
        raise FileNotFoundError(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(page(snapshot(path)), encoding="utf-8")


def create_dashboard(path: Path) -> FastAPI:
    """One fixed trace; no file browser, write routes, remote assets, or CORS access."""
    selected = path.resolve()
    app = FastAPI(title="sentinel observatory", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]"])

    @lru_cache(maxsize=1)
    def cached_snapshot(signature: tuple[tuple[int, int] | None, ...]) -> dict[str, Any]:
        return snapshot(selected)

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        return HTMLResponse(page({"events": [], "metadata": {}}, live=True), headers={"Cache-Control": "no-store"})

    @app.get("/api/trace")
    def trace() -> Any:
        from fastapi.responses import JSONResponse

        try:
            files = (selected, selected.parent / "manifest.json", selected.parent / "results.json")
            signature = tuple((p.stat().st_mtime_ns, p.stat().st_size) if p.exists() else None for p in files)
            data = cached_snapshot(signature)
        except (OSError, ValueError) as exc:
            raise HTTPException(
                status_code=503, detail="Trace unavailable or corrupt; retry after checking the file."
            ) from exc
        return JSONResponse(data, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})

    return app
