"""Local defense service. All valid requests resolve to a legal intervention."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Response

from sentinel.api.request_limits import RequestBodyLimitMiddleware
from sentinel.core.actions import Decision, DefenseDecision
from sentinel.defenses.interface import MAX_DEFENSE_REQUEST_BYTES, DefenseRequest
from sentinel.firewall.engine import Firewall
from sentinel.firewall.semantic import LocalMonitor


def create_app(
    *,
    semantic: bool = False,
    cascade: bool = False,
    model: str = "qwen3:8b",
    audit_dir: Path = Path("artifacts/defense"),
    firewall: Firewall | None = None,
) -> FastAPI:
    engine = firewall or Firewall(LocalMonitor(model) if semantic else None, cascade=cascade, audit_dir=audit_dir)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        engine.close()

    app = FastAPI(title="sentiel action firewall", lifespan=lifespan)
    app.state.firewall = engine

    @app.get("/healthz")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "defense": engine.name,
            "cascade": engine.cascade,
            "confidence": "uncalibrated",
            "human": "simulated by SENTINEL",
        }

    @app.post("/v1/decision", response_model=DefenseDecision)
    def decide(request: DefenseRequest) -> DefenseDecision:
        try:
            return engine.decide(request)
        except Exception:
            return engine.result(
                Decision.BLOCK, "SERVICE_FAILURE", risk=1, confidence=0, explanation="Service failed closed."
            )

    @app.delete("/v1/executions/{execution_id}", status_code=204)
    def end_execution(execution_id: str) -> Response:
        engine.end_execution(execution_id)
        return Response(status_code=204)

    app.add_middleware(RequestBodyLimitMiddleware, max_bytes=MAX_DEFENSE_REQUEST_BYTES)
    return app
