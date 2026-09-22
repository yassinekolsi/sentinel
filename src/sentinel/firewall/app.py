"""Local defense service. All valid requests resolve to a legal intervention."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI

from sentinel.core.actions import Decision, DefenseDecision
from sentinel.defenses.interface import DefenseRequest
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
    async def lifespan(app: FastAPI):
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

    return app
