"""FastAPI service implementing the SENTINEL v1 defense API."""

from __future__ import annotations

from fastapi import FastAPI

from app.decision import decide
from app.models import DefenseDecision, DefenseRequest
from app.request_limits import RequestBodyLimitMiddleware

app = FastAPI(title="SENTINEL defense starter", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(RequestBodyLimitMiddleware)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/decision", response_model=DefenseDecision)
def decision(request: DefenseRequest) -> DefenseDecision:
    return decide(request)
