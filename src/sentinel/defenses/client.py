"""HTTP client for participant defense services, plus fail-mode handling."""

from __future__ import annotations

import time
from threading import Lock
from urllib.parse import quote

import httpx
from pydantic import ValidationError

from sentinel.config import FailMode
from sentinel.core.actions import Decision, DefenseDecision
from sentinel.defenses.interface import Defense, DefenseRequest

MAX_RESPONSE_BYTES = 64_000


class DefenseUnavailable(RuntimeError):
    """Transport failure, timeout, bad status, or a malformed response."""


def fail_mode_decision(fail_mode: FailMode, error: str) -> DefenseDecision:
    kind = Decision.BLOCK if fail_mode is FailMode.CLOSED else Decision.ALLOW
    return DefenseDecision(
        decision=kind,
        risk_score=1.0 if kind is Decision.BLOCK else 0.0,
        confidence=0.0,
        reason_codes=["DEFENSE_UNAVAILABLE"],
        explanation=f"defense unavailable ({fail_mode.value} fail mode): {error[:200]}",
    )


class HttpDefense(Defense):
    """Calls ``POST /v1/decision``. Retries transport failures only; never retries bad responses.

    ``decide`` raises DefenseUnavailable so the evaluator can record the error and apply the
    configured fail mode. ``decide_or_fallback`` applies the fail mode directly.
    """

    def __init__(
        self,
        base_url: str,
        timeout_s: float = 5.0,
        transport_retries: int = 2,
        fail_mode: FailMode = FailMode.CLOSED,
        name: str = "http_defense",
        transport: httpx.BaseTransport | None = None,
        backoff_s: float = 0.05,
    ) -> None:
        self.name = name
        self.fail_mode = fail_mode
        self.transport_retries = transport_retries
        self.backoff_s = backoff_s
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"), timeout=timeout_s, transport=transport, follow_redirects=False
        )
        self._active_executions: set[str] = set()
        self._active_lock = Lock()
        self.cleanup_failures = 0
        self.cleanup_unsupported = 0

    def health(self) -> bool:
        try:
            return self._client.get("/healthz").status_code == 200
        except httpx.TransportError:
            return False

    def decide(self, request: DefenseRequest) -> DefenseDecision:
        payload = request.model_dump(mode="json")
        execution_id = request.execution_id or request.run_id
        with self._active_lock:
            self._active_executions.add(execution_id)
        last_error: Exception | None = None
        for attempt in range(self.transport_retries + 1):
            try:
                response = self._client.post("/v1/decision", json=payload)
                break
            except httpx.TransportError as exc:
                last_error = exc
                if attempt < self.transport_retries:
                    time.sleep(self.backoff_s * (attempt + 1))
        else:
            raise DefenseUnavailable(f"transport failure: {type(last_error).__name__}")
        if response.status_code != 200:
            raise DefenseUnavailable(f"HTTP {response.status_code}")
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise DefenseUnavailable("response too large")
        try:
            return DefenseDecision.model_validate_json(response.content)
        except ValidationError as exc:
            raise DefenseUnavailable(f"malformed decision: {exc.errors()[0]['msg']}") from exc

    def decide_or_fallback(self, request: DefenseRequest) -> DefenseDecision:
        try:
            return self.decide(request)
        except DefenseUnavailable as exc:
            return fail_mode_decision(self.fail_mode, str(exc))

    def end_execution(self, execution_id: str) -> None:
        """Ask a compatible service to release this run; legacy services may return 404/405."""
        with self._active_lock:
            if execution_id not in self._active_executions:
                return
        path = f"/v1/executions/{quote(execution_id, safe='')}"
        for attempt in range(self.transport_retries + 1):
            try:
                response = self._client.delete(path)
            except httpx.TransportError:
                if attempt < self.transport_retries:
                    time.sleep(self.backoff_s * (attempt + 1))
                    continue
                with self._active_lock:
                    self.cleanup_failures += 1
                return
            if response.status_code in {200, 204}:
                with self._active_lock:
                    self._active_executions.discard(execution_id)
                return
            if response.status_code in {404, 405}:
                with self._active_lock:
                    self.cleanup_unsupported += 1
                    self._active_executions.discard(execution_id)
                return
            if response.status_code >= 500 and attempt < self.transport_retries:
                time.sleep(self.backoff_s * (attempt + 1))
                continue
            with self._active_lock:
                self.cleanup_failures += 1
            return

    def close(self) -> None:
        with self._active_lock:
            active = list(self._active_executions)
        for execution_id in active:
            self.end_execution(execution_id)
        self._client.close()
        with self._active_lock:
            self._active_executions.clear()
