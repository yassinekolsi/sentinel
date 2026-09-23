"""Small request-size guard kept local so the starter kit remains self-contained."""

from __future__ import annotations

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

MAX_REQUEST_BODY_BYTES = 256 * 1024


class RequestBodyLimitMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") != "/v1/decision":
            await self.app(scope, receive, send)
            return

        content_length = next(
            (value for name, value in scope.get("headers", []) if name.lower() == b"content-length"), None
        )
        if content_length is not None:
            try:
                if int(content_length) > MAX_REQUEST_BODY_BYTES:
                    await self._reject(scope, receive, send)
                    return
            except ValueError:
                pass

        messages: list[Message] = []
        size = 0
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] == "http.disconnect":
                break
            if message["type"] != "http.request":
                continue
            size += len(message.get("body", b""))
            if size > MAX_REQUEST_BODY_BYTES:
                await self._reject(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        messages_iter = iter(messages)

        async def replay_receive() -> Message:
            try:
                return next(messages_iter)
            except StopIteration:
                return await receive()

        await self.app(scope, replay_receive, send)

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        response = JSONResponse(
            {"detail": f"Request body exceeds the {MAX_REQUEST_BODY_BYTES}-byte limit."},
            status_code=413,
        )
        await response(scope, receive, send)
