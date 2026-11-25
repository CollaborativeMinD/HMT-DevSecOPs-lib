from __future__ import annotations

import asyncio
import hmac
import threading
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from pydantic import ValidationError

from .contracts import ToolRequest
from .operations import execute
from .policy import BoundPolicy, Denied, parse_config, policy_path, read_credential
from . import __version__

TOOL_CALLS = Counter("hmt_devsecops_tool_calls_total", "Bounded DevSecOps tool calls", ["tool", "outcome"])
HTTP_REJECTED = Counter("hmt_devsecops_http_rejected_total", "Bounded HTTP admission rejects", ["reason"])
TOOL_LATENCY = Histogram("hmt_devsecops_tool_latency_seconds", "Bounded DevSecOps call latency", ["tool"])


@dataclass(frozen=True)
class HTTPRuntime:
    bound: BoundPolicy
    slots: threading.BoundedSemaphore
    api_token: bytes = field(repr=False)
    metrics_token: bytes = field(repr=False)


def bind_http(bound: BoundPolicy) -> HTTPRuntime:
    http = bound.policy.http
    if http is None:
        raise Denied("HTTP_POLICY_REQUIRED")
    api, metrics = (read_credential(bound.resolve_ref(ref)) for ref in (http.api_token_file, http.metrics_token_file))
    if api == metrics:
        raise Denied("CREDENTIAL_VALUES_MUST_DIFFER")
    if bound.approval in (api, metrics):
        raise Denied("CREDENTIAL_VALUES_MUST_DIFFER")
    return HTTPRuntime(bound, threading.BoundedSemaphore(http.max_inflight), api, metrics)


def _runtime(request: Request) -> HTTPRuntime:
    runtime = request.app.state.runtime
    if runtime is None:
        raise HTTPException(503, "CONFIG_UNAVAILABLE")
    return runtime


def _authenticate(request: Request, key: bytes, detail: str) -> None:
    authorization = request.headers.get("authorization", "").encode("latin-1")
    if not hmac.compare_digest(authorization, b"Bearer " + key):
        raise HTTPException(401, detail)


def create_app(source: Path | None = None, expected_sha256: str | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            bound = parse_config(policy_path(source))
            if expected_sha256 is not None and bound.sha256 != expected_sha256:
                raise Denied("POLICY_DIGEST_MISMATCH")
            app.state.runtime = bind_http(bound)
        except Denied:
            app.state.runtime = None
        yield

    app = FastAPI(title="HMT DevSecOps bounded operator API", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.runtime = None

    @app.get("/metrics")
    def metrics(request: Request):
        _authenticate(request, _runtime(request).metrics_token, "METRICS_AUTH_REQUIRED")
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.get("/health/live")
    def live():
        return {"status": "UP"}

    @app.get("/health/ready")
    def ready(request: Request):
        return {"status": "READY", "policy_sha256": _runtime(request).bound.sha256}

    @app.post("/tools/call")
    async def call(request: Request):
        length = request.headers.get("content-length", "0")
        if not length.isascii() or not length.isdecimal() or len(length) > 20:
            raise HTTPException(400, "INVALID_CONTENT_LENGTH")
        runtime = _runtime(request)
        budget = runtime.bound.policy.http.budget
        if int(length) > budget.request_bytes:
            raise HTTPException(413, "PAYLOAD_TOO_LARGE")
        _authenticate(request, runtime.api_token, "UNAUTHORIZED")
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > budget.request_bytes:
                raise HTTPException(413, "PAYLOAD_TOO_LARGE")
            body.extend(chunk)
        try:
            task = ToolRequest.model_validate_json(body)
        except ValidationError:
            raise HTTPException(400, "INVALID_CONTRACT") from None
        if not runtime.slots.acquire(blocking=False):
            HTTP_REJECTED.labels(reason="capacity").inc()
            raise HTTPException(429, "HTTP_CAPACITY_EXCEEDED", headers={"Retry-After": str(budget.retry_after_seconds)})

        def run_owned():
            try:
                with TOOL_LATENCY.labels(tool=task.tool).time():
                    result = execute(task, runtime.bound)
                TOOL_CALLS.labels(tool=task.tool, outcome=result.disposition).inc()
                return result
            finally:
                runtime.slots.release()

        # A disconnected caller cannot release capacity while its operation is still running.
        result = await asyncio.shield(asyncio.to_thread(run_owned))
        return JSONResponse(result.model_dump(), status_code=200 if result.disposition == "PASS" else 403)

    return app


app = create_app()
