"""
Structured logging and request correlation.

FRD ref: NFR-OBS-01/02 — every request carries a correlation id, and log
records are emitted as single-line JSON so they can be shipped to the same
kind of log pipeline this platform itself ingests from. The correlation id
is returned to the caller in the `X-Request-ID` response header and is
attached to every log record produced while handling that request.
"""

import contextvars
import json
import logging
import sys
import time
import uuid
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

REQUEST_ID_HEADER = "X-Request-ID"

_request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")


def get_request_id() -> str:
    return _request_id_ctx.get()


class JsonLogFormatter(logging.Formatter):
    """Render log records as one-line JSON, ECS-ish field names where natural."""

    _RESERVED = {
        "args", "asctime", "created", "exc_info", "exc_text", "filename", "funcName",
        "levelname", "levelno", "lineno", "module", "msecs", "message", "msg", "name",
        "pathname", "process", "processName", "relativeCreated", "stack_info",
        "thread", "threadName", "taskName",
    }

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "@timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "log.level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
            "request.id": getattr(record, "request_id", None) or get_request_id(),
        }
        for key, value in record.__dict__.items():
            if key not in self._RESERVED and not key.startswith("_") and key != "request_id":
                payload[key] = value
        if record.exc_info:
            payload["error.stack_trace"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", as_json: bool = True) -> None:
    handler = logging.StreamHandler(sys.stdout)
    if as_json:
        handler.setFormatter(JsonLogFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-8s %(name)s :: %(message)s"))

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level.upper())

    # uvicorn installs its own handlers; route them through ours instead.
    for noisy in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(noisy)
        logger.handlers = []
        logger.propagate = True


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assign/propagate a request id and emit one access log line per request."""

    def __init__(self, app, logger_name: str = "aegis.access"):
        super().__init__(app)
        self._log = logging.getLogger(logger_name)

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        request_id = request.headers.get(REQUEST_ID_HEADER) or uuid.uuid4().hex
        token = _request_id_ctx.set(request_id)
        request.state.request_id = request_id
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            self._log.exception(
                "request failed",
                extra={
                    "http.request.method": request.method,
                    "url.path": request.url.path,
                    "event.duration_ms": round((time.perf_counter() - started) * 1000, 2),
                },
            )
            raise
        finally:
            _request_id_ctx.reset(token)

        response.headers[REQUEST_ID_HEADER] = request_id
        self._log.info(
            "request handled",
            extra={
                "request_id": request_id,
                "http.request.method": request.method,
                "url.path": request.url.path,
                "http.response.status_code": response.status_code,
                "event.duration_ms": round((time.perf_counter() - started) * 1000, 2),
            },
        )
        return response
