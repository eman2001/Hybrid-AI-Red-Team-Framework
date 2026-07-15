"""
api/middleware/logging_middleware.py
--------------------------------------
Request/response logging middleware for FastAPI.
"""

import time
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from engine.config.logging_config import get_logger

log = get_logger("api.middleware")


class LoggingMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):
        start = time.time()
        response = await call_next(request)
        elapsed  = round((time.time() - start) * 1000, 1)
        log.info("%s %s → %s  (%sms)",
                 request.method, request.url.path,
                 response.status_code, elapsed)
        return response
