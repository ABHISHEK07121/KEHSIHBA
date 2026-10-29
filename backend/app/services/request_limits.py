import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request


REQUEST_LIMIT = 30
REQUEST_WINDOW_SECONDS = 60
_lock = threading.Lock()
_request_times: dict[tuple[str, str], deque[float]] = defaultdict(deque)


def enforce_request_limit(
    request: Request,
    scope: str,
    limit: int = REQUEST_LIMIT,
    window_seconds: int = REQUEST_WINDOW_SECONDS,
) -> None:
    client = request.client.host if request.client else "unknown"
    key = (client, scope)
    now = time.monotonic()
    with _lock:
        entries = _request_times[key]
        while entries and now - entries[0] > window_seconds:
            entries.popleft()
        if len(entries) >= limit:
            raise HTTPException(
                status_code=429,
                detail=f"Request limit reached; retry in {max(1, window_seconds // 60)} minute(s).",
            )
        entries.append(now)
