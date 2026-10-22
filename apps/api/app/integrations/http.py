"""HTTP access for connectors: bounded retries, Retry-After, size limits. Only configured endpoints are ever requested."""

import random
import time
from collections.abc import Callable

import httpx

from ..config import get_settings
from .base import IngestionError

MAX_RESPONSE_BYTES = 64 * 1024 * 1024


def fetch_json(client: httpx.Client, url: str, *, params=None, headers=None, sleep: Callable[[float], None] = time.sleep) -> dict:
    """GET with bounded retries. Retries network errors, 429 and 5xx; other 4xx fail immediately."""
    s = get_settings()
    last: Exception | None = None
    for attempt in range(s.ingestion_max_retries + 1):
        try:
            resp = client.get(url, params=params, headers=headers, timeout=s.ingestion_timeout_seconds)
            if resp.status_code == 200:
                if len(resp.content) > MAX_RESPONSE_BYTES:
                    raise IngestionError(f"{url} returned an oversized response")
                return resp.json()
            if resp.status_code not in (403, 429, 500, 502, 503, 504):
                raise IngestionError(f"{url} returned HTTP {resp.status_code}")
            last = IngestionError(f"{url} returned HTTP {resp.status_code}")
            retry_after = resp.headers.get("retry-after")
            delay = min(float(retry_after), 60.0) if retry_after and retry_after.replace(".", "", 1).isdigit() else None
        except (httpx.TransportError, ValueError) as exc:
            last = exc
            delay = None
        if attempt < s.ingestion_max_retries:
            sleep(delay if delay is not None else min(2 ** attempt + random.random(), 30.0))
    raise IngestionError(f"giving up on {url}: {last}")

