"""NVD API 2.0 client: windowed incremental fetch, pagination, rate-limit pacing, bounded retries."""

import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta

import httpx

from ...config import get_settings
from ..http import fetch_json
from .schemas import validate_page

MAX_WINDOW = timedelta(days=119)  # NVD rejects lastMod ranges over 120 days
PAGE_SIZE = 2000
SOURCE_HOSTS = ("services.nvd.nist.gov",)


class NvdClient:
    def __init__(self, http: httpx.Client, *, sleep: Callable[[float], None] = time.sleep):
        s = get_settings()
        self.http = http
        self.sleep = sleep
        self.base_url = s.nvd_base_url
        self.headers = {"apiKey": s.nvd_api_key} if s.nvd_api_key else {}
        # Public limit: 5 requests per rolling 30 s; with an API key: 50. Pace conservatively under both.
        self.pause = 0.7 if s.nvd_api_key else 6.5

    def pages(self, since: datetime, until: datetime | None = None) -> Iterator[list[dict]]:
        """Yield lists of raw vulnerability records modified between since and until (default: now)."""
        until = until or datetime.now(UTC)
        window_start = since
        while window_start < until:
            window_end = min(window_start + MAX_WINDOW, until)
            index = 0
            while True:
                params = {
                    "lastModStartDate": window_start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "lastModEndDate": window_end.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "resultsPerPage": PAGE_SIZE,
                    "startIndex": index,
                }
                page = validate_page(fetch_json(self.http, self.base_url, params=params, headers=self.headers, sleep=self.sleep))
                yield page.vulnerabilities
                index += len(page.vulnerabilities)
                if not page.vulnerabilities or index >= page.totalResults:
                    break
                self.sleep(self.pause)
            window_start = window_end
            if window_start < until:
                self.sleep(self.pause)
