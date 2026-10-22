"""CISA KEV client: fetches the official catalogue from the configured URL only."""

import time
from collections.abc import Callable

import httpx

from ...config import get_settings
from ..http import fetch_json
from .schemas import KevCatalog, validate_catalog

SOURCE_HOSTS = ("www.cisa.gov",)


def fetch_catalog(http: httpx.Client, *, sleep: Callable[[float], None] = time.sleep) -> KevCatalog:
    return validate_catalog(fetch_json(http, get_settings().kev_url, sleep=sleep))
