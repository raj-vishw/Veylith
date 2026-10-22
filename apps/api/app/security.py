import hashlib
import secrets
import time
from collections import defaultdict, deque
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import HTTPException, Request

from .config import get_settings

_hasher = PasswordHasher()  # argon2id, library defaults (RFC 9106 low-memory profile)
# Verified against when the account does not exist so that response time does not reveal valid emails.
_DUMMY_HASH = _hasher.hash("veylith-dummy-password")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    """Only the hash of a session token is stored, so a database leak does not yield usable sessions."""
    return hashlib.sha256(token.encode()).hexdigest()


def session_lifetime() -> timedelta:
    return timedelta(hours=get_settings().session_ttl_hours)


# --------------------------------------------------------------------------- rate limiting
class RateLimiter:
    """Sliding-window limiter. Redis-backed when reachable (shared across workers), in-process otherwise."""

    def __init__(self):
        self._local: dict[str, deque] = defaultdict(deque)
        self._redis = None
        self._redis_checked = False

    def _client(self):
        if not self._redis_checked:
            self._redis_checked = True
            try:
                import redis

                client = redis.Redis.from_url(get_settings().redis_url, socket_connect_timeout=0.5, socket_timeout=0.5)
                client.ping()
                self._redis = client
            except Exception:
                self._redis = None
        return self._redis

    def hit(self, key: str, limit: int, window: int) -> bool:
        """Records an attempt; returns False when the limit is exceeded."""
        client = self._client()
        if client is not None:
            try:
                bucket = f"rl:{key}:{int(time.time()) // window}"
                count = client.incr(bucket)
                if count == 1:
                    client.expire(bucket, window + 1)
                return count <= limit
            except Exception:
                pass
        now = time.monotonic()
        q = self._local[key]
        while q and q[0] <= now - window:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True

    def reset(self):
        self._local.clear()
        client = self._client()
        if client is not None:
            try:
                for k in client.scan_iter("rl:*"):
                    client.delete(k)
            except Exception:
                pass


limiter = RateLimiter()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def enforce_login_limit(request: Request, email: str) -> None:
    s = get_settings()
    if not limiter.hit(f"login:{client_ip(request)}:{email.lower()}", s.login_rate_limit, s.login_rate_window_seconds):
        raise HTTPException(status_code=429, detail="Too many attempts. Try again later.")


def enforce_expensive_limit(action: str, org_id, user_id) -> None:
    s = get_settings()
    if not limiter.hit(f"exp:{action}:{org_id}:{user_id}", s.expensive_rate_limit, s.expensive_rate_window_seconds):
        raise HTTPException(status_code=429, detail=f"Rate limit exceeded for {action}. Try again shortly.")
