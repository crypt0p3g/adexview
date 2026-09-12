"""Password login with cookie sessions for the viewer.

The viewer serves complete directory snapshots, so it requires a password by
default. Sessions are random tokens held in memory (one server process), sent
as an HttpOnly, SameSite=Strict cookie so a page on another origin cannot ride
an existing login. Failed logins are throttled per client address.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from http.cookies import SimpleCookie
from typing import Dict, Optional, Tuple

SESSION_COOKIE = "adexview_session"
DEFAULT_SESSION_HOURS = 12
MAX_FAILURES_BEFORE_DELAY = 5
LOCKOUT_FAILURES = 15
LOCKOUT_SECONDS = 300


class AuthManager:
    def __init__(
        self,
        password: Optional[str],
        secure_cookie: bool = False,
        session_hours: float = DEFAULT_SESSION_HOURS,
    ) -> None:
        self.enabled = password is not None
        self._digest = hashlib.sha256(password.encode("utf-8")).digest() if password is not None else b""
        self.secure_cookie = secure_cookie
        self.session_seconds = session_hours * 3600
        self._lock = threading.Lock()
        self._sessions: Dict[str, float] = {}
        self._failures: Dict[str, Tuple[int, float]] = {}

    # -- passwords ----------------------------------------------------------------

    def check_password(self, candidate: str) -> bool:
        digest = hashlib.sha256(candidate.encode("utf-8")).digest()
        return hmac.compare_digest(digest, self._digest)

    def login_delay(self, client: str) -> float:
        """Seconds the client must wait before another attempt (0 when free)."""
        with self._lock:
            count, last = self._failures.get(client, (0, 0.0))
            if count >= LOCKOUT_FAILURES and time.monotonic() - last < LOCKOUT_SECONDS:
                return LOCKOUT_SECONDS - (time.monotonic() - last)
            if count >= MAX_FAILURES_BEFORE_DELAY:
                return min(30.0, 2.0 * (count - MAX_FAILURES_BEFORE_DELAY + 1))
            return 0.0

    def record_failure(self, client: str) -> None:
        with self._lock:
            count, _last = self._failures.get(client, (0, 0.0))
            self._failures[client] = (count + 1, time.monotonic())

    def clear_failures(self, client: str) -> None:
        with self._lock:
            self._failures.pop(client, None)

    # -- sessions -----------------------------------------------------------------

    def create_session(self) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._prune()
            self._sessions[token] = time.monotonic() + self.session_seconds
        return token

    def revoke(self, token: Optional[str]) -> None:
        if not token:
            return
        with self._lock:
            self._sessions.pop(token, None)

    def session_from_cookie(self, cookie_header: Optional[str]) -> Optional[str]:
        """Return the valid session token carried by a Cookie header, if any."""
        if not self.enabled:
            return "anonymous"
        if not cookie_header:
            return None
        cookie: SimpleCookie = SimpleCookie()
        try:
            cookie.load(cookie_header)
        except Exception:
            return None
        morsel = cookie.get(SESSION_COOKIE)
        if morsel is None:
            return None
        token = morsel.value
        now = time.monotonic()
        with self._lock:
            expiry = self._sessions.get(token)
            if expiry is None or expiry < now:
                self._sessions.pop(token, None)
                return None
            # Sliding expiry: activity keeps a session alive.
            self._sessions[token] = now + self.session_seconds
        return token

    def cookie_header(self, token: str) -> str:
        attributes = [f"{SESSION_COOKIE}={token}", "Path=/", "HttpOnly", "SameSite=Strict",
                      f"Max-Age={int(self.session_seconds)}"]
        if self.secure_cookie:
            attributes.append("Secure")
        return "; ".join(attributes)

    def clear_cookie_header(self) -> str:
        attributes = [f"{SESSION_COOKIE}=", "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=0"]
        if self.secure_cookie:
            attributes.append("Secure")
        return "; ".join(attributes)

    def _prune(self) -> None:
        now = time.monotonic()
        expired = [token for token, expiry in self._sessions.items() if expiry < now]
        for token in expired:
            del self._sessions[token]


def generate_password() -> str:
    return secrets.token_urlsafe(18)
