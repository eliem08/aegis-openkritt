"""Task-scoped credential/session boundary (Phase 2 §Katana adapter).

Crawling an authenticated surface means holding cookies. Those cookies are the
most dangerous thing a discovery task touches, so their lifetime is bounded on
every axis that matters:

* **Per task.** A boundary belongs to one task; nothing is shared between tasks,
  scans, or engagements, and :meth:`close` wipes the state.
* **Per host, inside scope.** A cookie set by one host is never offered to
  another, and never to a host outside the authorized crawl scope.
* **Never in argv.** Values arrive as secret *references* and are written to a
  task-private file by the process runner; the command line only ever names a
  path (process listings are world-readable on most systems).
* **Never in output.** :meth:`redact` strips cookie and authorization material
  out of anything an adapter is about to emit, so session state cannot reach the
  asset graph, an artifact, or a report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .base import in_parent_scope

#: Field names whose values are session/credential material and must never leave
#: the boundary — matched case-insensitively against event data keys.
SENSITIVE_FIELDS = frozenset({
    "cookie", "cookies", "set-cookie", "set_cookie", "authorization", "auth",
    "session", "session_id", "sessionid", "token", "access_token", "refresh_token",
    "csrf", "csrf_token", "x-auth-token", "api_key", "apikey", "password", "secret",
})

REDACTED = "[redacted]"

_COOKIE_PAIR = re.compile(r"(?P<name>[^=;,\s]+)=(?P<value>[^;,]*)")


class SessionBoundaryError(RuntimeError):
    """An attempt to use session state outside the task/host it belongs to."""


@dataclass
class SessionBoundary:
    """Cookie state confined to one task and its authorized hosts."""

    task_id: str
    scope_root: str                              # authorized parent domain
    cookie_file: str = ""                        # path written by the runner; never a value
    _jar: dict[str, dict[str, str]] = field(default_factory=dict)  # host -> {name: value}
    _closed: bool = False

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        """Wipe session state. After this the boundary refuses all access."""
        for cookies in self._jar.values():
            cookies.clear()
        self._jar.clear()
        self._closed = True

    def __enter__(self) -> SessionBoundary:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def closed(self) -> bool:
        return self._closed

    # -- cookie state ------------------------------------------------------

    def accepts(self, host: str) -> bool:
        """Only hosts inside the authorized crawl scope may hold session state."""
        return bool(host) and in_parent_scope(host, self.scope_root)

    def store(self, host: str, header: str) -> int:
        """Record cookies a host set. Returns how many were kept."""
        self._check_open()
        host = (host or "").strip().lower()
        if not self.accepts(host):
            # Out-of-scope hosts get no session state at all — silently dropped
            # rather than stored and later leaked back to them.
            return 0
        jar = self._jar.setdefault(host, {})
        kept = 0
        for match in _COOKIE_PAIR.finditer(header or ""):
            name = match.group("name").strip()
            if name.lower() in {"path", "domain", "expires", "max-age", "samesite", "secure", "httponly"}:
                continue
            jar[name] = match.group("value").strip()
            kept += 1
        return kept

    def cookies_for(self, host: str) -> dict[str, str]:
        """Cookies this host may receive — never another host's."""
        self._check_open()
        host = (host or "").strip().lower()
        if not self.accepts(host):
            return {}
        return dict(self._jar.get(host, {}))

    def cookie_header(self, host: str) -> str:
        return "; ".join(f"{k}={v}" for k, v in sorted(self.cookies_for(host).items()))

    def _check_open(self) -> None:
        if self._closed:
            raise SessionBoundaryError(
                f"session boundary for task {self.task_id!r} is closed; state was wiped"
            )

    # -- outbound redaction ------------------------------------------------

    @classmethod
    def redact(cls, data):
        """Strip session/credential material from data about to be emitted.

        Applied to every adapter emission, so cookies cannot reach the asset
        graph, an artifact, or a report even if a tool echoes them back.
        """
        if isinstance(data, dict):
            clean = {}
            for key, value in data.items():
                if str(key).strip().lower() in SENSITIVE_FIELDS:
                    clean[key] = REDACTED
                else:
                    clean[key] = cls.redact(value)
            return clean
        if isinstance(data, list):
            return [cls.redact(v) for v in data]
        return data
