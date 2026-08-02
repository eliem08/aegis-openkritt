"""An in-process authorized lab target for the Phase 3 completion gate.

A synthetic app with *seeded* vulnerabilities and researcher-owned canaries — no
real data, no network. It answers both the gateway transport (used by the
clean-room discovery engines) and an httpx MockTransport (used by the detectors),
so the whole active pipeline can run end-to-end against it in-process.

Seeded facts:
  * ``/users/1001`` is alice's object and holds the canary; when
    ``bola_vulnerable`` (default) any authenticated account can read it — the bug.
  * the ``debug`` query parameter is reflected into the body (hidden param + a
    reflected-XSS style sink).
  * ``/health``, ``/search``, ``/users/{id}``, ``/orders/{id}`` exist; everything
    else is 404 (so route enumeration has a clean not-found baseline).
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from aegis.active import TransportResponse

CANARY = "CANARY-alice-7a3f-secret"
EXISTING_PREFIXES = ("/users/", "/orders/")
EXISTING_EXACT = {"/", "/health", "/search"}


class LabApp:
    def __init__(self, *, bola_vulnerable: bool = True, unstable: bool = False,
                 reflected_param: str = "debug") -> None:
        self.bola_vulnerable = bola_vulnerable
        self.unstable = unstable
        self.reflected_param = reflected_param
        self.calls = 0
        self._objects = {"/users/1001": ("alice", CANARY)}

    # -- core behavior ------------------------------------------------------

    def respond(self, method: str, url: str, headers: dict | None = None):
        self.calls += 1
        headers = {k.lower(): v for k, v in (headers or {}).items()}
        account = headers.get("x-account")
        parts = urlsplit(url)
        path = parts.path or "/"
        query = parse_qs(parts.query)

        if self.unstable:                      # status AND body flip: an unusable target
            jitter = "jitter " + " ".join(str(i) for i in range(self.calls % 5 + 1))
            return (200 if self.calls % 2 else 500), jitter, {"content-type": "text/plain"}

        body = "<html><body>lab</body></html>"
        if self.reflected_param in query:      # hidden/reflected parameter
            body += f"<echo>{query[self.reflected_param][0]}</echo>"

        if path in self._objects:              # BOLA object
            owner, canary = self._objects[path]
            if account == owner or (self.bola_vulnerable and account):
                return 200, body + f"<record>{canary}</record>", {"content-type": "text/html"}
            if account:
                return 403, "forbidden", {}
            return 401, "unauthorized", {}

        if path in EXISTING_EXACT or path.startswith(EXISTING_PREFIXES):
            return 200, body, {"content-type": "text/html"}
        return 404, "not found", {"content-type": "text/html"}

    # -- adapters -----------------------------------------------------------

    def gateway_transport(self, *, account: str | None = None):
        """A (method, url) -> TransportResponse callable for the discovery engines."""
        def tx(method: str, url: str) -> TransportResponse:
            hdrs = {"X-Account": account} if account else {}
            status, body, resp_headers = self.respond(method, url, hdrs)
            return TransportResponse(status=status, headers=resp_headers, body=body)
        return tx

    def httpx_transport(self):
        """An httpx MockTransport for the detectors' gated client."""
        import httpx

        def handler(request):
            status, body, resp_headers = self.respond(
                request.method, str(request.url), dict(request.headers))
            return httpx.Response(status, text=body, headers=resp_headers)

        return httpx.MockTransport(handler)
