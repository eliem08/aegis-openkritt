"""Dalfox adapter — guarded reflected/DOM XSS testing (Phase 3 §Dalfox adapter).

Dalfox actively injects payloads, so this adapter is deliberately conservative:

* **Reflected and DOM analysis only by default.** Blind and stored modes inject
  callbacks and persist state, so they are refused unless explicitly authorized
  *and* given a private OAST endpoint.
* **Everything is bounded** — targets, parameters, payloads per parameter,
  workers, rate, per-request and whole-target timeouts.
* **Session loss stops the host.** If responses start looking like a login/auth
  page, the adapter flags the host and suppresses its findings rather than
  "discovering" the login page over and over.
* **Per-target resume state** is exposed so a cancelled run continues safely, and
  the outcome is one of clean / finding / cancelled / truncated / error.
* Findings are candidates (``verified=False``); raw request/response inclusion is
  opt-in and, when on, is redacted before it can leave the adapter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlsplit

from .base import JsonLinesAdapter, SchemaMismatch
from .contract import AdapterEvent, AdapterManifest, CapabilityTier, EventKind, ExecutionEnvelope, event_from
from .session import SessionBoundary

# Dalfox PoC record types that represent a candidate.
POC_TYPES = frozenset({"R", "V", "G", "BAV"})
_TYPE_CONFIDENCE = {"V": 0.8, "R": 0.55, "G": 0.4, "BAV": 0.4}

DEFAULT_SESSION_LOSS_MARKERS = (
    "/login", "/signin", "/sign-in", "please sign in", "please log in",
    "session expired", "your session has ended", "unauthorized", "log in to continue",
)


class DalfoxMode(str, Enum):
    REFLECTED = "reflected"
    DOM = "dom"
    BLIND = "blind"
    STORED = "stored"


class DalfoxOutcome(str, Enum):
    CLEAN = "clean"
    FINDING = "finding"
    CANCELLED = "cancelled"
    TRUNCATED = "truncated"
    ERROR = "error"
    SESSION_LOST = "session_lost"


class DangerousModeNotAuthorized(RuntimeError):
    """Blind/stored XSS needs explicit authorization and a private OAST endpoint."""


DALFOX_MANIFEST = AdapterManifest(
    name="dalfox",
    version="2.9.1",
    executable_digest="",             # pin the release digest before distribution
    license="MIT",
    capability_tier=CapabilityTier.XSS_REFLECTION.value,
    input_schema_version=1,
    output_schema_version=1,
    network_profile="target-mutation",
)


@dataclass(frozen=True)
class DalfoxConfig:
    max_targets: int = 10
    max_params: int = 100
    payloads_per_param: int = 30
    workers: int = 40
    rate_limit: int = 0               # requests/sec; 0 = dalfox default (no delay)
    request_timeout: int = 10
    target_timeout: int = 120
    blind: bool = False
    stored: bool = False
    oast_url: str = ""
    include_request_response: bool = False
    output_format: str = "json"       # json | sarif
    session_loss_markers: tuple[str, ...] = DEFAULT_SESSION_LOSS_MARKERS


class DalfoxAdapter(JsonLinesAdapter):
    manifest = DALFOX_MANIFEST
    tool_name = "dalfox"

    def __init__(self, executable=None, *, config: DalfoxConfig | None = None,
                 resume_from: dict | None = None, **kw) -> None:
        super().__init__(executable, **kw)
        self.config = config or DalfoxConfig()
        self._assert_modes_authorized()
        self._findings = 0
        self._errors = 0
        self._suppressed = 0
        self._session_lost: set[str] = set()
        self._completed: set[str] = set(resume_from.get("completed", []) if resume_from else [])

    # -- authorization ------------------------------------------------------

    def _assert_modes_authorized(self) -> None:
        cfg = self.config
        if (cfg.blind or cfg.stored) and not cfg.oast_url:
            raise DangerousModeNotAuthorized(
                "blind/stored XSS requires an explicit private OAST endpoint")

    @property
    def modes(self) -> tuple[str, ...]:
        modes = [DalfoxMode.REFLECTED.value, DalfoxMode.DOM.value]
        if self.config.blind:
            modes.append(DalfoxMode.BLIND.value)
        if self.config.stored:
            modes.append(DalfoxMode.STORED.value)
        return tuple(modes)

    # -- command ------------------------------------------------------------

    def build_command(self, envelope: ExecutionEnvelope) -> list[str]:
        cfg = self.config
        argv = [
            self.resolve_executable(), "url", envelope.target,
            "--format", "json" if cfg.output_format == "sarif" else cfg.output_format,
            "--silence", "--no-color",
            "--worker", str(cfg.workers),
            "--timeout", str(cfg.request_timeout),
            "--waf-evasion=false",
            "--skip-bav" if not cfg.blind else "--use-bav",
        ]
        if cfg.rate_limit:
            argv += ["--delay", str(max(1, 1000 // cfg.rate_limit))]
        if cfg.blind:
            argv += ["--blind", cfg.oast_url]      # only reachable once authorized
        if cfg.include_request_response:
            argv += ["--output-request", "--output-response"]
        else:
            argv += ["--only-poc", "r,v,g"]        # keep raw traffic out of output
        return argv

    def already_done(self, target: str) -> bool:
        return target in self._completed

    def resume_state(self) -> dict:
        """Serializable per-target state for a safe resume."""
        return {
            "completed": sorted(self._completed),
            "findings": self._findings,
            "session_lost": sorted(self._session_lost),
        }

    # -- parsing ------------------------------------------------------------

    def map_record(self, record: dict, envelope: ExecutionEnvelope):
        rtype = str(record.get("type") or record.get("_type") or "").upper()
        host = _host_of(record) or envelope.target

        # Once a host's session is gone, everything from it is suppressed — we do
        # not keep "discovering" the login page it now redirects to.
        if host in self._session_lost:
            self._suppressed += 1
            return None
        # First sign of an auth/login page flags the host and stops it.
        if self._is_session_loss(record, host):
            self._session_lost.add(host)
            return (EventKind.DIAGNOSTIC,
                    {"code": "session_lost", "message": f"authentication lost on {host}; stopping host",
                     "host": host, "blocking": False}, 0.0)

        if rtype not in POC_TYPES:
            if rtype in ("ERROR", "E"):
                self._errors += 1
                return (EventKind.DIAGNOSTIC,
                        {"code": "target_error", "message": str(record.get("message") or "dalfox error"),
                         "host": host, "blocking": False}, 0.0)
            return None                            # log/info/debug lines are ignored

        if not (record.get("data") or record.get("param") or record.get("poc")):
            raise SchemaMismatch("dalfox PoC record has neither data, param, nor poc")

        self._findings += 1
        self._completed.add(envelope.target)
        data = {
            "vuln_type": "xss",
            "subtype": _subtype(record, rtype),
            "poc_type": rtype,
            "param": record.get("param") or "",
            "payload": record.get("payload") or record.get("data") or "",
            "inject_type": record.get("inject_type") or "",
            "severity": record.get("severity") or ("high" if rtype == "V" else "medium"),
            "cwe": record.get("cwe") or "CWE-79",
            "matched_at": record.get("data") or record.get("poc") or "",
            "evidence": record.get("evidence") or "",
            "host": host,
            "verified": False,                     # dalfox "V" is still our candidate
        }
        if self.config.include_request_response:
            # Opt-in raw traffic is redacted here before it can leave the adapter;
            # it still passes through evidence quarantine downstream.
            data["request"] = SessionBoundary.redact(record.get("request"))
            data["response"] = SessionBoundary.redact(record.get("response"))
            data["evidence_quarantined"] = True
        confidence = _TYPE_CONFIDENCE.get(rtype, 0.4)
        return (EventKind.FINDING, data, confidence)

    def parse_sarif(self, text: str, envelope: ExecutionEnvelope) -> list[AdapterEvent]:
        """Parse a full SARIF document into FINDING candidates."""
        import json

        doc = json.loads(text)
        events: list[AdapterEvent] = []
        for run in doc.get("runs", []):
            for result in run.get("results", []):
                loc = ""
                locations = result.get("locations") or []
                if locations:
                    loc = (((locations[0].get("physicalLocation") or {}).get("artifactLocation") or {})
                           .get("uri", ""))
                data = {
                    "vuln_type": "xss",
                    "subtype": result.get("ruleId") or "reflected",
                    "severity": _sarif_severity(result.get("level")),
                    "matched_at": loc,
                    "evidence": ((result.get("message") or {}).get("text") or ""),
                    "cwe": "CWE-79",
                    "host": _host_of({"data": loc}) or envelope.target,
                    "verified": False,
                }
                events.append(event_from(EventKind.FINDING, envelope, data,
                                         source=self.manifest.name, confidence=0.5))
        self._findings += len(events)
        return events

    # -- terminal -----------------------------------------------------------

    def interpret_result(self, result, envelope: ExecutionEnvelope):
        from aegis.process import ProcessOutcome

        event = super().interpret_result(result, envelope)
        outcome = self._outcome(result, ProcessOutcome)
        event.data.update({
            "outcome": outcome.value,
            "findings": self._findings,
            "errors": self._errors,
            "session_lost_hosts": sorted(self._session_lost),
            "suppressed_after_session_loss": self._suppressed,
            "modes": list(self.modes),
        })
        # For a session-loss or truncated/cancelled run, coverage is not clean.
        if outcome in (DalfoxOutcome.SESSION_LOST, DalfoxOutcome.TRUNCATED,
                       DalfoxOutcome.CANCELLED, DalfoxOutcome.ERROR):
            event.data["status"] = outcome.value
        return event

    def _outcome(self, result, ProcessOutcome) -> DalfoxOutcome:
        oc = getattr(result, "outcome", None)
        if oc == ProcessOutcome.CANCELLED:
            return DalfoxOutcome.CANCELLED
        if oc in (ProcessOutcome.OUTPUT_LIMIT, ProcessOutcome.TIMED_OUT) or getattr(result, "truncated", False):
            return DalfoxOutcome.TRUNCATED
        if not getattr(result, "ok", False):
            return DalfoxOutcome.ERROR
        if self._session_lost and self._findings == 0:
            return DalfoxOutcome.SESSION_LOST
        if self._findings > 0:
            return DalfoxOutcome.FINDING
        return DalfoxOutcome.CLEAN

    # -- session loss -------------------------------------------------------

    def _is_session_loss(self, record: dict, host: str) -> bool:
        haystack = " ".join(str(record.get(k, "")) for k in
                            ("message", "message_str", "msg", "data", "evidence", "matched-at", "poc")).lower()
        return any(marker in haystack for marker in self.config.session_loss_markers)


def _host_of(record: dict) -> str:
    url = record.get("host") or record.get("data") or record.get("matched-at") or ""
    if not url:
        return ""
    if "//" not in str(url) and "/" not in str(url):
        return str(url).lower()
    parts = urlsplit(str(url) if "//" in str(url) else f"//{url}")
    return (parts.hostname or "").lower()


def _subtype(record: dict, rtype: str) -> str:
    inject = str(record.get("inject_type") or "").lower()
    # A JS-context sink ("inJS", "toJS", "inDOM") is DOM-based; HTML reflection is
    # server-reflected.
    if any(marker in inject for marker in ("dom", "js")):
        return "dom"
    if rtype == "G":
        return "grep"
    return "reflected"


def _sarif_severity(level) -> str:
    return {"error": "high", "warning": "medium", "note": "low"}.get(str(level or "").lower(), "medium")
