"""Program rules of engagement, platform-agnostic (Master Prompt §4).

A ``ProgramRules`` captures what a public bounty/VDP program authorizes and
forbids: in/out-of-scope assets, and the clauses that constrain *how* we may
test — notably whether **automated tooling** or **AI-assisted** techniques are
allowed, and any rate cap. Our agent is automation; if a program forbids it, the
agent must not run active tests against it (§4) — the mapper flags that as a
hard conflict.

Policy-text parsing is heuristic and deliberately conservative: it can only
*raise* caution (flag a prohibition), never silently grant permission. The
authoritative decision still happens when a human/control-plane signs the
authorization this produces.
"""

from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class AssetType(str, Enum):
    URL = "url"
    WILDCARD = "wildcard"
    CIDR = "cidr"
    IP = "ip"
    ANDROID = "android"
    IOS = "ios"
    SOURCE_CODE = "source_code"
    EXECUTABLE = "executable"
    OTHER = "other"


# Map HackerOne (and similar) asset_type strings onto our coarse categories.
_HACKERONE_ASSET_TYPES: dict[str, AssetType] = {
    "URL": AssetType.URL,
    "CIDR": AssetType.CIDR,
    "IP_ADDRESS": AssetType.IP,
    "GOOGLE_PLAY_APP_ID": AssetType.ANDROID,
    "OTHER_APK": AssetType.ANDROID,
    "APPLE_STORE_APP_ID": AssetType.IOS,
    "TESTFLIGHT": AssetType.IOS,
    "OTHER_IPA": AssetType.IOS,
    "SOURCE_CODE": AssetType.SOURCE_CODE,
    "DOWNLOADABLE_EXECUTABLES": AssetType.EXECUTABLE,
    "OTHER": AssetType.OTHER,
}


def classify_asset_type(raw: str, identifier: str) -> AssetType:
    base = _HACKERONE_ASSET_TYPES.get(raw.upper(), AssetType.OTHER)
    if base == AssetType.URL and "*" in identifier:
        return AssetType.WILDCARD
    return base


def identifier_to_host(identifier: str) -> str | None:
    """Reduce a scope identifier (URL/host/wildcard) to a bare host.

    Keeps a leading ``*.`` wildcard; strips scheme, path, query, port.
    Returns ``None`` for identifiers with no host (CIDRs, app ids, etc.).
    """
    s = (identifier or "").strip()
    if not s:
        return None
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("?", 1)[0]
    if ":" in s and not s.startswith("*"):
        s = s.split(":", 1)[0]
    s = s.strip().lower().rstrip(".")
    # A bare host must contain a dot and only host-ish characters.
    if not s or " " in s:
        return None
    return s


class ScopeAsset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identifier: str
    asset_type: AssetType = AssetType.OTHER
    raw_asset_type: str = ""
    eligible_for_submission: bool = True
    eligible_for_bounty: bool = False
    max_severity: str | None = None
    instruction: str = ""

    @property
    def is_web(self) -> bool:
        return self.asset_type in (AssetType.URL, AssetType.WILDCARD)

    @property
    def is_wildcard(self) -> bool:
        return "*" in self.identifier

    def host(self) -> str | None:
        return identifier_to_host(self.identifier) if self.is_web else None


# --- policy-text heuristics ----------------------------------------------

_NO_AUTOMATION_PATTERNS = [
    r"no automated (scanning|testing|tool)",
    r"automated (scanning|testing|tools?) (is|are) (not allowed|prohibited|forbidden|not permitted)",
    r"do not (use|run) (any )?automated",
    r"(scanners?|scanning) (is|are)? ?(not allowed|prohibited|forbidden)",
    r"no automation",
    r"automated tooling is (not allowed|prohibited|forbidden)",
]

_NO_AI_PATTERNS = [
    r"ai[- ]generated (reports?|submissions?|content) (are|is) (not accepted|not allowed|prohibited|forbidden)",
    r"no ai[- ]generated",
    r"(generative ai|llm|chatgpt)[^.]{0,40}(not allowed|prohibited|forbidden|not accepted)",
    r"do not (use|submit).{0,30}\bai\b",
]

_RATE_PATTERNS = [
    r"(\d+(?:\.\d+)?)\s*(?:requests?|reqs?)\s*(?:per|/)\s*(?:second|sec|s)\b",
]


def _any_match(patterns: list[str], text: str) -> bool:
    return any(re.search(p, text) for p in patterns)


def parse_policy_constraints(policy_text: str) -> dict:
    """Extract automation / AI / rate constraints from free-text policy.

    Heuristic. Returns a dict with ``automation_allowed``, ``ai_allowed``,
    ``rate_limit_rps`` (or None), and human-readable ``notes`` describing what
    was (and was not) detected — so the result is auditable, not a black box.
    """
    text = (policy_text or "").lower()
    notes: list[str] = []

    automation_forbidden = _any_match(_NO_AUTOMATION_PATTERNS, text)
    ai_forbidden = _any_match(_NO_AI_PATTERNS, text)

    rate_rps: float | None = None
    for pat in _RATE_PATTERNS:
        m = re.search(pat, text)
        if m:
            rate_rps = float(m.group(1))
            notes.append(f"parsed rate cap ~{rate_rps} req/s from policy text")
            break

    if automation_forbidden:
        notes.append("policy appears to PROHIBIT automated tooling")
    if ai_forbidden:
        notes.append("policy appears to PROHIBIT AI-assisted / AI-generated work")
    notes.append("policy parsing is heuristic - verify manually before active testing")

    return {
        "automation_allowed": not automation_forbidden,
        "ai_allowed": not ai_forbidden,
        "rate_limit_rps": rate_rps,
        "notes": notes,
    }


# Default action vocabulary for a signed authorization derived from a program.
# Conservative: passive + authenticated testing + synthetic-data reads only.
# State-changing / sensitive actions are intentionally omitted so they must be
# added deliberately (and will require approval at the gate anyway).
DEFAULT_PERMITTED_ACTIONS = [
    "passive_discovery",
    "authenticated_testing",
    "synthetic_data_access",
]
DEFAULT_PROHIBITED_ACTIONS = [
    "denial_of_service",
    "persistence",
    "production_data_exfiltration",
    "third_party_targeting",
]
DEFAULT_RATE_RPS = 2.0  # gentle default when a program states no rate cap


class ProgramRules(BaseModel):
    model_config = ConfigDict(extra="forbid")

    platform: str = "hackerone"
    handle: str
    name: str = ""
    submission_state: str = "open"
    offers_bounties: bool = False
    policy_text: str = ""
    in_scope: list[ScopeAsset] = Field(default_factory=list)
    out_of_scope: list[ScopeAsset] = Field(default_factory=list)

    automation_allowed: bool = True
    ai_allowed: bool = True
    rate_limit_rps: float | None = None
    conflicts: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    # -- scope helpers --

    def eligible_web_assets(self) -> list[ScopeAsset]:
        return [a for a in self.in_scope if a.is_web and a.eligible_for_submission]

    def scope_guard_entries(self) -> list[str]:
        """Host / ``*.host`` entries for a ScopeGuard, deduplicated."""
        seen: list[str] = []
        for asset in self.eligible_web_assets():
            host = asset.host()
            if host and host not in seen:
                seen.append(host)
        return seen

    def out_of_scope_hosts(self) -> list[str]:
        hosts = []
        for asset in self.out_of_scope:
            host = asset.host()
            if host:
                hosts.append(host)
        return hosts

    @property
    def testable_by_automation(self) -> bool:
        return self.automation_allowed and bool(self.scope_guard_entries())

    # -- authorization draft --

    def to_authorization_draft(
        self,
        *,
        customer_id: str,
        authorization_id: str,
        valid_from: str,
        valid_until: str,
        permitted_actions: list[str] | None = None,
    ) -> dict:
        """Build an UNSIGNED authorization skeleton for control-plane signing.

        This is NOT a grant of permission on its own — the control plane must
        sign it, and a human confirms the scope and the automation/AI/rate
        rules. If the program forbids automation, permitted_actions is emptied
        and a conflict is recorded (our agent must not run active tests there).
        """
        entries = self.scope_guard_entries()
        actions = list(permitted_actions or DEFAULT_PERMITTED_ACTIONS)
        conflicts = list(self.conflicts)

        if not self.automation_allowed:
            actions = []
            conflicts.append(
                "program policy appears to prohibit automated tooling; "
                "no active actions permitted for this agent"
            )
        if not self.ai_allowed:
            conflicts.append(
                "program policy appears to prohibit AI-assisted work; "
                "confirm disclosure/eligibility before proceeding"
            )

        rps = self.rate_limit_rps or DEFAULT_RATE_RPS

        return {
            "customer_id": customer_id,
            "authorization_id": authorization_id,
            "ownership_proof": [f"hackerone-program:{self.handle}", "public-bounty-scope"],
            "targets": entries,
            "environment": "approved-production",
            "valid_from": valid_from,
            "valid_until": valid_until,
            "permitted_actions": actions,
            "prohibited_actions": list(DEFAULT_PROHIBITED_ACTIONS),
            "rate_limits": {"requests_per_second": rps, "max_concurrent_sessions": 2},
            "approval_required_for": [
                "cross_tenant_proof",
                "server_side_request_forgery",
                "privilege_escalation",
            ],
            "data_handling": {"stop_on_real_pii": True, "evidence_retention_days": 30, "region": "eu"},
            "_meta": {
                "platform": self.platform,
                "program_handle": self.handle,
                "offers_bounties": self.offers_bounties,
                "automation_allowed": self.automation_allowed,
                "ai_allowed": self.ai_allowed,
                "out_of_scope_hosts": self.out_of_scope_hosts(),
                "conflicts": conflicts,
                "notes": self.notes,
                "unsigned": True,
            },
        }
