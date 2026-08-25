"""VRT coverage map — which Bugcrowd VRT classes the arsenal can hunt, and how.

"Hunt anything" means *know the whole taxonomy and route each class to the right
lane* — not "attack everything." This module maps every top-level Bugcrowd VRT
category (v1.19) to a :class:`HuntLane` so the hunt loop / Jarvis can decide, per
class, whether and how to pursue it:

  * ``SOURCE_WEB``     — source-review of web/app/API code (the proven lane:
                          IDOR/BAC, injection, XSS, SSRF, auth, secrets, CSRF).
  * ``SOURCE_CRYPTO``  — smart-contract / DeFi / ZK source audit (the crypto lane).
  * ``LIVE_ONLY``      — only demonstrable against a running target; must go
                          through :mod:`aegis.policy.live_gate` (signed grant +
                          eligibility + human approval for anything consequential).
  * ``OUT_OF_BOUNDARY``— needs hardware / mobile-device / AD / physical / cloud-
                          tenant access we don't have; not pursued by this method.
  * ``CATEGORICALLY_OFF`` — never pursued regardless of authorization: DoS /
                          resource-exhaustion, CAPTCHA/bot-detection bypass,
                          phishing/social engineering, and (non-security) bias
                          classes. Mirrors the prohibited set in ``live_gate`` and
                          the live-attack boundary.

The map is intentionally conservative: unknown categories fail to ``LIVE_ONLY``
(so they still pass through the governed gate) rather than being assumed safe.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

__all__ = ["HuntLane", "Coverage", "classify", "pursuable_now"]


class HuntLane(str, Enum):
    SOURCE_WEB = "source_web"
    SOURCE_CRYPTO = "source_crypto"
    LIVE_ONLY = "live_only"
    OUT_OF_BOUNDARY = "out_of_boundary"
    CATEGORICALLY_OFF = "categorically_off"


# Lanes we actively hunt (LIVE_ONLY only via the governed live_gate).
_PURSUABLE = frozenset({HuntLane.SOURCE_WEB, HuntLane.SOURCE_CRYPTO, HuntLane.LIVE_ONLY})


# Top-level VRT category (lowercased) -> default lane.
_CATEGORY_LANE: dict[str, HuntLane] = {
    # source-reviewable web/app/API classes — the core lane
    "broken access control (bac)": HuntLane.SOURCE_WEB,
    "broken authentication and session management": HuntLane.SOURCE_WEB,
    "server-side injection": HuntLane.SOURCE_WEB,
    "cross-site scripting (xss)": HuntLane.SOURCE_WEB,
    "cross-site request forgery (csrf)": HuntLane.SOURCE_WEB,
    "sensitive data exposure": HuntLane.SOURCE_WEB,
    "server security misconfiguration": HuntLane.SOURCE_WEB,
    "cryptographic weakness": HuntLane.SOURCE_WEB,
    "unvalidated redirects and forwards": HuntLane.SOURCE_WEB,
    "ai application security": HuntLane.SOURCE_WEB,
    "using components with known vulnerabilities": HuntLane.SOURCE_WEB,
    "client-side injection": HuntLane.SOURCE_WEB,
    # crypto / decentralized — the second lane
    "smart contract misconfiguration": HuntLane.SOURCE_CRYPTO,
    "decentralized application misconfiguration": HuntLane.SOURCE_CRYPTO,
    "blockchain infrastructure misconfiguration": HuntLane.SOURCE_CRYPTO,
    "zero knowledge security misconfiguration": HuntLane.SOURCE_CRYPTO,
    "protocol specific misconfiguration": HuntLane.SOURCE_CRYPTO,
    # only demonstrable live (route via live_gate)
    "cloud security": HuntLane.LIVE_ONLY,
    "insufficient security configurability": HuntLane.LIVE_ONLY,
    "privacy concerns": HuntLane.LIVE_ONLY,
    "indicators of compromise": HuntLane.LIVE_ONLY,
    # outside method/boundary (hardware/mobile-device/AD/physical/network gear)
    "insecure os/firmware": HuntLane.OUT_OF_BOUNDARY,
    "insecure data storage": HuntLane.OUT_OF_BOUNDARY,
    "insecure data transport": HuntLane.OUT_OF_BOUNDARY,
    "mobile security misconfiguration": HuntLane.OUT_OF_BOUNDARY,
    "lack of binary hardening": HuntLane.OUT_OF_BOUNDARY,
    "automotive security misconfiguration": HuntLane.OUT_OF_BOUNDARY,
    "physical security issues": HuntLane.OUT_OF_BOUNDARY,
    "network security misconfiguration": HuntLane.OUT_OF_BOUNDARY,
    "active directory (ad)": HuntLane.OUT_OF_BOUNDARY,
    # never pursued regardless of authorization
    "application-level denial-of-service (dos)": HuntLane.CATEGORICALLY_OFF,
    "external behavior": HuntLane.CATEGORICALLY_OFF,  # captcha bypass, autocomplete, etc. (mostly noise/off)
    "algorithmic biases": HuntLane.CATEGORICALLY_OFF,
    "data biases": HuntLane.CATEGORICALLY_OFF,
    "developer biases": HuntLane.CATEGORICALLY_OFF,
    "societal biases": HuntLane.CATEGORICALLY_OFF,
    "misinterpretation biases": HuntLane.CATEGORICALLY_OFF,
}

# Specific-name overrides that cut across categories (checked before the category).
# Keyed by a substring of the specific vulnerability name (lowercased).
_SPECIFIC_OVERRIDES: tuple[tuple[str, HuntLane], ...] = (
    ("denial-of-service", HuntLane.CATEGORICALLY_OFF),
    ("denial of service", HuntLane.CATEGORICALLY_OFF),
    ("resource consumption", HuntLane.CATEGORICALLY_OFF),
    ("captcha", HuntLane.CATEGORICALLY_OFF),
    ("phishing", HuntLane.CATEGORICALLY_OFF),
    ("social engineering", HuntLane.CATEGORICALLY_OFF),
    # command injection appears under Insecure OS/Firmware but is source-reviewable
    ("command injection", HuntLane.SOURCE_WEB),
    ("path traversal", HuntLane.SOURCE_WEB),
    ("server-side request forgery", HuntLane.SOURCE_WEB),
    ("server-side template injection", HuntLane.SOURCE_WEB),
    ("insufficient signature validation", HuntLane.SOURCE_CRYPTO),
)


@dataclass(frozen=True)
class Coverage:
    category: str
    specific: str | None
    lane: HuntLane
    pursuable: bool
    reason: str

    def __str__(self) -> str:  # pragma: no cover - convenience
        return f"[{self.lane.value}] {self.category}{'/' + self.specific if self.specific else ''} :: {self.reason}"


def _norm(s: str | None) -> str:
    return (s or "").strip().lower()


def classify(category: str, specific: str | None = None) -> Coverage:
    """Map a VRT (category, specific) to a hunt lane + whether we pursue it now.

    Fail-safe: an unknown category is routed to ``LIVE_ONLY`` (still governed by
    the live gate), never assumed pursuable-without-governance.
    """
    cat = _norm(category)
    spec = _norm(specific)

    # 1. Specific-name overrides win (a DoS/CAPTCHA/command-injection leaf regardless of category).
    for needle, lane in _SPECIFIC_OVERRIDES:
        if needle in spec or needle in cat:
            return Coverage(category, specific, lane, lane in _PURSUABLE,
                            f"specific-name rule matched {needle!r}")

    # 2. Top-level category default.
    lane = _CATEGORY_LANE.get(cat)
    if lane is not None:
        return Coverage(category, specific, lane, lane in _PURSUABLE, f"category default for {cat!r}")

    # 3. Unknown → fail to LIVE_ONLY (governed), not to a silent pass.
    return Coverage(category, specific, HuntLane.LIVE_ONLY, True,
                    "unknown VRT category — routed to the governed live lane")


def pursuable_now(category: str, specific: str | None = None) -> bool:
    """True if this class is in a lane the arsenal actively hunts."""
    return classify(category, specific).pursuable
