"""Governed live (``live_only``) lane — a planner + gate, never an executor.

:mod:`aegis.policy.vrt_coverage` decides that a VRT class is ``LIVE_ONLY`` (only
demonstrable against a running target). This lane decides *whether a proposed live
check may fire* by composing the existing :mod:`aegis.policy.live_gate`
(eligibility + signed scope + action-class rules + kernel grant + human approval for
consequential actions). It performs **no network I/O**: it returns a
:class:`LiveLaneReport` carrying the gate verdict and, when a human must approve, a
serialisable *approval packet* describing the exact non-destructive check.

Why a planner and not an executor: the autonomous hunt routine runs **unsupervised**
in the cloud, where no human is present to approve a consequential action. There it
must only emit approval packets. In a **supervised** session an operator can sign a
``HumanApprovalReceipt`` and the same gate will then ``ALLOW`` the action — so the
decision is identical code, driven by whether an approval receipt is present, never by
a boolean "trust me". Read-only observations (headers, TLS, DNS, banners, redirects)
are non-consequential and the gate may ``ALLOW`` them without a receipt; anything that
mutates state, authenticates, or exploits is consequential and ``ESCALATE``\\ s.

This module mints no new authority — it only routes to and reports the live_gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aegis.policy.live_gate import (
    CONSEQUENTIAL_ACTION_CLASSES,
    LiveDecision,
    LiveVerdict,
    evaluate_live_action,
)
from aegis.policy.program_eligibility import Eligibility
from aegis.policy.vrt_coverage import HuntLane, classify

__all__ = [
    "READ_ONLY_ACTION_CLASS",
    "LiveLaneReport",
    "action_class_for",
    "plan_live_check",
]

# The non-consequential class for pure read-only observation of a live response.
READ_ONLY_ACTION_CLASS = "recon_read"

# Live-only leaves confirmable by *reading* a live response — headers, TLS, DNS,
# banners, error pages, a followed redirect. Non-consequential: the gate can ALLOW
# them without a human receipt. Everything not matched here fails safe to a
# consequential class (needs approval).
_READONLY_NEEDLES = (
    "security headers", "insecure ssl", "insecure cipher", "forward secrecy",
    "dns", "dnssec", "banner", "fingerprinting", "directory listing",
    "mixed content", "graphql introspection", "internal ip disclosure",
    "visible detailed error", "error/debug", "debug page", "cors",
    "cross-origin resource sharing", "mail server", "email spoofing",
    "dmarc", "dkim", "spf", "open redirect", "clickjacking", "referer",
)


def action_class_for(vrt_category: str, vrt_specific: str | None = None) -> str:
    """Map a live-only VRT leaf to a coarse action class the live_gate understands.

    Fail-safe: an unrecognised live action is treated as ``state_change``
    (consequential → the gate will ESCALATE for human approval), never as read-only.
    """
    hay = f"{(vrt_specific or '').lower()} {(vrt_category or '').lower()}"
    if "remote code" in hay or "rce" in hay:
        return "rce"
    if "takeover" in hay:  # e.g. subdomain takeover, account takeover — consequential
        return "account_takeover"
    for needle in _READONLY_NEEDLES:
        if needle in hay:
            return READ_ONLY_ACTION_CLASS
    return "state_change"


@dataclass
class LiveLaneReport:
    lane: str
    pursued: bool
    target: str
    action_class: str
    decision: LiveDecision | None = None
    approval_packet: dict | None = None
    skipped_reason: str | None = None

    @property
    def verdict(self) -> LiveVerdict | None:
        return self.decision.verdict if self.decision else None

    @property
    def needs_human(self) -> bool:
        return bool(self.decision and self.decision.verdict is LiveVerdict.ESCALATE)

    @property
    def allowed(self) -> bool:
        return bool(self.decision and self.decision.allowed)


def plan_live_check(
    *,
    program: dict,
    target: str,
    vrt_category: str,
    vrt_specific: str | None = None,
    check_description: str,
    proposal: Any,
    authorization: Any,
    policy: Any,
    scope_targets: list[str],
    action_class: str | None = None,
    approval_receipt: Any = None,
    verifier: Any = None,
    finding_id: str | None = None,
    eligibility_allow: tuple[Eligibility, ...] = (Eligibility.SUBMITTABLE,),
) -> LiveLaneReport:
    """Plan (and gate) one live check for a ``LIVE_ONLY`` VRT class.

    Returns a :class:`LiveLaneReport`. If the class does not route to
    ``LIVE_ONLY`` the report is ``pursued=False`` with a ``skipped_reason`` (this
    lane is only for live-only classes; source/crypto/off are handled elsewhere).
    When the gate verdict is ``ESCALATE`` an ``approval_packet`` is attached for a
    human to review and sign. This function never touches the network.
    """
    cov = classify(vrt_category, vrt_specific)
    if cov.lane is not HuntLane.LIVE_ONLY:
        return LiveLaneReport(
            lane=cov.lane.value, pursued=False, target=target, action_class="",
            skipped_reason=(
                f"class routes to {cov.lane.value}, not live_only "
                f"({cov.reason}); use the source-web / crypto / off handling instead"
            ),
        )

    ac = action_class or action_class_for(vrt_category, vrt_specific)
    decision = evaluate_live_action(
        program=program, target=target, action_class=ac,
        proposal=proposal, authorization=authorization, policy=policy,
        scope_targets=scope_targets, eligibility_allow=eligibility_allow,
        approval_receipt=approval_receipt, verifier=verifier, finding_id=finding_id,
    )

    packet: dict | None = None
    if decision.verdict is LiveVerdict.ESCALATE:
        packet = {
            "finding_id": finding_id,
            "program": str(program.get("handle") or program.get("url") or "?"),
            "target": target,
            "vrt": {"category": vrt_category, "specific": vrt_specific},
            "action_class": ac,
            "consequential": ac in CONSEQUENTIAL_ACTION_CLASSES,
            "check": check_description,
            "verdict": decision.verdict.value,
            "reasons": list(decision.reasons),
            "to_approve": (
                "operator: sign a HumanApprovalReceipt bound to finding_id, then "
                "re-run this check in a supervised session"
            ),
        }

    return LiveLaneReport(
        lane=cov.lane.value, pursued=True, target=target, action_class=ac,
        decision=decision, approval_packet=packet,
    )
