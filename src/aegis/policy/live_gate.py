"""Governed live-action gate — the engine that lets a LIVE bounty action fire.

A live action against a third-party bounty target is only permitted when EVERY
authority agrees:

  1. **Eligibility** — the target is submittable on the program's *current* policy
     (:func:`aegis.policy.program_eligibility.verify_target`): in-scope, not
     excluded, pays, not suspended. (This is the precondition that was missing;
     it is why pipelinewise/Nextcloud/Netflix work was wasted.)
  2. **Signed scope** — the target host is inside the operator's authorized scope
     allowlist (:class:`aegis.policy.scope.ScopeGuard`).
  3. **Action class** — the action is not in the categorically-prohibited set
     (CAPTCHA bypass, DoS, mass scanning/account creation, destructive/real-data
     mutation, detection evasion, credential stuffing, MITM) — denied regardless
     of any grant.
  4. **Signed capability** — a verified ``ExecutionGrant`` confers network
     authority (delegated to the existing ``ProposalPolicy``; no new authority is
     minted here).
  5. **Human approval for consequential actions** — RCE/exploit, writes, real-data
     access, or anything irreversible require a valid signed ``HumanApprovalReceipt``
     bound to the finding; without it the verdict is ``ESCALATE`` (ask a human),
     never a silent ``ALLOW``.

This module adds NO new authority — it *composes* the existing single-authority
kernel (``ProposalPolicy`` / ``ExecutionGrant`` / ``HumanApprovalReceipt``) with
the eligibility gate. ``ProposalPolicy``/proposal/authorization/receipt are taken
duck-typed so this stays lightweight and independent of the heavy agentic layer.
Fail-closed: any error or missing authority yields ``DENY``/``ESCALATE``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from aegis.policy.program_eligibility import Eligibility, verify_target
from aegis.policy.scope import ScopeGuard, normalize_host

__all__ = [
    "LiveVerdict",
    "LiveDecision",
    "evaluate_live_action",
    "PROHIBITED_ACTION_CLASSES",
    "CONSEQUENTIAL_ACTION_CLASSES",
]


class LiveVerdict(str, Enum):
    ALLOW = "allow"          # every authority agrees — the action may fire
    ESCALATE = "escalate"    # needs a human approval receipt before it can fire
    DENY = "deny"            # categorically refused (prohibited / ineligible / out of scope / no grant)


# Categorically off regardless of any grant or operator greenlight (mirrors the
# live-attack boundary + assistant policy: no DoS, no mass targeting, no
# detection evasion, no destructive or real-data-mutating actions).
PROHIBITED_ACTION_CLASSES = frozenset({
    "captcha_bypass", "bot_detection_bypass",
    "dos", "resource_exhaustion", "mass_scan", "broad_scan",
    "mass_account_create", "account_bruteforce", "credential_stuffing",
    "destructive", "data_destruction", "data_mutation_real", "mitm",
    "detection_evasion", "phishing", "social_engineering",
})

# Permitted only with a valid HumanApprovalReceipt (never fully autonomous).
CONSEQUENTIAL_ACTION_CLASSES = frozenset({
    "rce", "exploit", "code_execution",
    "data_write", "state_change", "real_data_access",
    "irreversible", "account_takeover", "fund_transfer",
})


class _Policy(Protocol):  # pragma: no cover - structural type
    def evaluate(self, proposal: Any, authorization: Any) -> Any: ...


class _Receipt(Protocol):  # pragma: no cover - structural type
    def verify(self, verifier: Any, finding_id: str, key_id: str = ...) -> bool: ...


@dataclass(frozen=True)
class LiveDecision:
    verdict: LiveVerdict
    target: str
    action_class: str
    eligibility: Eligibility | None
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def allowed(self) -> bool:
        return self.verdict is LiveVerdict.ALLOW

    def __str__(self) -> str:  # pragma: no cover - convenience
        return f"[{self.verdict.value}] {self.action_class} -> {self.target} :: {'; '.join(self.reasons)}"


def evaluate_live_action(
    *,
    program: dict,
    target: str,
    action_class: str,
    proposal: Any,
    authorization: Any,
    policy: _Policy,
    scope_targets: list[str],
    eligibility_allow: tuple[Eligibility, ...] = (Eligibility.SUBMITTABLE,),
    approval_receipt: _Receipt | None = None,
    verifier: Any = None,
    finding_id: str | None = None,
) -> LiveDecision:
    """Compose all authorities into a single live-action verdict (fail-closed).

    Args:
        program: the program record (fed to the eligibility gate).
        target: the concrete target (host or URL) the action would hit.
        action_class: a coarse class string (see the two class sets above).
        proposal, authorization, policy: the existing kernel objects — ``policy``
            must expose ``evaluate(proposal, authorization) -> Decision(.approved, .reason)``.
        scope_targets: the operator's signed in-scope allowlist.
        eligibility_allow: which eligibility verdicts may proceed (default: cash-submittable).
        approval_receipt, verifier, finding_id: for consequential actions, a signed
            ``HumanApprovalReceipt`` bound to ``finding_id``.
    """
    reasons: list[str] = []
    ac = (action_class or "").strip().lower()

    # 1. Categorically-prohibited classes — denied regardless of any grant.
    if ac in PROHIBITED_ACTION_CLASSES:
        return LiveDecision(LiveVerdict.DENY, target, ac, None,
                            (f"action class {ac!r} is categorically prohibited",))

    # 2. Program-policy eligibility (the missing precondition).
    elig = verify_target(program, target)
    if elig.verdict not in eligibility_allow:
        return LiveDecision(LiveVerdict.DENY, target, ac, elig.verdict,
                            tuple(f"eligibility gate: {r}" for r in elig.reasons)
                            or (f"target not eligible ({elig.verdict.value})",))
    reasons.append(f"eligible ({elig.verdict.value}, cash={elig.pays_cash})")

    # 3. Signed scope allowlist — target host must be inside it.
    try:
        host = normalize_host(target)
    except ValueError as exc:
        return LiveDecision(LiveVerdict.DENY, target, ac, elig.verdict,
                            (f"unparseable target host: {exc}",))
    if not ScopeGuard(scope_targets).is_allowed(host):
        return LiveDecision(LiveVerdict.DENY, target, ac, elig.verdict,
                            tuple(reasons) + (f"host {host} is outside the signed scope allowlist",))
    reasons.append(f"host {host} in signed scope")

    # 4. Signed capability / budget — delegate to the existing kernel policy.
    try:
        decision = policy.evaluate(proposal, authorization)
    except Exception as exc:  # fail closed on any policy error
        return LiveDecision(LiveVerdict.DENY, target, ac, elig.verdict,
                            tuple(reasons) + (f"policy evaluation error (fail-closed): {exc}",))
    if not getattr(decision, "approved", False):
        return LiveDecision(LiveVerdict.DENY, target, ac, elig.verdict,
                            tuple(reasons) + (f"kernel policy denied: {getattr(decision, 'reason', 'no reason')}",))
    reasons.append("kernel policy authorized (grant/budget ok)")

    # 5. Consequential actions require a valid human approval receipt.
    if ac in CONSEQUENTIAL_ACTION_CLASSES:
        ok = False
        if approval_receipt is not None and finding_id is not None:
            try:
                ok = bool(approval_receipt.verify(verifier, finding_id))
            except Exception:
                ok = False
        if not ok:
            return LiveDecision(LiveVerdict.ESCALATE, target, ac, elig.verdict,
                                tuple(reasons) + (f"consequential action {ac!r} needs a valid "
                                                  "HumanApprovalReceipt bound to the finding",))
        reasons.append("human approval receipt verified")

    return LiveDecision(LiveVerdict.ALLOW, target, ac, elig.verdict, tuple(reasons))
