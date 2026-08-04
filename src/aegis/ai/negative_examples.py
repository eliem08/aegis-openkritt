"""Negative exemplars — the shapes that get reports REJECTED — for the generator.

Retrieval shows the model what real disclosed bugs look like. This shows the opposite:
the recurring non-bug shapes that programs close as Not Applicable / Informative /
intended behaviour. Injecting them at generation time cuts the trust-model false
positives before they are ever produced, instead of only catching them at validation.

Original descriptions, distilled from this project's own false positives and the
standard out-of-scope classes bounty programs publish.
"""

from __future__ import annotations

# Each: a short label and the reason it is NOT a vulnerability.
_NEGATIVES: tuple[tuple[str, str], ...] = (
    ("intended-functionality",
     "behaviour the code's own comments/docs describe as intended, or that a role is "
     "designed to have (a lender seeing borrower data, an admin managing users)."),
    ("requires-privileged-access",
     "reachable only by an actor who already holds admin/owner/operator rights the "
     "system trusts by design — unless it bypasses a FURTHER control on top of that."),
    ("credential-after-auth-failure",
     "a token/credential left in a header AFTER authentication failed: the request is "
     "rejected, so nothing downstream ever consumes it."),
    ("verified-claim-injection",
     "unescaped use of a value that is a verified identity-provider claim (an IdP email) "
     "which cannot contain the dangerous metacharacter."),
    ("pre-auth-token-gated-csrf",
     "a missing CSRF token on a PRE-AUTH flow gated by a secret token from an email link: "
     "CSRF needs an authenticated victim's ambient session; there is none, and an "
     "attacker who knew the token would not need CSRF."),
    ("missing-defense-in-depth",
     "a 'should also validate X' / missing hardening where no attacker path exists and "
     "the primary control already holds."),
    ("self-only-impact",
     "an action that only affects the attacker's own account/session with no cross-user "
     "or privilege-escalation effect (self-XSS, own-data manipulation)."),
    ("non-production-only",
     "a flaw whose only location is test/example/mock/generated code or a local dev "
     "helper the shipped product never runs."),
    ("already-compromised-precondition",
     "requires an already-leaked key, a failed RNG, a malicious administrator, or a "
     "trusted attester turning hostile — the precondition is the real breach."),
    ("config-not-code",
     "an operator/deployment misconfiguration (file permissions, TLS/CSP settings, "
     "resource limits) the code under review does not control."),
)


def negative_examples_text() -> str:
    """A compact 'these get rejected — do not report them' block for the generator."""
    lines = [
        "\n## Do NOT report these (they are closed as Not Applicable / intended)",
        "If your finding matches one of these shapes, omit it — reporting it is penalized:",
    ]
    for label, reason in _NEGATIVES:
        lines.append(f"- {label}: {reason}")
    return "\n".join(lines)
