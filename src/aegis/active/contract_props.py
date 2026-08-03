"""Smart-contract safety-property analysis (lab-only; corpus web3 cluster).

A property-checking pass in the spirit of a formal AutoProver: it states the
safety properties a value-holding contract must uphold and flags where provided
Solidity source appears to violate them — the vectors that drain a protocol's TVL:

* **NoReentrancy** — no state-mutating value transfer performs an external call
  before it settles internal balances (checks-effects-interactions);
* **AccessControlledPrivileged** — every function that moves value, mints, or
  changes ownership/upgrades is guarded (modifier or ``msg.sender`` check);
* **ValueConservation** — value arithmetic is overflow-safe (>=0.8 or SafeMath,
  and no unchecked value math);
* **CheckedExternalCall** — a low-level ``.call`` return value is checked;
* **NoTxOriginAuth** — authorization does not rely on ``tx.origin``;
* **GuardedDestruct** — ``selfdestruct`` / ``delegatecall`` are access-controlled.

Purely static analysis over source the operator supplied for an **authorized**
engagement — no compilation, no execution, no chain interaction. Every finding is
a candidate (``verified=False``) that a human + a real prover must confirm; this
never touches a live protocol and asserts no disclosure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

_PRAGMA = re.compile(r"pragma\s+solidity\s+[\^>=~ ]*0\.(\d+)")
_FUNC = re.compile(r"function\s+(\w+)\s*\(([^)]*)\)([^{;]*)\{")
_EXTERNAL_CALL = re.compile(r"\.(call|delegatecall|transfer|send)\s*[\({]|\.call\{")
_VALUE_CALL = re.compile(r"\.call\s*\{[^}]*value\s*:|\.transfer\s*\(|\.send\s*\(")
_STATE_WRITE = re.compile(r"\b(balances?|balanceOf|deposits?|shares?)\b\s*\[[^\]]*\]\s*(=|-=|\+=)")
_AUTH_MODIFIER = re.compile(r"\b(onlyOwner|onlyAdmin|onlyRole|auth|restricted|onlyGovernance|requiresAuth)\b")
_SENDER_CHECK = re.compile(r"require\s*\(\s*msg\.sender\s*==|_checkOwner\s*\(|msg\.sender\s*==\s*owner")
#: Operations that must always be access-controlled regardless of recipient.
_HIGH_AUTHORITY = re.compile(
    r"\b(_?mint|setOwner|transferOwnership|upgradeTo|initialize|drain|sweep|rescue|_burn)\b|"
    r"selfdestruct\s*\(|\.delegatecall\s*\(|\bowner\s*=")
_VIEW = re.compile(r"\b(view|pure)\b")


class ContractProperty(str, Enum):
    NO_REENTRANCY = "NoReentrancy"
    ACCESS_CONTROLLED_PRIVILEGED = "AccessControlledPrivileged"
    VALUE_CONSERVATION = "ValueConservation"
    CHECKED_EXTERNAL_CALL = "CheckedExternalCall"
    NO_TX_ORIGIN_AUTH = "NoTxOriginAuth"
    GUARDED_DESTRUCT = "GuardedDestruct"


@dataclass(frozen=True)
class ContractFinding:
    property_violated: ContractProperty
    function: str
    line: int
    snippet: str
    severity: str
    confidence: float
    verified: bool = False


@dataclass
class _Function:
    name: str
    header: str
    body: str
    start_line: int
    guarded: bool


def analyze_solidity(source: str, *, path: str = "") -> list[ContractFinding]:
    source = source or ""
    pre_0_8 = _is_pre_0_8(source)
    uses_safemath = "SafeMath" in source
    findings: list[ContractFinding] = []

    for fn in _functions(source):
        base_line = fn.start_line

        # NoReentrancy: an external value transfer before an internal balance write.
        vloc = _search_line(fn.body, _VALUE_CALL)
        wloc = _search_line(fn.body, _STATE_WRITE)
        if vloc is not None and wloc is not None and wloc[0] > vloc[0]:
            findings.append(_finding(ContractProperty.NO_REENTRANCY, fn, base_line + vloc[0],
                                     vloc[1], "critical", 0.8))

        # AccessControlledPrivileged: fires on a high-authority op (mint/ownership/
        # upgrade/selfdestruct) OR a value transfer to an *arbitrary* recipient — a
        # withdraw that only moves the caller's own funds to msg.sender is self-scoped.
        priv = bool(_HIGH_AUTHORITY.search(fn.body)) or _has_arbitrary_transfer(fn.body)
        if priv and not fn.guarded and not _VIEW.search(fn.header) and _is_externally_callable(fn.header):
            findings.append(_finding(ContractProperty.ACCESS_CONTROLLED_PRIVILEGED, fn, base_line,
                                     fn.header.strip()[:120], "critical", 0.75))

        # GuardedDestruct: selfdestruct/delegatecall without a guard.
        dloc = _search_line(fn.body, re.compile(r"selfdestruct\s*\(|\.delegatecall\s*\("))
        if dloc is not None and not fn.guarded:
            findings.append(_finding(ContractProperty.GUARDED_DESTRUCT, fn, base_line + dloc[0],
                                     dloc[1], "critical", 0.8))

        # NoTxOriginAuth.
        tloc = _search_line(fn.body, re.compile(r"tx\.origin"))
        if tloc is not None:
            findings.append(_finding(ContractProperty.NO_TX_ORIGIN_AUTH, fn, base_line + tloc[0],
                                     tloc[1], "high", 0.7))

        # CheckedExternalCall: a low-level .call whose return isn't captured/checked.
        for ln, text in _lines(fn.body):
            if re.search(r"\.call\s*[\({]", text) and not re.search(
                    r"(\(?\s*bool\s+\w+\s*,|require\s*\(|if\s*\(|=\s*[\w(])", text):
                findings.append(_finding(ContractProperty.CHECKED_EXTERNAL_CALL, fn, base_line + ln,
                                         text.strip()[:120], "medium", 0.5))

        # ValueConservation: unsafe value arithmetic (pre-0.8 w/o SafeMath, or unchecked{}).
        aloc = _search_line(fn.body, re.compile(r"\b(balances?|amount|shares?|value)\b[^\n=]*[-+*]=|"
                                                r"[-+*]\s*\b(amount|balances?)\b"))
        if aloc is not None and pre_0_8 and not uses_safemath:
            findings.append(_finding(ContractProperty.VALUE_CONSERVATION, fn, base_line + aloc[0],
                                     aloc[1], "high", 0.6))
        uloc = _search_line(fn.body, re.compile(r"unchecked\s*\{"))
        if uloc is not None and re.search(r"[-+*]=|\+|\-", fn.body[fn.body.find("unchecked"):]):
            findings.append(_finding(ContractProperty.VALUE_CONSERVATION, fn, base_line + uloc[0],
                                     "unchecked value arithmetic", "high", 0.55))

    return findings


# --- parsing helpers -------------------------------------------------------

def _functions(source: str):
    for m in _FUNC.finditer(source):
        name = m.group(1)
        header = source[m.start():m.end()]
        body = _brace_body(source, m.end() - 1)
        start_line = source[:m.start()].count("\n") + 1
        guarded = bool(_AUTH_MODIFIER.search(header) or _SENDER_CHECK.search(body) or _AUTH_MODIFIER.search(body))
        yield _Function(name=name, header=header, body=body, start_line=start_line, guarded=guarded)


def _brace_body(source: str, open_idx: int) -> str:
    depth = 0
    for i in range(open_idx, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[open_idx + 1:i]
    return source[open_idx + 1:]


def _lines(text: str):
    return list(enumerate(text.splitlines()))


def _search_line(body: str, pattern):
    for ln, text in _lines(body):
        if pattern.search(text):
            return ln, text.strip()[:120]
    return None


def _is_pre_0_8(source: str) -> bool:
    m = _PRAGMA.search(source)
    return bool(m) and int(m.group(1)) < 8


def _has_arbitrary_transfer(body: str) -> bool:
    """A value transfer whose recipient is not ``msg.sender`` (i.e. a parameter)."""
    for _, text in _lines(body):
        if _VALUE_CALL.search(text) and "msg.sender" not in text:
            return True
    return False


def _is_externally_callable(header: str) -> bool:
    return bool(re.search(r"\b(public|external)\b", header)) or not re.search(
        r"\b(internal|private)\b", header)


def _finding(prop, fn, line, snippet, severity, confidence) -> ContractFinding:
    return ContractFinding(property_violated=prop, function=fn.name, line=line,
                           snippet=snippet, severity=severity, confidence=confidence)
