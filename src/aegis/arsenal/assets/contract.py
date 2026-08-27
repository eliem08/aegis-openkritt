"""Smart contract techniques: external static analysis plus contrast-driven patterns.

Two lanes run side by side. ``static_analysis`` shells out to slither/mythril when
they are installed (or reachable through ``Dockerfile.arsenal``) and normalizes
their JSON. ``pattern_review`` is a self-contained reader that never needs a
toolchain, and is written around the contrast the operator's method depends on: a
state-mutating function is only interesting when *comparable* functions in the same
contract carry the guard it is missing. A contract where nothing is guarded is a
design choice; a contract where one withdraw path forgot the modifier is a bug.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from .context import LaneContext
from .results import (
    Observation,
    TechniqueResult,
    deduplicate,
    executed,
    now,
    unavailable,
    waiting,
)

_SOURCE_SUFFIXES = frozenset({".sol", ".vy"})

_FUNCTION = re.compile(
    r"function\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^)]*)\)\s*(?P<modifiers>[^{;]*)\{",
    re.MULTILINE,
)
_CONTRACT = re.compile(r"\b(?:contract|library|interface)\s+([A-Za-z_]\w*)")
_STATE_WRITE = re.compile(r"^\s*(?!//)(?:[A-Za-z_]\w*)(?:\[[^\]]*\]|\.\w+)*\s*(?:=|\+=|-=)")
_EXTERNAL_CALL = re.compile(
    r"\.(?P<kind>call|delegatecall|staticcall|send|transfer)\s*(?:\{[^}]*\})?\s*\(",
)
_ACCESS_MODIFIERS = re.compile(
    r"\b(only\w*|auth|restricted|requiresAuth|nonReentrant|governance\w*)\b", re.IGNORECASE,
)
_MSG_SENDER_GUARD = re.compile(
    r"(?:require|assert|if)\s*\([^)]*msg\.sender[^)]*\)|revert\s+\w*Unauthorized",
)
_ORACLE_SPOT_PRICE = re.compile(
    r"\b(getReserves|balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)|"
    r"slot0|getAmountsOut|latestAnswer)\b",
)
_PROXY_MARKERS = re.compile(
    r"\b(delegatecall|Initializable|UUPSUpgradeable|TransparentUpgradeableProxy|"
    r"_authorizeUpgrade|upgradeTo|__gap)\b",
)
_INITIALIZER = re.compile(r"\b(initialize|__init|_init)\w*\s*\(")


@dataclass(frozen=True, slots=True)
class ContractFunction:
    """One parsed function body with the facts the pattern rules need."""

    contract: str
    name: str
    visibility: str
    modifiers: tuple[str, ...]
    body: str
    line: int

    @property
    def guarded(self) -> bool:
        return bool(self.modifiers) or bool(_MSG_SENDER_GUARD.search(self.body))

    @property
    def mutates_state(self) -> bool:
        if any(token in self.visibility for token in ("view", "pure")):
            return False
        return any(_STATE_WRITE.match(line) for line in self.body.splitlines())

    @property
    def externally_reachable(self) -> bool:
        return "public" in self.visibility or "external" in self.visibility

    def document(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("body", None)
        value["guarded"] = self.guarded
        return value


def parse_contract(source: str, *, path: str = "") -> tuple[ContractFunction, ...]:
    """Extract functions with brace-balanced bodies from Solidity source.

    A regular expression cannot parse Solidity in general; this deliberately does
    the narrow job of finding function headers and then walking braces to recover
    the body. Anything it fails to bracket is skipped rather than half-parsed.
    """
    contract_name = ""
    functions: list[ContractFunction] = []
    for match in _FUNCTION.finditer(source):
        preceding = source[: match.start()]
        contracts = _CONTRACT.findall(preceding)
        contract_name = contracts[-1] if contracts else (path or "unknown")
        body = _balanced_body(source, match.end() - 1)
        if body is None:
            continue
        raw_modifiers = match.group("modifiers") or ""
        visibility = " ".join(
            token for token in raw_modifiers.split()
            if token in {"public", "private", "internal", "external", "view", "pure",
                         "payable"}
        )
        modifiers = tuple(dict.fromkeys(_ACCESS_MODIFIERS.findall(raw_modifiers)))
        functions.append(ContractFunction(
            contract_name, match.group("name"), visibility, modifiers, body,
            preceding.count("\n") + 1,
        ))
    return tuple(functions)


def _balanced_body(source: str, open_index: int) -> str | None:
    depth = 0
    for index in range(open_index, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[open_index + 1: index]
    return None


def _sources(context: LaneContext) -> tuple[Path, ...]:
    root = context.artifact_path
    if root is None:
        return ()
    path = Path(root)
    if path.is_file():
        return (path,) if path.suffix.lower() in _SOURCE_SUFFIXES else ()
    if path.is_dir():
        return tuple(sorted(
            item for item in path.rglob("*")
            if item.is_file() and item.suffix.lower() in _SOURCE_SUFFIXES
            and "node_modules" not in item.parts and "lib" not in item.parts[:1]
        ))
    return ()


# ------------------------------------------------------------------ techniques

def static_analysis(context: LaneContext) -> TechniqueResult:
    """Run slither, falling back to mythril, and normalize whichever produced output."""
    technique = "contract-static-analysis"
    started = now()
    sources = _sources(context)
    if not sources:
        return waiting(
            technique, context.asset,
            "no Solidity/Vyper source supplied; pass --artifact pointing at a .sol/.vy "
            "file or a contracts directory",
        )
    target = Path(context.artifact_path)  # type: ignore[arg-type]
    mount = target if target.is_dir() else target.parent

    slither = context.resolver.resolve("slither")
    if slither.usable:
        code, stdout, stderr = context.resolver.run(
            slither, [str(target), "--json", "-"], mounts=[str(mount)], timeout=900.0,
        )
        if stdout.strip():
            observations = parse_slither(stdout, technique)
            return executed(
                technique, context.asset, deduplicate(observations), tool="slither",
                tool_version=slither.version, started_at=started,
                metadata={"location": slither.location.value, "exit_code": code,
                          "sources": [str(item) for item in sources]},
            )
        slither_reason = f"slither produced no JSON ({stderr.strip()[:200]})"
    else:
        slither_reason = f"slither unavailable ({slither.reason})"

    mythril = context.resolver.first_available(["myth", "mythril"])
    if mythril is not None and target.is_file():
        code, stdout, stderr = context.resolver.run(
            mythril, ["analyze", str(target), "-o", "json"], mounts=[str(mount)],
            timeout=1200.0,
        )
        if stdout.strip():
            observations = parse_mythril(stdout, technique)
            return executed(
                technique, context.asset, deduplicate(observations), tool="mythril",
                tool_version=mythril.version, started_at=started,
                reason=slither_reason,
                metadata={"location": mythril.location.value, "exit_code": code},
            )

    return unavailable(
        technique, context.asset,
        f"{slither_reason}; mythril was also not usable. Install slither "
        "(`pip install slither-analyzer`) or build the arsenal image with "
        "`docker build -f Dockerfile.arsenal -t aegis-arsenal .`. The pattern-review "
        "technique still ran and its result stands on its own.",
        tool="slither",
    )


_SLITHER_SEVERITY = {
    "High": "high", "Medium": "medium", "Low": "low",
    "Informational": "info", "Optimization": "info",
}


def parse_slither(payload: str, technique: str = "contract-static-analysis",
                  ) -> tuple[Observation, ...]:
    """Normalize slither's ``--json -`` document into observations."""
    try:
        document = json.loads(payload)
    except json.JSONDecodeError:
        return ()
    results = document.get("results") if isinstance(document, dict) else None
    detectors = results.get("detectors") if isinstance(results, dict) else None
    if not isinstance(detectors, list):
        return ()
    observations: list[Observation] = []
    for item in detectors:
        if not isinstance(item, dict):
            continue
        elements = item.get("elements") or []
        subject = ""
        if isinstance(elements, list) and elements and isinstance(elements[0], dict):
            mapping = elements[0].get("source_mapping") or {}
            subject = "{}:{}".format(
                mapping.get("filename_short") or mapping.get("filename_relative") or "",
                (mapping.get("lines") or [0])[0],
            )
        observations.append(Observation(
            technique, str(item.get("check") or "slither detector"),
            _SLITHER_SEVERITY.get(str(item.get("impact")), "info"),
            subject or str(item.get("check") or "contract"),
            evidence={"description": str(item.get("description") or "")[:2000],
                      "confidence": str(item.get("confidence") or ""),
                      "detector": str(item.get("check") or "")},
            weakness=str(item.get("check") or ""),
            confidence=str(item.get("confidence") or "unverified").lower(),
            recommendation="slither output is a lead; confirm reachability and impact",
        ))
    return tuple(observations)


def parse_mythril(payload: str, technique: str = "contract-static-analysis",
                  ) -> tuple[Observation, ...]:
    """Normalize mythril's JSON output into observations."""
    try:
        document = json.loads(payload)
    except json.JSONDecodeError:
        return ()
    issues = document.get("issues") if isinstance(document, dict) else document
    if not isinstance(issues, list):
        return ()
    severities = {"High": "high", "Medium": "medium", "Low": "low"}
    return tuple(
        Observation(
            technique, str(item.get("title") or "mythril issue"),
            severities.get(str(item.get("severity")), "info"),
            f"{item.get('filename', '')}:{item.get('lineno', 0)}",
            evidence={"description": str(item.get("description") or "")[:2000],
                      "swc_id": str(item.get("swc-id") or "")},
            weakness=str(item.get("swc-id") or item.get("title") or ""),
            recommendation="symbolic-execution lead; confirm the path is reachable on-chain",
        )
        for item in issues if isinstance(item, dict)
    )


def pattern_review(context: LaneContext) -> TechniqueResult:
    """Contrast-driven weakness review that needs no external toolchain."""
    technique = "contract-pattern-review"
    started = now()
    sources = _sources(context)
    if not sources:
        return waiting(
            technique, context.asset, "no Solidity/Vyper source supplied via --artifact",
        )
    observations: list[Observation] = []
    reviewed: list[str] = []
    for path in sources:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        reviewed.append(path.name)
        functions = parse_contract(source, path=path.name)
        observations.extend(_access_control(functions, path.name, technique))
        observations.extend(_reentrancy(functions, path.name, technique))
        observations.extend(_unchecked_calls(functions, path.name, technique))
        observations.extend(_oracle_manipulation(functions, path.name, technique))
        observations.extend(_upgradeability(source, functions, path.name, technique))
    if not reviewed:
        return unavailable(
            technique, context.asset, "no contract source could be read",
            tool="aegis-contract-patterns",
        )
    return executed(
        technique, context.asset, deduplicate(observations),
        tool="aegis-contract-patterns", started_at=started,
        metadata={"files_reviewed": reviewed, "file_count": len(reviewed)},
    )


def _access_control(
    functions: Iterable[ContractFunction], path: str, technique: str,
) -> list[Observation]:
    """An unguarded state mutator is only reported when siblings *are* guarded."""
    functions = list(functions)
    guarded = [
        item for item in functions
        if item.externally_reachable and item.mutates_state and item.guarded
    ]
    if not guarded:
        return []  # nothing is guarded: a design choice, not a missing modifier.
    modifier_vocabulary = sorted({m for item in guarded for m in item.modifiers})
    output = []
    for item in functions:
        if not (item.externally_reachable and item.mutates_state) or item.guarded:
            continue
        output.append(Observation(
            technique, "Externally callable state mutator has no access-control guard",
            "high", f"{path}:{item.contract}.{item.name}",
            evidence={"visibility": item.visibility, "line": item.line,
                      "guarded_siblings": [
                          f"{other.contract}.{other.name}" for other in guarded[:5]
                      ]},
            guarded_sibling=(
                f"sibling mutators in the same contract carry {modifier_vocabulary[:3]}"
            ),
            weakness="missing-access-control",
            recommendation="trace what the written state controls before assigning impact",
        ))
    return output


def _reentrancy(
    functions: Iterable[ContractFunction], path: str, technique: str,
) -> list[Observation]:
    """External call before a state write in the same body: checks-effects violated."""
    output = []
    for item in functions:
        call = _EXTERNAL_CALL.search(item.body)
        if call is None or call.group("kind") in {"staticcall"}:
            continue
        if "nonReentrant" in item.modifiers:
            continue
        after = item.body[call.end():]
        writes_after = [
            line.strip() for line in after.splitlines() if _STATE_WRITE.match(line)
        ]
        if not writes_after:
            continue
        output.append(Observation(
            technique, "State written after an external call (checks-effects-interactions)",
            "high", f"{path}:{item.contract}.{item.name}",
            evidence={"external_call": call.group("kind"), "line": item.line,
                      "post_call_writes": writes_after[:5],
                      "has_reentrancy_guard": False},
            guarded_sibling="",
            weakness="reentrancy",
            recommendation="confirm the callee is attacker-controlled and the written "
                           "state is read by the same path before reporting",
        ))
    return output


def _unchecked_calls(
    functions: Iterable[ContractFunction], path: str, technique: str,
) -> list[Observation]:
    output = []
    for item in functions:
        for match in _EXTERNAL_CALL.finditer(item.body):
            if match.group("kind") not in {"call", "send", "delegatecall"}:
                continue
            window = item.body[max(0, match.start() - 200): match.end() + 200]
            if re.search(r"\brequire\s*\(|\bif\s*\(\s*!?\s*(?:ok|success|sent)\b|"
                         r"\(\s*bool\s+\w+\s*,", window):
                continue
            output.append(Observation(
                technique, f"Return value of low-level {match.group('kind')} is unchecked",
                "medium", f"{path}:{item.contract}.{item.name}",
                evidence={"call_kind": match.group("kind"), "line": item.line},
                weakness="unchecked-external-call",
                recommendation="a silent failure is only impactful if the caller assumes "
                               "the transfer succeeded; show that assumption",
            ))
    return output


def _oracle_manipulation(
    functions: Iterable[ContractFunction], path: str, technique: str,
) -> list[Observation]:
    output = []
    for item in functions:
        match = _ORACLE_SPOT_PRICE.search(item.body)
        if match is None:
            continue
        if re.search(r"\b(TWAP|twap|consult|observe|cumulative|timeWeighted)\b", item.body):
            continue
        output.append(Observation(
            technique, "Price derived from a manipulable spot source", "high",
            f"{path}:{item.contract}.{item.name}",
            evidence={"source": match.group(0), "line": item.line,
                      "time_weighted_alternative_used": False},
            guarded_sibling="",
            weakness="oracle-manipulation",
            recommendation="show the value feeds a solvency or pricing decision; a spot "
                           "read used only for display is not exploitable",
        ))
    return output


def _upgradeability(
    source: str, functions: Iterable[ContractFunction], path: str, technique: str,
) -> list[Observation]:
    if not _PROXY_MARKERS.search(source):
        return []
    output: list[Observation] = []
    for item in functions:
        if not _INITIALIZER.match(f"{item.name}("):
            continue
        if "initializer" in " ".join(item.modifiers).lower() or item.guarded:
            continue
        if re.search(r"\binitialized\b|\brequire\s*\(\s*!\s*\w*[Ii]nit", item.body):
            continue
        output.append(Observation(
            technique, "Upgradeable initializer is callable without an initializer guard",
            "high", f"{path}:{item.contract}.{item.name}",
            evidence={"line": item.line, "modifiers": list(item.modifiers)},
            guarded_sibling="",
            weakness="unprotected-initializer",
            recommendation="confirm the implementation is not already initialized on-chain",
        ))
    if "__gap" not in source and re.search(r"\bUUPSUpgradeable|Initializable\b", source):
        output.append(Observation(
            technique, "Upgradeable contract declares no storage gap", "low", path,
            evidence={"storage_gap_present": False},
            weakness="proxy-storage-collision",
            recommendation="a future upgrade could collide storage; informational unless "
                           "an upgrade is already staged",
        ))
    if re.search(r"\b_authorizeUpgrade\s*\([^)]*\)\s*internal\s+override\s*\{\s*\}", source):
        output.append(Observation(
            technique, "UUPS upgrade authorization hook is empty", "critical", path,
            evidence={"hook": "_authorizeUpgrade", "body": "empty"},
            guarded_sibling="the OpenZeppelin pattern requires an owner or role check here",
            weakness="unprotected-upgrade",
            recommendation="anyone can replace the implementation; verify on-chain before "
                           "reporting, since a deployed proxy may use a different hook",
        ))
    return output


__all__ = [
    "ContractFunction",
    "parse_contract",
    "parse_mythril",
    "parse_slither",
    "pattern_review",
    "static_analysis",
]
