"""Property-driven contract analysis — infer invariants, emit runnable verification.

Inspired by the intent->specification->proof workflow (Certora AutoProver), but honest
about the split: an LLM is good at reading a contract and its docs and *proposing*
security properties; it is NOT a prover and cannot guarantee them. So this module does
the AI half — infer properties/invariants from source — and then emits **runnable test
files for real tools** (Foundry invariant tests, Halmos symbolic tests). The actual
proving/fuzzing is done by those tools, which give real guarantees; Aegis never claims
to have proved anything itself.

Fits the smart-contract lane: EtherscanSource / a .sol checkout provides the source,
this proposes properties + writes a test suite the operator runs with `forge` / `halmos`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .agents.contracts import Severity


class ContractProperty(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=80)          # a valid-ish identifier
    statement: str = Field(min_length=1, max_length=600)    # the invariant in plain language
    category: str = Field(pattern=r"^(access_control|arithmetic|reentrancy|state_machine|"
                          r"accounting|authorization|input_validation|other)$")
    severity_if_violated: Severity = "high"
    # a Solidity boolean expression that should ALWAYS hold (best-effort; the operator
    # adapts it to the real signatures). Kept simple so it renders into a test.
    invariant_expr: str = Field(default="", max_length=400)

    @property
    def ident(self) -> str:
        base = re.sub(r"[^A-Za-z0-9]", "", self.name) or "Property"
        return base[0].upper() + base[1:]


_SYSTEM = (
    "You are an authorized smart-contract security analyst. Read the supplied Solidity "
    "source (and any NatSpec) and propose the SECURITY PROPERTIES / INVARIANTS the "
    "contract must uphold — the things whose violation would be a vulnerability. Focus "
    "on access control, arithmetic/accounting conservation, reentrancy, state-machine "
    "ordering, and authorization. Each property must be a concrete claim about THIS "
    "contract's functions/state, not a generic platitude. Where you can, give a Solidity "
    "boolean expression that should always hold. Do not claim to prove anything.\n\n"
    "Return strict json: {\"properties\":[{\"name\": short identifier, \"statement\": the "
    "invariant in one sentence, \"category\": one of [access_control,arithmetic,"
    "reentrancy,state_machine,accounting,authorization,input_validation,other], "
    "\"severity_if_violated\": one of [critical,high,medium,low], \"invariant_expr\": a "
    "Solidity boolean expression or empty}]}"
)


class PropertyGenerator:
    """LLM proposes security properties for a contract. Proposals only — never proofs."""

    def __init__(self, client, *, max_properties: int = 12) -> None:
        self._client = client
        self._max = max(1, min(max_properties, 30))

    def infer(self, contract_source: str, *, docs: str = "") -> list[ContractProperty]:
        payload = {"source": contract_source[:110000], "docs": docs[:8000]}
        try:
            data = self._client.complete_json([
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": "Infer properties:\n" + json.dumps(payload)},
            ])
        except Exception:
            return []
        raw = data.get("properties") if isinstance(data, dict) else None
        if not isinstance(raw, list):
            return []
        out: list[ContractProperty] = []
        for item in raw[: self._max]:
            try:
                out.append(ContractProperty.model_validate(item))
            except ValidationError:
                continue
        return out


def render_foundry_test(properties: list[ContractProperty], *, contract_name: str) -> str:
    """A Foundry invariant-test skeleton — the operator fills setUp() and any handlers,
    then runs `forge test`. Foundry does the actual fuzzing; this is the harness."""
    lines = [
        "// SPDX-License-Identifier: MIT",
        "pragma solidity ^0.8.0;",
        "",
        'import "forge-std/Test.sol";',
        f'// import "../src/{contract_name}.sol";',
        "",
        f"/// @dev Aegis-proposed invariants for {contract_name}. FILL IN setUp() to deploy",
        "///      the contract (and any handler), then: forge test. These are PROPOSED",
        "///      properties for a real fuzzer to check — not proofs.",
        f"contract {contract_name}Invariants is Test {{",
        f"    // {contract_name} target;",
        "",
        "    function setUp() public {",
        f"        // target = new {contract_name}(...);   // FILL IN",
        "        // targetContract(address(target));",
        "    }",
        "",
    ]
    for prop in properties:
        expr = prop.invariant_expr.strip() or "true /* FILL IN: express the invariant */"
        lines += [
            f"    /// {prop.category} · {prop.severity_if_violated}: {prop.statement}",
            f"    function invariant_{prop.ident}() public view {{",
            f"        assertTrue({expr}, \"{prop.statement[:80]}\");",
            "    }",
            "",
        ]
    lines.append("}")
    return "\n".join(lines)


def render_halmos_test(properties: list[ContractProperty], *, contract_name: str) -> str:
    """A Halmos symbolic-test skeleton — `halmos` explores all inputs symbolically."""
    lines = [
        "// SPDX-License-Identifier: MIT",
        "pragma solidity ^0.8.0;",
        "",
        'import "forge-std/Test.sol";',
        "",
        f"/// @dev Aegis-proposed symbolic checks for {contract_name}. Run: halmos",
        f"contract {contract_name}Symbolic is Test {{",
    ]
    for prop in properties:
        expr = prop.invariant_expr.strip() or "true /* FILL IN */"
        lines += [
            f"    /// {prop.category}: {prop.statement}",
            f"    function check_{prop.ident}() public {{",
            "        // symbolic inputs via svm / vm; then assert the invariant holds",
            f"        assert({expr});",
            "    }",
            "",
        ]
    lines.append("}")
    return "\n".join(lines)


def write_property_suite(properties: list[ContractProperty], out_dir: str | Path, *,
                         contract_name: str) -> dict:
    """Write the Foundry + Halmos suites and a README; return the file paths."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    foundry = out / f"{contract_name}Invariants.t.sol"
    halmos = out / f"{contract_name}Symbolic.t.sol"
    readme = out / "README.md"
    foundry.write_text(render_foundry_test(properties, contract_name=contract_name), encoding="utf-8")
    halmos.write_text(render_halmos_test(properties, contract_name=contract_name), encoding="utf-8")
    readme.write_text(
        f"# Proposed invariants for {contract_name}\n\n"
        "Aegis (LLM) proposed these security properties from the contract source. They "
        "are **proposals, not proofs** — run them with real tools:\n\n"
        "- Fuzz: `forge test` on the `*Invariants.t.sol` harness (fill in `setUp()`).\n"
        "- Symbolic: `halmos` on the `*Symbolic.t.sol` file.\n\n"
        "## Properties\n" +
        "".join(f"- **[{p.category}/{p.severity_if_violated}] {p.name}** — {p.statement}\n"
                for p in properties),
        encoding="utf-8")
    return {"foundry": str(foundry), "halmos": str(halmos), "readme": str(readme),
            "count": len(properties)}
