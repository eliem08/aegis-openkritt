"""Crypto (source_crypto) lane orchestrator.

The Solidity analysis engine already exists per-file (``contract_static_pipeline``
runs Slither/Mythril on one SHA-bound ``.sol`` in a sandbox). This orchestrator is
the missing lane wiring: given a cloned contract repo, it (1) confirms via the VRT
bridge that the class routes to the ``SOURCE_CRYPTO`` lane, (2) discovers the real
contract sources (skipping vendored/test/mocks), and (3) runs the per-file pipeline
across them, aggregating + de-duplicating candidates.

The per-file pipeline runner is injectable (``pipeline_runner``) so this module is
unit-testable without Slither/Mythril — those tools only run in the Linux arsenal
image, not on every dev box.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from aegis.policy.vrt_coverage import HuntLane

from .contract_static_pipeline import ContractStaticReport, run_contract_static_pipeline
from .vrt_bridge import hunt_plan_for_vrt

__all__ = ["CryptoLaneReport", "discover_solidity_sources", "run_crypto_lane"]

# Directories that hold dependencies / tests / build output, not the audited contracts.
_EXCLUDE_DIR_SEGMENTS = frozenset({
    "node_modules", ".git", "lib", "test", "tests", "mock", "mocks", "script", "scripts",
    "out", "artifacts", "cache", "coverage", "forge-std", "ds-test", "openzeppelin",
    "openzeppelin-contracts", "@openzeppelin", "dependencies", ".deps", "fixtures",
})


@dataclass
class CryptoLaneReport:
    root: str
    scope_digest: str
    lane: str
    pursued: bool
    sol_files_found: int = 0
    files_scanned: int = 0
    candidates: list[dict] = field(default_factory=list)
    per_file: list[ContractStaticReport] = field(default_factory=list)
    engine_errors: dict[str, str] = field(default_factory=dict)
    skipped_reason: str | None = None

    @property
    def candidate_count(self) -> int:
        return len(self.candidates)


def discover_solidity_sources(
    root: str | Path, *, max_files: int = 400, exclude: Iterable[str] = _EXCLUDE_DIR_SEGMENTS,
) -> list[Path]:
    """Return the audited ``.sol`` sources under *root*, skipping vendored/test dirs."""
    root_path = Path(root).expanduser().resolve()
    exclude_set = {e.lower() for e in exclude}
    found: list[Path] = []
    for path in sorted(root_path.rglob("*.sol")):
        parts = {p.lower() for p in path.relative_to(root_path).parts[:-1]}
        if parts & exclude_set:
            continue
        # skip obvious test/mock files by name too
        name = path.name.lower()
        if name.endswith((".t.sol", ".s.sol")) or name.startswith(("test", "mock", "i")) and name.startswith("test"):
            continue
        found.append(path)
        if len(found) >= max_files:
            break
    return found


def _dedupe_candidates(rows: Iterable[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[tuple] = set()
    for row in rows:
        ans = row.get("json_answer") or {}
        key = (
            str(ans.get("vulnerability_type") or row.get("cwe") or ""),
            str(ans.get("file_path") or (row.get("contract_artifact") or {}).get("sha256") or ""),
            int(ans.get("line") or 0),
            str(ans.get("summary") or "")[:120],
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def run_crypto_lane(
    root: str | Path,
    *,
    scope_digest: str,
    vrt_category: str = "Smart Contract Misconfiguration",
    vrt_specific: str | None = None,
    pipeline_runner: Callable[..., ContractStaticReport] = run_contract_static_pipeline,
    max_files: int = 400,
) -> CryptoLaneReport:
    """Run the crypto lane over a contract repo, gated by the VRT bridge.

    Returns a :class:`CryptoLaneReport`. If the VRT class does not route to the
    ``SOURCE_CRYPTO`` lane, nothing is scanned and ``skipped_reason`` is set
    (defensive — this orchestrator is only for the crypto lane).
    """
    plan = hunt_plan_for_vrt(vrt_category, vrt_specific)
    report = CryptoLaneReport(
        root=str(root), scope_digest=str(scope_digest), lane=plan.lane.value, pursued=False,
    )
    if plan.lane is not HuntLane.SOURCE_CRYPTO:
        report.skipped_reason = (
            f"vrt class routes to {plan.lane.value}, not source_crypto; "
            "use the source-web / live lane instead"
        )
        return report
    if not plan.pursuable:
        report.skipped_reason = f"vrt class not pursuable ({plan.note})"
        return report

    report.pursued = True
    sources = discover_solidity_sources(root, max_files=max_files)
    report.sol_files_found = len(sources)

    rows: list[dict] = []
    for source in sources:
        try:
            file_report = pipeline_runner(source, scope_digest=scope_digest)
        except Exception as exc:  # a single-file failure must not abort the sweep
            report.engine_errors[str(source)] = f"{type(exc).__name__}: {exc}"[:240]
            continue
        report.files_scanned += 1
        report.per_file.append(file_report)
        rows.extend(file_report.candidates)
        report.engine_errors.update(file_report.engine_errors)

    report.candidates = _dedupe_candidates(rows)
    return report
