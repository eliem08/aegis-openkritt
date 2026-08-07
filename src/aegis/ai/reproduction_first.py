"""Reproduction-first orchestration primitives for authorized security research.

The objects in this module deliberately separate *planning* from execution. External engines
such as Joern, CodeQL, RESTler and OSV-Scanner may only be invoked by an existing Aegis
executor after policy/scope approval. Plans default to local repositories or disposable local
applications and carry deterministic provenance for evidence and benchmark accounting.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class FindingStage(str, Enum):
    SCANNER_CANDIDATE = "scanner_candidate"
    SOURCE_VALIDATED = "source_validated"
    APPLICATION_STARTED = "application_started"
    REQUEST_EXECUTED = "request_executed"
    ORACLE_PASSED = "oracle_passed"
    LOCALLY_REPRODUCED = "locally_reproduced"
    HUMAN_REVIEWED = "human_reviewed"


_STAGE_ORDER = tuple(FindingStage)


@dataclass(frozen=True, slots=True)
class ScannerCapability:
    name: str
    image: str
    digest: str
    languages: tuple[str, ...] = ()
    ecosystems: tuple[str, ...] = ()
    network: bool = False
    read_only_repo: bool = True
    cpu_limit: float = 1.0
    memory_mb: int = 1024
    pid_limit: int = 256
    timeout_seconds: int = 600
    schema_version: str = "1"

    def __post_init__(self) -> None:
        if not self.digest.startswith("sha256:") or len(self.digest) != 71:
            raise ValueError("scanner image must use an immutable sha256 digest")
        if self.cpu_limit <= 0 or self.memory_mb <= 0 or self.pid_limit <= 0:
            raise ValueError("scanner resource limits must be positive")
        if self.timeout_seconds <= 0:
            raise ValueError("scanner timeout must be positive")


@dataclass(frozen=True, slots=True)
class RepositoryProfile:
    languages: tuple[str, ...]
    ecosystems: tuple[str, ...]
    manifests: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ScannerExecutionPlan:
    capability: ScannerCapability
    repo_path: str
    network: bool
    read_only_repo: bool
    expected_schema: str

    @property
    def provenance_digest(self) -> str:
        payload = {
            "name": self.capability.name,
            "image": self.capability.image,
            "digest": self.capability.digest,
            "repo_path": self.repo_path,
            "network": self.network,
            "read_only_repo": self.read_only_repo,
            "schema": self.expected_schema,
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(raw).hexdigest()


class ScannerCapabilityRegistry:
    """One deterministic registry for the live and hardened scanner paths."""

    def __init__(self, capabilities: Iterable[ScannerCapability] = ()) -> None:
        self._items: dict[str, ScannerCapability] = {}
        for capability in capabilities:
            self.register(capability)

    def register(self, capability: ScannerCapability) -> None:
        existing = self._items.get(capability.name)
        if existing and existing != capability:
            raise ValueError(f"scanner capability already registered: {capability.name}")
        self._items[capability.name] = capability

    def plan(self, profile: RepositoryProfile, repo_path: str) -> list[ScannerExecutionPlan]:
        languages = {value.lower() for value in profile.languages}
        ecosystems = {value.lower() for value in profile.ecosystems}
        selected: list[ScannerExecutionPlan] = []
        for capability in sorted(self._items.values(), key=lambda item: item.name):
            supported_language = not capability.languages or bool(
                languages.intersection(value.lower() for value in capability.languages)
            )
            supported_ecosystem = not capability.ecosystems or bool(
                ecosystems.intersection(value.lower() for value in capability.ecosystems)
            )
            if supported_language and supported_ecosystem:
                selected.append(
                    ScannerExecutionPlan(
                        capability=capability,
                        repo_path=repo_path,
                        network=capability.network,
                        read_only_repo=capability.read_only_repo,
                        expected_schema=capability.schema_version,
                    )
                )
        return selected


@dataclass(frozen=True, slots=True)
class NormalizedFinding:
    scanner: str
    rule_id: str
    fingerprint: str
    path: str
    line: int
    weakness: str
    confidence: float
    stage: FindingStage = FindingStage.SCANNER_CANDIDATE
    provenance: Mapping[str, str] = field(default_factory=dict)

    def promote(self, stage: FindingStage) -> NormalizedFinding:
        current = _STAGE_ORDER.index(self.stage)
        requested = _STAGE_ORDER.index(stage)
        if requested != current + 1:
            raise ValueError("findings must advance exactly one evidence stage at a time")
        return NormalizedFinding(
            scanner=self.scanner,
            rule_id=self.rule_id,
            fingerprint=self.fingerprint,
            path=self.path,
            line=self.line,
            weakness=self.weakness,
            confidence=self.confidence,
            stage=stage,
            provenance=self.provenance,
        )


def deduplicate_findings(findings: Iterable[NormalizedFinding]) -> list[NormalizedFinding]:
    """Keep the strongest observation for each stable finding fingerprint."""
    by_fingerprint: dict[str, NormalizedFinding] = {}
    for finding in findings:
        existing = by_fingerprint.get(finding.fingerprint)
        if existing is None or finding.confidence > existing.confidence:
            by_fingerprint[finding.fingerprint] = finding
    return sorted(
        by_fingerprint.values(),
        key=lambda finding: (-finding.confidence, finding.path, finding.line),
    )


@dataclass(frozen=True, slots=True)
class OfflineOsvSnapshot:
    path: str
    sha256: str
    created_at: str
    ecosystems: tuple[str, ...]

    def verify(self) -> bool:
        file_path = Path(self.path)
        if not file_path.is_file():
            return False
        hasher = hashlib.sha256()
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(chunk)
        return hasher.hexdigest() == self.sha256.lower()


@dataclass(frozen=True, slots=True)
class DependencyEvidence:
    package: str
    version: str
    vulnerability_id: str
    direct: bool
    vulnerable_function_called: bool
    externally_reachable: bool
    practical_impact: float

    @property
    def priority(self) -> float:
        score = max(0.0, min(self.practical_impact, 1.0))
        if self.direct:
            score += 0.15
        if self.vulnerable_function_called:
            score += 0.35
        if self.externally_reachable:
            score += 0.35
        return min(score, 1.0)


@dataclass(frozen=True, slots=True)
class GraphFlow:
    source: str
    sink: str
    path: tuple[str, ...]
    sanitizers: tuple[str, ...]
    entrypoint_reachable: bool
    confidence: float
    engine: str


@dataclass(frozen=True, slots=True)
class GraphAnalysisPlan:
    engine: str
    repository: str
    query_kind: str
    local_only: bool = True

    def __post_init__(self) -> None:
        if self.engine not in {"joern", "codeql"}:
            raise ValueError("graph engine must be joern or codeql")
        if not self.local_only:
            raise ValueError("graph analysis plans are local-only by default")


class GraphAnalysisAdapter:
    """Normalize cross-file source-to-sink paths from a graph engine."""

    @staticmethod
    def plan(repository: str, engine: str = "joern") -> GraphAnalysisPlan:
        return GraphAnalysisPlan(
            engine=engine.lower(),
            repository=repository,
            query_kind="source_to_sink_path",
        )

    @staticmethod
    def normalize(engine: str, result: Mapping[str, Any]) -> GraphFlow:
        path = tuple(str(item) for item in result.get("path", ()))
        if not path:
            raise ValueError("graph result must include a non-empty path")
        return GraphFlow(
            source=str(result["source"]),
            sink=str(result["sink"]),
            path=path,
            sanitizers=tuple(str(item) for item in result.get("sanitizers", ())),
            entrypoint_reachable=bool(result.get("entrypoint_reachable", False)),
            confidence=max(0.0, min(float(result.get("confidence", 0.0)), 1.0)),
            engine=engine,
        )


@dataclass(frozen=True, slots=True)
class IdentityContext:
    name: str
    role: str
    tenant: str | None = None
    canary: str | None = None


@dataclass(frozen=True, slots=True)
class AuthorizationObservation:
    requester: IdentityContext
    owner: IdentityContext
    status_code: int
    returned_identifiers: tuple[str, ...] = ()
    returned_markers: tuple[str, ...] = ()
    side_effect_markers: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AuthorizationOracleResult:
    reproduced: bool
    reason: str


def evaluate_cross_user_exposure(
    observation: AuthorizationObservation,
) -> AuthorizationOracleResult:
    canary = observation.owner.canary
    if observation.requester.name == observation.owner.name:
        return AuthorizationOracleResult(False, "same identity is not a differential control")
    if not canary:
        return AuthorizationOracleResult(False, "owner has no unique canary")
    if canary not in observation.returned_markers:
        return AuthorizationOracleResult(False, "owner canary was not returned")
    return AuthorizationOracleResult(
        True,
        "different identity received an owner-unique canary",
    )


@dataclass(frozen=True, slots=True)
class OpenApiOperation:
    operation_id: str
    method: str
    path: str
    produces: tuple[str, ...] = ()
    consumes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class StatefulApiPlan:
    operations: tuple[OpenApiOperation, ...]
    mode: str = "test"
    local_only: bool = True
    request_budget: int = 100

    def __post_init__(self) -> None:
        if self.mode not in {"test", "fuzz-lean"}:
            raise ValueError("RESTler mode must be test or fuzz-lean")
        if not self.local_only:
            raise ValueError("stateful API fuzzing is local-only by default")
        if self.request_budget <= 0:
            raise ValueError("request budget must be positive")


def order_api_operations(operations: Sequence[OpenApiOperation]) -> tuple[OpenApiOperation, ...]:
    """Stable producer-before-consumer ordering for generated RESTler-style sequences."""
    pending = list(operations)
    ordered: list[OpenApiOperation] = []
    produced: set[str] = set()
    while pending:
        progress = False
        for operation in list(pending):
            if set(operation.consumes).issubset(produced):
                ordered.append(operation)
                produced.update(operation.produces)
                pending.remove(operation)
                progress = True
        if not progress:
            ordered.extend(sorted(pending, key=lambda item: item.operation_id))
            break
    return tuple(ordered)


@dataclass(frozen=True, slots=True)
class PatchSignal:
    file: str
    added_guard: str | None = None
    removed_sink: str | None = None
    object_type: str | None = None
    route_family: str | None = None


@dataclass(frozen=True, slots=True)
class VariantQuery:
    weakness_hint: str
    structural_terms: tuple[str, ...]
    target_areas: tuple[str, ...]


def infer_variant_query(signals: Sequence[PatchSignal]) -> VariantQuery:
    guards = sorted({signal.added_guard for signal in signals if signal.added_guard})
    sinks = sorted({signal.removed_sink for signal in signals if signal.removed_sink})
    objects = sorted({signal.object_type for signal in signals if signal.object_type})
    routes = sorted({signal.route_family for signal in signals if signal.route_family})
    if guards:
        weakness = "missing authorization or validation guard"
    elif sinks:
        weakness = "dangerous sink or unsafe data flow"
    else:
        weakness = "security-sensitive behavioral change"
    return VariantQuery(
        weakness_hint=weakness,
        structural_terms=tuple(guards + sinks + objects),
        target_areas=tuple(routes),
    )


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    detected: int
    reproduced: int
    false_positives: int
    bounty_value_usd: float
    duplicate_adjusted_value_usd: float
    model_cost_usd: float
    scanner_cost_usd: float
    human_review_minutes: float

    @property
    def precision(self) -> float:
        denominator = self.reproduced + self.false_positives
        return self.reproduced / denominator if denominator else 0.0

    @property
    def reproduction_rate(self) -> float:
        return self.reproduced / self.detected if self.detected else 0.0

    @property
    def total_cost_usd(self) -> float:
        return self.model_cost_usd + self.scanner_cost_usd

    @property
    def cost_per_reproduced(self) -> float:
        return self.total_cost_usd / self.reproduced if self.reproduced else float("inf")


@dataclass(frozen=True, slots=True)
class BenchmarkGate:
    min_precision: float
    min_reproduction_rate: float
    max_cost_per_reproduced: float
    min_duplicate_adjusted_value: float = 0.0

    def accepts(self, result: BenchmarkResult) -> bool:
        return (
            result.precision >= self.min_precision
            and result.reproduction_rate >= self.min_reproduction_rate
            and result.cost_per_reproduced <= self.max_cost_per_reproduced
            and result.duplicate_adjusted_value_usd >= self.min_duplicate_adjusted_value
        )
