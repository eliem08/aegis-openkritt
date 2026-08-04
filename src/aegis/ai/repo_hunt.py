"""Autonomous repository hunting for the Aegis-native DeepSeek pipeline.

open·kritt clones a whole repository and fans agents across it. This module gives
Aegis the same autonomy without the container stack: it selects security-relevant
files from a repository tree by deterministic heuristics, fetches only those files,
runs :class:`~aegis.ai.agents.runner.SpecializedAgent` over each with the matching
agent kind, and writes a persisted report that
:func:`~aegis.ai.report_validation.validate_deepseek_report` can then validate
against the same pinned checkout.

Design constraints, deliberately kept:

* **Bounded.** A repository is never fully downloaded — only the selected files, up
  to explicit caps. A 1.5 GB monorepo costs the same as a small one.
* **Deterministic selection.** Which files get analyzed is decided by scored
  heuristics in code, not by a model, so a run is reproducible and auditable.
* **Non-production code is skipped** (tests, examples, vendor, generated), the same
  exclusion the open·kritt workflows carry.
* **Read-only.** Fetches public source over HTTPS; never executes it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .agents.contracts import AgentKind, AgentTask, SourceSlice
from .agents.runner import SpecializedAgent

#: Path fragments that mark non-production code — never selected for analysis.
_EXCLUDED = re.compile(
    r"(^|/)(test|tests|__tests__|spec|specs|example|examples|demo|demos|fixtures?|"
    r"mocks?|benchmarks?|vendor|third_party|node_modules|docs?|\.github)(/|$)|"
    r"(_test|\.test|\.spec|_generated|\.pb|_pb2)\.",
    re.IGNORECASE,
)

#: Source extensions we can meaningfully review.
_EXTENSIONS = {
    ".go": AgentKind.INJECTION, ".py": AgentKind.INJECTION, ".rb": AgentKind.INJECTION,
    ".php": AgentKind.INJECTION, ".js": AgentKind.CLIENT_API, ".ts": AgentKind.CLIENT_API,
    ".java": AgentKind.INJECTION, ".cs": AgentKind.INJECTION, ".rs": AgentKind.SSRF_PARSERS,
    ".c": AgentKind.SSRF_PARSERS, ".cc": AgentKind.SSRF_PARSERS, ".cpp": AgentKind.SSRF_PARSERS,
    ".sol": AgentKind.SMART_CONTRACT,
}

#: Path/name signals -> (score, agent kind). Higher score = analyzed sooner.
_SIGNALS: tuple[tuple[re.Pattern, int, AgentKind], ...] = (
    # authorization first: "authorizer"/"authz" must not be captured by the auth
    # pattern below (which would misclassify RBAC code as authentication).
    (re.compile(r"rbac|permission|authoriz|authz|access.?control|policy|admission", re.I), 9,
     AgentKind.AUTHORIZATION),
    (re.compile(r"authn|\bauth\b|auth[/_.]|login|session|credential|token|jwt|oauth|saml|oidc",
                re.I), 10, AgentKind.AUTHENTICATION),
    (re.compile(r"crypto|cipher|hash|signature|signing|secret|keyring|random", re.I), 8,
     AgentKind.SECRETS_CRYPTO),
    (re.compile(r"webhook|proxy|fetch|request|client|url|redirect|forward", re.I), 7,
     AgentKind.SSRF_PARSERS),
    (re.compile(r"parse|decode|unmarshal|deserial|upload|file|path", re.I), 6,
     AgentKind.INJECTION),
    (re.compile(r"exec|command|shell|query|sql|template|render", re.I), 6,
     AgentKind.INJECTION),
    (re.compile(r"validat|sanitiz|escape|filter", re.I), 5, AgentKind.INJECTION),
)


@dataclass
class RepoHuntConfig:
    max_files: int = 12               # files actually analyzed (cost ceiling)
    max_file_bytes: int = 120_000     # skip files larger than this
    max_hypotheses_per_file: int = 5
    subpath: str = ""                 # restrict selection to this subtree, e.g. "pkg/"
    # Cross-file context: real vulnerabilities span files (entry point -> handler ->
    # sink), so each primary file is analyzed together with its nearest neighbours.
    context_files: int = 3            # supporting files bundled per primary file
    max_bundle_bytes: int = 200_000   # total budget for one bundle
    require_reachability: bool = True  # drop hypotheses with no entry point/impact
    min_confidence: float = 0.0


@dataclass
class SelectedFile:
    path: str
    score: int
    kind: AgentKind


@dataclass
class RepoHuntResult:
    repository: str
    commit: str
    selected: list[SelectedFile] = field(default_factory=list)
    hypotheses: list[dict] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)

    def report(self) -> dict:
        """A persisted-report dict in the shape report_validation expects."""
        return {
            "scan": {
                "id": f"ds-{self.repository.replace('/', '-')}-{self.commit[:8]}",
                "provider": "DeepSeek Platform",
                "repository": self.repository,
                "commit": self.commit,
                "source_files": len(self.selected),
                "status": "completed",
                "selected_files": [
                    {"path": f.path, "score": f.score, "kind": f.kind.value}
                    for f in self.selected
                ],
                "failures": self.failures,
            },
            "vulnerabilities": self.hypotheses,
        }


def score_path(path: str) -> tuple[int, AgentKind] | None:
    """Deterministic relevance score for a repository path, or None to skip it."""
    if _EXCLUDED.search(path):
        return None
    suffix = Path(path).suffix.lower()
    if suffix not in _EXTENSIONS:
        return None
    best_score, best_kind = 0, _EXTENSIONS[suffix]
    for pattern, score, kind in _SIGNALS:
        # first match wins at equal-or-higher score, so _SIGNALS order disambiguates
        # overlapping vocabulary (e.g. "authorizer" is authorization, not authn).
        if pattern.search(path) and score > best_score:
            best_score, best_kind = score, kind
    if best_kind is AgentKind.AUTHENTICATION and re.search(r"authoriz|authz|rbac|permission", path, re.I):
        best_kind, best_score = AgentKind.AUTHORIZATION, 9
    if best_score == 0:
        return None                      # no security signal in the path -> skip
    if suffix == ".sol":                 # contracts are always contract-reviewed
        best_kind = AgentKind.SMART_CONTRACT
    return best_score, best_kind


def select_files(paths, config: RepoHuntConfig) -> list[SelectedFile]:
    """Rank repository paths by security relevance and take the top ``max_files``."""
    scored: list[SelectedFile] = []
    for path in paths:
        if config.subpath and not path.startswith(config.subpath):
            continue
        result = score_path(path)
        if result is None:
            continue
        score, kind = result
        scored.append(SelectedFile(path=path, score=score, kind=kind))
    # deterministic: score desc, then path asc
    scored.sort(key=lambda f: (-f.score, f.path))
    return scored[: config.max_files]


def related_paths(primary: str, all_paths, limit: int) -> list[str]:
    """Nearest supporting files for a primary file: same directory first (the package
    that defines its callers and helpers), then the parent directory. Deterministic."""
    if limit <= 0:
        return []
    primary_dir = str(Path(primary).parent).replace("\\", "/")
    parent_dir = str(Path(primary).parent.parent).replace("\\", "/")
    suffix = Path(primary).suffix.lower()

    def usable(path: str) -> bool:
        return (path != primary and Path(path).suffix.lower() == suffix
                and not _EXCLUDED.search(path))

    same = sorted(p for p in all_paths
                  if usable(p) and str(Path(p).parent).replace("\\", "/") == primary_dir)
    near = sorted(p for p in all_paths
                  if usable(p) and p not in same
                  and str(Path(p).parent).replace("\\", "/").startswith(parent_dir))
    # prefer neighbours that themselves carry a security signal
    same.sort(key=lambda p: (-(score_path(p) or (0, None))[0], p))
    near.sort(key=lambda p: (-(score_path(p) or (0, None))[0], p))
    return (same + near)[:limit]


def hunt_repository(fetcher, client, repository: str, *,
                    config: RepoHuntConfig | None = None,
                    pin_dir: str | Path | None = None,
                    progress=None) -> RepoHuntResult:
    """Select security-relevant files, analyze each, and collect hypotheses.

    ``fetcher`` supplies the repository contents and must provide
    ``list_paths(repository) -> (paths, commit)`` and
    ``read(repository, path) -> str``. Injecting it keeps this testable offline.
    """
    config = config or RepoHuntConfig()
    paths, commit = fetcher.list_paths(repository)
    selected = select_files(paths, config)
    result = RepoHuntResult(repository=repository, commit=commit, selected=selected)
    agent = SpecializedAgent(
        client, max_hypotheses=config.max_hypotheses_per_file,
        require_reachability=config.require_reachability,
        min_confidence=config.min_confidence,
    )
    seen: set[tuple[str, int, str]] = set()          # cross-file hypothesis dedup

    for index, item in enumerate(selected, start=1):
        if progress:
            progress(index, len(selected), item.path)
        bundle = _read_bundle(fetcher, repository, item.path, paths, config, result, pin_dir)
        if bundle is None:
            continue
        primary_only = [s.path for s in bundle if s.path == item.path]
        if not primary_only:
            continue
        task = AgentTask(
            kind=item.kind,
            target=f"{repository}:{item.path}",
            source_slices=bundle,
            policy_notes=(
                f"Authorized static source review of {repository}. The PRIMARY file under "
                f"review is {item.path}; the other slices are supporting context (callers, "
                "helpers, neighbouring handlers) supplied so you can trace a flow across "
                "files. Report a weakness only if its vulnerable line is in the primary "
                "file and you can trace an untrusted entry point to it. Ignore issues that "
                "exist solely in non-production code. No live execution or target contact."
            ),
        )
        try:
            hypotheses = agent.analyze(task)
        except Exception as exc:
            result.failures.append(f"{item.path}: analysis failed ({type(exc).__name__})")
            continue
        for hypothesis in hypotheses:
            if hypothesis.file_path != item.path:
                continue                              # context files are read-only evidence
            key = (hypothesis.file_path, hypothesis.line, hypothesis.weakness.lower())
            if key in seen:
                continue                              # same issue re-reported from a neighbour
            seen.add(key)
            result.hypotheses.append(_row(repository, hypothesis))
    return result


def _read_bundle(fetcher, repository, primary, all_paths, config, result, pin_dir):
    """Primary file plus bounded supporting context, pinned for later validation."""
    try:
        content = fetcher.read(repository, primary)
    except Exception as exc:
        result.failures.append(f"{primary}: fetch failed ({type(exc).__name__})")
        return None
    if not content or len(content.encode("utf-8", "ignore")) > config.max_file_bytes:
        result.failures.append(f"{primary}: skipped (empty or too large)")
        return None

    slices, budget = [], config.max_bundle_bytes
    def add(path: str, text: str) -> None:
        nonlocal budget
        size = len(text.encode("utf-8", "ignore"))
        if size > budget:
            return
        budget -= size
        slices.append(SourceSlice(path=path, content=text))
        if pin_dir is not None:                       # pin for citation validation
            destination = Path(pin_dir) / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text, encoding="utf-8")

    add(primary, content)
    for neighbour in related_paths(primary, all_paths, config.context_files):
        try:
            text = fetcher.read(repository, neighbour)
        except Exception:
            continue                                   # context is best-effort
        if text and len(text.encode("utf-8", "ignore")) <= config.max_file_bytes:
            add(neighbour, text)
    return slices


def _row(repository: str, hypothesis) -> dict:
    """Shape one hypothesis into the persisted-report vulnerability row."""
    severity = getattr(hypothesis.severity, "value", str(hypothesis.severity or "medium"))
    trigger = hypothesis.entry_point or hypothesis.verification.expected_observation
    return {
        "json_answer": {
            "vulnerability_type": hypothesis.weakness,
            "file_path": hypothesis.file_path,
            "line": hypothesis.line,
            "summary": hypothesis.title,
            "explanation": hypothesis.rationale,
            "trigger_flow": trigger,
            "impact": hypothesis.impact,
            "malicious_input_example": "",
            "malicious_actor": hypothesis.attacker or "untrusted caller, subject to manual validation",
            "severity": severity,
        },
        "severity": severity,
        "source": "aegis:deepseek-platform",
        "confidence": hypothesis.confidence,
        "dedupe_is_canonical": True,
        "target": f"{repository}:{hypothesis.file_path}:{hypothesis.line}:{hypothesis.weakness}",
    }
