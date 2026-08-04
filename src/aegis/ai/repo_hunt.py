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
    # test/spec dirs, allowing leading/trailing underscores: test, tests, _test,
    # _tests, __tests__, spec, specs, _specs — the underscore-prefixed forms
    # (chia/_tests/...) were previously slipping through and crowding out real code.
    r"(^|/)_*(tests?|specs?)_*(/|$)|"
    r"(^|/)(example|examples|demo|demos|fixtures?|mocks?|benchmarks?|vendor|"
    r"third_party|node_modules|docs?|\.github|anvil|scripts?)(/|$)|"
    r"(_test|\.test|\.spec|_generated|\.pb|_pb2|\.t)\.",
    re.IGNORECASE,
)

#: Declaration-only files with no exploitable logic — an interface/abstract ABI.
#: Matches `.../interfaces/Foo.sol` and top-level `IFoo.sol` (Solidity convention).
_INTERFACE_ONLY = re.compile(r"(^|/)interfaces?/|(^|/)I[A-Z][A-Za-z0-9]*\.sol$")

#: Content signals — the dangerous primitives themselves, keyed to an agent kind and
#: a weight. These catch files whose *name* is neutral (MessageTransmitter.sol,
#: Message.sol) but whose *body* is exactly where signature/replay/reentrancy bugs
#: live. Path scoring alone is blind to these.
_CONTENT_SIGNALS: tuple[tuple[re.Pattern, int, AgentKind], ...] = (
    (re.compile(r"\becrecover\b|SignatureChecker|isValidSignature|_hashTypedData|EIP712",
                re.I), 10, AgentKind.SECRETS_CRYPTO),
    (re.compile(r"\bnonce\b|usedNonces|replay|\bdomain\b.*message|attest", re.I), 9,
     AgentKind.BUSINESS_LOGIC),
    (re.compile(r"delegatecall|\bcall\{|\.call\(|selfdestruct|assembly\s*\{", re.I), 9,
     AgentKind.INJECTION),
    (re.compile(r"onlyOwner|onlyRole|_checkRole|hasRole|require\(msg\.sender", re.I), 8,
     AgentKind.AUTHORIZATION),
    (re.compile(r"transferFrom|safeTransfer|_mint\(|_burn\(|approve\(", re.I), 7,
     AgentKind.BUSINESS_LOGIC),
    (re.compile(r"password|api[_-]?key|private[_-]?key|jwt|bearer|hmac", re.I), 8,
     AgentKind.SECRETS_CRYPTO),
    (re.compile(r"exec\(|eval\(|subprocess|os\.system|Runtime\.getRuntime|child_process",
                re.I), 9, AgentKind.INJECTION),
    (re.compile(r"\.query\(|executeQuery|rawQuery|db\.Raw|fmt\.Sprintf.*(SELECT|INSERT)",
                re.I), 8, AgentKind.INJECTION),
    (re.compile(r"http\.Get|requests\.get|\bfetch\b|node-fetch|urllib|HttpClient|"
                r"\.newClient|axios|got\(|http\.request", re.I), 6,
     AgentKind.SSRF_PARSERS),
    # untrusted value interpolated into a URL/query string without encoding —
    # parameter injection / SSRF path construction. Matches template literals and
    # concatenation that build a URL or query with a variable and no encodeURIComponent.
    (re.compile(r"(https?://[^`\"']*\$\{)|([?&][A-Za-z_]+=\$\{)|"
                r"(url\s*[+=].*\$\{)", re.I), 7, AgentKind.SSRF_PARSERS),
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
    include_paths: frozenset = frozenset()  # if set, only these exact paths are eligible
    # Cross-file context: real vulnerabilities span files (entry point -> handler ->
    # sink), so each primary file is analyzed together with its nearest neighbours.
    context_files: int = 3            # supporting files bundled per primary file
    max_bundle_bytes: int = 200_000   # total budget for one bundle
    require_reachability: bool = True  # drop hypotheses with no entry point/impact
    min_confidence: float = 0.0
    # Ensemble: generate this many times per file over a temperature spread and union
    # the findings, to catch borderline bugs a single generation misses ~7/8 of the time.
    samples: int = 1
    # Content-aware selection: peek at the body of the top path-ranked candidates and
    # re-rank by the dangerous primitives they actually contain, so logic files with
    # neutral names (MessageTransmitter.sol) are not invisible to name-only scoring.
    content_scan: bool = True
    content_scan_pool: int = 40       # candidates to peek at before final ranking
    baseline_score: int = 1          # score for a logic file with no path signal
    # Diversity: cap files taken from any one COMPONENT (the segment past the
    # candidates' shared prefix — e.g. plugins/<Name>, across all its subdirs) so a
    # single keyword-dense component can't consume every slot and starve the rest of
    # the repo. 0 disables the cap. (Name kept for back-compat; semantics = per component.)
    max_per_dir: int = 3


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


def score_path(path: str, *, baseline: int = 0) -> tuple[int, AgentKind] | None:
    """Deterministic relevance score for a repository path, or None to skip it.

    ``baseline`` (when > 0) is the score given to a real logic file that carries no
    path signal, so content scanning can still reach it; with baseline 0 an unsignalled
    file is skipped, preserving the original name-only behaviour.
    """
    if _EXCLUDED.search(path):
        return None
    suffix = Path(path).suffix.lower()
    if suffix not in _EXTENSIONS:
        return None
    if _INTERFACE_ONLY.search(path):
        return None                      # declaration-only ABI, no exploitable logic
    best_score, best_kind = 0, _EXTENSIONS[suffix]
    for pattern, score, kind in _SIGNALS:
        # first match wins at equal-or-higher score, so _SIGNALS order disambiguates
        # overlapping vocabulary (e.g. "authorizer" is authorization, not authn).
        if pattern.search(path) and score > best_score:
            best_score, best_kind = score, kind
    if best_kind is AgentKind.AUTHENTICATION and re.search(r"authoriz|authz|rbac|permission", path, re.I):
        best_kind, best_score = AgentKind.AUTHORIZATION, 9
    if best_score == 0:
        if baseline <= 0:
            return None                  # no path signal -> skip (name-only behaviour)
        best_score = baseline
    if suffix == ".sol":                 # contracts are always contract-reviewed
        best_kind = AgentKind.SMART_CONTRACT
    return best_score, best_kind


def score_content(content: str, suffix: str) -> tuple[int, AgentKind] | None:
    """Relevance from the file body: the dangerous primitives it actually contains.
    Returns the single highest-weighted content signal, or None if the body is inert."""
    best_score, best_kind = 0, None
    for pattern, score, kind in _CONTENT_SIGNALS:
        if score > best_score and pattern.search(content):
            best_score, best_kind = score, kind
    if best_score == 0:
        return None
    if suffix == ".sol":
        best_kind = AgentKind.SMART_CONTRACT
    return best_score, best_kind


def select_files(paths, config: RepoHuntConfig) -> list[SelectedFile]:
    """Rank repository paths by security relevance and take the top ``max_files``.

    Name-only ranking. When ``config.content_scan`` is on, ``hunt_repository`` calls
    :func:`refine_by_content` on a larger candidate pool to re-rank by file body.
    """
    baseline = config.baseline_score if config.content_scan else 0
    scored: list[SelectedFile] = []
    for path in paths:
        if config.subpath and not path.startswith(config.subpath):
            continue
        if config.include_paths and path not in config.include_paths:
            continue
        result = score_path(path, baseline=baseline)
        if result is None:
            continue
        score, kind = result
        scored.append(SelectedFile(path=path, score=score, kind=kind))
    scored.sort(key=lambda f: (-f.score, f.path))   # deterministic: score desc, path asc
    return scored


def refine_by_content(fetcher, repository, candidates, config, result):
    """Re-rank the top path candidates by the dangerous primitives their bodies hold.

    A file's final score is max(path score, content score), so a neutral-named logic
    file (MessageTransmitter.sol) that contains ecrecover/nonce beats a well-named
    file that contains nothing interesting. Bounded: peeks at ``content_scan_pool``
    candidates only. The pool is itself component-diversified first, so a
    keyword-dense component (e.g. one plugin with 20 login files) can't crowd every
    other component out of the pool and out of the final selection via backfill.
    Deterministic given the same repository contents."""
    pool = _diversify(candidates, config.content_scan_pool, config.max_per_dir)
    refined: list[SelectedFile] = []
    for item in pool:
        try:
            content = fetcher.read(repository, item.path)
        except Exception:
            refined.append(item)                     # keep its path score on fetch failure
            continue
        if not content or len(content.encode("utf-8", "ignore")) > config.max_file_bytes:
            continue                                 # unreadable / too large -> drop
        signal = score_content(content, Path(item.path).suffix.lower())
        if signal and signal[0] >= item.score:
            refined.append(SelectedFile(path=item.path, score=signal[0], kind=signal[1]))
        elif score_path(item.path) is not None:      # had a real path signal -> keep it
            refined.append(item)
        # else: baseline-only file with an inert body -> dropped
    refined.sort(key=lambda f: (-f.score, f.path))
    return refined


def _common_prefix_segments(paths: list[str]) -> list[str]:
    """Longest shared leading directory segments across the candidate paths."""
    seg_lists = [p.split("/")[:-1] for p in paths]   # dir segments, drop filename
    if not seg_lists:
        return []
    common = seg_lists[0]
    for segs in seg_lists[1:]:
        i = 0
        while i < len(common) and i < len(segs) and common[i] == segs[i]:
            i += 1
        common = common[:i]
    return common


def _component_key(path: str, common_len: int) -> str:
    """The component a path belongs to: the segment just past the shared prefix, so a
    plugin (plugins/<Name>) or module groups together regardless of how many subdirs
    (Emails/, Security/, config/) it spreads across. Files sitting directly in the
    shared root are each their own key (a flat dir has nothing to spread across)."""
    segs = path.split("/")
    return "/".join(segs[: common_len + 1])


def _diversify(candidates: list[SelectedFile], max_files: int, max_per_dir: int) -> list[SelectedFile]:
    """Take up to ``max_files``, capping how many come from any one COMPONENT so a
    single keyword-dense component (e.g. one plugin, across all its subdirs) can't
    starve the rest of the repo. Candidates are already score-sorted. Pass 1 honours
    the cap; pass 2 backfills leftover slots in score order if the cap left budget
    unused (few-component repos still fill up)."""
    if max_per_dir <= 0:
        return candidates[:max_files]
    common_len = len(_common_prefix_segments([f.path for f in candidates]))
    per_component: dict[str, int] = {}
    chosen: list[SelectedFile] = []
    deferred: list[SelectedFile] = []
    for f in candidates:
        key = _component_key(f.path, common_len)
        if per_component.get(key, 0) < max_per_dir:
            per_component[key] = per_component.get(key, 0) + 1
            chosen.append(f)
            if len(chosen) >= max_files:
                return chosen
        else:
            deferred.append(f)
    for f in deferred:                     # backfill only if the cap left room
        if len(chosen) >= max_files:
            break
        chosen.append(f)
    return chosen


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
    candidates = select_files(paths, config)
    result = RepoHuntResult(repository=repository, commit=commit, selected=[])
    if config.content_scan:
        candidates = refine_by_content(fetcher, repository, candidates, config, result)
    selected = _diversify(candidates, config.max_files, config.max_per_dir)
    result.selected = selected
    retriever = None
    try:                                             # retrieval-augmented detection, if a corpus is set
        from .knowledge_retrieval import KnowledgeRetriever, load_default_corpus
        corpus = load_default_corpus()
        if corpus is not None:
            retriever = KnowledgeRetriever(corpus)
    except Exception:
        retriever = None
    agent = SpecializedAgent(
        client, max_hypotheses=config.max_hypotheses_per_file,
        require_reachability=config.require_reachability,
        min_confidence=config.min_confidence,
        samples=config.samples, retriever=retriever,
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
            # surface the reason, not just the type — a swallowed message hides
            # truncated json, rate limits, and context-length errors alike
            result.failures.append(
                f"{item.path}: analysis failed ({type(exc).__name__}: {str(exc)[:200]})")
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
