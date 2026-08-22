"""Engine ports — the seam between the product layer and :mod:`aegis.ai`.

Products depend on a small :class:`Ports` bundle of callables, never on the engine directly.
:func:`default_ports` binds them to the real, maintained engine (lazy imports so importing
``aegis.products`` stays cheap and dependency-light); tests pass a :class:`Ports` with fakes and
run fully offline. This is the only place that knows how the engine is wired.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass
class Ports:
    """Injectable engine operations. All operate on the report dict {scan, vulnerabilities}."""

    # hunt(repo, *, repo_dir, files, samples, subpath, include_paths) -> validated report dict
    hunt: Callable[..., dict]
    # validate_report(report, repo_dir) -> validated report dict (verdicts filled)
    validate_report: Callable[[dict, str], dict]
    # reproduce_report(report, repo_dir, **kw) -> summary dict; mutates report rows in place
    reproduce_report: Callable[..., dict]
    # dedupe(rows) -> aegis.ai.candidate_reduction.Reduction
    dedupe: Callable[[list], object]
    # corroborate(rows) -> rows (annotated with cross-engine agreement)
    corroborate: Callable[[list], list]


# --------------------------------------------------------------------------------------------
# Default (real-engine) implementations
# --------------------------------------------------------------------------------------------

def _make_client():
    """Build the configured LLM client (context manager). Raises if no key is set."""
    from ..ai.client import DeepSeekClient
    from ..ai.config import DeepSeekConfig

    return DeepSeekClient(DeepSeekConfig.from_env(dict(os.environ)))


def _git_commit(repo_dir: str) -> str:
    try:
        import subprocess

        out = subprocess.run(
            ["git", "-C", repo_dir, "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=15,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return "local"


def _report_dir() -> Path:
    return Path(os.environ.get("AEGIS_REPORT_DIR", "reports"))


def _default_validate_report(report: dict, repo_dir: str) -> dict:
    """Validate every hypothesis against the pinned source; return the validated report."""
    from ..ai.report_validation import validate_deepseek_report

    tmp = Path(tempfile.mkdtemp(prefix="aegis-prod-")) / "report.json"
    tmp.write_text(json.dumps(report), encoding="utf-8")
    with _make_client() as client:
        validated, _model = validate_deepseek_report(tmp, repo_dir, client)
    return validated


def _default_reproduce_report(report: dict, repo_dir: str, **kw) -> dict:
    """Reproduce validator-confirmed rows on a disposable local instance (opt-in, local-only)."""
    from ..ai.repro_hook import maybe_reproduce

    with _make_client() as client:
        return maybe_reproduce(repo_dir, report, client, **kw)


def _default_dedupe(rows: list):
    from ..ai.candidate_reduction import reduce_candidates

    return reduce_candidates(rows)


def _default_corroborate(rows: list):
    from ..ai.corroboration import corroborate

    return corroborate(rows)


def _fold_scanners(report: dict, repo_dir: str) -> None:
    """Run installed OSS scanners on the checkout and fold their rows into the report."""
    try:
        from ..ai.tool_bridge import ToolBridge, available_tools
    except Exception:
        return
    avail = available_tools("code") + available_tools("secrets") + available_tools("deps")
    if not avail:
        return
    tools = list({t.name: t for t in avail}.values())
    bridge = ToolBridge()
    results = bridge.scan(str(repo_dir), tools=tools)
    rows = bridge.findings(results)
    if rows:
        report.setdefault("vulnerabilities", []).extend(rows)


def _default_hunt(repo: str, *, repo_dir: str | None = None, files: int = 12, samples: int = 2,
                  subpath: str = "", include_paths=None, fold_scanners: bool = True,
                  validate: bool = True) -> dict:
    """Local-source hunt: arsenal + LLM ensemble + funnel + citation validator.

    ``repo_dir`` is a local checkout the operator controls (the own-code path for group A). If it
    is ``None`` the repo is cloned via the engine's authorized clone path.
    """
    from ..ai.repo_clone import LocalRepoSource, clone_repository
    from ..ai.repo_hunt import RepoHuntConfig, hunt_repository

    if repo_dir is None:
        clone = clone_repository(repo, cache_dir=str(_report_dir() / "clones"),
                                 token=os.environ.get("GITHUB_TOKEN", ""))
        repo_dir = clone.path
        commit = clone.commit
    else:
        commit = _git_commit(repo_dir)

    cfg = RepoHuntConfig(
        max_files=files, subpath=subpath, samples=samples,
        include_paths=frozenset(include_paths or ()),
    )
    source = LocalRepoSource(repo_dir, commit)
    with source as src, _make_client() as client:
        result = hunt_repository(src, client, repo, config=cfg, pin_dir=repo_dir)
    report = result.report()
    if fold_scanners:
        _fold_scanners(report, repo_dir)
    if validate and (report.get("vulnerabilities")):
        report = _default_validate_report(report, repo_dir)
    return report


def default_ports() -> Ports:
    """Ports bound to the real engine."""
    return Ports(
        hunt=_default_hunt,
        validate_report=_default_validate_report,
        reproduce_report=_default_reproduce_report,
        dedupe=_default_dedupe,
        corroborate=_default_corroborate,
    )
