"""Production wiring for the autonomous hunt: the real hunt function + target builder.

Kept apart from ``auto_hunt`` (pure orchestration) so that module stays network-free
and testable. This is the side that actually clones, calls the model, validates, and
scaffolds PoCs — reusing the exact pipeline the CLI uses.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .auto_hunt import HuntOutcome, HuntTarget


def make_hunt_fn(*, report_root: str | Path = "reports"):
    """A hunt function for AutoHunter that runs the full code-lane pipeline per target.

    Reuses clone -> ensemble hunt (retrieval+calibration auto-load) -> citation
    validation -> outcome recording -> PoC scaffold. Contract targets go through the
    Etherscan source instead of a clone. Never submits."""
    from .client import DeepSeekClient
    from .config import DeepSeekConfig
    from .repo_hunt import RepoHuntConfig, hunt_repository

    root = Path(report_root).resolve()

    def hunt_fn(target: HuntTarget, samples: int) -> HuntOutcome:
        env = dict(os.environ)
        env.update(DEEPSEEK_THINKING="disabled", DEEPSEEK_TEMPERATURE="0.1",
                   DEEPSEEK_MAX_TOKENS="16000", DEEPSEEK_READ_TIMEOUT="300")
        config = DeepSeekConfig.from_env(env)

        slug = target.repository.replace("/", "_").replace("0x", "contract_0x")
        report_path = root / f"deepseek_{slug}.json"

        if target.kind == "contract":
            from .etherscan_source import EtherscanError, EtherscanSource
            pin_dir = root / "contracts" / target.repository.lower()
            pin_dir.mkdir(parents=True, exist_ok=True)
            try:
                source_cm = EtherscanSource(api_key=os.environ.get("ETHERSCAN_API_KEY", ""))
            except EtherscanError as exc:
                return HuntOutcome(target=target, error=str(exc)[:200])
        else:
            from .repo_clone import RepoCloneError, clone_repository
            from .repo_clone import LocalRepoSource
            pin_dir = root / "repos" / target.repository.replace("/", "__")
            pin_dir.mkdir(parents=True, exist_ok=True)
            try:
                clone = clone_repository(
                    target.repository,
                    cache_dir=os.environ.get("AEGIS_CLONE_DIR") or root / "clones",
                    token=os.environ.get("GITHUB_TOKEN", ""))
                source_cm = LocalRepoSource(clone.path, clone.commit)
            except RepoCloneError as exc:
                return HuntOutcome(target=target, error=str(exc)[:200])

        hunt_config = RepoHuntConfig(max_files=10, subpath=target.subpath, samples=samples,
                                     content_scan_pool=3000)
        with source_cm as source, DeepSeekClient(config) as client:
            result = hunt_repository(source, client, target.repository,
                                     config=hunt_config, pin_dir=pin_dir)
        report_path.write_text(json.dumps(result.report(), indent=2), encoding="utf-8")

        if not result.hypotheses:
            return HuntOutcome(target=target)

        from .report_validation import validate_deepseek_report
        val_env = dict(env)
        val_env.update(DEEPSEEK_MAX_TOKENS="4096")
        with DeepSeekClient(DeepSeekConfig.from_env(val_env)) as client:
            validated, model = validate_deepseek_report(report_path, pin_dir, client)
        counts = validated["scan"]["validation_counts"]

        _record(validated, target.handle)
        findings = [{"cwe": (row.get("json_answer") or {}).get("vulnerability_type", ""),
                     "location": f"{(row.get('json_answer') or {}).get('file_path','')}:"
                                 f"{(row.get('json_answer') or {}).get('line','')}",
                     "summary": (row.get("json_answer") or {}).get("summary", "")[:160]}
                    for row in validated.get("vulnerabilities") or []
                    if (row.get("validation") or {}).get("verdict") == "confirmed"]

        poc_dir = ""
        if counts.get("confirmed"):
            from .poc_harness import build_pocs_from_report
            out = root / "poc" / target.repository.replace("/", "__").lower()
            build_pocs_from_report(report_path, out, program_handle=target.handle,
                                   repo_root=pin_dir)
            poc_dir = str(out)

        return HuntOutcome(target=target, confirmed=counts.get("confirmed", 0),
                           unresolved=counts.get("unresolved", 0),
                           rejected=counts.get("false_positive", 0),
                           poc_dir=poc_dir, findings=findings)

    return hunt_fn


def _record(validated: dict, handle: str) -> None:
    try:
        from ..learn.store import Outcome, OutcomeStore, Verdict
        from .agents.runner import cwe_key
        db = os.environ.get("AEGIS_LEARN_DB")
        if not db:
            return
        store = OutcomeStore(db)
        mp = {"confirmed": Verdict.CONFIRMED, "false_positive": Verdict.FALSE_POSITIVE,
              "unresolved": Verdict.PENDING}
        repo = (validated.get("scan") or {}).get("repository", "")
        for row in validated.get("vulnerabilities") or []:
            a = row.get("json_answer") or {}
            v = (row.get("validation") or {}).get("verdict", "unresolved")
            store.record(Outcome(detector="ai:auto-hunt", cwe=cwe_key(a.get("vulnerability_type") or "")[:80],
                                 verdict=mp.get(v, Verdict.PENDING),
                                 fingerprint=str(row.get("target") or a.get("file_path") or "")[:200],
                                 asset=repo, program=handle, summary=str(a.get("summary") or "")[:200]))
    except Exception:
        return


def build_targets_from_ranking(ranking_path: str | Path) -> list[HuntTarget]:
    """Load a saved profit ranking (json list of dicts) into HuntTargets. Fields:
    repository, handle, reward_ceiling, findability, subpath, kind."""
    data = json.loads(Path(ranking_path).read_text(encoding="utf-8"))
    out: list[HuntTarget] = []
    for row in data:
        if not isinstance(row, dict) or not row.get("repository"):
            continue
        out.append(HuntTarget(
            repository=row["repository"], handle=row.get("handle", ""),
            reward_ceiling=float(row.get("reward_ceiling", 0) or 0),
            findability=float(row.get("findability", 0.5) or 0.5),
            subpath=row.get("subpath", ""), kind=row.get("kind", "repo")))
    return out
