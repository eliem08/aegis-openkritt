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


def make_hunt_fn(*, report_root: str | Path = "reports", hint: str = ""):
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

        # scan_root is where the deterministic scanners + auto-hint read the WHOLE code
        # (the full clone), vs pin_dir which holds only the LLM's pinned slices. Scanners
        # are cheap and should see every file, not just the ~10 the LLM sampled.
        scan_root = None
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
                scan_root = clone.path            # full clone for scanners + auto-hint
            except RepoCloneError as exc:
                return HuntOutcome(target=target, error=str(exc)[:200])

            # scope gate: skip retired/archived/demo repos before spending any budget —
            # no program pays for known issues in code its own README says not to use.
            try:
                from .repo_status import retirement_status
                st = retirement_status(clone.path)
                if st["retired"]:
                    return HuntOutcome(target=target,
                                       error=f"skipped (out of scope): {st['reason']}"[:200])
            except Exception:
                pass

        scan_root = scan_root or pin_dir          # contracts scan the pinned .sol

        # self-hint: if no operator hint was given and AEGIS_AUTO_HINT=1, let the model read
        # a sample of the code and produce its own focused lead (the "small hint" edge,
        # generated automatically) to seed the ensemble. Cheap recon pass; degrades to "".
        effective_hint = hint
        if not effective_hint and os.environ.get("AEGIS_AUTO_HINT", "").strip() == "1" \
                and target.kind == "repo":
            try:
                from .auto_hint import auto_hint_for
                with DeepSeekClient(config) as hc:
                    effective_hint = auto_hint_for(scan_root, target.repository, hc,
                                                   subpath=target.subpath)
            except Exception:
                effective_hint = ""

        # coverage: analyze EVERY eligible source file by default (AEGIS_MAX_FILES=all/0),
        # not a sampled top-N. The deterministic scanners already cover the whole repo;
        # this makes the LLM ensemble cover it too. A number caps it for cost control.
        _mf = os.environ.get("AEGIS_MAX_FILES", "all").strip().lower()
        cover_all = _mf in ("all", "0", "")
        max_files = 100000 if cover_all else int(_mf)
        # max_per_dir=0 disables the per-component cap (default 3) that was limiting the LLM
        # to a handful of files — the real reason coverage was ~10, not max_files.
        hunt_config = RepoHuntConfig(max_files=max_files, subpath=target.subpath, samples=samples,
                                     content_scan_pool=100000, operator_hint=effective_hint,
                                     max_per_dir=0 if cover_all else 3)
        with source_cm as source, DeepSeekClient(config) as client:
            result = hunt_repository(source, client, target.repository,
                                     config=hunt_config, pin_dir=pin_dir)
        report = result.report()

        # --- full arsenal: fold arm's-length skills + installed OSS scanners into the
        # report BEFORE validation, so their findings run through the SAME citation
        # validator as the LLM's (mutual cross-check). Each row is tagged with its source
        # ("aegis:tool:<name>" / "aegis:skill:<name>") for UI provenance. ---
        scanner_candidates = skill_candidates = 0
        tools_run: list[str] = []
        try:
            from .skill_bridge import SkillBridge
            sb = SkillBridge()
            if sb.enabled:
                runs = sb.run(target.repository, target_kind=target.kind)
                srows = sb.to_findings(runs, repository=target.repository)
                if srows:
                    report.setdefault("vulnerabilities", []).extend(srows)
                    skill_candidates = len(srows)
                tools_run += [f"skill:{r.skill}" for r in runs if getattr(r, "ok", False)]
        except Exception:
            pass
        try:
            from .tool_bridge import ToolBridge, available_tools
            lanes = ("contract",) if target.kind == "contract" else ("code", "secrets", "deps")
            avail = []
            for ln in lanes:
                avail += available_tools(ln)
            avail = list({t.name: t for t in avail}.values())
            if avail:
                # bounded per-tool timeout so a slow scanner (e.g. psalm + 163k-line WP
                # stubs on a whole plugin) can't stall the hunt for many minutes.
                _stimeout = int(os.environ.get("AEGIS_SCANNER_TIMEOUT", "300") or 300)
                tresults = ToolBridge(timeout=_stimeout).scan(str(scan_root), tools=avail)
                trows = ToolBridge().findings(tresults)
                if trows:
                    report.setdefault("vulnerabilities", []).extend(trows)
                scanner_candidates = len(trows)
                tools_run += [tr.tool for tr in tresults if getattr(tr, "ran", False)]
        except Exception:
            pass

        # arm's-length Strix (autonomous AI pentester) — opt-in (AEGIS_ALLOW_STRIX=1), a
        # heavyweight engine that runs its own agent + PoC validation on the local source.
        # Its findings fold in like any other engine and are re-checked by Aegis's validator.
        try:
            from .strix_bridge import StrixBridge
            strix = StrixBridge()
            if strix.enabled and target.kind == "repo":
                run_dir = strix.run(scan_root, instruction=effective_hint)
                xrows = strix.to_findings(run_dir, repository=target.repository)
                if xrows:
                    report.setdefault("vulnerabilities", []).extend(xrows)
                tools_run += ["strix"] if run_dir else []
        except Exception:
            pass

        # cross-engine corroboration: tag each candidate with how many DISTINCT engines
        # (llm / scanner:x / skill:y) flagged the same file+line. Agreement is strong signal.
        try:
            from .corroboration import corroborate
            corroborate(report.get("vulnerabilities", []))
        except Exception:
            pass

        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        # nothing at all to validate (no LLM hypotheses AND no scanner/skill rows)
        if not report.get("vulnerabilities"):
            return HuntOutcome(target=target, scanner_candidates=scanner_candidates,
                               skill_candidates=skill_candidates, tools_run=tools_run)

        from .report_validation import validate_deepseek_report
        # Two-model split: DeepSeek did the bulk re-runs (dirty work); the FINAL check
        # runs on a stronger, separately-configured model when AEGIS_VALIDATOR_MODEL /
        # _BASE_URL / _API_KEY are set (e.g. a Sonnet-class reasoner) — else the same
        # DeepSeek at a tighter budget.
        val_env = dict(env)
        val_env.update(DEEPSEEK_MAX_TOKENS="4096")
        vm = os.environ.get("AEGIS_VALIDATOR_MODEL")
        if vm:
            val_env["DEEPSEEK_MODEL"] = vm
            if os.environ.get("AEGIS_VALIDATOR_BASE_URL"):
                val_env["DEEPSEEK_BASE_URL"] = os.environ["AEGIS_VALIDATOR_BASE_URL"]
            if os.environ.get("AEGIS_VALIDATOR_API_KEY"):
                val_env["DEEPSEEK_API_KEY"] = os.environ["AEGIS_VALIDATOR_API_KEY"]
            val_env["DEEPSEEK_THINKING"] = os.environ.get("AEGIS_VALIDATOR_THINKING", "enabled")
        with DeepSeekClient(DeepSeekConfig.from_env(val_env)) as client:
            validated, model = validate_deepseek_report(report_path, scan_root, client)
        counts = validated["scan"]["validation_counts"]

        # reachability gate: a confirmed taint/sink is worthless if no call site can reach
        # the sink. Flip 'confirmed' rows whose enclosing function is PROVABLY unreachable
        # (arity mismatch = a guaranteed runtime error before the sink) to false_positive.
        # Conservative: only arity-mismatch flips; 'no-callers' is advisory (routes/DI/
        # reflection make it unreliable). This is the fix for the render_inline dead-code miss.
        try:
            from .reachability import check as _reach
            flipped = 0
            for row in validated.get("vulnerabilities") or []:
                v = row.get("validation") or {}
                if v.get("verdict") != "confirmed":
                    continue
                a = row.get("json_answer") or {}
                rc = _reach(scan_root, str(a.get("file_path") or ""), a.get("line") or 0)
                row["reachability"] = rc
                if rc.get("verdict") == "arity-mismatch":
                    v["verdict"] = "false_positive"
                    v["reason"] = ("reachability gate: " + rc.get("note", "unreachable"))[:300]
                    flipped += 1
            if flipped:
                c = {"confirmed": 0, "false_positive": 0, "unresolved": 0}
                for row in validated.get("vulnerabilities") or []:
                    vd = (row.get("validation") or {}).get("verdict")
                    if vd in c:
                        c[vd] += 1
                counts = validated["scan"]["validation_counts"] = c
                report_path.write_text(json.dumps(validated, indent=2), encoding="utf-8")
        except Exception:
            pass

        _record(validated, target.handle)
        # professional per-finding triage (trust-model gate, CVSS, chain, prior-art,
        # bounty, remediation) — Aegis-native, one DeepSeek call per confirmed finding
        if counts.get("confirmed"):
            try:
                from .enrich import enrich_report
                purl = f"https://hackerone.com/{target.handle}" if target.handle else ""
                with DeepSeekClient(DeepSeekConfig.from_env(val_env)) as ec:
                    enrich_report(report_path, ec, program_url=purl, only_confirmed=True)
                validated = json.loads(report_path.read_text(encoding="utf-8"))
            except Exception:
                pass

        # guarded local-instance reproduction: if opt-in (AEGIS_ALLOW_REPRO=1) and the repo
        # ships a docker-compose, bring up a disposable LOCALHOST instance and prove-or-
        # refute each confirmed finding with a deterministic oracle. Default OFF; never a
        # third party; any failure degrades to "not attempted".
        repro_summary = {"attempted": False}
        if counts.get("confirmed"):
            try:
                from .repro_hook import maybe_reproduce, repro_enabled
                if repro_enabled():
                    with DeepSeekClient(DeepSeekConfig.from_env(val_env)) as rc_client:
                        repro_summary = maybe_reproduce(scan_root, validated, rc_client)
                    report_path.write_text(json.dumps(validated, indent=2), encoding="utf-8")
            except Exception as exc:
                repro_summary = {"attempted": False, "reason": f"{type(exc).__name__}"}

        from .economics import estimate
        findings = []
        for row in validated.get("vulnerabilities") or []:
            if (row.get("validation") or {}).get("verdict") != "confirmed":
                continue
            a = row.get("json_answer") or {}
            est = estimate(vuln_type=a.get("vulnerability_type", ""),
                           severity=a.get("severity") or row.get("severity") or "medium",
                           handle=target.handle,
                           agreement=int(row.get("agreement", 1) or 1),
                           samples=int(row.get("samples", 1) or 1)).as_dict()
            enr = row.get("enrichment") or {}
            # provenance: which engine originally proposed this (llm / scanner / skill)
            src = str(row.get("source") or "aegis:llm")
            origin = ("scanner" if ":tool:" in src else "skill" if ":skill:" in src else "llm")
            corr = row.get("corroboration") or {"count": 1, "engines": []}
            findings.append({
                "cwe": a.get("vulnerability_type", ""),
                "location": f"{a.get('file_path','')}:{a.get('line','')}",
                "summary": (a.get("summary") or "")[:160],
                "origin": origin, "engine": src.split(":")[-1] if ":" in src else "deepseek",
                "corroboration": int(corr.get("count", 1)),
                "corroborated_by": corr.get("engines", []),
                "severity": est["severity"], "agreement": est["agreement"],
                "min_bounty": est["min_bounty"], "likely_bounty": est["likely_bounty"],
                "expected_gain": est["expected_gain"], "vuln_type": est["vuln_type"],
                # professional triage layer (Aegis-native enrichment)
                "cvss": enr.get("cvss_score"), "cvss_vector": enr.get("cvss_vector"),
                "trust_model_holds": enr.get("trust_model_holds"),
                "exploit_practicality": enr.get("exploit_practicality"),
                "chain_required": enr.get("chain_required"),
                "remediation": enr.get("remediation"),
                # local-instance reproduction verdict (reproduced / not_reproduced / None)
                "reproduction": (row.get("reproduction") or {}).get("verdict"),
                "repro_summary": (row.get("reproduction") or {}).get("summary")})

        # rank: locally REPRODUCED first (proven exploitable), then multi-engine
        # corroboration, then expected gain
        findings.sort(key=lambda f: (0 if f.get("reproduction") == "reproduced" else 1,
                                     -int(f.get("corroboration", 1)),
                                     -float(f.get("expected_gain", 0) or 0)))

        poc_dir = ""
        if counts.get("confirmed"):
            from .poc_harness import build_pocs_from_report
            out = root / "poc" / target.repository.replace("/", "__").lower()
            build_pocs_from_report(report_path, out, program_handle=target.handle,
                                   repo_root=scan_root)
            poc_dir = str(out)

        return HuntOutcome(target=target, confirmed=counts.get("confirmed", 0),
                           unresolved=counts.get("unresolved", 0),
                           rejected=counts.get("false_positive", 0),
                           poc_dir=poc_dir, findings=findings,
                           scanner_candidates=scanner_candidates,
                           skill_candidates=skill_candidates, tools_run=tools_run)

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
            saturation=float(row.get("saturation", 0.0) or 0.0),
            subpath=row.get("subpath", ""), kind=row.get("kind", "repo")))
    return out
