"""Review-console UI — one page over findings from Aegis + open·kritt.

``GET /ui`` serves a self-contained console (no external assets). It renders a
*console model* built by :func:`aegis.report.build_console`, obtained either from a
connected open·kritt backend (``GET /ui/review?scan=<id>``) or by uploading an
open·kritt export (``POST /ui/review``). Every row is a candidate pending Aegis's
own verification gate — the console is a human-review surface, not a verdict, in
keeping with the human-supervised model.
"""

from __future__ import annotations

from pathlib import Path

import httpx
from fastapi import APIRouter, Body, Request
from fastapi.responses import HTMLResponse

from aegis.report import build_console

_TEMPLATES = Path(__file__).resolve().parent.parent / "templates"


def _hunt_console_html() -> str:
    """The autonomous-hunt dashboard, read fresh so edits show without a restart."""
    try:
        return (_TEMPLATES / "hunt_console.html").read_text(encoding="utf-8")
    except OSError:
        return "<h1>hunt console template missing</h1>"

router = APIRouter(tags=["ui"])


@router.get("/ui", response_class=HTMLResponse, summary="Findings review console")
def console_page() -> HTMLResponse:
    return HTMLResponse(CONSOLE_HTML)


@router.get("/ui/review", summary="Merged review model (live from open·kritt if connected)")
def review(request: Request, scan: str = "", scans: str = "") -> dict:
    config = request.app.state.config
    client = config.build_openkritt_client()
    if client is None:
        return _empty("No open·kritt backend connected. Set AEGIS_OPENKRITT_URL, or "
                      "upload an open·kritt export below.")
    url = getattr(config, "openkritt_url", "")
    scan_ids = [s.strip() for s in scans.split(",") if s.strip()] or ([scan] if scan else [])
    cal = _calibration(request)
    try:
        if not scan_ids:
            found = client.list_scans()
            return _empty(f"open·kritt backend connected ({len(found)} scans). "
                          "Enter a scan id to load its findings.", backend=True)
        if len(scan_ids) == 1:
            model = build_console(client.import_candidates(scan_ids[0]), scan_id=scan_ids[0],
                                  calibration=cal)
        else:
            from aegis.integrations import console_for_scans
            model = console_for_scans(client, scan_ids, calibration=cal)
        model["backend_connected"] = True
        return model
    except httpx.HTTPError as exc:
        # Configured but unreachable/erroring: degrade to a clear message, not a 500.
        return _empty(f"open·kritt is configured ({url}) but not reachable: {exc}. "
                      "Start it (./kritt setup) or upload an export below.")
    finally:
        client.close()


@router.post("/ui/h1-scan", summary="HackerOne program -> open·kritt scans (code-repo programs)")
def h1_scan(request: Request, payload=Body(...)) -> dict:
    """Discover a HackerOne program's in-scope repos and launch an open·kritt scan
    on each. Read-only on HackerOne; launches on authorized targets only; never
    exploits and never auto-submits."""
    from aegis.ingest.hackerone import HackerOneAuthError, HackerOneClient
    from aegis.integrations import PipelineError, run_repo_pipeline

    config = request.app.state.config
    ok_client = config.build_openkritt_client()
    if ok_client is None:
        return {"error": "No open·kritt backend connected. Set AEGIS_OPENKRITT_URL."}
    handle = str((payload or {}).get("handle") or "").strip()
    model = str((payload or {}).get("model") or "").strip()
    if not handle:
        return {"error": "A HackerOne program handle is required."}
    if not model:
        return {"error": "A model id is required (from your open·kritt account, e.g. a Claude model)."}
    try:
        h1 = HackerOneClient.from_env()
    except HackerOneAuthError:
        return {"error": "HackerOne credentials not set "
                         "(HACKERONE_API_USERNAME / HACKERONE_API_TOKEN)."}
    try:
        result = run_repo_pipeline(h1, ok_client, handle, model=model)
    except PipelineError as exc:
        return {"error": str(exc)}
    except httpx.HTTPError as exc:
        return {"error": f"request failed: {exc}"}
    finally:
        ok_client.close()

    return {
        "handle": result.handle, "program_name": result.program_name,
        "gated": result.gated, "reason": result.reason,
        "repos": [{"repo_full": r.repo_full, "identifier": r.identifier} for r in result.repos],
        "launches": [{"repo_full": l.repo.repo_full, "scan_id": l.scan_id, "error": l.error}
                     for l in result.launches],
        "scan_ids": result.scan_ids,
        "review_url": ("/ui/review?scans=" + ",".join(result.scan_ids)) if result.scan_ids else "",
    }


@router.post("/ui/review", summary="Build a review model from an uploaded open·kritt export")
def review_from_export(request: Request, payload=Body(...)) -> dict:
    from aegis.integrations import ingest_openkritt_findings

    export = payload.get("export") if isinstance(payload, dict) else payload
    candidates = ingest_openkritt_findings(export)
    model = build_console(candidates, calibration=_calibration(request))
    model["note"] = f"Loaded {len(candidates)} finding(s) from an uploaded export."
    return model


@router.post("/ui/deepseek/validate", summary="Automatically validate a direct DeepSeek report")
def start_deepseek_validation(request: Request, payload=Body(None)) -> dict:
    """Refresh authorization, then validate every hypothesis in a background job."""
    import os
    import re
    import threading
    import uuid
    from pathlib import Path

    from aegis.ai import DeepSeekConfig
    from aegis.ingest.hackerone import HackerOneClient
    from aegis.integrations import repos_in_scope

    data = payload if isinstance(payload, dict) else {}
    handle = str(data.get("handle") or "circle-bbp").strip()
    repo_full = str(data.get("repo_full") or "circlefin/evm-cctp-contracts").strip()
    try:
        DeepSeekConfig.from_env()
        h1 = HackerOneClient.from_env()
    except Exception as exc:
        return {"error": f"validation configuration failed: {type(exc).__name__}"}
    try:
        rules = h1.fetch_program_rules(handle)
        scope = repos_in_scope(rules, bounty_only=True)
        target = next((r for r in scope.repos if r.repo_full.casefold() == repo_full.casefold()), None)
        if scope.gated or target is None:
            return {"error": scope.reason or "repository is not currently bounty eligible"}
    except httpx.HTTPError as exc:
        return {"error": f"scope refresh failed: {exc}"}
    finally:
        h1.close()

    report_root = Path(os.environ.get("AEGIS_REPORT_DIR", "reports")).resolve()
    canonical_name = f"deepseek_{repo_full.replace('/', '_')}.json"
    sanitized_name = "deepseek_" + re.sub(r"[^A-Za-z0-9]+", "_", repo_full).strip("_") + ".json"
    report_path = report_root / canonical_name
    if not report_path.is_file():
        report_path = report_root / sanitized_name
    repo_root = report_root / "repos" / repo_full.replace("/", "__")
    if not report_path.is_file():
        return {"error": f"DeepSeek report is missing: {canonical_name}"}
    if not repo_root.is_dir():
        return {"error": "pinned repository checkout is missing"}

    jobs = getattr(request.app.state, "deepseek_validation_jobs", None)
    if jobs is None:
        jobs = request.app.state.deepseek_validation_jobs = {}
    job_id = uuid.uuid4().hex[:12]
    jobs[job_id] = {
        "id": job_id, "status": "queued", "completed": 0, "total": 0,
        "repo_full": repo_full, "handle": handle, "current_file": "",
    }
    threading.Thread(
        target=_run_deepseek_validation,
        args=(request.app, job_id, report_path, repo_root),
        daemon=True,
        name=f"aegis-validate-{job_id}",
    ).start()
    return {
        "job_id": job_id, "status": "queued",
        "status_url": f"/ui/deepseek/jobs/{job_id}",
        "result_url": f"/ui/deepseek/results/{job_id}",
    }


@router.get("/ui/deepseek/jobs/{job_id}", summary="DeepSeek validation progress")
def deepseek_validation_status(request: Request, job_id: str) -> dict:
    jobs = getattr(request.app.state, "deepseek_validation_jobs", {})
    return jobs.get(job_id) or {"error": "validation job not found"}


@router.post("/ui/autohunt", summary="Start an autonomous, EV-ranked code-lane hunt (candidates only)")
def start_autohunt(request: Request, payload=Body(None)) -> dict:
    """Rank code/contract targets by expected value and hunt the best ones in the
    background, surfacing confirmed candidates + PoC scaffolds. Never submits."""
    import os
    import threading
    import uuid
    from pathlib import Path

    from aegis.ai.auto_hunt import AutoHuntConfig
    from aegis.ai.auto_hunt_run import build_targets_from_ranking

    data = payload if isinstance(payload, dict) else {}
    report_root = Path(os.environ.get("AEGIS_REPORT_DIR", "reports")).resolve()
    ranking = str(data.get("ranking") or (report_root / "autohunt_targets.json"))
    if not Path(ranking).is_file():
        return {"error": f"target ranking not found: {ranking} — POST a 'ranking' path "
                         "(a json list of {repository, handle, reward_ceiling, findability})"}
    try:
        targets = build_targets_from_ranking(ranking)
    except Exception as exc:
        return {"error": f"could not load targets: {type(exc).__name__}"}
    if not targets:
        return {"error": "no valid targets in the ranking file"}

    config = AutoHuntConfig(
        max_targets=int(data.get("max_targets", 3)),
        samples=int(data.get("samples", 3)),
        min_ev=float(data.get("min_ev", 0.0)),
    )
    jobs = getattr(request.app.state, "autohunt_jobs", None)
    if jobs is None:
        jobs = request.app.state.autohunt_jobs = {}
    continuous = bool(data.get("continuous", False))
    interval = float(data.get("interval", 30.0))
    job_id = uuid.uuid4().hex[:12]
    jobs[job_id] = {"id": job_id, "status": "queued", "events": [], "continuous": continuous,
                    "targets": len(targets), "confirmed_total": 0, "summary": None, "stop": False}
    threading.Thread(target=_run_autohunt,
                     args=(request.app, job_id, targets, config, str(report_root)),
                     kwargs={"continuous": continuous, "interval": interval},
                     daemon=True, name=f"aegis-autohunt-{job_id}").start()
    return {"job_id": job_id, "status": "queued", "continuous": continuous,
            "status_url": f"/ui/autohunt/{job_id}", "stop_url": f"/ui/autohunt/{job_id}/stop"}


@router.post("/ui/autohunt/{job_id}/stop", summary="Signal a continuous hunt to stop after the current target")
def stop_autohunt(request: Request, job_id: str) -> dict:
    jobs = getattr(request.app.state, "autohunt_jobs", {})
    job = jobs.get(job_id)
    if not job:
        return {"error": "autohunt job not found"}
    job["stop"] = True
    return {"job_id": job_id, "status": "stopping"}


@router.get("/ui/autohunt/{job_id}", summary="Autonomous hunt progress + confirmed candidates")
def autohunt_status(request: Request, job_id: str) -> dict:
    jobs = getattr(request.app.state, "autohunt_jobs", {})
    return jobs.get(job_id) or {"error": "autohunt job not found"}


@router.get("/ui/autohunt-jobs", summary="List autohunt jobs so the dashboard can re-attach")
def autohunt_jobs(request: Request) -> dict:
    jobs = getattr(request.app.state, "autohunt_jobs", {}) or {}
    return {"jobs": [
        {"job_id": j.get("id"), "status": j.get("status"), "continuous": j.get("continuous", False),
         "cycle": j.get("cycle"), "confirmed_total": j.get("confirmed_total", 0)}
        for j in jobs.values()]}


@router.get("/ui/autohunt-targets", summary="Preview the EV-ranked target queue")
def autohunt_targets(request: Request) -> dict:
    import os
    from pathlib import Path

    from aegis.ai.auto_hunt import AutoHuntConfig, rank_targets
    from aegis.ai.auto_hunt_run import build_targets_from_ranking

    report_root = Path(os.environ.get("AEGIS_REPORT_DIR", "reports")).resolve()
    path = report_root / "autohunt_targets.json"
    if not path.is_file():
        return {"targets": [], "note": "no reports/autohunt_targets.json yet"}
    try:
        targets = build_targets_from_ranking(path)
    except Exception as exc:
        return {"targets": [], "error": type(exc).__name__}
    ranked = rank_targets(targets, AutoHuntConfig())
    return {"targets": [
        {"repository": t.repository, "handle": t.handle, "kind": t.kind,
         "reward_ceiling": t.reward_ceiling, "findability": round(t.findability, 3),
         "saturation": round(t.saturation, 3), "subpath": t.subpath, "ev": ev}
        for t, ev in ranked]}


@router.get("/ui/hunt-console", response_class=HTMLResponse,
            summary="Autonomous hunt operations dashboard")
def hunt_console() -> HTMLResponse:
    return HTMLResponse(_hunt_console_html())


def _run_autohunt(app, job_id, targets, config, report_root,
                  *, continuous: bool = False, interval: float = 30.0) -> None:
    import time

    from aegis.ai.auto_hunt import AutoHunter
    from aegis.ai.auto_hunt_run import make_hunt_fn

    job = app.state.autohunt_jobs[job_id]
    job["status"] = "running"

    def on_event(kind, data):
        job["events"].append({"kind": kind, **{k: v for k, v in data.items() if k != "ranked"}})
        # keep the live log bounded so a 24/7 job doesn't grow without limit
        if len(job["events"]) > 500:
            del job["events"][: len(job["events"]) - 500]
        if kind == "hunt_done":
            job["confirmed_total"] = job.get("confirmed_total", 0) + int(data.get("confirmed", 0))

    try:
        from aegis.ai.auto_hunt import rank_targets

        hunt_fn = make_hunt_fn(report_root=report_root)
        hunter = AutoHunter(hunt_fn, config=config, on_event=on_event)
        # Pre-rank ONCE (saturation-penalized EV), drop everything below min_ev — i.e.
        # the crowded/low-value tail — then walk the least-crowded pool in sequential
        # chunks across cycles so an overnight run actually covers the whole shortlist
        # instead of re-hunting the same top targets each cycle.
        ranked_all = rank_targets(targets, config)
        pool = [t for t, ev in ranked_all if ev >= config.min_ev] or [t for t, _ in ranked_all]
        job["pool_size"] = len(pool)
        step = max(1, config.max_targets)
        offset = 0
        cum: dict[str, dict] = {}       # cumulative per-target results across cycles
        while True:
            cycle += 1
            job["cycle"] = cycle
            chunk = [pool[(offset + i) % len(pool)] for i in range(min(step, len(pool)))]
            on_event("cycle_start", {"cycle": cycle, "chunk": [t.repository for t in chunk],
                                     "pool": len(pool)})
            session = hunter.run(chunk)
            for res in session.summary().get("results", []):
                cum[res["repository"]] = res      # latest verdict per target
            job["summary"] = {"targets_hunted": len(cum), "results": list(cum.values())}
            if not continuous or job.get("stop"):
                break
            offset = (offset + step) % len(pool)
            if offset < step:
                on_event("pool_wrapped", {"cycle": cycle})   # completed a full sweep
            on_event("cycle_sleep", {"cycle": cycle, "seconds": interval})
            slept = 0.0
            while slept < interval and not job.get("stop"):
                time.sleep(min(2.0, interval - slept)); slept += 2.0
            if job.get("stop"):
                break
        job["status"] = "stopped" if job.get("stop") else "completed"
    except Exception as exc:
        job["status"] = "error"
        job["error"] = f"{type(exc).__name__}: {exc}"[:200]


@router.get("/ui/deepseek/latest", response_class=HTMLResponse,
            summary="Latest persisted DeepSeek validation")
def latest_deepseek_validation(repo_full: str = "circlefin/evm-cctp-contracts") -> HTMLResponse:
    """Render the last persisted validation, including after an API restart."""
    import os
    import re
    from pathlib import Path

    from aegis.ai.report_validation import review_model_from_report

    report_root = Path(os.environ.get("AEGIS_REPORT_DIR", "reports")).resolve()
    names = [
        f"deepseek_{repo_full.replace('/', '_')}.json",
        "deepseek_" + re.sub(r"[^A-Za-z0-9]+", "_", repo_full).strip("_") + ".json",
    ]
    report_path = next((report_root / name for name in names if (report_root / name).is_file()), None)
    if report_path is None:
        return HTMLResponse("Validated DeepSeek report not found", status_code=404)
    return HTMLResponse(_static_console(review_model_from_report(report_path)))


@router.get("/ui/deepseek/results/{job_id}", response_class=HTMLResponse,
            summary="Validated DeepSeek findings")
def deepseek_validation_result(request: Request, job_id: str) -> HTMLResponse:
    jobs = getattr(request.app.state, "deepseek_validation_jobs", {})
    job = jobs.get(job_id)
    if not job:
        return HTMLResponse("Validation job not found", status_code=404)
    if job.get("status") != "completed":
        return HTMLResponse("Validation is still running", status_code=202)
    return HTMLResponse(_static_console(job["model"]))


def _run_deepseek_validation(app, job_id, report_path, repo_root) -> None:
    import os
    from aegis.ai import DeepSeekClient
    from aegis.ai.report_validation import validate_deepseek_report

    job = app.state.deepseek_validation_jobs[job_id]
    job["status"] = "running"

    def progress(completed, total, current_file):
        job.update(completed=completed, total=total, current_file=current_file)

    env = dict(os.environ)
    env.update(
        DEEPSEEK_READ_TIMEOUT="300", DEEPSEEK_THINKING="disabled",
        DEEPSEEK_TEMPERATURE="0.1", DEEPSEEK_MAX_TOKENS="4096",
    )
    try:
        with DeepSeekClient.from_env(env=env) as client:
            report, model = validate_deepseek_report(
                report_path, repo_root, client, progress=progress,
            )
        job.update(
            status="completed", model=model,
            validation_counts=report["scan"]["validation_counts"],
            result_url=f"/ui/deepseek/results/{job_id}",
        )
    except Exception as exc:
        job.update(status="failed", error=f"{type(exc).__name__}: {str(exc)[:240]}")


def _static_console(model: dict) -> str:
    import json
    bootstrap = "<script>window.__CONSOLE__=" + json.dumps(model).replace("</", "<\\/") + ";</script>\n"
    return CONSOLE_HTML.replace("<script>\n(function () {", bootstrap + "<script>\n(function () {", 1)


@router.post("/ui/feedback", summary="Record a human verdict on a finding (the learning loop)")
def feedback(request: Request, payload=Body(...)) -> dict:
    """A confirmed / false_positive / duplicate verdict updates the calibration priors
    and the planner's retrieval memory — the console reranks and the LLM plans better
    from here on, automatically."""
    from aegis.learn import Calibration, Outcome, Verdict

    store = getattr(request.app.state, "outcomes", None)
    if store is None:
        return {"error": "learning store not available"}
    data = payload if isinstance(payload, dict) else {}
    try:
        verdict = Verdict(str(data.get("verdict", "")).strip().lower())
    except ValueError:
        return {"error": "verdict must be one of: confirmed, false_positive, duplicate, pending"}
    detector = str(data.get("detector") or data.get("worker") or "").strip()
    cwe = str(data.get("cwe") or "").strip()
    store.record(Outcome(
        detector=detector, cwe=cwe, verdict=verdict,
        fingerprint=str(data.get("fingerprint") or ""), asset=str(data.get("asset") or ""),
        program=str(data.get("program") or ""), summary=str(data.get("summary") or "")[:240]))
    cal = Calibration.from_outcomes(store.all())
    return {"recorded": store.count(),
            "learned_prior": round(cal.prior(detector=detector, cwe=cwe), 3)}


@router.post("/ui/hunt", summary="Run one automatic-hunting cycle (dry-run unless armed)")
def hunt_cycle(request: Request, payload=Body(None)) -> dict:
    """One pass of the hunter: authorized programs -> scan in-scope repos -> collect
    findings -> fold in report outcomes. Dry-run by default (plans, launches nothing);
    pass ``{"arm": true, "model": "..."}`` to actually launch. Never submits."""
    from aegis.ingest.hackerone import HackerOneAuthError, HackerOneClient
    from aegis.hunt import HuntConfig, HuntOrchestrator

    config = request.app.state.config
    ok = config.build_openkritt_client()
    if ok is None:
        return {"error": "No open·kritt backend connected. Set AEGIS_OPENKRITT_URL."}
    data = payload if isinstance(payload, dict) else {}
    armed = bool(data.get("arm"))
    model = str(data.get("model") or "")
    if armed and not model:
        return {"error": "model is required to arm (launch) scans."}
    try:
        h1 = HackerOneClient.from_env()
    except HackerOneAuthError:
        return {"error": "HackerOne credentials not set "
                         "(HACKERONE_API_USERNAME / HACKERONE_API_TOKEN)."}
    handles = tuple(str(h).strip() for h in (data.get("handles") or []) if str(h).strip())
    fallbacks = tuple(str(m).strip() for m in (data.get("fallbacks") or []) if str(m).strip())
    try:
        from decimal import Decimal

        payout_data = data.get("expected_bounties") or {}
        if not isinstance(payout_data, dict):
            raise ValueError("expected_bounties must be an object")
        expected_bounties = {
            str(handle).strip(): Decimal(str(amount))
            for handle, amount in payout_data.items()
            if str(handle).strip()
        }
        cfg = HuntConfig(
            model=model, fallback_models=fallbacks, only_handles=handles,
            dry_run=not armed, max_programs=int(data.get("max_programs") or 3),
            max_repos_per_program=int(data.get("max_repos") or 3),
            portfolio_capacity=int(data.get("portfolio_capacity") or 0),
            exploration_fraction=float(data.get("exploration_fraction", 0.2)),
            expected_bounties=expected_bounties,
            verify_model=str(data.get("verify_model") or ""),
            verify_threshold=float(data.get("verify_threshold", 0.35)),
            use_deepseek_fallback=bool(data.get("deepseek_fallback")),
        )
    except (TypeError, ValueError) as exc:
        ok.close()
    hunter = HuntOrchestrator(h1, ok, request.app.state.outcomes,
                              request.app.state.submissions, config=cfg)
    try:
        report = hunter.cycle()
    except httpx.HTTPError as exc:
        return {"error": f"request failed: {exc}"}
    finally:
        ok.close()
        h1.close()
    return report.summary()


def _calibration(request: Request):
    """Calibration built from all recorded verdicts (neutral when none yet)."""
    from aegis.learn import Calibration

    store = getattr(request.app.state, "outcomes", None)
    return Calibration.from_outcomes(store.all()) if store is not None else None


@router.post("/ui/submission", summary="Link a submitted HackerOne report to its finding")
def link_submission(request: Request, payload=Body(...)) -> dict:
    """Record that HackerOne report ``report_id`` came from this finding, so its
    eventual resolution can be attributed to the right detector/CWE. Call this when
    you submit a report."""
    ledger = getattr(request.app.state, "submissions", None)
    if ledger is None:
        return {"error": "submission ledger not available"}
    data = payload if isinstance(payload, dict) else {}
    report_id = str(data.get("report_id") or "").strip()
    if not report_id:
        return {"error": "report_id is required"}
    ledger.record_link(
        report_id, detector=str(data.get("detector") or data.get("worker") or ""),
        cwe=str(data.get("cwe") or ""), fingerprint=str(data.get("fingerprint") or ""),
        asset=str(data.get("asset") or ""), program=str(data.get("program") or ""),
        summary=str(data.get("summary") or ""))
    return {"linked": report_id}


@router.post("/ui/hackerone-sync", summary="Fold HackerOne report outcomes into the learning loop")
def hackerone_sync(request: Request) -> dict:
    """Read the states of your submitted reports and record resolved/duplicate/N-A
    as verdicts. Read-only on HackerOne; idempotent; teaches calibration + memory
    from real bounty outcomes."""
    from aegis.ingest.hackerone import HackerOneAuthError, HackerOneClient
    from aegis.learn import sync_hackerone_outcomes

    outcomes = getattr(request.app.state, "outcomes", None)
    ledger = getattr(request.app.state, "submissions", None)
    if outcomes is None or ledger is None:
        return {"error": "learning store not available"}
    try:
        h1 = HackerOneClient.from_env()
    except HackerOneAuthError:
        return {"error": "HackerOne credentials not set "
                         "(HACKERONE_API_USERNAME / HACKERONE_API_TOKEN)."}
    try:
        result = sync_hackerone_outcomes(h1, ledger, outcomes)
    except httpx.HTTPError as exc:
        return {"error": f"HackerOne request failed: {exc}"}
    finally:
        h1.close()
    return {"recorded": result.recorded, "by_verdict": result.by_verdict,
            "skipped_pending": result.skipped_pending,
            "skipped_unlinked": result.skipped_unlinked,
            "already_recorded": result.already_recorded,
            "total_outcomes": outcomes.count()}


def _empty(note: str, *, backend: bool = False) -> dict:
    model = build_console([])
    model["note"] = note
    model["backend_connected"] = backend
    return model


# --- the page (self-contained: inline CSS/JS, no external requests) ---------

CONSOLE_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Aegis — review console</title>
<style>
  :root {
    --bg: #0d1017; --panel: #141a26; --panel2: #1b2231; --line: #232c3f;
    --fg: #e8ecf5; --muted: #8a97b0; --faint: #566079;
    --accent: #5b8cff;
    --crit: #ff5d6b; --high: #ff9646; --med: #f2c14e; --low: #7c8aa5; --info: #4aa8ff;
    --ok: #35d29a; --aegis: #5b8cff; --okritt: #a06bff; --contract: #24cabb;
    --mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  @media (prefers-color-scheme: light) {
    :root { --bg:#f2f5fb; --panel:#ffffff; --panel2:#eef2f9; --line:#e0e6f1;
            --fg:#161c2b; --muted:#5c6880; --faint:#94a0b6; }
  }
  :root[data-theme="dark"] {
    --bg:#0d1017; --panel:#141a26; --panel2:#1b2231; --line:#232c3f;
    --fg:#e8ecf5; --muted:#8a97b0; --faint:#566079;
  }
  :root[data-theme="light"] {
    --bg:#f2f5fb; --panel:#ffffff; --panel2:#eef2f9; --line:#e0e6f1;
    --fg:#161c2b; --muted:#5c6880; --faint:#94a0b6;
  }
  * { box-sizing: border-box; }
  html { color-scheme: light dark; }
  body { margin: 0; background: var(--bg); color: var(--fg); font: 14px/1.55 var(--sans);
    -webkit-font-smoothing: antialiased; }
  header { padding: 20px 24px 16px; border-bottom: 1px solid var(--line);
    display: flex; align-items: baseline; gap: 14px; flex-wrap: wrap; }
  h1 { font-size: 16px; margin: 0; font-weight: 640; letter-spacing: .3px; }
  h1 b { font-weight: 740; }
  h1 .sep { color: var(--accent); font-family: var(--mono); margin: 0 2px; }
  h1 .tag { font: 600 10px/1 var(--mono); color: var(--faint); border: 1px solid var(--line);
    padding: 3px 6px; border-radius: 5px; letter-spacing: .5px; margin-left: 4px; text-transform: uppercase; }
  .sub { color: var(--muted); font: 12px/1.4 var(--mono); }
  main { padding: 20px 24px 60px; max-width: 1200px; }

  .summary { display: grid; grid-template-columns: repeat(4, auto) 1fr; gap: 12px;
    align-items: stretch; margin-bottom: 18px; }
  @media (max-width: 720px) { .summary { grid-template-columns: repeat(3, 1fr); } }
  .card { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 12px 15px; }
  .card .n { font: 650 24px/1.1 var(--mono); font-variant-numeric: tabular-nums; }
  .card .l { color: var(--muted); font-size: 10.5px; text-transform: uppercase; letter-spacing: .7px; margin-top: 3px; }
  .card.wide { display: flex; flex-direction: column; justify-content: center; min-width: 220px; }
  .sevbar { display: flex; height: 12px; border-radius: 6px; overflow: hidden; margin-bottom: 8px;
    background: var(--panel2); }
  .sevbar i { display: block; height: 100%; }
  .legend { display: flex; gap: 12px; flex-wrap: wrap; }
  .legend span { color: var(--muted); font: 11px/1 var(--mono); display: inline-flex; align-items: center; gap: 5px; }
  .legend b { width: 8px; height: 8px; border-radius: 2px; display: inline-block; }

  .controls { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-bottom: 14px; }
  .live { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
  input, button, select { font: inherit; color: var(--fg); background: var(--panel2);
    border: 1px solid var(--line); border-radius: 9px; padding: 8px 11px; }
  input { font-family: var(--mono); }
  button { cursor: pointer; }
  button.primary { background: var(--accent); color: #0b1220; border-color: transparent; font-weight: 620; }
  button:focus-visible, input:focus-visible, select:focus-visible, tr:focus-visible {
    outline: 2px solid var(--accent); outline-offset: 1px; }
  .up { display: inline-flex; align-items: center; gap: 6px; cursor: pointer; color: var(--muted);
    border: 1px dashed var(--line); border-radius: 9px; padding: 8px 11px; }
  .spacer { flex: 1; }
  .note { background: var(--panel); border: 1px dashed var(--line); border-radius: 10px;
    padding: 12px 14px; color: var(--muted); margin-bottom: 14px; font-size: 13px; }
  .hunt { background: var(--panel); border: 1px solid var(--line); border-radius: 12px;
    padding: 4px 14px 14px; margin-bottom: 14px; }
  .hunt summary { cursor: pointer; padding: 10px 0; font-weight: 620; color: var(--fg);
    font-size: 13px; }
  .hunt-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 10px; align-items: end; margin-top: 6px; }
  .hunt-grid label { display: flex; flex-direction: column; gap: 4px; font-size: 11.5px;
    color: var(--muted); }
  .hunt-grid label.chk { flex-direction: row; align-items: center; font-size: 12.5px; }
  .hunt-grid input[type=text], .hunt-grid input:not([type]) { width: 100%; }
  .hunt-out { margin: 10px 0 0; padding: 10px 12px; background: var(--panel2);
    border-radius: 8px; font: 12px/1.5 var(--mono); white-space: pre-wrap;
    max-height: 260px; overflow: auto; color: var(--muted); }

  .overflow { overflow-x: auto; border: 1px solid var(--line); border-radius: 12px; background: var(--panel); }
  table { width: 100%; border-collapse: collapse; min-width: 720px; }
  thead th { position: sticky; top: 0; background: var(--panel); z-index: 1; }
  th, td { text-align: left; padding: 11px 12px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { color: var(--muted); font-weight: 600; font-size: 10.5px; text-transform: uppercase; letter-spacing: .6px; }
  tbody tr { cursor: pointer; }
  tbody tr:hover { background: var(--panel2); }
  td.stripe { padding: 0; width: 4px; }
  td.rank, td.pri, td.cwe { font-family: var(--mono); font-variant-numeric: tabular-nums; color: var(--muted); }
  td.pri { color: var(--fg); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font: 600 11px/1.5 var(--sans); white-space: nowrap; }
  .mono { font-family: var(--mono); }
  .sev-critical { background: color-mix(in srgb, var(--crit) 18%, transparent); color: var(--crit); }
  .sev-high { background: color-mix(in srgb, var(--high) 18%, transparent); color: var(--high); }
  .sev-medium { background: color-mix(in srgb, var(--med) 20%, transparent); color: #c69a2f; }
  .sev-low { background: color-mix(in srgb, var(--low) 20%, transparent); color: var(--low); }
  .sev-info { background: color-mix(in srgb, var(--info) 18%, transparent); color: var(--info); }
  .src-aegis { background: color-mix(in srgb, var(--aegis) 16%, transparent); color: var(--aegis); }
  .src-open-kritt, .src-openkritt { background: color-mix(in srgb, var(--okritt) 18%, transparent); color: var(--okritt); }
  .src-contract { background: color-mix(in srgb, var(--contract) 18%, transparent); color: var(--contract); }
  .st-verified, .st-confirmed { background: color-mix(in srgb, var(--ok) 18%, transparent); color: var(--ok); }
  .st-false_positive { background: color-mix(in srgb, var(--low) 18%, transparent); color: var(--low); }
  .st-unresolved { border: 1px solid var(--line); color: var(--muted); }
  .st-hypothesis { border: 1px solid var(--line); color: var(--muted); }
  .title { font-weight: 600; }
  .loc { color: var(--faint); font: 12px/1.4 var(--mono); word-break: break-all; margin-top: 3px; }
  .dup { color: var(--faint); font: 11px/1 var(--mono); }
  .detail { color: var(--muted); font-size: 12.5px; margin-top: 7px; display: none;
    border-left: 2px solid var(--line); padding-left: 10px; }
  tr.open .detail { display: block; }
  .detail b { color: var(--fg); font-weight: 600; }
  .empty { text-align: center; color: var(--muted); padding: 44px; }
  @media (prefers-reduced-motion: no-preference) { tbody tr { transition: background .12s; } }
</style>
</head>
<body>
<header>
  <h1><b>Aegis</b><span class="sep">/</span>review console<span class="tag">human-supervised</span></h1>
  <span class="sub" id="genAt"></span>
</header>
<main>
  <section class="summary" id="summary"></section>

  <div class="controls">
    <div class="live" id="live">
      <input id="scanId" placeholder="open·kritt scan id" size="16" aria-label="open·kritt scan id" />
      <button class="primary" id="loadBtn">Load from backend</button>
      <label class="up">↑ Upload export<input id="fileIn" type="file" accept="application/json,.json" hidden /></label>
    </div>
    <span class="spacer"></span>
    <select id="fSource" aria-label="filter by source"><option value="">all sources</option></select>
    <select id="fSeverity" aria-label="filter by severity">
      <option value="">all severities</option>
      <option>critical</option><option>high</option><option>medium</option><option>low</option>
    </select>
    <select id="fStatus" aria-label="filter by status">
      <option value="">all statuses</option>
      <option value="confirmed">confirmed</option><option value="false_positive">rejected</option>
      <option value="unresolved">unresolved</option>
      <option value="verified">verified</option><option value="hypothesis">hypothesis</option>
    </select>
  </div>

  <details class="hunt">
    <summary>Hunt — run a cycle (dry-run unless armed)</summary>
    <div class="hunt-grid">
      <label>Model<input id="huntModel" placeholder="claude-sonnet-5" value="claude-sonnet-5" /></label>
      <label>Verify model (Opus, optional)<input id="huntVerifyModel" placeholder="claude-opus-5" /></label>
      <label>Handles (comma-separated, optional)<input id="huntHandles" placeholder="auto-select if blank" /></label>
      <label class="chk"><input id="huntDeepseek" type="checkbox" />Add DeepSeek (via OpenRouter) as a cheap fallback model</label>
      <label class="chk"><input id="huntArm" type="checkbox" />Arm — actually launch scans</label>
      <button class="primary" id="huntRunBtn">Run cycle</button>
    </div>
    <pre id="huntOut" class="hunt-out"></pre>
  </details>

  <details class="hunt" open>
    <summary>DeepSeek Platform - automatic code validation</summary>
    <div class="hunt-grid">
      <label>HackerOne handle<input id="validateHandle" value="circle-bbp" /></label>
      <label>Repository<input id="validateRepo" value="circlefin/evm-cctp-contracts" /></label>
      <button class="primary" id="validateRunBtn">Validate hypotheses against code</button>
    </div>
    <pre id="validateOut" class="hunt-out">Ready. Scope is refreshed before validation.</pre>
  </details>

  <div class="note" id="note" style="display:none"></div>

  <div class="overflow">
    <table>
      <thead><tr>
        <th class="stripe" aria-hidden="true"></th>
        <th>#</th><th>Sev</th><th>Source</th><th>Finding</th><th>CWE</th><th>Priority</th><th>Status</th>
      </tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
  <div class="empty" id="empty" style="display:none">No findings to show yet.</div>
</main>
<script>
(function () {
  var STATIC = !!window.__CONSOLE__;
  var model = window.__CONSOLE__ || null;
  var filters = { source: "", severity: "", status: "" };
  var SEV = ["critical", "high", "medium", "low", "info"];

  function esc(s) { return (s == null ? "" : String(s)).replace(/[&<>"]/g,
    function (c){ return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"}[c]; }); }

  function card(n, l) { return '<div class="card"><div class="n">' + n + '</div><div class="l">' + l + '</div></div>'; }

  function sevSummary(bySev) {
    var total = SEV.reduce(function (a, k){ return a + (bySev[k] || 0); }, 0) || 1;
    var bar = SEV.map(function (k) {
      var w = (bySev[k] || 0) / total * 100;
      return w ? '<i class="sev-' + k + '" style="width:' + w + '%;background:var(--' +
        (k === "medium" ? "med" : k) + ')"></i>' : "";
    }).join("");
    var legend = SEV.filter(function (k){ return bySev[k]; }).map(function (k) {
      return '<span><b style="background:var(--' + (k === "medium" ? "med" : k) + ')"></b>' +
        k + " " + bySev[k] + "</span>";
    }).join("");
    return '<div class="card wide"><div class="sevbar">' + bar + '</div><div class="legend">' +
      (legend || '<span>no findings</span>') + "</div></div>";
  }

  function render() {
    if (!model) return;
    var t = model.totals || { candidates: 0, verified: 0, hypotheses: 0, by_source: {}, by_severity: {} };
    document.getElementById("genAt").textContent =
      (model.scan_id ? "scan " + model.scan_id + " · " : "") +
      (model.generated_at ? new Date(model.generated_at).toLocaleString() : "") +
      (model.backend_connected ? " · backend connected" : "");
    var isValidated = Object.prototype.hasOwnProperty.call(t, "confirmed");
    document.getElementById("summary").innerHTML = isValidated
      ? card(t.candidates, "families") + card(t.confirmed, "confirmed") +
        card(t.rejected, "rejected") + card(t.unresolved, "unresolved") +
        sevSummary(t.by_severity || {})
      : card(t.candidates, "candidates") + card(t.verified, "verified") +
        card(t.hypotheses, "hypotheses") + sevSummary(t.by_severity || {});

    var note = document.getElementById("note");
    if (model.note) { note.style.display = "block"; note.textContent = model.note; }
    else { note.style.display = "none"; }

    var sel = document.getElementById("fSource");
    var have = {}; Array.prototype.forEach.call(sel.options, function (o){ have[o.value] = 1; });
    (model.sources || []).forEach(function (s){
      if (!have[s]) { var o = document.createElement("option"); o.value = o.textContent = s; sel.appendChild(o); }
    });

    var items = (model.items || []).filter(function (it) {
      return (!filters.source || it.source === filters.source) &&
             (!filters.severity || it.severity === filters.severity) &&
             (!filters.status || it.status === filters.status);
    });
    document.getElementById("empty").style.display = items.length ? "none" : "block";
    document.getElementById("rows").innerHTML = items.map(function (it) {
      var dup = it.duplicate_count > 1 ? ' <span class="dup">×' + it.duplicate_count + "</span>" : "";
      var stripe = "background:var(--" + (it.severity === "medium" ? "med" : it.severity) + ")";
      var validation = it.validation_reason
        ? '<br><b>code validation</b> - ' + esc(it.validation_reason) : "";
      var anchors = (it.code_anchors || []).map(function (a) {
        return '<br><b>source</b> - ' + esc(a.path) + ':' + a.line_start + '-' + a.line_end +
          ' - <span class="mono">' + esc(a.quote) + '</span>';
      }).join("");
      var test = it.verification_test
        ? '<br><b>local test</b> - ' + esc(it.verification_test) : "";
      return '<tr class="row" tabindex="0">' +
        '<td class="stripe" style="' + stripe + '"></td>' +
        '<td class="rank">' + it.rank + "</td>" +
        '<td><span class="badge sev-' + esc(it.severity) + '">' + esc(it.severity) + "</span></td>" +
        '<td><span class="badge src-' + esc(it.source) + '">' + esc(it.source) + "</span></td>" +
        '<td><div class="title">' + esc(it.title) + dup + "</div>" +
          '<div class="loc">' + esc(it.code_location || it.route || it.asset) + "</div>" +
          '<div class="detail"><b>observed</b> · ' + esc(it.observed) +
            (it.expected ? '<br><b>expected</b> · ' + esc(it.expected) : "") + validation + anchors + test + "</div></td>" +
        '<td class="cwe">' + esc(it.cwe || "—") + "</td>" +
        '<td class="pri">' + it.priority + "</td>" +
        '<td><span class="badge st-' + esc(it.status) + '">' + esc(it.status) + "</span></td>" +
        "</tr>";
    }).join("");
    Array.prototype.forEach.call(document.querySelectorAll("tr.row"), function (tr) {
      function toggle(){ tr.classList.toggle("open"); }
      tr.addEventListener("click", toggle);
      tr.addEventListener("keydown", function (e){ if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
    });
  }

  function setModel(m) { model = m; render(); }

  function loadReview(scan) {
    fetch("/ui/review" + (scan ? "?scan=" + encodeURIComponent(scan) : ""))
      .then(function (r){ return r.json(); }).then(setModel)
      .catch(function (e){ setModel({ totals:{}, items:[], note: "Failed to load: " + e }); });
  }

  ["fSource","fSeverity","fStatus"].forEach(function (id) {
    document.getElementById(id).addEventListener("change", function (e) {
      filters[id === "fSource" ? "source" : id === "fSeverity" ? "severity" : "status"] = e.target.value;
      render();
    });
  });
  document.getElementById("loadBtn").addEventListener("click", function () {
    loadReview(document.getElementById("scanId").value.trim());
  });
  document.getElementById("fileIn").addEventListener("change", function (e) {
    var f = e.target.files[0]; if (!f) return;
    var rd = new FileReader();
    rd.onload = function () {
      var data;
      try { data = JSON.parse(rd.result); }
      catch (err) { setModel({ totals:{}, items:[], note: "Invalid JSON in the uploaded file." }); return; }
      fetch("/ui/review", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ export: data }) })
        .then(function (r){ return r.json(); }).then(setModel)
        .catch(function (err){ setModel({ totals:{}, items:[], note: "Upload failed: " + err }); });
    };
    rd.readAsText(f);
  });

  var huntBtn = document.getElementById("huntRunBtn");
  if (huntBtn) {
    huntBtn.addEventListener("click", function () {
      var handles = document.getElementById("huntHandles").value.split(",")
        .map(function (s) { return s.trim(); }).filter(Boolean);
      var body = {
        model: document.getElementById("huntModel").value.trim(),
        verify_model: document.getElementById("huntVerifyModel").value.trim(),
        deepseek_fallback: document.getElementById("huntDeepseek").checked,
        arm: document.getElementById("huntArm").checked,
        handles: handles,
      };
      var out = document.getElementById("huntOut");
      out.textContent = "running...";
      huntBtn.disabled = true;
      fetch("/ui/hunt", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body) })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          out.textContent = JSON.stringify(data, null, 2);
          huntBtn.disabled = false;
          if (!data.error) loadReview("");   // pick up anything newly tracked
        })
        .catch(function (err) { out.textContent = "Hunt request failed: " + err; huntBtn.disabled = false; });
    });
  }



  var validateBtn = document.getElementById("validateRunBtn");
  if (validateBtn) {
    validateBtn.addEventListener("click", function () {
      var out = document.getElementById("validateOut");
      var body = {
        handle: document.getElementById("validateHandle").value.trim(),
        repo_full: document.getElementById("validateRepo").value.trim()
      };
      validateBtn.disabled = true;
      out.textContent = "Refreshing scope and starting validation...";
      fetch("/ui/deepseek/validate", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify(body)
      }).then(function (r) { return r.json(); }).then(function (start) {
        if (start.error) throw new Error(start.error);
        function poll() {
          fetch(start.status_url).then(function (r) { return r.json(); }).then(function (job) {
            out.textContent = JSON.stringify({
              status: job.status, completed: job.completed, total: job.total,
              current_file: job.current_file, validation_counts: job.validation_counts || null,
              error: job.error || null
            }, null, 2);
            if (job.status === "completed") {
              setModel(job.model);
              validateBtn.disabled = false;
            } else if (job.status === "failed") {
              validateBtn.disabled = false;
            } else {
              window.setTimeout(poll, 1500);
            }
          });
        }
        poll();
      }).catch(function (err) {
        out.textContent = "Validation failed: " + err;
        validateBtn.disabled = false;
      });
    });
  }

  if (STATIC) {
    document.getElementById("live").style.display = "none";
    Array.prototype.forEach.call(document.querySelectorAll(".hunt"), function (panel) {
      panel.style.display = "none";
    });
    render();
  }
  else { loadReview(""); }
})();
</script>
</body>
</html>
"""
