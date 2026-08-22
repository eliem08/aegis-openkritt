"""`aegis products ...` — the operator entrypoints for the seven product surfaces.

Thin argparse glue over :mod:`aegis.products`. Each command loads its input, runs the product with
the real engine (:func:`aegis.products.ports.default_ports`), and emits a JSON result. The finder
commands (autopilot/pr-gate/redteam) invoke the LLM+scanner hunt and therefore need the engine
configured (an LLM key, git, installed scanners); the proof commands operate on findings you supply.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from . import (
    bounty_triage,
    pr_gatekeeper,
    proof_of_fix,
    proof_of_vuln,
    repo_autopilot,
    slop_filter,
    standing_redteam,
)


def add_products_parser(commands) -> None:
    products = commands.add_parser("products", help="run an Aegis product surface")
    sub = products.add_subparsers(dest="products_command", required=True)

    ap = sub.add_parser("autopilot", help="A1 - governed review of your own repo")
    ap.add_argument("--repo", required=True, help="owner/repo (identity for the report)")
    ap.add_argument("--repo-dir", help="local checkout to review (own-code path)")
    ap.add_argument("--files", type=int, default=12)
    ap.add_argument("--samples", type=int, default=2)
    ap.add_argument("--no-reproduce", action="store_true")
    ap.add_argument("--reproduced-only", action="store_true")
    ap.add_argument("--json", dest="json_path")

    pg = sub.add_parser("pr-gate", help="A2 - diff-scoped CI gate (exit 1 blocks the PR)")
    pg.add_argument("--repo", required=True)
    pg.add_argument("--repo-dir")
    pg.add_argument("--changed", action="append", default=[], help="a changed file (repeatable)")
    pg.add_argument("--changed-from", help="file with one changed path per line")
    pg.add_argument("--files", type=int, default=40)
    pg.add_argument("--samples", type=int, default=2)
    pg.add_argument("--fail-on", nargs="+", default=["confirmed", "reproduced"])
    pg.add_argument("--sarif", dest="sarif_path")
    pg.add_argument("--json", dest="json_path")

    rt = sub.add_parser("redteam", help="A3 - scheduled autopilot + what's-new digest")
    rt.add_argument("--repo", required=True)
    rt.add_argument("--repo-dir")
    rt.add_argument("--previous-ids", help="JSON file of prior finding ids (state)")
    rt.add_argument("--files", type=int, default=12)
    rt.add_argument("--samples", type=int, default=2)
    rt.add_argument("--no-reproduce", action="store_true")
    rt.add_argument("--json", dest="json_path")

    pv = sub.add_parser("proof-vuln", help="B4 - reproduce/refute a finding")
    pv.add_argument("--finding", required=True, help="JSON finding / report / list")
    pv.add_argument("--repo-dir", required=True)
    pv.add_argument("--no-reproduce", action="store_true")
    pv.add_argument("--json", dest="json_path")

    pf = sub.add_parser("proof-fix", help="B5 - prove a patch closes the bug")
    pf.add_argument("--finding", required=True)
    pf.add_argument("--vuln-dir", required=True)
    pf.add_argument("--fixed-dir", required=True)
    pf.add_argument("--json", dest="json_path")

    sf = sub.add_parser("slop-filter", help="B6 - validate/kill another tool's findings")
    sf.add_argument("--findings", required=True, help="JSON list of findings to validate")
    sf.add_argument("--repo-dir", required=True)
    sf.add_argument("--reproduce", action="store_true")
    sf.add_argument("--json", dest="json_path")

    tr = sub.add_parser("triage", help="B7 - dedupe + validate incoming bounty reports")
    tr.add_argument("--reports", required=True, help="JSON list of incoming reports")
    tr.add_argument("--repo-dir")
    tr.add_argument("--no-validate", action="store_true")
    tr.add_argument("--json", dest="json_path")


def _load(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _emit(result, json_path: str | None) -> None:
    doc = result.to_dict()
    text = json.dumps(doc, indent=2)
    if json_path:
        Path(json_path).write_text(text, encoding="utf-8")
    else:
        print(text)
    s = doc["stats"]
    print(f"[{doc['product']}] {doc['target']} - {s['total']} finding(s): "
          f"{s['reproduced']} reproduced, {s['confirmed']} confirmed, {s['refuted']} refuted",
          file=sys.stderr)


def run_products(args) -> int:
    cmd = args.products_command
    if cmd == "autopilot":
        res = repo_autopilot.run(args.repo, repo_dir=args.repo_dir, files=args.files,
                                 samples=args.samples, reproduce=not args.no_reproduce,
                                 reproduced_only=args.reproduced_only)
        _emit(res, args.json_path)
        return 0
    if cmd == "pr-gate":
        changed = list(args.changed)
        if args.changed_from:
            changed += [ln.strip() for ln in Path(args.changed_from).read_text(
                encoding="utf-8").splitlines() if ln.strip()]
        res = pr_gatekeeper.run(args.repo, changed, repo_dir=args.repo_dir, files=args.files,
                                samples=args.samples, fail_on=tuple(args.fail_on))
        _emit(res, args.json_path)
        if args.sarif_path:
            Path(args.sarif_path).write_text(json.dumps(pr_gatekeeper.to_sarif(res), indent=2),
                                             encoding="utf-8")
        failed = pr_gatekeeper.gate_failed(res)
        print(f"[pr-gate] {'BLOCK' if failed else 'PASS'}", file=sys.stderr)
        return 1 if failed else 0
    if cmd == "redteam":
        prev = _load(args.previous_ids) if args.previous_ids else None
        res = standing_redteam.run(args.repo, repo_dir=args.repo_dir, previous_ids=prev,
                                   files=args.files, samples=args.samples,
                                   reproduce=not args.no_reproduce)
        _emit(res, args.json_path)
        return 0
    if cmd == "proof-vuln":
        res = proof_of_vuln.run(_load(args.finding), args.repo_dir,
                                reproduce=not args.no_reproduce)
        _emit(res, args.json_path)
        return 0
    if cmd == "proof-fix":
        res = proof_of_fix.run(_load(args.finding), args.vuln_dir, args.fixed_dir)
        _emit(res, args.json_path)
        return 0
    if cmd == "slop-filter":
        res = slop_filter.run(_load(args.findings), args.repo_dir, reproduce=args.reproduce)
        _emit(res, args.json_path)
        return 0
    if cmd == "triage":
        res = bounty_triage.run(_load(args.reports), repo_dir=args.repo_dir,
                                validate=not args.no_validate)
        _emit(res, args.json_path)
        return 0
    raise SystemExit(f"unknown products command: {cmd}")
