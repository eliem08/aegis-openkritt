"""Hunt a verified smart contract — the Smart Contract asset lane.

    python -m aegis.ai.hunt_contract <address> [--chainid N] [--files K] [--samples N] [--handle h]

Fetches the verified Solidity source for an on-chain address and runs the same
selection -> ensemble generation -> citation validation -> PoC scaffold pipeline used
for repositories, with the SMART_CONTRACT agent kind. Read-only: pulls source text
from the explorer; never sends a transaction or touches the chain.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from ..env import load_dotenv
from .client import DeepSeekClient
from .config import DeepSeekConfig
from .etherscan_source import EtherscanError, EtherscanSource
from .repo_hunt import RepoHuntConfig, hunt_repository


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m aegis.ai.hunt_contract")
    parser.add_argument("address", help="on-chain contract address (0x...)")
    parser.add_argument("--chainid", type=int, default=1, help="explorer chain id (1=Ethereum)")
    parser.add_argument("--files", type=int, default=10, help="source files to analyze")
    parser.add_argument("--samples", type=int, default=1, help="generator ensemble size")
    parser.add_argument("--handle", default="", help="HackerOne program handle for outcomes/PoCs")
    parser.add_argument("--no-validate", action="store_true")
    parser.add_argument("--properties", action="store_true",
                        help="also infer security invariants and write runnable Foundry/"
                             "Halmos verification stubs (proposals, not proofs)")
    args = parser.parse_args(list(argv) if argv is not None else None)

    load_dotenv()
    report_root = Path(os.environ.get("AEGIS_REPORT_DIR", "reports")).resolve()
    slug = "contract_" + args.address.lower()
    report_path = report_root / f"deepseek_{slug}.json"
    pin_dir = report_root / "contracts" / args.address.lower()
    pin_dir.mkdir(parents=True, exist_ok=True)

    env = dict(os.environ)
    env.update(DEEPSEEK_THINKING="disabled", DEEPSEEK_TEMPERATURE="0.1",
               DEEPSEEK_MAX_TOKENS="16000", DEEPSEEK_READ_TIMEOUT="300")
    try:
        config = DeepSeekConfig.from_env(env)
    except Exception as exc:
        print(f"error: DeepSeek not configured ({type(exc).__name__})", file=sys.stderr)
        return 2

    def progress(index, total, path):
        print(f"  [{index}/{total}] {path}", flush=True)

    try:
        source = EtherscanSource(api_key=os.environ.get("ETHERSCAN_API_KEY", ""),
                                 chainid=args.chainid)
        print(f"fetching verified source for {args.address} (chain {args.chainid}) ...", flush=True)
        with source, DeepSeekClient(config) as client:
            result = hunt_repository(
                source, client, args.address,
                config=RepoHuntConfig(max_files=args.files, samples=args.samples,
                                      content_scan_pool=3000),
                pin_dir=pin_dir, progress=progress,
            )
    except EtherscanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4

    report = result.report()
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nselected {len(result.selected)} source files, "
          f"{len(result.hypotheses)} hypotheses -> {report_path.name}")

    # arm's-length skill invocation: if the operator has wired AEGIS_SKILL_CMD to their
    # installed skills, run the recommended contract skills (Pashov solidity-auditor /
    # x-ray / fizz, etc.) on this target and surface their output. Aegis never embeds a
    # skill's content — it invokes the one the operator installed.
    skill_cmd = os.environ.get("AEGIS_SKILL_CMD")
    if skill_cmd:
        from .skill_registry import SkillInvoker, make_shell_runner, recommend
        skills = recommend("contract")
        print(f"\ninvoking {len(skills)} installed skill(s) on {args.address} ...", flush=True)
        runs = SkillInvoker(make_shell_runner(skill_cmd)).run(skills, args.address)
        for r in runs:
            print(f"  [{'ok' if r.ok else 'fail'}] {r.skill}" + (f" — {r.error}" if r.error else ""))
        (report_root / f"skills_{slug}.json").write_text(
            json.dumps([{"skill": r.skill, "ok": r.ok, "output": r.output, "error": r.error}
                        for r in runs], indent=2), encoding="utf-8")

    if args.properties and result.selected:
        from .contract_properties import PropertyGenerator, write_property_suite
        primary = result.selected[0].path
        source = (pin_dir / primary).read_text(encoding="utf-8", errors="replace") \
            if (pin_dir / primary).is_file() else ""
        if source:
            with DeepSeekClient(config) as client:
                props = PropertyGenerator(client).infer(source)
            name = Path(primary).stem or "Contract"
            suite = write_property_suite(props, report_root / "properties" / slug,
                                         contract_name=name)
            print(f"inferred {suite['count']} invariants -> {report_root / 'properties' / slug}"
                  f" (run: forge test / halmos — proposals, not proofs)")
    for failure in result.failures:
        print(f"  ! {failure}")

    if args.no_validate or not result.hypotheses:
        return 0

    print("\nvalidating hypotheses against the pinned source ...", flush=True)
    from .report_validation import validate_deepseek_report

    validation_env = dict(env)
    validation_env.update(DEEPSEEK_MAX_TOKENS="4096")
    with DeepSeekClient(DeepSeekConfig.from_env(validation_env)) as client:
        validated, model = validate_deepseek_report(report_path, pin_dir, client)
    counts = validated["scan"]["validation_counts"]
    print(f"\nverdicts: {counts}")
    for item in model["items"]:
        if item["status"] == "confirmed":
            print(f"  CONFIRMED  {item['code_location']}  {item['observed'][:90]}")
    print(f"\nreview: http://127.0.0.1:8000/ui/deepseek/latest?repo_full={args.address}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
