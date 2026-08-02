"""Inspect a corpus of past reports:  python -m aegis.knowledge <corpus.jsonl>

Prints total reports, the most common weaknesses (with average bounty), the
per-asset-type breakdown, and a per-program summary. Read-only.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from .corpus import ReportCorpus
from .insights import CorpusInsights


def load(path: str) -> ReportCorpus:
    p = Path(path)
    if p.suffix.lower() == ".json":
        return ReportCorpus.from_json(p)
    return ReportCorpus.from_jsonl(p)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis.knowledge", description="Corpus insights")
    parser.add_argument("corpus", help="path to a .jsonl or .json report corpus")
    parser.add_argument("-n", "--top", type=int, default=8, help="how many weaknesses to show")
    args = parser.parse_args(argv)

    corpus = load(args.corpus)
    insights = CorpusInsights(corpus)

    print(f"corpus: {len(corpus)} reports | {len(corpus.programs())} programs")
    print("\ntop weaknesses:")
    for s in insights.top_weaknesses(args.top):
        bounty = f"~${s.avg_bounty:,.0f}" if s.avg_bounty else "-"
        print(f"  {s.key:10} {s.weakness[:34]:34} n={s.count:<4} {s.share*100:5.1f}%  bounty {bounty}")

    print("\nby asset type:")
    for asset_type, stats in insights.by_asset_type().items():
        top = ", ".join(f"{s.key}({s.count})" for s in stats[:3])
        print(f"  {asset_type or 'unknown':10} -> {top}")

    print("\nby program:")
    for handle in sorted(corpus.programs()):
        summ = insights.program_summary(handle)
        print(f"  {handle:20} {summ['reports']} reports  top={summ['top_weaknesses'][:3]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
