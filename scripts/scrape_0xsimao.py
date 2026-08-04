"""Build a contract-lane vulnerability-CLASS corpus from 0xSimao's findings database.

Extracts only FACTS (protocol category, severity, source firm, link) from the public
/findings.md export and derives an original vulnerability-class taxonomy from keyword
signals. It does NOT store 0xSimao's finding titles/descriptions — those are the
auditor's copyrighted work. The output teaches the smart-contract generator the real
DISTRIBUTION of contract bugs (which classes appear in which protocol types, at which
severity), which is what powers retrieval — not the prose.

Output: reports/contract_corpus_0xsimao.jsonl in the DisclosedReport shape, with an
original generic label ("<class> in <category> protocol"), NOT the source title.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import httpx

# Original class taxonomy — keyword signals -> a smart-contract weakness class.
_CLASSES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("reentrancy", ("reentran",)),
    ("access-control", ("access control", "onlyowner", "unauthor", "permission", "missing check",
                        "auth ", "role", "privileg", "arbitrary call")),
    ("rounding/precision", ("round", "precision", "truncat", "decimal", "division", "rounding")),
    ("overflow/underflow", ("overflow", "underflow")),
    ("oracle-manipulation", ("oracle", "price manip", "twap", "spot price", "manipulat")),
    ("accounting/inflation", ("inflation", "first deposit", "donation", "share price", "virtual shares",
                              "accounting", "balance mismatch")),
    ("liquidation", ("liquidat",)),
    ("slippage/mev", ("slippage", "sandwich", "front-run", "frontrun", "mev", "deadline", "min amount")),
    ("signature/replay", ("signature", "replay", "nonce", "permit", "ecrecover", "malleab")),
    ("initialization", ("initiali", "uninitiali", "constructor")),
    ("dos", ("denial of service", "dos", "gas limit", "unbounded", "griefing", "block")),
    ("flashloan", ("flash loan", "flashloan")),
    ("token-integration", ("fee-on-transfer", "rebasing", "erc777", "weird erc20", "return value",
                           "safetransfer", "approve")),
    ("timelock/governance", ("timelock", "governance", "proposal", "voting")),
    ("withdrawal/redeem-logic", ("withdraw", "redeem", "claim", "unstake", "exit")),
)

_SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")


def classify(text: str) -> str:
    low = text.lower()
    for label, keys in _CLASSES:
        if any(k in low for k in keys):
            return label
    return "logic"


def parse(md: str) -> list[dict]:
    """Parse reports and their finding rows into fact records (no source titles kept)."""
    records: list[dict] = []
    # split into report sections on level-2 headers
    sections = re.split(r"\n## ", md)
    for sec in sections:
        header, _, body = sec.partition("\n")
        protocol = header.strip()
        if not protocol or protocol.startswith("#"):
            continue
        # "Firm · Category · Date" meta line (bullet separators vary in encoding)
        meta = ""
        for line in body.splitlines():
            if re.search(r"\d{4}-\d{2}-\d{2}", line) and ("[" not in line):
                meta = line
                break
        parts = re.split(r"\s*[·•\|]\s*|\s+\W\s+", meta) if meta else []
        firm = parts[0].strip() if parts else ""
        category = parts[1].strip() if len(parts) > 1 else ""
        url_m = re.search(r"\[report\]\((https?://[^)]+)\)", body)
        source_url = url_m.group(1) if url_m else "https://0xsimao.com/findings"
        # table rows: | Severity | Finding | Read it |
        for row in re.findall(r"\|\s*(Critical|High|Medium|Low|Info)\s*\|([^|]*)\|", body):
            severity, finding_cell = row[0], row[1]
            vclass = classify(finding_cell)      # classify from the cell, but DO NOT store it
            records.append({
                "severity": severity.lower(),
                "vuln_class": vclass,
                "category": category or "smart contract",
                "firm": firm,
                "protocol": protocol,
                "source_url": source_url,
            })
    return records


def to_corpus(records: list[dict]) -> list[dict]:
    """DisclosedReport-shaped rows with an ORIGINAL generic label (class + category)."""
    out = []
    for i, r in enumerate(records, start=1):
        label = f"{r['vuln_class']} in a {r['category'].lower()} protocol"
        out.append({
            "report_id": f"0xsimao-{i:04d}",
            "source": "0xsimao",
            "program": r["firm"],
            "title": label,                      # our label, not the auditor's title
            "weakness": r["vuln_class"],
            "cwe": r["vuln_class"],
            "severity": r["severity"],
            "asset_type": "smart_contract",
            "summary": label,
            "url": r["source_url"],
            "tags": [r["category"].lower(), r["vuln_class"], r["firm"].lower()],
        })
    return out


def main() -> int:
    dest = Path(sys.argv[1] if len(sys.argv) > 1 else "reports/contract_corpus_0xsimao.jsonl")
    md = httpx.get("https://0xsimao.com/findings.md", timeout=30,
                   headers={"User-Agent": "aegis-research"}).text
    records = parse(md)
    corpus = to_corpus(records)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", encoding="utf-8") as fh:
        for row in corpus:
            fh.write(json.dumps(row) + "\n")
    # print the class distribution — the actual signal
    from collections import Counter
    by_class = Counter(r["vuln_class"] for r in records)
    by_cat = Counter(r["category"] for r in records if r["category"])
    print(f"parsed {len(records)} finding facts -> {dest}")
    print("top classes:", by_class.most_common(10))
    print("top categories:", by_cat.most_common(8))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
