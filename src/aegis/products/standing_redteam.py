"""Standing Red Team — scheduled autopilot + a "what's new" digest.

Product A3. Runs :mod:`aegis.products.repo_autopilot` on a schedule and diffs the result against
the previous run so the customer sees only *newly* exploitable findings, not the same list every
week. Persist ``stats["current_ids"]`` and pass it back as ``previous_ids`` next run.
"""

from __future__ import annotations

from . import repo_autopilot
from .models import ProductResult
from .ports import Ports, default_ports


def run(repo: str, *, repo_dir: str | None = None, ports: Ports | None = None,
        previous_ids=None, files: int = 12, samples: int = 2, reproduce: bool = True,
        repository: str = "") -> ProductResult:
    ports = ports or default_ports()
    base = repo_autopilot.run(repo, repo_dir=repo_dir, ports=ports, files=files,
                              samples=samples, reproduce=reproduce, repository=repository)

    prev = set(previous_ids or [])
    new, known = [], []
    for f in base.findings:
        if f.id in prev:
            known.append(f)
        else:
            f.meta["new"] = True
            new.append(f)

    return ProductResult(
        product="standing-redteam",
        target=base.target,
        findings=base.findings,
        stats={
            "new": len(new),
            "known": len(known),
            "current_ids": [f.id for f in base.findings],
            "digest": {
                "new_findings": [f.public() for f in ProductResult(
                    product="_", target="_", findings=new).ranked()],
            },
            "reproduction": (base.stats or {}).get("reproduction"),
        },
    )
