#!/opt/venvs/angr/bin/python
"""Deterministic CLI for the canonical angr control-flow capability."""

from __future__ import annotations

import json
import sys

import angr


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] in {"--version", "version", "-version"}:
        print(f"angr {angr.__version__}")
        return 0
    if len(sys.argv) != 2:
        print("usage: angr <executable>", file=sys.stderr)
        return 2
    project = angr.Project(sys.argv[1], auto_load_libs=False)
    cfg = project.analyses.CFGFast(normalize=True)
    symbol = project.loader.main_object.get_symbol("main")
    function = cfg.kb.functions.get(symbol.rebased_addr) if symbol is not None else None
    if function is None:
        print(json.dumps({"error": "main function not found"}))
        return 3
    branch_nodes = sum(1 for node in function.graph.nodes if function.graph.out_degree(node) > 1)
    print(json.dumps({
        "architecture": project.arch.name,
        "main_address": int(function.addr),
        "basic_blocks": len(function.block_addrs_set),
        "branch_nodes": branch_nodes,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
