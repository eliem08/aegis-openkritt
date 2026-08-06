"""CLI entrypoint: `python -m aegis.ai.import_programs [sources] [--source-code-only]`.

Thin wrapper around program_sources.main so the import has an obvious command name. With no
args it pulls every source (bountytargets + code4rena) into reports/programs.json, merging
without clobbering operator annotations. Then rank with `python -m aegis.ai.selection`.
"""

from __future__ import annotations

from .program_sources import main

if __name__ == "__main__":
    raise SystemExit(main())
