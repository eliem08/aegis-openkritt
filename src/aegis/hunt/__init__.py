"""Automatic hunting loop (discover -> scan -> collect -> learn -> repeat).

Human-supervised by construction: it never exploits and never submits, only scans
authorized automation-permitted code-repo scope, and is dry-run until armed. See
:mod:`aegis.hunt.orchestrator`.
"""

from .orchestrator import HuntConfig, HuntOrchestrator, HuntReport

__all__ = ["HuntConfig", "HuntOrchestrator", "HuntReport"]
