"""Machine-readable production gate and non-destructive live probes."""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path

from aegis.api.prodcheck import ProductionReadinessError

from .config import ProductionSettings
from .readiness import production_deployment_issues
from .releases import ReleaseLockError, load_release_lock, verify_locked_executables


@dataclass(frozen=True)
class DrillResult:
    name: str
    status: str
    detail: str
    required: bool = True
    duration_ms: int = 0


def _timed(name, function, *, required=True) -> DrillResult:
    started = time.monotonic()
    try:
        detail = function() or "passed"
        status = "pass"
    except NotConfigured as exc:
        detail, status = str(exc), "not_configured"
    except Exception as exc:
        detail, status = f"{type(exc).__name__}: {exc}", "fail"
    return DrillResult(name, status, detail, required, int((time.monotonic() - started) * 1000))


class NotConfigured(RuntimeError):
    pass


def _static(settings: ProductionSettings) -> str:
    issues = production_deployment_issues(settings)
    if issues:
        raise ProductionReadinessError(issues)
    return "all static production requirements satisfied"


def _redis(settings: ProductionSettings) -> str:
    coordinator = settings.build_coordinator()
    if not coordinator.redis_backend.connected:
        raise RuntimeError("Redis ping failed")
    key = f"readiness:{int(time.time())}"
    if coordinator.is_duplicate(key):
        raise RuntimeError("fresh Redis dedup key was already present")
    if not coordinator.is_duplicate(key):
        raise RuntimeError("Redis atomic dedup did not persist")
    return "authenticated ping and atomic TTL operation passed"


def _postgres(settings: ProductionSettings) -> str:
    repository = settings.control.build_repository()
    if repository is None:
        raise RuntimeError("production repository was not constructed")
    try:
        repository._query("SELECT 1")
    finally:
        repository.close()
    return "TLS connection, migrations, and SELECT 1 passed"


def _http_health(url: str | None, label: str) -> str:
    if not url:
        raise NotConfigured(f"{label} URL is not configured")
    request = urllib.request.Request(url.rstrip("/") + "/healthz", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            if response.status != 200:
                raise RuntimeError(f"{label} returned HTTP {response.status}")
    except urllib.error.URLError as exc:
        raise RuntimeError(f"{label} is unreachable") from exc
    return f"{label} health endpoint passed"


def _release_lock(settings: ProductionSettings) -> str:
    if not settings.scanner_lock_path:
        raise NotConfigured("scanner release lock is not configured")
    releases = load_release_lock(settings.scanner_lock_path)
    return f"{len(releases)} approved digest-pinned release(s) loaded"


def _executables(settings: ProductionSettings) -> str:
    if not settings.scanner_lock_path:
        raise NotConfigured("scanner release lock is not configured")
    try:
        pins = verify_locked_executables(settings.scanner_lock_path)
    except ReleaseLockError as exc:
        raise NotConfigured(str(exc)) from exc
    return f"{len(pins)} executable checksum(s) verified"


def run_drills(settings: ProductionSettings) -> list[DrillResult]:
    oast_url = None
    if settings.oast_domain:
        oast_url = "https://" + settings.oast_domain
    return [
        _timed("static_readiness", lambda: _static(settings)),
        _timed("postgres", lambda: _postgres(settings)),
        _timed("redis", lambda: _redis(settings)),
        _timed("scoped_egress", lambda: _http_health(settings.egress_url, "egress")),
        _timed("scanner_release_lock", lambda: _release_lock(settings)),
        _timed("scanner_executables", lambda: _executables(settings)),
        _timed("private_oast", lambda: _http_health(oast_url, "private OAST")),
    ]


def render_markdown(results: list[DrillResult]) -> str:
    lines = ["# Aegis production drill report", "", "| Gate | Status | Required | Detail | Duration |",
             "|---|---:|---:|---|---:|"]
    for result in results:
        detail = result.detail.replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| {result.name} | {result.status} | {'yes' if result.required else 'no'} | "
            f"{detail} | {result.duration_ms} ms |"
        )
    return "\n".join(lines) + "\n"


def verdict(results: list[DrillResult]) -> bool:
    return all(result.status == "pass" for result in results if result.required)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", dest="json_path")
    parser.add_argument("--markdown", dest="markdown_path")
    args = parser.parse_args(argv)
    settings = ProductionSettings.from_env()
    results = run_drills(settings)
    document = json.dumps({"ready": verdict(results), "results": [asdict(r) for r in results]}, indent=2)
    if args.json_path:
        Path(args.json_path).write_text(document + "\n", encoding="utf-8")
    else:
        print(document)
    if args.markdown_path:
        Path(args.markdown_path).write_text(render_markdown(results), encoding="utf-8")
    return 0 if verdict(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
