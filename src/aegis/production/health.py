"""Machine-readable production dependency health for supervised hunting."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from .config import ProductionSettings
from .drills import run_drills


class HealthStatus(str, Enum):
    READY = "READY"
    DEGRADED = "DEGRADED"
    NOT_REQUIRED = "NOT_REQUIRED_FOR_SELECTED_MISSION"
    WAITING = "WAITING_FOR_PREREQUISITE"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class HealthCell:
    name: str
    status: HealthStatus
    required: bool
    detail: str


@dataclass(frozen=True, slots=True)
class HealthReport:
    schema_version: int
    observed_at: str
    ready: bool
    cells: tuple[HealthCell, ...]

    def document(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "observed_at": self.observed_at,
            "ready": self.ready,
            "summary": {
                status.value: sum(cell.status is status for cell in self.cells)
                for status in HealthStatus
            },
            "cells": [asdict(cell) | {"status": cell.status.value} for cell in self.cells],
        }


Probe = Callable[[], str]


def _bounded_version(executable: str, *args: str) -> str:
    path = shutil.which(executable)
    if not path:
        raise FileNotFoundError(f"{executable} is not installed")
    result = subprocess.run(
        [path, *args], capture_output=True, text=True, timeout=10, check=False,
    )
    if result.returncode:
        raise RuntimeError(f"{executable} version probe exited {result.returncode}")
    output = (result.stdout or result.stderr).strip().splitlines()
    return output[0][:160] if output else f"{executable} version probe passed"


def _playwright_probe() -> str:
    if importlib.util.find_spec("playwright") is None:
        raise FileNotFoundError("Playwright Python package is not installed")
    return _bounded_version("playwright", "--version")


def _android_probe() -> str:
    version = _bounded_version("adb", "version")
    path = shutil.which("adb")
    assert path is not None
    devices = subprocess.run(
        [path, "devices"], capture_output=True, text=True, timeout=10, check=False,
    )
    if devices.returncode:
        raise RuntimeError("adb device enumeration failed")
    connected = [line for line in devices.stdout.splitlines()[1:] if line.strip().endswith("device")]
    if not connected:
        raise FileNotFoundError("adb is installed but no controlled device is connected")
    return f"{version}; {len(connected)} controlled device(s) connected"


def _grpc_probe(env: Mapping[str, str]) -> str:
    if importlib.util.find_spec("grpc") is None:
        raise FileNotFoundError("grpcio is not installed")
    registry = env.get("AEGIS_GRPC_METHOD_REGISTRY", "").strip()
    if not registry:
        raise FileNotFoundError("AEGIS_GRPC_METHOD_REGISTRY is not configured")
    path = Path(registry)
    if not path.is_file():
        raise FileNotFoundError("configured gRPC method registry is not readable")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, (dict, list)) or not data:
        raise ValueError("gRPC method registry is empty")
    return "grpcio and a non-empty controlled method registry are available"


def _configured(env: Mapping[str, str], key: str, label: str) -> str:
    if not env.get(key, "").strip():
        raise FileNotFoundError(f"{key} is not configured")
    return f"{label} is configured; live readiness is covered by its canonical gateway probe"


def _cell(name: str, required: bool, probe: Probe) -> HealthCell:
    try:
        detail = probe()
        return HealthCell(name, HealthStatus.READY, required, detail or "ready")
    except FileNotFoundError as exc:
        status = HealthStatus.WAITING if required else HealthStatus.NOT_REQUIRED
        return HealthCell(name, status, required, str(exc))
    except (ImportError, ModuleNotFoundError) as exc:
        return HealthCell(name, HealthStatus.UNAVAILABLE, required, str(exc))
    except Exception as exc:
        return HealthCell(name, HealthStatus.FAILED, required, f"{type(exc).__name__}: {exc}")


def _effectiveness_cell(env: Mapping[str, str], required: bool) -> HealthCell:
    backend = env.get("AEGIS_EFFECTIVENESS_BACKEND", "postgresql").strip().lower()
    dsn = env.get("AEGIS_EFFECTIVENESS_DB_URL", "").strip()
    if backend != "postgresql":
        return HealthCell(
            "effectiveness_learning",
            HealthStatus.FAILED if required else HealthStatus.DEGRADED,
            required,
            "production effectiveness storage must use PostgreSQL",
        )
    if not dsn:
        return HealthCell(
            "effectiveness_learning",
            HealthStatus.WAITING if required else HealthStatus.NOT_REQUIRED,
            required,
            "AEGIS_EFFECTIVENESS_DB_URL is not configured",
        )
    try:
        import psycopg

        with psycopg.connect(dsn, connect_timeout=3) as connection, connection.cursor() as cursor:
            cursor.execute("SELECT to_regclass('effectiveness_subjects')")
            if cursor.fetchone()[0] is None:
                raise RuntimeError("effectiveness schema migration has not been applied")
        return HealthCell(
            "effectiveness_learning", HealthStatus.READY, required,
            "authoritative PostgreSQL effectiveness ledger is reachable",
        )
    except Exception as exc:
        return HealthCell(
            "effectiveness_learning",
            HealthStatus.FAILED if required else HealthStatus.DEGRADED,
            required,
            f"{type(exc).__name__}: authoritative effectiveness ledger unavailable",
        )


def build_health_report(
    settings: ProductionSettings | None,
    *,
    env: Mapping[str, str] | None = None,
    settings_error: Exception | None = None,
    extra_probes: Mapping[str, Probe] | None = None,
) -> HealthReport:
    """Run bounded, non-target dependency probes and retain every failure explicitly."""
    source = os.environ if env is None else env
    required = {
        item.strip() for item in source.get(
            "AEGIS_HEALTH_REQUIRED",
            "policy_authority,database,workers,network_executor,scanner_versions,artifact_acquisition",
        ).split(",") if item.strip()
    }
    cells: list[HealthCell] = []
    if settings is None:
        detail = str(settings_error or "production settings are unavailable")
        cells.append(HealthCell("policy_authority", HealthStatus.FAILED, True, detail))
        drill_map = {}
    else:
        from aegis.ai.jarvis_control_plane import validate_authority_map

        cells.append(_cell("policy_authority", True, lambda: (
            validate_authority_map() or "canonical authority map and signed-policy configuration loaded"
        )))
        drill_map = {result.name: result for result in run_drills(settings)}

    drill_names = {
        "database": "postgres",
        "workers": "redis",
        "ct_provider": "ct_provider",
        "private_oast": "private_oast",
        "scanner_versions": "scanner_executables",
        "network_executor": "scoped_egress",
        "model_providers": "model_gateway",
    }
    for name, drill_name in drill_names.items():
        if name == "ct_provider":
            cells.append(_cell(name, name in required, lambda: _configured(
                source, "AEGIS_CT_PROVIDER_URL", "certificate-transparency provider",
            )))
            continue
        result = drill_map.get(drill_name)
        is_required = name in required or (
            name == "private_oast" and bool(settings and settings.require_oast)
        ) or (
            name == "model_providers" and bool(settings and settings.require_model_gateway)
        )
        if result is None:
            cells.append(HealthCell(
                name, HealthStatus.WAITING, is_required,
                "production settings must load before this dependency can be probed",
            ))
        else:
            status = {
                "pass": HealthStatus.READY,
                "not_configured": (
                    HealthStatus.WAITING if is_required else HealthStatus.NOT_REQUIRED
                ),
                "fail": HealthStatus.FAILED,
            }.get(result.status, HealthStatus.FAILED)
            cells.append(HealthCell(name, status, is_required, result.detail))

    cells.extend([
        _cell("playwright", "playwright" in required, _playwright_probe),
        _cell("android_runtime", "android_runtime" in required, _android_probe),
        _cell("grpc_prerequisites", "grpc_prerequisites" in required, lambda: _grpc_probe(source)),
        _cell(
            "artifact_acquisition", "artifact_acquisition" in required,
            lambda: _configured(source, "AEGIS_ARTIFACT_ACQUISITION_ENABLED", "artifact acquisition"),
        ),
        _effectiveness_cell(source, "effectiveness_learning" in required),
    ])
    for name, probe in (extra_probes or {}).items():
        cells.append(_cell(name, name in required, probe))
    ready = all(cell.status is HealthStatus.READY for cell in cells if cell.required)
    return HealthReport(
        schema_version=1,
        observed_at=datetime.now(timezone.utc).isoformat(),
        ready=ready,
        cells=tuple(cells),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", dest="json_path")
    args = parser.parse_args(argv)
    settings = None
    error = None
    try:
        settings = ProductionSettings.from_env()
    except Exception as exc:
        error = exc
    report = build_health_report(settings, settings_error=error)
    document = json.dumps(report.document(), indent=2, sort_keys=True) + "\n"
    if args.json_path:
        Path(args.json_path).write_text(document, encoding="utf-8")
    else:
        print(document, end="")
    return 0 if report.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
