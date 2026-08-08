"""Static-only iOS pipeline for an authorized local IPA artifact."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

from ..mobsf_adapter import MobSFConfig
from .asset_capabilities import MOBSF, AssetKind
from .asset_execution import execute_authorized_offline_method
from .asset_execution_ticket import CapabilityAvailability, issue_offline_execution_ticket
from .ios_static import (
    IOSFileRef,
    IOSStaticReport,
    analyze_ios_ipa,
    cleanup_ios_static,
    issue_ios_ipa_ticket,
)
from .macho_metadata import MachOError, analyze_macho_metadata


@dataclass(frozen=True)
class IOSStageResult:
    stage: str
    status: str
    detail: str = ""


@dataclass
class IOSPipelineReport:
    ipa_path: str
    scope_digest: str
    stages: list[IOSStageResult] = field(default_factory=list)
    candidates: list[dict] = field(default_factory=list)
    observations: list[dict] = field(default_factory=list)
    engine_errors: dict[str, str] = field(default_factory=dict)
    static_report: IOSStaticReport | None = None


def _dedupe(rows: Iterable[dict]) -> list[dict]:
    output: list[dict] = []
    seen: set[tuple[str, str, int, str]] = set()
    for row in rows:
        answer = row.get("json_answer") or {}
        key = (
            str(answer.get("vulnerability_type") or row.get("cwe") or ""),
            str(answer.get("file_path") or ""),
            int(answer.get("line") or 0),
            str(answer.get("summary") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
    return output


def _macho_observation(path: Path, label: str) -> dict:
    metadata = analyze_macho_metadata(path)
    return {
        "kind": "macho_metadata",
        "label": label,
        "path": str(path),
        "file_name": metadata.file_name,
        "size_bytes": metadata.size_bytes,
        "sha256": metadata.sha256,
        "format": metadata.format,
        "architectures": metadata.architectures,
        "bits": metadata.bits,
        "endianness": metadata.endianness,
        "file_type": metadata.file_type,
        "pie": metadata.pie,
        "code_signature": metadata.code_signature,
        "encryption_info": metadata.encryption_info,
        "encrypted": metadata.encrypted,
        "dylibs": metadata.dylibs,
        "rpaths": metadata.rpaths,
        "load_command_count": metadata.load_command_count,
        "verification_state": "observation",
    }


def _resolved_ref(root: Path, ref: IOSFileRef) -> Path | None:
    candidate = (root / ref.path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate if candidate.is_file() and not candidate.is_symlink() else None


def run_ios_static_pipeline(
    ipa_path: str | Path,
    *,
    scope_digest: str,
    mobsf_config: MobSFConfig | None = None,
    mobsf_client=None,
    workspace_root: str | Path | None = None,
    retain_extraction: bool = False,
    maximum_framework_binaries: int = 100,
) -> IOSPipelineReport:
    """Run local IPA metadata/Mach-O/MobSF lanes; never start a device or app runtime."""
    ipa = Path(ipa_path).expanduser().resolve()
    report = IOSPipelineReport(str(ipa), str(scope_digest))
    rows: list[dict] = []

    static: IOSStaticReport | None = None
    try:
        ticket = issue_ios_ipa_ticket(ipa, scope_digest=scope_digest)
        static = analyze_ios_ipa(
            ipa,
            ticket=ticket,
            scope_digest=scope_digest,
            workspace_root=workspace_root,
        )
        report.static_report = static
        rows.extend(static.candidates)
        report.observations.append(
            {
                "kind": "ios_ipa_metadata",
                "bundle_id": static.bundle_id,
                "display_name": static.display_name,
                "bundle_version": static.bundle_version,
                "short_version": static.short_version,
                "minimum_os_version": static.minimum_os_version,
                "executable": asdict(static.executable) if static.executable else None,
                "framework_count": len(static.frameworks),
                "provisioning_profile_count": len(static.provisioning_profiles),
                "url_schemes": static.url_schemes,
                "query_schemes": static.query_schemes,
                "ats": static.ats,
                "file_sharing": static.file_sharing,
                "ipa_sha256": static.ipa_sha256,
                "verification_state": "hypothesis_generation",
            }
        )
        report.stages.append(IOSStageResult("ipa_metadata", "complete"))
    except Exception as exc:
        report.engine_errors["ipa_metadata"] = f"{type(exc).__name__}: {exc}"[:240]
        report.stages.append(IOSStageResult("ipa_metadata", "failed", report.engine_errors["ipa_metadata"]))
        return report

    root = Path(static.extraction.root).resolve()
    if static.executable is not None:
        path = _resolved_ref(root, static.executable)
        if path is not None:
            try:
                report.observations.append(_macho_observation(path, "main_executable"))
                report.stages.append(IOSStageResult("macho_main", "complete"))
            except MachOError as exc:
                report.engine_errors["macho_main"] = str(exc)[:240]
                report.stages.append(IOSStageResult("macho_main", "failed", str(exc)[:240]))

    parsed_frameworks = 0
    macho_errors = 0
    for ref in static.frameworks[:max(0, int(maximum_framework_binaries))]:
        path = _resolved_ref(root, ref)
        if path is None:
            continue
        try:
            report.observations.append(_macho_observation(path, "framework_or_embedded_binary"))
            parsed_frameworks += 1
        except MachOError:
            macho_errors += 1
    report.stages.append(
        IOSStageResult(
            "macho_frameworks",
            "complete" if macho_errors == 0 else "partial",
            f"parsed={parsed_frameworks}, non_macho_or_invalid={macho_errors}",
        )
    )

    if mobsf_config is not None:
        try:
            ticket = issue_offline_execution_ticket(
                asset_kind=AssetKind.IOS_IPA,
                method=MOBSF,
                scope_digest=scope_digest,
                availability=CapabilityAvailability(artifact_available=True),
            )
            outcome = execute_authorized_offline_method(
                MOBSF,
                ticket=ticket,
                scope_digest=scope_digest,
                artifact_path=ipa,
                mobsf_config=mobsf_config,
                mobsf_client=mobsf_client,
            )
            rows.extend(outcome.candidates)
            report.observations.extend(
                {
                    "kind": observation.kind,
                    "tool": observation.tool,
                    "method": observation.method,
                    "data": observation.data,
                }
                for observation in outcome.observations
            )
            report.stages.append(IOSStageResult("mobsf", "complete"))
        except Exception as exc:
            report.engine_errors["MobSF"] = f"{type(exc).__name__}: {exc}"[:240]
            report.stages.append(IOSStageResult("mobsf", "failed", report.engine_errors["MobSF"]))
    else:
        report.stages.append(IOSStageResult("mobsf", "skipped", "MobSF not configured"))

    report.candidates = _dedupe(rows)
    if not retain_extraction:
        cleanup_ios_static(static)
        report.static_report = None
    return report


def cleanup_ios_pipeline(report: IOSPipelineReport) -> None:
    if report.static_report is not None:
        cleanup_ios_static(report.static_report)
        report.static_report = None
