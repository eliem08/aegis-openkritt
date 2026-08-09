"""Static-only iOS IPA analysis for an already-authorized local artifact.

The IPA is SHA-bound to an explicit ticket and extracted with Aegis' bounded ZIP extractor. Only a
small allowlist of Info.plist fields is surfaced; arbitrary plist values are never emitted. The
analyzer inventories the main executable/frameworks by path/hash and creates context-required
hypotheses for broad ATS/file-sharing posture. No device, simulator, jailbreak, Frida, Objection,
store acquisition or application execution occurs.
"""

from __future__ import annotations

import hashlib
import plistlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .asset_execution_ticket import AssetExecutionTicket, AssetExecutionTicketError, _ticket_id
from .safe_archive import (
    SafeArchiveExtraction,
    SafeArchiveLimits,
    cleanup_safe_archive,
    extract_safe_archive,
)


class IOSStaticError(RuntimeError):
    pass


@dataclass(frozen=True)
class IOSFileRef:
    path: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class IOSStaticReport:
    ipa_path: str
    ipa_sha256: str
    bundle_id: str
    display_name: str
    bundle_version: str
    short_version: str
    minimum_os_version: str
    executable: IOSFileRef | None
    frameworks: tuple[IOSFileRef, ...]
    provisioning_profiles: tuple[IOSFileRef, ...]
    url_schemes: tuple[str, ...]
    query_schemes: tuple[str, ...]
    ats: dict[str, bool | None]
    file_sharing: dict[str, bool | None]
    candidates: tuple[dict, ...]
    extraction: SafeArchiveExtraction


IOS_IPA_STATIC_TOOL = "aegis-ios-ipa-static"
IOS_IPA_STATIC_METHOD = "bounded-ipa-metadata"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_ipa(path: str | Path, *, max_bytes: int = 4 * 1024 * 1024 * 1024) -> Path:
    ipa = Path(path).expanduser().resolve()
    if not ipa.is_file():
        raise IOSStaticError("IPA must be an existing regular file")
    if ipa.suffix.lower() != ".ipa":
        raise IOSStaticError("iOS static analysis accepts .ipa artifacts only")
    size = ipa.stat().st_size
    if size <= 0 or size > max_bytes:
        raise IOSStaticError("IPA size is outside the allowed range")
    return ipa


def issue_ios_ipa_ticket(ipa_path: str | Path, *, scope_digest: str) -> AssetExecutionTicket:
    scope = str(scope_digest or "").strip()
    if not scope:
        raise AssetExecutionTicketError("scope_digest is required")
    ipa = _validate_ipa(ipa_path)
    digest = _sha256_file(ipa)
    requirements = ("authorized_artifact", f"ipa_sha256:{digest}")
    material = {
        "scope_digest": scope,
        "asset_kind": "ios_ipa",
        "tool": IOS_IPA_STATIC_TOOL,
        "method": IOS_IPA_STATIC_METHOD,
        "requirements": requirements,
        "availability_digest": digest,
        "offline_only": True,
    }
    return AssetExecutionTicket(
        ticket_id=_ticket_id(material),
        scope_digest=scope,
        asset_kind="ios_ipa",
        tool=IOS_IPA_STATIC_TOOL,
        method=IOS_IPA_STATIC_METHOD,
        requirements=requirements,
        availability_digest=digest,
        offline_only=True,
    )


def _verify_ticket(ticket: AssetExecutionTicket, *, scope_digest: str, ipa_digest: str) -> None:
    if ticket.scope_digest != str(scope_digest or "").strip():
        raise IOSStaticError("IPA ticket scope digest mismatch")
    if ticket.asset_kind != "ios_ipa":
        raise IOSStaticError("ticket does not authorize an iOS IPA")
    if (ticket.tool, ticket.method) != (IOS_IPA_STATIC_TOOL, IOS_IPA_STATIC_METHOD):
        raise IOSStaticError("IPA ticket method mismatch")
    if ticket.availability_digest != ipa_digest:
        raise IOSStaticError("IPA digest changed after ticket issuance")
    material = {
        "scope_digest": ticket.scope_digest,
        "asset_kind": ticket.asset_kind,
        "tool": ticket.tool,
        "method": ticket.method,
        "requirements": ticket.requirements,
        "availability_digest": ticket.availability_digest,
        "offline_only": ticket.offline_only,
    }
    if ticket.ticket_id != _ticket_id(material):
        raise IOSStaticError("IPA ticket integrity mismatch")


def _safe_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _safe_text(value: Any, limit: int = 300) -> str:
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        return str(value)[:limit]
    return ""


def _ref(path: Path, root: Path, *, max_hash_bytes: int = 2 * 1024 * 1024 * 1024) -> IOSFileRef:
    size = path.stat().st_size
    digest = _sha256_file(path) if size <= max_hash_bytes else ""
    return IOSFileRef(path.relative_to(root).as_posix(), size, digest)


def _candidate(
    *,
    weakness: str,
    summary: str,
    explanation: str,
    severity: str,
    plist_path: str,
    kind: str,
) -> dict:
    return {
        "json_answer": {
            "vulnerability_type": weakness[:200],
            "file_path": plist_path[:500],
            "line": 0,
            "summary": summary[:300],
            "explanation": explanation[:1600],
        },
        "severity": severity,
        "source": "aegis:ios-static",
        "confidence": 0.4,
        "validation_status": "unverified",
        "scanner_metadata": {
            "analysis_kind": kind,
            "context_required": True,
            "plist_allowlist_only": True,
        },
    }


def _url_schemes(plist: dict) -> tuple[str, ...]:
    output: set[str] = set()
    raw = plist.get("CFBundleURLTypes")
    if not isinstance(raw, list):
        return ()
    for row in raw[:100]:
        if not isinstance(row, dict):
            continue
        schemes = row.get("CFBundleURLSchemes")
        if not isinstance(schemes, list):
            continue
        for value in schemes[:100]:
            text = _safe_text(value, 120).strip()
            if text:
                output.add(text)
    return tuple(sorted(output))


def analyze_ios_ipa(
    ipa_path: str | Path,
    *,
    ticket: AssetExecutionTicket,
    scope_digest: str,
    workspace_root: str | Path | None = None,
    extraction_limits: SafeArchiveLimits | None = None,
) -> IOSStaticReport:
    """Extract and inspect selected IPA metadata. Caller owns cleanup of the returned extraction."""
    ipa = _validate_ipa(ipa_path)
    digest = _sha256_file(ipa)
    _verify_ticket(ticket, scope_digest=scope_digest, ipa_digest=digest)
    extraction: SafeArchiveExtraction | None = None
    try:
        extraction = extract_safe_archive(
            ipa,
            workspace_root=workspace_root,
            limits=extraction_limits,
        )
        if extraction.archive_type != "zip":
            raise IOSStaticError("IPA container must be a ZIP archive")
        root = Path(extraction.root).resolve()
        app_dirs = sorted(path for path in (root / "Payload").glob("*.app") if path.is_dir())
        if not app_dirs:
            raise IOSStaticError("IPA does not contain Payload/*.app")
        app = app_dirs[0]
        plist_path = app / "Info.plist"
        if not plist_path.is_file() or plist_path.stat().st_size > 16 * 1024 * 1024:
            raise IOSStaticError("IPA app Info.plist is missing or oversized")
        try:
            plist = plistlib.loads(plist_path.read_bytes())
        except Exception as exc:
            raise IOSStaticError(f"Info.plist could not be parsed: {type(exc).__name__}") from exc
        if not isinstance(plist, dict):
            raise IOSStaticError("Info.plist root must be a dictionary")

        executable_name = _safe_text(plist.get("CFBundleExecutable"), 255).strip()
        executable_path = app / executable_name if executable_name else None
        executable = (
            _ref(executable_path, root)
            if executable_path is not None and executable_path.is_file()
            else None
        )
        frameworks = tuple(
            _ref(path, root)
            for path in sorted((app / "Frameworks").glob("**/*"))
            if path.is_file() and not path.is_symlink()
        )[:1000]
        profiles = tuple(
            _ref(path, root)
            for path in sorted(app.glob("embedded.mobileprovision"))
            if path.is_file() and not path.is_symlink()
        )

        ats_raw = plist.get("NSAppTransportSecurity")
        ats_map = ats_raw if isinstance(ats_raw, dict) else {}
        ats = {
            "allows_arbitrary_loads": _safe_bool(ats_map.get("NSAllowsArbitraryLoads")),
            "allows_arbitrary_loads_in_web_content": _safe_bool(
                ats_map.get("NSAllowsArbitraryLoadsInWebContent")
            ),
            "allows_local_networking": _safe_bool(ats_map.get("NSAllowsLocalNetworking")),
        }
        file_sharing = {
            "ui_file_sharing_enabled": _safe_bool(plist.get("UIFileSharingEnabled")),
            "supports_opening_documents_in_place": _safe_bool(
                plist.get("LSSupportsOpeningDocumentsInPlace")
            ),
        }
        candidates: list[dict] = []
        relative_plist = plist_path.relative_to(root).as_posix()
        if ats["allows_arbitrary_loads"] is True:
            candidates.append(
                _candidate(
                    weakness="iOS ATS arbitrary loads enabled",
                    summary="Info.plist enables NSAllowsArbitraryLoads",
                    explanation=(
                        "Broad App Transport Security exceptions can permit weaker transport. "
                        "Validate concrete sensitive endpoints and runtime networking before impact claims."
                    ),
                    severity="low",
                    plist_path=relative_plist,
                    kind="ats_arbitrary_loads",
                )
            )
        if ats["allows_arbitrary_loads_in_web_content"] is True:
            candidates.append(
                _candidate(
                    weakness="iOS ATS arbitrary web-content loads enabled",
                    summary="Info.plist relaxes ATS for web content",
                    explanation=(
                        "The app relaxes App Transport Security for web content. Confirm an attacker-relevant "
                        "web view and sensitive traffic before treating this posture as exploitable."
                    ),
                    severity="low",
                    plist_path=relative_plist,
                    kind="ats_web_content",
                )
            )
        if (
            file_sharing["ui_file_sharing_enabled"] is True
            and file_sharing["supports_opening_documents_in_place"] is True
        ):
            candidates.append(
                _candidate(
                    weakness="iOS document/file sharing exposure posture",
                    summary="App enables file sharing and in-place document opening",
                    explanation=(
                        "These settings can expose app-managed documents through supported sharing workflows. "
                        "Validate which files are actually reachable and whether sensitive data is present."
                    ),
                    severity="low",
                    plist_path=relative_plist,
                    kind="file_sharing_posture",
                )
            )

        query_raw = plist.get("LSApplicationQueriesSchemes")
        query_schemes = tuple(
            sorted(
                {
                    text
                    for value in (query_raw if isinstance(query_raw, list) else [])[:500]
                    if (text := _safe_text(value, 120).strip())
                }
            )
        )
        return IOSStaticReport(
            ipa_path=str(ipa),
            ipa_sha256=digest,
            bundle_id=_safe_text(plist.get("CFBundleIdentifier"), 300),
            display_name=_safe_text(
                plist.get("CFBundleDisplayName") or plist.get("CFBundleName"), 300
            ),
            bundle_version=_safe_text(plist.get("CFBundleVersion"), 120),
            short_version=_safe_text(plist.get("CFBundleShortVersionString"), 120),
            minimum_os_version=_safe_text(plist.get("MinimumOSVersion"), 120),
            executable=executable,
            frameworks=frameworks,
            provisioning_profiles=profiles,
            url_schemes=_url_schemes(plist),
            query_schemes=query_schemes,
            ats=ats,
            file_sharing=file_sharing,
            candidates=tuple(candidates),
            extraction=extraction,
        )
    except Exception:
        if extraction is not None:
            cleanup_safe_archive(extraction)
        raise


def cleanup_ios_static(report: IOSStaticReport) -> None:
    cleanup_safe_archive(report.extraction)
