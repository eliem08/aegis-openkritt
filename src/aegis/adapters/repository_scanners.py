"""Strict parsers for pinned repository scanners.

These adapters intentionally expose parsing only. Their manifests pin the
official container release digests, but ``build_command`` fails closed until
Aegis' hardened container executor (read-only filesystem, no direct egress,
non-root user) is wired. This prevents a host binary from being mistaken for a
verified container release.
"""

from __future__ import annotations

from pathlib import PurePath, PurePosixPath

from .base import JsonDocumentAdapter, SchemaMismatch, ToolUnavailable
from .contract import AdapterManifest, CapabilityTier, EventKind, ExecutionEnvelope


SEMGREP_MANIFEST = AdapterManifest(
    name="semgrep",
    version="1.164.0",
    executable_digest="207983631beecdbe7fa29196c7f4a7a5f29033933cdb76c687ce4a672e07618d",
    license="LGPL-2.1",
    capability_tier=CapabilityTier.PASSIVE_DISCOVERY.value,
    input_schema_version=1,
    output_schema_version=1,
    network_profile="none",
)

GITLEAKS_MANIFEST = AdapterManifest(
    name="gitleaks",
    version="8.30.1",
    executable_digest="c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f",
    license="MIT",
    capability_tier=CapabilityTier.PASSIVE_DISCOVERY.value,
    input_schema_version=1,
    output_schema_version=1,
    network_profile="none",
)

OSV_SCANNER_MANIFEST = AdapterManifest(
    name="osv-scanner",
    version="2.4.0",
    executable_digest="5116601dedc01c1c580eb92371883ec052fc4c13c3fbc109d621a63ac416d475",
    license="Apache-2.0",
    capability_tier=CapabilityTier.PASSIVE_DISCOVERY.value,
    input_schema_version=1,
    output_schema_version=1,
    network_profile="none",
)


def _relative_path(value) -> str:
    """Return a normalized repo-relative path without leaking host directories."""
    if not isinstance(value, str) or not value.strip():
        raise SchemaMismatch("finding path must be a non-empty string")
    normalized = value.replace("\\", "/")
    # Absolute scanner paths commonly end in /src/<repo path>. Keep only the
    # mounted-repository suffix. Unknown absolute roots degrade to basename.
    if "/src/" in normalized:
        normalized = normalized.split("/src/", 1)[1]
    path = PurePosixPath(normalized)
    if path.is_absolute() or (len(normalized) > 1 and normalized[1] == ":"):
        path = PurePosixPath(PurePath(normalized).name)
    safe = [part for part in path.parts if part not in ("", ".", "..", "/")]
    if not safe:
        raise SchemaMismatch("finding path cannot be normalized safely")
    return "/".join(safe)


def _positive_int(value, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise SchemaMismatch(f"{field} must be a positive integer")
    return value


class _ContainerOnlyDocumentAdapter(JsonDocumentAdapter):
    def build_command(self, envelope: ExecutionEnvelope) -> list[str]:
        raise ToolUnavailable(
            f"{self.manifest.name} is parser-ready but disabled until the hardened "
            "digest-pinned container executor is configured"
        )


class SemgrepDocumentAdapter(_ContainerOnlyDocumentAdapter):
    manifest = SEMGREP_MANIFEST

    def map_document(self, root, envelope):
        if not isinstance(root, dict) or not isinstance(root.get("results"), list):
            raise SchemaMismatch("Semgrep document.results must be an array")
        errors = root.get("errors", [])
        if not isinstance(errors, list):
            raise SchemaMismatch("Semgrep document.errors must be an array")
        mapped = []
        if errors:
            mapped.append((EventKind.DIAGNOSTIC, {
                "code": "parser_incompatible",
                "message": "Semgrep reported scan errors; coverage is incomplete",
                "blocking": True,
                "error_count": len(errors),
            }, 0.0))
        for result in root["results"]:
            if not isinstance(result, dict):
                raise SchemaMismatch("Semgrep result must be an object")
            extra = result.get("extra")
            start = result.get("start")
            end = result.get("end")
            if not isinstance(extra, dict) or not isinstance(start, dict) or not isinstance(end, dict):
                raise SchemaMismatch("Semgrep result is missing extra/start/end objects")
            rule_id = result.get("check_id")
            message = extra.get("message")
            severity = extra.get("severity")
            if not all(isinstance(v, str) and v for v in (rule_id, message, severity)):
                raise SchemaMismatch("Semgrep result rule/message/severity must be strings")
            metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
            mapped.append((EventKind.FINDING, {
                "scanner": "semgrep",
                "rule_id": rule_id,
                "path": _relative_path(result.get("path")),
                "start_line": _positive_int(start.get("line"), "Semgrep start.line"),
                "end_line": _positive_int(end.get("line"), "Semgrep end.line"),
                "message": message[:1000],
                "severity": severity.lower(),
                "category": metadata.get("category"),
                "confidence_label": metadata.get("confidence"),
                "verified": False,
            }, 0.5))
        return mapped


class GitleaksDocumentAdapter(_ContainerOnlyDocumentAdapter):
    manifest = GITLEAKS_MANIFEST

    def map_document(self, root, envelope):
        if not isinstance(root, list):
            raise SchemaMismatch("Gitleaks report must be an array")
        mapped = []
        for finding in root:
            if not isinstance(finding, dict):
                raise SchemaMismatch("Gitleaks finding must be an object")
            rule_id = finding.get("RuleID")
            fingerprint = finding.get("Fingerprint")
            if not isinstance(rule_id, str) or not rule_id:
                raise SchemaMismatch("Gitleaks RuleID must be a non-empty string")
            if not isinstance(fingerprint, str) or not fingerprint:
                raise SchemaMismatch("Gitleaks Fingerprint must be a non-empty string")
            # Deliberately omit Secret, Match, Line, author identity, email, and
            # commit message even when the upstream report includes them.
            mapped.append((EventKind.SECRET_CANDIDATE, {
                "scanner": "gitleaks",
                "rule_id": rule_id,
                "path": _relative_path(finding.get("File")),
                "start_line": _positive_int(finding.get("StartLine"), "Gitleaks StartLine"),
                "fingerprint": fingerprint[:512],
                "commit": str(finding.get("Commit") or "")[:64] or None,
                "redacted": True,
                "verified": False,
            }, 0.5))
        return mapped


class OsvScannerDocumentAdapter(_ContainerOnlyDocumentAdapter):
    manifest = OSV_SCANNER_MANIFEST

    def result_succeeded(self, result) -> bool:
        # OSV-Scanner documents exit code 1 as "vulnerabilities/findings found".
        # Other non-zero values remain failures; timeouts/limits have no exit code.
        return getattr(result, "exit_code", None) in (0, 1)

    def map_document(self, root, envelope):
        if not isinstance(root, dict) or not isinstance(root.get("results"), list):
            raise SchemaMismatch("OSV-Scanner document.results must be an array")
        mapped = []
        for result in root["results"]:
            if not isinstance(result, dict):
                raise SchemaMismatch("OSV-Scanner result must be an object")
            source = result.get("source", {})
            packages = result.get("packages")
            if not isinstance(source, dict) or not isinstance(packages, list):
                raise SchemaMismatch("OSV-Scanner result source/packages schema mismatch")
            source_path = _relative_path(source.get("path"))
            source_type = source.get("type")
            for item in packages:
                if not isinstance(item, dict) or not isinstance(item.get("package"), dict):
                    raise SchemaMismatch("OSV-Scanner package entry is invalid")
                package = item["package"]
                vulns = item.get("vulnerabilities", [])
                if not isinstance(vulns, list):
                    raise SchemaMismatch("OSV-Scanner vulnerabilities must be an array")
                name, version, ecosystem = (
                    package.get("name"), package.get("version"), package.get("ecosystem"),
                )
                if not all(isinstance(v, str) and v for v in (name, version, ecosystem)):
                    raise SchemaMismatch("OSV package name/version/ecosystem must be strings")
                for vuln in vulns:
                    if not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str):
                        raise SchemaMismatch("OSV vulnerability must have a string id")
                    aliases = vuln.get("aliases", [])
                    severity = vuln.get("severity", [])
                    mapped.append((EventKind.FINDING, {
                        "scanner": "osv-scanner",
                        "vulnerability_id": vuln["id"],
                        "aliases": [a for a in aliases if isinstance(a, str)][:32]
                        if isinstance(aliases, list) else [],
                        "package": name,
                        "version": version,
                        "ecosystem": ecosystem,
                        "source_path": source_path,
                        "source_type": source_type if isinstance(source_type, str) else None,
                        "severity": [s for s in severity if isinstance(s, dict)][:8]
                        if isinstance(severity, list) else [],
                        "verified": False,
                    }, 0.7))
        return mapped


SOURCE_SCANNER_MANIFESTS = (
    SEMGREP_MANIFEST,
    GITLEAKS_MANIFEST,
    OSV_SCANNER_MANIFEST,
)


def source_scanner_parsers() -> dict[str, JsonDocumentAdapter]:
    """Return parser-ready scanners; execution remains fail-closed."""
    adapters = (SemgrepDocumentAdapter(), GitleaksDocumentAdapter(), OsvScannerDocumentAdapter())
    return {adapter.manifest.name: adapter for adapter in adapters}
