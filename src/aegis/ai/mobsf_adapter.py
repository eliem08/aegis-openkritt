"""Loopback-only MobSF static-analysis adapter for authorized mobile artifacts.

The adapter implements MobSF's current static REST workflow:
``upload -> scan -> report_json -> delete_scan``. It never downloads an app from a store,
never starts dynamic analysis, and never accepts a non-loopback MobSF server by default.

MobSF output is normalized into *unverified candidates*. Aegis citation/evidence/reproduction
stages remain responsible for promotion; a MobSF warning is never treated as proof by itself.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

_SUPPORTED_EXTENSIONS = {
    ".apk", ".xapk", ".apks", ".jar", ".aar", ".zip", ".ipa",
    ".so", ".dylib", ".a", ".appx",
}
_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,128}$")
_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "warning": "medium",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "low",
    "informational": "low",
    "secure": "low",
    "good": "low",
}
_RISK_SECTIONS = {
    "code_analysis",
    "manifest_analysis",
    "certificate_analysis",
    "binary_analysis",
    "file_analysis",
    "permissions",
    "network_security",
}
_SENSITIVE_KEY_PARTS = ("secret", "password", "passwd", "token", "credential", "private_key")


class MobSFError(RuntimeError):
    """Safe, redacted MobSF adapter failure."""


@dataclass(frozen=True)
class MobSFConfig:
    base_url: str = "http://127.0.0.1:8000"
    api_key: str = ""
    timeout_seconds: float = 900.0
    max_artifact_bytes: int = 1024 * 1024 * 1024
    max_report_bytes: int = 64 * 1024 * 1024
    cleanup: bool = True

    def __post_init__(self) -> None:
        base = str(self.base_url or "").strip().rstrip("/")
        key = str(self.api_key or "").strip()
        parsed = urlsplit(base)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("MobSF base_url must be an HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("MobSF base_url cannot contain credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("MobSF base_url cannot contain query or fragment")
        if parsed.path not in {"", "/"}:
            raise ValueError("MobSF base_url must not contain an API path")
        if not _is_loopback(parsed.hostname):
            raise ValueError("MobSF server must resolve to an explicit loopback hostname/address")
        if not key:
            raise ValueError("MobSF API key is required")
        if not 0 < float(self.timeout_seconds) <= 3600:
            raise ValueError("MobSF timeout_seconds must be in (0, 3600]")
        if not 1 <= int(self.max_artifact_bytes) <= 4 * 1024 * 1024 * 1024:
            raise ValueError("MobSF max_artifact_bytes is outside the allowed range")
        if not 1024 <= int(self.max_report_bytes) <= 512 * 1024 * 1024:
            raise ValueError("MobSF max_report_bytes is outside the allowed range")
        object.__setattr__(self, "base_url", base)
        object.__setattr__(self, "api_key", key)

    @classmethod
    def from_env(cls, env: dict | None = None) -> "MobSFConfig":
        values = env if env is not None else os.environ
        return cls(
            base_url=values.get("AEGIS_MOBSF_URL", "http://127.0.0.1:8000"),
            api_key=values.get("AEGIS_MOBSF_API_KEY", ""),
            timeout_seconds=float(values.get("AEGIS_MOBSF_TIMEOUT", "900") or 900),
            max_artifact_bytes=int(
                values.get("AEGIS_MOBSF_MAX_ARTIFACT_BYTES", str(1024 * 1024 * 1024))
                or 1024 * 1024 * 1024
            ),
            max_report_bytes=int(
                values.get("AEGIS_MOBSF_MAX_REPORT_BYTES", str(64 * 1024 * 1024))
                or 64 * 1024 * 1024
            ),
            cleanup=str(values.get("AEGIS_MOBSF_CLEANUP", "1")).strip() != "0",
        )


@dataclass(frozen=True)
class MobSFScanResult:
    artifact_sha256: str
    mobsf_hash: str
    scan_type: str
    file_name: str
    report_digest: str
    report_metadata: dict[str, Any]
    findings: tuple[dict, ...]
    cleanup_deleted: bool
    cleanup_error: str = ""


class MobSFStaticAdapter:
    """Static MobSF client. Dynamic/mobile-device APIs are intentionally absent."""

    def __init__(self, config: MobSFConfig, *, client: httpx.Client | None = None) -> None:
        self.config = config
        self._owns_client = client is None
        self._client = client or httpx.Client(
            base_url=config.base_url,
            timeout=httpx.Timeout(config.timeout_seconds),
            follow_redirects=False,
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "MobSFStaticAdapter":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @property
    def _headers(self) -> dict[str, str]:
        return {"X-Mobsf-Api-Key": self.config.api_key}

    def scan(self, artifact: str | Path) -> MobSFScanResult:
        path = _validate_artifact(artifact, self.config.max_artifact_bytes)
        artifact_digest = _sha256_file(path)
        scan_hash = ""
        scan_type = ""
        file_name = path.name
        cleanup_deleted = False
        cleanup_error = ""
        report: dict[str, Any] | None = None

        try:
            upload = self._upload(path)
            scan_hash = _require_hash(upload.get("hash"))
            scan_type = _safe_scalar(upload.get("scan_type"), 80)
            file_name = _safe_scalar(upload.get("file_name"), 240) or path.name
            self._post_json("/api/v1/scan", data={"hash": scan_hash, "re_scan": "0"})
            report = self._post_json("/api/v1/report_json", data={"hash": scan_hash})
        finally:
            if scan_hash and self.config.cleanup:
                try:
                    deleted = self._post_json("/api/v1/delete_scan", data={"hash": scan_hash})
                    cleanup_deleted = str(deleted.get("deleted", "")).strip().lower() in {
                        "yes", "scan hash not found"
                    }
                    if not cleanup_deleted:
                        cleanup_error = "MobSF cleanup returned an unexpected response"
                except Exception as exc:
                    cleanup_error = f"{type(exc).__name__}: cleanup failed"[:160]

        if report is None:
            raise MobSFError("MobSF did not return a static JSON report")
        report_digest = _sha256_json(report)
        findings = tuple(normalize_mobsf_report(report, artifact_name=file_name))
        metadata = _report_metadata(report, file_name=file_name, scan_type=scan_type)
        return MobSFScanResult(
            artifact_sha256=artifact_digest,
            mobsf_hash=scan_hash,
            scan_type=scan_type,
            file_name=file_name,
            report_digest=report_digest,
            report_metadata=metadata,
            findings=findings,
            cleanup_deleted=cleanup_deleted,
            cleanup_error=cleanup_error,
        )

    def _upload(self, path: Path) -> dict[str, Any]:
        with path.open("rb") as handle:
            response = self._request(
                "POST",
                "/api/v1/upload",
                files={"file": (path.name, handle, "application/octet-stream")},
            )
        return self._json(response)

    def _post_json(self, endpoint: str, *, data: dict[str, str]) -> dict[str, Any]:
        return self._json(self._request("POST", endpoint, data=data))

    def _request(self, method: str, endpoint: str, **kwargs) -> httpx.Response:
        try:
            response = self._client.request(
                method,
                endpoint,
                headers=self._headers,
                **kwargs,
            )
        except httpx.HTTPError as exc:
            raise MobSFError(f"MobSF request failed: {type(exc).__name__}") from exc
        if response.status_code >= 400:
            detail = _safe_error(response)
            raise MobSFError(f"MobSF HTTP {response.status_code}: {detail}"[:240])
        if len(response.content) > self.config.max_report_bytes:
            raise MobSFError("MobSF response exceeded the configured size limit")
        return response

    @staticmethod
    def _json(response: httpx.Response) -> dict[str, Any]:
        try:
            payload = response.json()
        except ValueError as exc:
            raise MobSFError("MobSF returned non-JSON content") from exc
        if not isinstance(payload, dict):
            raise MobSFError("MobSF returned an unexpected JSON shape")
        if payload.get("error"):
            raise MobSFError(f"MobSF error: {_safe_scalar(payload.get('error'), 180)}")
        return payload


def _is_loopback(hostname: str) -> bool:
    host = hostname.strip().lower().rstrip(".")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_artifact(artifact: str | Path, maximum_bytes: int) -> Path:
    path = Path(artifact).expanduser().resolve()
    if not path.is_file():
        raise ValueError("MobSF artifact must be an existing regular file")
    if path.suffix.lower() not in _SUPPORTED_EXTENSIONS:
        raise ValueError(f"unsupported MobSF static artifact extension: {path.suffix.lower()}")
    size = path.stat().st_size
    if size <= 0:
        raise ValueError("MobSF artifact cannot be empty")
    if size > maximum_bytes:
        raise ValueError("MobSF artifact exceeds the configured size limit")
    return path


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_json(payload: dict[str, Any]) -> str:
    import json

    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _require_hash(value: Any) -> str:
    scan_hash = str(value or "").strip()
    if not _HASH_RE.fullmatch(scan_hash):
        raise MobSFError("MobSF upload response did not contain a valid scan hash")
    return scan_hash.lower()


def _safe_scalar(value: Any, limit: int) -> str:
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return ""
    text = str(value).replace("\x00", " ").replace("\r", " ").replace("\n", " ").strip()
    return text[:limit]


def _safe_error(response: httpx.Response) -> str:
    try:
        payload = response.json()
        if isinstance(payload, dict):
            return _safe_scalar(payload.get("error") or payload.get("message"), 180) or "request failed"
    except ValueError:
        pass
    return "request failed"


def _report_metadata(report: dict[str, Any], *, file_name: str, scan_type: str) -> dict[str, Any]:
    allow = ("version", "title", "app_name", "package_name", "bundle_id", "app_type")
    metadata = {"file_name": file_name, "scan_type": scan_type}
    for key in allow:
        value = _safe_scalar(report.get(key), 240)
        if value:
            metadata[key] = value
    return metadata


def normalize_mobsf_report(report: dict[str, Any], *, artifact_name: str = "") -> list[dict]:
    rows: list[dict] = []
    for section in _RISK_SECTIONS:
        value = report.get(section)
        if value is not None:
            _walk_findings(value, section, (), rows, artifact_name)
    return _dedupe_rows(rows)


def _walk_findings(value: Any, section: str, path: tuple[str, ...], rows: list[dict],
                   artifact_name: str) -> None:
    if isinstance(value, list):
        for index, item in enumerate(value[:5000]):
            _walk_findings(item, section, (*path, str(index)), rows, artifact_name)
        return
    if not isinstance(value, dict):
        return

    node = {str(key): item for key, item in value.items()}
    severity_raw = _first_value(node, ("severity", "level", "risk", "status"))
    severity = _SEVERITY.get(str(severity_raw or "").strip().lower())
    title = _first_text(node, ("title", "name", "rule", "rule_id", "issue", "finding"))
    description = _first_text(node, ("description", "message", "summary", "info", "reason"))
    if severity and (title or description):
        rule = title or (path[-1] if path else section)
        file_path = _extract_path(node) or artifact_name
        cwe = _extract_cwe(node)
        rows.append({
            "json_answer": {
                "vulnerability_type": cwe or f"MobSF:{rule}"[:200],
                "file_path": file_path[:500],
                "line": _extract_line(node),
                "summary": (title or description)[:300],
                "explanation": description[:1600],
            },
            "severity": severity,
            "source": "aegis:tool:mobsf",
            "validation_status": "unverified",
            "confidence": 0.55 if severity in {"critical", "high"} else 0.45,
            "scanner_metadata": {
                "section": section,
                "rule_id": rule[:160],
                "cwe": cwe or None,
                "validation": "mobsf-static-candidate",
            },
        })

    for key, child in node.items():
        if any(part in key.lower() for part in _SENSITIVE_KEY_PARTS):
            continue
        if isinstance(child, (dict, list)):
            _walk_findings(child, section, (*path, key), rows, artifact_name)


def _first_value(node: dict[str, Any], keys: tuple[str, ...]) -> Any:
    lowered = {key.lower(): value for key, value in node.items()}
    for key in keys:
        if key in lowered:
            return lowered[key]
    return None


def _first_text(node: dict[str, Any], keys: tuple[str, ...]) -> str:
    value = _first_value(node, keys)
    return _safe_scalar(value, 1800)


def _extract_path(node: dict[str, Any]) -> str:
    for key in ("file", "file_path", "path", "filename"):
        value = _first_value(node, (key,))
        text = _safe_scalar(value, 500)
        if text:
            return text
    files = _first_value(node, ("files",))
    if isinstance(files, list) and files:
        return _safe_scalar(files[0], 500)
    if isinstance(files, dict) and files:
        first = next(iter(files.keys()), "")
        return _safe_scalar(first, 500)
    return ""


def _extract_line(node: dict[str, Any]) -> int:
    value = _first_value(node, ("line", "line_no", "line_number"))
    try:
        line = int(value)
    except (TypeError, ValueError):
        return 0
    return max(0, line)


def _extract_cwe(node: dict[str, Any]) -> str:
    value = _first_value(node, ("cwe", "cwe_id"))
    text = _safe_scalar(value, 80)
    match = re.search(r"CWE[-_ ]?(\d+)", text, re.IGNORECASE)
    return f"CWE-{int(match.group(1))}" if match else ""


def _dedupe_rows(rows: list[dict]) -> list[dict]:
    output: list[dict] = []
    seen: set[tuple[str, str, int, str]] = set()
    for row in rows:
        answer = row.get("json_answer") or {}
        key = (
            str(answer.get("vulnerability_type") or ""),
            str(answer.get("file_path") or ""),
            int(answer.get("line") or 0),
            str(answer.get("summary") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
    return output
