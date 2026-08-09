"""Offline Android manifest/source hypotheses over integrity-bound derived trees.

The analyzer never executes the application. Manifest exposure is treated as a hypothesis boundary,
not proof: an exported component without a manifest permission still needs code/caller validation.
Likewise WebView/TLS patterns are candidates that require contextual evidence. Deep-link and SDK
posture is emitted as observation metadata.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .android_static import AndroidDerivedTree

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")


class AndroidSurfaceError(RuntimeError):
    pass


@dataclass(frozen=True)
class AndroidStaticAnalysis:
    candidates: tuple[dict, ...]
    observation: dict[str, Any]


def _attr(element: ET.Element, name: str) -> str:
    return str(element.attrib.get(_ANDROID_NS + name, "")).strip()


def _bool(value: str) -> bool | None:
    text = str(value or "").strip().lower()
    if text == "true":
        return True
    if text == "false":
        return False
    return None


def _candidate(*, weakness: str, summary: str, explanation: str, file_path: str,
               line: int = 0, severity: str = "medium", kind: str,
               metadata: dict | None = None) -> dict:
    return {
        "json_answer": {
            "vulnerability_type": weakness[:200],
            "file_path": file_path[:500],
            "line": max(0, int(line)),
            "summary": summary[:300],
            "explanation": explanation[:1800],
        },
        "severity": severity,
        "source": "aegis:android-static",
        "confidence": 0.55 if severity in {"high", "critical"} else 0.45,
        "validation_status": "unverified",
        "scanner_metadata": {
            "analysis_kind": kind,
            "context_required": True,
            **(metadata or {}),
        },
    }


def _find_manifest(root: Path) -> Path | None:
    candidates = sorted(
        (path for path in root.rglob("AndroidManifest.xml") if path.is_file()),
        key=lambda path: (len(path.relative_to(root).parts), len(str(path))),
    )
    return candidates[0] if candidates else None


def _manifest_analysis(root: Path) -> tuple[list[dict], dict]:
    manifest = _find_manifest(root)
    if manifest is None:
        return [], {"manifest_found": False}
    try:
        tree = ET.parse(manifest)
    except (ET.ParseError, OSError) as exc:
        return [], {
            "manifest_found": True,
            "manifest_path": manifest.relative_to(root).as_posix(),
            "manifest_parse_error": type(exc).__name__,
        }
    document = tree.getroot()
    application = document.find("application")
    relative = manifest.relative_to(root).as_posix()
    candidates: list[dict] = []
    observation: dict[str, Any] = {
        "manifest_found": True,
        "manifest_path": relative,
        "package": document.attrib.get("package", ""),
        "components": [],
        "deep_links": [],
    }

    uses_sdk = document.find("uses-sdk")
    if uses_sdk is not None:
        observation["min_sdk"] = _attr(uses_sdk, "minSdkVersion")
        observation["target_sdk"] = _attr(uses_sdk, "targetSdkVersion")

    app_permission = ""
    if application is not None:
        app_permission = _attr(application, "permission")
        debuggable = _bool(_attr(application, "debuggable"))
        allow_backup = _bool(_attr(application, "allowBackup"))
        cleartext = _bool(_attr(application, "usesCleartextTraffic"))
        observation.update(
            {
                "application_permission": app_permission,
                "debuggable": debuggable,
                "allow_backup": allow_backup,
                "uses_cleartext_traffic": cleartext,
                "network_security_config": _attr(application, "networkSecurityConfig"),
            }
        )
        if debuggable is True:
            candidates.append(
                _candidate(
                    weakness="Android debuggable production posture",
                    summary="Application manifest enables android:debuggable",
                    explanation=(
                        "Debuggable builds can expose additional inspection/debug surfaces. "
                        "Confirm this manifest belongs to an in-scope production artifact before impact claims."
                    ),
                    file_path=relative,
                    severity="low",
                    kind="manifest_debuggable",
                )
            )
        if allow_backup is True:
            candidates.append(
                _candidate(
                    weakness="Android backup exposure posture",
                    summary="Application manifest explicitly enables allowBackup",
                    explanation=(
                        "Backup eligibility can expose application data depending on Android version, "
                        "backup rules and data classification. Validate actual backup contents and platform behavior."
                    ),
                    file_path=relative,
                    severity="low",
                    kind="manifest_backup",
                )
            )
        if cleartext is True:
            candidates.append(
                _candidate(
                    weakness="Android cleartext traffic posture",
                    summary="Application manifest explicitly permits cleartext traffic",
                    explanation=(
                        "Cleartext allowance weakens transport policy but is not proof that sensitive traffic "
                        "uses HTTP. Validate concrete endpoints and transmitted data before reporting impact."
                    ),
                    file_path=relative,
                    severity="low",
                    kind="manifest_cleartext",
                )
            )

        for tag in _COMPONENT_TAGS:
            for component in application.findall(tag):
                name = _attr(component, "name")
                exported = _bool(_attr(component, "exported"))
                permission = _attr(component, "permission") or app_permission
                component_row = {
                    "type": tag,
                    "name": name,
                    "exported": exported,
                    "permission": permission,
                    "intent_filters": len(component.findall("intent-filter")),
                }
                observation["components"].append(component_row)
                if exported is True and not permission:
                    candidates.append(
                        _candidate(
                            weakness="Android exported component without manifest permission",
                            summary=f"Exported {tag} has no manifest permission: {name or '<unnamed>'}",
                            explanation=(
                                "The manifest exposes this component to external callers without a manifest-level "
                                "permission. Confirm the component is reachable by an attacker and that its code "
                                "does not enforce equivalent authorization before treating this as exploitable."
                            ),
                            file_path=relative,
                            severity="medium",
                            kind="exported_component",
                            metadata={"component_type": tag, "component_name": name},
                        )
                    )

                for intent_filter in component.findall("intent-filter"):
                    actions = {_attr(item, "name") for item in intent_filter.findall("action")}
                    categories = {_attr(item, "name") for item in intent_filter.findall("category")}
                    browsable = "android.intent.category.BROWSABLE" in categories
                    view = "android.intent.action.VIEW" in actions
                    if not (browsable and view):
                        continue
                    for data in intent_filter.findall("data"):
                        observation["deep_links"].append(
                            {
                                "component": name,
                                "scheme": _attr(data, "scheme"),
                                "host": _attr(data, "host"),
                                "port": _attr(data, "port"),
                                "path": _attr(data, "path") or _attr(data, "pathPrefix"),
                                "auto_verify": _bool(_attr(intent_filter, "autoVerify")),
                            }
                        )
    return candidates, observation


_SOURCE_PATTERNS = (
    (
        "webview_universal_file_access",
        re.compile(r"setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)"),
        "Android WebView universal file-URL access enabled",
        "WebView permits file-origin content to access arbitrary origins; validate whether attacker-controlled local/remote content can reach this WebView.",
        "high",
    ),
    (
        "webview_file_url_access",
        re.compile(r"setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)"),
        "Android WebView file-URL cross-file access enabled",
        "WebView permits file-origin cross-file access; confirm attacker-controlled file content and sensitive reachable resources.",
        "medium",
    ),
    (
        "ssl_error_proceed",
        re.compile(r"onReceivedSslError[\s\S]{0,1200}?\.proceed\s*\(\s*\)"),
        "WebView SSL error handler appears to proceed",
        "Proceeding after TLS certificate errors can disable server authentication for WebView traffic. Validate the concrete handler/control flow and sensitive endpoint usage.",
        "high",
    ),
    (
        "hostname_verifier_true",
        re.compile(r"HostnameVerifier[\s\S]{0,800}?return\s+true\s*;"),
        "HostnameVerifier appears to accept every hostname",
        "An always-true hostname verifier can disable hostname authentication. Validate that this verifier is installed on security-sensitive production connections.",
        "high",
    ),
    (
        "empty_trust_manager",
        re.compile(r"checkServerTrusted\s*\([^)]*\)\s*\{\s*\}"),
        "TrustManager checkServerTrusted implementation appears empty",
        "An empty server-trust check can disable certificate validation. Confirm this TrustManager is instantiated and used by an in-scope network client.",
        "high",
    ),
)


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _source_analysis(root: Path, *, max_files: int = 50_000,
                     max_total_bytes: int = 512 * 1024 * 1024,
                     max_file_bytes: int = 2 * 1024 * 1024) -> tuple[list[dict], dict]:
    candidates: list[dict] = []
    scanned = total = 0
    bridge_files = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise AndroidSurfaceError("derived Android tree contains a symlink")
        if not path.is_file() or path.suffix.lower() not in {".java", ".kt", ".smali"}:
            continue
        scanned += 1
        if scanned > max_files:
            raise AndroidSurfaceError("Android source tree exceeds file-count limit")
        size = path.stat().st_size
        total += size
        if total > max_total_bytes:
            raise AndroidSurfaceError("Android source tree exceeds byte limit")
        if size > max_file_bytes:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        relative = path.relative_to(root).as_posix()
        javascript = bool(re.search(r"setJavaScriptEnabled\s*\(\s*true\s*\)", text))
        bridge = bool(re.search(r"addJavascriptInterface\s*\(", text))
        if javascript and bridge:
            bridge_files += 1
            offset = text.find("addJavascriptInterface")
            candidates.append(
                _candidate(
                    weakness="Android WebView JavaScript bridge exposure",
                    summary="WebView enables JavaScript and registers a JavaScript interface",
                    explanation=(
                        "A JavaScript bridge can expose native methods to page content. Confirm attacker-controlled "
                        "content/origins can load in this WebView and inspect the exposed interface methods before "
                        "claiming code/data impact."
                    ),
                    file_path=relative,
                    line=_line(text, max(0, offset)),
                    severity="medium",
                    kind="webview_javascript_bridge",
                )
            )
        for kind, pattern, summary, explanation, severity in _SOURCE_PATTERNS:
            for match in pattern.finditer(text):
                candidates.append(
                    _candidate(
                        weakness=summary,
                        summary=summary,
                        explanation=explanation,
                        file_path=relative,
                        line=_line(text, match.start()),
                        severity=severity,
                        kind=kind,
                    )
                )
    return candidates, {
        "source_files_scanned": scanned,
        "source_bytes_scanned": total,
        "javascript_bridge_files": bridge_files,
    }


def _dedupe(rows: list[dict]) -> tuple[dict, ...]:
    output: list[dict] = []
    seen: set[tuple[str, str, int, str]] = set()
    for row in rows:
        answer = row.get("json_answer") or {}
        key = (
            str(answer.get("vulnerability_type") or ""),
            str(answer.get("file_path") or ""),
            int(answer.get("line") or 0),
            str((row.get("scanner_metadata") or {}).get("analysis_kind") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
    return tuple(output)


def analyze_android_derived_tree(tree: AndroidDerivedTree) -> AndroidStaticAnalysis:
    root = Path(tree.root).resolve()
    if not root.is_dir():
        raise AndroidSurfaceError("derived Android tree is unavailable")
    manifest_candidates, manifest_observation = _manifest_analysis(root)
    source_candidates, source_observation = _source_analysis(root)
    return AndroidStaticAnalysis(
        candidates=_dedupe([*manifest_candidates, *source_candidates]),
        observation={
            "kind": "android_static_surface",
            "source_tool": tree.tool,
            "apk_sha256": tree.apk_sha256,
            "tree_digest": tree.tree_digest,
            "manifest": manifest_observation,
            "source": source_observation,
            "verification_state": "hypothesis_generation",
        },
    )
