"""Automatic code-level validation for persisted direct-DeepSeek scan reports."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path

from aegis.integrations import ingest_openkritt_findings
from aegis.report import build_console

from .agents.contracts import Hypothesis, SourceSlice, VerificationProposal
from .code_validation import CodeValidationAgent

_IMPORT = re.compile(r'import\s+(?:\{[^}]*\}\s+from\s+)?["\x27]([^"\x27]+)["\x27]\s*;')


def validate_deepseek_report(
    report_path: str | Path,
    repo_root: str | Path,
    client,
    *,
    progress: Callable[[int, int, str], None] | None = None,
) -> tuple[dict, dict]:
    """Validate every hypothesis, persist verdicts, and return report + UI model."""
    report_path = Path(report_path).resolve()
    repo_root = Path(repo_root).resolve()
    data = json.loads(report_path.read_text(encoding="utf-8"))
    rows = list(data.get("vulnerabilities") or [])
    total = len(rows)
    validator = CodeValidationAgent(client)

    for index, row in enumerate(rows, start=1):
        answer = row.get("json_answer") or {}
        path = str(answer.get("file_path") or "")
        if progress:
            progress(index - 1, total, path)
        # A row without a file anchor (some scanner/skill outputs) can't be citation-
        # validated. Mark it unresolved rather than crashing the whole report's validation.
        if not path.strip():
            row["validation"] = {
                "verdict": "unresolved",
                "reason": "no source file anchor to validate against",
                "confidence": 0.0, "anchors": [], "verification_test": "",
            }
            row["validation_status"] = "unresolved"
            if progress:
                progress(index, total, path)
            continue
        try:
            hypothesis = _hypothesis(row)
        except Exception as exc:                       # malformed scanner/skill row
            row["validation"] = {
                "verdict": "unresolved",
                "reason": f"row could not be normalized for validation: {type(exc).__name__}",
                "confidence": 0.0, "anchors": [], "verification_test": "",
            }
            row["validation_status"] = "unresolved"
            if progress:
                progress(index, total, path)
            continue
        slices = _context(repo_root, path)
        if not slices:
            payload = {
                "verdict": "unresolved",
                "reason": "source file is absent from the pinned checkout",
                "confidence": 0.0,
                "anchors": [],
                "verification_test": "",
            }
        else:
            # caller-tracing: pull in the functions that CALL the flagged code so the
            # validator can resolve deferred-verification patterns (a helper that omits a
            # guard is only vulnerable if a CALLER also fails to supply it).
            try:
                from .caller_trace import caller_slices
                extra = caller_slices(repo_root, path, getattr(hypothesis, "line", 1),
                                      max_callers=4)
                if extra:
                    slices = list(slices) + list(extra)
            except Exception:
                pass
            try:
                validation = validator.validate(
                    hypothesis,
                    slices,
                    policy_notes=(
                        "Pinned source-only validation. Check documented intent, caller and role "
                        "restrictions, signed-message trust, state ordering, inherited guards, and "
                        "SafeMath before confirming. Slices whose path starts with 'caller::' show "
                        "where the flagged function is INVOKED — if the flawed function defers a "
                        "check to its caller (e.g. 'verify in caller'), it is only a vulnerability "
                        "when a caller actually fails to supply that guard; confirm by reading "
                        "these callers, and refute if every caller verifies. No live execution."
                    ),
                )
                payload = validation.model_dump(mode="json")
            except Exception as exc:
                # one flaky/oversized validation call must NOT sink the whole report —
                # mark this row unresolved and keep going.
                payload = {
                    "verdict": "unresolved",
                    "reason": f"validation call failed: {type(exc).__name__}",
                    "confidence": 0.0, "anchors": [], "verification_test": "",
                }
        row["validation"] = payload
        row["validation_status"] = payload["verdict"]
        if progress:
            progress(index, total, path)

    scan = data.setdefault("scan", {})
    scan["validation_status"] = "completed"
    scan["validation_counts"] = _counts(rows)
    report_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    model = _review_model(data)
    return data, model


def _hypothesis(row: dict) -> Hypothesis:
    answer = row.get("json_answer") or {}
    method = str(answer.get("verification_method") or "static_analysis")
    if method not in {"static_analysis", "contract_property", "manual_review"}:
        method = "static_analysis"
    severity = str(answer.get("severity") or row.get("severity") or "medium").lower()
    if severity not in {"critical", "high", "medium", "low"}:
        severity = "medium"
    return Hypothesis(
        weakness=str(answer.get("vulnerability_type") or "Security issue"),
        title=str(answer.get("summary") or "Untitled security hypothesis"),
        file_path=str(answer.get("file_path") or ""),
        line=max(1, int(answer.get("line") or 1)),
        rationale=str(answer.get("explanation") or "No rationale supplied"),
        confidence=float(row.get("confidence", 0.5)),
        # carry the reachability claim so the validator can check it, not just the code
        entry_point=str(answer.get("trigger_flow") or "")[:600],
        attacker=str(answer.get("malicious_actor") or "")[:300],
        impact=str(answer.get("impact") or "")[:600],
        severity=severity,
        verification=VerificationProposal(
            method=method,
            expected_observation=str(answer.get("trigger_flow") or "Review the cited code."),
            maximum_requests=0,
        ),
    )


def _context(repo_root: Path, relative: str) -> list[SourceSlice]:
    primary = _inside(repo_root, repo_root / relative)
    if primary is None or not primary.is_file():
        return []
    queue: list[tuple[Path, int]] = [(primary, 0)]
    seen: set[Path] = set()
    output: list[SourceSlice] = []
    chars = 0
    while queue and len(output) < 20 and chars < 240_000:
        path, depth = queue.pop(0)
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        content = path.read_text(encoding="utf-8", errors="replace")
        if chars + len(content) > 250_000:
            continue
        output.append(SourceSlice(path=path.relative_to(repo_root).as_posix(), content=content))
        chars += len(content)
        if depth >= 2:
            continue
        for imported in _IMPORT.findall(content):
            if imported.startswith("."):
                candidate = _inside(repo_root, (path.parent / imported).resolve())
                if candidate is not None:
                    queue.append((candidate, depth + 1))

    stem = primary.stem
    for test in sorted((repo_root / "test").rglob(f"{stem}*.sol"))[:2]:
        content = test.read_text(encoding="utf-8", errors="replace")
        if chars + len(content) <= 250_000 and len(output) < 20:
            output.append(SourceSlice(path=test.relative_to(repo_root).as_posix(), content=content))
            chars += len(content)
    return output


def _inside(root: Path, candidate: Path) -> Path | None:
    try:
        resolved = candidate.resolve()
        resolved.relative_to(root)
        return resolved
    except (OSError, ValueError):
        return None


def _counts(rows: list[dict]) -> dict[str, int]:
    counts = {"confirmed": 0, "false_positive": 0, "unresolved": 0}
    for row in rows:
        verdict = str((row.get("validation") or {}).get("verdict") or "unresolved")
        counts[verdict if verdict in counts else "unresolved"] += 1
    return counts


def _review_model(data: dict) -> dict:
    rows = list(data.get("vulnerabilities") or [])
    candidates = []
    validation_by_key: dict[tuple[str, str], dict] = {}
    for row in rows:
        imported = ingest_openkritt_findings([row])
        if not imported:
            continue
        candidate = imported[0]
        candidate.worker = "integration:deepseek-platform"
        candidates.append(candidate)
        validation_by_key[(candidate.code_location, candidate.observed)] = row.get("validation") or {}

    model = build_console(candidates, scan_id=str((data.get("scan") or {}).get("id") or ""))
    counts = {"confirmed": 0, "false_positive": 0, "unresolved": 0}
    for item in model["items"]:
        validation = dict(validation_by_key.get((item["code_location"], item["observed"])) or {})
        normalized_location = "/" + item["code_location"].replace("\\", "/").lower().lstrip("/")
        if validation.get("verdict") == "confirmed" and "/examples/" in normalized_location:
            validation["verdict"] = "unresolved"
            validation["reason"] = (
                "Example-only source is not report-ready without a passing local reproducer and "
                "evidence of deployed reachability. " + str(validation.get("reason") or "")
            ).strip()
        verdict = str(validation.get("verdict") or "unresolved")
        if verdict not in counts:
            verdict = "unresolved"
        item["status"] = verdict
        item["validation_reason"] = str(validation.get("reason") or "")
        item["validation_confidence"] = float(validation.get("confidence") or 0)
        item["code_anchors"] = list(validation.get("anchors") or [])
        item["verification_test"] = str(validation.get("verification_test") or "")
        counts[verdict] += 1
    model["totals"]["confirmed"] = counts["confirmed"]
    model["totals"]["rejected"] = counts["false_positive"]
    model["totals"]["unresolved"] = counts["unresolved"]
    model["totals"]["verified"] = counts["confirmed"]
    model["totals"]["hypotheses"] = counts["unresolved"]
    model["validation_counts"] = counts
    model["note"] = (
        f"Automatic source validation completed: {counts['confirmed']} confirmed, "
        f"{counts['false_positive']} rejected, {counts['unresolved']} unresolved. "
        "Confirmed requires exact citations that Aegis matched to the pinned checkout."
    )
    return model


def review_model_from_report(report_path: str | Path) -> dict:
    """Build the validated console model from an already-persisted report."""
    path = Path(report_path).resolve()
    return _review_model(json.loads(path.read_text(encoding="utf-8")))
