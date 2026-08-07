"""A corpus of past disclosed reports — the LEARN feedback store (§3, §12).

Load from JSONL (one report per line) or JSON (a list), query/filter, and
persist. Kept behind a small interface so it can later back onto a database or
vector store without changing callers.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from pathlib import Path

from .report import DisclosedReport, Severity


class ReportCorpus:
    def __init__(self, reports: Iterable[DisclosedReport] | None = None) -> None:
        self._reports: list[DisclosedReport] = list(reports or [])

    # -- population --

    def add(self, report: DisclosedReport) -> None:
        self._reports.append(report)

    def extend(self, reports: Iterable[DisclosedReport]) -> None:
        self._reports.extend(reports)

    @classmethod
    def from_jsonl(cls, path: str | Path) -> ReportCorpus:
        corpus = cls()
        text = Path(path).read_text(encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                corpus.add(DisclosedReport(**json.loads(line)))
            except (json.JSONDecodeError, ValueError) as exc:
                raise ValueError(f"invalid report on line {line_no}: {exc}") from exc
        return corpus

    @classmethod
    def from_json(cls, path: str | Path) -> ReportCorpus:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        items = data.get("reports", data) if isinstance(data, dict) else data
        return cls(DisclosedReport(**item) for item in items)

    def to_jsonl(self, path: str | Path) -> None:
        with Path(path).open("w", encoding="utf-8") as fh:
            fh.writelines(report.model_dump_json() + "\n" for report in self._reports)

    # -- access --

    def __len__(self) -> int:
        return len(self._reports)

    def __iter__(self) -> Iterator[DisclosedReport]:
        return iter(self._reports)

    @property
    def reports(self) -> list[DisclosedReport]:
        return list(self._reports)

    def filter(
        self,
        *,
        program: str | None = None,
        cwe: str | None = None,
        asset_type: str | None = None,
        min_severity: Severity | None = None,
        host_suffix: str | None = None,
    ) -> list[DisclosedReport]:
        out = self._reports
        if program is not None:
            out = [r for r in out if r.program == program]
        if cwe is not None:
            cwe = cwe.upper()
            out = [r for r in out if r.cwe == cwe]
        if asset_type is not None:
            at = asset_type.lower()
            out = [r for r in out if r.asset_type == at]
        if min_severity is not None:
            out = [r for r in out if r.severity >= min_severity]
        if host_suffix is not None:
            suf = host_suffix.lower()
            out = [r for r in out if suf in (r.asset_identifier or "").lower()]
        return list(out)

    def programs(self) -> set[str]:
        return {r.program for r in self._reports if r.program}

    def asset_types(self) -> set[str]:
        return {r.asset_type for r in self._reports if r.asset_type}
