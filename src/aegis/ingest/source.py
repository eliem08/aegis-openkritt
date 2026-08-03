"""Provenance-rich imports for user-authorized bounty-platform exports."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from .program import ProgramRules, ScopeAsset, classify_asset_type, parse_policy_constraints


class SourceFormatError(ValueError):
    pass


class ProgramSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: ProgramRules
    source: str
    source_hash: str
    retrieved_at: datetime
    authorization_expires_at: datetime

    @property
    def expired(self) -> bool:
        return self.authorization_expires_at <= datetime.now(timezone.utc)


class ProgramSource(Protocol):
    def programs(self) -> list[ProgramSnapshot]: ...


def _parse_time(value: str, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise SourceFormatError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise SourceFormatError(f"{name} must include a timezone")
    return parsed.astimezone(timezone.utc)


def map_platform_export(document: dict, *, platform: str) -> list[ProgramSnapshot]:
    if platform not in {"bugcrowd", "intigriti"}:
        raise SourceFormatError("unsupported platform export")
    programs = document.get("programs")
    retrieved = _parse_time(document.get("retrieved_at", ""), "retrieved_at")
    expires = _parse_time(
        document.get("authorization_expires_at", ""), "authorization_expires_at",
    )
    if not isinstance(programs, list):
        raise SourceFormatError("programs must be a list")
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    source_hash = hashlib.sha256(canonical).hexdigest()
    output = []
    for raw in programs:
        if not isinstance(raw, dict) or not raw.get("handle"):
            raise SourceFormatError("each program requires a handle")
        policy = str(raw.get("policy") or "")
        constraints = parse_policy_constraints(policy)
        inside, outside = [], []
        for item in raw.get("scope") or []:
            if not isinstance(item, dict) or not item.get("target"):
                raise SourceFormatError("each scope item requires a target")
            target = str(item["target"])
            raw_type = str(item.get("type") or "OTHER")
            eligible = bool(item.get("eligible_for_submission", item.get("in_scope", True)))
            asset = ScopeAsset(
                identifier=target,
                asset_type=classify_asset_type(raw_type, target),
                raw_asset_type=raw_type,
                eligible_for_submission=eligible,
                eligible_for_bounty=bool(item.get("eligible_for_bounty", False)),
                max_severity=item.get("max_severity"),
                instruction=str(item.get("instruction") or ""),
            )
            (inside if eligible else outside).append(asset)
        rules = ProgramRules(
            platform=platform,
            handle=str(raw["handle"]),
            name=str(raw.get("name") or raw["handle"]),
            submission_state=str(raw.get("submission_state") or "open"),
            offers_bounties=bool(raw.get("offers_bounties", False)),
            policy_text=policy,
            in_scope=inside,
            out_of_scope=outside,
            automation_allowed=constraints["automation_allowed"],
            ai_allowed=constraints["ai_allowed"],
            rate_limit_rps=constraints["rate_limit_rps"],
            notes=constraints["notes"] + [f"imported from user-provided {platform} export"],
        )
        output.append(ProgramSnapshot(
            rules=rules,
            source=f"{platform}:user-export",
            source_hash=source_hash,
            retrieved_at=retrieved,
            authorization_expires_at=expires,
        ))
    return output


class JsonExportProgramSource:
    def __init__(self, path: str | Path, *, platform: str) -> None:
        self._path = Path(path)
        self._platform = platform

    def programs(self) -> list[ProgramSnapshot]:
        try:
            document = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SourceFormatError("cannot read platform export") from exc
        if not isinstance(document, dict):
            raise SourceFormatError("platform export must be an object")
        return map_platform_export(document, platform=self._platform)
