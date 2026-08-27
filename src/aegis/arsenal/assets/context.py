"""The inputs a lane is handed, and nothing it can reach around.

``LaneContext`` is the only object a technique receives. It carries the guarded
session, the tool resolver, and whatever *operator-supplied* material the lane
needs (a downloaded artifact, an OpenAPI document, a policy JSON, a second
identity's headers). A technique cannot open a socket, shell out, or read a
credential except through what is on this object.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .session import HuntSession
from .tooling import ToolResolver
from .types import ArsenalAssetType


@dataclass(frozen=True, slots=True)
class Identity:
    """A role the operator has already authenticated, expressed as headers.

    Aegis never performs the login. The operator obtains the session themselves and
    passes the resulting header material in, which is what makes the cross-role
    authorization matrix possible without any credential handling here.
    """

    label: str
    headers: Mapping[str, str] = field(default_factory=dict)
    expected_role: str = ""

    def document(self) -> dict[str, Any]:
        # Header *values* are session material and never leave the process.
        return {
            "label": self.label,
            "expected_role": self.expected_role,
            "header_names": sorted(self.headers),
        }


@dataclass(frozen=True, slots=True)
class LaneContext:
    """Everything one asset lane may use."""

    asset: str
    asset_type: ArsenalAssetType
    session: HuntSession
    resolver: ToolResolver
    artifact_path: Path | None = None
    specification_path: Path | None = None
    policy_documents: tuple[Path, ...] = ()
    identities: tuple[Identity, ...] = ()
    workspace: Path | None = None
    options: Mapping[str, Any] = field(default_factory=dict)

    @property
    def anonymous_only(self) -> bool:
        return not self.identities

    def option(self, name: str, default: Any = None) -> Any:
        return self.options.get(name, default)

    def base_url(self) -> str:
        """The asset expressed as an absolute URL, defaulting to HTTPS."""
        value = self.asset.strip()
        if value.startswith(("http://", "https://")):
            return value.rstrip("/")
        return "https://" + value.lstrip("/").rstrip("/")

    def document(self) -> dict[str, Any]:
        return {
            "asset": self.asset,
            "asset_type": self.asset_type.value,
            "artifact_path": str(self.artifact_path) if self.artifact_path else "",
            "specification_path": (
                str(self.specification_path) if self.specification_path else ""
            ),
            "policy_documents": [str(item) for item in self.policy_documents],
            "identities": [item.document() for item in self.identities],
            "options": dict(self.options),
        }


def redact(value: Any) -> Any:
    """Strip anything that looks like session or credential material from evidence."""
    sensitive = {
        "authorization", "cookie", "set-cookie", "token", "api_key", "apikey",
        "password", "secret", "x-api-key", "x-auth-token", "proxy-authorization",
    }
    if isinstance(value, Mapping):
        return {
            key: "[redacted]" if str(key).lower() in sensitive else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    return value


__all__ = ["Identity", "LaneContext", "redact"]
