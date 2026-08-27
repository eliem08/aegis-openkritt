"""Federate canonical code/runtime registries without replacing their authority."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import Any

from aegis.adapters import DISCOVERY_MANIFESTS, SOURCE_SCANNER_MANIFESTS
from aegis.ai.jarvis.asset_deep_capabilities import (
    method_requirements,
    plan_deep_asset_scan,
    supported_deep_asset_kinds,
)
from aegis.ai.jarvis.hunter_techniques import TECHNIQUES
from aegis.ai.tool_registry import TOOLS

from .assets.types import TECHNIQUE_MAP as ASSET_TECHNIQUE_MAP
from .models import (
    CapabilityConflict,
    CapabilityDefinition,
    CapabilityProvenance,
    ConflictClaim,
    ToolBackend,
)


def _digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return sha256(raw).hexdigest()


def _provenance(field: str, registry: str, reference: str, value: Any):
    return CapabilityProvenance(field, registry, reference, _digest(value))


def _slug(value: str) -> str:
    return "-".join(part for part in "".join(
        char.lower() if char.isalnum() else " " for char in value
    ).split() if part)


def _release_versions(path: str | Path | None) -> dict[str, str]:
    if not path:
        return {}
    source = Path(path)
    if not source.is_file():
        return {}
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return {
        str(item.get("name")): str(item.get("version") or "")
        for item in data.get("releases", []) if isinstance(item, dict) and item.get("name")
    }


class ArsenalInventoryBuilder:
    """Create stable definitions with field-level origin and visible conflicts."""

    def __init__(self, *, release_lock_path: str | Path | None = None) -> None:
        self.release_lock_path = release_lock_path

    def build(self) -> tuple[CapabilityDefinition, ...]:
        versions = _release_versions(self.release_lock_path)
        definitions: dict[str, CapabilityDefinition] = {}
        for tool in TOOLS:
            for lane in sorted(tool.lanes):
                capability_id = f"tool:{_slug(tool.name)}/{_slug(lane)}"
                expected = versions.get(tool.name, "")
                definitions[capability_id] = CapabilityDefinition(
                    capability_id, 1, (),
                    (ToolBackend(f"tool-registry:{tool.name}", tool.name, tool.binary,
                                 expected, "tool-bridge/1"),),
                    ("source_code",), "aegis.ai.tool_bridge.ToolBridge",
                    f"fixture:scanner:{tool.name}", ("TOOLS",),
                    ("src/aegis/ai/tool_registry.py", "src/aegis/ai/tool_bridge.py"),
                    (
                        _provenance("tool_backends", "TOOLS", tool.name, tool.binary),
                        _provenance("supported_asset_classes", "TOOLS", tool.name, lane),
                    ), fixture_executable=True,
                )

        assets_by_method: dict[tuple[str, str], set[str]] = defaultdict(set)
        methods: dict[tuple[str, str], Any] = {}
        for asset_kind in supported_deep_asset_kinds():
            plan = plan_deep_asset_scan(
                asset_kind, artifact_available=True, credentials_available=True,
                api_spec_available=True, endpoint_available=True, firmware_available=True,
                language_hints=("python", "go", "ruby", "java"),
                platform_hint="windows", service_hints=("tls", "ssh"),
            )
            for method in (*plan.ready, *plan.blocked):
                key = (str(method.tool), str(method.method))
                methods[key] = method
                assets_by_method[key].add(str(asset_kind.value))
        for key, method in sorted(methods.items()):
            tool_name, method_name = key
            capability_id = f"asset:{_slug(tool_name)}/{_slug(method_name)}"
            command = tuple(getattr(method, "command_template", ()) or ())
            binary = command[0] if command else _slug(tool_name)
            requirements = tuple(item.value for item in method_requirements(method))
            definitions[capability_id] = CapabilityDefinition(
                capability_id, 1, (),
                (ToolBackend(f"deep-asset:{tool_name}:{method_name}", tool_name, binary,
                             versions.get(tool_name.lower(), ""), "deep-asset/1"),),
                tuple(sorted(assets_by_method[key])),
                "aegis.ai.jarvis.asset_cli_executor.AssetCliExecutor",
                f"fixture:asset:{_slug(tool_name)}:{_slug(method_name)}",
                ("deep_asset_capabilities",),
                ("src/aegis/ai/jarvis/asset_deep_capabilities.py",),
                (
                    _provenance("tool_backends", "deep_asset_capabilities", method_name,
                                {"tool": tool_name, "binary": binary}),
                    _provenance("supported_asset_classes", "deep_asset_capabilities",
                                method_name, sorted(assets_by_method[key])),
                    _provenance("requirements", "deep_asset_capabilities", method_name,
                                requirements),
                ), fixture_executable=bool(getattr(method, "local_only", False)),
            )

        for technique, definition in sorted(TECHNIQUES.items(), key=lambda item: item[0].value):
            capability_id = f"hunter:{technique.value}"
            definitions[capability_id] = CapabilityDefinition(
                capability_id, 1, (technique.value,), (), definition.compatible_asset_types,
                definition.worker_capability,
                f"fixture:hunter:{technique.value}", ("TECHNIQUES",),
                ("src/aegis/ai/jarvis/hunter_techniques.py",),
                (
                    _provenance("technique_ids", "TECHNIQUES", technique.value,
                                technique.value),
                    _provenance("executor_provider", "TECHNIQUES", technique.value,
                                definition.worker_capability),
                ), fixture_executable=False,
            )

        capability_id = "fixture:ai/llm-security-boundary"
        definitions[capability_id] = CapabilityDefinition(
            capability_id, 1, ("ai-llm-boundary",), (), ("ai_model",),
            "jarvis:arsenal:llm-security-fixture", "aegis.arsenal.llm_lab",
            ("arsenal_builtin_fixtures",),
            ("src/aegis/arsenal/llm_lab.py", "src/aegis/arsenal/exercise.py"),
            (
                _provenance("executor_provider", "arsenal_builtin_fixtures", capability_id,
                            "jarvis:arsenal:llm-security-fixture"),
                _provenance("fixture_provider", "arsenal_builtin_fixtures", capability_id,
                            "aegis.arsenal.llm_lab"),
            ), fixture_executable=True,
        )

        # Per-asset-type lanes (aegis.arsenal.assets). These are executable arsenal
        # techniques with a concrete implementation, so they are inventoried
        # alongside the tool and hunter capabilities rather than living outside the
        # audit. Asset classes are taken from the routing table, so audit coverage
        # and the CLI cannot drift apart.
        assets_by_technique: dict[str, set[str]] = defaultdict(set)
        asset_techniques: dict[str, Any] = {}
        for asset_type, techniques in ASSET_TECHNIQUE_MAP.items():
            for technique in techniques:
                asset_techniques[technique.technique_id] = technique
                assets_by_technique[technique.technique_id].add(asset_type.value)
        for technique_id, technique in sorted(asset_techniques.items()):
            capability_id = f"asset-lane:{technique_id}"
            module, _, function = technique.executor.partition(":")
            backends = tuple(
                ToolBackend(f"asset-lane:{technique_id}:{name}", name, name,
                            versions.get(name.lower(), ""), "asset-lane/1")
                for name in technique.tools
            )
            definitions[capability_id] = CapabilityDefinition(
                capability_id, 1, (technique_id,), backends,
                tuple(sorted(assets_by_technique[technique_id])),
                f"{module}:{function}", None, ("ASSET_TECHNIQUE_MAP",),
                ("src/aegis/arsenal/assets/types.py", module.replace(".", "/") + ".py"),
                (
                    _provenance("technique_ids", "ASSET_TECHNIQUE_MAP", technique_id,
                                technique_id),
                    _provenance("supported_asset_classes", "ASSET_TECHNIQUE_MAP",
                                technique_id, sorted(assets_by_technique[technique_id])),
                    _provenance("executor_provider", "ASSET_TECHNIQUE_MAP", technique_id,
                                technique.executor),
                ), fixture_executable=False,
            )

        manifests = tuple(DISCOVERY_MANIFESTS) + tuple(SOURCE_SCANNER_MANIFESTS)
        for manifest in manifests:
            tier = str(manifest.capability_tier)
            capability_id = f"adapter:{_slug(manifest.name)}/{_slug(tier)}"
            candidate = CapabilityDefinition(
                capability_id, 1, (),
                (ToolBackend(f"adapter:{manifest.name}", manifest.name, manifest.name,
                             manifest.version, manifest.version),),
                (), f"adapter:{manifest.name}", None, ("adapter_manifests",),
                ("src/aegis/adapters",),
                (_provenance("tool_backends", "adapter_manifests", manifest.name,
                             manifest.version),), fixture_executable=False,
            )
            if capability_id not in definitions:
                definitions[capability_id] = candidate
            elif definitions[capability_id] != candidate:
                prior = definitions[capability_id]
                conflict = CapabilityConflict(
                    capability_id, "definition",
                    (ConflictClaim(prior.document(), prior.source_registries[0],
                                   prior.implementation_paths[0]),
                     ConflictClaim(candidate.document(), "adapter_manifests",
                                   "src/aegis/adapters")),
                    "high", True, "inventory-build",
                )
                definitions[capability_id] = replace(
                    prior, conflicts=(*prior.conflicts, conflict),
                )
        return tuple(definitions[key] for key in sorted(definitions))


__all__ = ["ArsenalInventoryBuilder"]
