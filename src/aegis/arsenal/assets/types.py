"""First-class bounty asset types and the technique map that routes work to them.

The repository already carries two asset vocabularies:

* ``aegis.ingest.program.AssetType`` — what a *program scope page* declares.
* ``aegis.ai.jarvis.asset_capabilities.AssetKind`` — what the deep tool planner
  reasons about.

This module is the arsenal-side bridge between them. ``ArsenalAssetType`` is the
set of asset classes the arsenal can actually *execute* against, and
``TECHNIQUE_MAP`` states, per asset type, which techniques apply and what each one
needs before it may run. Nothing here performs I/O; it is a pure routing table so
the CLI, the inventory, and the tests all agree on one description of coverage.

Mobile (Android/iOS) and hardware are deliberately absent: the operator does not
work those asset classes, and a technique map that claimed them would overstate
coverage. They raise ``UnsupportedAssetType`` instead of silently degrading.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from aegis.ai.jarvis.asset_capabilities import AssetKind
from aegis.ingest.program import AssetType


class UnsupportedAssetType(ValueError):
    """The asset class is outside what this arsenal implements (mobile, hardware)."""


class ArsenalAssetType(str, Enum):
    """Asset classes the arsenal can plan and execute techniques against."""

    CIDR = "cidr"
    DOMAIN = "domain"
    WILDCARD = "wildcard"
    IP_ADDRESS = "ip_address"
    API = "api"
    AWS_ACCOUNT = "aws_account"
    AZURE_ACCOUNT = "azure_account"
    SOURCE_CODE = "source_code"
    EXECUTABLE = "executable"
    SMART_CONTRACT = "smart_contract"
    AI_MODEL = "ai_model"
    OTHER_ASSET = "other_asset"


#: Asset classes an operator may legitimately name but this arsenal refuses to
#: pretend it covers. Kept explicit so a typo in a scope file is distinguishable
#: from a deliberate out-of-charter request.
REFUSED_ASSET_TYPES: frozenset[str] = frozenset({
    "android", "ios", "mobile", "hardware", "firmware", "iot",
})


class Requirement(str, Enum):
    """What a technique needs before it is permitted to execute."""

    NONE = "none"
    NETWORK = "authorized_network_access"
    ARTIFACT = "authorized_local_artifact"
    API_SPEC = "api_specification"
    CREDENTIALS = "authorized_read_only_credentials"
    POLICY_DOCUMENT = "provided_policy_document"
    SECOND_IDENTITY = "second_authorized_identity"
    STATE_CHANGE_OPT_IN = "explicit_state_change_opt_in"


@dataclass(frozen=True, slots=True)
class Technique:
    """One executable unit of arsenal work bound to an asset type.

    ``executor`` is a dotted reference to the callable that implements it, kept as
    a string so this table stays import-free and cheap to inspect from the CLI.
    """

    technique_id: str
    title: str
    executor: str
    requirements: tuple[Requirement, ...] = ()
    tools: tuple[str, ...] = ()
    linux_only_tools: tuple[str, ...] = ()
    state_changing: bool = False
    purpose: str = ""

    def document(self) -> dict[str, Any]:
        value = asdict(self)
        value["requirements"] = [item.value for item in self.requirements]
        return value


_NETWORK_SURFACE = (
    Technique(
        "passive-certificate-transparency", "Certificate transparency enumeration",
        "aegis.arsenal.assets.network:certificate_transparency",
        (Requirement.NETWORK,), ("crt.sh",),
        purpose="passive subdomain discovery from public CT logs before any active probe",
    ),
    Technique(
        "dns-enumeration", "DNS record enumeration",
        "aegis.arsenal.assets.network:dns_enumeration",
        (Requirement.NETWORK,), ("stdlib-resolver",),
        purpose="A/AAAA/CNAME/MX/TXT/NS resolution for scoped names",
    ),
    Technique(
        "subdomain-takeover", "Dangling CNAME takeover detection",
        "aegis.arsenal.assets.network:subdomain_takeover",
        (Requirement.NETWORK,), ("stdlib-resolver",),
        purpose="CNAME pointing at an unclaimed provider hostname",
    ),
    Technique(
        "service-identification", "Port and service identification",
        "aegis.arsenal.assets.network:service_identification",
        (Requirement.NETWORK,), ("nmap",), ("nmap",),
        purpose="bounded top-port service and version fingerprinting",
    ),
    Technique(
        "tls-inspection", "TLS and certificate inspection",
        "aegis.arsenal.assets.network:tls_inspection",
        (Requirement.NETWORK,), ("stdlib-ssl",),
        purpose="protocol version, expiry, SAN inventory, and hostname mismatch",
    ),
    Technique(
        "security-headers", "HTTP security header analysis",
        "aegis.arsenal.assets.network:security_headers",
        (Requirement.NETWORK,), ("stdlib-http",),
        purpose="HSTS/CSP/frame/content-type/referrer posture on a single GET",
    ),
    Technique(
        "virtual-host-discovery", "Virtual host discovery",
        "aegis.arsenal.assets.network:virtual_host_discovery",
        (Requirement.NETWORK,), ("stdlib-http",),
        purpose="differential Host-header responses that expose unlinked vhosts",
    ),
)

_API_SURFACE = (
    Technique(
        "openapi-ingest", "OpenAPI/Swagger specification ingestion",
        "aegis.arsenal.assets.api_surface:ingest_specification",
        (Requirement.API_SPEC,), ("aegis-openapi-parser",),
        purpose="endpoint, parameter, and declared-auth inventory from the spec",
    ),
    Technique(
        "authorization-matrix", "Cross-role authorization matrix",
        "aegis.arsenal.assets.api_surface:authorization_matrix",
        (Requirement.API_SPEC, Requirement.NETWORK, Requirement.SECOND_IDENTITY),
        ("aegis-authz-matrix",),
        purpose="same request as role A vs role B vs unauthenticated, contrasted",
    ),
    Technique(
        "object-reference-probe", "BOLA/IDOR object reference probing",
        "aegis.arsenal.assets.api_surface:object_reference_probe",
        (Requirement.API_SPEC, Requirement.NETWORK, Requirement.SECOND_IDENTITY),
        ("aegis-bola-probe",),
        purpose="object identifiers reachable across identity boundaries",
    ),
    Technique(
        "mass-assignment", "Mass-assignment surface analysis",
        "aegis.arsenal.assets.api_surface:mass_assignment",
        (Requirement.API_SPEC,), ("aegis-openapi-parser",),
        purpose="writable request schemas carrying privileged read-only properties",
    ),
    Technique(
        "rate-limit-check", "Rate limit signalling check",
        "aegis.arsenal.assets.api_surface:rate_limit_check",
        (Requirement.API_SPEC, Requirement.NETWORK), ("stdlib-http",),
        purpose="whether the endpoint advertises or enforces any request budget",
    ),
)

_CLOUD_COMMON = (
    Technique(
        "iam-policy-review", "Over-broad IAM policy detection",
        "aegis.arsenal.assets.cloud:iam_policy_review",
        (Requirement.POLICY_DOCUMENT,), ("aegis-policy-parser",),
        purpose="wildcard action/resource and missing-condition grants in policy JSON",
    ),
    Technique(
        "metadata-endpoint-exposure", "Instance metadata exposure check",
        "aegis.arsenal.assets.cloud:metadata_endpoint_exposure",
        (Requirement.NETWORK,), ("stdlib-http",),
        purpose="whether a scoped front end proxies cloud instance metadata",
    ),
)

_AWS_SURFACE = _CLOUD_COMMON + (
    Technique(
        "public-bucket-review", "Public S3 bucket and ACL review",
        "aegis.arsenal.assets.cloud:public_bucket_review",
        (Requirement.NETWORK,), ("stdlib-http",),
        purpose="anonymous list/read on named buckets, read-only",
    ),
)

_AZURE_SURFACE = _CLOUD_COMMON + (
    Technique(
        "public-blob-review", "Public Azure blob container review",
        "aegis.arsenal.assets.cloud:public_blob_review",
        (Requirement.NETWORK,), ("stdlib-http",),
        purpose="anonymous container enumeration on named storage accounts, read-only",
    ),
)

_EXECUTABLE_SURFACE = (
    Technique(
        "binary-triage", "Binary format, packer, and signature triage",
        "aegis.arsenal.assets.executable:binary_triage",
        (Requirement.ARTIFACT,), ("aegis-binary-triage",),
        purpose="format, architecture, section entropy, packer and signing indicators",
    ),
    Technique(
        "embedded-secret-scan", "Embedded secret and endpoint extraction",
        "aegis.arsenal.assets.executable:embedded_secret_scan",
        (Requirement.ARTIFACT,), ("aegis-strings",),
        purpose="high-entropy strings, credential patterns, and hardcoded endpoints",
    ),
    Technique(
        "dependency-extraction", "Dependency and version extraction",
        "aegis.arsenal.assets.executable:dependency_extraction",
        (Requirement.ARTIFACT,), ("aegis-strings", "syft"), ("syft",),
        purpose="linked libraries and embedded version banners for CVE mapping",
    ),
    Technique(
        "bundle-unpack", "Electron/ASAR bundle unpack to the source lane",
        "aegis.arsenal.assets.executable:bundle_unpack",
        (Requirement.ARTIFACT,), ("aegis-asar",),
        purpose="unpack embedded JavaScript so the existing source review path runs on it",
    ),
)

_CONTRACT_SURFACE = (
    Technique(
        "contract-static-analysis", "Solidity/Vyper static analysis",
        "aegis.arsenal.assets.contract:static_analysis",
        (Requirement.ARTIFACT,), ("slither", "mythril"), ("slither", "mythril"),
        purpose="whole-contract static and symbolic analysis when the tools are installed",
    ),
    Technique(
        "contract-pattern-review", "Contract weakness pattern review",
        "aegis.arsenal.assets.contract:pattern_review",
        (Requirement.ARTIFACT,), ("aegis-contract-patterns",),
        purpose="reentrancy, access control, unchecked calls, oracle and proxy-storage risk",
    ),
)

_AI_MODEL_SURFACE = (
    Technique(
        "prompt-injection-suite", "Prompt injection and guardrail bypass cases",
        "aegis.arsenal.assets.ai_model:prompt_injection_suite",
        (), ("aegis-llm-lab",),
        purpose="generate the adversarial case set; execution against a live endpoint opts in",
    ),
    Technique(
        "system-prompt-extraction", "System prompt extraction attempts",
        "aegis.arsenal.assets.ai_model:system_prompt_extraction",
        (), ("aegis-llm-lab",),
        purpose="cases that try to recover hidden instructions and configuration",
    ),
    Technique(
        "tool-abuse-chain", "Tool and function-call abuse chains",
        "aegis.arsenal.assets.ai_model:tool_abuse_chain",
        (), ("aegis-llm-lab",),
        purpose="chains that turn model output into an unauthorized tool invocation",
    ),
    Technique(
        "output-handling-review", "Model output handling review",
        "aegis.arsenal.assets.ai_model:output_handling_review",
        (), ("aegis-output-oracle",),
        purpose="whether the consuming application renders model output as HTML or markup",
    ),
)

_SOURCE_SURFACE = (
    Technique(
        "source-scanner-sweep", "Deterministic source scanner sweep",
        "aegis.arsenal.assets.source:scanner_sweep",
        (Requirement.ARTIFACT,), ("semgrep", "gitleaks", "bandit", "trivy"),
        ("semgrep",),
        purpose="the existing ToolBridge scanner lane over a local checkout",
    ),
)

_OTHER_SURFACE = (
    Technique(
        "asset-triage", "Unclassified asset triage",
        "aegis.arsenal.assets.other:asset_triage",
        (), ("aegis-asset-triage",),
        purpose="classify an 'Other' scope entry and name the lane it should be re-run as",
    ),
)


#: The routing table. Every supported asset type maps to at least one technique.
TECHNIQUE_MAP: Mapping[ArsenalAssetType, tuple[Technique, ...]] = {
    ArsenalAssetType.DOMAIN: _NETWORK_SURFACE,
    ArsenalAssetType.WILDCARD: _NETWORK_SURFACE,
    ArsenalAssetType.IP_ADDRESS: _NETWORK_SURFACE,
    ArsenalAssetType.CIDR: _NETWORK_SURFACE,
    ArsenalAssetType.API: _API_SURFACE,
    ArsenalAssetType.AWS_ACCOUNT: _AWS_SURFACE,
    ArsenalAssetType.AZURE_ACCOUNT: _AZURE_SURFACE,
    ArsenalAssetType.SOURCE_CODE: _SOURCE_SURFACE,
    ArsenalAssetType.EXECUTABLE: _EXECUTABLE_SURFACE,
    ArsenalAssetType.SMART_CONTRACT: _CONTRACT_SURFACE,
    ArsenalAssetType.AI_MODEL: _AI_MODEL_SURFACE,
    ArsenalAssetType.OTHER_ASSET: _OTHER_SURFACE,
}


#: Bridge to the deep tool planner's vocabulary so arsenal coverage and the
#: capability inventory describe the same asset in the same words.
_ASSET_KIND_BY_TYPE: Mapping[ArsenalAssetType, AssetKind] = {
    ArsenalAssetType.CIDR: AssetKind.CIDR,
    ArsenalAssetType.DOMAIN: AssetKind.DOMAIN,
    ArsenalAssetType.WILDCARD: AssetKind.WILDCARD,
    ArsenalAssetType.IP_ADDRESS: AssetKind.IP_ADDRESS,
    ArsenalAssetType.API: AssetKind.API,
    ArsenalAssetType.AWS_ACCOUNT: AssetKind.AWS_ACCOUNT,
    ArsenalAssetType.AZURE_ACCOUNT: AssetKind.AZURE_ACCOUNT,
    ArsenalAssetType.SOURCE_CODE: AssetKind.SOURCE_CODE,
    ArsenalAssetType.EXECUTABLE: AssetKind.EXECUTABLE,
    ArsenalAssetType.SMART_CONTRACT: AssetKind.SMART_CONTRACT,
    ArsenalAssetType.AI_MODEL: AssetKind.AI_MODEL,
    ArsenalAssetType.OTHER_ASSET: AssetKind.OTHER_ASSET,
}

#: Bridge to the program-scope vocabulary produced by ``aegis.ingest.program``.
_PROGRAM_TYPE_BRIDGE: Mapping[AssetType, ArsenalAssetType] = {
    AssetType.URL: ArsenalAssetType.DOMAIN,
    AssetType.WILDCARD: ArsenalAssetType.WILDCARD,
    AssetType.CIDR: ArsenalAssetType.CIDR,
    AssetType.IP: ArsenalAssetType.IP_ADDRESS,
    AssetType.SOURCE_CODE: ArsenalAssetType.SOURCE_CODE,
    AssetType.EXECUTABLE: ArsenalAssetType.EXECUTABLE,
    AssetType.API: ArsenalAssetType.API,
    AssetType.SMART_CONTRACT: ArsenalAssetType.SMART_CONTRACT,
    AssetType.AI_MODEL: ArsenalAssetType.AI_MODEL,
    AssetType.CLOUD_ACCOUNT: ArsenalAssetType.AWS_ACCOUNT,
    AssetType.OTHER: ArsenalAssetType.OTHER_ASSET,
}

_ALIASES: Mapping[str, ArsenalAssetType] = {
    "url": ArsenalAssetType.DOMAIN,
    "host": ArsenalAssetType.DOMAIN,
    "hostname": ArsenalAssetType.DOMAIN,
    "ip": ArsenalAssetType.IP_ADDRESS,
    "ip_address": ArsenalAssetType.IP_ADDRESS,
    "ipv4": ArsenalAssetType.IP_ADDRESS,
    "ipv6": ArsenalAssetType.IP_ADDRESS,
    "aws": ArsenalAssetType.AWS_ACCOUNT,
    "azure": ArsenalAssetType.AZURE_ACCOUNT,
    "cloud_account": ArsenalAssetType.AWS_ACCOUNT,
    "repo": ArsenalAssetType.SOURCE_CODE,
    "repository": ArsenalAssetType.SOURCE_CODE,
    "binary": ArsenalAssetType.EXECUTABLE,
    "contract": ArsenalAssetType.SMART_CONTRACT,
    "llm": ArsenalAssetType.AI_MODEL,
    "model": ArsenalAssetType.AI_MODEL,
    "other": ArsenalAssetType.OTHER_ASSET,
}

_CONTRACT_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-z0-9_-]{1,63}\.)+[a-z]{2,63}$")
_AWS_ACCOUNT_ID = re.compile(r"^\d{12}$")
_EXECUTABLE_SUFFIXES = frozenset({
    ".exe", ".dll", ".so", ".dylib", ".elf", ".bin", ".appimage", ".asar", ".apk",
})
_CONTRACT_SUFFIXES = frozenset({".sol", ".vy"})


def parse_asset_type(raw: str) -> ArsenalAssetType:
    """Resolve an operator-supplied asset-type string, refusing out-of-charter classes."""
    value = (raw or "").strip().lower().replace("-", "_").replace(" ", "_")
    if not value:
        raise ValueError("asset type is required")
    if value in REFUSED_ASSET_TYPES:
        raise UnsupportedAssetType(
            f"{value!r} is out of charter for this arsenal (mobile and hardware are not "
            "implemented); no technique will be planned for it"
        )
    if value in _ALIASES:
        return _ALIASES[value]
    try:
        return ArsenalAssetType(value)
    except ValueError as exc:
        raise ValueError(f"unknown asset type: {raw!r}") from exc


def from_program_asset_type(value: AssetType) -> ArsenalAssetType:
    """Map a parsed program-scope asset type onto an arsenal asset type."""
    if value in (AssetType.ANDROID, AssetType.IOS, AssetType.FIRMWARE):
        raise UnsupportedAssetType(
            f"program asset type {value.value!r} is mobile/hardware and is not implemented"
        )
    resolved = _PROGRAM_TYPE_BRIDGE.get(value)
    if resolved is None:
        raise UnsupportedAssetType(f"program asset type {value.value!r} has no arsenal lane")
    return resolved


def classify_identifier(identifier: str) -> ArsenalAssetType:
    """Infer the asset type from the identifier alone.

    Used only when the operator does not declare one. Inference is conservative:
    anything it cannot place lands in ``OTHER_ASSET``, whose single technique is
    triage — never a network probe.
    """
    value = (identifier or "").strip()
    if not value:
        raise ValueError("asset identifier is required")
    lowered = value.lower()

    if "/" in lowered and not lowered.startswith(("http://", "https://")):
        try:
            ipaddress.ip_network(lowered, strict=False)
            return ArsenalAssetType.CIDR
        except ValueError:
            pass
    try:
        ipaddress.ip_address(lowered)
        return ArsenalAssetType.IP_ADDRESS
    except ValueError:
        pass
    if lowered.startswith("*."):
        return ArsenalAssetType.WILDCARD
    if _CONTRACT_ADDRESS.match(value):
        return ArsenalAssetType.SMART_CONTRACT

    suffix = Path(lowered).suffix
    if suffix in _CONTRACT_SUFFIXES:
        return ArsenalAssetType.SMART_CONTRACT
    if suffix in _EXECUTABLE_SUFFIXES:
        return ArsenalAssetType.EXECUTABLE
    if suffix in {".json", ".yaml", ".yml"} and any(
        token in lowered for token in ("openapi", "swagger")
    ):
        return ArsenalAssetType.API
    if _AWS_ACCOUNT_ID.match(lowered):
        return ArsenalAssetType.AWS_ACCOUNT
    # A repository URL is source code, not a web host — check it before the generic
    # URL rule, which would otherwise claim every https:// identifier as a domain.
    if any(host in lowered for host in ("github.com/", "gitlab.com/", "bitbucket.org/")):
        return ArsenalAssetType.SOURCE_CODE
    if lowered.startswith(("http://", "https://")):
        return ArsenalAssetType.API if "/api" in lowered else ArsenalAssetType.DOMAIN
    if _HOSTNAME.match(lowered):
        return ArsenalAssetType.DOMAIN
    return ArsenalAssetType.OTHER_ASSET


def techniques_for(asset_type: ArsenalAssetType) -> tuple[Technique, ...]:
    """Return the techniques registered for an asset type."""
    techniques = TECHNIQUE_MAP.get(asset_type)
    if not techniques:
        raise UnsupportedAssetType(f"no techniques registered for {asset_type.value!r}")
    return techniques


def asset_kind_for(asset_type: ArsenalAssetType) -> AssetKind:
    """Return the deep-planner ``AssetKind`` this arsenal asset type corresponds to."""
    return _ASSET_KIND_BY_TYPE[asset_type]


def coverage_matrix() -> dict[str, Any]:
    """A non-targeting description of what each asset type routes to."""
    return {
        "supported_asset_types": [item.value for item in ArsenalAssetType],
        "refused_asset_types": sorted(REFUSED_ASSET_TYPES),
        "techniques": {
            asset_type.value: [item.document() for item in techniques]
            for asset_type, techniques in TECHNIQUE_MAP.items()
        },
    }


__all__ = [
    "ArsenalAssetType",
    "REFUSED_ASSET_TYPES",
    "Requirement",
    "TECHNIQUE_MAP",
    "Technique",
    "UnsupportedAssetType",
    "asset_kind_for",
    "classify_identifier",
    "coverage_matrix",
    "from_program_asset_type",
    "parse_asset_type",
    "techniques_for",
]
