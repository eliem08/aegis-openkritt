"""Real-tool capability registry for heterogeneous bug-bounty assets.

This module plans authorized analysis; it does not bypass acquisition controls.
Store listings, cloud account identifiers, hardware, and AI endpoints are only
promoted to deeper scanners once the required authorized artifact, credentials,
or endpoint access is explicitly available.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class AssetKind(str, Enum):
    CIDR = "cidr"
    DOMAIN = "domain"
    IOS_APP_STORE = "ios_app_store"
    IOS_TESTFLIGHT = "ios_testflight"
    IOS_IPA = "ios_ipa"
    ANDROID_PLAY_STORE = "android_play_store"
    ANDROID_APK = "android_apk"
    WINDOWS_MICROSOFT_STORE = "windows_microsoft_store"
    SOURCE_CODE = "source_code"
    EXECUTABLE = "executable"
    SMART_CONTRACT = "smart_contract"
    WILDCARD = "wildcard"
    IP_ADDRESS = "ip_address"
    HARDWARE = "hardware"
    OTHER_ASSET = "other_asset"
    AI_MODEL = "ai_model"
    API = "api"
    AWS_ACCOUNT = "aws_account"
    AZURE_ACCOUNT = "azure_account"


class Requirement(str, Enum):
    NONE = "none"
    ARTIFACT = "authorized_artifact"
    CREDENTIALS = "authorized_credentials"
    API_SPEC = "api_specification"
    ENDPOINT = "authorized_endpoint"
    FIRMWARE = "authorized_firmware"


@dataclass(frozen=True)
class ScannerMethod:
    tool: str
    method: str
    command_template: tuple[str, ...] = ()
    requirement: Requirement = Requirement.NONE
    requires_network: bool = False
    local_only: bool = False
    state_change_possible: bool = False
    output: str = "json"
    purpose: str = ""


@dataclass(frozen=True)
class AssetScanPlan:
    asset_kind: AssetKind
    ready: tuple[ScannerMethod, ...]
    blocked: tuple[ScannerMethod, ...]


SUBFINDER = ScannerMethod(
    "subfinder",
    "passive-subdomain-enumeration",
    ("subfinder", "-d", "{target}", "-silent", "-json"),
    requires_network=True,
    purpose="passive subdomain discovery",
)
DNSX = ScannerMethod(
    "dnsx",
    "dns-resolution-and-wildcard-filtering",
    ("dnsx", "-l", "{target_list}", "-json", "-auto-wildcard"),
    requires_network=True,
    purpose="DNS record resolution, normalization and wildcard filtering",
)
HTTPX = ScannerMethod(
    "httpx",
    "http-service-enrichment",
    ("httpx", "-u", "{target}", "-json", "-silent"),
    requires_network=True,
    purpose="HTTP/TLS/service metadata and reachability",
)
KATANA = ScannerMethod(
    "katana",
    "scoped-endpoint-crawl",
    ("katana", "-u", "{target}", "-jsonl", "-d", "3", "-mdp", "100"),
    requires_network=True,
    purpose="scope-controlled web/API endpoint and JavaScript discovery",
)
NAABU = ScannerMethod(
    "naabu",
    "bounded-port-discovery",
    ("naabu", "-host", "{target}", "-json", "-top-ports", "100"),
    requires_network=True,
    purpose="bounded TCP/UDP service discovery",
)
NUCLEI = ScannerMethod(
    "nuclei",
    "signed-safe-template-validation",
    (
        "nuclei",
        "-u",
        "{target}",
        "-jsonl",
        "-severity",
        "info,low,medium,high,critical",
    ),
    requires_network=True,
    state_change_possible=True,
    purpose="template-based vulnerability validation under program policy",
)
MOBSF = ScannerMethod(
    "MobSF",
    "rest-static-analysis",
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="APK/IPA/APPX static mobile analysis through MobSF REST API",
)
JADX = ScannerMethod(
    "jadx",
    "android-decompile",
    ("jadx", "-d", "{output_dir}", "{artifact}"),
    requirement=Requirement.ARTIFACT,
    local_only=True,
    output="directory",
    purpose="Android bytecode/resource decompilation for source-assisted analysis",
)
SEMGREP = ScannerMethod(
    "semgrep",
    "source-static-analysis",
    ("semgrep", "scan", "--json", "{target}"),
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="source pattern and taint analysis",
)
CODEQL = ScannerMethod(
    "CodeQL",
    "cross-file-dataflow",
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="cross-file path and variant analysis",
)
GITLEAKS = ScannerMethod(
    "gitleaks",
    "git-secret-detection",
    (
        "gitleaks",
        "git",
        "--report-format",
        "json",
        "--report-path",
        "{output}",
        "{target}",
    ),
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="repository history secret discovery with redacted evidence",
)
TRIVY_FS = ScannerMethod(
    "trivy",
    "filesystem-security-scan",
    (
        "trivy",
        "fs",
        "--scanners",
        "vuln,secret,misconfig",
        "--format",
        "json",
        "{target}",
    ),
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="dependencies, CVEs, secrets, IaC and misconfiguration analysis",
)
SCORECARD = ScannerMethod(
    "OpenSSF Scorecard",
    "repository-supply-chain-posture",
    ("scorecard", "--repo", "{target}", "--format", "json"),
    requires_network=True,
    purpose="repository supply-chain and CI posture",
)
CAPA = ScannerMethod(
    "capa",
    "binary-capability-analysis",
    ("capa", "-j", "{artifact}"),
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="PE/ELF/.NET executable capability analysis",
)
SYFT = ScannerMethod(
    "syft",
    "artifact-sbom",
    ("syft", "{artifact}", "-o", "json"),
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="SBOM/package inventory for binaries, firmware and filesystems",
)
GRYPE = ScannerMethod(
    "grype",
    "artifact-vulnerability-scan",
    ("grype", "{artifact}", "-o", "json"),
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="known-vulnerability matching against artifact packages/SBOM",
)
SLITHER = ScannerMethod(
    "slither",
    "solidity-vyper-static-analysis",
    ("slither", "{target}", "--json", "-"),
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="Solidity/Vyper vulnerability and contract-structure analysis",
)
BINWALK = ScannerMethod(
    "binwalk",
    "firmware-structure-analysis",
    ("binwalk", "{artifact}"),
    requirement=Requirement.FIRMWARE,
    local_only=True,
    output="text",
    purpose="firmware embedded-file, compression and entropy analysis",
)
MODELSCAN = ScannerMethod(
    "ModelScan",
    "serialized-model-safety-scan",
    ("modelscan", "-p", "{artifact}", "-r", "json", "-o", "{output}"),
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="unsafe model-serialization code detection",
)
GARAK = ScannerMethod(
    "garak",
    "llm-security-probing",
    requirement=Requirement.ENDPOINT,
    requires_network=True,
    state_change_possible=True,
    purpose="authorized LLM prompt-injection, leakage and robustness assessment",
)
PROMPTFOO = ScannerMethod(
    "promptfoo",
    "ai-red-team-evaluation",
    requirement=Requirement.ENDPOINT,
    requires_network=True,
    state_change_possible=True,
    purpose="declarative AI/agent red-team evaluation and regression testing",
)
PROWLER_AWS = ScannerMethod(
    "Prowler",
    "aws-security-posture",
    ("prowler", "aws"),
    requirement=Requirement.CREDENTIALS,
    requires_network=True,
    purpose="authorized AWS configuration, IAM and service security checks",
)
PROWLER_AZURE = ScannerMethod(
    "Prowler",
    "azure-security-posture",
    ("prowler", "azure"),
    requirement=Requirement.CREDENTIALS,
    requires_network=True,
    purpose="authorized Azure configuration, identity and service security checks",
)
RESTLER = ScannerMethod(
    "RESTler",
    "stateful-openapi-sequence-testing",
    requirement=Requirement.API_SPEC,
    local_only=True,
    state_change_possible=True,
    purpose="bounded producer/consumer API sequence testing against disposable or approved targets",
)


_STORE_METADATA = ScannerMethod(
    "aegis-store-metadata",
    "public-listing-metadata",
    requires_network=True,
    output="metadata",
    purpose="collect public store metadata only; no binary acquisition bypass",
)
_GENERIC_CLASSIFIER = ScannerMethod(
    "aegis-asset-classifier",
    "deterministic-asset-classification",
    local_only=True,
    output="metadata",
    purpose="classify a generic asset before selecting a concrete scanner lane",
)


_BASE: dict[AssetKind, tuple[ScannerMethod, ...]] = {
    AssetKind.CIDR: (NAABU, HTTPX, NUCLEI),
    AssetKind.DOMAIN: (SUBFINDER, DNSX, HTTPX, KATANA, NUCLEI),
    AssetKind.WILDCARD: (SUBFINDER, DNSX, HTTPX, KATANA, NUCLEI),
    AssetKind.IP_ADDRESS: (NAABU, HTTPX, NUCLEI),
    AssetKind.IOS_APP_STORE: (_STORE_METADATA, MOBSF),
    AssetKind.IOS_TESTFLIGHT: (_STORE_METADATA, MOBSF),
    AssetKind.IOS_IPA: (MOBSF,),
    AssetKind.ANDROID_PLAY_STORE: (_STORE_METADATA, MOBSF, JADX),
    AssetKind.ANDROID_APK: (MOBSF, JADX),
    AssetKind.WINDOWS_MICROSOFT_STORE: (_STORE_METADATA, MOBSF, CAPA, SYFT, GRYPE),
    AssetKind.SOURCE_CODE: (SEMGREP, CODEQL, GITLEAKS, TRIVY_FS, SCORECARD),
    AssetKind.EXECUTABLE: (CAPA, SYFT, GRYPE),
    AssetKind.SMART_CONTRACT: (SLITHER,),
    AssetKind.HARDWARE: (BINWALK, SYFT, GRYPE, TRIVY_FS),
    AssetKind.AI_MODEL: (MODELSCAN, GARAK, PROMPTFOO),
    AssetKind.API: (HTTPX, KATANA, NUCLEI, RESTLER),
    AssetKind.AWS_ACCOUNT: (PROWLER_AWS,),
    AssetKind.AZURE_ACCOUNT: (PROWLER_AZURE,),
    AssetKind.OTHER_ASSET: (_GENERIC_CLASSIFIER,),
}


def plan_asset_scan(
    asset_kind: AssetKind,
    *,
    artifact_available: bool = False,
    credentials_available: bool = False,
    api_spec_available: bool = False,
    endpoint_available: bool = False,
    firmware_available: bool = False,
) -> AssetScanPlan:
    """Return ready and blocked real-tool methods for one asset type."""
    availability = {
        Requirement.NONE: True,
        Requirement.ARTIFACT: artifact_available or firmware_available,
        Requirement.CREDENTIALS: credentials_available,
        Requirement.API_SPEC: api_spec_available,
        Requirement.ENDPOINT: endpoint_available,
        Requirement.FIRMWARE: firmware_available,
    }
    methods = _BASE[asset_kind]
    ready = tuple(method for method in methods if availability[method.requirement])
    blocked = tuple(method for method in methods if not availability[method.requirement])
    return AssetScanPlan(asset_kind=asset_kind, ready=ready, blocked=blocked)


def supported_asset_kinds() -> tuple[AssetKind, ...]:
    return tuple(AssetKind)
