"""Deep real-tool asset capability registry for Jarvis.

This layer extends the stable base registry without weakening its prerequisite
or authorization model.  It adds specialist tools, multi-prerequisite runtime
methods, and additional bounty asset classes.  It plans work only; execution is
still controlled by the central Aegis policy/authorization layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TypeAlias

from .asset_capabilities import (
    AssetKind,
    AssetScanPlan,
    Requirement,
    ScannerMethod,
    plan_asset_scan,
)


class ExtendedAssetKind(str, Enum):
    KUBERNETES_CLUSTER = "kubernetes_cluster"
    CONTAINER_IMAGE = "container_image"
    BROWSER_EXTENSION = "browser_extension"
    ELECTRON_APP = "electron_app"
    GITHUB_ORG = "github_org"
    GITLAB_GROUP = "gitlab_group"
    SAAS_TENANT = "saas_tenant"
    GRAPHQL_ENDPOINT = "graphql_endpoint"
    WEBSOCKET_SERVICE = "websocket_service"
    GRPC_API = "grpc_api"
    PACKAGE_REGISTRY = "package_registry"
    CICD_PIPELINE = "cicd_pipeline"
    DOCKER_REGISTRY = "docker_registry"
    NPM_PACKAGE = "npm_package"
    PYPI_PACKAGE = "pypi_package"
    TERRAFORM_REPO = "terraform_repo"
    LLM_RAG_APP = "llm_rag_app"


TargetAssetKind: TypeAlias = AssetKind | ExtendedAssetKind


@dataclass(frozen=True)
class DeepScannerMethod:
    tool: str
    method: str
    command_template: tuple[str, ...] = ()
    requirement: Requirement = Requirement.NONE
    additional_requirements: tuple[Requirement, ...] = ()
    requires_network: bool = False
    local_only: bool = False
    state_change_possible: bool = False
    output: str = "json"
    purpose: str = ""

    @property
    def requirements(self) -> tuple[Requirement, ...]:
        return tuple(dict.fromkeys((self.requirement, *self.additional_requirements)))


PlannedMethod: TypeAlias = ScannerMethod | DeepScannerMethod


@dataclass(frozen=True)
class DeepAssetScanPlan:
    asset_kind: TargetAssetKind
    ready: tuple[PlannedMethod, ...]
    blocked: tuple[PlannedMethod, ...]


# Network depth.
NMAP = DeepScannerMethod(
    "nmap",
    "bounded-service-fingerprinting",
    (
        "nmap",
        "-sV",
        "--version-light",
        "-T3",
        "--top-ports",
        "100",
        "-oX",
        "{output}",
        "{target}",
    ),
    requires_network=True,
    purpose="bounded service/version fingerprinting and protocol metadata",
)
RUSTSCAN = DeepScannerMethod(
    "RustScan",
    "bounded-fast-port-prefilter",
    requires_network=True,
    purpose="authorized fast port prefilter before slower service analysis",
)
TESTSSL = DeepScannerMethod(
    "testssl.sh",
    "tls-configuration-analysis",
    requirement=Requirement.ENDPOINT,
    requires_network=True,
    purpose="TLS protocol, cipher, certificate, and HTTP security configuration review",
)
SSH_AUDIT = DeepScannerMethod(
    "ssh-audit",
    "ssh-configuration-analysis",
    requirement=Requirement.ENDPOINT,
    requires_network=True,
    purpose="SSH algorithm, host-key, and protocol configuration analysis",
)

# Mobile depth.
STORE_DIFF = DeepScannerMethod(
    "aegis-artifact-diff",
    "authorized-mobile-release-diff",
    requirement=Requirement.ARTIFACT,
    local_only=True,
    output="metadata",
    purpose="compare authorized builds, manifests, entitlements, URLs, and dependencies",
)
APKTOOL = DeepScannerMethod(
    "apktool",
    "android-resource-and-manifest-decode",
    ("apktool", "d", "-f", "-o", "{output_dir}", "{artifact}"),
    requirement=Requirement.ARTIFACT,
    local_only=True,
    output="directory",
    purpose="decode Android resources, manifest, and smali",
)
FRIDA_ANDROID = DeepScannerMethod(
    "Frida",
    "android-runtime-instrumentation",
    requirement=Requirement.ARTIFACT,
    additional_requirements=(Requirement.ENDPOINT,),
    local_only=True,
    state_change_possible=True,
    purpose="instrument an authorized Android app on a dedicated test runtime",
)
OBJECTION_ANDROID = DeepScannerMethod(
    "objection",
    "android-runtime-exploration",
    requirement=Requirement.ARTIFACT,
    additional_requirements=(Requirement.ENDPOINT,),
    local_only=True,
    state_change_possible=True,
    purpose="Frida-backed Android runtime exploration on an authorized test runtime",
)
FRIDA_IOS = DeepScannerMethod(
    "Frida",
    "ios-runtime-instrumentation",
    requirement=Requirement.ARTIFACT,
    additional_requirements=(Requirement.ENDPOINT,),
    local_only=True,
    state_change_possible=True,
    purpose="instrument an authorized iOS app on a dedicated test runtime",
)
OBJECTION_IOS = DeepScannerMethod(
    "objection",
    "ios-runtime-exploration",
    requirement=Requirement.ARTIFACT,
    additional_requirements=(Requirement.ENDPOINT,),
    local_only=True,
    state_change_possible=True,
    purpose="Frida-backed iOS runtime exploration on an authorized test runtime",
)
OTOOL = DeepScannerMethod(
    "otool",
    "ios-macos-load-command-analysis",
    ("otool", "-L", "{artifact}"),
    requirement=Requirement.ARTIFACT,
    local_only=True,
    output="text",
    purpose="Mach-O linked-library and load-command review",
)
CLASS_DUMP = DeepScannerMethod(
    "class-dump",
    "objective-c-interface-recovery",
    requirement=Requirement.ARTIFACT,
    local_only=True,
    output="text",
    purpose="optional Objective-C interface recovery when the artifact is compatible",
)

# Source-language specialists.
BANDIT = DeepScannerMethod(
    "Bandit",
    "python-security-static-analysis",
    ("bandit", "-r", "{target}", "-f", "json"),
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="Python-specific security static analysis",
)
GOSEC = DeepScannerMethod(
    "gosec",
    "go-security-static-analysis",
    ("gosec", "-fmt", "json", "-out", "{output}", "./..."),
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="Go-specific static and taint security analysis",
)
BRAKEMAN = DeepScannerMethod(
    "Brakeman",
    "rails-security-static-analysis",
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="Ruby on Rails security static analysis",
)
SPOTBUGS = DeepScannerMethod(
    "SpotBugs",
    "java-bytecode-static-analysis",
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="Java bytecode static analysis with security detectors when configured",
)
CHECKOV = DeepScannerMethod(
    "Checkov",
    "iac-cicd-and-container-policy-scan",
    ("checkov", "--directory", "{target}", "-o", "json"),
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="graph-aware IaC, CI/CD, Kubernetes, OpenAPI, and container policy analysis",
)
KICS = DeepScannerMethod(
    "KICS",
    "iac-security-scan",
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="IaC security and compliance analysis with built-in OPA queries",
)
ZIZMOR = DeepScannerMethod(
    "zizmor",
    "github-actions-security-audit",
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="GitHub Actions workflow security analysis",
)

# Binary depth.
GHIDRA = DeepScannerMethod(
    "Ghidra",
    "headless-binary-analysis",
    requirement=Requirement.ARTIFACT,
    additional_requirements=(Requirement.ENDPOINT,),
    local_only=True,
    output="directory",
    purpose="isolated disassembly, decompilation, call-graph, and scriptable binary analysis",
)
FLOSS = DeepScannerMethod(
    "FLOSS",
    "static-string-deobfuscation",
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="extract static, stack, tight, and obfuscated strings from binaries",
)
YARA = DeepScannerMethod(
    "YARA",
    "approved-rule-binary-scan",
    requirement=Requirement.ARTIFACT,
    local_only=True,
    output="text",
    purpose="scan artifacts with pinned and reviewed YARA rule packs",
)
PEFILE = DeepScannerMethod(
    "pefile",
    "pe-structure-analysis",
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="Windows PE headers, sections, imports, resources, and security metadata",
)
ANGR = DeepScannerMethod(
    "angr",
    "binary-control-flow-analysis",
    requirement=Requirement.ARTIFACT,
    additional_requirements=(Requirement.ENDPOINT,),
    local_only=True,
    purpose="isolated symbolic and control-flow analysis of native binaries",
)
RIZIN = DeepScannerMethod(
    "Rizin",
    "binary-reverse-engineering",
    requirement=Requirement.ARTIFACT,
    additional_requirements=(Requirement.ENDPOINT,),
    local_only=True,
    purpose="isolated disassembly, analysis, and scripting for native binaries",
)

# Smart-contract depth.
ECHIDNA = DeepScannerMethod(
    "Echidna",
    "smart-contract-property-fuzzing",
    requirement=Requirement.ARTIFACT,
    additional_requirements=(Requirement.ENDPOINT,),
    local_only=True,
    state_change_possible=True,
    purpose="property-based fuzzing against a local smart-contract test harness",
)
FOUNDRY = DeepScannerMethod(
    "Foundry",
    "smart-contract-fuzz-and-invariant-tests",
    requirement=Requirement.ARTIFACT,
    additional_requirements=(Requirement.ENDPOINT,),
    local_only=True,
    state_change_possible=True,
    purpose="local Forge fuzzing and invariant/property test execution",
)
MYTHRIL = DeepScannerMethod(
    "Mythril",
    "evm-symbolic-execution",
    ("myth", "analyze", "{target}", "-o", "json"),
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="symbolic execution for EVM smart-contract security analysis",
)

# Firmware/hardware depth.
ARCH_DETECT = DeepScannerMethod(
    "aegis-firmware-arch",
    "firmware-architecture-detection",
    requirement=Requirement.FIRMWARE,
    local_only=True,
    output="metadata",
    purpose="identify architecture, endianness, filesystem, init system, and likely services",
)
FIRMAE = DeepScannerMethod(
    "FirmAE",
    "firmware-emulation",
    requirement=Requirement.FIRMWARE,
    additional_requirements=(Requirement.ENDPOINT,),
    local_only=True,
    state_change_possible=True,
    purpose="isolated IoT firmware emulation for dynamic analysis",
)
FIRMADYNE = DeepScannerMethod(
    "Firmadyne",
    "firmware-emulation-fallback",
    requirement=Requirement.FIRMWARE,
    additional_requirements=(Requirement.ENDPOINT,),
    local_only=True,
    state_change_possible=True,
    purpose="isolated firmware emulation fallback for supported Linux-based images",
)

# API and authenticated traffic depth.
SCHEMATHESIS = DeepScannerMethod(
    "Schemathesis",
    "schema-guided-api-testing",
    requirement=Requirement.API_SPEC,
    additional_requirements=(Requirement.ENDPOINT,),
    requires_network=True,
    state_change_possible=True,
    purpose="OpenAPI schema-guided property and stateful workflow testing",
)
SCHEMATHESIS_GRAPHQL = DeepScannerMethod(
    "Schemathesis",
    "graphql-schema-guided-testing",
    requirement=Requirement.ENDPOINT,
    requires_network=True,
    state_change_possible=True,
    purpose="GraphQL schema-driven input generation and contract testing",
)
PLAYWRIGHT_TRAFFIC = DeepScannerMethod(
    "Playwright",
    "authenticated-browser-traffic-learning",
    requirement=Requirement.ENDPOINT,
    additional_requirements=(Requirement.CREDENTIALS,),
    requires_network=True,
    state_change_possible=True,
    purpose="authorized browser-session discovery, HAR/trace capture, and workflow modeling",
)
MITMPROXY_TRAFFIC = DeepScannerMethod(
    "mitmproxy",
    "authorized-http-traffic-capture",
    requirement=Requirement.ENDPOINT,
    additional_requirements=(Requirement.CREDENTIALS,),
    requires_network=True,
    state_change_possible=True,
    purpose="authorized request/response capture and normalization",
)
WEBSOCAT = DeepScannerMethod(
    "websocat",
    "websocket-protocol-observation",
    requirement=Requirement.ENDPOINT,
    requires_network=True,
    purpose="authorized WebSocket handshake and protocol observation",
)
GRPCURL = DeepScannerMethod(
    "grpcurl",
    "grpc-service-introspection",
    requirement=Requirement.ENDPOINT,
    requires_network=True,
    purpose="authorized gRPC reflection, service, and schema inspection",
)

# Cloud depth.
SCOUTSUITE_AWS = DeepScannerMethod(
    "ScoutSuite",
    "aws-attack-surface-audit",
    requirement=Requirement.CREDENTIALS,
    requires_network=True,
    purpose="authorized AWS configuration collection and offline attack-surface review",
)
SCOUTSUITE_AZURE = DeepScannerMethod(
    "ScoutSuite",
    "azure-attack-surface-audit",
    requirement=Requirement.CREDENTIALS,
    requires_network=True,
    purpose="authorized Azure configuration collection and offline attack-surface review",
)
CLOUDSPLAINING = DeepScannerMethod(
    "Cloudsplaining",
    "aws-iam-risk-analysis",
    requirement=Requirement.CREDENTIALS,
    requires_network=True,
    purpose="authorized AWS IAM privilege and policy risk analysis",
)
ROADTOOLS = DeepScannerMethod(
    "ROADtools",
    "entra-identity-analysis",
    requirement=Requirement.CREDENTIALS,
    requires_network=True,
    purpose="authorized Microsoft Entra ID collection and relationship analysis",
)
AZUREHOUND = DeepScannerMethod(
    "AzureHound",
    "azure-entra-relationship-collection",
    requirement=Requirement.CREDENTIALS,
    requires_network=True,
    purpose="authorized Azure/Entra relationship collection for permission-graph analysis",
)

# Kubernetes, container, registry, and IaC depth.
KUBESCAPE = DeepScannerMethod(
    "Kubescape",
    "kubernetes-posture-and-runtime-scan",
    requirement=Requirement.CREDENTIALS,
    requires_network=True,
    purpose="authorized Kubernetes posture, compliance, and runtime-risk assessment",
)
TRIVY_IMAGE = DeepScannerMethod(
    "trivy",
    "container-image-security-scan",
    ("trivy", "image", "--format", "json", "{target}"),
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="container-image vulnerabilities, secrets, and configuration context",
)
SYFT_IMAGE = DeepScannerMethod(
    "syft",
    "container-image-sbom",
    ("syft", "{target}", "-o", "json"),
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="container-image SBOM generation",
)
GRYPE_IMAGE = DeepScannerMethod(
    "grype",
    "container-image-vulnerability-scan",
    ("grype", "{target}", "-o", "json"),
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="container-image known-vulnerability analysis",
)
CHECKOV_IMAGE = DeepScannerMethod(
    "Checkov",
    "container-image-policy-scan",
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="container-image and Dockerfile policy/security analysis",
)
SKOPEO = DeepScannerMethod(
    "skopeo",
    "container-registry-metadata",
    requirement=Requirement.CREDENTIALS,
    requires_network=True,
    purpose="authorized registry image manifest inspection without execution",
)

# AI depth.
MODEL_PROVENANCE = DeepScannerMethod(
    "aegis-model-provenance",
    "model-provenance-and-hash-ledger",
    requirement=Requirement.ARTIFACT,
    local_only=True,
    output="metadata",
    purpose="hash model artifacts and capture framework, provenance, SBOM, and dependency context",
)
PYRIT = DeepScannerMethod(
    "PyRIT",
    "generative-ai-risk-identification",
    requirement=Requirement.ENDPOINT,
    requires_network=True,
    state_change_possible=True,
    purpose="authorized multi-turn generative-AI risk scenarios with persistent evidence",
)
AGENT_PERMISSION_AUDIT = DeepScannerMethod(
    "aegis-agent-permission-audit",
    "agent-tool-permission-analysis",
    requirement=Requirement.ENDPOINT,
    local_only=True,
    purpose="map agent tools, scopes, approvals, and confused-deputy trust boundaries",
)
MEMORY_POISONING_PLAN = DeepScannerMethod(
    "aegis-memory-poisoning",
    "agent-memory-poisoning-regression",
    requirement=Requirement.ENDPOINT,
    additional_requirements=(Requirement.CREDENTIALS,),
    local_only=True,
    state_change_possible=True,
    purpose="sandboxed regression tests for persistent-memory trust boundaries",
)
RAG_BOUNDARY_AUDIT = DeepScannerMethod(
    "aegis-rag-boundary",
    "rag-retrieval-trust-analysis",
    requirement=Requirement.ENDPOINT,
    local_only=True,
    purpose="analyze retrieval provenance, tenant separation, and instruction/data boundaries",
)

# New asset-class methods.
WEB_EXT_LINT = DeepScannerMethod(
    "web-ext",
    "browser-extension-structure-lint",
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="browser-extension manifest and packaging validation",
)
ASAR_EXTRACT = DeepScannerMethod(
    "@electron/asar",
    "electron-package-extraction",
    requirement=Requirement.ARTIFACT,
    local_only=True,
    output="directory",
    purpose="extract Electron ASAR packages for source and dependency analysis",
)
GITHUB_ORG_INVENTORY = DeepScannerMethod(
    "aegis-github-org",
    "github-org-public-inventory",
    requires_network=True,
    output="metadata",
    purpose="inventory public repos, languages, releases, Actions, and security-relevant changes",
)
GITHUB_ORG_AUTH = DeepScannerMethod(
    "aegis-github-org",
    "github-org-authorized-inventory",
    requirement=Requirement.CREDENTIALS,
    requires_network=True,
    output="metadata",
    purpose="authorized organization permission, repository, and workflow inventory",
)
GITLAB_GROUP_INVENTORY = DeepScannerMethod(
    "aegis-gitlab-group",
    "gitlab-group-public-inventory",
    requires_network=True,
    output="metadata",
    purpose="inventory public projects, releases, CI, and security-relevant changes",
)
GITLAB_GROUP_AUTH = DeepScannerMethod(
    "aegis-gitlab-group",
    "gitlab-group-authorized-inventory",
    requirement=Requirement.CREDENTIALS,
    requires_network=True,
    output="metadata",
    purpose="authorized group permission, project, and CI inventory",
)
REGISTRY_METADATA = DeepScannerMethod(
    "aegis-package-registry",
    "public-package-metadata",
    requires_network=True,
    output="metadata",
    purpose="collect public package/version/provenance metadata without installing package code",
)
OSV_SCANNER = DeepScannerMethod(
    "osv-scanner",
    "dependency-vulnerability-analysis",
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="lockfile, SBOM, and package vulnerability analysis using OSV data",
)
PIP_AUDIT = DeepScannerMethod(
    "pip-audit",
    "python-dependency-vulnerability-analysis",
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="Python dependency vulnerability analysis from supplied requirements artifacts",
)
NPM_AUDIT = DeepScannerMethod(
    "npm",
    "npm-dependency-audit",
    requirement=Requirement.ARTIFACT,
    local_only=True,
    purpose="npm lockfile dependency audit without arbitrary package-script execution",
)


_EXTRA_EXISTING: dict[AssetKind, tuple[DeepScannerMethod, ...]] = {
    AssetKind.CIDR: (NMAP,),
    AssetKind.DOMAIN: (NMAP,),
    AssetKind.WILDCARD: (NMAP,),
    AssetKind.IP_ADDRESS: (NMAP,),
    AssetKind.IOS_APP_STORE: (STORE_DIFF, OTOOL, CLASS_DUMP, FRIDA_IOS, OBJECTION_IOS),
    AssetKind.IOS_TESTFLIGHT: (STORE_DIFF, OTOOL, CLASS_DUMP, FRIDA_IOS, OBJECTION_IOS),
    AssetKind.IOS_IPA: (OTOOL, CLASS_DUMP, FRIDA_IOS, OBJECTION_IOS),
    AssetKind.ANDROID_PLAY_STORE: (STORE_DIFF, APKTOOL, FRIDA_ANDROID, OBJECTION_ANDROID),
    AssetKind.ANDROID_APK: (APKTOOL, FRIDA_ANDROID, OBJECTION_ANDROID),
    AssetKind.WINDOWS_MICROSOFT_STORE: (STORE_DIFF, GHIDRA, FLOSS, YARA, PEFILE),
    AssetKind.SOURCE_CODE: (CHECKOV, KICS, ZIZMOR),
    AssetKind.EXECUTABLE: (GHIDRA, FLOSS, YARA, ANGR, RIZIN),
    AssetKind.SMART_CONTRACT: (ECHIDNA, FOUNDRY, MYTHRIL),
    AssetKind.HARDWARE: (ARCH_DETECT, GHIDRA, FIRMAE, FIRMADYNE),
    AssetKind.AI_MODEL: (
        MODEL_PROVENANCE,
        PYRIT,
        AGENT_PERMISSION_AUDIT,
        MEMORY_POISONING_PLAN,
        RAG_BOUNDARY_AUDIT,
    ),
    AssetKind.API: (SCHEMATHESIS, PLAYWRIGHT_TRAFFIC, MITMPROXY_TRAFFIC),
    AssetKind.AWS_ACCOUNT: (SCOUTSUITE_AWS, CLOUDSPLAINING),
    AssetKind.AZURE_ACCOUNT: (SCOUTSUITE_AZURE, ROADTOOLS, AZUREHOUND),
}


_EXTENDED: dict[ExtendedAssetKind, tuple[PlannedMethod, ...]] = {
    ExtendedAssetKind.KUBERNETES_CLUSTER: (KUBESCAPE, CHECKOV, KICS),
    ExtendedAssetKind.CONTAINER_IMAGE: (TRIVY_IMAGE, SYFT_IMAGE, GRYPE_IMAGE, CHECKOV_IMAGE),
    ExtendedAssetKind.BROWSER_EXTENSION: (WEB_EXT_LINT, CHECKOV, KICS),
    ExtendedAssetKind.ELECTRON_APP: (ASAR_EXTRACT, GHIDRA, FLOSS, YARA),
    ExtendedAssetKind.GITHUB_ORG: (GITHUB_ORG_INVENTORY, GITHUB_ORG_AUTH, ZIZMOR),
    ExtendedAssetKind.GITLAB_GROUP: (GITLAB_GROUP_INVENTORY, GITLAB_GROUP_AUTH),
    ExtendedAssetKind.SAAS_TENANT: (PLAYWRIGHT_TRAFFIC, MITMPROXY_TRAFFIC, SCHEMATHESIS),
    ExtendedAssetKind.GRAPHQL_ENDPOINT: (
        SCHEMATHESIS_GRAPHQL,
        PLAYWRIGHT_TRAFFIC,
        MITMPROXY_TRAFFIC,
    ),
    ExtendedAssetKind.WEBSOCKET_SERVICE: (WEBSOCAT, PLAYWRIGHT_TRAFFIC, MITMPROXY_TRAFFIC),
    ExtendedAssetKind.GRPC_API: (GRPCURL,),
    ExtendedAssetKind.PACKAGE_REGISTRY: (REGISTRY_METADATA, OSV_SCANNER),
    ExtendedAssetKind.CICD_PIPELINE: (CHECKOV, KICS, ZIZMOR),
    ExtendedAssetKind.DOCKER_REGISTRY: (SKOPEO,),
    ExtendedAssetKind.NPM_PACKAGE: (REGISTRY_METADATA, NPM_AUDIT, OSV_SCANNER),
    ExtendedAssetKind.PYPI_PACKAGE: (REGISTRY_METADATA, PIP_AUDIT, OSV_SCANNER),
    ExtendedAssetKind.TERRAFORM_REPO: (CHECKOV, KICS),
    ExtendedAssetKind.LLM_RAG_APP: (
        PYRIT,
        AGENT_PERMISSION_AUDIT,
        MEMORY_POISONING_PLAN,
        RAG_BOUNDARY_AUDIT,
        PLAYWRIGHT_TRAFFIC,
    ),
}


def _requirements(method: PlannedMethod) -> tuple[Requirement, ...]:
    if isinstance(method, DeepScannerMethod):
        return method.requirements
    return (method.requirement,)


def _conditional_existing(
    asset_kind: AssetKind,
    *,
    language_hints: tuple[str, ...],
    platform_hint: str,
    service_hints: tuple[str, ...],
) -> tuple[DeepScannerMethod, ...]:
    values: list[DeepScannerMethod] = []
    languages = {value.strip().lower() for value in language_hints if value.strip()}
    services = {value.strip().lower() for value in service_hints if value.strip()}
    platform = platform_hint.strip().lower()

    if asset_kind == AssetKind.SOURCE_CODE:
        if languages & {"python", "py"}:
            values.append(BANDIT)
        if languages & {"go", "golang"}:
            values.append(GOSEC)
        if languages & {"ruby", "rails"}:
            values.append(BRAKEMAN)
        if languages & {"java", "kotlin", "jvm"}:
            values.append(SPOTBUGS)

    if asset_kind == AssetKind.EXECUTABLE and platform in {"windows", "pe", "win32", "win64"}:
        values.append(PEFILE)

    if asset_kind in {AssetKind.CIDR, AssetKind.DOMAIN, AssetKind.WILDCARD, AssetKind.IP_ADDRESS}:
        if services:
            values.append(RUSTSCAN)
        if services & {"tls", "https", "ssl"}:
            values.append(TESTSSL)
        if "ssh" in services:
            values.append(SSH_AUDIT)

    return tuple(values)


def _availability(
    *,
    artifact_available: bool,
    credentials_available: bool,
    api_spec_available: bool,
    endpoint_available: bool,
    firmware_available: bool,
) -> dict[Requirement, bool]:
    return {
        Requirement.NONE: True,
        Requirement.ARTIFACT: artifact_available or firmware_available,
        Requirement.CREDENTIALS: credentials_available,
        Requirement.API_SPEC: api_spec_available,
        Requirement.ENDPOINT: endpoint_available,
        Requirement.FIRMWARE: firmware_available,
    }


def plan_deep_asset_scan(
    asset_kind: TargetAssetKind,
    *,
    artifact_available: bool = False,
    credentials_available: bool = False,
    api_spec_available: bool = False,
    endpoint_available: bool = False,
    firmware_available: bool = False,
    language_hints: tuple[str, ...] = (),
    platform_hint: str = "",
    service_hints: tuple[str, ...] = (),
) -> DeepAssetScanPlan:
    """Plan base plus deep real-tool methods for one asset kind."""
    availability = _availability(
        artifact_available=artifact_available,
        credentials_available=credentials_available,
        api_spec_available=api_spec_available,
        endpoint_available=endpoint_available,
        firmware_available=firmware_available,
    )

    methods: list[PlannedMethod]
    if isinstance(asset_kind, AssetKind):
        base: AssetScanPlan = plan_asset_scan(
            asset_kind,
            artifact_available=artifact_available,
            credentials_available=credentials_available,
            api_spec_available=api_spec_available,
            endpoint_available=endpoint_available,
            firmware_available=firmware_available,
        )
        methods = [*base.ready, *base.blocked, *_EXTRA_EXISTING.get(asset_kind, ())]
        methods.extend(
            _conditional_existing(
                asset_kind,
                language_hints=language_hints,
                platform_hint=platform_hint,
                service_hints=service_hints,
            )
        )
    else:
        methods = list(_EXTENDED[asset_kind])

    deduped: list[PlannedMethod] = []
    seen: set[tuple[str, str]] = set()
    for method in methods:
        key = (method.tool, method.method)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(method)

    def is_ready(method: PlannedMethod) -> bool:
        return all(availability.get(requirement, False) for requirement in _requirements(method))

    return DeepAssetScanPlan(
        asset_kind=asset_kind,
        ready=tuple(method for method in deduped if is_ready(method)),
        blocked=tuple(method for method in deduped if not is_ready(method)),
    )


def method_requirements(method: PlannedMethod) -> tuple[Requirement, ...]:
    return _requirements(method)


def supported_deep_asset_kinds() -> tuple[TargetAssetKind, ...]:
    return (*tuple(AssetKind), *tuple(ExtendedAssetKind))
