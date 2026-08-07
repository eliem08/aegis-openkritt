"""Specialist Jarvis agents for heterogeneous asset deep dives.

These agents reason about evidence and sequencing.  They do not execute tools;
concrete scanner execution remains the responsibility of AssetCapabilityAgent
and the central authorization policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from ..agentic_os import AgentContext, AgentProposal, AgentRole, RiskClass, SecurityAgent
from .asset_capabilities import AssetKind
from .asset_deep_capabilities import ExtendedAssetKind, TargetAssetKind


@dataclass(frozen=True)
class DeepDiveProfile:
    name: str
    role: AgentRole
    kinds: tuple[TargetAssetKind, ...]
    action: str
    focus: tuple[str, ...]
    preferred_tools: tuple[str, ...]
    evidence: tuple[str, ...]
    information_gain: float = 0.82


class AssetDeepDiveAgent:
    profile: DeepDiveProfile

    @staticmethod
    def _kind(context: AgentContext) -> TargetAssetKind | None:
        item = context.memory.get("asset:kind")
        if item is None:
            return None
        value = item.value
        if isinstance(value, (AssetKind, ExtendedAssetKind)):
            return value
        text = str(value)
        try:
            return AssetKind(text)
        except ValueError:
            try:
                return ExtendedAssetKind(text)
            except ValueError:
                return None

    def propose(self, context: AgentContext) -> Iterable[AgentProposal]:
        kind = self._kind(context)
        if kind is None or kind not in self.profile.kinds:
            return ()
        return (
            AgentProposal(
                role=self.profile.role,
                action=self.profile.action,
                rationale=(
                    f"Run the {self.profile.name} research playbook for {kind.value}; "
                    "correlate specialist-tool observations before escalating any finding."
                ),
                risk=RiskClass.OFFLINE,
                expected_information_gain=self.profile.information_gain,
                metadata={
                    "asset_kind": kind.value,
                    "focus": self.profile.focus,
                    "preferred_tools": self.profile.preferred_tools,
                    "required_evidence": self.profile.evidence,
                    "execution_authority": "central_policy_only",
                },
            ),
        )


class AndroidDeepDiveAgent(AssetDeepDiveAgent):
    profile = DeepDiveProfile(
        "Android",
        AgentRole.STATIC_ANALYSIS,
        (AssetKind.ANDROID_PLAY_STORE, AssetKind.ANDROID_APK),
        "analyze_android_asset",
        (
            "manifest/exported-component trust",
            "deep links and intent surfaces",
            "WebView and JavaScript bridges",
            "network security configuration",
            "local storage and secret handling",
            "runtime-only authorization assumptions",
        ),
        ("MobSF", "jadx", "apktool", "Frida", "objection"),
        ("static finding", "code location", "runtime observation when needed", "negative control"),
    )


class IOSDeepDiveAgent(AssetDeepDiveAgent):
    profile = DeepDiveProfile(
        "iOS",
        AgentRole.STATIC_ANALYSIS,
        (AssetKind.IOS_APP_STORE, AssetKind.IOS_TESTFLIGHT, AssetKind.IOS_IPA),
        "analyze_ios_asset",
        (
            "entitlements and URL schemes",
            "universal/deep links",
            "ATS and transport configuration",
            "keychain and local storage",
            "Objective-C/Swift trust boundaries",
            "runtime-only authorization assumptions",
        ),
        ("MobSF", "otool", "class-dump", "Frida", "objection"),
        ("entitlement evidence", "binary/code evidence", "runtime observation when needed"),
    )


class BinaryDeepDiveAgent(AssetDeepDiveAgent):
    profile = DeepDiveProfile(
        "Native Binary",
        AgentRole.STATIC_ANALYSIS,
        (AssetKind.EXECUTABLE, AssetKind.WINDOWS_MICROSOFT_STORE, ExtendedAssetKind.ELECTRON_APP),
        "analyze_native_binary_asset",
        (
            "binary hardening and unsafe loading",
            "dangerous imports and privileged operations",
            "embedded endpoints/configuration/secrets",
            "parser and file-format attack surfaces",
            "native module trust boundaries",
        ),
        ("capa", "Ghidra", "FLOSS", "YARA", "pefile", "angr", "Rizin"),
        ("binary hash", "function/import evidence", "call-path evidence", "sandboxed reproduction when needed"),
    )


class FirmwareDeepDiveAgent(AssetDeepDiveAgent):
    profile = DeepDiveProfile(
        "Firmware",
        AgentRole.STATIC_ANALYSIS,
        (AssetKind.HARDWARE,),
        "analyze_firmware_asset",
        (
            "architecture/filesystem identification",
            "embedded web interfaces and services",
            "default configuration and secret material",
            "update/signature trust",
            "unsafe parsers and privileged daemons",
        ),
        ("binwalk", "Ghidra", "FirmAE", "Firmadyne", "syft", "grype", "trivy"),
        ("firmware hash", "filesystem provenance", "service map", "isolated emulation evidence"),
        0.9,
    )


class SmartContractDeepDiveAgent(AssetDeepDiveAgent):
    profile = DeepDiveProfile(
        "Smart Contract",
        AgentRole.STATIC_ANALYSIS,
        (AssetKind.SMART_CONTRACT,),
        "analyze_smart_contract_asset",
        (
            "authorization and ownership invariants",
            "state-transition invariants",
            "external-call/reentrancy boundaries",
            "accounting and precision invariants",
            "upgradeability and initialization",
        ),
        ("Slither", "Echidna", "Foundry", "Mythril"),
        ("source/bytecode evidence", "falsified invariant", "local reproducer", "negative property test"),
        0.93,
    )


class CloudDeepDiveAgent(AssetDeepDiveAgent):
    profile = DeepDiveProfile(
        "Cloud Identity and Configuration",
        AgentRole.CLOUD,
        (AssetKind.AWS_ACCOUNT, AssetKind.AZURE_ACCOUNT, ExtendedAssetKind.KUBERNETES_CLUSTER),
        "analyze_cloud_asset",
        (
            "identity privilege paths",
            "cross-service trust",
            "public exposure",
            "credential and workload identity boundaries",
            "logging and security-control gaps",
        ),
        ("Prowler", "ScoutSuite", "Cloudsplaining", "ROADtools", "AzureHound", "Kubescape"),
        ("authorized inventory", "permission graph", "configuration evidence", "impact path"),
        0.9,
    )


class APIDeepDiveAgent(AssetDeepDiveAgent):
    profile = DeepDiveProfile(
        "API and Stateful Protocol",
        AgentRole.API,
        (
            AssetKind.API,
            ExtendedAssetKind.GRAPHQL_ENDPOINT,
            ExtendedAssetKind.WEBSOCKET_SERVICE,
            ExtendedAssetKind.GRPC_API,
            ExtendedAssetKind.SAAS_TENANT,
        ),
        "analyze_api_protocol_asset",
        (
            "authentication/authorization differentials",
            "producer-consumer state sequences",
            "schema/implementation mismatches",
            "tenant/object ownership",
            "workflow and asynchronous state",
        ),
        ("RESTler", "Schemathesis", "Katana", "Playwright", "mitmproxy", "websocat", "grpcurl"),
        ("request sequence", "identity context", "response oracle", "negative control", "state diff"),
        0.94,
    )


class ContainerK8sDeepDiveAgent(AssetDeepDiveAgent):
    profile = DeepDiveProfile(
        "Container and Kubernetes",
        AgentRole.CLOUD,
        (ExtendedAssetKind.CONTAINER_IMAGE, ExtendedAssetKind.KUBERNETES_CLUSTER, ExtendedAssetKind.DOCKER_REGISTRY),
        "analyze_container_kubernetes_asset",
        (
            "image provenance and vulnerable packages",
            "runtime privilege and capability boundaries",
            "workload identity and secrets",
            "network exposure and admission policy",
            "registry trust and mutable tags",
        ),
        ("trivy", "syft", "grype", "Checkov", "Kubescape", "skopeo"),
        ("image digest", "SBOM", "policy finding", "runtime/configuration evidence"),
    )


class SupplyChainDeepDiveAgent(AssetDeepDiveAgent):
    profile = DeepDiveProfile(
        "Software Supply Chain",
        AgentRole.DEPENDENCY,
        (
            ExtendedAssetKind.GITHUB_ORG,
            ExtendedAssetKind.GITLAB_GROUP,
            ExtendedAssetKind.PACKAGE_REGISTRY,
            ExtendedAssetKind.CICD_PIPELINE,
            ExtendedAssetKind.NPM_PACKAGE,
            ExtendedAssetKind.PYPI_PACKAGE,
            ExtendedAssetKind.TERRAFORM_REPO,
        ),
        "analyze_supply_chain_asset",
        (
            "workflow permissions and untrusted input",
            "package provenance and release integrity",
            "dependency reachability",
            "secrets and artifact exposure",
            "IaC and CI trust relationships",
        ),
        ("OpenSSF Scorecard", "zizmor", "Checkov", "KICS", "osv-scanner", "gitleaks"),
        ("repository/package provenance", "workflow evidence", "dependency evidence", "release/version identity"),
    )


class BrowserDesktopDeepDiveAgent(AssetDeepDiveAgent):
    profile = DeepDiveProfile(
        "Browser and Desktop",
        AgentRole.STATIC_ANALYSIS,
        (ExtendedAssetKind.BROWSER_EXTENSION, ExtendedAssetKind.ELECTRON_APP),
        "analyze_browser_desktop_asset",
        (
            "extension/app permissions",
            "content-script/preload trust",
            "IPC and native bridge boundaries",
            "remote content and update trust",
            "local secrets and token handling",
        ),
        ("web-ext", "@electron/asar", "Semgrep", "CodeQL", "Ghidra"),
        ("manifest/config evidence", "source/native bridge path", "permission impact"),
    )


class AIDeepDiveAgent(AssetDeepDiveAgent):
    profile = DeepDiveProfile(
        "AI Model, Agent, and RAG",
        AgentRole.ATTACK_SURFACE,
        (AssetKind.AI_MODEL, ExtendedAssetKind.LLM_RAG_APP),
        "analyze_ai_asset",
        (
            "model serialization/provenance",
            "prompt and instruction boundaries",
            "tool permissions and confused-deputy paths",
            "RAG tenant/provenance boundaries",
            "persistent-memory contamination",
            "data leakage and unsafe action escalation",
        ),
        ("ModelScan", "garak", "promptfoo", "PyRIT", "syft", "trivy"),
        ("model/endpoint identity", "scenario trace", "tool-call evidence", "independent scorer/judge result"),
        0.95,
    )


def default_asset_deep_dive_agents() -> tuple[SecurityAgent, ...]:
    return (
        AndroidDeepDiveAgent(),
        IOSDeepDiveAgent(),
        BinaryDeepDiveAgent(),
        FirmwareDeepDiveAgent(),
        SmartContractDeepDiveAgent(),
        CloudDeepDiveAgent(),
        APIDeepDiveAgent(),
        ContainerK8sDeepDiveAgent(),
        SupplyChainDeepDiveAgent(),
        BrowserDesktopDeepDiveAgent(),
        AIDeepDiveAgent(),
    )
