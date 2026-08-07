from __future__ import annotations

from aegis.ai.jarvis.asset_capabilities import AssetKind
from aegis.ai.jarvis.asset_capability_planner import RuntimeRequirement, plan_capability_scan
from aegis.ai.jarvis.asset_deep_capabilities import ExtendedAssetKind


def _tools(plan) -> set[str]:
    return {method.tool for method in plan.ready}


def _blocked_tools(plan) -> set[str]:
    return {method.tool for method in plan.blocked}


def test_all_extended_asset_classes_are_supported() -> None:
    assert {kind.value for kind in ExtendedAssetKind} == {
        "kubernetes_cluster",
        "container_image",
        "browser_extension",
        "electron_app",
        "github_org",
        "gitlab_group",
        "saas_tenant",
        "graphql_endpoint",
        "websocket_service",
        "grpc_api",
        "package_registry",
        "cicd_pipeline",
        "docker_registry",
        "npm_package",
        "pypi_package",
        "terraform_repo",
        "llm_rag_app",
    }


def test_android_static_and_runtime_tools_have_separate_prerequisites() -> None:
    static = plan_capability_scan(AssetKind.ANDROID_APK, artifact_available=True)
    assert {"MobSF", "jadx", "apktool"} <= _tools(static)
    assert {"Frida", "objection"} <= _blocked_tools(static)

    dynamic = plan_capability_scan(
        AssetKind.ANDROID_APK,
        artifact_available=True,
        mobile_runtime_available=True,
    )
    assert {"Frida", "objection"} <= _tools(dynamic)


def test_ios_runtime_requires_test_runtime_not_just_ipa() -> None:
    static = plan_capability_scan(AssetKind.IOS_IPA, artifact_available=True)
    assert {"MobSF", "otool", "class-dump"} <= _tools(static)
    assert {"Frida", "objection"} <= _blocked_tools(static)

    dynamic = plan_capability_scan(
        AssetKind.IOS_IPA,
        artifact_available=True,
        mobile_runtime_available=True,
    )
    assert {"Frida", "objection"} <= _tools(dynamic)


def test_binary_depth_uses_sandbox_and_platform_specific_pefile() -> None:
    static = plan_capability_scan(
        AssetKind.EXECUTABLE,
        artifact_available=True,
        platform_hint="windows",
    )
    assert {"capa", "syft", "grype", "FLOSS", "YARA", "pefile"} <= _tools(static)
    assert {"Ghidra", "angr", "Rizin"} <= _blocked_tools(static)

    deep = plan_capability_scan(
        AssetKind.EXECUTABLE,
        artifact_available=True,
        sandbox_available=True,
        platform_hint="windows",
    )
    assert {"Ghidra", "angr", "Rizin", "pefile"} <= _tools(deep)


def test_source_language_specialists_are_profile_driven() -> None:
    plan = plan_capability_scan(
        AssetKind.SOURCE_CODE,
        artifact_available=True,
        language_hints=("python", "go", "ruby", "java"),
    )
    assert {
        "semgrep",
        "CodeQL",
        "gitleaks",
        "trivy",
        "Bandit",
        "gosec",
        "Brakeman",
        "SpotBugs",
        "Checkov",
        "KICS",
        "zizmor",
    } <= _tools(plan)


def test_network_service_hints_unlock_protocol_specialists() -> None:
    plan = plan_capability_scan(
        AssetKind.DOMAIN,
        endpoint_available=True,
        service_hints=("https", "ssh"),
    )
    assert {"nmap", "RustScan", "testssl.sh", "ssh-audit"} <= _tools(plan)


def test_contract_fuzzers_wait_for_isolated_sandbox() -> None:
    static = plan_capability_scan(AssetKind.SMART_CONTRACT, artifact_available=True)
    assert {"slither", "Mythril"} <= _tools(static)
    assert {"Echidna", "Foundry"} <= _blocked_tools(static)

    local_lab = plan_capability_scan(
        AssetKind.SMART_CONTRACT,
        artifact_available=True,
        sandbox_available=True,
    )
    assert {"Echidna", "Foundry"} <= _tools(local_lab)


def test_firmware_emulation_waits_for_sandbox() -> None:
    static = plan_capability_scan(AssetKind.HARDWARE, firmware_available=True)
    assert {"binwalk", "syft", "grype", "trivy", "aegis-firmware-arch"} <= _tools(static)
    assert {"FirmAE", "Firmadyne", "Ghidra"} <= _blocked_tools(static)

    emulated = plan_capability_scan(
        AssetKind.HARDWARE,
        firmware_available=True,
        sandbox_available=True,
    )
    assert {"FirmAE", "Firmadyne", "Ghidra"} <= _tools(emulated)


def test_schema_guided_api_testing_requires_spec_and_endpoint() -> None:
    spec_only = plan_capability_scan(AssetKind.API, api_spec_available=True)
    assert "RESTler" in _tools(spec_only)
    assert "Schemathesis" in _blocked_tools(spec_only)

    live = plan_capability_scan(
        AssetKind.API,
        api_spec_available=True,
        endpoint_available=True,
    )
    assert "Schemathesis" in _tools(live)


def test_cloud_depth_adds_real_identity_and_posture_tools() -> None:
    aws = plan_capability_scan(AssetKind.AWS_ACCOUNT, credentials_available=True)
    assert {"Prowler", "ScoutSuite", "Cloudsplaining"} <= _tools(aws)

    azure = plan_capability_scan(AssetKind.AZURE_ACCOUNT, credentials_available=True)
    assert {"Prowler", "ScoutSuite", "ROADtools", "AzureHound"} <= _tools(azure)


def test_kubernetes_cluster_access_is_distinct_from_cloud_credentials() -> None:
    blocked = plan_capability_scan(ExtendedAssetKind.KUBERNETES_CLUSTER)
    assert "Kubescape" in _blocked_tools(blocked)

    cluster = plan_capability_scan(
        ExtendedAssetKind.KUBERNETES_CLUSTER,
        cluster_access_available=True,
    )
    assert "Kubescape" in _tools(cluster)
    assert {"Checkov", "KICS"} <= _blocked_tools(cluster)


def test_container_and_registry_assets_have_real_specialized_lanes() -> None:
    image = plan_capability_scan(ExtendedAssetKind.CONTAINER_IMAGE, artifact_available=True)
    assert {"trivy", "syft", "grype", "Checkov"} <= _tools(image)

    registry = plan_capability_scan(
        ExtendedAssetKind.DOCKER_REGISTRY,
        registry_access_available=True,
    )
    assert "skopeo" in _tools(registry)


def test_source_like_new_assets_inherit_source_security_stack() -> None:
    extension = plan_capability_scan(
        ExtendedAssetKind.BROWSER_EXTENSION,
        artifact_available=True,
    )
    assert {"web-ext", "semgrep", "CodeQL", "gitleaks", "trivy"} <= _tools(extension)

    pipeline = plan_capability_scan(
        ExtendedAssetKind.CICD_PIPELINE,
        artifact_available=True,
    )
    assert {"Checkov", "KICS", "zizmor", "gitleaks", "trivy"} <= _tools(pipeline)


def test_protocol_asset_classes_route_to_real_methods() -> None:
    graphql = plan_capability_scan(
        ExtendedAssetKind.GRAPHQL_ENDPOINT,
        endpoint_available=True,
    )
    assert "Schemathesis" in _tools(graphql)

    websocket = plan_capability_scan(
        ExtendedAssetKind.WEBSOCKET_SERVICE,
        endpoint_available=True,
    )
    assert "websocat" in _tools(websocket)

    grpc = plan_capability_scan(
        ExtendedAssetKind.GRPC_API,
        endpoint_available=True,
    )
    assert "grpcurl" in _tools(grpc)


def test_package_and_terraform_assets_keep_execution_off_by_default() -> None:
    npm_public = plan_capability_scan(ExtendedAssetKind.NPM_PACKAGE)
    assert "aegis-package-registry" in _tools(npm_public)
    assert {"npm", "osv-scanner"} <= _blocked_tools(npm_public)

    npm_artifact = plan_capability_scan(
        ExtendedAssetKind.NPM_PACKAGE,
        artifact_available=True,
    )
    assert {"npm", "osv-scanner"} <= _tools(npm_artifact)

    terraform = plan_capability_scan(
        ExtendedAssetKind.TERRAFORM_REPO,
        artifact_available=True,
    )
    assert {"Checkov", "KICS", "trivy", "gitleaks"} <= _tools(terraform)


def test_ai_depth_separates_artifact_endpoint_auth_and_sandbox() -> None:
    artifact = plan_capability_scan(AssetKind.AI_MODEL, artifact_available=True)
    assert {"ModelScan", "aegis-model-provenance"} <= _tools(artifact)

    endpoint = plan_capability_scan(
        ExtendedAssetKind.LLM_RAG_APP,
        endpoint_available=True,
    )
    assert {"PyRIT", "aegis-agent-permission-audit", "aegis-rag-boundary"} <= _tools(endpoint)
    assert "aegis-memory-poisoning" in _blocked_tools(endpoint)

    lab = plan_capability_scan(
        ExtendedAssetKind.LLM_RAG_APP,
        endpoint_available=True,
        auth_session_available=True,
        sandbox_available=True,
    )
    assert "aegis-memory-poisoning" in _tools(lab)


def test_runtime_requirement_enum_documents_distinct_authorizations() -> None:
    assert {item.value for item in RuntimeRequirement} == {
        "authorized_mobile_runtime",
        "isolated_sandbox",
        "authorized_cluster_access",
        "authorized_registry_access",
        "authorized_authenticated_session",
    }
