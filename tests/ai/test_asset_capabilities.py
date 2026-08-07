from __future__ import annotations

from aegis.ai.jarvis.asset_capabilities import AssetKind, Requirement, plan_asset_scan


def _tools(plan) -> set[str]:
    return {method.tool for method in plan.ready}


def _blocked_requirements(plan) -> set[Requirement]:
    return {method.requirement for method in plan.blocked}


def test_all_bug_bounty_asset_types_are_first_class() -> None:
    assert {kind.value for kind in AssetKind} == {
        "cidr",
        "domain",
        "ios_app_store",
        "ios_testflight",
        "ios_ipa",
        "android_play_store",
        "android_apk",
        "windows_microsoft_store",
        "source_code",
        "executable",
        "smart_contract",
        "wildcard",
        "ip_address",
        "hardware",
        "other_asset",
        "ai_model",
        "api",
        "aws_account",
        "azure_account",
    }


def test_store_listing_does_not_fake_binary_access() -> None:
    plan = plan_asset_scan(AssetKind.IOS_APP_STORE)
    assert _tools(plan) == {"aegis-store-metadata"}
    assert Requirement.ARTIFACT in _blocked_requirements(plan)

    with_artifact = plan_asset_scan(AssetKind.IOS_APP_STORE, artifact_available=True)
    assert "MobSF" in _tools(with_artifact)


def test_android_store_unlocks_real_binary_tools_only_with_artifact() -> None:
    plan = plan_asset_scan(AssetKind.ANDROID_PLAY_STORE)
    assert _tools(plan) == {"aegis-store-metadata"}

    with_artifact = plan_asset_scan(AssetKind.ANDROID_PLAY_STORE, artifact_available=True)
    assert {"MobSF", "jadx"} <= _tools(with_artifact)


def test_cloud_accounts_require_authorized_credentials() -> None:
    aws = plan_asset_scan(AssetKind.AWS_ACCOUNT)
    azure = plan_asset_scan(AssetKind.AZURE_ACCOUNT)
    assert not aws.ready
    assert not azure.ready
    assert Requirement.CREDENTIALS in _blocked_requirements(aws)
    assert Requirement.CREDENTIALS in _blocked_requirements(azure)

    assert _tools(plan_asset_scan(AssetKind.AWS_ACCOUNT, credentials_available=True)) == {"Prowler"}
    assert _tools(plan_asset_scan(AssetKind.AZURE_ACCOUNT, credentials_available=True)) == {"Prowler"}


def test_ai_model_separates_file_scan_from_endpoint_red_team() -> None:
    model_file = plan_asset_scan(AssetKind.AI_MODEL, artifact_available=True)
    assert "ModelScan" in _tools(model_file)
    assert "garak" not in _tools(model_file)
    assert "promptfoo" not in _tools(model_file)

    endpoint = plan_asset_scan(AssetKind.AI_MODEL, endpoint_available=True)
    assert {"garak", "promptfoo"} <= _tools(endpoint)
    assert "ModelScan" not in _tools(endpoint)


def test_firmware_enables_binwalk_and_downstream_sbom_scanners() -> None:
    plan = plan_asset_scan(AssetKind.HARDWARE, firmware_available=True)
    assert {"binwalk", "syft", "grype", "trivy"} <= _tools(plan)


def test_api_spec_adds_stateful_restler_lane() -> None:
    base = plan_asset_scan(AssetKind.API)
    assert {"httpx", "nuclei"} <= _tools(base)
    assert "RESTler" not in _tools(base)

    with_spec = plan_asset_scan(AssetKind.API, api_spec_available=True)
    assert "RESTler" in _tools(with_spec)


def test_real_tools_are_selected_for_source_binary_and_contracts() -> None:
    source = plan_asset_scan(AssetKind.SOURCE_CODE, artifact_available=True)
    assert {"semgrep", "CodeQL", "gitleaks", "trivy", "OpenSSF Scorecard"} <= _tools(source)

    executable = plan_asset_scan(AssetKind.EXECUTABLE, artifact_available=True)
    assert {"capa", "syft", "grype"} <= _tools(executable)

    contract = plan_asset_scan(AssetKind.SMART_CONTRACT, artifact_available=True)
    assert _tools(contract) == {"slither"}
