"""Asset-type routing: the enum, classification, and the technique map."""

import pytest

from aegis.arsenal.assets.hunt import load_executor
from aegis.arsenal.assets.types import (
    ArsenalAssetType,
    UnsupportedAssetType,
    asset_kind_for,
    classify_identifier,
    coverage_matrix,
    from_program_asset_type,
    parse_asset_type,
    techniques_for,
)
from aegis.ingest.program import AssetType

#: The asset classes the operator asked the arsenal to cover.
REQUIRED = {
    "cidr", "domain", "wildcard", "ip_address", "api", "aws_account", "azure_account",
    "source_code", "executable", "smart_contract", "ai_model", "other_asset",
}


def test_every_required_asset_type_is_supported():
    assert {item.value for item in ArsenalAssetType} == REQUIRED


def test_every_asset_type_routes_to_at_least_one_technique():
    for asset_type in ArsenalAssetType:
        assert techniques_for(asset_type), asset_type


def test_every_registered_technique_resolves_to_a_real_callable():
    for asset_type in ArsenalAssetType:
        for technique in techniques_for(asset_type):
            assert callable(load_executor(technique)), technique.technique_id


def test_technique_ids_are_unique_within_an_asset_type():
    for asset_type in ArsenalAssetType:
        ids = [item.technique_id for item in techniques_for(asset_type)]
        assert len(ids) == len(set(ids)), asset_type


@pytest.mark.parametrize("raw", ["android", "ios", "mobile", "hardware", "firmware", "iot"])
def test_mobile_and_hardware_are_refused_rather_than_degraded(raw):
    with pytest.raises(UnsupportedAssetType):
        parse_asset_type(raw)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("domain", ArsenalAssetType.DOMAIN),
        ("IP-Address", ArsenalAssetType.IP_ADDRESS),
        ("smart contract", ArsenalAssetType.SMART_CONTRACT),
        ("aws", ArsenalAssetType.AWS_ACCOUNT),
        ("llm", ArsenalAssetType.AI_MODEL),
        ("repo", ArsenalAssetType.SOURCE_CODE),
    ],
)
def test_parse_asset_type_accepts_aliases_and_normalizes_separators(raw, expected):
    assert parse_asset_type(raw) is expected


def test_parse_asset_type_rejects_unknown_and_empty():
    with pytest.raises(ValueError):
        parse_asset_type("quantum_toaster")
    with pytest.raises(ValueError):
        parse_asset_type("")


@pytest.mark.parametrize(
    "identifier,expected",
    [
        ("203.0.113.0/24", ArsenalAssetType.CIDR),
        ("2001:db8::/48", ArsenalAssetType.CIDR),
        ("203.0.113.9", ArsenalAssetType.IP_ADDRESS),
        ("*.example.com", ArsenalAssetType.WILDCARD),
        ("api.example.com", ArsenalAssetType.DOMAIN),
        ("https://example.com/api/v1", ArsenalAssetType.API),
        ("0x" + "ab" * 20, ArsenalAssetType.SMART_CONTRACT),
        ("Token.sol", ArsenalAssetType.SMART_CONTRACT),
        ("installer.exe", ArsenalAssetType.EXECUTABLE),
        ("app.asar", ArsenalAssetType.EXECUTABLE),
        ("openapi.yaml", ArsenalAssetType.API),
        ("https://github.com/acme/widget", ArsenalAssetType.SOURCE_CODE),
        ("123456789012", ArsenalAssetType.AWS_ACCOUNT),
    ],
)
def test_classify_identifier(identifier, expected):
    assert classify_identifier(identifier) is expected


def test_unclassifiable_identifier_lands_in_other_not_a_network_lane():
    # The important property: an unknown string must never be inferred into a lane
    # that would send traffic at it.
    assert classify_identifier("the office badge reader") is ArsenalAssetType.OTHER_ASSET


def test_program_scope_asset_types_bridge_or_refuse():
    assert from_program_asset_type(AssetType.WILDCARD) is ArsenalAssetType.WILDCARD
    assert from_program_asset_type(AssetType.API) is ArsenalAssetType.API
    for refused in (AssetType.ANDROID, AssetType.IOS, AssetType.FIRMWARE):
        with pytest.raises(UnsupportedAssetType):
            from_program_asset_type(refused)


def test_each_asset_type_maps_to_a_deep_planner_asset_kind():
    for asset_type in ArsenalAssetType:
        assert asset_kind_for(asset_type) is not None


def test_coverage_matrix_is_non_targeting_and_complete():
    matrix = coverage_matrix()
    assert set(matrix["supported_asset_types"]) == REQUIRED
    assert "android" in matrix["refused_asset_types"]
    assert set(matrix["techniques"]) == REQUIRED
    for entries in matrix["techniques"].values():
        for entry in entries:
            assert entry["purpose"], entry


def test_asset_lanes_appear_in_the_capability_inventory():
    """The audit and the CLI must describe the same coverage, not drift apart."""
    from aegis.arsenal.inventory import ArsenalInventoryBuilder

    definitions = {
        item.capability_id: item for item in ArsenalInventoryBuilder().build()
    }
    for asset_type in ArsenalAssetType:
        for technique in techniques_for(asset_type):
            capability_id = f"asset-lane:{technique.technique_id}"
            assert capability_id in definitions, capability_id
            definition = definitions[capability_id]
            assert asset_type.value in definition.supported_asset_classes
            assert definition.provenance
            assert definition.executor_provider
