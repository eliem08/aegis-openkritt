"""Hunt orchestration: routing, scope refusal, honest degradation, and reporting.

Every test is offline. Network lanes are exercised through a recording transport,
and external-binary lanes through a resolver that reports the binary as missing —
which is the case on the operator's Windows workstation.
"""

import json

import pytest

from aegis.arsenal.assets.context import Identity
from aegis.arsenal.assets.hunt import (
    HuntRefused,
    render_markdown,
    run_hunt,
    write_report,
)
from aegis.arsenal.assets.scope import build_allowlist
from aegis.arsenal.assets.session import HuntSession, RateLimit
from aegis.arsenal.assets.tooling import ToolAvailability, ToolLocation, ToolResolver
from aegis.arsenal.assets.types import ArsenalAssetType
from aegis.arsenal.models import ArsenalCoverageState


class NoTools(ToolResolver):
    """A workstation where no external security binary is installed."""

    def __init__(self):
        super().__init__(which=lambda name: None, allow_container=False)


class DeadTransport:
    """Every request fails at the socket, as it would with no network."""

    def __init__(self):
        self.calls = []

    def __call__(self, request, timeout):
        self.calls.append(request.full_url)
        raise OSError("network is unreachable")


@pytest.fixture
def allowlist():
    return build_allowlist(
        program="acme", in_scope=["*.acme.com", "acme.com"],
        out_of_scope=["admin.acme.com"],
    )


def offline_session(allowlist, **kwargs):
    return HuntSession(
        allowlist=allowlist, transport=DeadTransport(), sleep=lambda _: None,
        rate_limit=RateLimit(max_requests=50), **kwargs,
    )


# ------------------------------------------------------------------- refusal


def test_hunt_refuses_an_out_of_scope_asset_before_any_technique_runs(allowlist):
    transport = DeadTransport()
    session = HuntSession(allowlist=allowlist, transport=transport, sleep=lambda _: None)
    with pytest.raises(HuntRefused) as info:
        run_hunt(asset="evil.com", allowlist=allowlist, session=session,
                 resolver=NoTools())
    assert "refusing to hunt" in str(info.value)
    assert transport.calls == []


def test_hunt_refuses_an_explicitly_excluded_subdomain(allowlist):
    with pytest.raises(HuntRefused):
        run_hunt(asset="admin.acme.com", allowlist=allowlist, resolver=NoTools())


def test_offline_asset_types_do_not_need_a_host_match(allowlist):
    # A contract source file is not a host; requiring it on the allowlist would make
    # the local lanes unusable.
    report = run_hunt(
        asset="Vault.sol", allowlist=allowlist,
        asset_type=ArsenalAssetType.SMART_CONTRACT, resolver=NoTools(),
    )
    assert report.asset_type is ArsenalAssetType.SMART_CONTRACT


# ------------------------------------------------------------------- routing


def test_asset_type_is_inferred_when_not_declared(allowlist):
    report = run_hunt(asset="www.acme.com", allowlist=allowlist,
                      session=offline_session(allowlist), resolver=NoTools())
    assert report.asset_type is ArsenalAssetType.DOMAIN


def test_only_filter_runs_the_named_technique(allowlist):
    report = run_hunt(
        asset="www.acme.com", allowlist=allowlist, session=offline_session(allowlist),
        resolver=NoTools(), only=["security-headers"],
    )
    assert [item.technique_id for item in report.results] == ["security-headers"]


def test_unknown_technique_for_the_asset_type_is_rejected(allowlist):
    with pytest.raises(ValueError, match="not registered"):
        run_hunt(asset="www.acme.com", allowlist=allowlist, resolver=NoTools(),
                 only=["contract-pattern-review"])


@pytest.mark.parametrize(
    "asset,asset_type",
    [
        ("www.acme.com", ArsenalAssetType.DOMAIN),
        ("*.acme.com", ArsenalAssetType.WILDCARD),
        ("acme.com", ArsenalAssetType.API),
        ("123456789012", ArsenalAssetType.AWS_ACCOUNT),
        ("123456789012", ArsenalAssetType.AZURE_ACCOUNT),
        ("app.exe", ArsenalAssetType.EXECUTABLE),
        ("Vault.sol", ArsenalAssetType.SMART_CONTRACT),
        ("acme.com", ArsenalAssetType.AI_MODEL),
        ("a badge reader", ArsenalAssetType.OTHER_ASSET),
        ("/tmp/checkout", ArsenalAssetType.SOURCE_CODE),
    ],
)
def test_every_asset_type_produces_a_report_with_no_technique_crashing(
    allowlist, asset, asset_type,
):
    report = run_hunt(
        asset=asset, allowlist=allowlist, asset_type=asset_type,
        session=offline_session(allowlist), resolver=NoTools(),
    )
    assert report.results
    for result in report.results:
        # Every technique must report a state; none may raise or vanish.
        assert isinstance(result.state, ArsenalCoverageState)
        if not result.executed:
            assert result.reason, result.technique_id


# ------------------------------------------------- honest degradation


def test_missing_binary_is_reported_as_unavailable_with_a_reason(allowlist):
    report = run_hunt(
        asset="www.acme.com", allowlist=allowlist, session=offline_session(allowlist),
        resolver=NoTools(), only=["service-identification"],
    )
    result = report.results[0]
    assert result.state is ArsenalCoverageState.UNAVAILABLE
    assert "nmap" in result.reason
    assert result.observations == ()


def test_missing_prerequisite_is_waiting_not_a_clean_pass(allowlist):
    report = run_hunt(
        asset="acme.com", allowlist=allowlist, asset_type=ArsenalAssetType.API,
        session=offline_session(allowlist), resolver=NoTools(),
        only=["openapi-ingest"],
    )
    result = report.results[0]
    assert result.state is ArsenalCoverageState.WAITING_FOR_PREREQUISITE
    assert "--api-spec" in result.reason


def test_authorization_matrix_requires_two_operator_supplied_identities(
    tmp_path, allowlist,
):
    spec = tmp_path / "api.json"
    spec.write_text(json.dumps({
        "openapi": "3.0.0", "servers": [{"url": "https://acme.com"}],
        "security": [{"bearer": []}], "paths": {"/me": {"get": {}}},
    }), encoding="utf-8")
    report = run_hunt(
        asset="acme.com", allowlist=allowlist, asset_type=ArsenalAssetType.API,
        specification_path=spec, session=offline_session(allowlist), resolver=NoTools(),
        identities=[Identity("user", {"Authorization": "Bearer a"})],
        only=["authorization-matrix"],
    )
    result = report.results[0]
    assert result.state is ArsenalCoverageState.WAITING_FOR_PREREQUISITE
    assert "does not log in" in result.reason


def test_ai_lane_generates_cases_offline_and_sends_nothing(allowlist):
    transport = DeadTransport()
    session = HuntSession(allowlist=allowlist, transport=transport, sleep=lambda _: None)
    report = run_hunt(
        asset="acme.com", allowlist=allowlist, asset_type=ArsenalAssetType.AI_MODEL,
        session=session, resolver=NoTools(),
        only=["prompt-injection-suite", "system-prompt-extraction", "tool-abuse-chain"],
    )
    assert transport.calls == []
    for result in report.results:
        assert result.executed
        assert result.metadata["executed"] is False
        assert result.metadata["case_count"] > 0


def test_ai_lane_will_not_send_prompts_without_the_state_change_opt_in(allowlist):
    transport = DeadTransport()
    session = HuntSession(allowlist=allowlist, transport=transport, sleep=lambda _: None)
    report = run_hunt(
        asset="acme.com", allowlist=allowlist, asset_type=ArsenalAssetType.AI_MODEL,
        session=session, resolver=NoTools(), only=["prompt-injection-suite"],
        options={"model_endpoint": "https://acme.com/chat"},
    )
    assert transport.calls == []
    assert "state-change opt-in" in report.results[0].reason


# ------------------------------------------------- lanes that do real work


def test_contract_pattern_review_finds_the_unguarded_sibling(tmp_path, allowlist):
    source = tmp_path / "Vault.sol"
    source.write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Vault {\n"
        "  function setFee(uint f) public onlyOwner { feeBps = f; }\n"
        "  function setTreasury(address t) public { treasury = t; }\n"
        "}\n",
        encoding="utf-8",
    )
    report = run_hunt(
        asset="Vault.sol", allowlist=allowlist,
        asset_type=ArsenalAssetType.SMART_CONTRACT, artifact_path=source,
        resolver=NoTools(), only=["contract-pattern-review"],
    )
    findings = [item for item in report.observations
                if item.weakness == "missing-access-control"]
    assert len(findings) == 1
    assert "setTreasury" in findings[0].subject
    assert findings[0].guarded_sibling  # the contrast is what makes it reportable


def test_contract_lane_reports_slither_absence_without_losing_the_pattern_lane(
    tmp_path, allowlist,
):
    source = tmp_path / "Vault.sol"
    source.write_text("contract V { function f() public { x = 1; } }", encoding="utf-8")
    report = run_hunt(
        asset="Vault.sol", allowlist=allowlist,
        asset_type=ArsenalAssetType.SMART_CONTRACT, artifact_path=source,
        resolver=NoTools(),
    )
    states = {item.technique_id: item.state for item in report.results}
    assert states["contract-static-analysis"] is ArsenalCoverageState.UNAVAILABLE
    assert states["contract-pattern-review"].value.startswith("EXECUTED")


def test_mass_assignment_flags_privileged_write_properties(tmp_path, allowlist):
    spec = tmp_path / "api.json"
    spec.write_text(json.dumps({
        "openapi": "3.0.0", "paths": {"/users": {"post": {
            "requestBody": {"content": {"application/json": {"schema": {"properties": {
                "name": {}, "is_admin": {}, "role": {},
            }}}}},
        }}},
    }), encoding="utf-8")
    report = run_hunt(
        asset="acme.com", allowlist=allowlist, asset_type=ArsenalAssetType.API,
        specification_path=spec, session=offline_session(allowlist), resolver=NoTools(),
        only=["mass-assignment"],
    )
    assert len(report.observations) == 1
    evidence = report.observations[0].evidence
    assert set(evidence["privileged_properties"]) == {"is_admin", "role"}


def test_iam_policy_lane_reviews_operator_supplied_documents(tmp_path, allowlist):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }), encoding="utf-8")
    report = run_hunt(
        asset="123456789012", allowlist=allowlist,
        asset_type=ArsenalAssetType.AWS_ACCOUNT, policy_documents=[policy],
        resolver=NoTools(), only=["iam-policy-review"],
    )
    assert any(item.weakness == "wildcard-iam-grant" for item in report.observations)


def test_executable_lane_triages_a_binary_and_extracts_a_secret(tmp_path, allowlist):
    binary = tmp_path / "app.bin"
    binary.write_bytes(
        b"\x7fELF" + b"\x00" * 20
        + b"AKIAIOSFODNN7EXAMPLE" + b"\x00"
        + b"https://internal.acme.local/admin" + b"\x00" * 32
    )
    report = run_hunt(
        asset="app.bin", allowlist=allowlist, asset_type=ArsenalAssetType.EXECUTABLE,
        artifact_path=binary, resolver=NoTools(),
        only=["binary-triage", "embedded-secret-scan"],
    )
    weaknesses = {item.weakness for item in report.observations}
    assert "hardcoded-credential" in weaknesses
    secret = next(item for item in report.observations
                  if item.weakness == "hardcoded-credential")
    # The secret value itself must never be written into evidence.
    assert secret.evidence["value_recorded"] is False
    assert "AKIA" not in json.dumps(secret.document())


def test_other_lane_classifies_and_names_the_next_command(allowlist):
    report = run_hunt(
        asset="chrome-extension://abcdef", allowlist=allowlist,
        asset_type=ArsenalAssetType.OTHER_ASSET, resolver=NoTools(),
    )
    assert report.observations
    assert "source_code" in report.observations[0].recommendation


# --------------------------------------------------------------- reporting


def test_report_records_every_technique_including_the_ones_that_did_not_run(allowlist):
    report = run_hunt(
        asset="www.acme.com", allowlist=allowlist, session=offline_session(allowlist),
        resolver=NoTools(),
    )
    document = report.document()
    assert document["summary"]["techniques_registered"] == len(report.results)
    assert document["summary"]["techniques_executed"] <= len(report.results)
    assert set(document["summary"]["technique_states"])
    assert document["read_only"] is True
    assert document["scope"]["program"] == "acme"


def test_report_carries_the_request_audit_log(allowlist):
    session = offline_session(allowlist)
    report = run_hunt(
        asset="www.acme.com", allowlist=allowlist, session=session, resolver=NoTools(),
        only=["security-headers"],
    )
    assert report.request_log
    assert report.request_log[-1]["technique_id"] == "security-headers"


def test_report_is_json_serializable_and_writable(tmp_path, allowlist):
    report = run_hunt(
        asset="www.acme.com", allowlist=allowlist, session=offline_session(allowlist),
        resolver=NoTools(), only=["security-headers"],
    )
    path = tmp_path / "nested" / "report.json"
    write_report(report, path)
    reloaded = json.loads(path.read_text(encoding="utf-8"))
    assert reloaded["hunt_id"] == report.hunt_id


def test_markdown_says_no_observations_is_not_a_clean_bill_of_health(allowlist):
    report = run_hunt(
        asset="www.acme.com", allowlist=allowlist, session=offline_session(allowlist),
        resolver=NoTools(), only=["service-identification"],
    )
    markdown = render_markdown(report)
    assert "not a clean bill of health" in markdown
    assert "service-identification" in markdown


def test_a_technique_that_raises_becomes_unavailable_not_a_crash(allowlist, monkeypatch):
    from aegis.arsenal.assets import network

    def boom(context):
        raise RuntimeError("detector exploded")

    monkeypatch.setattr(network, "security_headers", boom)
    report = run_hunt(
        asset="www.acme.com", allowlist=allowlist, session=offline_session(allowlist),
        resolver=NoTools(), only=["security-headers"],
    )
    assert report.results[0].state is ArsenalCoverageState.UNAVAILABLE
    assert "detector exploded" in report.results[0].reason


def test_tool_resolver_reports_missing_binaries_rather_than_raising():
    resolver = NoTools()
    availability = resolver.resolve("nmap")
    assert availability.location is ToolLocation.MISSING
    assert not availability.usable
    assert "Dockerfile.arsenal" in availability.reason
    assert resolver.first_available(["nmap", "slither"]) is None


def test_container_routing_builds_a_network_isolated_docker_command():
    tool = ToolAvailability("slither", ToolLocation.CONTAINER)
    command = tool.command(["--json", "-"], mounts=[])
    assert command[:6] == ["docker", "run", "--rm", "--network", "none", "aegis-arsenal"]


def test_internal_tools_are_always_available():
    resolver = NoTools()
    assert resolver.resolve("aegis-openapi-parser").location is ToolLocation.INTERNAL
