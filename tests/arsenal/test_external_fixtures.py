from __future__ import annotations

from pathlib import Path

from aegis.ai.tool_bridge import _parse
from aegis.arsenal.external_fixtures import (
    external_fixture_capability_ids,
    external_fixture_spec,
)
from aegis.arsenal.inventory import ArsenalInventoryBuilder


def test_external_fixture_registry_is_projected_into_inventory() -> None:
    definitions = {
        item.capability_id: item for item in ArsenalInventoryBuilder().build()
    }
    for capability_id in external_fixture_capability_ids():
        assert definitions[capability_id].fixture_executable is True
        assert external_fixture_spec(capability_id) is not None


def test_external_fixture_materializers_are_comparable(tmp_path: Path) -> None:
    for capability_id in sorted(external_fixture_capability_ids()):
        root = tmp_path / capability_id.replace(":", "-").replace("/", "-")
        positive, negative = root / "positive", root / "negative"
        positive.mkdir(parents=True)
        negative.mkdir(parents=True)
        spec = external_fixture_spec(capability_id)
        assert spec is not None
        spec.materialize(positive, negative)
        assert any(item.is_file() for item in positive.rglob("*"))
        assert any(item.is_file() for item in negative.rglob("*"))
        assert str(root) in spec.tool.cmd.format(
            target=str(root), rules="", phpstubs="", psalmcfg="",
        )


def test_text_and_xml_native_output_parsers_fail_closed() -> None:
    yara = external_fixture_spec("asset:yara/approved-rule-binary-scan")
    spotbugs = external_fixture_spec("asset:spotbugs/java-bytecode-static-analysis")
    assert yara is not None and spotbugs is not None
    assert len(_parse(yara.tool, "AegisFixtureMarker sample.bin\n")) == 1
    assert _parse(yara.tool, "") == []
    assert _parse(spotbugs.tool, "not xml") == []
    xml = (
        '<BugCollection><BugInstance type="ES_COMPARING_STRINGS_WITH_EQ">'
        '<SourceLine sourcepath="Fixture.java" start="3"/></BugInstance></BugCollection>'
    )
    assert len(_parse(spotbugs.tool, xml)) == 1
    parameter_xml = (
        '<BugCollection><BugInstance type="ES_COMPARING_PARAMETER_STRING_WITH_EQ">'
        '<Class><SourceLine sourcepath="Fixture.java" start="3"/></Class>'
        '</BugInstance></BugCollection>'
    )
    assert len(_parse(spotbugs.tool, parameter_xml)) == 1


def test_json_external_parsers_require_expected_semantic_signal() -> None:
    syft = external_fixture_spec("asset:syft/artifact-sbom")
    zizmor = external_fixture_spec("asset:zizmor/github-actions-security-audit")
    assert syft is not None and zizmor is not None
    assert len(_parse(syft.tool, '{"artifacts":[{"name":"lodash","version":"4.17.19"}]}')) == 1
    assert _parse(syft.tool, '{"artifacts":[]}') == []
    assert len(_parse(zizmor.tool, '[{"audit":"dangerous-triggers"}]')) == 1
    assert _parse(zizmor.tool, "not json") == []


def test_network_native_parsers_require_the_controlled_open_port() -> None:
    nmap = external_fixture_spec("asset:nmap/bounded-service-fingerprinting")
    rustscan = external_fixture_spec("asset:rustscan/bounded-fast-port-prefilter")
    assert nmap is not None and rustscan is not None
    open_xml = (
        '<nmaprun><host><ports><port portid="48391"><state state="open"/>'
        "</port></ports></host></nmaprun>"
    )
    closed_xml = open_xml.replace('state="open"', 'state="closed"')
    assert len(_parse(nmap.tool, open_xml)) == 1
    assert _parse(nmap.tool, closed_xml) == []
    assert len(_parse(rustscan.tool, "Open 127.0.0.1:48391")) == 1
    assert _parse(rustscan.tool, "No ports found") == []

    httpx = external_fixture_spec("asset:httpx/http-service-enrichment")
    naabu = external_fixture_spec("asset:naabu/bounded-port-discovery")
    assert httpx is not None and naabu is not None
    assert len(_parse(
        httpx.tool,
        '{"url":"http://127.0.0.1:48391","status_code":200}',
    )) == 1
    assert _parse(httpx.tool, '{"url":"http://127.0.0.1:48391","status_code":404}') == []
    assert len(_parse(naabu.tool, '{"host":"127.0.0.1","port":48391}')) == 1
    assert _parse(naabu.tool, '{"host":"127.0.0.1","port":443}') == []

    websocat = external_fixture_spec("asset:websocat/websocket-protocol-observation")
    assert websocat is not None
    assert len(_parse(websocat.tool, "AEGIS_WEBSOCKET_ECHO_CONTROL\n")) == 1
    assert _parse(websocat.tool, "connection refused") == []

    grpcurl = external_fixture_spec("asset:grpcurl/grpc-service-introspection")
    assert grpcurl is not None
    assert len(_parse(grpcurl.tool, "aegis.fixture.Greeter\ngrpc.reflection.v1.ServerReflection")) == 1
    assert _parse(grpcurl.tool, "Failed to dial target host") == []


def test_extended_linux_parsers_require_the_expected_signal() -> None:
    modelscan = external_fixture_spec("asset:modelscan/serialized-model-safety-scan")
    pefile = external_fixture_spec("asset:pefile/pe-structure-analysis")
    npm = external_fixture_spec("asset:npm/npm-dependency-audit")
    kics = external_fixture_spec("asset:kics/iac-security-scan")
    assert modelscan is not None and pefile is not None and npm is not None and kics is not None

    assert len(_parse(modelscan.tool, '{"issues":[{"description":"unsafe","source":"x.pkl"}]}')) == 1
    assert _parse(modelscan.tool, '{"issues":[]}') == []
    assert len(_parse(pefile.tool, '{"nx_compat":false,"sections":[".text"]}')) == 1
    assert _parse(pefile.tool, '{"nx_compat":true,"sections":[".text"]}') == []
    assert len(_parse(npm.tool, '{"vulnerabilities":{"lodash":{"severity":"high"}}}')) == 1
    assert _parse(npm.tool, '{"vulnerabilities":{}}') == []
    assert len(_parse(
        kics.tool,
        '{"queries":[{"query_id":"dd29336b-fe57-445b-a26e-e6aa867ae609",'
        '"query_name":"Privileged container"}]}',
    )) == 1
    assert _parse(kics.tool, '{"queries":[]}') == []


def test_binary_api_and_oci_parsers_require_the_expected_signal() -> None:
    angr = external_fixture_spec("asset:angr/binary-control-flow-analysis")
    capa = external_fixture_spec("asset:capa/binary-capability-analysis")
    schemathesis = external_fixture_spec("asset:schemathesis/schema-guided-api-testing")
    skopeo = external_fixture_spec("asset:skopeo/container-registry-metadata")
    assert angr is not None and capa is not None and schemathesis is not None and skopeo is not None

    assert len(_parse(angr.tool, '{"branch_nodes":1,"basic_blocks":3}')) == 1
    assert _parse(angr.tool, '{"branch_nodes":0,"basic_blocks":1}') == []
    assert len(_parse(capa.tool, '{"rules":{"create TCP socket":{}}}')) == 1
    assert _parse(capa.tool, '{"rules":{}}') == []
    failed_junit = '<testsuites><testsuite tests="1" failures="1" errors="0"/></testsuites>'
    passed_junit = '<testsuites><testsuite tests="1" failures="0" errors="0"/></testsuites>'
    assert len(_parse(schemathesis.tool, failed_junit)) == 1
    assert _parse(schemathesis.tool, passed_junit) == []
    assert len(_parse(
        skopeo.tool,
        '{"Labels":{"org.aegis.fixture.security-control":"missing"}}',
    )) == 1
    assert _parse(
        skopeo.tool,
        '{"Labels":{"org.aegis.fixture.security-control":"present"}}',
    ) == []


def test_contract_parsers_require_failed_control_behavior() -> None:
    foundry = external_fixture_spec("asset:foundry/smart-contract-fuzz-and-invariant-tests")
    echidna = external_fixture_spec("asset:echidna/smart-contract-property-fuzzing")
    assert foundry is not None and echidna is not None
    assert len(_parse(foundry.tool, '{"AegisInvariantTest":{"invariant_aegis_control":{"status":"Fail"}}}')) == 1
    assert _parse(foundry.tool, '{"AegisInvariantTest":{"invariant_aegis_control":{"status":"Pass"}}}') == []
    assert len(_parse(echidna.tool, '{"status":"falsified","name":"echidna_aegis_control"}')) == 1
    assert _parse(echidna.tool, '{"status":"passed","name":"echidna_aegis_control"}') == []


def test_final_software_closure_parsers_require_semantic_controls() -> None:
    codeql = external_fixture_spec("asset:codeql/cross-file-dataflow")
    floss = external_fixture_spec("asset:floss/static-string-deobfuscation")
    ghidra = external_fixture_spec("asset:ghidra/headless-binary-analysis")
    jadx = external_fixture_spec("asset:jadx/android-decompile")
    pip_audit = external_fixture_spec(
        "asset:pip-audit/python-dependency-vulnerability-analysis"
    )
    restler = external_fixture_spec("asset:restler/stateful-openapi-sequence-testing")
    rizin = external_fixture_spec("asset:rizin/binary-reverse-engineering")
    assert all((codeql, floss, ghidra, jadx, pip_audit, restler, rizin))

    sarif = {
        "runs": [{"results": [{"message": {
            "text": "AEGIS_CODEQL_CROSS_FILE_CONTROL",
        }}]}],
    }
    assert len(_parse(codeql.tool, __import__("json").dumps(sarif))) == 1
    assert _parse(codeql.tool, '{"runs":[{"results":[]}]}') == []
    assert len(_parse(
        floss.tool,
        '{"strings":{"static_strings":[{"string":"AEGIS_FLOSS_SENSITIVE_MARKER_4D91"}]}}',
    )) == 1
    assert _parse(floss.tool, '{"strings":{"static_strings":[]}}') == []
    assert len(_parse(ghidra.tool, "AEGIS_GHIDRA_SENSITIVE_MARKER_FOUND")) == 1
    assert _parse(ghidra.tool, "ANALYSIS COMPLETE") == []
    assert len(_parse(jadx.tool, "Marker.java: AEGIS_JADX_SENSITIVE_MARKER")) == 1
    assert _parse(jadx.tool, "Marker.java: AEGIS_JADX_CLEAN_CONTROL") == []
    audit = [{"name": "pip", "version": "1.5.4", "vulns": [
        {"id": "AEGIS-LOCAL-PIP-0001"},
    ]}]
    assert len(_parse(pip_audit.tool, __import__("json").dumps(audit))) == 1
    assert _parse(pip_audit.tool, "[]") == []
    assert len(_parse(restler.tool, "AEGIS_RESTLER_500_BUCKET")) == 1
    assert _parse(restler.tool, "RESTler completed without bug buckets") == []
    assert len(_parse(rizin.tool, "AEGIS_RIZIN_SENSITIVE_MARKER")) == 1
    assert _parse(rizin.tool, "AEGIS_RIZIN_CLEAN_CONTROL") == []


def test_network_closure_parsers_require_controlled_loopback_observations() -> None:
    dnsx = external_fixture_spec("asset:dnsx/dns-resolution-and-wildcard-filtering")
    jsluice = external_fixture_spec("adapter:jsluice/passive-discovery")
    katana = external_fixture_spec("asset:katana/scoped-endpoint-crawl")
    assert dnsx is not None and jsluice is not None and katana is not None

    assert len(_parse(dnsx.tool, '{"host":"controlled.aegis.invalid","a":["127.0.0.42"]}')) == 1
    assert _parse(dnsx.tool, '{"host":"clean.aegis.invalid","a":[]}') == []
    assert len(_parse(jsluice.tool, '{"url":"/aegis-controlled-admin?scope=local"}')) == 1
    assert _parse(jsluice.tool, '{"url":"/safe-health"}') == []
    assert len(_parse(katana.tool, '{"request":{"endpoint":"http://127.0.0.1/aegis-controlled-admin"}}')) == 1
    assert _parse(katana.tool, '{"request":{"endpoint":"http://127.0.0.1/safe-health"}}') == []

    mitmproxy = external_fixture_spec("asset:mitmproxy/authorized-http-traffic-capture")
    testssl = external_fixture_spec("asset:testssl-sh/tls-configuration-analysis")
    ssh_audit = external_fixture_spec("asset:ssh-audit/ssh-configuration-analysis")
    assert mitmproxy is not None and testssl is not None and ssh_audit is not None
    assert len(_parse(mitmproxy.tool, "AEGIS_MITMPROXY_CONTROLLED")) == 1
    assert _parse(mitmproxy.tool, "safe local capture") == []
    assert len(_parse(testssl.tool, "127.0.0.1:48409 TLS 1.2 offered")) == 1
    assert _parse(testssl.tool, "127.0.0.1:48409 TLS 1.3 offered") == []
    assert len(_parse(ssh_audit.tool, "diffie-hellman-group1-sha1")) == 1
    assert _parse(ssh_audit.tool, "curve25519-sha256") == []
    nuclei = external_fixture_spec("asset:nuclei/signed-safe-template-validation")
    assert nuclei is not None
    assert len(_parse(nuclei.tool, '{"template-id":"aegis-local-marker","host":"http://127.0.0.1:48411/"}')) == 1
    assert _parse(nuclei.tool, '{"template-id":"other","host":"http://127.0.0.1:48411/"}') == []
