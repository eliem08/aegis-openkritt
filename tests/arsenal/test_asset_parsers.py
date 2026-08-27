"""Parsers added by the asset lanes. All offline; no network, no external binaries."""

import json
import struct
import zipfile

import pytest

from aegis.arsenal.assets.api_surface import (
    SpecificationError,
    parse_specification,
)
from aegis.arsenal.assets.cloud import review_policy_document
from aegis.arsenal.assets.contract import parse_contract, parse_mythril, parse_slither
from aegis.arsenal.assets.executable import (
    detect_format,
    extract_asar,
    iter_strings,
    parse_syft,
    profile_binary,
    shannon_entropy,
)
from aegis.arsenal.assets.network import parse_crtsh, parse_nmap_xml, summarize_certificate

# --------------------------------------------------------------------- network


def test_parse_crtsh_normalizes_wildcards_and_multiline_sans():
    payload = json.dumps([
        {"name_value": "*.acme.com\napi.acme.com", "common_name": "acme.com"},
        {"name_value": "API.ACME.COM"},
        {"name_value": "someone@acme.com"},
        "not a dict",
    ])
    assert parse_crtsh(payload) == ("acme.com", "api.acme.com")


@pytest.mark.parametrize("payload", ["", "not json", "{}", "[1, 2, 3]"])
def test_parse_crtsh_returns_nothing_on_bad_payloads(payload):
    assert parse_crtsh(payload) == ()


def test_parse_nmap_xml_extracts_open_ports():
    xml = """<?xml version="1.0"?><nmaprun><host><ports>
      <port protocol="tcp" portid="443"><state state="open"/>
        <service name="https" product="nginx" version="1.24.0"/></port>
      <port protocol="tcp" portid="22"><state state="filtered"/>
        <service name="ssh"/></port>
    </ports></host></nmaprun>"""
    rows = parse_nmap_xml(xml)
    assert len(rows) == 2
    assert rows[0] == {"port": 443, "protocol": "tcp", "state": "open",
                       "service": "https", "product": "nginx", "version": "1.24.0"}
    assert rows[1]["state"] == "filtered"


@pytest.mark.parametrize("payload", ["", "   ", "<not-xml"])
def test_parse_nmap_xml_tolerates_garbage(payload):
    assert parse_nmap_xml(payload) == ()


def test_summarize_certificate_detects_expiry_and_hostname_mismatch():
    certificate = {
        "subjectAltName": (("DNS", "other.example.com"),),
        "notAfter": "Jan  1 00:00:00 2020 GMT",
        "notBefore": "Jan  1 00:00:00 2019 GMT",
        "issuer": ((("commonName", "Test CA"),),),
        "subject": ((("commonName", "other.example.com"),),),
    }
    summary = summarize_certificate(certificate, "acme.com")
    assert summary["expired"] is True
    assert summary["hostname_mismatch"] is True
    assert summary["issuer"]["commonName"] == "Test CA"


def test_summarize_certificate_accepts_a_covering_wildcard():
    certificate = {"subjectAltName": (("DNS", "*.acme.com"),),
                   "notAfter": "Jan  1 00:00:00 2999 GMT"}
    summary = summarize_certificate(certificate, "api.acme.com")
    assert summary["hostname_mismatch"] is False
    assert summary["expired"] is False


# ------------------------------------------------------------------------- API

OPENAPI = {
    "openapi": "3.0.0",
    "info": {"title": "Acme", "version": "1.0"},
    "servers": [{"url": "https://api.acme.com/v1"}],
    "security": [{"bearerAuth": []}],
    "components": {"schemas": {"User": {"properties": {
        "name": {}, "role": {}, "is_admin": {},
    }}}},
    "paths": {
        "/users/{userId}": {
            "get": {"operationId": "getUser", "parameters": [
                {"name": "userId", "in": "path"}, {"name": "expand", "in": "query"},
            ]},
        },
        "/users": {
            "post": {
                "operationId": "createUser",
                "requestBody": {"content": {"application/json": {
                    "schema": {"$ref": "#/components/schemas/User"},
                }}},
            },
            "get": {"operationId": "listUsers", "security": []},
        },
    },
}


def test_parse_specification_extracts_endpoints_parameters_and_security():
    spec = parse_specification(OPENAPI, source="acme.json")
    assert spec.title == "Acme"
    assert spec.servers == ("https://api.acme.com/v1",)
    by_id = {item.operation_id: item for item in spec.endpoints}
    assert by_id["getUser"].path_parameters == ("userId",)
    assert by_id["getUser"].query_parameters == ("expand",)
    assert by_id["getUser"].object_parameters == ("userId",)
    assert by_id["getUser"].security == ("bearerAuth",)
    assert by_id["listUsers"].declared_public is True
    assert set(by_id["createUser"].request_properties) == {"name", "role", "is_admin"}


def test_parse_specification_recovers_templated_path_parameters_without_declarations():
    spec = parse_specification({
        "paths": {"/a/{id}/b/{sub}": {"get": {}}},
    })
    assert spec.endpoints[0].path_parameters == ("id", "sub")


def test_parse_specification_handles_swagger_2_host_and_body_parameter():
    spec = parse_specification({
        "swagger": "2.0", "host": "api.acme.com", "basePath": "/v2", "schemes": ["https"],
        "definitions": {"Thing": {"properties": {"id": {}, "label": {}}}},
        "paths": {"/things": {"post": {"parameters": [
            {"in": "body", "name": "body", "schema": {"$ref": "#/definitions/Thing"}},
        ]}}},
    })
    assert spec.servers == ("https://api.acme.com/v2",)
    assert set(spec.endpoints[0].request_properties) == {"id", "label"}


@pytest.mark.parametrize("document", [None, "text", {}, {"paths": {}}, {"paths": {"/x": {}}}])
def test_parse_specification_rejects_unusable_documents(document):
    with pytest.raises(SpecificationError):
        parse_specification(document)


def test_unresolved_schema_reference_is_warned_not_silently_dropped():
    spec = parse_specification({
        "paths": {"/x": {"post": {"requestBody": {"content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/Missing"},
        }}}}}},
    })
    assert any("Missing" in item for item in spec.warnings)


# ----------------------------------------------------------------------- cloud


def test_policy_review_flags_full_wildcard_grant():
    observations = review_policy_document({
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    })
    assert any(item.weakness == "wildcard-iam-grant" for item in observations)


def test_policy_review_flags_privilege_escalation_actions():
    observations = review_policy_document({
        "Statement": [{"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "*"}],
    })
    assert any(item.weakness == "iam-privilege-escalation" for item in observations)


def test_policy_review_flags_wildcard_principal():
    observations = review_policy_document({
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                       "Resource": "arn:aws:s3:::bucket/*"}],
    })
    assert any(item.weakness == "public-resource-policy" for item in observations)


def test_policy_review_ignores_deny_statements():
    assert review_policy_document({
        "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
    }) == ()


def test_policy_review_downgrades_a_service_wildcard_below_full_admin():
    observations = review_policy_document({
        "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
    })
    assert [item.severity for item in observations] == ["medium"]


@pytest.mark.parametrize("document", [None, [], {}, "text", {"Statement": "bad"}])
def test_policy_review_tolerates_malformed_documents(document):
    assert review_policy_document(document) == ()


# -------------------------------------------------------------------- contract

CONTRACT = """
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint) balances;
    address owner;

    function setFee(uint fee) public onlyOwner { feeBps = fee; }

    function setTreasury(address t) public { treasury = t; }

    function withdraw() public {
        (bool ok, ) = msg.sender.call{value: balances[msg.sender]}("");
        balances[msg.sender] = 0;
    }

    function total() public view returns (uint) { return feeBps; }
}
"""


def test_parse_contract_recovers_functions_visibility_and_modifiers():
    functions = {item.name: item for item in parse_contract(CONTRACT, path="Vault.sol")}
    assert set(functions) == {"setFee", "setTreasury", "withdraw", "total"}
    assert functions["setFee"].modifiers == ("onlyOwner",)
    assert functions["setFee"].guarded is True
    assert functions["setTreasury"].guarded is False
    assert functions["setTreasury"].mutates_state is True
    assert functions["total"].mutates_state is False
    assert functions["setFee"].contract == "Vault"


def test_parse_contract_returns_nothing_for_non_contract_text():
    assert parse_contract("just some prose about functions") == ()


def test_parse_slither_normalizes_detectors():
    payload = json.dumps({"results": {"detectors": [{
        "check": "reentrancy-eth", "impact": "High", "confidence": "Medium",
        "description": "Reentrancy in withdraw()",
        "elements": [{"source_mapping": {"filename_short": "Vault.sol", "lines": [12]}}],
    }]}})
    observations = parse_slither(payload)
    assert len(observations) == 1
    assert observations[0].severity == "high"
    assert observations[0].subject == "Vault.sol:12"
    assert observations[0].weakness == "reentrancy-eth"


def test_parse_mythril_normalizes_issues():
    payload = json.dumps({"issues": [{
        "title": "Unprotected Ether Withdrawal", "severity": "High",
        "filename": "Vault.sol", "lineno": 20, "swc-id": "105",
        "description": "Anyone can withdraw",
    }]})
    observations = parse_mythril(payload)
    assert observations[0].severity == "high"
    assert observations[0].weakness == "105"


@pytest.mark.parametrize("payload", ["", "not json", "{}", "[]"])
def test_contract_tool_parsers_tolerate_garbage(payload):
    assert parse_slither(payload) == ()
    assert parse_mythril(payload) in ((), tuple())


# ------------------------------------------------------------------ executable


def test_shannon_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"aaaaaaaa") == 0.0
    assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)


def test_detect_format_identifies_elf_and_pe():
    elf = b"\x7fELF" + b"\x00" * 14 + struct.pack("<H", 0x3E) + b"\x00" * 32
    assert detect_format(elf) == ("elf", "x86-64")
    pe = bytearray(b"MZ" + b"\x00" * 0x3E)
    pe[0x3C:0x40] = struct.pack("<I", 0x40)
    pe += b"PE\x00\x00" + struct.pack("<H", 0x8664) + b"\x00" * 16
    assert detect_format(bytes(pe)) == ("pe", "x86-64")
    assert detect_format(b"random bytes") == ("unknown", "unknown")


def test_iter_strings_extracts_printable_runs():
    payload = b"\x00\x01hello world\x00xy\x00another-string\xff"
    assert list(iter_strings(payload)) == ["hello world", "another-string"]


def test_profile_binary_reports_packer_markers(tmp_path):
    path = tmp_path / "packed.bin"
    path.write_bytes(b"MZ" + b"\x00" * 100 + b"UPX!" + b"\x00" * 100)
    profile = profile_binary(path)
    assert profile.format == "pe"
    assert "UPX" in profile.packers
    assert profile.truncated is False


def test_parse_syft_normalizes_packages():
    payload = json.dumps({"artifacts": [
        {"name": "openssl", "version": "3.0.2", "type": "deb"},
        {"version": "no name"},
    ]})
    assert parse_syft(payload) == [{"name": "openssl", "version": "3.0.2", "type": "deb"}]
    assert parse_syft("not json") == []


def _build_asar(tmp_path, files):
    index = {"files": {}}
    blob = b""
    for name, content in files.items():
        index["files"][name] = {"offset": str(len(blob)), "size": len(content)}
        blob += content
    header = json.dumps(index).encode("utf-8")
    padded = header + b"\x00" * ((4 - len(header) % 4) % 4)
    path = tmp_path / "app.asar"
    path.write_bytes(
        struct.pack("<IIII", 4, len(padded) + 8, len(padded) + 4, len(header))
        + padded + blob
    )
    return path


def test_extract_asar_writes_bundle_members(tmp_path):
    path = _build_asar(tmp_path, {
        "main.js": b"require('electron');\n", "package.json": b'{"name":"x"}',
    })
    destination = tmp_path / "out"
    count = extract_asar(path, destination)
    assert count == 2
    assert (destination / "main.js").read_bytes() == b"require('electron');\n"


def test_extract_asar_rejects_a_traversing_member(tmp_path):
    path = _build_asar(tmp_path, {"../escape.js": b"bad"})
    with pytest.raises(ValueError, match="escapes"):
        extract_asar(path, tmp_path / "out")


def test_extract_asar_rejects_a_non_asar_file(tmp_path):
    path = tmp_path / "short.bin"
    path.write_bytes(b"MZ")
    with pytest.raises(ValueError):
        extract_asar(path, tmp_path / "out")


def test_zip_bundles_refuse_traversal(tmp_path):
    from aegis.arsenal.assets.executable import _extract_zip

    archive = tmp_path / "b.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../escape.js", "bad")
    with pytest.raises(ValueError, match="escapes"):
        _extract_zip(archive, tmp_path / "out")
