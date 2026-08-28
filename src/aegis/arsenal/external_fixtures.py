"""Deterministic real-process fixtures for non-TOOLS arsenal backends.

These specifications describe fixture material and native-output parsers only.  They are
executed by :mod:`aegis.arsenal.tool_exercise`, after PolicyEngine authorization and signed
LOCAL_FIXTURE_ONLY grant verification, so this registry cannot become execution authority.
"""

from __future__ import annotations

import gzip
import json
import pickle
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Callable

from aegis.ai.tool_registry import Tool


@dataclass(frozen=True, slots=True)
class ExternalFixtureSpec:
    capability_id: str
    tool: Tool
    fixture_version: str
    materialize: Callable[[Path, Path], None]


def _row(source: str, summary: str, *, path: str = "", line: int = 0) -> dict:
    return {
        "json_answer": {
            "vulnerability_type": f"fixture:{source}",
            "file_path": path,
            "line": line,
            "summary": summary,
            "explanation": "Deterministic local positive-control observation.",
        },
        "severity": "low",
        "source": f"aegis:tool:{source}",
        "validation_status": "unverified",
        "confidence": 1.0,
    }


def _write(root: Path, name: str, value: str | bytes) -> None:
    destination = root / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, bytes):
        destination.write_bytes(value)
    else:
        destination.write_text(value, encoding="utf-8")


def _materialize_yara(positive: Path, negative: Path) -> None:
    rule = (
        "rule AegisFixtureMarker { strings: $marker = "
        '"AEGIS_YARA_POSITIVE_7A9F" condition: $marker }\n'
    )
    for root in (positive, negative):
        _write(root, "rules.yar", rule)
    _write(positive, "sample.bin", b"header\x00AEGIS_YARA_POSITIVE_7A9F\x00tail")
    _write(negative, "sample.bin", b"header\x00AEGIS_YARA_NEGATIVE\x00tail")


def _parse_yara(data) -> list[dict]:
    text = str(data.get("text", "")) if isinstance(data, dict) else ""
    return [
        _row("yara", line.split(maxsplit=1)[0], path="sample.bin")
        for line in text.splitlines() if line.strip().startswith("AegisFixtureMarker ")
    ]


def _materialize_syft(positive: Path, negative: Path) -> None:
    _write(
        positive,
        "package-lock.json",
        '{"name":"aegis-syft-positive","version":"1.0.0","lockfileVersion":3,'
        '"packages":{"":{"dependencies":{"lodash":"4.17.19"}},'
        '"node_modules/lodash":{"version":"4.17.19"}}}\n',
    )
    _write(negative, "README.txt", "No package metadata is present in this control.\n")


def _parse_syft(data) -> list[dict]:
    if not isinstance(data, dict):
        return []
    rows = []
    for artifact in data.get("artifacts", ()) or ():
        if not isinstance(artifact, dict):
            continue
        name = str(artifact.get("name") or "")
        version = str(artifact.get("version") or "")
        if name == "lodash" and version == "4.17.19":
            rows.append(_row("syft", "Expected lodash package present in generated SBOM"))
    return rows


def _materialize_zizmor(positive: Path, negative: Path) -> None:
    _write(
        positive,
        ".github/workflows/unsafe.yml",
        """name: unsafe
on: pull_request_target
permissions: write-all
jobs:
  unsafe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo \"${{ github.event.pull_request.title }}\"
""",
    )
    _write(
        negative,
        ".github/workflows/safe.yml",
        """name: safe
on: push
permissions:
  contents: read
jobs:
  safe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
        with:
          persist-credentials: false
      - run: echo fixture
""",
    )


def _parse_zizmor(data) -> list[dict]:
    """Accept zizmor JSON-v1 without assuming one minor release's envelope name."""
    if isinstance(data, list):
        findings = data
    elif isinstance(data, dict):
        findings = next((
            data[key] for key in ("findings", "results", "audits", "diagnostics")
            if isinstance(data.get(key), list)
        ), [])
    else:
        findings = []
    rows = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        audit = finding.get("audit") or finding.get("rule") or finding.get("ident") or "zizmor"
        # Use the analyzed filename without the repository metadata prefix. The
        # product-path noise filter intentionally excludes .github/, but this is a
        # dedicated CI-workflow capability whose deterministic fixture must remain
        # eligible for semantic-control evaluation.
        rows.append(_row("zizmor", str(audit), path="unsafe.yml"))
    return rows


def _materialize_spotbugs(positive: Path, negative: Path) -> None:
    _write(
        positive,
        "Fixture.java",
        """public final class Fixture {
  public static boolean broken(String value) {
    return value == \"AEGIS\";
  }
}
""",
    )
    _write(
        negative,
        "Fixture.java",
        """public final class Fixture {
  public static boolean safe(String value) {
    return \"AEGIS\".equals(value);
  }
}
""",
    )


def _parse_spotbugs(data) -> list[dict]:
    text = str(data.get("text", "")) if isinstance(data, dict) else ""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    rows = []
    for bug in root.findall(".//BugInstance"):
        bug_type = str(bug.attrib.get("type") or "SpotBugs")
        if bug_type in {
            "ES_COMPARING_STRINGS_WITH_EQ",
            "ES_COMPARING_PARAMETER_STRING_WITH_EQ",
        }:
            source = bug.find(".//SourceLine")
            rows.append(_row(
                "spotbugs", bug_type,
                path=str(source.attrib.get("sourcepath") or "Fixture.java") if source is not None
                else "Fixture.java",
                line=int(source.attrib.get("start") or 0) if source is not None else 0,
            ))
    return rows


def _materialize_loopback_port(positive: Path, negative: Path) -> None:
    _write(positive, "open-control", "start the controlled service\n")
    _write(negative, "closed-control", "leave the controlled port closed\n")


def _loopback_command(scanner: str) -> str:
    if scanner == "nmap":
        scan = "nmap -Pn -sV --version-light -p 48391 -oX - 127.0.0.1"
    else:
        scan = "rustscan -a 127.0.0.1 -p 48391 --ulimit 1000 --no-config"
    return (
        'cd "{target}" && pid=""; cleanup() {{ if test -n "$pid"; then '
        'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi; }}; '
        'trap cleanup EXIT INT TERM; '
        'if test -f open-control; then python -m http.server 48391 '
        '--bind 127.0.0.1 >server.log 2>&1 & pid=$!; sleep 1; fi; '
        f'{scan}; code=$?; exit "$code"'
    )


def _parse_nmap(data) -> list[dict]:
    text = str(data.get("text", "")) if isinstance(data, dict) else ""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    return [
        _row("nmap", "Expected controlled loopback port is open", path="127.0.0.1:48391")
        for port in root.findall(".//port")
        if port.attrib.get("portid") == "48391"
        and (port.find("state") is not None)
        and port.find("state").attrib.get("state") == "open"
    ]


def _parse_rustscan(data) -> list[dict]:
    text = str(data.get("text", "")) if isinstance(data, dict) else ""
    marker = "127.0.0.1:48391"
    return [
        _row("rustscan", "Expected controlled loopback port is open", path=marker)
    ] if marker in text and "open" in text.casefold() else []


def _loopback_http_command(scanner: str) -> str:
    if scanner == "httpx":
        scan = (
            "printf '%s\\n' http://127.0.0.1:48391 | "
            "httpx -silent -json -status-code -timeout 2 -retries 0"
        )
    else:
        scan = (
            "naabu -host 127.0.0.1 -p 48391 -silent -json -no-stdin "
            "-rate 10 -timeout 1000 -retries 0"
        )
    return (
        'cd "{target}" && pid=""; cleanup() {{ if test -n "$pid"; then '
        'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi; }}; '
        'trap cleanup EXIT INT TERM; '
        'if test -f open-control; then python -m http.server 48391 '
        '--bind 127.0.0.1 >server.log 2>&1 & pid=$!; sleep 1; fi; '
        f'{scan}; code=$?; exit "$code"'
    )


def _parse_httpx(data) -> list[dict]:
    rows = data if isinstance(data, list) else [data]
    return [
        _row("httpx", "Controlled HTTP service responded", path="127.0.0.1:48391")
        for item in rows if isinstance(item, dict)
        and int(item.get("status_code") or 0) == 200
        and "127.0.0.1:48391" in str(item.get("url") or item.get("input") or "")
    ]


def _parse_naabu(data) -> list[dict]:
    rows = data if isinstance(data, list) else [data]
    return [
        _row("naabu", "Controlled loopback port is open", path="127.0.0.1:48391")
        for item in rows if isinstance(item, dict)
        and int(item.get("port") or 0) == 48391
        and str(item.get("host") or item.get("ip") or "") == "127.0.0.1"
    ]


def _websocat_command() -> str:
    return (
        'cd "{target}" && pid=""; cleanup() {{ if test -n "$pid"; then '
        'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi; }}; '
        'trap cleanup EXIT INT TERM; '
        'if test -f open-control; then websocat -E --text ws-l:127.0.0.1:48393 mirror: '
        '>server.log 2>&1 & pid=$!; sleep 1; fi; '
        "printf '%s\\n' AEGIS_WEBSOCKET_ECHO_CONTROL | "
        'timeout 5 websocat -n1 ws://127.0.0.1:48393 2>/dev/null || true'
    )


def _parse_websocat(data) -> list[dict]:
    text = str(data.get("text", "")) if isinstance(data, dict) else ""
    return [
        _row("websocat", "Controlled WebSocket echo round trip succeeded", path="127.0.0.1:48393")
    ] if "AEGIS_WEBSOCKET_ECHO_CONTROL" in text else []


def _materialize_grpcurl(positive: Path, negative: Path) -> None:
    proto = """syntax = "proto3";
package aegis.fixture;
service Greeter { rpc Ping (PingRequest) returns (PingReply); }
message PingRequest { string value = 1; }
message PingReply { string value = 1; }
"""
    server = """from concurrent import futures
import grpc
from grpc_reflection.v1alpha import reflection
import fixture_pb2
import fixture_pb2_grpc

class Greeter(fixture_pb2_grpc.GreeterServicer):
    def Ping(self, request, context):
        return fixture_pb2.PingReply(value=request.value)

server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
fixture_pb2_grpc.add_GreeterServicer_to_server(Greeter(), server)
service = fixture_pb2.DESCRIPTOR.services_by_name["Greeter"].full_name
reflection.enable_server_reflection((service, reflection.SERVICE_NAME), server)
server.add_insecure_port("127.0.0.1:48394")
server.start()
server.wait_for_termination()
"""
    for root in (positive, negative):
        _write(root, "fixture.proto", proto)
        _write(root, "server.py", server)
    _write(positive, "open-control", "start the controlled gRPC service\n")
    _write(negative, "closed-control", "leave the controlled gRPC port closed\n")


def _grpcurl_command() -> str:
    return (
        'cd "{target}" && python -m grpc_tools.protoc -I. --python_out=. '
        '--grpc_python_out=. fixture.proto && pid=""; cleanup() {{ if test -n "$pid"; then '
        'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi; }}; '
        'trap cleanup EXIT INT TERM; if test -f open-control; then python server.py '
        '>server.log 2>&1 & pid=$!; sleep 1; fi; '
        'grpcurl -plaintext -max-time 3 127.0.0.1:48394 list 2>/dev/null || true'
    )


def _parse_grpcurl(data) -> list[dict]:
    text = str(data.get("text", "")) if isinstance(data, dict) else ""
    return [
        _row("grpcurl", "Controlled reflected gRPC service discovered", path="127.0.0.1:48394")
    ] if "aegis.fixture.Greeter" in text else []


def _materialize_apktool(positive: Path, negative: Path) -> None:
    apktool_yml = """version: 3.0.3
apkFileName: fixture.apk
isFrameworkApk: false
usesFramework:
  ids:
  - 1
sdkInfo:
  minSdkVersion: '21'
  targetSdkVersion: '28'
packageInfo:
  forcedPackageId: '127'
versionInfo:
  versionCode: 1
  versionName: '1.0'
doNotCompress: []
"""
    for root, debuggable in ((positive, "true"), (negative, "false")):
        _write(root, "fixture-src/apktool.yml", apktool_yml)
        _write(
            root,
            "fixture-src/AndroidManifest.xml",
            """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="org.aegis.fixture">
  <application android:label="Aegis Fixture" android:debuggable="%s" />
</manifest>
""" % debuggable,
        )


def _parse_apktool(data) -> list[dict]:
    text = str(data.get("text", "")) if isinstance(data, dict) else ""
    return [
        _row("apktool", "Decoded manifest contains the expected debuggable control")
    ] if "AEGIS_APKTOOL_DEBUGGABLE_TRUE" in text else []


def _materialize_asar(positive: Path, negative: Path) -> None:
    _write(positive, "fixture-src/app.js", "const marker = 'AEGIS_ASAR_SENSITIVE_MARKER';\n")
    _write(negative, "fixture-src/app.js", "const marker = 'AEGIS_ASAR_CLEAN_MARKER';\n")


def _parse_asar(data) -> list[dict]:
    text = str(data.get("text", "")) if isinstance(data, dict) else ""
    return [
        _row("asar", "Extracted archive contains the expected controlled marker")
    ] if "AEGIS_ASAR_SENSITIVE_MARKER" in text else []


def _materialize_binwalk(positive: Path, negative: Path) -> None:
    payload = gzip.compress(b"AEGIS_BINWALK_GZIP_CONTROL\n", mtime=0)
    _write(positive, "firmware.bin", b"AEGISFW\x00" + payload + b"\x00END")
    _write(negative, "firmware.bin", b"AEGISFW\x00NO_EMBEDDED_SIGNATURE\x00END")


def _parse_binwalk(data) -> list[dict]:
    text = str(data.get("text", "")) if isinstance(data, dict) else ""
    return [
        _row("binwalk", "Embedded gzip stream detected", path="firmware.bin")
    ] if "gzip compressed data" in text.casefold() else []


def _materialize_web_ext(positive: Path, negative: Path) -> None:
    _write(
        positive,
        "manifest.json",
        '{"manifest_version":2,"name":"Aegis invalid fixture"}\n',
    )
    _write(
        negative,
        "manifest.json",
        '{"manifest_version":2,"name":"Aegis clean fixture","version":"1.0.0",'
        '"description":"Controlled lint fixture"}\n',
    )


def _parse_web_ext(data) -> list[dict]:
    if not isinstance(data, dict):
        return []
    errors = data.get("errors") or ()
    if isinstance(errors, int):
        messages = data.get("messages") or ()
        errors = messages if errors else ()
    return [
        _row("web-ext", "Extension manifest failed structural validation", path="manifest.json")
        for item in errors if isinstance(item, (dict, str))
    ]


def _materialize_modelscan(positive: Path, negative: Path) -> None:
    class UnsafeFixture:
        def __reduce__(self):
            return eval, ("2 + 2",)

    _write(positive, "model.pkl", pickle.dumps(UnsafeFixture(), protocol=4))
    _write(negative, "model.pkl", pickle.dumps({"aegis": "safe"}, protocol=4))


def _parse_modelscan(data) -> list[dict]:
    if not isinstance(data, dict):
        return []
    return [
        _row(
            "modelscan",
            str(issue.get("description") or "Unsafe serialized-model operation"),
            path=str(issue.get("source") or "model.pkl"),
        )
        for issue in data.get("issues", ()) or () if isinstance(issue, dict)
    ]


def _minimal_pe(*, nx_compat: bool) -> bytes:
    """Build a deterministic, parseable PE32 fixture without a cross-compiler."""
    dos = bytearray(0x80)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    optional = bytearray(0xE0)
    struct.pack_into("<H", optional, 0, 0x10B)
    struct.pack_into("<I", optional, 16, 0x1000)
    struct.pack_into("<I", optional, 20, 0x1000)
    struct.pack_into("<I", optional, 24, 0x2000)
    struct.pack_into("<I", optional, 28, 0x400000)
    struct.pack_into("<I", optional, 32, 0x1000)
    struct.pack_into("<I", optional, 36, 0x200)
    struct.pack_into("<HH", optional, 40, 4, 0)
    struct.pack_into("<I", optional, 56, 0x2000)
    struct.pack_into("<I", optional, 60, 0x200)
    struct.pack_into("<H", optional, 68, 3)
    struct.pack_into("<H", optional, 70, 0x0100 if nx_compat else 0)
    struct.pack_into("<I", optional, 92, 16)
    section = bytearray(40)
    section[:8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", section, 8, 1, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", section, 36, 0x60000020)
    image = bytes(dos) + b"PE\x00\x00" + coff + bytes(optional) + bytes(section)
    image += bytes(0x200 - len(image))
    return image + b"\xC3" + bytes(0x1FF)


def _materialize_pefile(positive: Path, negative: Path) -> None:
    _write(positive, "fixture.exe", _minimal_pe(nx_compat=False))
    _write(negative, "fixture.exe", _minimal_pe(nx_compat=True))


def _parse_pefile(data) -> list[dict]:
    if not isinstance(data, dict) or data.get("nx_compat") is not False:
        return []
    return [_row("pefile", "PE fixture lacks the NX_COMPAT mitigation", path="fixture.exe")]


def _materialize_npm_audit(positive: Path, negative: Path) -> None:
    lock = {
        "name": "aegis-npm-audit-fixture",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {"dependencies": {"lodash": "4.17.19"}},
            "node_modules/lodash": {"version": "4.17.19"},
        },
    }
    vulnerable = {
        "lodash": [{
                "source": 1106913,
                "name": "lodash",
                "title": "Aegis local advisory fixture",
                "url": "https://fixture.invalid/advisory",
                "severity": "high",
                "cwe": ["CWE-1321"],
                "cvss": {"score": 7.4, "vectorString": None},
                "vulnerable_versions": "<4.17.21",
        }],
    }
    server = """import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

RESPONSE = Path(__file__).with_name('advisory.json').read_bytes()
PACKUMENT = json.dumps({
    'name': 'lodash',
    'versions': {
        '4.17.19': {'name': 'lodash', 'version': '4.17.19'},
        '4.17.21': {'name': 'lodash', 'version': '4.17.21'},
    },
}).encode()

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('content-length', '0'))
        self.rfile.read(length)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(RESPONSE)))
        self.end_headers()
        self.wfile.write(RESPONSE)

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(PACKUMENT)))
        self.end_headers()
        self.wfile.write(PACKUMENT)

    def log_message(self, *args):
        return

HTTPServer(('127.0.0.1', 48401), Handler).serve_forever()
"""
    for root, advisory in ((positive, vulnerable), (negative, {})):
        _write(root, "package-lock.json", json.dumps(lock, sort_keys=True))
        _write(root, "package.json", json.dumps({"name": lock["name"], "version": "1.0.0"}))
        _write(root, "advisory.json", json.dumps(advisory, sort_keys=True))
        _write(root, "audit_server.py", server)


def _parse_npm_audit(data) -> list[dict]:
    if not isinstance(data, dict):
        return []
    vulnerabilities = data.get("vulnerabilities") or {}
    return [
        _row("npm", f"Local advisory matched dependency {name}", path="package-lock.json")
        for name, value in vulnerabilities.items() if isinstance(value, dict)
    ] if isinstance(vulnerabilities, dict) else []


def _materialize_kics(positive: Path, negative: Path) -> None:
    insecure = """apiVersion: v1
kind: Pod
metadata:
  name: aegis-positive
spec:
  hostNetwork: true
  containers:
    - name: fixture
      image: busybox:1.36
      securityContext:
        privileged: true
"""
    secure = """apiVersion: v1
kind: Pod
metadata:
  name: aegis-negative
spec:
  containers:
    - name: fixture
      image: busybox:1.36
      securityContext:
        allowPrivilegeEscalation: false
        privileged: false
        runAsNonRoot: true
        capabilities:
          drop: [ALL]
"""
    _write(positive, "pod.yml", insecure)
    _write(negative, "pod.yml", secure)


def _parse_kics(data) -> list[dict]:
    if not isinstance(data, dict):
        return []
    queries = data.get("queries") or ()
    return [
        _row(
            "kics",
            str(query.get("query_name") or query.get("queryName") or "KICS policy violation"),
            path="pod.yml",
        )
        for query in queries if isinstance(query, dict)
        and str(query.get("query_id") or query.get("queryId") or "")
        == "dd29336b-fe57-445b-a26e-e6aa867ae609"
    ]


def _materialize_angr(positive: Path, negative: Path) -> None:
    _write(
        positive,
        "fixture.c",
        """#include <stdio.h>
int main(int argc, char **argv) {
  if (argc == 7) { puts(argv[0]); } else { puts("aegis"); }
  return 0;
}
""",
    )
    _write(negative, "fixture.c", "int main(void) { return 0; }\n")


def _parse_angr(data) -> list[dict]:
    if not isinstance(data, dict) or int(data.get("branch_nodes") or 0) < 1:
        return []
    return [_row("angr", "A branch was recovered in the controlled main CFG", path="sample.elf")]


def _materialize_capa(positive: Path, negative: Path) -> None:
    _write(
        positive,
        "fixture.c",
        """#include <sys/socket.h>
volatile const char *marker = "AEGIS_CAPA_NETWORK_CONTROL";
int main(void) { return socket(AF_INET, SOCK_STREAM, 0) < 0; }
""",
    )
    _write(negative, "fixture.c", "int main(void) { return 0; }\n")


def _parse_capa(data) -> list[dict]:
    if not isinstance(data, dict):
        return []
    rules = data.get("rules")
    if not isinstance(rules, dict):
        meta = data.get("meta") or {}
        rules = meta.get("rules") if isinstance(meta, dict) else {}
    if not isinstance(rules, dict):
        return []
    matches = [name for name in rules if "socket" in str(name).casefold()]
    return [_row("capa", str(name), path="sample.elf") for name in matches]


def _materialize_schemathesis(positive: Path, negative: Path) -> None:
    schema = {
        "openapi": "3.0.3",
        "info": {"title": "Aegis controlled API", "version": "1.0.0"},
        "paths": {
            "/items": {
                "get": {
                    "operationId": "getItems",
                    "responses": {"200": {"description": "OK"}},
                },
            },
        },
    }
    server = """import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).parent
SCHEMA = (ROOT / 'openapi.json').read_bytes()
FAIL = (ROOT / 'fail-control').exists()

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/openapi.json':
            body, status = SCHEMA, 200
        elif self.path.startswith('/items'):
            body, status = b'{"items":[]}', 500 if FAIL else 200
        else:
            body, status = b'{}', 404
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return

HTTPServer(('127.0.0.1', 48402), Handler).serve_forever()
"""
    for root in (positive, negative):
        _write(root, "openapi.json", json.dumps(schema, sort_keys=True))
        _write(root, "server.py", server)
    _write(positive, "fail-control", "return a deterministic server error\n")


def _parse_schemathesis(data) -> list[dict]:
    text = str(data.get("text", "")) if isinstance(data, dict) else ""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    failures = sum(int(suite.attrib.get("failures") or 0) for suite in root.iter("testsuite"))
    errors = sum(int(suite.attrib.get("errors") or 0) for suite in root.iter("testsuite"))
    return [
        _row("schemathesis", "Controlled API violates not_a_server_error", path="/items")
    ] if failures + errors > 0 else []


def _oci_descriptor(content: bytes, media_type: str) -> dict:
    return {
        "mediaType": media_type,
        "digest": f"sha256:{sha256(content).hexdigest()}",
        "size": len(content),
    }


def _materialize_skopeo(positive: Path, negative: Path) -> None:
    for root, labels in (
        (positive, {"org.aegis.fixture.security-control": "missing"}),
        (negative, {"org.aegis.fixture.security-control": "present"}),
    ):
        config = json.dumps({
            "architecture": "amd64",
            "os": "linux",
            "config": {"Labels": labels},
            "rootfs": {"type": "layers", "diff_ids": []},
            "history": [],
        }, sort_keys=True, separators=(",", ":")).encode()
        config_descriptor = _oci_descriptor(
            config, "application/vnd.oci.image.config.v1+json",
        )
        manifest = json.dumps({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": config_descriptor,
            "layers": [],
        }, sort_keys=True, separators=(",", ":")).encode()
        manifest_descriptor = _oci_descriptor(
            manifest, "application/vnd.oci.image.manifest.v1+json",
        )
        manifest_descriptor["annotations"] = {"org.opencontainers.image.ref.name": "latest"}
        _write(root, "image/oci-layout", '{"imageLayoutVersion":"1.0.0"}')
        _write(root, "image/index.json", json.dumps({
            "schemaVersion": 2, "manifests": [manifest_descriptor],
        }, sort_keys=True))
        _write(root, f"image/blobs/sha256/{sha256(config).hexdigest()}", config)
        _write(root, f"image/blobs/sha256/{sha256(manifest).hexdigest()}", manifest)


def _parse_skopeo(data) -> list[dict]:
    if not isinstance(data, dict):
        return []
    labels = data.get("Labels") or {}
    return [
        _row("skopeo", "Controlled OCI security label is missing", path="image:latest")
    ] if isinstance(labels, dict) and labels.get("org.aegis.fixture.security-control") == "missing" else []


_SPECS = {
    "asset:yara/approved-rule-binary-scan": ExternalFixtureSpec(
        "asset:yara/approved-rule-binary-scan",
        Tool("YARA", "yara", ("binary",), 'yara "{target}/rules.yar" "{target}/sample.bin"',
             "BSD-3-Clause", _parse_yara, "text"),
        "yara-marker-v1", _materialize_yara,
    ),
    "asset:syft/artifact-sbom": ExternalFixtureSpec(
        "asset:syft/artifact-sbom",
        Tool("syft", "syft", ("deps",), 'syft "dir:{target}" -o json',
             "Apache-2.0", _parse_syft),
        "syft-npm-sbom-v1", _materialize_syft,
    ),
    "asset:zizmor/github-actions-security-audit": ExternalFixtureSpec(
        "asset:zizmor/github-actions-security-audit",
        Tool("zizmor", "zizmor", ("cicd",),
             'zizmor --offline --format=json --no-progress "{target}"',
             "MIT", _parse_zizmor),
        "zizmor-pull-request-target-v1", _materialize_zizmor,
    ),
    "asset:spotbugs/java-bytecode-static-analysis": ExternalFixtureSpec(
        "asset:spotbugs/java-bytecode-static-analysis",
        Tool("SpotBugs", "spotbugs", ("bytecode",),
             'cd "{target}" && mkdir -p classes && javac -d classes Fixture.java && '
             'spotbugs -textui -xml:withMessages -output /dev/stdout classes',
             "LGPL-2.1", _parse_spotbugs, "xml"),
        "spotbugs-string-equality-v1", _materialize_spotbugs,
    ),
    "asset:nmap/bounded-service-fingerprinting": ExternalFixtureSpec(
        "asset:nmap/bounded-service-fingerprinting",
        Tool("nmap", "nmap", ("network",), _loopback_command("nmap"),
             "Nmap", _parse_nmap, "xml"),
        "nmap-loopback-service-v1", _materialize_loopback_port,
    ),
    "asset:rustscan/bounded-fast-port-prefilter": ExternalFixtureSpec(
        "asset:rustscan/bounded-fast-port-prefilter",
        Tool("RustScan", "rustscan", ("network",), _loopback_command("rustscan"),
             "GPL-3.0", _parse_rustscan, "text"),
        "rustscan-loopback-port-v1", _materialize_loopback_port,
    ),
    "asset:httpx/http-service-enrichment": ExternalFixtureSpec(
        "asset:httpx/http-service-enrichment",
        Tool(
            "httpx", "httpx", ("network",), _loopback_http_command("httpx"),
            "MIT", _parse_httpx,
        ),
        "httpx-loopback-http-v1", _materialize_loopback_port,
    ),
    "asset:naabu/bounded-port-discovery": ExternalFixtureSpec(
        "asset:naabu/bounded-port-discovery",
        Tool(
            "naabu", "naabu", ("network",), _loopback_http_command("naabu"),
            "MIT", _parse_naabu,
        ),
        "naabu-loopback-port-v1", _materialize_loopback_port,
    ),
    "asset:websocat/websocket-protocol-observation": ExternalFixtureSpec(
        "asset:websocat/websocket-protocol-observation",
        Tool(
            "websocat", "websocat", ("websocket",), _websocat_command(),
            "MIT", _parse_websocat, "text",
        ),
        "websocat-loopback-echo-v1", _materialize_loopback_port,
    ),
    "asset:grpcurl/grpc-service-introspection": ExternalFixtureSpec(
        "asset:grpcurl/grpc-service-introspection",
        Tool(
            "grpcurl", "grpcurl", ("grpc",), _grpcurl_command(),
            "MIT", _parse_grpcurl, "text",
        ),
        "grpcurl-reflection-v1", _materialize_grpcurl,
    ),
    "asset:apktool/android-resource-and-manifest-decode": ExternalFixtureSpec(
        "asset:apktool/android-resource-and-manifest-decode",
        Tool(
            "apktool", "apktool", ("android",),
            'cd "{target}" && rm -rf decoded fixture.apk && '
            'apktool b fixture-src -o fixture.apk >/dev/null && '
            'apktool d -f -o decoded fixture.apk >/dev/null && '
            'if grep -q \'android:debuggable="true"\' decoded/AndroidManifest.xml; '
            'then echo AEGIS_APKTOOL_DEBUGGABLE_TRUE; fi',
            "Apache-2.0", _parse_apktool, "text",
        ),
        "apktool-debuggable-manifest-v1", _materialize_apktool,
    ),
    "asset:electron-asar/electron-package-extraction": ExternalFixtureSpec(
        "asset:electron-asar/electron-package-extraction",
        Tool(
            "electron-asar", "asar", ("electron",),
            'cd "{target}" && rm -rf extracted app.asar && '
            'asar pack fixture-src app.asar && asar extract app.asar extracted && '
            'if grep -q AEGIS_ASAR_SENSITIVE_MARKER extracted/app.js; '
            'then echo AEGIS_ASAR_SENSITIVE_MARKER; fi',
            "MIT", _parse_asar, "text",
        ),
        "asar-pack-extract-v1", _materialize_asar,
    ),
    "asset:binwalk/firmware-structure-analysis": ExternalFixtureSpec(
        "asset:binwalk/firmware-structure-analysis",
        Tool(
            "binwalk", "binwalk", ("firmware",), 'binwalk "{target}/firmware.bin"',
            "MIT", _parse_binwalk, "text",
        ),
        "binwalk-embedded-gzip-v1", _materialize_binwalk,
    ),
    "asset:web-ext/browser-extension-structure-lint": ExternalFixtureSpec(
        "asset:web-ext/browser-extension-structure-lint",
        Tool(
            "web-ext", "web-ext", ("browser_extension",),
            'web-ext lint --source-dir "{target}" --output=json --no-input --boring',
            "MPL-2.0", _parse_web_ext,
        ),
        "web-ext-invalid-manifest-v1", _materialize_web_ext,
    ),
    "asset:modelscan/serialized-model-safety-scan": ExternalFixtureSpec(
        "asset:modelscan/serialized-model-safety-scan",
        Tool(
            "ModelScan", "modelscan", ("ai_model",),
            'cd "{target}" && modelscan scan -p "{target}/model.pkl" -r json '
            '-o "{target}/report.json" >/dev/null 2>&1; cat "{target}/report.json"',
            "Apache-2.0", _parse_modelscan,
        ),
        "modelscan-unsafe-pickle-v1", _materialize_modelscan,
    ),
    "asset:pefile/pe-structure-analysis": ExternalFixtureSpec(
        "asset:pefile/pe-structure-analysis",
        Tool(
            "pefile", "pefile", ("executable",),
            'pefile "{target}/fixture.exe"', "MIT", _parse_pefile,
        ),
        "pefile-nx-compat-v1", _materialize_pefile,
    ),
    "asset:npm/npm-dependency-audit": ExternalFixtureSpec(
        "asset:npm/npm-dependency-audit",
        Tool(
            "npm", "npm", ("npm_package",),
            'cd "{target}" && (python audit_server.py & server=$!; sleep 0.25; '
            'npm audit --package-lock-only --json --registry=http://127.0.0.1:48401 '
            '> audit.json 2>/dev/null; kill "$server" 2>/dev/null || true; '
            'wait "$server" 2>/dev/null || true; cat audit.json; exit 0)',
            "Artistic-2.0", _parse_npm_audit,
        ),
        "npm-local-advisory-v1", _materialize_npm_audit,
    ),
    "asset:kics/iac-security-scan": ExternalFixtureSpec(
        "asset:kics/iac-security-scan",
        Tool(
            "KICS", "kics", ("kubernetes",),
            'cd "{target}" && rm -rf "{target}/results"; mkdir -p "{target}/results"; '
            'cd /opt/kics && kics scan -p "{target}/pod.yml" '
            '-o "{target}/results" --output-name kics --report-formats json '
            '--include-queries dd29336b-fe57-445b-a26e-e6aa867ae609 '
            '--no-progress --silent --ignore-on-exit results --disable-secrets; '
            'cat "{target}/results/kics.json"',
            "Apache-2.0", _parse_kics,
        ),
        "kics-kubernetes-policy-v1", _materialize_kics,
    ),
    "asset:angr/binary-control-flow-analysis": ExternalFixtureSpec(
        "asset:angr/binary-control-flow-analysis",
        Tool(
            "angr", "angr", ("executable",),
            'cd "{target}" && gcc -O0 -fno-inline -fno-if-conversion '
            '-fno-if-conversion2 -fno-pie -no-pie fixture.c -o fixture && angr fixture',
            "BSD-2-Clause", _parse_angr,
        ),
        "angr-main-cfg-branch-v1", _materialize_angr,
    ),
    "asset:capa/binary-capability-analysis": ExternalFixtureSpec(
        "asset:capa/binary-capability-analysis",
        Tool(
            "capa", "capa", ("executable",),
            'cd "{target}" && gcc -O0 fixture.c -o fixture && '
            'capa -j -r /opt/capa-rules fixture',
            "Apache-2.0", _parse_capa,
        ),
        "capa-network-socket-v1", _materialize_capa,
    ),
    "asset:schemathesis/schema-guided-api-testing": ExternalFixtureSpec(
        "asset:schemathesis/schema-guided-api-testing",
        Tool(
            "Schemathesis", "schemathesis", ("api",),
            'cd "{target}" && (python server.py & server=$!; sleep 0.4; '
            'schemathesis run openapi.json --url http://127.0.0.1:48402 '
            '--checks not_a_server_error --phases fuzzing -n 1 --seed 1 '
            '--generation-deterministic --workers 1 '
            '--rate-limit 5/s --request-timeout 1 --report junit '
            '--report-junit-path result.xml --no-color >/dev/null 2>&1 || true; '
            'kill "$server" 2>/dev/null || true; wait "$server" 2>/dev/null || true; '
            'cat result.xml)',
            "MIT", _parse_schemathesis, "xml",
        ),
        "schemathesis-openapi-500-v1", _materialize_schemathesis,
    ),
    "asset:skopeo/container-registry-metadata": ExternalFixtureSpec(
        "asset:skopeo/container-registry-metadata",
        Tool(
            "skopeo", "skopeo", ("docker_registry",),
            'skopeo inspect "oci:{target}/image:latest"',
            "Apache-2.0", _parse_skopeo,
        ),
        "skopeo-local-oci-label-v1", _materialize_skopeo,
    ),
}


def external_fixture_spec(capability_id: str) -> ExternalFixtureSpec | None:
    return _SPECS.get(capability_id)


def external_fixture_capability_ids() -> frozenset[str]:
    return frozenset(_SPECS)


__all__ = [
    "ExternalFixtureSpec", "external_fixture_capability_ids", "external_fixture_spec",
]
