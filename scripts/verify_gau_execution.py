import argparse
import hashlib
import json
import socket
import subprocess
import threading
from pathlib import Path

from aegis.adapters.contract import ExecutionEnvelope
from aegis.adapters.gau import GAU_MANIFEST, GauAdapter, GauConfig

MOCK_PORT = 19998

def get_file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

def handle_proxy_client(sock: socket.socket):
    try:
        req = sock.recv(4096).decode("latin1", errors="ignore")
        if not req:
            sock.close()
            return
        line0 = req.splitlines()[0] if req else ""
        if line0.startswith("CONNECT"):
            sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            inner = sock.recv(4096).decode("latin1", errors="ignore")
            if "collinfo.json" in inner:
                indexes = [{"id": "CC-AEGIS-TEST", "cdx-api": f"http://index.commoncrawl.org:{MOCK_PORT}/CC-INDEX"}]
                resp_body = json.dumps(indexes).encode()
                headers = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: " + str(len(resp_body)).encode() + b"\r\n\r\n"
                )
                sock.sendall(headers + resp_body)
            elif "showNumPages=true" in inner:
                if "non-existent" in inner:
                    resp_body = json.dumps({"pages": 0, "pageSize": 10, "actual_size": 0}).encode()
                else:
                    resp_body = json.dumps({"pages": 1, "pageSize": 10, "actual_size": 4}).encode()
                headers = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: " + str(len(resp_body)).encode() + b"\r\n\r\n"
                )
                sock.sendall(headers + resp_body)
            elif "CC-INDEX" in inner:
                if "non-existent" in inner:
                    resp_body = b""
                else:
                    items = [
                        {"url": "http://synthetic.target.internal/api/v1/auth.json", "timestamp": "20240101120000"},
                        {"url": "http://synthetic.target.internal/admin/dashboard.html", "timestamp": "20240102120000"},
                        {"url": "http://synthetic.target.internal/swagger.json", "timestamp": "20240103120000"},
                        {"url": "http://synthetic.target.internal/backup.zip", "timestamp": "20240105120000"},
                    ]
                    lines = [json.dumps(it) for it in items]
                    resp_body = ("\n".join(lines) + "\n").encode()
                headers = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: " + str(len(resp_body)).encode() + b"\r\n\r\n"
                )
                sock.sendall(headers + resp_body)
    except Exception:
        pass
    finally:
        sock.close()

def start_mock_proxy_server():
    srv = socket.socket()
    srv.bind(("127.0.0.1", MOCK_PORT))
    srv.listen(20)

    def run_srv():
        while True:
            try:
                conn, _ = srv.accept()
                threading.Thread(target=handle_proxy_client, args=(conn,), daemon=True).start()
            except:
                break

    t = threading.Thread(target=run_srv, daemon=True)
    t.start()
    return srv

def parse_args():
    parser = argparse.ArgumentParser(description="Verify gau execution")
    parser.add_argument("--binary", default=None, help="Path to gau binary")
    parser.add_argument("--output-dir", default="runs/evidence/gau", help="Evidence output directory")
    return parser.parse_args()

def make_envelope(target: str, task_id: str, checksum: str) -> ExecutionEnvelope:
    return ExecutionEnvelope(
        tenant_id="tenant-local",
        engagement_id="eng-local",
        scan_id="scan-gau-001",
        stage_id="stage-recon",
        task_id=task_id,
        target=target,
        scope_digest="scope-digest-123",
        adapter_name=GAU_MANIFEST.name,
        adapter_version=GAU_MANIFEST.version,
        adapter_checksum=checksum,
        adapter_license=GAU_MANIFEST.license,
        capability_tier=GAU_MANIFEST.capability_tier,
        network_profile=GAU_MANIFEST.network_profile,
        idempotency_key=f"key-{task_id}",
    )

def main():
    args = parse_args()
    evidence_dir = Path(args.output_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    if args.binary:
        gau_exe = Path(args.binary).resolve()
    elif Path("bin/gau.exe").is_file():
        gau_exe = Path("bin/gau.exe").resolve()
    elif Path("bin/gau").is_file():
        gau_exe = Path("bin/gau").resolve()
    else:
        gau_exe = Path("gau")

    gau_sha256 = get_file_sha256(gau_exe) if gau_exe.is_file() else "unknown"
    print(f"=== GAU Execution and Verification: {gau_exe} (SHA256={gau_sha256}) ===")

    srv = start_mock_proxy_server()
    print(f"Mock archive web fixture active on port {MOCK_PORT}")

    adapter = GauAdapter(
        executable=str(gau_exe),
        digest=gau_sha256,
        config=GauConfig(providers=("commoncrawl",), max_results=100)
    )

    # 1. Positive Run
    envelope_pos = make_envelope("synthetic.target.internal", "task-gau-pos-001", gau_sha256)
    pos_cmd = [
        str(gau_exe),
        "--json",
        "--providers", "commoncrawl",
        "--proxy", f"http://127.0.0.1:{MOCK_PORT}",
        envelope_pos.target
    ]
    print(f"\n[1/2] Executing positive run: {' '.join(pos_cmd)}")
    pos_proc = subprocess.run(pos_cmd, capture_output=True, text=True, timeout=15)
    
    pos_lines = [l for l in pos_proc.stdout.splitlines() if l.strip()]
    parsed_events = []
    for line in pos_lines:
        ev = adapter.parse_line(line, envelope_pos)
        if ev:
            parsed_events.append({
                "kind": ev.kind.value,
                "source": ev.source,
                "data": ev.data,
                "confidence": ev.confidence
            })

    print("Positive run complete:")
    print(f" - Exit code: {pos_proc.returncode}")
    print(f" - Stdout lines: {len(pos_lines)}")
    print(f" - Parsed ASSET events: {len(parsed_events)}")
    assert pos_proc.returncode == 0, f"Positive run failed with exit code {pos_proc.returncode}"
    assert len(pos_lines) > 0, "Positive run emitted 0 lines"
    assert len(parsed_events) > 0, "Adapter parsed 0 ASSET events"
    assert parsed_events[0]["kind"] == "asset"
    assert parsed_events[0]["data"]["asset_type"] == "url"
    for ev in parsed_events:
        print(f"   -> Found asset: {ev['data']['identifier']} (provider={ev['data']['provider']})")

    # Save positive artifacts
    with open(evidence_dir / "positive_stdout.jsonl", "w", encoding="utf-8") as f:
        f.write(pos_proc.stdout)
    with open(evidence_dir / "positive_events.json", "w", encoding="utf-8") as f:
        json.dump(parsed_events, f, indent=2)

    # 2. Negative Run (Control: non-existent target)
    envelope_neg = make_envelope("non-existent-domain.internal", "task-gau-neg-001", gau_sha256)
    neg_cmd = [
        str(gau_exe),
        "--json",
        "--providers", "commoncrawl",
        "--proxy", f"http://127.0.0.1:{MOCK_PORT}",
        envelope_neg.target
    ]
    print(f"\n[2/2] Executing negative control: {' '.join(neg_cmd)}")
    neg_proc = subprocess.run(neg_cmd, capture_output=True, text=True, timeout=15)
    
    neg_lines = [l for l in neg_proc.stdout.splitlines() if l.strip()]
    neg_events = []
    for line in neg_lines:
        ev = adapter.parse_line(line, envelope_neg)
        if ev:
            neg_events.append(ev.data)

    print("Negative control complete:")
    print(f" - Exit code: {neg_proc.returncode}")
    print(f" - Stdout lines: {len(neg_lines)}")
    print(f" - Parsed events: {len(neg_events)}")
    assert neg_proc.returncode == 0, f"Negative run failed with exit code {neg_proc.returncode}"
    assert len(neg_lines) == 0, f"Negative run emitted unexpected lines: {neg_lines}"
    assert len(neg_events) == 0

    with open(evidence_dir / "negative_stdout.txt", "w", encoding="utf-8") as f:
        f.write(neg_proc.stdout)

    summary = {
        "backend": "external:gau",
        "status": "EXECUTED_PASS",
        "binary": {
            "path": str(gau_exe),
            "sha256": gau_sha256,
            "version": "2.2.4"
        },
        "positive_run": {
            "target": envelope_pos.target,
            "cli": pos_cmd,
            "exit_code": pos_proc.returncode,
            "stdout_lines_total": len(pos_lines),
            "parsed_asset_events_total": len(parsed_events),
            "sample_urls": [e["data"]["identifier"] for e in parsed_events]
        },
        "negative_run": {
            "target": envelope_neg.target,
            "cli": neg_cmd,
            "exit_code": neg_proc.returncode,
            "stdout_lines_total": len(neg_lines),
            "events_count": len(neg_events)
        }
    }
    with open(evidence_dir / "execution_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    srv.close()
    print(f"\nGAU verified and native artifacts recorded to {evidence_dir}:")
    print(f" - {evidence_dir / 'positive_stdout.jsonl'}")
    print(f" - {evidence_dir / 'positive_events.json'}")
    print(f" - {evidence_dir / 'negative_stdout.txt'}")
    print(f" - {evidence_dir / 'execution_summary.json'}")

if __name__ == "__main__":
    main()
