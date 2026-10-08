import argparse
import hashlib
import json
import socket
import subprocess
import threading
from pathlib import Path

from aegis.adapters.contract import ExecutionEnvelope
from aegis.adapters.subfinder import SUBFINDER_MANIFEST, SubfinderAdapter, SubfinderConfig

MOCK_PORT = 19996

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
        
        target = req
        if "non-existent" in target or "invalid" in target:
            resp_body = b""
        else:
            # Wayback CDX format output=txt lines
            urls = [
                "http://api.synthetic.target.internal/v1/auth",
                "http://vpn.synthetic.target.internal/login",
                "http://admin.synthetic.target.internal/dashboard",
                "http://mail.synthetic.target.internal/webmail",
                "http://portal.synthetic.target.internal/sso",
            ]
            resp_body = ("\n".join(urls) + "\n").encode()

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
    parser = argparse.ArgumentParser(description="Verify subfinder execution")
    parser.add_argument("--binary", default=None, help="Path to subfinder binary")
    parser.add_argument("--output-dir", default="runs/evidence/subfinder", help="Evidence output directory")
    return parser.parse_args()

def make_envelope(target: str, task_id: str, checksum: str) -> ExecutionEnvelope:
    return ExecutionEnvelope(
        tenant_id="tenant-local",
        engagement_id="eng-local",
        scan_id="scan-subfinder-001",
        stage_id="stage-recon",
        task_id=task_id,
        target=target,
        scope_digest="scope-digest-123",
        adapter_name=SUBFINDER_MANIFEST.name,
        adapter_version=SUBFINDER_MANIFEST.version,
        adapter_checksum=checksum,
        adapter_license=SUBFINDER_MANIFEST.license,
        capability_tier=SUBFINDER_MANIFEST.capability_tier,
        network_profile=SUBFINDER_MANIFEST.network_profile,
        idempotency_key=f"key-{task_id}",
    )

def main():
    args = parse_args()
    evidence_dir = Path(args.output_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    if args.binary:
        subf_exe = Path(args.binary).resolve()
    elif Path("bin/subfinder.exe").is_file():
        subf_exe = Path("bin/subfinder.exe").resolve()
    elif Path("bin/subfinder").is_file():
        subf_exe = Path("bin/subfinder").resolve()
    else:
        subf_exe = Path("subfinder")

    subf_sha256 = get_file_sha256(subf_exe) if subf_exe.is_file() else "unknown"
    print(f"=== SUBFINDER Execution and Verification: {subf_exe} (SHA256={subf_sha256}) ===")

    srv = start_mock_proxy_server()
    print(f"Mock subdomain fixture server active on port {MOCK_PORT}")

    adapter = SubfinderAdapter(
        executable=str(subf_exe),
        digest=subf_sha256,
        config=SubfinderConfig(sources=("waybackarchive",), max_results=100)
    )

    # 1. Positive Run
    envelope_pos = make_envelope("synthetic.target.internal", "task-subfinder-pos-001", subf_sha256)
    pos_cmd = [
        str(subf_exe),
        "-d", envelope_pos.target,
        "-s", "waybackarchive",
        "-proxy", f"http://127.0.0.1:{MOCK_PORT}",
        "-json",
        "-silent"
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
    assert parsed_events[0]["data"]["asset_type"] == "domain"
    assert parsed_events[0]["data"]["parent_domain"] == envelope_pos.target
    for ev in parsed_events:
        print(f"   -> Discovered subdomain: {ev['data']['identifier']} (source={ev['data']['provider']})")

    # Save positive artifacts
    with open(evidence_dir / "positive_stdout.jsonl", "w", encoding="utf-8") as f:
        f.write(pos_proc.stdout)
    with open(evidence_dir / "positive_events.json", "w", encoding="utf-8") as f:
        json.dump(parsed_events, f, indent=2)

    # 2. Negative Run (Control: non-existent target)
    envelope_neg = make_envelope("non-existent-control.invalid", "task-subfinder-neg-001", subf_sha256)
    neg_cmd = [
        str(subf_exe),
        "-d", envelope_neg.target,
        "-s", "waybackarchive",
        "-proxy", f"http://127.0.0.1:{MOCK_PORT}",
        "-json",
        "-silent"
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
        "backend": "external:subfinder",
        "status": "EXECUTED_PASS",
        "binary": {
            "path": str(subf_exe),
            "sha256": subf_sha256,
            "version": "2.6.6"
        },
        "positive_run": {
            "target": envelope_pos.target,
            "cli": pos_cmd,
            "exit_code": pos_proc.returncode,
            "stdout_lines_total": len(pos_lines),
            "parsed_asset_events_total": len(parsed_events),
            "discovered_subdomains": [e["data"]["identifier"] for e in parsed_events]
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
    print(f"\nSUBFINDER verified and native artifacts recorded to {evidence_dir}:")
    print(f" - {evidence_dir / 'positive_stdout.jsonl'}")
    print(f" - {evidence_dir / 'positive_events.json'}")
    print(f" - {evidence_dir / 'negative_stdout.txt'}")
    print(f" - {evidence_dir / 'execution_summary.json'}")

if __name__ == "__main__":
    main()
