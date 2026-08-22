"""Hosted product API tests — TestClient + injected fake ports, no engine/network/Docker."""

from __future__ import annotations

import time

from aegis.products.ports import Ports


def _row(cwe, file="app/x.py", line=10, sev="high"):
    return {"json_answer": {"vulnerability_type": cwe, "file_path": file, "line": line,
                            "summary": f"{cwe} at {file}"}, "severity": sev, "source": "test"}


def _fake_validate(report, repo_dir):
    for r in report.get("vulnerabilities", []):
        cwe = (r.get("json_answer") or {}).get("vulnerability_type", "")
        v = "confirmed" if "REAL" in cwe else "false_positive" if "FAKE" in cwe else "unresolved"
        r["validation"] = {"verdict": v, "reason": f"test:{v}", "confidence": 0.9}
        r["validation_status"] = v
    return report


def _fake_reproduce(report, repo_dir, **kw):
    trig = str(repo_dir).endswith("-triggers")
    for r in report.get("vulnerabilities", []):
        if (r.get("validation") or {}).get("verdict") == "confirmed":
            r["reproduction"] = {"verdict": "reproduced" if trig else "refuted"}
    return {"attempted": True}


def _fake_hunt(repo, *, repo_dir=None, files=12, samples=2, include_paths=None, **kw):
    rows = [_row("REAL-CWE-89"), _row("FAKE-CWE-79", file="app/y.py")]
    return _fake_validate({"scan": {"repository": repo}, "vulnerabilities": rows}, repo_dir or "h")


def _fake_ports():
    return Ports(hunt=_fake_hunt, validate_report=_fake_validate, reproduce_report=_fake_reproduce,
                 dedupe=lambda rows: rows, corroborate=lambda rows: rows)


def _wait(client, headers, job_id, timeout=6.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(f"/products/jobs/{job_id}", headers=headers)
        assert r.status_code == 200, r.text
        body = r.json()
        if body["status"] in ("completed", "failed"):
            return body
        time.sleep(0.02)
    raise AssertionError("job did not finish in time")


def test_products_api_requires_auth(client):
    assert client.post("/products/triage", json={"reports": []}).status_code in (401, 403)


def test_products_api_triage_job(client, agent_headers):
    client.app.state.product_ports = _fake_ports()
    reports = [_row("REAL-CWE-89"), _row("REAL-CWE-89", line=11), _row("FAKE-CWE-79", file="a/y.py")]
    r = client.post("/products/triage", headers=agent_headers,
                    json={"reports": reports, "repo_dir": "app", "validate_reports": True})
    assert r.status_code == 202
    done = _wait(client, agent_headers, r.json()["job_id"])
    assert done["status"] == "completed"
    st = done["result"]["stats"]
    assert st["received"] == 3 and st["unique"] == 2 and st["duplicates"] == 1


def test_products_api_proof_vuln_reproduces(client, agent_headers):
    client.app.state.product_ports = _fake_ports()
    r = client.post("/products/proof-vuln", headers=agent_headers,
                    json={"finding": _row("REAL-CWE-89"), "repo_dir": "app-triggers"})
    done = _wait(client, agent_headers, r.json()["job_id"])
    assert done["status"] == "completed"
    assert done["result"]["findings"][0]["evidence"]["verdict"] == "reproduced"


def test_products_api_autopilot_ships_conclusions(client, agent_headers):
    client.app.state.product_ports = _fake_ports()
    r = client.post("/products/autopilot", headers=agent_headers,
                    json={"repo": "o/r", "repo_dir": "checkout-triggers"})
    done = _wait(client, agent_headers, r.json()["job_id"])
    verdicts = {f["evidence"]["verdict"] for f in done["result"]["findings"]}
    assert verdicts <= {"confirmed", "reproduced"}
    assert all("FAKE" not in f["cwe"] for f in done["result"]["findings"])


def test_products_api_job_isolation_and_404(client, agent_headers):
    client.app.state.product_ports = _fake_ports()
    assert client.get("/products/jobs/does-not-exist", headers=agent_headers).status_code == 404
