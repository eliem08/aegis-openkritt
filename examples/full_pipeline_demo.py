"""End-to-end money path: detect -> triage -> submission-ready report.

    python examples/full_pipeline_demo.py

Runs the DetectorWorker against a SIMULATED vulnerable target (no network), then
triages the candidates into findings and prepares a redacted, quality-gated,
HackerOne-ready report. Demonstrates the full revenue pipeline safely offline.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import httpx  # noqa: E402

from aegis.detect import DetectorWorker, Identity, default_registry  # noqa: E402
from aegis.model import AttackSurface, PlannedAction  # noqa: E402
from aegis.netgate import build_gated_client  # noqa: E402
from aegis.orchestrator import WorkerContext, triage  # noqa: E402
from aegis.report import prepare_submission  # noqa: E402

PUBLIC = lambda h: ["93.184.216.34"]  # noqa: E731


def vulnerable_target(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/users/1001":
        # object served to ANY authenticated user -> BOLA; contains a canary + PII
        return httpx.Response(200, text='{"email":"victim@corp.com","canary":"CANARY-7f3"}')
    if path == "/.git/config":
        return httpx.Response(200, text="[core]\n\trepositoryformatversion = 0\n")
    return httpx.Response(404)


def client_factory(target: str) -> httpx.Client:
    return build_gated_client(["api.acme.test"], inner=httpx.MockTransport(vulnerable_target), resolver=PUBLIC)


def main() -> None:
    print("=" * 72)
    print("full pipeline: detectors -> triage -> submission report (simulated target)")
    print("=" * 72)

    worker = DetectorWorker(
        default_registry(),
        client_factory=client_factory,
        identities=[Identity("user_a", {"Authorization": "Bearer A"}),
                    Identity("user_b", {"Authorization": "Bearer B"})],
    )
    action = PlannedAction(
        target="api.acme.test", action="authenticated_testing", worker="detector",
        params={"objects": [{"url": "/users/1001", "owner": "user_a", "canary": "CANARY-7f3"}]},
    )
    result = worker.run(action, WorkerContext(engagement_id="acme", surface=AttackSurface()))
    evidence_by_id = {e.evidence_id: e for e in result.evidence}
    tri = triage(result.candidates, evidence_by_id)

    print(f"\ndetectors -> {len(result.candidates)} candidate(s) -> "
          f"{len(tri.findings)} finding(s), {len(tri.hypotheses)} hypothesis(es)\n")

    for finding in tri.findings:
        ev = evidence_by_id.get(finding.exploit_proof_ref)
        pkg = prepare_submission(finding, ev, program_handle="acme", in_scope=True)
        blocking = [g["name"] for g in pkg.gate_results if not g["passed"]] or ["(all pass)"]
        print("-" * 72)
        print(f"{finding.cwe} {finding.route}  ssvc={finding.ssvc.value}  "
              f"submittable={pkg.submittable}  gates_failing={blocking}")
        print(pkg.markdown[:520])
        print("...")
    print("=" * 72)
    print("Submission stays HUMAN-APPROVED — this prepares reports, it does not send.")


if __name__ == "__main__":
    main()
