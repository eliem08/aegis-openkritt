"""Build a signed, bounded offline-source campaign manifest.

This helper never fetches program policy or source artifacts. It accepts a fresh
authoritative ProgramSnapshot and an operator-acquired source checkout, verifies
that the exact repository is an eligible source-code scope row, and emits the
typed campaign input consumed by ``aegis production operator campaign``.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

from aegis.ai.jarvis.hunter_techniques import TECHNIQUES, HunterTechnique
from aegis.ingest.source import ProgramSnapshot
from aegis.policy.signing import Ed25519Signer
from aegis.production.campaign_runner import (
    OperatorTechniqueApproval,
    sign_operator_approval,
)
from aegis.production.operator_manifest import document_digest
from aegis.production.operator_workflow import policy_snapshot_document


def _files(root: Path, *, max_files: int, max_bytes: int) -> dict[str, str]:
    selected: dict[str, str] = {}
    consumed = 0
    candidates: list[Path] = []
    for directory, names, files in os.walk(root):
        names[:] = sorted(name for name in names if name != ".git")
        candidates.extend(
            Path(directory) / name
            for name in sorted(files)
            if Path(name).suffix.lower() in {".js", ".mjs", ".ts"}
        )
    candidates.sort()
    for path in candidates:
        data = path.read_bytes()
        if not data or consumed + len(data) > max_bytes:
            continue
        relative = path.relative_to(root).as_posix()
        selected[relative] = data.decode("utf-8", errors="replace")
        consumed += len(data)
        if len(selected) >= max_files:
            break
    if not selected:
        raise SystemExit("no bounded JavaScript/TypeScript source artifacts were selected")
    return selected


def _approval(
    signer: Ed25519Signer,
    *,
    campaign_id: str,
    technique: HunterTechnique,
    asset: str,
    valid_from: datetime,
    valid_until: datetime,
) -> dict:
    approval = sign_operator_approval(OperatorTechniqueApproval(
        approval_id=(
            "approval:" + sha256(
                f"{campaign_id}\x1f{technique.value}\x1f{asset}".encode()
            ).hexdigest()[:24]
        ),
        campaign_id=campaign_id,
        technique=technique,
        asset=asset,
        context="offline-source",
        identity_refs=(),
        valid_from=valid_from.isoformat(),
        valid_until=valid_until.isoformat(),
        key_id=signer.key_id,
    ), signer)
    value = approval.signing_payload()
    value.update({"key_id": approval.key_id, "signature": approval.signature})
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--asset", required=True)
    parser.add_argument("--operator-key-file", required=True)
    parser.add_argument("--operator-key-id", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--operator-id", default="operator")
    parser.add_argument("--max-files", type=int, default=200)
    parser.add_argument("--max-artifact-bytes", type=int, default=4_194_304)
    parser.add_argument("--max-duration-seconds", type=int, default=21_600)
    parser.add_argument("--max-cost-usd", type=float, default=10.0)
    args = parser.parse_args()

    snapshot = ProgramSnapshot.model_validate_json(Path(args.snapshot).read_text(encoding="utf-8"))
    matches = [row for row in snapshot.rules.in_scope if row.identifier == args.asset]
    if len(matches) != 1 or not matches[0].eligible_for_submission:
        raise SystemExit("exact source repository is not one explicitly eligible scope row")
    if matches[0].asset_type.value != "source_code":
        raise SystemExit("selected campaign asset is not typed as source_code")
    if snapshot.rules.submission_state.casefold() not in {"open", "active", "public"}:
        raise SystemExit("program is not currently open or active")
    if not snapshot.rules.automation_allowed or not snapshot.rules.ai_allowed:
        raise SystemExit("current program rules do not permit this automated AI-assisted campaign")
    now = datetime.now(UTC)
    if snapshot.authorization_expires_at <= now or now - snapshot.retrieved_at > timedelta(hours=1):
        raise SystemExit("program snapshot is stale or expired")

    source_root = Path(args.source_root).resolve()
    bundles = _files(
        source_root, max_files=args.max_files, max_bytes=args.max_artifact_bytes,
    )
    revision = "unknown"
    head = source_root / ".git" / "refs" / "heads" / "master"
    if head.is_file():
        revision = head.read_text(encoding="utf-8").strip()
    provenance = [
        f"authoritative_program_snapshot:{snapshot.source_hash}",
        f"source_repository:{args.asset}",
        f"source_revision:{revision}",
        f"artifact_count:{len(bundles)}",
        "acquisition_mode:git_shallow_sparse_checkout",
    ]
    policy_digest = document_digest(policy_snapshot_document(snapshot))
    evidence = {
        "source_reference": snapshot.source,
        "snapshot_timestamp": snapshot.retrieved_at.isoformat(),
        "snapshot_digest": policy_digest,
        "rule_id": "structured-scope:source-code:" + sha256(args.asset.encode()).hexdigest()[:16],
        "adapter_version": "hackerone-structured-source-code/1",
        "evidence_span": json.dumps(matches[0].model_dump(mode="json"), sort_keys=True),
    }
    signer = Ed25519Signer(
        Path(args.operator_key_file).read_text(encoding="utf-8").strip(),
        args.operator_key_id,
    )
    valid_until = min(
        snapshot.authorization_expires_at,
        now + timedelta(seconds=args.max_duration_seconds),
    )
    constraints = {"max_requests": 1, "max_cost_usd": args.max_cost_usd}
    route = HunterTechnique.JS_ROUTE_RECOVERY
    source_map = HunterTechnique.JS_SOURCE_MAP_RECOVERY
    techniques = [
        {
            "technique": route.value,
            "asset": args.asset,
            "context": "offline-source",
            "identity_refs": [],
            "execution_inputs": {
                "provenance_evidence": provenance,
                "bundles": {
                    f"{args.asset}/-/blob/{revision}/{name}": content
                    for name, content in bundles.items()
                },
                "source_maps": {},
                "scope_hosts": ["gitlab.com"],
            },
        },
        {
            "technique": source_map.value,
            "asset": args.asset,
            "context": "offline-source",
            "identity_refs": [],
            "execution_inputs": {
                "provenance_evidence": provenance,
                "bundles": {},
                "source_maps": {},
                "scope_hosts": ["gitlab.com"],
            },
        },
    ]
    permissions = [
        {
            "technique": technique.value,
            "asset": args.asset,
            "context": "offline-source",
            "effect": "permit",
            "policy_action": "source_analysis",
            "typed_constraints": constraints,
            "evidence": evidence,
        }
        for technique in (route, source_map)
    ]
    approvals = [
        _approval(
            signer, campaign_id=args.campaign_id, technique=technique,
            asset=args.asset, valid_from=now - timedelta(minutes=1),
            valid_until=valid_until,
        )
        for technique in (route, source_map)
    ]
    route_definition = TECHNIQUES[route]
    source_map_definition = TECHNIQUES[source_map]
    backends = [
        {
            "worker_capability": route_definition.worker_capability,
            "backend": "deterministic-networkless-javascript-intelligence",
            "backend_version": "1",
            "available": True,
            "safe": True,
            "enforceable_constraints": ["max_requests", "max_cost_usd"],
            "satisfied_prerequisites": list(route_definition.required_prerequisites),
        },
        {
            "worker_capability": source_map_definition.worker_capability,
            "backend": "deterministic-networkless-javascript-intelligence",
            "backend_version": "1",
            "available": False,
            "safe": True,
            "enforceable_constraints": ["max_requests", "max_cost_usd"],
            "satisfied_prerequisites": [],
            "unavailable_reason": "no authorized public source-map artifact was acquired",
        },
    ]
    document = {
        "schema_version": 1,
        "campaign_id": args.campaign_id,
        "operator_id": args.operator_id,
        "signing_key_ref": args.operator_key_id,
        "signing_key_path": str(Path(args.operator_key_file).resolve()),
        "budgets": {
            "max_requests": 1,
            "requests_per_second": 1.0,
            "max_cost_usd": args.max_cost_usd,
            "max_concurrent_sessions": 1,
            "max_duration_seconds": args.max_duration_seconds,
            "max_attempts": 2,
        },
        "techniques": techniques,
        "permissions": permissions,
        "approvals": approvals,
        "backends": backends,
        "artifact_summary": {
            "source_revision": revision,
            "file_count": len(bundles),
            "byte_count": sum(len(value.encode()) for value in bundles.values()),
            "source_maps_acquired": 0,
        },
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "campaign_manifest": str(output),
        "campaign_id": args.campaign_id,
        "asset": args.asset,
        "artifact_summary": document["artifact_summary"],
        "source_map_status": "UNAVAILABLE",
        "private_key_persisted": False,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
