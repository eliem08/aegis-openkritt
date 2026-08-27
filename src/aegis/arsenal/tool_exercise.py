"""Real local scanner fixture execution through the canonical mission runtime."""

from __future__ import annotations

import os
import secrets
import tempfile
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from aegis.ai.agentic_os import AuthorizationEnvelope, Budget, mint_execution_grant
from aegis.ai.jarvis.asset_execution_ticket import CapabilityAvailability
from aegis.ai.jarvis.mission_capabilities import (
    ExecutionClass,
    MissionWorkerRegistry,
    WorkerCapability,
)
from aegis.ai.jarvis.mission_scheduler import MissionPlan, MissionScheduler, MissionTask
from aegis.ai.jarvis.state_store import JarvisStateStore
from aegis.ai.jarvis.universal_runtime import UniversalMissionRuntime
from aegis.ai.tool_bridge import ToolBridge
from aegis.ai.tool_registry import TOOLS
from aegis.ai.tool_runtime import ToolRuntimeManager
from aegis.policy.consequence import ConsequenceTier
from aegis.policy.decisions import ActionRequest
from aegis.policy.engine import PolicyEngine
from aegis.policy.signing import HmacSignatureVerifier
from aegis.production.operator_manifest import (
    ImmutableRunStore,
    OperatorRunManifest,
    RunBudgets,
    RunMode,
    RunStatus,
    document_digest,
)

from .exercise import ExerciseResult
from .fixture_authority import (
    LOCAL_FIXTURE_ONLY,
    LocalFixtureSignatureVerifier,
    signed_fixture_authorization,
)
from .inventory import ArsenalInventoryBuilder
from .ledger import CoverageRepository
from .models import ArsenalCoverageState, CapabilityCoverageRecord, CapabilityMode

TOOL_FIXTURE_CAPABILITY = "jarvis:arsenal:tool-fixture"

_POSITIVE_FIXTURES = {
    "app.py": "import os\ndef unsafe(value):\n    return os.system(value)\n",
    "app.js": (
        "const cp=require('child_process');\n"
        "const libxml=require('libxmljs');\n"
        "module.exports=(req,res)=>{ eval(req.body.code); "
        "libxml.parseXml(req.body.xml,{noent:true}); "
        "return cp.exec(req.body.cmd,(e,out)=>res.send(out)); };\n"
    ),
    "main.go": "package main\nimport (\"os/exec\")\nfunc main(){exec.Command(\"sh\",\"-c\",\"input\").Run()}\n",
    "unsafe.php": (
        "<?php $id=$_GET['id']; $pdo->query(\"SELECT * FROM users WHERE id=\".$id); "
        "system($_GET['cmd']);\n"
    ),
    "Contract.sol": (
        "pragma solidity ^0.8.0; contract Unsafe { mapping(address=>uint) b; "
        "function w() public {(bool ok,)=msg.sender.call{value:b[msg.sender]}(''); "
        "require(ok); b[msg.sender]=0;} }\n"
    ),
    "main.tf": (
        "resource \"aws_s3_bucket\" \"x\" { bucket=\"aegis-fixture\" }\n"
        "resource \"aws_s3_bucket_public_access_block\" \"x\" { "
        "bucket=aws_s3_bucket.x.id block_public_acls=false }\n"
    ),
    "package.json": (
        '{"name":"aegis-positive-fixture","version":"1.0.0",'
        '"dependencies":{"lodash":"4.17.19"}}\n'
    ),
    "Gemfile.lock": "GEM\n  specs:\n    rails (5.2.0)\nDEPENDENCIES\n  rails (= 5.2.0)\n",
    "Gemfile": "source 'https://rubygems.org'\ngem 'rails', '5.2.0'\n",
    "config/application.rb": (
        "require 'rails/all'\nmodule Fixture\n  class Application < Rails::Application; end\nend\n"
    ),
    "config/routes.rb": "Rails.application.routes.draw { get '/users', to: 'users#index' }\n",
    "app/controllers/users_controller.rb": (
        "class UsersController < ApplicationController\n"
        "  def index\n    render html: params[:content].html_safe\n  end\nend\n"
    ),
    "fixture-secrets.txt": (
        "AEGIS_FIXTURE_ONLY_AWS_ACCESS_KEY_ID=AKIAJ7M4Q2R8W6X9Z3KP\n"
        "AWS_SECRET_ACCESS_KEY='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"
        "AEGIS_FIXTURE_ONLY_GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwx\n"
        "AEGIS_FIXTURE_ONLY_HEX_SECRET="
        "2f5d4e9c7a1b3d8e6f0123456789abcdef0123456789abcdef0123456789abcd\n"
        "-----BEGIN PRIVATE KEY-----\nAEGIS-FIXTURE-NOT-A-REAL-KEY\n"
        "-----END PRIVATE KEY-----\n"
    ),
    "jquery-1.8.3.js": "/*! jQuery v1.8.3 | Aegis deterministic fixture */\n",
    "package-lock.json": (
        '{"name":"aegis-positive-fixture","version":"1.0.0","lockfileVersion":3,'
        '"packages":{"":{"dependencies":{"lodash":"4.17.19"}},'
        '"node_modules/lodash":{"version":"4.17.19"}},'
        '"dependencies":{"lodash":{"version":"4.17.19"}}}\n'
    ),
}
_NEGATIVE_FIXTURES = {
    "app.py": "def add(left: int, right: int) -> int:\n    return left + right\n",
    "app.js": "module.exports=(left,right)=>left+right;\n",
    "main.go": 'package main\nimport "fmt"\nfunc main(){fmt.Println("fixture")}\n',
    "safe.php": "<?php function add(int $a,int $b): int { return $a+$b; }\n",
    "Contract.sol": (
        "pragma solidity ^0.8.0; contract Safe { function add(uint a,uint b) "
        "public pure returns(uint){return a+b;} }\n"
    ),
    "main.tf": 'terraform { required_version = ">= 1.5.0" }\n',
    "package.json": '{"name":"aegis-negative-fixture","version":"1.0.0"}\n',
    "Gemfile": "source 'https://rubygems.org'\ngem 'rails', '7.2.0'\n",
    "config/application.rb": (
        "require 'rails/all'\nmodule Fixture\n  class Application < Rails::Application; end\nend\n"
    ),
    "config/routes.rb": "Rails.application.routes.draw { get '/users', to: 'users#index' }\n",
    "app/controllers/users_controller.rb": (
        "class UsersController < ApplicationController\n"
        "  def index\n    render plain: 'fixture'\n  end\nend\n"
    ),
    "fixture-secrets.txt": "AEGIS_FIXTURE_ONLY=true\n",
    "jquery-3.7.1.js": "/*! jQuery v3.7.1 | Aegis deterministic fixture */\n",
    "package-lock.json": (
        '{"name":"aegis-negative-fixture","version":"1.0.0",'
        '"lockfileVersion":3,"packages":{"":{"dependencies":{"lodash":"4.18.0"}},'
        '"node_modules/lodash":{"version":"4.18.0"}}}\n'
    ),
}


_FIXTURE_COMMANDS = {
    ("detect-secrets", "secrets"): (
        'cd "{target}" && detect-secrets scan --all-files --no-verify .'
    ),
    ("brakeman", "code"): (
        'brakeman -f json -q -x EOLRails "{target}"'
    ),
    ("checkov", "deps"): (
        'checkov -d "{target}" -o json --compact --quiet --skip-download'
    ),
    ("mythril", "contract"): 'myth analyze "{target}/Contract.sol" -o json',
    ("gitleaks", "secrets"): (
        'gitleaks detect --no-git --source "{target}" --report-format json '
        '--report-path /dev/stdout --exit-code 0'
    ),
    ("retire.js", "deps"): (
        'retire --outputformat json --path "{target}" '
        '--jsrepo /opt/aegis-data/retire/jsrepository.json'
    ),
    ("slither", "contract"): (
        'slither "{target}/Contract.sol" --exclude-low --exclude-informational --json -'
    ),
    ("osv-scanner", "deps"): (
        'osv-scanner scan source --offline --format json --lockfile "{target}/package-lock.json"'
    ),
    ("grype", "deps"): (
        'grype "dir:{target}" -o json'
    ),
    ("trivy", "deps"): (
        'trivy fs --scanners vuln --skip-db-update --offline-scan '
        '--format json --quiet "{target}"'
    ),
    ("trivy", "secrets"): (
        'trivy fs --scanners secret --skip-db-update --format json --quiet "{target}"'
    ),
}

# A shared binary execution may cover another canonical capability only when this exact
# positive/negative fixture validates the same semantics. Image/container modes are excluded.
_EQUIVALENT_CAPABILITIES = {
    "tool:bandit/code": ("asset:bandit/python-security-static-analysis",),
    "tool:brakeman/code": ("asset:brakeman/rails-security-static-analysis",),
    "tool:checkov/deps": ("asset:checkov/iac-cicd-and-container-policy-scan",),
    "tool:gitleaks/secrets": ("asset:gitleaks/git-secret-detection",),
    "tool:gosec/code": ("asset:gosec/go-security-static-analysis",),
    "tool:grype/deps": ("asset:grype/artifact-vulnerability-scan",),
    "tool:mythril/contract": ("asset:mythril/evm-symbolic-execution",),
    "tool:osv-scanner/deps": ("asset:osv-scanner/dependency-vulnerability-analysis",),
    "tool:semgrep/code": ("asset:semgrep/source-static-analysis",),
    "tool:slither/contract": ("asset:slither/solidity-vyper-static-analysis",),
    "tool:trivy/deps": ("asset:trivy/filesystem-security-scan",),
}


def equivalent_capability_ids(capability_id: str) -> tuple[str, ...]:
    """Return exact canonical aliases covered by the same fixture execution."""
    return _EQUIVALENT_CAPABILITIES.get(capability_id, ())


def _materialize_builtin_fixtures() -> tuple[tempfile.TemporaryDirectory, Path]:
    temporary = tempfile.TemporaryDirectory(prefix="aegis-arsenal-fixture-")
    root = Path(temporary.name)
    for control, documents in (("positive", _POSITIVE_FIXTURES),
                               ("negative", _NEGATIVE_FIXTURES)):
        directory = root / control
        directory.mkdir()
        for name, content in documents.items():
            destination = directory / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content, encoding="utf-8")
    return temporary, root


def _directory_digest(path: Path) -> str:
    rows = []
    for item in sorted(candidate for candidate in path.rglob("*") if candidate.is_file()):
        rows.append({
            "path": item.relative_to(path).as_posix(),
            "sha256": sha256(item.read_bytes()).hexdigest(),
        })
    return document_digest(rows)


def _definition(capability_id: str):
    matches = [
        item for item in ArsenalInventoryBuilder().build()
        if item.capability_id == capability_id and item.capability_id.startswith("tool:")
    ]
    if len(matches) != 1 or not matches[0].tool_backends:
        raise ValueError(f"unknown tool fixture capability: {capability_id}")
    return matches[0]


class _ToolFixtureProvider:
    def __init__(self, *, capability_id: str, tool_name: str, bridge: ToolBridge,
                 positive: Path, negative: Path) -> None:
        self.capability_id = capability_id
        self.tool_name = tool_name
        self.bridge = bridge
        self.positive = positive
        self.negative = negative

    def runtime_executors(self):
        def execute(task, plan, authorization):
            grant = authorization.grant
            constraints = dict(grant.constraints if grant else {})
            if (
                grant is None
                or constraints.get("authorization_class") != LOCAL_FIXTURE_ONLY
                or constraints.get("capability_id") != self.capability_id
            ):
                raise PermissionError("tool fixture grant is missing or bound to another capability")
            tool = next(item for item in TOOLS if item.name == self.tool_name)
            lane = self.capability_id.rsplit("/", 1)[-1]
            command = _FIXTURE_COMMANDS.get((tool.name, lane))
            if command:
                tool = replace(tool, cmd=command)
            positive = self.bridge.scan(str(self.positive), tools=[tool])[0]
            negative = self.bridge.scan(str(self.negative), tools=[tool])[0]
            return {
                "tool": self.tool_name,
                "positive": {
                    "ran": positive.ran, "finding_count": len(positive.findings),
                    "error": positive.error, "runtime": positive.runtime,
                    "exit_code": positive.exit_code, "duration_ms": positive.duration_ms,
                    "execution_started_at": positive.execution_started_at,
                    "execution_completed_at": positive.execution_completed_at,
                    "stdout_digest": positive.stdout_digest,
                    "stderr_digest": positive.stderr_digest,
                    "parsed_result_digest": positive.parsed_result_digest,
                },
                "negative": {
                    "ran": negative.ran, "finding_count": len(negative.findings),
                    "error": negative.error, "runtime": negative.runtime,
                    "exit_code": negative.exit_code, "duration_ms": negative.duration_ms,
                    "execution_started_at": negative.execution_started_at,
                    "execution_completed_at": negative.execution_completed_at,
                    "stdout_digest": negative.stdout_digest,
                    "stderr_digest": negative.stderr_digest,
                    "parsed_result_digest": negative.parsed_result_digest,
                },
                "fixture_detection": bool(positive.findings),
                "negative_control_passed": negative.ran and not negative.findings,
            }

        return {TOOL_FIXTURE_CAPABILITY: execute}


def execute_tool_fixture(
    capability_id: str,
    *,
    runs_dir: str | Path,
    coverage_repository: CoverageRepository | None = None,
    bridge: ToolBridge | None = None,
    fixture_root: str | Path | None = None,
) -> ExerciseResult:
    definition = _definition(capability_id)
    backend = definition.tool_backends[0]
    covered_capability_ids = (capability_id, *_EQUIVALENT_CAPABILITIES.get(capability_id, ()))
    temporary = None
    if fixture_root:
        root = Path(fixture_root)
    else:
        temporary, root = _materialize_builtin_fixtures()
    positive, negative = root / "positive", root / "negative"
    if not positive.is_dir() or not negative.is_dir():
        raise FileNotFoundError("both positive and negative scanner fixture directories are required")
    positive_fixture_digest = _directory_digest(positive)
    negative_fixture_digest = _directory_digest(negative)

    raw = HmacSignatureVerifier({
        "fixture-auth": secrets.token_bytes(32), "grant": secrets.token_bytes(32),
    })
    verifier = LocalFixtureSignatureVerifier(raw)
    authorization = signed_fixture_authorization(verifier)
    policy_engine = PolicyEngine(authorization=authorization, verifier=verifier)
    decision = policy_engine.authorize(ActionRequest(
        target="127.0.0.1", action="source_analysis", tier_hint=ConsequenceTier.PASSIVE,
        description=f"local fixture exercise for {capability_id}", touches_production=False,
        request_id=f"arsenal:{capability_id}",
    ))
    if not decision.allowed:
        raise PermissionError("PolicyEngine denied the local scanner fixture")
    scope_document = {"assets": ["127.0.0.1"], "network_isolation": "loopback-only"}
    scope_digest = document_digest(scope_document)
    grant = mint_execution_grant(
        decision, scope_digest=scope_digest, budget=Budget(), verifier=verifier,
        constraints={
            "authorization_class": LOCAL_FIXTURE_ONLY, "capability_id": capability_id,
            "covered_capability_ids": list(covered_capability_ids),
            "positive_fixture_digest": positive_fixture_digest,
            "negative_fixture_digest": negative_fixture_digest,
            "fixture_version": "scanner-fixture-v2",
        },
    )
    now = datetime.now(UTC)
    suffix = sha256(f"{capability_id}:{now.isoformat()}:{grant.nonce}".encode()).hexdigest()[:12]
    run_id = f"arsenal-{now.strftime('%Y%m%dT%H%M%SZ')}-{suffix[:8]}"
    mission_id, task_id = f"arsenal-tool-{suffix}", f"arsenal-tool-{suffix}-execute"
    policy_snapshot = {
        "authorization_class": LOCAL_FIXTURE_ONLY, "permitted_actions": ["source_analysis"],
        "prohibited_real_targets": True,
    }
    store = ImmutableRunStore(runs_dir)
    store.create(OperatorRunManifest(
        1, run_id, RunMode.ARSENAL_FIXTURE, now.isoformat(), "local-fixture-operator",
        "aegis-local-fixtures", "built-in deterministic fixtures", ("127.0.0.1",), None, (),
        policy_snapshot, document_digest(policy_snapshot), scope_document, scope_digest,
        {"capabilities": [capability_id]},
        RunBudgets(1, 1.0, 0.0, max_duration_seconds=1200, max_attempts=1),
        authorization.model_dump(mode="json"),
    ))
    store.append_event(run_id, "arsenal_fixture_authorized", RunStatus.AUTHORIZED, {
        "capability_id": capability_id, "policy_decision": decision.as_dict(),
        "grant": grant._payload(),
    })
    task = MissionTask(
        task_id, "reproduction", "execute_scanner_fixture",
        payload={"authorization_class": LOCAL_FIXTURE_ONLY, "capability_id": capability_id},
        opportunity_id=f"fixture-opp-{suffix}", asset_id="fixture:source-code",
        asset_kind="source_code", asset_locator="127.0.0.1",
        executor_capability=TOOL_FIXTURE_CAPABILITY, risk="offline", expected_cost_usd=0.0,
        evidence_required=("positive_fixture", "negative_control"),
        idempotency_key=f"{mission_id}:{task_id}",
    )
    plan = MissionPlan(
        mission_id, scope_digest, f"Exercise {capability_id} against local controls", (task,),
        opportunity_id=task.opportunity_id, program_id="aegis-local-fixtures",
        asset_id=task.asset_id, asset_kind=task.asset_kind,
        authorization_id=authorization.authorization_id,
    )
    state_store = JarvisStateStore(":memory:")
    scheduler = MissionScheduler(state_store)
    provider = _ToolFixtureProvider(
        capability_id=capability_id, tool_name=backend.tool_name,
        bridge=bridge or ToolBridge(
            timeout=max(1, int(os.environ.get("AEGIS_FIXTURE_TOOL_TIMEOUT_SECONDS", "120"))),
            runtime_manager=ToolRuntimeManager(version_timeout=15.0),
        ), positive=positive, negative=negative,
    )
    runtime = UniversalMissionRuntime(
        scheduler, grant_verifier=verifier,
        workers=MissionWorkerRegistry((WorkerCapability(
            TOOL_FIXTURE_CAPABILITY, ExecutionClass.INTERNAL_EXECUTOR,
            asset_kinds=("source_code",), risk_classes=("offline",),
        ),)), executor_providers=(provider,),
    )
    plan = scheduler.create(plan)
    store.append_event(run_id, "arsenal_task_started", RunStatus.RUNNING, {
        "capability_id": capability_id, "mission_id": mission_id, "task_id": task_id,
    })
    execution = runtime.execute_first(
        plan, authorization=AuthorizationEnvelope(scope_digest, budget=Budget(), grant=grant),
        availability=CapabilityAvailability(artifact_available=True),
    )
    summary = dict(execution.outcome or {})
    summary["covered_capability_ids"] = list(covered_capability_ids)
    actually_ran = bool(summary.get("positive", {}).get("ran")) and bool(
        summary.get("negative", {}).get("ran")
    )
    positive_detected = bool(summary.get("fixture_detection"))
    negative_clean = bool(summary.get("negative_control_passed"))
    passed = actually_ran and positive_detected and negative_clean
    result_state = (
        ArsenalCoverageState.EXECUTED_PASS if passed
        else ArsenalCoverageState.BACKEND_UNHEALTHY
    )
    negative_status = (
        "PASSED" if summary.get("negative_control_passed")
        else "FAILED" if actually_ran else "NOT_RUN"
    )
    if not actually_ran:
        blocking_reason = str(
            summary.get("positive", {}).get("error")
            or summary.get("negative", {}).get("error")
            or execution.reason
            or "scanner process did not complete both controls"
        )
        error_class = "TOOL_CRASH"
    elif not positive_detected:
        blocking_reason = "positive control was not detected"
        error_class = "POSITIVE_CONTROL_MISSED"
    elif not negative_clean:
        blocking_reason = "negative control produced findings"
        error_class = "NEGATIVE_CONTROL_FAILED"
    else:
        blocking_reason = ""
        error_class = None
    summary["blocking_reason"] = blocking_reason
    summary["execution_error_class"] = error_class
    runtime_document = dict(summary.get("positive", {}).get("runtime", {}) or {})
    evidence_complete = bool(
        actually_ran
        and runtime_document.get("resolved_path")
        and summary.get("positive", {}).get("execution_started_at")
        and summary.get("negative", {}).get("execution_completed_at")
        and summary.get("positive", {}).get("stdout_digest")
        and summary.get("negative", {}).get("stdout_digest")
    )
    evidence = {
        "kind": "arsenal_tool_fixture_execution", "capability_id": capability_id,
        "mode": CapabilityMode.FIXTURE.value, "run_id": run_id, "mission_id": mission_id,
        "task_id": task_id, "policy_decision": decision.as_dict(),
        "execution_grant_payload": grant._payload(), "runtime_disposition": execution.disposition.value,
        "runtime_reason": execution.reason, "summary": summary,
        "negative_control_status": negative_status, "execution_performed": actually_ran,
        "backend_name": backend.tool_name,
        "backend_version": str(summary.get("positive", {}).get("runtime", {}).get("version", "")),
        "binary_path": str(
            summary.get("positive", {}).get("runtime", {}).get("resolved_path", "")
        ),
        "container_digest_if_applicable": os.environ.get("AEGIS_ARSENAL_IMAGE_DIGEST", ""),
        "adapter_version": backend.adapter_version,
        "capability_ids": list(covered_capability_ids),
        "fixture_version": "scanner-fixture-v2",
        "positive_fixture_digest": positive_fixture_digest,
        "negative_fixture_digest": negative_fixture_digest,
        "execution_started_at": summary.get("positive", {}).get("execution_started_at", ""),
        "execution_completed_at": summary.get("negative", {}).get("execution_completed_at", ""),
        "duration_ms": int(summary.get("positive", {}).get("duration_ms", 0))
        + int(summary.get("negative", {}).get("duration_ms", 0)),
        "exit_code": summary.get("positive", {}).get("exit_code"),
        "stdout_digest": document_digest([
            summary.get("positive", {}).get("stdout_digest", ""),
            summary.get("negative", {}).get("stdout_digest", ""),
        ]),
        "stderr_digest": document_digest([
            summary.get("positive", {}).get("stderr_digest", ""),
            summary.get("negative", {}).get("stderr_digest", ""),
        ]),
        "parsed_result_digest": document_digest([
            summary.get("positive", {}).get("parsed_result_digest", ""),
            summary.get("negative", {}).get("parsed_result_digest", ""),
        ]),
        "positive_control_detected": positive_detected,
        "negative_control_clean": negative_clean,
        "coverage_state": result_state.value,
        "blocking_reason": blocking_reason,
    }
    evidence_ref, evidence_digest = store.persist_evidence(run_id, evidence)
    store.append_event(
        run_id, "arsenal_task_completed",
        RunStatus.COMPLETED if passed else RunStatus.FAILED,
        {
        "capability_id": capability_id, "mode": CapabilityMode.FIXTURE.value,
        "mission_id": mission_id, "task_id": task_id, "backend": backend.tool_name,
        "backend_version": str(summary.get("positive", {}).get("runtime", {}).get("version", "")),
        "policy_snapshot_digest": document_digest(policy_snapshot), "asset": "127.0.0.1",
        "authorization_decision": decision.request_id or "", "execution_grant_id": grant.nonce,
        "evidence_ref": evidence_ref, "evidence_digest": evidence_digest,
        "result": result_state.value, "negative_control_status": negative_status,
        "finding_ids": [], "fixture_detection": positive_detected,
        "blocking_reason": blocking_reason, "execution_error_class": error_class,
    })
    recorded, degraded = False, coverage_repository is None
    if coverage_repository is not None:
        record = CapabilityCoverageRecord(
            f"acr:{sha256((run_id + task_id).encode()).hexdigest()[:24]}",
            f"arsenal:{run_id}:{task_id}", capability_id, CapabilityMode.FIXTURE,
            backend.tool_name, str(summary.get("positive", {}).get("runtime", {}).get("version", "")),
            definition.technique_ids[0] if definition.technique_ids else "", ("source_code",),
            definition.implementation_paths[0], backend.backend_id, backend.adapter_version,
            "HEALTHY" if actually_ran else "UNHEALTHY", document_digest(policy_snapshot),
            "127.0.0.1", decision.request_id or "", None, grant.nonce, run_id, mission_id,
            task_id, actually_ran, now.isoformat() if actually_ran else None,
            evidence_digest if actually_ran else None, result_state, (),
            blocking_reason, error_class, negative_status,
            schema_version=2 if evidence_complete else 1,
            backend_execution_id=f"{run_id}:{task_id}",
            binary_path=str(
                summary.get("positive", {}).get("runtime", {}).get("resolved_path", "")
            ),
            container_digest=os.environ.get("AEGIS_ARSENAL_IMAGE_DIGEST", ""),
            adapter_version=backend.adapter_version,
            capability_ids=covered_capability_ids,
            fixture_version="scanner-fixture-v2",
            positive_fixture_digest=positive_fixture_digest,
            negative_fixture_digest=negative_fixture_digest,
            execution_started_at=str(
                summary.get("positive", {}).get("execution_started_at", "")
            ),
            execution_completed_at=str(
                summary.get("negative", {}).get("execution_completed_at", "")
            ),
            duration_ms=int(summary.get("positive", {}).get("duration_ms", 0))
            + int(summary.get("negative", {}).get("duration_ms", 0)),
            exit_code=summary.get("positive", {}).get("exit_code"),
            stdout_digest=document_digest([
                summary.get("positive", {}).get("stdout_digest", ""),
                summary.get("negative", {}).get("stdout_digest", ""),
            ]),
            stderr_digest=document_digest([
                summary.get("positive", {}).get("stderr_digest", ""),
                summary.get("negative", {}).get("stderr_digest", ""),
            ]),
            parsed_result_digest=document_digest([
                summary.get("positive", {}).get("parsed_result_digest", ""),
                summary.get("negative", {}).get("parsed_result_digest", ""),
            ]),
            positive_control_detected=positive_detected,
            negative_control_clean=negative_clean,
        )
        try:
            _, recorded = coverage_repository.record(record)
        except Exception as exc:
            degraded = True
            store.append_event(run_id, "coverage_recording_degraded", RunStatus.COMPLETED, {
                "error_class": type(exc).__name__, "execution_result_remains_canonical": True,
            })
    if coverage_repository is None:
        store.append_event(run_id, "coverage_recording_degraded", RunStatus.COMPLETED, {
            "error_class": "CoverageRepositoryUnavailable",
            "execution_result_remains_canonical": True,
        })
    store.verify(run_id)
    state_store.close()
    result = ExerciseResult(
        run_id, mission_id, task_id, capability_id, result_state, evidence_ref, evidence_digest,
        recorded, degraded, summary,
    )
    if temporary is not None:
        temporary.cleanup()
    return result


__all__ = ["execute_tool_fixture"]
