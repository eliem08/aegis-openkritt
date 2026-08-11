"""Production assembly for one operator-selected supervised HTTP canary."""

from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.parse import urlsplit

from aegis.ai.jarvis.asset_execution_ticket import CapabilityAvailability
from aegis.ai.jarvis.mission_scheduler import MissionScheduler
from aegis.ai.jarvis.scoped_http_executor import POLICY_ACTION, ScopedEgressHttpExecutor
from aegis.ai.jarvis.state_store import JarvisStateStore
from aegis.ai.jarvis.supervised_canary_executor import SupervisedHttpCanaryExecutor
from aegis.ai.jarvis.universal_runtime import UniversalMissionRuntime
from aegis.egress.auth import EgressClaims, issue_token
from aegis.gateway import NetworkProfile
from aegis.policy.signing import HmacSignatureVerifier


class LiveCanaryConfigurationError(RuntimeError):
    pass


def _secret(path_text: str, label: str) -> str:
    path = Path(path_text)
    if not path.is_file():
        raise LiveCanaryConfigurationError(f"{label} secret file is unavailable")
    value = path.read_text(encoding="utf-8").strip()
    if len(value) < 32:
        raise LiveCanaryConfigurationError(f"{label} secret is too short")
    return value


def require_fresh_ready_health(path_text: str, *, max_age_seconds: int = 300) -> dict:
    try:
        report = json.loads(Path(path_text).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LiveCanaryConfigurationError("production health report is unavailable") from exc
    if report.get("ready") is not True:
        raise LiveCanaryConfigurationError("production health gate is not ready")
    try:
        from datetime import datetime

        observed = datetime.fromisoformat(str(report["observed_at"]))
        age = time.time() - observed.timestamp()
    except (KeyError, TypeError, ValueError) as exc:
        raise LiveCanaryConfigurationError("production health timestamp is invalid") from exc
    if age < -5 or age > max_age_seconds:
        raise LiveCanaryConfigurationError("production health report is stale")
    cells = {str(item.get("name")): item for item in report.get("cells", [])}
    required = {"policy_authority", "database", "workers", "network_executor"}
    if any(cells.get(name, {}).get("status") != "READY" for name in required):
        raise LiveCanaryConfigurationError("a required canary health cell is not READY")
    return report


def build_supervised_runtime(
    *,
    egress_endpoint: str,
    egress_signing_key_file: str,
    grant_signing_key_file: str,
    mission_state_path: str,
    run_id: str,
    max_requests: int,
):
    egress_secret = _secret(egress_signing_key_file, "egress signing")
    grant_secret = _secret(grant_signing_key_file, "execution grant")
    grant_verifier = HmacSignatureVerifier({"grant": grant_secret})

    def token_issuer(action, method, destination, authorization):
        if action != POLICY_ACTION:
            raise PermissionError("unexpected scoped-egress policy action")
        grant = authorization.grant
        if (
            grant is None
            or not grant.verify(grant_verifier)
            or destination not in grant.allowed_destinations
            or method.upper() not in grant.allowed_methods
        ):
            raise PermissionError("execution grant does not cover the exact egress request")
        hostname = urlsplit(destination).hostname
        if not hostname:
            raise PermissionError("egress destination hostname is missing")
        now = int(time.time())
        return issue_token(EgressClaims(
            tenant_id="operator-supervised",
            engagement_id=run_id,
            profile=NetworkProfile.TARGET_OBSERVATION.value,
            method=method.upper(),
            destination=destination,
            issued_at=now,
            expires_at=now + 60,
            budget_id=f"{run_id}:read-only-canary",
            request_limit=min(max_requests, authorization.budget.max_requests),
            scope=[hostname],
            allowed_methods=[method.upper()],
        ), egress_secret, now=now)

    http = ScopedEgressHttpExecutor(
        egress_endpoint,
        token_issuer=token_issuer,
        grant_verifier=grant_verifier,
        max_requests=max_requests,
        max_requests_per_second=1,
    )
    provider = SupervisedHttpCanaryExecutor(http, grant_verifier=grant_verifier)
    state = JarvisStateStore(mission_state_path)
    runtime = UniversalMissionRuntime(
        MissionScheduler(state),
        grant_verifier=grant_verifier,
        executor_providers=(provider,),
    )
    return runtime, grant_verifier, CapabilityAvailability()


__all__ = [
    "LiveCanaryConfigurationError", "build_supervised_runtime", "require_fresh_ready_health",
]
