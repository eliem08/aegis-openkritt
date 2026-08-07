from decimal import Decimal
import pytest
from aegis.benchmarking import BenchmarkRun, ReleaseGate
from aegis.template_manifest import (
    RiskMode, SecurityTemplateManifest, TemplateKind, TemplateRequirements, TemplateRisk,
)


def manifest(**changes):
    values = dict(
        template_id="aegis-auth-001", version="1.0.0", kind=TemplateKind.VALIDATION,
        author="aegis", risk=TemplateRisk(mode=RiskMode.READ_ONLY, maximum_requests=6,
                                          requires_human_approval=False),
        requirements=TemplateRequirements(asset_types=("api_endpoint",),
                                           authentication_contexts=2,
                                           evidence=("negative_control", "canary")),
        oracle_type="response_canary_difference", cwe=("CWE-639",),
    )
    values.update(changes)
    return SecurityTemplateManifest(**values)


def test_manifest_digest_and_policy_summary():
    base = manifest()
    signed = base.model_copy(update={"content_digest": base.digest(), "signature": "sig"})
    assert signed.verify_declared_digest()
    assert signed.policy_summary()["maximum_requests"] == 6
    assert signed.policy_summary()["signed"] is True


def test_state_change_template_cannot_skip_human_approval():
    with pytest.raises(ValueError):
        TemplateRisk(mode=RiskMode.CONTROLLED_STATE_CHANGE, maximum_requests=1,
                     state_changes=True, requires_human_approval=False)


def test_release_gate_rewards_reproduction_quality_and_cost():
    good = BenchmarkRun("xbow", detected=20, reproduced=8, false_positives=2,
                        accepted=3, duplicates=1, bounty_value=Decimal("2000"),
                        model_cost=Decimal("100"), scanner_cost=Decimal("50"))
    assert ReleaseGate(require_nonnegative_net_value=True).evaluate(good) == (True, [])
    noisy = BenchmarkRun("xbow", detected=100, reproduced=2, false_positives=30,
                         model_cost=Decimal("1000"))
    passed, reasons = ReleaseGate().evaluate(noisy)
    assert not passed and "precision_below_threshold" in reasons
