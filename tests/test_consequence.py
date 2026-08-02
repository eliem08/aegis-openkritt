from aegis.policy import ConsequenceClassifier, ConsequenceTier, TierPolicy


def test_known_action_maps_to_tier():
    c = ConsequenceClassifier()
    assert c.classify("passive_discovery") == ConsequenceTier.PASSIVE
    assert c.classify("safe_state_change") == ConsequenceTier.STATE_CHANGING
    assert c.classify("cross_tenant_proof") == ConsequenceTier.SENSITIVE
    assert c.classify("denial_of_service") == ConsequenceTier.PROHIBITED


def test_unknown_action_is_sensitive_by_default():
    c = ConsequenceClassifier()
    assert not c.is_known("mystery_action")
    assert c.classify("mystery_action") == ConsequenceTier.SENSITIVE


def test_hint_can_only_raise_tier_never_lower():
    c = ConsequenceClassifier()
    # base PASSIVE, hint SENSITIVE -> SENSITIVE
    assert c.classify("passive_discovery", ConsequenceTier.SENSITIVE) == ConsequenceTier.SENSITIVE
    # base SENSITIVE, hint PASSIVE -> still SENSITIVE (cannot downgrade)
    assert c.classify("cross_tenant_proof", ConsequenceTier.PASSIVE) == ConsequenceTier.SENSITIVE


def test_tier_ordering():
    assert ConsequenceTier.PASSIVE < ConsequenceTier.PROHIBITED
    assert max(ConsequenceTier.PASSIVE, ConsequenceTier.SENSITIVE) == ConsequenceTier.SENSITIVE


def test_policy_for_tier():
    c = ConsequenceClassifier()
    assert c.policy_for(ConsequenceTier.PASSIVE) == TierPolicy.AUTO_ALLOW
    assert c.policy_for(ConsequenceTier.NON_INVASIVE_ACTIVE) == TierPolicy.AUTO_ALLOW_WITHIN_BUDGET
    assert c.policy_for(ConsequenceTier.STATE_CHANGING) == TierPolicy.CUSTOMER_CONFIGURABLE_APPROVAL
    assert c.policy_for(ConsequenceTier.SENSITIVE) == TierPolicy.HUMAN_APPROVAL
    assert c.policy_for(ConsequenceTier.PROHIBITED) == TierPolicy.NEVER
