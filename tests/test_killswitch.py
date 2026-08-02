from aegis.policy import KillSwitch


def test_starts_inactive():
    ks = KillSwitch()
    assert not ks.is_active


def test_fire_latches():
    ks = KillSwitch()
    ks.fire("health check failed", source="monitor")
    assert ks.is_active
    assert ks.state.reason == "health check failed"
    assert ks.state.source == "monitor"
    assert ks.state.fired_at is not None


def test_fire_is_idempotent_keeps_first_reason():
    ks = KillSwitch()
    ks.fire("first")
    ks.fire("second")
    assert ks.state.reason == "first"


def test_reset():
    ks = KillSwitch()
    ks.fire("stop")
    ks.reset()
    assert not ks.is_active
    assert ks.state.reason is None
