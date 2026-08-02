import pytest

from aegis.policy import RateBudget, SpendBudget, TokenBucket


def test_token_bucket_starts_full_and_consumes():
    b = TokenBucket(rate=5, capacity=5)
    assert b.available(0.0) == 5
    assert b.consume(0.0)
    assert b.available(0.0) == 4


def test_token_bucket_refills_over_time():
    b = TokenBucket(rate=2, capacity=2)
    assert b.consume(0.0)
    assert b.consume(0.0)
    assert not b.check(0.0)  # drained
    # 1 second later, 2 tokens/sec -> capacity reached
    assert b.check(1.0)
    assert b.available(1.0) == 2


def test_token_bucket_fractional_rate():
    b = TokenBucket(rate=0.5, capacity=1)
    assert b.consume(0.0)
    assert not b.check(0.0)
    assert not b.check(1.0)  # only 0.5 tokens back
    assert b.check(2.0)  # 1.0 token back


def test_rate_budget_rejects_bad_params():
    with pytest.raises(ValueError):
        RateBudget(0, 1)
    with pytest.raises(ValueError):
        RateBudget(5, 0)


def test_rate_budget_sessions():
    rb = RateBudget(5, 2)
    assert rb.acquire_session()
    assert rb.acquire_session()
    assert not rb.has_session_capacity()
    assert not rb.acquire_session()
    rb.release_session()
    assert rb.has_session_capacity()


def test_spend_budget():
    s = SpendBudget(limit=10)
    assert s.check(10)
    assert not s.check(11)
    s.record(7)
    assert s.remaining == 3
    assert not s.check(4)
    assert s.check(3)


def test_spend_budget_unlimited():
    s = SpendBudget(limit=None)
    assert s.check(1_000_000)
    assert s.remaining == float("inf")
