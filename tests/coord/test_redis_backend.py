"""Production Redis backend behavior without requiring a local daemon."""

from __future__ import annotations

import pytest

from aegis.coord.coordinator import Admission, CoordUnavailable
from aegis.coord.redis_backend import ACQUIRE_SCRIPT, RATE_SCRIPT, RedisBackend, RedisCoordinator


class Pipeline:
    def __init__(self, client):
        self.client = client
        self.calls = []

    def __getattr__(self, name):
        def call(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            return self
        return call

    def execute(self):
        if self.client.fail:
            raise ConnectionError("down")
        self.client.pipeline_calls.append(self.calls)
        if self.calls and self.calls[-1][0] == "zrange":
            return [1, list(self.client.members)]
        return [1 for _ in self.calls]


class Client:
    def __init__(self):
        self.fail = False
        self.members = {"w1"}
        self.pipeline_calls = []
        self.eval_calls = []
        self.set_calls = []

    def ping(self):
        if self.fail:
            raise ConnectionError("down")
        return True

    def eval(self, script, number_of_keys, *args):
        if self.fail:
            raise ConnectionError("down")
        self.eval_calls.append((script, number_of_keys, args))
        return 2 if script == RATE_SCRIPT else 1

    def pipeline(self, transaction=True):
        assert transaction is True
        return Pipeline(self)

    def zrem(self, key, member):
        if self.fail:
            raise ConnectionError("down")
        self.members.discard(member)
        return 1

    def set(self, *args, **kwargs):
        if self.fail:
            raise ConnectionError("down")
        self.set_calls.append((args, kwargs))
        return True


def backend():
    client = Client()
    return RedisBackend(client=client, namespace="prod", tenant_id="tenant-a"), client


def test_keys_are_namespaced_and_rate_increment_is_atomic():
    store, client = backend()
    assert store.incr_window("rate:api", 60) == 2
    script, count, args = client.eval_calls[-1]
    assert script == RATE_SCRIPT and count == 1
    assert args == ("prod:tenant-a:rate:api", 60)


def test_semaphore_acquisition_uses_one_atomic_script():
    store, client = backend()
    coordinator = RedisCoordinator(store)
    assert coordinator.acquire("sem:scan", 3, "worker-1", ttl_seconds=30)
    script, count, args = client.eval_calls[-1]
    assert script == ACQUIRE_SCRIPT and count == 1
    assert args[0] == "prod:tenant-a:sem:scan"
    assert args[2] == "worker-1" and args[-2:] == (30, 3)


def test_sets_are_expiring_sorted_sets_and_members_are_pruned():
    store, client = backend()
    store.sadd("cancel", "scan-1", 20)
    assert store.members("cancel") == {"w1"}
    names = [call[0] for calls in client.pipeline_calls for call in calls]
    assert {"zadd", "expire", "zremrangebyscore", "zrange"} <= set(names)


def test_dedup_uses_atomic_set_nx_with_expiry():
    store, client = backend()
    assert store.setnx("event:1", 10)
    args, kwargs = client.set_calls[-1]
    assert args == ("prod:tenant-a:event:1", "1")
    assert kwargs == {"nx": True, "ex": 10}


def test_loss_is_translated_and_coordinator_fails_closed():
    store, client = backend()
    coordinator = RedisCoordinator(store)
    client.fail = True
    assert store.connected is False
    assert coordinator.admit("authenticated_testing") == Admission.DENY
    assert coordinator.acquire("sem", 10, "w") is False
    assert coordinator.rate_allow("rate", 10, 10) is False
    assert coordinator.is_cancelled("scan") is True
    with pytest.raises(CoordUnavailable):
        store.members("cancel")


@pytest.mark.parametrize("key", ["", "bad\nkey", "bad\x00key"])
def test_invalid_keys_are_rejected(key):
    store, _ = backend()
    with pytest.raises(ValueError):
        store.setnx(key, 10)
