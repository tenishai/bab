from bab.door import Door, Verdict
from bab.store import Tuple
from tests.conftest import FakeStore

NS = "namespace:platform-prod/ingest"


def test_allow_when_direct_grant(cat):
    door = Door(FakeStore({Tuple("agent:atlas", "pod_delete", NS)}), cat)
    d = door.decide("atlas", "pod_delete", NS)
    assert d.verdict is Verdict.ALLOW and not d.degraded


def test_approve_lists_approvers(cat):
    store = FakeStore({Tuple("agent:atlas", "pod_delete_gated", NS),
                       Tuple("user:alice@example.com", "approver", NS), Tuple("user:carol@example.com", "approver", NS)})
    d = Door(store, cat).decide("agent:atlas", "pod_delete", NS)
    assert d.verdict is Verdict.APPROVE
    assert d.approvers == ("user:alice@example.com", "user:carol@example.com")


def test_approve_with_nobody_to_ask_is_deny(cat):
    d = Door(FakeStore({Tuple("agent:atlas", "pod_delete_gated", NS)}), cat).decide("atlas", "pod_delete", NS)
    assert d.verdict is Verdict.DENY and "no approvers" in d.reason


def test_deny_by_default_and_for_unknown_action_or_object(cat):
    door = Door(FakeStore(), cat)
    assert door.decide("atlas", "pod_delete", NS).verdict is Verdict.DENY
    assert "not in the catalogue" in door.decide("atlas", "reboot_world", NS).reason
    assert "is not a project/cluster/namespace" in door.decide("atlas", "pod_delete", "topic:x").reason
    assert door.decide("atlas", "pod_delete", "no-type-here").verdict is Verdict.DENY


def test_fail_closed_when_store_is_down(cat):
    broken = FakeStore(broken=True)
    reads = Door(broken, cat).decide("atlas", "log_read", NS)
    assert reads.verdict is Verdict.ALLOW and reads.degraded

    with_fallback = Door(broken, cat, fallback_approvers=("user:alice@example.com",)).decide("atlas", "pod_delete", NS)
    assert with_fallback.verdict is Verdict.APPROVE and with_fallback.degraded
    assert with_fallback.approvers == ("user:alice@example.com",)

    no_fallback = Door(broken, cat).decide("atlas", "pod_delete", NS)
    assert no_fallback.verdict is Verdict.DENY and no_fallback.degraded
