from bab.ceiling import Grant, permitted, team_of, violations
from bab.store import Tuple
from tests.conftest import FakeStore

P = "project:acme-platform-prod"


def test_allow_grant_needs_allow_ceiling_approve_needs_either():
    store = FakeStore({Tuple("team:platform-infra", "ceiling_pod_delete_gated", P)})
    assert not permitted(store, "platform-infra", Grant("atlas", "pod_delete", P))
    assert permitted(store, "platform-infra", Grant("atlas", "pod_delete", P, gated=True))
    assert not permitted(store, "data-infra", Grant("beacon", "pod_delete", P, gated=True))


def test_grant_shapes():
    assert Grant("atlas", "pod_delete", P).as_tuple() == Tuple("agent:atlas", "pod_delete", P)
    assert Grant("agent:atlas", "pod_delete", P, gated=True).relation == "pod_delete_gated"
    assert Grant("*", "log_read", P).subject == "agent:*"


def test_violations_after_a_ceiling_shrink():
    store = FakeStore({Tuple("team:platform-infra", "ceiling_pod_delete", P),
                       Tuple("team:platform-infra", "team", "agent:atlas")})
    grants = [("platform-infra", Grant("atlas", "pod_delete", P)), ("platform-infra", Grant("atlas", "pod_delete", "project:other"))]
    assert violations(store, grants) == [grants[1]]
    assert team_of(store, "atlas") == "team:platform-infra"
    assert team_of(store, "nobody") is None
