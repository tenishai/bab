from datetime import UTC, datetime

import pytest

from bab import grants
from bab.catalogue import Catalogue
from bab.ceiling import Grant
from bab.store import Tuple
from tests.conftest import FakeStore

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)


def test_grant_needs_a_ceiling_then_writes_the_tier_expiry(cat):
    store = FakeStore({Tuple("team:infra", "ceiling_pod_delete", "project:p")})
    with pytest.raises(grants.CeilingError):
        grants.grant(store, cat, "infra", Grant("atlas", "pod_delete", "project:other"), NOW)
    t = grants.grant(store, cat, "infra", Grant("atlas", "pod_delete", "project:p"), NOW)
    assert t == Tuple("agent:atlas", "pod_delete", "project:p", "2026-11-26T12:00:00Z")  # mutate: 30 days
    assert t in store.tuples


def test_read_tier_grants_stand_and_destroy_tier_grants_are_short(cat):
    cat = Catalogue.from_dict({
        "resources": ["project"],
        "actions": [{"name": "log_read", "tier": "read"}, {"name": "drop_db", "tier": "destroy"}],
        "tiers": {"destroy": {"validity_days": 1, "lease_seconds": 600}},
    })
    assert grants.expiry_for(cat, "log_read", NOW) is None
    assert grants.expiry_for(cat, "drop_db", NOW) == datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
    assert cat.tier("destroy").lease_seconds == 600
    assert cat.tier("read").lease_seconds == 3600


def test_sweep_deletes_only_what_has_expired():
    live = Tuple("agent:a", "x", "project:p", "2026-10-27T13:00:00Z")
    dead = Tuple("agent:b", "x", "project:p", "2026-10-27T11:00:00Z")
    standing = Tuple("agent:c", "x", "project:p")
    store = FakeStore({live, dead, standing})
    assert grants.sweep(store, NOW) == [dead]
    assert store.tuples == {live, standing}
