from bab.store import Tuple
from bab.sync import okta, reconcile, topology
from tests.conftest import FakeStore


def test_okta_groups_become_team_members():
    api = {
        "/api/groups": [{"id": "g1", "profile": {"name": "engineering_platform_infra"}},
                        {"id": "g2", "profile": {"name": "everyone"}}],
        "/api/groups/g1/users": [{"profile": {"email": "Alice@example.com"}}, {"profile": {"login": "carol@example.com"}}, {"profile": {}}],
    }
    got = sorted(okta.tuples(api.__getitem__), key=str)
    assert got == [Tuple("user:alice@example.com", "member", "team:platform-infra"),
                   Tuple("user:carol@example.com", "member", "team:platform-infra")]
    assert okta.team_name("engineering_data_infra") == "data-infra"
    assert okta.team_name("everyone") is None


def test_topology_tree_and_ownership(cat):
    topo = {"agents": [{"name": "atlas", "team": "platform-infra"}],
            "projects": [{"name": "acme-platform-prod", "team": "platform-infra"}, {"name": "acme-legacy-dev"}],
            "clusters": [{"name": "platform-prod", "project": "acme-platform-prod"}],
            "namespaces": [{"name": "platform-prod/ingest", "cluster": "platform-prod"}]}
    got = set(topology.tuples(topo, cat))
    assert got == {Tuple("team:platform-infra", "team", "agent:atlas"),
                   Tuple("team:platform-infra", "owner", "project:acme-platform-prod"),
                   Tuple("project:acme-platform-prod", "project", "cluster:platform-prod"),
                   Tuple("cluster:platform-prod", "cluster", "namespace:platform-prod/ingest")}
    assert topology.relations(cat) == {"team", "owner", "project", "cluster"}


def test_reconcile_owns_its_relations_only():
    grant = Tuple("agent:atlas", "pod_delete", "project:x")          # not ours: untouched
    stale = Tuple("user:gone@example.com", "member", "team:platform-infra")  # ours, no longer desired: deleted
    keep = Tuple("user:alice@example.com", "member", "team:platform-infra")
    new = Tuple("user:carol@example.com", "member", "team:platform-infra")
    store = FakeStore({grant, stale, keep})
    write, delete = reconcile(store, [keep, new, grant], {"member"})
    assert (write, delete) == ([new], [stale])
    assert store.tuples == {grant, keep, new}

    dry = FakeStore({grant, stale})
    reconcile(dry, [new], {"member"}, dry_run=True)
    assert dry.tuples == {grant, stale}
