"""The contract: ask, decide, hold, lease, revoke, sweep. Fake store, in-memory ledger."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from bab import catalogue
from bab.service.app import Settings, create_app
from bab.service.identity import Caller, ConsoleAuth, IdentityError, StaticVerifier
from bab.service.ledger import Event, Ledger
from bab.service.minters import StaticMinter
from bab.store import Tuple
from tests.conftest import FakeStore

T0 = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
NO_BORROWING_SENTENCE = "a credential is never borrowed for another agent's task"
ADMIN = {"X-Bab-Console-Token": "console-secret", "X-Bab-Actor": "kyle@example.com"}
SEC = {"X-Bab-Console-Token": "console-secret", "X-Bab-Actor": "sam@example.com"}
OWNER = {"X-Bab-Console-Token": "console-secret", "X-Bab-Actor": "owner@example.com"}
AGENT = {"Authorization": "Bearer sherlock-token"}


@pytest.fixture
def world():
    clock = {"now": T0}
    store = FakeStore({
        Tuple("user:kyle@example.com", "member", "team:admins"),
        Tuple("user:sam@example.com", "member", "team:security"),
        Tuple("team:sre", "team", "agent:sherlock"),
    })
    cat = catalogue.load("catalogues/room.yaml")
    minter = StaticMinter(now=lambda: clock["now"].timestamp())
    ledger = Ledger()
    app = create_app(store, cat, ledger, StaticVerifier({"sherlock-token": "sherlock"}),
                     ConsoleAuth("console-secret"), {"aws": minter},
                     Settings(room="acme", admin_team="admins", security_team="security", now=lambda: clock["now"]))
    app.state.ledger = ledger  # for tests that read the audit trail
    return TestClient(app), store, clock, minter


def connect(c, ceiling):
    r = c.put("/integrations/aws-prod", json={"vendor": "aws", "spec": {"role_arn": "arn:aws:iam::123456789012:role/KoboAccess-Role"}, "ceiling": ceiling}, headers=ADMIN)
    assert r.status_code == 200, r.text
    return r.json()


def test_connect_writes_the_ceiling_for_every_team_and_the_room_link(world):
    c, store, _, _ = world
    out = connect(c, ["aws_inventory_read", "aws_logs_read"])
    assert out["teams"] == ["team:sre"]
    assert Tuple("room:acme", "room", "integration:aws-prod") in store.tuples
    assert Tuple("team:sre", "ceiling_aws_inventory_read", "integration:aws-prod") in store.tuples
    # The picker's tree, grouped the vendor's way, with the tier as a column.
    tree = c.get("/catalogue/aws", headers=OWNER).json()
    assert {g["name"] for g in tree["groups"]} >= {"Compute", "Storage", "Security", "Billing"}
    assert (tree["kind"], tree["label"], tree["account"]) == ("cloud", "AWS", "account")
    assert tree["tiers"][0] == {"name": "read", "lease_seconds": 3600, "validity_days": None}
    # The vendor list: clouds are connected per account, services are one connection.
    vendors = {v["vendor"]: v for v in c.get("/catalogue", headers=OWNER).json()["vendors"]}
    assert vendors["aws"]["kind"] == "cloud" and vendors["gcp"]["account"] == "project"
    assert vendors["datadog"] == {"vendor": "datadog", "kind": "service", "label": "Datadog", "account": None,
                                  "permissions": {"read": 12, "mutate": 1}}


def test_ask_decide_hold_lease_revoke_sweep(world):
    c, store, clock, minter = world
    connect(c, ["aws_inventory_read", "aws_logs_read", "aws_ecs_update_service"])

    # The owner asks for four permissions; one is above the ceiling.
    r = c.post("/requests", json={"agent": "sherlock", "integration": "aws-prod",
                                  "permissions": ["aws_inventory_read", "aws_logs_read", "aws_ecs_update_service", "aws_cost_read"],
                                  "note": "incident work"}, headers=OWNER)
    assert r.status_code == 201, r.text
    rid = r.json()["id"]
    assert r.json()["tiers"] == {"read": 3, "mutate": 1}
    assert c.get("/requests", headers=ADMIN).json()["requests"][0]["id"] == rid

    # Only a reviewer decides; the owner is refused.
    assert c.post("/requests/decide", json={"ids": [rid], "verdict": "approve"}, headers=OWNER).status_code == 403
    out = c.post("/requests/decide", json={"ids": [rid], "verdict": "approve"}, headers=ADMIN).json()["results"][0]
    assert out["status"] == "approved"
    assert out["outcome"]["aws_cost_read"].startswith("refused: team:sre holds no ceiling")
    assert out["outcome"]["aws_inventory_read"] == "granted"

    # Grants: read-tier standing, mutate-tier expiring in 30 days.
    held = {g["permission"]: g for g in c.get("/agents/sherlock/grants", headers=OWNER).json()["grants"]}
    assert held["aws_inventory_read"]["expires_at"] is None
    assert held["aws_ecs_update_service"]["expires_at"] == "2026-11-26T12:00:00Z"
    assert Tuple("agent:sherlock", "aws_ecs_update_service", "integration:aws-prod", "2026-11-26T12:00:00Z") in store.tuples

    # The agent leases what it holds; an unheld permission is named as refused, not fatal.
    r = c.post("/leases", json={"integration": "aws-prod", "permissions": ["aws_inventory_read", "aws_cost_read"], "task": "inc 4312"}, headers=AGENT)
    assert r.status_code == 200, r.text
    lease = r.json()
    assert lease["granted"] == ["aws_inventory_read"] and lease["refused"] == ["aws_cost_read"]
    assert lease["expires_at"] == "2026-10-27T13:00:00Z"  # read tier: one hour
    assert "token" in lease["credential"]
    # No permissions named: everything the agent holds, lease as short as the shortest tier.
    r = c.post("/leases", json={"integration": "aws-prod"}, headers=AGENT)
    assert sorted(r.json()["granted"]) == ["aws_ecs_update_service", "aws_inventory_read", "aws_logs_read"]
    assert c.get("/leases?agent=sherlock", headers=ADMIN).json()["leases"][0]["task"] is None
    assert len(c.get("/leases", headers=ADMIN).json()["leases"]) == 2

    # A stranger's token gets nothing; the console cannot lease.
    assert c.post("/leases", json={"integration": "aws-prod"}, headers={"Authorization": "Bearer nope"}).status_code == 401
    assert c.post("/leases", json={"integration": "aws-prod"}, headers=ADMIN).status_code == 401

    # Revoke now: the tuple goes, the next lease refuses that permission.
    gid = held["aws_inventory_read"]["id"]
    assert c.delete(f"/grants/{gid}", headers=ADMIN).status_code == 200
    r = c.post("/leases", json={"integration": "aws-prod", "permissions": ["aws_inventory_read"]}, headers=AGENT)
    assert r.status_code == 403 and r.json()["detail"]["refused"] == ["aws_inventory_read"]

    # Time passes: the mutate grant expires on the dot. Any lease request ends the leases that
    # have run out (their vendor-side keys go, where the vendor can); sweep tidies the tuples.
    clock["now"] = T0 + timedelta(days=30)
    r = c.post("/leases", json={"integration": "aws-prod", "permissions": ["aws_ecs_update_service"]}, headers=AGENT)
    assert r.status_code == 403
    assert len(minter.ended) == 2
    assert c.get("/agents/sherlock/grants", headers=OWNER).json()["grants"][-1]["state"] == "expired"
    out = c.post("/sweep", headers=ADMIN).json()
    assert out == {"expired_tuples_deleted": 1, "leases_ended": 0}
    assert len(minter.ended) == 2


def test_destroy_tier_needs_the_security_team_and_a_denial_needs_a_reason(world):
    c, _store, _, _ = world
    connect(c, ["aws_ec2_stop_instances", "aws_inventory_read"])
    rid = c.post("/requests", json={"agent": "sherlock", "integration": "aws-prod",
                                    "permissions": ["aws_ec2_stop_instances", "aws_inventory_read"]}, headers=OWNER).json()["id"]
    out = c.post("/requests/decide", json={"ids": [rid], "verdict": "approve"}, headers=ADMIN).json()["results"][0]
    assert out["outcome"] == {"aws_ec2_stop_instances": "refused: the destroy tier needs the security team",
                              "aws_inventory_read": "granted"}
    rid2 = c.post("/requests", json={"agent": "sherlock", "integration": "aws-prod",
                                     "permissions": ["aws_ec2_stop_instances"]}, headers=OWNER).json()["id"]
    assert c.post("/requests/decide", json={"ids": [rid2], "verdict": "deny"}, headers=SEC).status_code == 422
    out = c.post("/requests/decide", json={"ids": [rid2], "verdict": "approve"}, headers=SEC).json()["results"][0]
    assert out["outcome"] == {"aws_ec2_stop_instances": "granted"}
    g = next(g for g in c.get("/agents/sherlock/grants", headers=OWNER).json()["grants"] if g["permission"] == "aws_ec2_stop_instances")
    assert g["expires_at"] == "2026-11-03T12:00:00Z"  # destroy: 7 days


def test_a_gated_permission_turns_a_lease_into_a_one_hour_request(world):
    c, store, _clock, _ = world
    connect(c, ["aws_logs_read"])
    store.write([Tuple("agent:sherlock", "aws_logs_read_gated", "integration:aws-prod")])
    r = c.post("/leases", json={"integration": "aws-prod", "permissions": ["aws_logs_read"], "task": "look at errors"}, headers=AGENT)
    assert r.status_code == 202, r.text
    rid = r.json()["detail"]["request_id"]
    req = c.get("/requests?agent=sherlock", headers=ADMIN).json()["requests"][0]
    assert req["id"] == rid and req["kind"] == "lease" and req["requested_by"] == "agent:sherlock"
    out = c.post("/requests/decide", json={"ids": [rid], "verdict": "approve"}, headers=ADMIN).json()["results"][0]
    assert out["outcome"] == {"aws_logs_read": "granted"}
    r = c.post("/leases", json={"integration": "aws-prod", "permissions": ["aws_logs_read"]}, headers=AGENT)
    assert r.status_code == 200
    held = c.get("/agents/sherlock/grants", headers=OWNER).json()["grants"][0]
    assert held["expires_at"] == "2026-10-27T13:00:00Z"


class PodVerifier:
    """Tokens name a pod identity (service account + namespace), the way TokenReview answers."""

    def __init__(self, pods: dict[str, tuple[str, str]]):
        self.pods = pods

    def verify(self, token: str) -> Caller:
        try:
            sa, ns = self.pods[token]
        except KeyError as exc:
            raise IdentityError("unknown token") from exc
        return Caller("agent", sa, namespace=ns)


@pytest.fixture
def pods():
    clock = {"now": T0}
    store = FakeStore({Tuple("user:kyle@example.com", "member", "team:admins")})
    cat = catalogue.load("catalogues/room.yaml")
    minter = StaticMinter(now=lambda: clock["now"].timestamp())
    verifier = PodVerifier({"ledger-pod": ("agent-ledger", "ledger"), "stray-pod": ("default", "kube-system")})
    app = create_app(store, cat, Ledger(), verifier, ConsoleAuth("console-secret"), {"aws": minter},
                     Settings(room="acme", admin_team="admins", security_team="security", now=lambda: clock["now"]))
    return TestClient(app), store


def test_topology_push_names_the_agent_behind_a_pod_identity(pods):
    c, store = pods
    # Before any topology, the agent is its service account (how 0.2.0 behaved).
    r = c.post("/leases", json={"integration": "aws-prod"}, headers={"Authorization": "Bearer ledger-pod"})
    assert r.status_code == 404 and "aws-prod" in r.text  # verified as agent-ledger, no such integration

    # Connect first, with no team in the store yet: the ceiling has nobody to land on.
    connect(c, ["aws_inventory_read"])
    (integ,) = c.get("/integrations", headers=OWNER).json()["integrations"]
    assert (integ["integration"], integ["vendor"], integ["ceiling"]) == ("aws-prod", "aws", ["aws_inventory_read"])
    assert integ["created_at"].startswith("2026-10-27T12:00:00")

    body = {"agents": [{"name": "ledger", "team": "sre", "namespace": "ledger", "service_account": "agent-ledger"}],
            "rooms": [{"name": "acme", "team": "admins"}]}
    # The console pushes as the room itself: the token is the authority, the actor is recorded.
    out = c.put("/topology", json=body, headers={**OWNER, "X-Bab-Actor": "room@console"}).json()
    # team + owner, plus the connected integration's ceiling extended to the new team.
    assert out == {"agents": 1, "removed": 0, "tuples_written": 3, "tuples_deleted": 0}
    assert Tuple("team:sre", "team", "agent:ledger") in store.tuples
    assert Tuple("team:admins", "owner", "room:acme") in store.tuples
    assert Tuple("team:sre", "ceiling_aws_inventory_read", "integration:aws-prod") in store.tuples
    assert c.get("/agents", headers=OWNER).json()["agents"] == [
        {"name": "ledger", "team": "sre", "namespace": "ledger", "service_account": "agent-ledger"}]

    # Grant to the agent by the name the room uses, and the pod's lease lands under it.
    rid = c.post("/requests", json={"agent": "ledger", "integration": "aws-prod",
                                    "permissions": ["aws_inventory_read"]}, headers=OWNER).json()["id"]
    assert c.post("/requests/decide", json={"ids": [rid], "verdict": "approve"}, headers=ADMIN).json()["results"][0]["status"] == "approved"
    r = c.post("/leases", json={"integration": "aws-prod", "task": "count instances"},
               headers={"Authorization": "Bearer ledger-pod"})
    assert r.status_code == 200, r.text
    assert c.get("/leases", headers=OWNER).json()["leases"][0]["agent"] == "ledger"

    # A pod the topology does not name is not an agent, whatever its service account is called.
    r = c.post("/leases", json={"integration": "aws-prod"}, headers={"Authorization": "Bearer stray-pod"})
    assert r.status_code == 401 and "not an agent this room knows" in r.text

    # A push without `rooms` leaves ownership alone; with `rooms: []` it owns (and empties) it.
    out = c.put("/topology", json={"agents": []}, headers=ADMIN).json()
    assert out["removed"] == 1 and out["tuples_deleted"] == 1
    assert Tuple("team:admins", "owner", "room:acme") in store.tuples
    out = c.put("/topology", json={"agents": [], "rooms": []}, headers=ADMIN).json()
    assert out["tuples_deleted"] == 1
    # The room link that connect wrote survives every push.
    assert Tuple("room:acme", "room", "integration:aws-prod") in store.tuples


def test_identity_probe_and_disconnect(world):
    c, store, _, _ = world
    assert c.get("/identity/aws", headers=OWNER).json()["subject"] == "static-minter"
    assert c.get("/identity/datadog", headers=OWNER).status_code == 501
    # A probe before saving: the owner cannot, a reviewer can, AWS's no is a 409 with its sentence.
    arn = "arn:aws:iam::123456789012:role/KoboAccess-Role"
    assert c.post("/probe/aws", json={"role_arn": arn}, headers=OWNER).status_code == 403
    assert c.post("/probe/aws", json={"role_arn": arn}, headers=ADMIN).json()["account"] == "123456789012"
    # The route hands the minter the fields its probe accepts; one it requires and did not get is a 422 naming it.
    r = c.post("/probe/aws", json={"project": "example-project"}, headers=ADMIN)
    assert r.status_code == 422 and r.json()["detail"] == "a probe for 'aws' needs role_arn"
    r = c.post("/probe/aws", json={"role_arn": "arn:aws:iam::123456789012:role/refuse-me"}, headers=ADMIN)
    assert r.status_code == 409 and "AccessDenied" in r.text

    connect(c, ["aws_inventory_read"])
    rid = c.post("/requests", json={"agent": "sherlock", "integration": "aws-prod", "permissions": ["aws_inventory_read"]},
                 headers=OWNER).json()["id"]
    c.post("/requests/decide", json={"ids": [rid], "verdict": "approve"}, headers=ADMIN)
    assert len(c.get("/agents/sherlock/grants", headers=OWNER).json()["grants"]) == 1
    # Disconnect: the row, the grant (revoked), and every tuple naming the integration.
    out = c.delete("/integrations/aws-prod", headers=ADMIN).json()
    assert out["removed"] == "aws-prod" and out["grants_revoked"] == 1 and out["tuples_deleted"] >= 3
    assert not [t for t in store.tuples if t.object == "integration:aws-prod"]
    assert c.get("/integrations", headers=OWNER).json()["integrations"] == []
    assert c.delete("/integrations/aws-prod", headers=ADMIN).status_code == 404


def test_an_organization_hub_and_its_accounts(world):
    c, _, _, minter = world
    hub = "arn:aws:iam::999999999999:role/BabHub"
    # The organization row: the hub role, no ceiling (nothing is granted on an organization).
    out = c.put("/integrations/acme-aws", json={"vendor": "aws", "spec": {"hub_role_arn": hub, "name": "acme-aws"}},
                headers=ADMIN).json()
    assert out["kind"] == "org" and out["parent"] is None
    # Its accounts, as the hub sees them, none connected yet.
    accts = c.get("/integrations/acme-aws/accounts", headers=OWNER).json()["accounts"]
    assert [(a["id"], a["connected"]) for a in accts] == [("111111111111", False), ("222222222222", False)]
    # A spoke under it: probed through the hub, then connected with the parent.
    spoke = "arn:aws:iam::111111111111:role/BabSpoke"
    assert c.post("/probe/aws", json={"role_arn": spoke, "hub_role_arn": hub, "external_id": "x1"}, headers=ADMIN).json()["hops"] == 2
    bad = c.put("/integrations/acme-prod", json={"vendor": "aws", "parent": "nope", "spec": {}}, headers=ADMIN)
    assert bad.status_code == 422
    out = c.put("/integrations/acme-prod", json={"vendor": "aws", "parent": "acme-aws", "ceiling": ["aws_inventory_read"],
                                                 "spec": {"spoke_role_arn": spoke, "external_id": "x1", "account_id": "111111111111", "name": "acme-prod"}},
                headers=ADMIN).json()
    assert out["kind"] == "account" and out["parent"] == "acme-aws"
    rows = {r["integration"]: r for r in c.get("/integrations", headers=OWNER).json()["integrations"]}
    assert rows["acme-aws"]["kind"] == "org" and rows["acme-prod"]["parent"] == "acme-aws" and rows["acme-prod"]["account_id"] == "111111111111"
    assert rows["acme-aws"]["hub_role_arn"] == hub and rows["acme-prod"]["hub_role_arn"] is None
    accts = {a["id"]: a for a in c.get("/integrations/acme-aws/accounts", headers=OWNER).json()["accounts"]}
    assert accts["111111111111"]["connected"] is True and accts["111111111111"]["integration"] == "acme-prod"
    # A lease on the account carries the hub to the minter; a lease on the organization is refused.
    rid = c.post("/requests", json={"agent": "sherlock", "integration": "acme-prod", "permissions": ["aws_inventory_read"]}, headers=OWNER).json()["id"]
    c.post("/requests/decide", json={"ids": [rid], "verdict": "approve"}, headers=ADMIN)
    r = c.post("/leases", json={"integration": "acme-prod"}, headers=AGENT)
    assert r.status_code == 200, r.text
    assert minter.minted[-1]["spec"] == {"hub_role_arn": hub, "audience": None, "spoke_role_arn": spoke, "external_id": "x1",
                                         "account_id": "111111111111", "name": "acme-prod"}
    assert c.post("/leases", json={"integration": "acme-aws", "permissions": ["aws_inventory_read"]}, headers=AGENT).status_code == 409

    # Discover: with one external id on the organization, every account is probed through the
    # hub for the spoke role; the ones that carry it are what a console registers next.
    assert c.post("/integrations/acme-aws/discover", json={}, headers=ADMIN).status_code == 409  # no external id yet
    c.put("/integrations/acme-aws", json={"vendor": "aws", "spec": {"hub_role_arn": hub, "name": "acme-aws", "external_id": "org-x"}},
          headers=ADMIN)
    found = c.post("/integrations/acme-aws/discover", json={"role_name": "KoboAccess-Role"}, headers=ADMIN).json()
    assert found["external_id"] == "org-x"
    by_id = {a["id"]: a for a in found["accounts"]}
    assert by_id["111111111111"]["connected"] is True and by_id["111111111111"]["reachable"] is True
    assert by_id["222222222222"]["reachable"] is False and "refused" in by_id["222222222222"]["reason"]
    assert by_id["222222222222"]["role_arn"] == "arn:aws:iam::222222222222:role/KoboAccess-Role"
    assert ("arn:aws:iam::222222222222:role/KoboAccess-Role", hub, "org-x") in minter.probed
    # An account connected without its own external id leases with the organization's.
    c.put("/integrations/acme-data", json={"vendor": "aws", "parent": "acme-aws", "ceiling": ["aws_inventory_read"],
                                           "spec": {"spoke_role_arn": "arn:aws:iam::222222222222:role/KoboAccess-Role",
                                                    "account_id": "222222222222", "name": "acme-data"}}, headers=ADMIN)
    rid = c.post("/requests", json={"agent": "sherlock", "integration": "acme-data", "permissions": ["aws_inventory_read"]}, headers=OWNER).json()["id"]
    c.post("/requests/decide", json={"ids": [rid], "verdict": "approve"}, headers=ADMIN)
    assert c.post("/leases", json={"integration": "acme-data"}, headers=AGENT).status_code == 200
    assert minter.minted[-1]["spec"]["external_id"] == "org-x"
    assert c.delete("/integrations/acme-data", headers=ADMIN).json()["removed"] == "acme-data"
    # The organization cannot go while an account hangs under it.
    assert c.delete("/integrations/acme-aws", headers=ADMIN).status_code == 409
    assert c.delete("/integrations/acme-prod", headers=ADMIN).json()["removed"] == "acme-prod"
    assert c.delete("/integrations/acme-aws", headers=ADMIN).json()["removed"] == "acme-aws"


def test_a_live_credential_is_reused_and_a_revoke_ends_it(world):
    c, _, clock, minter = world
    connect(c, ["aws_inventory_read"])
    rid = c.post("/requests", json={"agent": "sherlock", "integration": "aws-prod", "permissions": ["aws_inventory_read"]},
                 headers=OWNER).json()["id"]
    c.post("/requests/decide", json={"ids": [rid], "verdict": "approve"}, headers=ADMIN)
    first = c.post("/leases", json={"integration": "aws-prod", "task": "one"}, headers=AGENT).json()
    second = c.post("/leases", json={"integration": "aws-prod", "task": "two"}, headers=AGENT).json()
    # The runtime may ask on every call: the same credential comes back while it is good.
    assert first["reused"] is False and second["reused"] is True
    assert second["lease_id"] == first["lease_id"] and second["credential"] == first["credential"]
    assert len(minter.minted) == 1
    assert len(c.get("/leases", headers=OWNER).json()["leases"]) == 1
    # Near the end of its life a fresh one is minted.
    clock["now"] = T0 + timedelta(seconds=3600 - 60)
    third = c.post("/leases", json={"integration": "aws-prod"}, headers=AGENT).json()
    assert third["reused"] is False and third["lease_id"] != first["lease_id"]
    # Revoke: the grant check fails before the cache is consulted, and the cache is dropped.
    gid = c.get("/agents/sherlock/grants", headers=OWNER).json()["grants"][0]["id"]
    c.delete(f"/grants/{gid}", headers=ADMIN)
    r = c.post("/leases", json={"integration": "aws-prod", "permissions": ["aws_inventory_read"]}, headers=AGENT)
    assert r.status_code == 403


def test_talking_to_another_agent_is_a_grant_the_switchboard_reads_never_a_lease(world):
    c, _, _, minter = world
    # The other agent is an integration of the `agents` vendor: one per agent, id = its name.
    out = c.put("/integrations/watson", json={"vendor": "agents", "ceiling": ["a2a_ask"]}, headers=ADMIN).json()
    assert out["kind"] == "connection" and out["ceiling"] == ["a2a_ask"]
    vendors = {v["vendor"]: v for v in c.get("/catalogue", headers=OWNER).json()["vendors"]}
    assert vendors["agents"] == {"vendor": "agents", "kind": "service", "label": "Other agents", "account": None,
                                 "permissions": {"read": 1}}
    assert c.get("/catalogue/agents", headers=OWNER).json()["groups"][0]["name"] == "Colleagues"
    assert c.get("/agents/sherlock/talks-to", headers=OWNER).json() == {"agent": "sherlock", "talks_to": []}

    # Gate one: the asker's owner requests it, a reviewer approves it in Review, like any permission.
    rid = c.post("/requests", json={"agent": "sherlock", "integration": "watson", "permissions": ["a2a_ask"]}, headers=OWNER).json()["id"]
    out = c.post("/requests/decide", json={"ids": [rid], "verdict": "approve"}, headers=ADMIN).json()["results"][0]
    assert out["outcome"] == {"a2a_ask": "granted"}
    assert c.get("/agents/sherlock/talks-to", headers=OWNER).json()["talks_to"] == ["watson"]
    assert c.get("/agents/watson/talks-to", headers=OWNER).json()["talks_to"] == []  # not symmetric

    # Talking is never minted: a lease on another agent is refused with the reason.
    r = c.post("/leases", json={"integration": "watson"}, headers=AGENT)
    assert r.status_code == 409 and r.json()["detail"] == "talking is granted, not leased: the switchboard reads the grant"

    # Gate two, the second wall: a lease for another agent's task is refused whatever is held, and recorded.
    connect(c, ["aws_inventory_read"])
    rid = c.post("/requests", json={"agent": "sherlock", "integration": "aws-prod", "permissions": ["aws_inventory_read"]}, headers=OWNER).json()["id"]
    c.post("/requests/decide", json={"ids": [rid], "verdict": "approve"}, headers=ADMIN)
    r = c.post("/leases", json={"integration": "aws-prod", "task": "watson asked", "on_behalf_of": ["watson"]}, headers=AGENT)
    assert r.status_code == 403 and r.json()["detail"] == "a credential is never borrowed for another agent's task"
    assert minter.minted == []
    with c.app.state.ledger.session() as s:
        (ev,) = s.scalars(select(Event).where(Event.kind == "lease.refused"))
    assert ev.actor == "sherlock" and ev.detail["integration"] == "aws-prod" and ev.detail["on_behalf_of"] == ["watson"]
    # An empty list is nobody: the agent's own task, leased as always.
    assert c.post("/leases", json={"integration": "aws-prod", "on_behalf_of": []}, headers=AGENT).status_code == 200

    # Revoked, the pair is gone from the switchboard's list.
    gid = next(g["id"] for g in c.get("/agents/sherlock/grants", headers=OWNER).json()["grants"] if g["integration"] == "watson")
    assert c.delete(f"/grants/{gid}", headers=ADMIN).status_code == 200
    assert c.get("/agents/sherlock/talks-to", headers=OWNER).json()["talks_to"] == []



def test_the_room_registers_agents_itself_but_every_other_vendor_takes_a_reviewer(world):
    """Gate: an `agents` integration is the room's own fact, written and removed with the
    console token by any actor (the room pushes it at boot as itself); an ordinary vendor
    still takes an admin or security reviewer."""
    c, _, _, _ = world
    room = {**OWNER, "X-Bab-Actor": "room@console"}
    r = c.put("/integrations/sage", json={"vendor": "agents", "spec": {"name": "sage"}, "ceiling": ["a2a_ask"]}, headers=room)
    assert r.status_code == 200, r.text
    assert c.put("/integrations/aws-x", json={"vendor": "aws", "spec": {"role_arn": "arn:aws:iam::111111111111:role/R"},
                                           "ceiling": ["aws_inventory_read"]}, headers=room).status_code == 403
    assert c.delete("/integrations/sage", headers=room).json()["removed"] == "sage"


def gateway_room(keys=None):
    from bab.service.minters import DatadogMinter
    from tests.conftest import FakeDatadog

    clock = {"now": T0}
    store = FakeStore({Tuple("user:kyle@example.com", "member", "team:admins")})
    cat = catalogue.load("catalogues/room.yaml")
    aws = StaticMinter(now=lambda: clock["now"].timestamp())
    dd = FakeDatadog()
    datadog = DatadogMinter.from_env({"DD_SERVICE_ACCOUNT_ID": "sa-123", "DD_API_KEY": "api-xyz", "DD_MGMT_APP_KEY": "mgmt-abc"},
                                     http=dd, now=lambda: clock["now"].timestamp(), keys=keys)
    verifier = PodVerifier({"ledger-pod": ("agent-ledger", "ledger"), "gateway-pod": ("tool-gateway", "gateway"),
                            "stray-pod": ("default", "kube-system")})
    ledger = Ledger()
    app = create_app(store, cat, ledger, verifier, ConsoleAuth("console-secret"), {"aws": aws, "datadog": datadog},
                     Settings(room="acme", admin_team="admins", security_team="security", now=lambda: clock["now"],
                              gateway_service_account="gateway/tool-gateway"))
    app.state.ledger = ledger
    app.state.datadog = datadog
    c = TestClient(app)
    c.put("/topology", json={"agents": [{"name": "ledger", "team": "sre", "namespace": "ledger", "service_account": "agent-ledger"},
                                        {"name": "watson", "team": "sre", "namespace": "watson", "service_account": "agent-watson"}]},
          headers=ADMIN)
    return c, clock, aws, dd


@pytest.fixture
def gateway():
    """A room with a tool gateway: pods for an agent, the gateway and a stranger; AWS and Datadog minters."""
    return gateway_room()


GATEWAY = {"Authorization": "Bearer gateway-pod"}


def grant(c, agent, integration, permissions):
    rid = c.post("/requests", json={"agent": agent, "integration": integration, "permissions": permissions}, headers=OWNER).json()["id"]
    out = c.post("/requests/decide", json={"ids": [rid], "verdict": "approve"}, headers=ADMIN).json()["results"][0]
    assert out["status"] == "approved", out


def test_the_gateway_leases_for_a_granted_agent_and_nobody_else_may(gateway):
    c, _, aws, _ = gateway
    connect(c, ["aws_inventory_read"])
    grant(c, "ledger", "aws-prod", ["aws_inventory_read"])
    body = {"agent": "ledger", "integration": "aws-prod", "task": "count instances"}
    # Only the gateway's own pod identity: an agent's pod and a stranger's are 403, no token 401.
    assert c.post("/leases/for-agent", json=body, headers={"Authorization": "Bearer stray-pod"}).status_code == 403
    assert c.post("/leases/for-agent", json=body, headers={"Authorization": "Bearer ledger-pod"}).status_code == 403
    assert c.post("/leases/for-agent", json=body, headers={"Authorization": "Bearer nope"}).status_code == 401
    assert c.post("/leases/for-agent", json=body, headers=ADMIN).status_code == 401
    # The gateway, for a granted agent: the agent's grants, the agent's row, marked via gateway.
    r = c.post("/leases/for-agent", json=body, headers=GATEWAY)
    assert r.status_code == 200, r.text
    assert r.json()["granted"] == ["aws_inventory_read"] and r.json()["reused"] is False
    assert aws.minted[-1]["agent"] == "ledger"
    (row,) = c.get("/leases", headers=OWNER).json()["leases"]
    assert (row["agent"], row["via"], row["task"]) == ("ledger", "gateway", "count instances")
    # The agent's own path shares the live credential, and its own rows say via nothing.
    again = c.post("/leases", json={"integration": "aws-prod"}, headers={"Authorization": "Bearer ledger-pod"}).json()
    assert again["reused"] is True and again["lease_id"] == r.json()["lease_id"]
    # An ungranted agent gets nothing; an agent the room does not know is a 404; borrowing is refused.
    r = c.post("/leases/for-agent", json={"agent": "watson", "integration": "aws-prod"}, headers=GATEWAY)
    assert r.status_code == 403 and "holds nothing" in r.text
    r = c.post("/leases/for-agent", json={"agent": "moriarty", "integration": "aws-prod"}, headers=GATEWAY)
    assert r.status_code == 403 and r.json()["detail"] == "moriarty is not an agent this room knows"
    # Named permissions nobody granted: still one plain sentence (the agent's own path gets the list).
    r = c.post("/leases/for-agent", json={"agent": "watson", "integration": "aws-prod", "permissions": ["aws_inventory_read"]}, headers=GATEWAY)
    assert r.status_code == 403 and r.json()["detail"] == "watson does not hold aws_inventory_read on aws-prod"
    assert c.post("/leases/for-agent", json={"agent": "ledger", "integration": "nope"}, headers=GATEWAY).status_code == 404
    r = c.post("/leases/for-agent", json={**body, "on_behalf_of": ["watson"]}, headers=GATEWAY)
    assert r.status_code == 403 and r.json()["detail"] == "a credential is never borrowed for another agent's task"


def test_a_datadog_lease_is_a_scoped_key_that_a_revoke_or_expiry_deletes(gateway):
    c, clock, _, dd = gateway
    r = c.put("/integrations/datadog", json={"vendor": "datadog", "spec": {"service_account_id": "sa-123"},
                                            "ceiling": ["datadog_monitors_read", "datadog_metrics_read"]}, headers=ADMIN)
    assert r.status_code == 200 and r.json()["kind"] == "connection"
    assert c.get("/identity/datadog", headers=OWNER).json() == {"subject": "sa-123", "site": "datadoghq.com", "kind": "datadog_service_account"}
    assert c.post("/probe/datadog", json={}, headers=ADMIN).json()["subject"] == "sa-123"
    assert c.post("/probe/datadog", json={"role_arn": "sa-999"}, headers=ADMIN).status_code == 409
    grant(c, "ledger", "datadog", ["datadog_monitors_read", "datadog_metrics_read"])
    r = c.post("/leases/for-agent", json={"agent": "ledger", "integration": "datadog", "task": "which monitor fired"}, headers=GATEWAY)
    assert r.status_code == 200, r.text
    lease = r.json()
    assert lease["credential"] == {"dd_api_key": "api-xyz", "dd_app_key": "secret-kid-2", "dd_site": "datadoghq.com"}
    assert lease["expires_at"] == "2026-10-27T13:00:00Z" and lease["note"] == "application key scoped to the granted permissions"
    key = dd.keys["kid-2"]
    assert key["name"].startswith("bab-ledger-") and key["scopes"] == ["mcp_read", "metrics_read", "monitors_read", "timeseries_query"]
    # Revoking one permission deletes the key the agent holds: the next lease is narrower and new.
    gid = next(g["id"] for g in c.get("/agents/ledger/grants", headers=OWNER).json()["grants"] if g["permission"] == "datadog_metrics_read")
    assert c.delete(f"/grants/{gid}", headers=ADMIN).json() == {"revoked": gid, "leases_ended": 1}
    assert "kid-2" not in dd.keys
    r = c.post("/leases/for-agent", json={"agent": "ledger", "integration": "datadog"}, headers=GATEWAY).json()
    assert r["reused"] is False and r["credential"]["dd_app_key"] == "secret-kid-3" and dd.keys["kid-3"]["scopes"] == ["mcp_read", "monitors_read"]
    # Expiry: the next lease request, from anyone, deletes keys whose hour is up.
    clock["now"] = T0 + timedelta(hours=2)
    c.post("/leases/for-agent", json={"agent": "ledger", "integration": "datadog"}, headers=GATEWAY)
    assert set(dd.keys) == {"kid-4"}
    rows = c.get("/leases?agent=ledger", headers=OWNER).json()["leases"]  # newest first; the revoked one ended at 12:00
    assert [(x["via"], x["expires_at"][:16]) for x in rows] == [("gateway", "2026-10-27T15:00"), ("gateway", "2026-10-27T13:00"), ("gateway", "2026-10-27T12:00")]


def test_a_kept_datadog_key_is_still_leased_by_the_hour_and_goes_when_access_changes():
    """Keeping the key must cost nothing the lease gave: every hour is still a ledger row, a
    revoke still deletes the key the agent holds at once, and disconnecting leaves none behind."""
    from tests.conftest import FakeKeys

    keys = FakeKeys()
    c, clock, _, dd = gateway_room(keys)
    connection = {"vendor": "datadog", "spec": {"service_account_id": "sa-123"},
                  "ceiling": ["datadog_monitors_read", "datadog_metrics_read"]}
    c.put("/integrations/datadog", json=connection, headers=ADMIN)
    grant(c, "ledger", "datadog", ["datadog_monitors_read", "datadog_metrics_read"])
    ask = {"agent": "ledger", "integration": "datadog"}
    first = c.post("/leases/for-agent", json=ask, headers=GATEWAY).json()
    held = first["credential"]["dd_app_key"].removeprefix("secret-")
    assert dd.keys[held]["name"] == "bab-ledger" and first["expires_at"] == "2026-10-27T13:00:00Z"
    assert keys.stored["datadog.ledger"]["key_id"] == held
    # Two hours on the lease has run out and the key has not: a new row, the same key.
    clock["now"] = T0 + timedelta(hours=2)
    second = c.post("/leases/for-agent", json=ask, headers=GATEWAY).json()
    assert second["reused"] is False and second["lease_id"] != first["lease_id"]
    assert second["credential"] == first["credential"] and second["expires_at"] == "2026-10-27T15:00:00Z"
    assert set(dd.keys) == {held}
    # A lease that names its permissions is a key of its own: it cannot end the one the gateway holds.
    own = c.post("/leases", json={"integration": "datadog", "permissions": ["datadog_monitors_read"]},
                 headers={"Authorization": "Bearer ledger-pod"}).json()
    apart = own["credential"]["dd_app_key"].removeprefix("secret-")
    assert apart != held and dd.keys[apart]["name"].startswith("bab-ledger-2026")
    # Revoking one permission deletes both now. The next lease is narrower, on a new kept key.
    gid = next(g["id"] for g in c.get("/agents/ledger/grants", headers=OWNER).json()["grants"] if g["permission"] == "datadog_metrics_read")
    assert c.delete(f"/grants/{gid}", headers=ADMIN).json() == {"revoked": gid, "leases_ended": 2}
    assert dd.keys == {} and keys.stored == {}
    third = c.post("/leases/for-agent", json=ask, headers=GATEWAY).json()
    narrow = third["credential"]["dd_app_key"].removeprefix("secret-")
    assert dd.keys == {narrow: {"name": "bab-ledger", "scopes": ["mcp_read", "monitors_read"]}}
    # Disconnecting Datadog takes the kept key with the grants.
    assert c.delete("/integrations/datadog", headers=ADMIN).json()["grants_revoked"] == 1
    assert dd.keys == {} and keys.stored == {}


def test_a_kept_datadog_key_never_outlives_what_its_agent_holds():
    """A revoke tells the minter once, and a grant that runs out tells nobody. A key Datadog
    would not delete when asked, or whose grant ran out while its agent was not asking, must
    still go: every kept key is checked against the ledger as leases are made and on a sweep."""
    from tests.conftest import FakeKeys

    keys = FakeKeys()
    c, clock, _, dd = gateway_room(keys)
    c.put("/integrations/datadog", headers=ADMIN, json={
        "vendor": "datadog", "spec": {"service_account_id": "sa-123"},
        "ceiling": ["datadog_monitors_read", "datadog_metrics_read", "datadog_monitors_write"]})
    grant(c, "ledger", "datadog", ["datadog_monitors_read", "datadog_monitors_write"])
    grant(c, "watson", "datadog", ["datadog_monitors_read"])

    def lease(agent):
        return c.post("/leases/for-agent", json={"agent": agent, "integration": "datadog"}, headers=GATEWAY).json()

    def key_of(agent):
        return [k for k, v in dd.keys.items() if v["name"] == f"bab-{agent}"]

    def grant_id(agent, permission):
        return next(g["id"] for g in c.get(f"/agents/{agent}/grants", headers=OWNER).json()["grants"] if g["permission"] == permission)

    lease("ledger"), lease("watson")
    assert "monitors_write" in dd.keys[key_of("ledger")[0]]["scopes"] and len(dd.keys) == 2
    # The write grant runs out while ledger is idle. Another agent's lease is what notices.
    clock["now"] = T0 + timedelta(days=31)
    watsons = key_of("watson")
    lease("watson")
    assert key_of("ledger") == [] and key_of("watson") == watsons and set(keys.stored) == {"datadog.watson"}
    # Datadog refuses the delete when the last grant is revoked, and the agent never asks again.
    lease("ledger")
    stuck, dd.keep = key_of("ledger"), True
    c.delete(f"/grants/{grant_id('ledger', 'datadog_monitors_read')}", headers=ADMIN)
    assert key_of("ledger") == stuck
    dd.keep = False
    c.post("/sweep", headers=ADMIN)
    assert key_of("ledger") == [] and set(keys.stored) == {"datadog.watson"}
    # The same refusal, and then the connection goes: the key goes with it though its agent holds no grant by then.
    grant(c, "ledger", "datadog", ["datadog_monitors_read"])
    lease("ledger")
    dd.keep = True
    c.delete(f"/grants/{grant_id('ledger', 'datadog_monitors_read')}", headers=ADMIN)
    dd.keep = False
    assert len(key_of("ledger")) == 1
    assert c.delete("/integrations/datadog", headers=ADMIN).status_code == 200
    assert dd.keys == {} and keys.stored == {}


def test_a_change_on_one_vendor_never_asks_another_vendors_key_store():
    """A revoke, an approval or a refusal tells only the integration's own minter that the
    agent's access changed. An AWS revoke never waits on the store Datadog keeps its keys in."""
    from tests.conftest import FakeKeys

    keys = FakeKeys()
    c, _, _, _ = gateway_room(keys)
    connect(c, ["aws_inventory_read"])
    grant(c, "ledger", "aws-prod", ["aws_inventory_read"])
    asked = []
    names = keys.names
    keys.names = lambda: (asked.append(1), names())[1]
    gid = next(g["id"] for g in c.get("/agents/ledger/grants", headers=OWNER).json()["grants"])
    assert c.delete(f"/grants/{gid}", headers=ADMIN).status_code == 200
    assert c.post("/leases/for-agent", json={"agent": "ledger", "integration": "aws-prod"}, headers=GATEWAY).status_code == 403
    assert asked == []


def test_a_change_that_lands_while_a_lease_is_being_made_is_not_outrun_by_it():
    """A lease reads the grants, then mints. A revoke or an approval between the two finds no
    lease to end, and the key made a moment later would carry what was just taken back, for as
    long as the key is kept, or be a key the approval just deleted. The grants and the minter
    are asked again once the lease is recorded, and the lease is refused: ask again."""
    import threading

    from tests.conftest import FakeKeys

    keys = FakeKeys()
    c, clock, _, dd = gateway_room(keys)
    c.put("/integrations/datadog", headers=ADMIN, json={
        "vendor": "datadog", "spec": {"service_account_id": "sa-123"}, "ceiling": ["datadog_monitors_read", "datadog_metrics_read"]})
    grant(c, "ledger", "datadog", ["datadog_monitors_read", "datadog_metrics_read"])
    gid = next(g["id"] for g in c.get("/agents/ledger/grants", headers=OWNER).json()["grants"] if g["permission"] == "datadog_metrics_read")
    minter, revoked = c.app.state.datadog, []
    mint_standing = minter.mint_standing

    def racing(*args, **kwargs):
        if not revoked:
            t = threading.Thread(target=lambda: revoked.append(c.delete(f"/grants/{gid}", headers=ADMIN).status_code))
            t.start()
            t.join(20)
        return mint_standing(*args, **kwargs)

    minter.mint_standing = racing
    ask = {"agent": "ledger", "integration": "datadog"}
    refused = c.post("/leases/for-agent", json=ask, headers=GATEWAY)
    assert revoked == [200] and refused.status_code == 409 and "ask again" in refused.json()["detail"]
    assert dd.keys == {} and keys.stored == {}
    again = c.post("/leases/for-agent", json=ask, headers=GATEWAY).json()
    assert again["granted"] == ["datadog_monitors_read"]
    assert list(dd.keys.values()) == [{"name": "bab-ledger", "scopes": ["mcp_read", "monitors_read"]}]
    first = next(r for r in c.get("/leases", headers=ADMIN).json()["leases"] if sorted(r["permissions"]) == ["datadog_metrics_read", "datadog_monitors_read"])
    assert first["expires_at"] <= first["issued_at"]  # recorded, and ended at once

    # An approval in the same moment takes nothing away, and drops the key the lease was just
    # given, so the agent can have the wider one. The lease is refused rather than handed a
    # key Datadog no longer has.
    minter.mint_standing, approved = mint_standing, []
    clock["now"] = T0 + timedelta(hours=2)  # the lease in hand ran out: the next one is minted

    def approving(*args, **kwargs):
        out = mint_standing(*args, **kwargs)
        if not approved:
            t = threading.Thread(target=lambda: (grant(c, "ledger", "datadog", ["datadog_metrics_read"]), approved.append(1)))
            t.start()
            t.join(20)
        return out

    minter.mint_standing = approving
    raced = c.post("/leases/for-agent", json=ask, headers=GATEWAY)
    assert approved == [1] and raced.status_code == 409 and "ask again" in raced.json()["detail"]
    minter.mint_standing = mint_standing
    wide = c.post("/leases/for-agent", json=ask, headers=GATEWAY).json()
    assert sorted(wide["granted"]) == ["datadog_metrics_read", "datadog_monitors_read"]
    assert wide["credential"]["dd_app_key"].removeprefix("secret-") in dd.keys


def test_a_new_grant_ends_the_credential_in_hand_and_the_next_one_carries_both(gateway):
    c, _, _, dd = gateway
    c.put("/integrations/datadog", json={"vendor": "datadog", "spec": {"service_account_id": "sa-123"},
                                        "ceiling": ["datadog_monitors_read", "datadog_metrics_read"]}, headers=ADMIN)
    c.post("/probe/datadog", json={}, headers=ADMIN)
    grant(c, "ledger", "datadog", ["datadog_monitors_read"])
    ask = {"agent": "ledger", "integration": "datadog"}
    first = c.post("/leases/for-agent", json=ask, headers=GATEWAY).json()
    held = first["credential"]["dd_app_key"].removeprefix("secret-")
    assert dd.keys[held]["scopes"] == ["mcp_read", "monitors_read"]
    # Someone sees the agent needs more and approves it while that key is still good.
    rid = c.post("/requests", json={**ask, "permissions": ["datadog_metrics_read"]}, headers=OWNER).json()["id"]
    out = c.post("/requests/decide", json={"ids": [rid], "verdict": "approve"}, headers=ADMIN).json()["results"][0]
    assert out["status"] == "approved" and out["leases_ended"] == 1
    assert held not in dd.keys
    second = c.post("/leases/for-agent", json=ask, headers=GATEWAY).json()
    assert second["reused"] is False and second["lease_id"] != first["lease_id"]
    assert sorted(second["granted"]) == ["datadog_metrics_read", "datadog_monitors_read"]
    fresh = second["credential"]["dd_app_key"].removeprefix("secret-")
    assert dd.keys[fresh]["scopes"] == ["mcp_read", "metrics_read", "monitors_read", "timeseries_query"]
    # A denial changes nothing the agent holds, so its credential stays.
    rid = c.post("/requests", json={**ask, "permissions": ["datadog_metrics_read"]}, headers=OWNER).json()["id"]
    out = c.post("/requests/decide", json={"ids": [rid], "verdict": "deny", "reason": "held already"}, headers=ADMIN).json()["results"][0]
    assert "leases_ended" not in out and fresh in dd.keys


def test_the_gateway_lane_is_closed_until_a_gateway_is_named(pods):
    c, _ = pods
    r = c.post("/leases/for-agent", json={"agent": "ledger", "integration": "aws-prod"}, headers={"Authorization": "Bearer ledger-pod"})
    assert r.status_code == 501 and "BAB_GATEWAY_SERVICE_ACCOUNT" in r.text


def test_the_github_catalogue_is_three_labelled_levels(world):
    """GET /catalogue/github carries a `label` on every permission; a vendor without labels gets null."""
    c, _, _, _ = world
    tree = c.get("/catalogue/github", headers=OWNER).json()
    assert [g["name"] for g in tree["groups"]] == ["Repositories", "Pull requests"]
    assert tree["groups"][0]["permissions"] == [
        {"name": "github_repos_read", "tier": "read", "label": "Read",
         "description": "Read code, issues, pull requests, checks and workflow runs", "room_default": True}]
    # Read is the one level the room may allow itself (on an agent's own repository set).
    assert [p["room_default"] for p in tree["groups"][1]["permissions"]] == [False, False]
    assert [(p["name"], p["label"]) for p in tree["groups"][1]["permissions"]] == [
        ("github_pulls_review", "Review pull requests"), ("github_pulls_write", "Open pull requests")]
    aws = c.get("/catalogue/aws", headers=OWNER).json()
    assert all(p["label"] is None and p["room_default"] is False for g in aws["groups"] for p in g["permissions"])
    assert c.get("/catalogue", headers=OWNER).json()["vendors"][5]["permissions"] == {"read": 1, "mutate": 2}


def test_a_child_may_hang_under_a_service_connection_one_level_deep(world):
    c, _, _, _ = world
    r = c.put("/integrations/github", json={"vendor": "github", "spec": {"name": "github", "installation_id": "777"},
                                           "ceiling": ["github_repos_read", "github_pulls_write"]}, headers=ADMIN)
    assert r.status_code == 200 and r.json()["kind"] == "connection"
    # A repository set under the connection: kind account, parent the connection.
    r = c.put("/integrations/github-ledger", json={"vendor": "github", "parent": "github", "ceiling": ["github_pulls_write"],
                                                  "spec": {"name": "github-ledger", "repositories": ["acme-infra"]}}, headers=ADMIN)
    assert r.status_code == 200, r.text
    assert (r.json()["kind"], r.json()["parent"]) == ("account", "github")
    rows = {r["integration"]: r for r in c.get("/integrations", headers=OWNER).json()["integrations"]}
    assert rows["github"]["kind"] == "connection" and rows["github"]["parent"] is None and rows["github"]["repositories"] is None
    assert rows["github-ledger"]["parent"] == "github" and rows["github-ledger"]["repositories"] == ["acme-infra"]
    # One level deep: a parent that itself has a parent is refused; so is a parent of another vendor.
    r = c.put("/integrations/github-deeper", json={"vendor": "github", "parent": "github-ledger", "spec": {}}, headers=ADMIN)
    assert r.status_code == 422 and "one level deep" in r.json()["detail"]
    connect(c, ["aws_inventory_read"])
    r = c.put("/integrations/github-x", json={"vendor": "github", "parent": "aws-prod", "spec": {}}, headers=ADMIN)
    assert r.status_code == 422 and "not a connected github" in r.json()["detail"]
    # The connection cannot go while a child hangs under it.
    r = c.delete("/integrations/github", headers=ADMIN)
    assert r.status_code == 409 and "github-ledger" in r.json()["detail"]
    assert c.delete("/integrations/github-ledger", headers=ADMIN).json()["removed"] == "github-ledger"
    assert c.delete("/integrations/github", headers=ADMIN).json()["removed"] == "github"


@pytest.fixture
def repos():
    """A room with a GitHub connection and a tool gateway: the gateway asks for "github", an
    agent's grant lives on its own repository set under it."""
    clock = {"now": T0}
    store = FakeStore({Tuple("user:kyle@example.com", "member", "team:admins")})
    cat = catalogue.load("catalogues/room.yaml")
    gh = StaticMinter(now=lambda: clock["now"].timestamp())
    verifier = PodVerifier({"ledger-pod": ("agent-ledger", "ledger"), "gateway-pod": ("tool-gateway", "gateway")})
    ledger = Ledger()
    app = create_app(store, cat, ledger, verifier, ConsoleAuth("console-secret"), {"github": gh},
                     Settings(room="acme", admin_team="admins", security_team="security", now=lambda: clock["now"],
                              gateway_service_account="gateway/tool-gateway"))
    c = TestClient(app)
    c.put("/topology", json={"agents": [{"name": "ledger", "team": "sre", "namespace": "ledger", "service_account": "agent-ledger"},
                                        {"name": "watson", "team": "sre", "namespace": "watson", "service_account": "agent-watson"}]},
          headers=ADMIN)
    assert c.put("/integrations/github", json={"vendor": "github", "spec": {"name": "github", "installation_id": "777"},
                                              "ceiling": ["github_repos_read", "github_pulls_review", "github_pulls_write"]},
                 headers=ADMIN).status_code == 200
    for child, repo in (("github-ledger", "acme-infra"), ("github-ledger-web", "acme-web")):
        assert c.put(f"/integrations/{child}", json={"vendor": "github", "parent": "github", "ceiling": ["github_repos_read", "github_pulls_review"],
                                                    "spec": {"name": child, "repositories": [repo]}}, headers=ADMIN).status_code == 200
    return c, gh


def test_a_lease_on_the_connection_lands_on_the_one_child_the_agent_holds(repos):
    c, gh = repos
    # No grant anywhere: the existing 403, one sentence for the gateway.
    r = c.post("/leases/for-agent", json={"agent": "ledger", "integration": "github"}, headers=GATEWAY)
    assert r.status_code == 403 and r.json()["detail"] == "ledger holds nothing on github"
    assert c.post("/leases", json={"integration": "github"}, headers={"Authorization": "Bearer ledger-pod"}).status_code == 403
    # One child granted: the gateway asks for "github" and leases github-ledger, narrowed to its repositories.
    grant(c, "ledger", "github-ledger", ["github_repos_read", "github_pulls_review"])
    r = c.post("/leases/for-agent", json={"agent": "ledger", "integration": "github", "task": "review #12"}, headers=GATEWAY)
    assert r.status_code == 200, r.text
    lease = r.json()
    assert (lease["integration"], lease["resolved_from"], lease["vendor"]) == ("github-ledger", "github", "github")
    assert sorted(lease["granted"]) == ["github_pulls_review", "github_repos_read"]
    assert gh.minted[-1] == {"agent": "ledger", "integration": "github-ledger",
                             "spec": {"name": "github-ledger", "installation_id": "777", "repositories": ["acme-infra"]}}
    (row,) = c.get("/leases", headers=OWNER).json()["leases"]
    assert (row["integration"], row["via"]) == ("github-ledger", "gateway")
    # The agent's own path resolves the same way and shares the live credential.
    again = c.post("/leases", json={"integration": "github"}, headers={"Authorization": "Bearer ledger-pod"}).json()
    assert again["reused"] is True and again["integration"] == "github-ledger" and again["resolved_from"] == "github"
    # Named permissions are checked against the child; one it does not hold there is refused by name.
    r = c.post("/leases", json={"integration": "github", "permissions": ["github_repos_read", "github_pulls_write"]},
               headers={"Authorization": "Bearer ledger-pod"})
    assert r.status_code == 200 and r.json()["refused"] == ["github_pulls_write"] and "resolved_from" in r.json()
    # Asked for by its own name, the child leases as always, with no resolution to report.
    direct = c.post("/leases/for-agent", json={"agent": "ledger", "integration": "github-ledger"}, headers=GATEWAY).json()
    assert direct["integration"] == "github-ledger" and "resolved_from" not in direct
    # Two children granted: the agent must say which; the sentence names them.
    grant(c, "ledger", "github-ledger-web", ["github_repos_read"])
    r = c.post("/leases/for-agent", json={"agent": "ledger", "integration": "github"}, headers=GATEWAY)
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == ("ledger holds github on more than one of its integrations (github-ledger, github-ledger-web); "
                                  "ask for one by name")
    assert c.post("/leases/for-agent", json={"agent": "ledger", "integration": "github-ledger-web"}, headers=GATEWAY).json()["granted"] == ["github_repos_read"]
    assert gh.minted[-1]["spec"]["repositories"] == ["acme-web"]
    # A grant on the connection itself wins: no resolution, the connection's own spec (no repositories).
    grant(c, "watson", "github", ["github_repos_read"])
    r = c.post("/leases/for-agent", json={"agent": "watson", "integration": "github"}, headers=GATEWAY).json()
    assert r["integration"] == "github" and "resolved_from" not in r and "repositories" not in gh.minted[-1]["spec"]
    # Revoking the one child's grants takes the resolution with it.
    for g in c.get("/agents/ledger/grants", headers=OWNER).json()["grants"]:
        if g["integration"] == "github-ledger-web":
            c.delete(f"/grants/{g['id']}", headers=ADMIN)
    assert c.post("/leases/for-agent", json={"agent": "ledger", "integration": "github"}, headers=GATEWAY).json()["integration"] == "github-ledger"


def test_an_owner_picks_an_agents_repositories_and_a_reviewer_still_decides_what_they_are_for(repos):
    """Gate: an agent's repository set under a service connection is written by a caller on no
    team (the room vouches the person owns the agent). It grants nothing, so it is safe to pick;
    what stays a reviewer's is everything a pick could widen: any other integration, an empty
    set (the whole connection), and a repository added to a set that already carries grants,
    which the owner may ask for and a reviewer allows."""
    c, gh = repos

    def put(name, repositories, headers=OWNER, **body):
        return c.put(f"/integrations/{name}", headers=headers,
                     json={"vendor": "github", "parent": "github", "ceiling": ["github_repos_read", "github_pulls_write"],
                           "spec": {"name": name, "repositories": repositories}, **body})

    def held():
        rows = {i["integration"]: i for i in c.get("/integrations", headers=OWNER).json()["integrations"]}
        return rows["github-watson"]["repositories"]

    r = put("github-watson", ["acme-web"])
    assert r.status_code == 200, r.text
    assert (r.json()["kind"], r.json()["parent"]) == ("account", "github")
    # Picked, not granted: the gateway is still refused for watson.
    ask = {"agent": "watson", "integration": "github"}
    assert c.post("/leases/for-agent", json=ask, headers=GATEWAY).status_code == 403
    # Nothing granted on it yet, so the set may grow.
    assert put("github-watson", ["acme-web", "acme-infra"]).status_code == 200

    team = "owner@example.com is not on the admin or security team"
    # Not a repository set: no repositories named (or a name that names nothing), no parent, the
    # connection itself, another vendor's row.
    assert put("github-watson", []).json()["detail"] == team
    for nothing in (None, "acme-web", [""], ["acme/"], [{"name": "acme-web"}]):
        assert put("github-watson", nothing).json()["detail"] == team
    assert put("github-watson", ["acme-web"], parent="github-other").json()["detail"] == team
    assert put("github-other", ["acme-web"], parent=None).json()["detail"] == team
    assert put("github", ["acme-web"]).json()["detail"] == team
    connect(c, ["aws_inventory_read"])
    r = c.put("/integrations/aws-prod", headers=OWNER, json={"vendor": "aws", "ceiling": ["aws_inventory_read"],
                                                           "spec": {"role_arn": "arn:aws:iam::123456789012:role/Other"}})
    assert (r.status_code, r.json()["detail"]) == (403, team)

    # Once the set carries a grant, what an owner removes leaves at once and what they add waits.
    grant(c, "watson", "github-watson", ["github_repos_read"])
    first = c.post("/leases/for-agent", json=ask, headers=GATEWAY).json()
    r = put("github-watson", ["acme-web", "acme-secrets"])
    assert r.status_code == 202, r.text
    asked = r.json()["pending"]
    assert r.json()["repositories"] == held() == ["acme-web"]
    assert (asked["kind"], asked["status"], asked["agent"], asked["requested_by"]) == ("repositories", "pending", "watson", "owner@example.com")
    assert asked["proposal"] == {"added": ["acme-secrets"], "removed": []} and asked["permissions"] == ["github_repos_read"]
    # The set narrowed, so the credential in hand is dropped: the next one is for acme-web alone.
    second = c.post("/leases/for-agent", json=ask, headers=GATEWAY).json()
    assert second["reused"] is False and second["lease_id"] != first["lease_id"]
    assert gh.minted[-1]["spec"]["repositories"] == ["acme-web"]
    # Picking again replaces what waits; an owner cannot decide it.
    again = put("github-watson", ["acme-web", "acme-secrets", "acme-vault"]).json()["pending"]
    assert again["id"] == asked["id"] and again["proposal"]["added"] == ["acme-secrets", "acme-vault"]
    assert [q["id"] for q in c.get("/requests", headers=OWNER).json()["requests"]] == [asked["id"]]
    assert c.post("/requests/decide", json={"ids": [asked["id"]], "verdict": "approve"}, headers=OWNER).status_code == 403
    # A reviewer allows it: the set grows and the next credential carries it.
    out = c.post("/requests/decide", json={"ids": [asked["id"]], "verdict": "approve"}, headers=ADMIN).json()["results"][0]
    assert (out["status"], out["outcome"]) == ("approved", {"acme-secrets": "added", "acme-vault": "added"})
    assert held() == ["acme-secrets", "acme-vault", "acme-web"]
    third = c.post("/leases/for-agent", json=ask, headers=GATEWAY).json()
    assert third["reused"] is False and gh.minted[-1]["spec"]["repositories"] == ["acme-secrets", "acme-vault", "acme-web"]

    # A denial leaves the set as it was.
    rid = put("github-watson", ["acme-secrets", "acme-vault", "acme-web", "acme-infra"]).json()["pending"]["id"]
    c.post("/requests/decide", json={"ids": [rid], "verdict": "deny", "reason": "not that one"}, headers=ADMIN)
    assert held() == ["acme-secrets", "acme-vault", "acme-web"]
    # A pick that keeps nothing is not applied in part (it would empty the set): the swap waits whole.
    swap = put("github-watson", ["acme-infra"]).json()
    assert swap["repositories"] == ["acme-secrets", "acme-vault", "acme-web"]
    assert swap["pending"]["proposal"] == {"added": ["acme-infra"], "removed": ["acme-secrets", "acme-vault", "acme-web"]}
    # Saving the set without the addition takes back what waits; so does a reviewer writing the set.
    assert put("github-watson", ["acme-web"]).status_code == 200
    gone = [q for q in c.get("/requests", params={"status": "withdrawn"}, headers=OWNER).json()["requests"]]
    assert [(q["id"], q["decided_by"]) for q in gone] == [(swap["pending"]["id"], "owner@example.com")]
    assert put("github-watson", ["acme-web", "acme-infra"]).status_code == 202
    assert put("github-watson", ["acme-infra", "acme-web"], headers=ADMIN).status_code == 200
    assert held() == ["acme-infra", "acme-web"] and c.get("/requests", headers=OWNER).json()["requests"] == []
    # So does the owner saving the set exactly as it stands: the addition is unticked, nothing else moved.
    assert put("github-watson", ["acme-infra", "acme-web", "acme-vault"]).status_code == 202
    assert put("github-watson", ["acme-infra", "acme-web"]).status_code == 200
    assert held() == ["acme-infra", "acme-web"] and c.get("/requests", headers=OWNER).json()["requests"] == []


def test_every_repository_is_for_read_alone_and_widening_a_watched_set_to_it_waits_for_a_reviewer(repos):
    """Gate: an agent's repository set may be every repository the connection can see, for Read
    alone. An owner picks it like a named set. A level beyond Read is refused on it; a set that
    holds or is asked for more cannot become it, whoever writes it. Once the set carries a
    grant, every repository is a widening no reviewer looked at, so it waits for one; back to
    named repositories is a narrowing and lands."""
    c, gh = repos

    def put(name, spec, headers=OWNER):
        return c.put(f"/integrations/{name}", headers=headers,
                     json={"vendor": "github", "parent": "github", "spec": {"name": name, **spec},
                           "ceiling": ["github_repos_read", "github_pulls_review", "github_pulls_write"]})

    def held():
        rows = {i["integration"]: i for i in c.get("/integrations", headers=OWNER).json()["integrations"]}
        return rows["github-watson"]["repositories"], rows["github-watson"]["all_repositories"]

    assert put("github-watson", {"all_repositories": True}).status_code == 200
    assert held() == (None, True)
    ask = {"agent": "watson", "integration": "github-watson", "permissions": ["github_pulls_review"]}
    r = c.post("/requests", json=ask, headers=OWNER)
    assert r.status_code == 409 and "Read alone" in r.json()["detail"]
    grant(c, "watson", "github-watson", ["github_repos_read"])
    lease = c.post("/leases/for-agent", json={"agent": "watson", "integration": "github"}, headers=GATEWAY)
    assert lease.status_code == 200, lease.text
    assert gh.minted[-1]["spec"]["all_repositories"] is True and "repositories" not in gh.minted[-1]["spec"]
    # Back to a named set narrows, so it lands; widening the watched set again waits.
    assert put("github-watson", {"repositories": ["acme-web"]}).status_code == 200 and held() == (["acme-web"], False)
    r = put("github-watson", {"all_repositories": True})
    assert r.status_code == 202 and r.json()["pending"]["proposal"] == {"all": True, "added": [], "removed": []}
    assert held() == (["acme-web"], False)
    assert c.post("/requests/decide", json={"ids": [r.json()["pending"]["id"]], "verdict": "approve"},
                  headers=OWNER).status_code == 403
    out = c.post("/requests/decide", json={"ids": [r.json()["pending"]["id"]], "verdict": "approve"},
                 headers=ADMIN).json()["results"][0]
    assert (out["status"], out["outcome"]) == ("approved", {"every repository": "added"}) and held() == (None, True)
    # A set holding more than Read stays named, for an owner and for a reviewer.
    grant(c, "ledger", "github-ledger", ["github_pulls_review"])
    for headers in (OWNER, ADMIN):
        r = put("github-ledger", {"all_repositories": True}, headers=headers)
        assert r.status_code == 409 and "github_pulls_review" in r.json()["detail"], r.text


def test_a_database_born_before_repository_requests_gains_the_column(tmp_path):
    """`create_all` never alters a table: a requests table from an older bab gets `proposal` at boot."""
    from sqlalchemy import create_engine, inspect, text

    url = f"sqlite+pysqlite:///{tmp_path / 'bab.db'}"
    Ledger(url)
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE requests DROP COLUMN proposal"))
    Ledger(url)
    assert "proposal" in {col["name"] for col in inspect(engine).get_columns("requests")}


def test_events_read_newest_first_and_every_refusal_names_the_agent_and_integration(world):
    """`GET /events` (kobo#371, the Agents audit): console auth, newest first, `kind` repeats or takes a
    comma list, `agent` reads `detail.agent`, `since`/`until` bound `at`. A lease the agent holds nothing
    for, one it holds only in part, one borrowed for another agent's task and one the minter could not
    mint each leave a row whose detail carries the agent, the integration, the permissions and a reason."""
    from bab.service.minters import MintError

    c, _, clock, minter = world
    connect(c, ["aws_inventory_read", "aws_cost_read"])
    # Holds nothing: refused and recorded.
    assert c.post("/leases", json={"integration": "aws-prod"}, headers=AGENT).status_code == 403
    rid = c.post("/requests", json={"agent": "sherlock", "integration": "aws-prod", "permissions": ["aws_inventory_read"]}, headers=OWNER).json()["id"]
    c.post("/requests/decide", json={"ids": [rid], "verdict": "approve"}, headers=ADMIN)
    clock["now"] = T0 + timedelta(minutes=1)
    # Asks for what it does not hold: refused with the permission named.
    assert c.post("/leases", json={"integration": "aws-prod", "permissions": ["aws_cost_read"]}, headers=AGENT).status_code == 403
    clock["now"] = T0 + timedelta(minutes=2)
    # Another agent's task: the borrowing wall.
    assert c.post("/leases", json={"integration": "aws-prod", "on_behalf_of": ["watson"]}, headers=AGENT).status_code == 403
    clock["now"] = T0 + timedelta(minutes=3)
    # The minter says no.
    real = minter.mint
    minter.mint = lambda *a, **k: (_ for _ in ()).throw(MintError("the vendor is away"))
    assert c.post("/leases", json={"integration": "aws-prod", "task": "count instances"}, headers=AGENT).status_code == 502
    minter.mint = real
    clock["now"] = T0 + timedelta(minutes=4)
    assert c.post("/leases", json={"integration": "aws-prod"}, headers=AGENT).status_code == 200

    assert c.get("/events", headers=AGENT).status_code == 401
    rows = c.get("/events", headers=OWNER).json()["events"]
    assert [r["kind"] for r in rows if r["kind"].startswith("lease.")] == ["lease.failed", "lease.refused", "lease.refused", "lease.refused"]
    assert set(rows[0]) == {"id", "at", "kind", "actor", "detail"} and rows[0]["at"] > rows[-1]["at"]
    failed, borrowed, partial, nothing = [r for r in rows if r["kind"].startswith("lease.")]
    for r in (failed, borrowed, partial, nothing):
        assert r["actor"] == "sherlock" and r["detail"]["agent"] == "sherlock" and r["detail"]["integration"] == "aws-prod"
    assert nothing["detail"]["reason"] == "not granted" and nothing["detail"]["permissions"] == []
    assert partial["detail"]["reason"] == "not granted" and partial["detail"]["permissions"] == ["aws_cost_read"]
    assert borrowed["detail"]["reason"] == NO_BORROWING_SENTENCE and borrowed["detail"]["on_behalf_of"] == ["watson"]
    assert failed["detail"]["reason"] == "the vendor is away" and failed["detail"]["permissions"] == ["aws_inventory_read"]

    # The filters the room's Agents audit sends.
    both = c.get("/events?kind=lease.refused,lease.failed", headers=OWNER).json()["events"]
    assert [r["kind"] for r in both] == ["lease.failed", "lease.refused", "lease.refused", "lease.refused"]
    assert [r["kind"] for r in c.get("/events?kind=lease.refused&kind=lease.failed", headers=OWNER).json()["events"]] == [r["kind"] for r in both]
    assert len(c.get("/events?kind=lease.failed&agent=sherlock", headers=OWNER).json()["events"]) == 1
    assert c.get("/events?agent=watson", headers=OWNER).json()["events"] == []
    window = c.get("/events", params={"kind": "lease.refused", "since": (T0 + timedelta(minutes=1)).isoformat(),
                                      "until": (T0 + timedelta(minutes=2)).isoformat()}, headers=OWNER).json()["events"]
    assert [r["detail"]["permissions"] for r in window] == [["aws_cost_read"]]
    assert len(c.get("/events?limit=2", headers=OWNER).json()["events"]) == 2
    assert c.get("/events?limit=5000", headers=OWNER).status_code == 422


@pytest.fixture
def google():
    """The room with Google Cloud minting against a fake Google: AWS stays the static minter."""
    from bab.service.minters import GcpMinter
    from tests.conftest import FakeGoogle

    clock = {"now": T0}
    store = FakeStore({
        Tuple("user:kyle@example.com", "member", "team:admins"),
        Tuple("team:sre", "team", "agent:sherlock"),
    })
    cat = catalogue.load("catalogues/room.yaml")
    fake = FakeGoogle()
    app = create_app(store, cat, Ledger(), StaticVerifier({"sherlock-token": "sherlock"}), ConsoleAuth("console-secret"),
                     {"aws": StaticMinter(now=lambda: clock["now"].timestamp()),
                      "gcp": GcpMinter(http=fake, now=lambda: clock["now"].timestamp())},
                     Settings(room="acme", admin_team="admins", security_team="security", now=lambda: clock["now"]))
    return TestClient(app), fake, clock


def test_a_google_cloud_project_is_probed_connected_discovered_and_leased(google):
    from tests.conftest import BAB_EMAIL

    c, fake, clock = google
    # Identity: the service account an admin grants the role pack to.
    assert c.get("/identity/gcp", headers=OWNER).json() == {"subject": "1122334455", "email": BAB_EMAIL, "kind": "google_service_account"}
    # Probe, the Google way: the project id, with bab's own identity or through a service account.
    assert c.post("/probe/gcp", json={"project": "example-project"}, headers=OWNER).status_code == 403
    out = c.post("/probe/gcp", json={"project": "example-project"}, headers=ADMIN).json()
    assert out == {"project": "example-project", "project_number": "123456789012", "subject": BAB_EMAIL, "hops": 1}
    sa = "reader@example-project.iam.gserviceaccount.com"
    assert c.post("/probe/gcp", json={"project": "example-project", "service_account": sa}, headers=ADMIN).json()["hops"] == 2
    r = c.post("/probe/gcp", json={"project": "locked-project"}, headers=ADMIN)
    assert r.status_code == 409 and r.json()["detail"].startswith(f"{BAB_EMAIL} has no access on project locked-project")
    assert c.post("/probe/gcp", json={"parent": "folders/123"}, headers=ADMIN).json()["projects"] == 3  # the sub-folder's too
    # A project that serves models: `vertex_location` adds a Vertex check; a `vertex_url` the room sends is
    # accepted and never fetched (the token goes only to the URL bab builds). Vertex refusing is a 502.
    out = c.post("/probe/gcp", json={"project": "example-project", "vertex_location": "us-east5",
                                     "vertex_url": "https://attacker.example/collect"}, headers=ADMIN).json()
    assert out["vertex"] == {"location": "us-east5", "ok": True}
    assert not any("attacker.example" in u for _, u, _ in fake.calls)
    r = c.post("/probe/gcp", json={"project": "example-project", "vertex_location": "europe-west9"}, headers=ADMIN)
    assert r.status_code == 502 and "cannot reach Vertex AI in europe-west9" in r.json()["detail"]
    assert c.post("/probe/gcp", json={"role_arn": "arn:aws:iam::123456789012:role/x"}, headers=ADMIN).status_code == 409  # not a GCP field: ignored, nothing named
    # An organization row names a folder or organization; its accounts are the active projects under it.
    out = c.put("/integrations/example-org", json={"vendor": "gcp", "spec": {"parent_resource": "folders/123", "name": "example-org"}}, headers=ADMIN).json()
    assert out["kind"] == "org"
    accts = c.get("/integrations/example-org/accounts", headers=OWNER).json()
    assert [(a["id"], a["status"], a["connected"], a["folder_path"]) for a in accts["accounts"]] == [
        ("example-project", "ACTIVE", False, []), ("locked-project", "ACTIVE", False, []), ("nested-project", "ACTIVE", False, ["Dev"])]
    assert accts["accounts"][0]["project_number"] == "123456789012"
    # A project under it: kind account, no role to look for; discover marks the one bab can read.
    out = c.put("/integrations/example-project", json={"vendor": "gcp", "parent": "example-org", "ceiling": ["gcp_compute_read", "gcp_vertex_ai_user"],
                                                       "spec": {"project": "example-project", "name": "example-project"}}, headers=ADMIN).json()
    assert out["kind"] == "account" and out["parent"] == "example-org"
    rows = {r["integration"]: r for r in c.get("/integrations", headers=OWNER).json()["integrations"]}
    assert rows["example-org"]["parent_resource"] == "folders/123" and rows["example-project"]["project"] == "example-project"
    assert rows["example-project"]["parent_resource"] is None and rows["example-org"]["hub_role_arn"] is None
    found = c.post("/integrations/example-org/discover", json={}, headers=ADMIN).json()
    assert found["organization"] == "example-org" and found["parent"] == "folders/123" and "external_id" not in found
    by_id = {a["id"]: a for a in found["accounts"]}
    assert by_id["example-project"]["connected"] is True and by_id["example-project"]["reachable"] is True
    # Every project the search returned is readable by construction: no per-project probe.
    assert by_id["locked-project"]["connected"] is False and by_id["locked-project"]["reachable"] is True
    assert by_id["locked-project"]["reason"] is None
    assert "role_arn" not in by_id["example-project"]
    # A project two folders down is discovered too, with the folders between it and the parent.
    assert by_id["nested-project"]["reachable"] is True and by_id["nested-project"]["folder_path"] == ["Dev"]
    # A lease on the project is an access token for bab's own identity, capped at the token's own end.
    rid = c.post("/requests", json={"agent": "sherlock", "integration": "example-project", "permissions": ["gcp_compute_read"]}, headers=OWNER).json()["id"]
    c.post("/requests/decide", json={"ids": [rid], "verdict": "approve"}, headers=ADMIN)
    r = c.post("/leases", json={"integration": "example-project"}, headers=AGENT)
    assert r.status_code == 200, r.text
    lease = r.json()
    assert lease["credential"]["gcp_project"] == "example-project" and lease["credential"]["gcp_access_token"].startswith("own-")
    assert lease["note"] == "access token for bab's own identity; narrowing is bab's check only, the token carries the role pack"
    assert lease["expires_at"] == "2026-10-27T12:30:00Z"  # the metadata token's 30 minutes, not the tier's hour
    # A lease on the organization is refused, as for AWS; a project that names a service account impersonates it.
    assert c.post("/leases", json={"integration": "example-org", "permissions": ["gcp_compute_read"]}, headers=AGENT).status_code == 409
    c.put("/integrations/example-project", json={"vendor": "gcp", "parent": "example-org", "ceiling": ["gcp_compute_read"],
                                                 "spec": {"project": "example-project", "service_account": sa, "name": "example-project"}}, headers=ADMIN)
    clock["now"] = T0 + timedelta(hours=2)
    lease = c.post("/leases", json={"integration": "example-project"}, headers=AGENT).json()
    assert lease["credential"]["gcp_access_token"].startswith("imp-") and lease["note"].startswith(f"access token for {sa};")
    assert fake.calls[-1][2] == {"scope": ["https://www.googleapis.com/auth/cloud-platform"], "lifetime": "3600s"}


def test_a_google_cloud_row_lists_vertex_ai_chat_models_for_its_vertex_project(google):
    from tests.conftest import BAB_EMAIL

    c, fake, _ = google
    # An organization row that names its Vertex project the way the console writes it, and a project row.
    c.put("/integrations/example-org", json={"vendor": "gcp", "spec": {"parent_resource": "organizations/123", "name": "example-org",
                                                                        "models": {"provider": "vertex_ai", "project": "example-project", "location": "us-east5"}}}, headers=ADMIN)
    c.put("/integrations/example-project", json={"vendor": "gcp", "parent": "example-org", "ceiling": ["gcp_vertex_ai_user"],
                                                 "spec": {"project": "example-project", "name": "example-project"}}, headers=ADMIN)
    c.put("/integrations/locked-project", json={"vendor": "gcp", "ceiling": ["gcp_vertex_ai_user"],
                                                "spec": {"project": "locked-project", "name": "locked-project"}}, headers=ADMIN)
    # Console auth and the reviewer gate, as for discover.
    assert c.get("/integrations/example-org/models").status_code == 401
    assert c.get("/integrations/example-org/models", headers=OWNER).status_code == 403
    assert c.get("/integrations/nope/models", headers=ADMIN).status_code == 404
    out = c.get("/integrations/example-org/models", headers=ADMIN).json()
    assert out["integration"] == "example-org" and out["provider"] == "vertex_ai" and out["fetched_at"] == "2026-10-27T12:00:00Z"
    assert [m["id"] for m in out["models"]] == ["claude-3-5-sonnet-v2", "claude-opus-4-1", "claude-sonnet-4-6",
                                                "gemini-2.0-flash-001", "gemini-2.5-flash", "gemini-2.5-pro"]
    assert out["models"][2] == {"id": "claude-sonnet-4-6", "label": "Claude Sonnet 4.6", "publisher": "Anthropic",
                                "family": "claude", "stage": "GA", "via": None}
    # Only the global endpoint was asked, both publishers, billed to the Vertex project; a probe's token path.
    urls = [u for _, u, _ in fake.calls if "/v1beta1/publishers/" in u]
    assert len(urls) == 3 and all(u.startswith("https://aiplatform.googleapis.com/v1beta1/publishers/") for u in urls)
    assert {u.split("/publishers/")[1].split("/")[0] for u in urls} == {"google", "anthropic"}
    assert all(h.get("x-goog-user-project") == "example-project" for h in fake.headers[-3:])
    assert fake.headers[-1]["Authorization"].startswith("Bearer own-")
    # The project row answers the same list from its own project; a location is checked, not sent.
    assert len(c.get("/integrations/example-project/models?location=global", headers=ADMIN).json()["models"]) == 6
    r = c.get("/integrations/example-project/models?location=nowhere", headers=ADMIN)
    assert r.status_code == 502 and "is not a Vertex AI location" in r.json()["detail"]
    # Google refusing is a 502 with its sentence, naming the identity and the project.
    r = c.get("/integrations/locked-project/models", headers=ADMIN)
    assert r.status_code == 502
    assert r.json()["detail"].startswith(f"{BAB_EMAIL} cannot list Vertex AI's google models for project locked-project:")
    assert "publisherModels.list" in r.json()["detail"]
    # An organization row that names no Vertex project cannot list.
    c.put("/integrations/bare-org", json={"vendor": "gcp", "spec": {"parent_resource": "folders/9", "name": "bare-org"}}, headers=ADMIN)
    r = c.get("/integrations/bare-org/models", headers=ADMIN)
    assert r.status_code == 409 and "names no Vertex AI project" in r.json()["detail"]


@pytest.fixture
def bedrock():
    """The room with a real AwsMinter over faked STS and Bedrock: who was assumed, which region was read."""
    from bab.service.minters import AwsMinter
    from tests.conftest import BEDROCK_MODELS, BEDROCK_PROFILES

    clock = {"now": T0}
    calls = {"hops": [], "listed": []}

    def assume(role_arn, token, name, seconds, policy):
        calls["hops"].append(("web-identity", role_arn, name))
        return {"Credentials": {"AccessKeyId": "HUB" if "Hub" in role_arn else "FLAT", "SecretAccessKey": "s", "SessionToken": "t",
                                "Expiration": T0}, "AssumedRoleUser": {"Arn": role_arn.replace(":role/", ":assumed-role/") + f"/{name}"}}

    def assume_role(creds, role_arn, name, seconds, policy, external_id):
        calls["hops"].append(("assume-role", creds["AccessKeyId"], role_arn, name, external_id))
        return {"Credentials": {"AccessKeyId": "SPOKE", "SecretAccessKey": "s", "SessionToken": "t", "Expiration": T0},
                "AssumedRoleUser": {"Arn": role_arn.replace(":role/", ":assumed-role/") + f"/{name}"}}

    def list_bedrock(creds, region):
        calls["listed"].append((creds["AccessKeyId"], region))
        if region == "eu-west-1":
            from bab.service.minters import MintError
            raise MintError("AWS refused listing Bedrock models in eu-west-1: AccessDeniedException not authorized")
        return BEDROCK_MODELS, BEDROCK_PROFILES

    store = FakeStore({Tuple("user:kyle@example.com", "member", "team:admins"), Tuple("team:sre", "team", "agent:sherlock")})
    cat = catalogue.load("catalogues/room.yaml")
    app = create_app(store, cat, Ledger(), StaticVerifier({"sherlock-token": "sherlock"}), ConsoleAuth("console-secret"),
                     {"aws": AwsMinter(token_source=lambda aud: "jwt", assume=assume, assume_role=assume_role, list_bedrock=list_bedrock)},
                     Settings(room="acme", admin_team="admins", security_team="security", now=lambda: clock["now"]))
    return TestClient(app), calls


def test_an_aws_row_lists_bedrock_models_through_its_role_and_other_vendors_cannot(bedrock):
    c, calls = bedrock
    hub = "arn:aws:iam::999999999999:role/KoboAccess-Hub"
    c.put("/integrations/aws-prod", json={"vendor": "aws", "ceiling": ["aws_inventory_read"],
                                          "spec": {"role_arn": "arn:aws:iam::123456789012:role/KoboAccess-Role"}}, headers=ADMIN)
    c.put("/integrations/acme-aws", json={"vendor": "aws", "spec": {"hub_role_arn": hub, "external_id": "org-x", "name": "acme-aws"}}, headers=ADMIN)
    c.put("/integrations/acme-data", json={"vendor": "aws", "parent": "acme-aws", "ceiling": ["aws_inventory_read"],
                                           "spec": {"spoke_role_arn": "arn:aws:iam::111111111111:role/KoboAccess-Role", "account_id": "111111111111"}}, headers=ADMIN)
    assert c.put("/integrations/github", json={"vendor": "github", "spec": {"installation_id": "777"}, "ceiling": ["github_repos_read"]}, headers=ADMIN).status_code == 200
    # A flat role: one hop, the default region, the mapped list.
    out = c.get("/integrations/aws-prod/models", headers=ADMIN).json()
    assert out["integration"] == "aws-prod" and out["provider"] == "bedrock" and out["fetched_at"] == "2026-10-27T12:00:00Z"
    assert calls["hops"][-1] == ("web-identity", "arn:aws:iam::123456789012:role/KoboAccess-Role", "bab-models")
    assert calls["listed"][-1] == ("FLAT", "us-east-1")
    by_id = {m["id"]: m for m in out["models"]}
    assert by_id["us.anthropic.claude-sonnet-4-5-20250929-v1:0"]["via"] == "inference-profile"
    assert by_id["anthropic.claude-3-haiku-20240307-v1:0"]["via"] == "on-demand"
    assert "meta.llama3-3-70b-instruct-v1:0" not in by_id and not any("canvas" in k or "embed" in k for k in by_id)
    # An account under an organization: through the hub with the organization's external id, in the asked region.
    out = c.get("/integrations/acme-data/models?region=us-west-2", headers=ADMIN).json()
    assert calls["hops"][-2:] == [("web-identity", hub, "bab-models"),
                                  ("assume-role", "HUB", "arn:aws:iam::111111111111:role/KoboAccess-Role", "bab-models", "org-x")]
    assert calls["listed"][-1] == ("SPOKE", "us-west-2") and len(out["models"]) == 6
    # The organization row itself has no role to list with; AWS refusing is a 502 with its sentence.
    r = c.get("/integrations/acme-aws/models", headers=ADMIN)
    assert r.status_code == 409 and "is an organization" in r.json()["detail"]
    r = c.get("/integrations/aws-prod/models?region=eu-west-1", headers=ADMIN)
    assert r.status_code == 502 and r.json()["detail"].startswith("AWS refused listing Bedrock models in eu-west-1")
    # A vendor that is not a cloud with models, or one whose minter cannot list, is 501.
    r = c.get("/integrations/github/models", headers=ADMIN)
    assert r.status_code == 501 and r.json()["detail"] == "bab cannot list models for 'github'"


def test_a_cloud_row_whose_minter_cannot_list_models_is_501(world):
    c, _, _, _ = world  # the static AWS minter has no list_models
    connect(c, ["aws_inventory_read"])
    assert c.get("/integrations/aws-prod/models", headers=ADMIN).status_code == 501


def test_an_owners_pick_changes_the_repositories_and_nothing_else(repos):
    """Gate: of an owner's write the service takes the repositories alone. The ceiling and the
    rest of the spec of an existing set stay a reviewer's; a new set starts with the repositories
    only; the lane is for a vendor whose credential is narrowed by them; and naming the `agents`
    vendor does not open another vendor's row."""
    c, gh = repos
    team = "owner@example.com is not on the admin or security team"

    def put(name, spec, ceiling, headers=OWNER, vendor="github", parent="github"):
        return c.put(f"/integrations/{name}", headers=headers,
                     json={"vendor": vendor, "parent": parent, "ceiling": ceiling, "spec": spec})

    def row(name):
        return {i["integration"]: i for i in c.get("/integrations", headers=ADMIN).json()["integrations"]}[name]

    # A reviewer made this set, with a ceiling short of opening pull requests.
    made = {"name": "docs only", "repositories": ["acme-docs"]}
    assert put("github-watson", made, ["github_repos_read"], headers=ADMIN).status_code == 200
    r = put("github-watson", {"name": "anything", "installation_id": "999", "repositories": [" acme-docs ", "acme-docs", "acme-web"]},
            ["github_repos_read", "github_pulls_write"])
    assert (r.status_code, r.json()["ceiling"]) == (200, ["github_repos_read"])
    held = row("github-watson")
    assert (held["ceiling"], held["name"], held["repositories"]) == (["github_repos_read"], "docs only", ["acme-docs", "acme-web"])
    grant(c, "watson", "github-watson", ["github_repos_read"])
    c.post("/leases/for-agent", json={"agent": "watson", "integration": "github"}, headers=GATEWAY)
    assert gh.minted[-1]["spec"].get("installation_id") != "999"
    asked = c.post("/requests", json={"agent": "watson", "integration": "github-watson", "permissions": ["github_pulls_write"]},
                   headers=OWNER).json()
    out = c.post("/requests/decide", json={"ids": [asked["id"]], "verdict": "approve"}, headers=ADMIN).json()["results"][0]
    assert out["status"] == "refused"

    # A set an owner starts carries the repositories and nothing else of what was sent.
    r = put("github-watson-web", {"name": "reviewed", "installation_id": "999", "repositories": ["acme-web"]}, ["github_repos_read"])
    assert r.status_code == 200, r.text
    assert (row("github-watson-web")["name"], row("github-watson-web")["repositories"]) == ("github-watson-web", ["acme-web"])
    grant(c, "watson", "github-watson-web", ["github_repos_read"])
    c.post("/leases/for-agent", json={"agent": "watson", "integration": "github-watson-web"}, headers=GATEWAY)
    assert gh.minted[-1]["spec"].get("installation_id") != "999" and gh.minted[-1]["spec"]["repositories"] == ["acme-web"]

    # Another vendor's connection takes no repository sets from an owner.
    connect(c, ["aws_inventory_read"])
    r = put("aws-prod-watson", {"repositories": ["x"]}, ["aws_inventory_read"], vendor="aws", parent="aws-prod")
    assert (r.status_code, r.json()["detail"]) == (403, team)

    # The agents lane writes agents rows: it does not turn this one into one (and so into one anybody may delete).
    r = put("github-watson", {}, [], vendor="agents", parent=None)
    assert (r.status_code, r.json()["detail"]) == (403, team)
    assert c.delete("/integrations/github-watson", headers=OWNER).status_code == 403
    assert row("github-watson")["vendor"] == "github"


def test_a_level_being_asked_for_holds_the_set_as_a_grant_does(repos):
    """Gate: a reviewer deciding a level request is saying yes to the set as they see it. So a
    request still waiting holds the set the way a grant does (what an owner adds waits beside
    it), a waiting pick is read against the levels on the set now, and a set that is
    disconnected takes what waited on it along."""
    c, gh = repos

    def put(repositories, headers=OWNER):
        return c.put("/integrations/github-watson", headers=headers,
                     json={"vendor": "github", "parent": "github", "ceiling": ["github_repos_read", "github_pulls_write"],
                           "spec": {"repositories": repositories}})

    def waiting():
        return c.get("/requests", headers=ADMIN).json()["requests"]

    def held():
        rows = {i["integration"]: i for i in c.get("/integrations", headers=ADMIN).json()["integrations"]}
        return rows["github-watson"]["repositories"]

    def ask(permissions):
        return c.post("/requests", json={"agent": "watson", "integration": "github-watson", "permissions": permissions},
                      headers=OWNER).json()["id"]

    def decide(ids, verdict="approve"):
        return c.post("/requests/decide", json={"ids": ids, "verdict": verdict, "reason": "no"}, headers=ADMIN).json()["results"]

    assert put(["acme-web"]).status_code == 200
    level = ask(["github_pulls_write"])
    # The swap an owner could make while the reviewer reads the request: it waits beside it.
    r = put(["acme-secrets", "acme-vault"])
    assert r.status_code == 202, r.text
    pick = r.json()["pending"]
    assert (pick["agent"], pick["permissions"], held()) == ("watson", ["github_pulls_write"], ["acme-web"])
    assert pick["proposal"] == {"added": ["acme-secrets", "acme-vault"], "removed": ["acme-web"]}
    assert [q["id"] for q in waiting()] == [level, pick["id"]]
    # The level is allowed on the set the reviewer saw; the swap is its own yes, and it carries what it replaces out.
    assert decide([level])[0]["status"] == "approved"
    c.post("/leases/for-agent", json={"agent": "watson", "integration": "github"}, headers=GATEWAY)
    assert gh.minted[-1]["spec"]["repositories"] == ["acme-web"]
    out = decide([pick["id"]])[0]
    assert out["outcome"] == {"acme-web": "removed", "acme-secrets": "added", "acme-vault": "added"}
    assert held() == ["acme-secrets", "acme-vault"]

    # A pick shows the levels on its set as they stand: one asked for after it counts.
    pick = put(["acme-secrets", "acme-vault", "acme-infra"]).json()["pending"]
    assert pick["permissions"] == ["github_pulls_write"]
    more = ask(["github_repos_read"])
    assert [q["permissions"] for q in waiting() if q["id"] == pick["id"]] == [["github_pulls_write", "github_repos_read"]]
    decide([more], "deny")
    assert [q["permissions"] for q in waiting() if q["id"] == pick["id"]] == [["github_pulls_write"]]

    # Disconnected: what waited on the set is taken back, and a set that later takes the name starts clean.
    again = ask(["github_repos_read"])
    assert c.delete("/integrations/github-watson", headers=ADMIN).status_code == 200
    assert waiting() == []
    gone = c.get("/requests", params={"status": "withdrawn"}, headers=ADMIN).json()["requests"]
    assert sorted(q["id"] for q in gone) == [pick["id"], again]
    assert put(["acme-docs"]).status_code == 200
    assert decide([pick["id"], again])[0]["status"] == "skipped" and held() == ["acme-docs"]



ROOM = {"X-Bab-Console-Token": "console-secret", "X-Bab-Actor": "room@acme"}


def test_the_room_allows_the_default_it_asked_for_and_nothing_else(repos):
    """Gate: one caller on no team may approve, and only its own default. The room asks for
    Read on a newborn agent's repository set as itself (`room@<room>`) with nobody there to
    click yes, so it may say yes to exactly that: a pending level request it raised, every
    permission marked `room_default` in the catalogue, on a set that names repositories under
    a service connection. Anything else in the batch refuses the whole batch with the
    sentence every non-reviewer gets, and leaves what was asked waiting for a reviewer."""
    c, gh = repos
    assert Settings(room="acme", admin_team="admins", security_team="security").room_actor == "room@acme"
    team = "room@acme is not on the admin or security team"

    def put(name, repositories, headers=ROOM):
        return c.put(f"/integrations/{name}", headers=headers,
                     json={"vendor": "github", "parent": "github", "ceiling": ["github_repos_read", "github_pulls_write"],
                           "spec": {"repositories": repositories}})

    def ask(integration, permissions, headers=ROOM, agent="watson"):
        r = c.post("/requests", json={"agent": agent, "integration": integration, "permissions": permissions}, headers=headers)
        assert r.status_code == 201, r.text
        return r.json()["id"]

    def decide(ids, headers=ROOM, verdict="approve", **body):
        return c.post("/requests/decide", json={"ids": ids, "verdict": verdict, **body}, headers=headers)

    def refused(ids, **kw):
        r = decide(ids, **kw)
        return (r.status_code, r.json()["detail"]) == (403, team)

    def waiting():
        return [q["id"] for q in c.get("/requests", headers=ADMIN).json()["requests"]]

    # An agent is born: the room writes its set, asks for Read as itself, and says yes.
    assert put("github-watson", ["acme-watson"]).status_code == 200
    born = ask("github-watson", ["github_repos_read"])
    r = decide([born])
    assert r.status_code == 200, r.text
    assert r.json()["results"] == [{"id": born, "status": "approved", "outcome": {"github_repos_read": "granted"},
                                    "leases_ended": 0}]
    held = c.get("/agents/watson/grants", headers=OWNER).json()["grants"]
    assert [(g["integration"], g["permission"], g["granted_by"], g["expires_at"]) for g in held] == [
        ("github-watson", "github_repos_read", "room@acme", None)]
    lease = c.post("/leases/for-agent", json={"agent": "watson", "integration": "github"}, headers=GATEWAY).json()
    assert lease["granted"] == ["github_repos_read"] and gh.minted[-1]["spec"]["repositories"] == ["acme-watson"]
    # The ledger names the room as the one who decided, and says it was a default.
    event = c.get("/events?kind=request.decided", headers=OWNER).json()["events"][0]
    assert (event["actor"], event["detail"]) == ("room@acme", {"verdict": "approve", "ids": [born], "room_default": True})
    asked = c.get("/requests", params={"status": "approved"}, headers=OWNER).json()["requests"][-1]
    assert (asked["id"], asked["requested_by"], asked["decided_by"]) == (born, "room@acme", "room@acme")

    # Decided once: the room has no second say on it, as it has none on anything already decided.
    assert refused([born])
    # A repository added to a set that carries a grant waits for a reviewer, whoever picked it:
    # the room's own pick, with Read the only level on the set, is still not the room's to allow.
    r = put("github-watson", ["acme-watson", "acme-secrets"])
    assert r.status_code == 202, r.text
    pick = r.json()["pending"]["id"]
    assert (r.json()["pending"]["requested_by"], r.json()["pending"]["permissions"]) == ("room@acme", ["github_repos_read"])
    assert refused([pick])
    # A request a person raised is a reviewer's, even for the same level on the same set.
    mine = ask("github-watson", ["github_repos_read"], headers=OWNER)
    assert refused([mine])
    # A level the catalogue does not mark, alone or beside one it does.
    more = ask("github-watson", ["github_pulls_write"])
    both = ask("github-watson", ["github_repos_read", "github_pulls_write"])
    assert refused([more]) and refused([both])
    # The connection itself is every repository; so is a set that names none. Never a default.
    whole = ask("github", ["github_repos_read"])
    assert c.put("/integrations/github-all", headers=ADMIN,
                 json={"vendor": "github", "parent": "github", "ceiling": ["github_repos_read"], "spec": {}}).status_code == 200
    unnamed = ask("github-all", ["github_repos_read"])
    assert refused([whole]) and refused([unnamed])
    # The room approves; it does not deny. And nobody else on no team decides the room's request.
    again = ask("github-ledger", ["github_repos_read"], agent="ledger")
    assert refused([again], verdict="deny", reason="no")
    for other in ("owner@example.com", "room@elsewhere"):
        r = decide([again], headers={**ROOM, "X-Bab-Actor": other})
        assert (r.status_code, r.json()["detail"]) == (403, f"{other} is not on the admin or security team")
    # An agent's default is on its own set: Read for one agent on another's set is a reviewer's.
    crossed = ask("github-watson", ["github_repos_read"], agent="ledger")
    assert refused([crossed])
    # One request in a batch that is not a default refuses the batch: nothing in it is decided.
    assert refused([again, mine]) and refused([again, 9999])
    assert waiting() == [pick, mine, more, both, whole, unnamed, again, crossed]
    assert [g["integration"] for g in c.get("/agents/ledger/grants", headers=OWNER).json()["grants"]] == []
    # Alone, it is the room's to allow; what the room could not decide is still a reviewer's.
    assert decide([again]).json()["results"][0]["status"] == "approved"
    out = decide([mine, more, pick], headers=ADMIN).json()["results"]
    assert [o["status"] for o in out] == ["approved", "approved", "approved"]


def test_the_room_says_an_agent_is_gone_and_what_it_held_goes_with_it(repos):
    """Gate: `DELETE /agents/{agent}` is the room's own fact, like the topology: any actor
    holding the console token may say it, and it is refused while the topology still lists
    the agent. It takes back everything the agent held anywhere (grants, the tuples, the
    credential in hand, requests still waiting), removes its repository set and its `agents`
    row (so nobody is left allowed to talk to it), and keeps a set another agent still uses.
    Saying it again finds nothing."""
    c, gh = repos

    def put(name, repositories, headers=ROOM):
        return c.put(f"/integrations/{name}", headers=headers,
                     json={"vendor": "github", "parent": "github", "ceiling": ["github_repos_read", "github_pulls_write"],
                           "spec": {"repositories": repositories}})

    def rows():
        return {i["integration"] for i in c.get("/integrations", headers=OWNER).json()["integrations"]}

    def held(agent):
        return sorted((g["integration"], g["permission"]) for g in c.get(f"/agents/{agent}/grants", headers=OWNER).json()["grants"])

    def verdict(agent, action, integration):
        return c.post("/check", json={"agent": agent, "action": action, "object": f"integration:{integration}"},
                      headers=OWNER).json()["verdict"]

    for name in ("ledger", "watson"):
        assert c.put(f"/integrations/{name}", json={"vendor": "agents", "spec": {"name": name}, "ceiling": ["a2a_ask"]},
                     headers=ROOM).status_code == 200
    assert put("github-watson", ["acme-watson"]).status_code == 200
    grant(c, "watson", "github-watson", ["github_repos_read"])
    grant(c, "watson", "github-ledger", ["github_repos_read"])  # a level on another agent's set
    grant(c, "ledger", "github-ledger", ["github_repos_read"])
    grant(c, "ledger", "github-watson", ["github_repos_read"])  # and another agent on this one's
    grant(c, "watson", "ledger", ["a2a_ask"])
    grant(c, "ledger", "watson", ["a2a_ask"])
    asked = c.post("/requests", json={"agent": "watson", "integration": "github-watson", "permissions": ["github_pulls_write"]},
                   headers=OWNER).json()["id"]
    elsewhere = c.post("/requests", json={"agent": "watson", "integration": "github-ledger", "permissions": ["github_pulls_review"]},
                       headers=OWNER).json()["id"]
    c.post("/leases/for-agent", json={"agent": "watson", "integration": "github-watson"}, headers=GATEWAY)
    c.post("/leases/for-agent", json={"agent": "ledger", "integration": "github-ledger"}, headers=GATEWAY)

    # Still in the topology: a living agent keeps what it holds.
    r = c.delete("/agents/watson", headers=ROOM)
    assert r.status_code == 409 and "push the topology without it first" in r.json()["detail"]
    assert len(held("watson")) == 3 and verdict("watson", "github_repos_read", "github-watson") == "allow"
    assert c.delete("/agents/watson", headers=AGENT).status_code == 401

    topology = {"agents": [{"name": "ledger", "team": "sre", "namespace": "ledger", "service_account": "agent-ledger"}]}
    assert c.put("/topology", json=topology, headers=ROOM).json()["removed"] == 1
    out = c.delete("/agents/watson", headers=OWNER)
    assert out.status_code == 200, out.text
    # Its three grants and the one that let ledger talk to it (four grant tuples, and the room
    # link and the team's ceiling on its `agents` row); both requests; the credential in hand.
    # Its `agents` row goes; its set stays, because ledger still holds a level there.
    assert out.json() == {"agent": "watson", "grants_revoked": 4, "requests_withdrawn": 2, "integrations_removed": 1,
                          "tuples_deleted": 6, "leases_ended": 1, "removed": ["watson"], "kept": ["github-watson"]}
    assert held("watson") == [] and len(gh.ended) == 1
    for action, integration in (("github_repos_read", "github-watson"), ("github_repos_read", "github-ledger"), ("a2a_ask", "ledger")):
        assert verdict("watson", action, integration) == "deny"
    assert verdict("ledger", "a2a_ask", "watson") == "deny" and verdict("ledger", "github_repos_read", "github-watson") == "allow"
    assert held("ledger") == [("github-ledger", "github_repos_read"), ("github-watson", "github_repos_read")]
    assert c.get("/agents/ledger/talks-to", headers=OWNER).json()["talks_to"] == []
    assert rows() >= {"github", "github-ledger", "github-watson", "ledger"} and "watson" not in rows()
    gone = c.get("/requests", params={"status": "withdrawn", "agent": "watson"}, headers=OWNER).json()["requests"]
    assert [(q["id"], q["decided_by"], q["reason"]) for q in gone] == [
        (q, "owner@example.com", "the agent was removed before this was decided") for q in (asked, elsewhere)]
    event = c.get("/events?kind=agent.removed&agent=watson", headers=OWNER).json()["events"]
    assert len(event) == 1 and event[0]["actor"] == "owner@example.com" and event[0]["detail"] == out.json()
    # Nothing it held can be approved back: the requests are no longer pending.
    out = c.post("/requests/decide", json={"ids": [asked, elsewhere], "verdict": "approve"}, headers=ADMIN).json()["results"]
    assert [o["status"] for o in out] == ["skipped", "skipped"]

    # Once nobody else uses the set, saying it again takes the set too; a third time finds nothing.
    gid = next(g["id"] for g in c.get("/agents/ledger/grants", headers=OWNER).json()["grants"] if g["integration"] == "github-watson")
    assert c.delete(f"/grants/{gid}", headers=ADMIN).status_code == 200
    out = c.delete("/agents/watson", headers=ROOM).json()
    assert (out["removed"], out["kept"], out["grants_revoked"], out["integrations_removed"]) == (["github-watson"], [], 0, 1)
    assert out["tuples_deleted"] >= 2 and "github-watson" not in rows()  # the room link and the team's ceilings
    assert c.delete("/agents/watson", headers=ROOM).json() == {
        "agent": "watson", "grants_revoked": 0, "requests_withdrawn": 0, "integrations_removed": 0,
        "tuples_deleted": 0, "leases_ended": 0, "removed": [], "kept": []}
    assert len(c.get("/events?kind=agent.removed", headers=OWNER).json()["events"]) == 2
    # An agent the room never knew is the same answer; a set named like another agent's is not this one's.
    assert c.delete("/agents/led", headers=ROOM).json()["removed"] == []
    assert {"github-ledger", "github-ledger-web"} <= rows()

    # A pick of repositories names the first agent on its set. When that agent goes, a pick on a
    # set that stays is handed to whoever is left there, and taken back when nobody is.
    abel = {"name": "abel", "team": "sre", "namespace": "abel", "service_account": "agent-abel"}
    c.put("/topology", json={"agents": [*topology["agents"], abel]}, headers=ROOM)
    grant(c, "abel", "github-ledger", ["github_repos_read"])
    grant(c, "abel", "github-ledger-web", ["github_repos_read"])
    shared, alone = (c.put(f"/integrations/{name}", headers=OWNER,
                           json={"vendor": "github", "parent": "github", "ceiling": [], "spec": {"repositories": [*repos_, "acme-docs"]}})
                     for name, repos_ in (("github-ledger", ["acme-infra"]), ("github-ledger-web", ["acme-web"])))
    assert (shared.status_code, shared.json()["pending"]["agent"]) == (202, "abel")
    assert (alone.status_code, alone.json()["pending"]["agent"]) == (202, "abel")
    c.put("/topology", json=topology, headers=ROOM)
    out = c.delete("/agents/abel", headers=ROOM).json()
    assert (out["grants_revoked"], out["requests_withdrawn"], out["removed"], out["kept"]) == (2, 1, [], [])
    assert [(q["id"], q["agent"]) for q in c.get("/requests", headers=ADMIN).json()["requests"]] == [
        (shared.json()["pending"]["id"], "ledger")]


def test_a_missing_integration_is_404_whoever_asks(world):
    """Disconnecting a row that is not there answered 403 to a caller on no team (the reviewer
    gate ran first), so a room tidying up after itself could not tell "already gone" from
    "not yours". Absent is 404 for everyone; a row that is there still takes a reviewer."""
    c, _, _, _ = world
    connect(c, ["aws_inventory_read"])
    for who in (OWNER, ROOM, ADMIN):
        r = c.delete("/integrations/never-there", headers=who)
        assert (r.status_code, r.json()["detail"]) == (404, "no integration 'never-there'")
    assert c.delete("/integrations/aws-prod", headers=OWNER).status_code == 403
    assert c.delete("/integrations/aws-prod", headers=ADMIN).status_code == 200
    assert c.delete("/integrations/aws-prod", headers=OWNER).status_code == 404
