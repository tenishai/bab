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


@pytest.fixture
def gateway():
    """A room with a tool gateway: pods for an agent, the gateway and a stranger; AWS and Datadog minters."""
    from bab.service.minters import DatadogMinter
    from tests.conftest import FakeDatadog

    clock = {"now": T0}
    store = FakeStore({Tuple("user:kyle@example.com", "member", "team:admins")})
    cat = catalogue.load("catalogues/room.yaml")
    aws = StaticMinter(now=lambda: clock["now"].timestamp())
    dd = FakeDatadog()
    datadog = DatadogMinter("sa-123", "api-xyz", "mgmt-abc", http=dd, now=lambda: clock["now"].timestamp())
    verifier = PodVerifier({"ledger-pod": ("agent-ledger", "ledger"), "gateway-pod": ("tool-gateway", "gateway"),
                            "stray-pod": ("default", "kube-system")})
    ledger = Ledger()
    app = create_app(store, cat, ledger, verifier, ConsoleAuth("console-secret"), {"aws": aws, "datadog": datadog},
                     Settings(room="acme", admin_team="admins", security_team="security", now=lambda: clock["now"],
                              gateway_service_account="gateway/tool-gateway"))
    app.state.ledger = ledger
    c = TestClient(app)
    c.put("/topology", json={"agents": [{"name": "ledger", "team": "sre", "namespace": "ledger", "service_account": "agent-ledger"},
                                        {"name": "watson", "team": "sre", "namespace": "watson", "service_account": "agent-watson"}]},
          headers=ADMIN)
    return c, clock, aws, dd


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
    assert key["name"].startswith("bab-ledger-") and key["scopes"] == ["metrics_read", "monitors_read", "timeseries_query"]
    # Revoking one permission deletes the key the agent holds: the next lease is narrower and new.
    gid = next(g["id"] for g in c.get("/agents/ledger/grants", headers=OWNER).json()["grants"] if g["permission"] == "datadog_metrics_read")
    assert c.delete(f"/grants/{gid}", headers=ADMIN).json() == {"revoked": gid, "leases_ended": 1}
    assert "kid-2" not in dd.keys
    r = c.post("/leases/for-agent", json={"agent": "ledger", "integration": "datadog"}, headers=GATEWAY).json()
    assert r["reused"] is False and r["credential"]["dd_app_key"] == "secret-kid-3" and dd.keys["kid-3"]["scopes"] == ["monitors_read"]
    # Expiry: the next lease request, from anyone, deletes keys whose hour is up.
    clock["now"] = T0 + timedelta(hours=2)
    c.post("/leases/for-agent", json={"agent": "ledger", "integration": "datadog"}, headers=GATEWAY)
    assert set(dd.keys) == {"kid-4"}
    rows = c.get("/leases?agent=ledger", headers=OWNER).json()["leases"]  # newest first; the revoked one ended at 12:00
    assert [(x["via"], x["expires_at"][:16]) for x in rows] == [("gateway", "2026-10-27T15:00"), ("gateway", "2026-10-27T13:00"), ("gateway", "2026-10-27T12:00")]


def test_the_gateway_lane_is_closed_until_a_gateway_is_named(pods):
    c, _ = pods
    r = c.post("/leases/for-agent", json={"agent": "ledger", "integration": "aws-prod"}, headers={"Authorization": "Bearer ledger-pod"})
    assert r.status_code == 501 and "BAB_GATEWAY_SERVICE_ACCOUNT" in r.text
